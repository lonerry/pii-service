"""Хранилище пар (original, masked) по payload_id.

- InMemoryStore — для одного воркера.
- RedisStore    — для нескольких воркеров; при сбое хранилища запрос fail-closed.
- Original шифруется Fernet'ом на запись и расшифровывается на чтение.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import time

from cryptography.fernet import Fernet, InvalidToken
from redis.exceptions import RedisError

from .engine.errors import RecordDecryptFailed

logger = logging.getLogger("pii.store")

Pair = tuple[str, str]


class Cipher:
    def __init__(self, key: str | None = None) -> None:
        if key is None:
            key = os.getenv("PII_ENCRYPTION_KEY")
        if key:
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key
            self._f = Fernet(key_bytes)
        else:
            self._f = Fernet(Fernet.generate_key())
            logger.warning(
                "PII_ENCRYPTION_KEY not set; using ephemeral key "
                "(entries will not survive restart)"
            )

    def encrypt_b64(self, value: str) -> str:
        return base64.b64encode(self._f.encrypt(value.encode("utf-8"))).decode("ascii")

    def decrypt_b64(self, token: str) -> str | None:
        try:
            return self._f.decrypt(base64.b64decode(token)).decode("utf-8")
        except (InvalidToken, ValueError):
            logger.warning("failed to decrypt stored value (key rotation?)")
            return None


class InMemoryStore:
    def __init__(self, cipher: Cipher, ttl: int = 3600) -> None:
        self._cipher = cipher
        self._data: dict[str, tuple[str, str, float]] = {}
        self.ttl = ttl
        self._lock = asyncio.Lock()

    def _purge_expired(self, now: float) -> None:
        expired = [key for key, item in self._data.items() if item[2] < now]
        for key in expired:
            self._data.pop(key, None)

    async def get(self, key: str) -> Pair | None:
        async with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            enc_orig, masked, exp = item
            if exp < time.time():
                self._data.pop(key, None)
                return None
        original = self._cipher.decrypt_b64(enc_orig)
        if original is None:
            raise RecordDecryptFailed
        return original, masked

    async def set_if_absent(self, key: str, original: str, masked: str) -> bool:
        enc_orig = self._cipher.encrypt_b64(original)
        async with self._lock:
            now = time.time()
            self._purge_expired(now)
            item = self._data.get(key)
            if item is not None:
                return False
            self._data[key] = (enc_orig, masked, now + self.ttl)
            return True


class RedisStore:
    def __init__(self, url: str, cipher: Cipher, ttl: int = 3600) -> None:
        import redis.asyncio as redis

        self._client = redis.from_url(url, decode_responses=True)
        self._cipher = cipher
        self.ttl = ttl

    async def get(self, key: str) -> Pair | None:
        try:
            data = await self._client.hgetall(f"pii:{key}")
        except RedisError:
            logger.exception("redis get failed")
            raise
        if not data:
            return None
        original = self._cipher.decrypt_b64(data.get("orig", ""))
        if original is None:
            raise RecordDecryptFailed
        return original, data.get("masked", "")

    async def set_if_absent(self, key: str, original: str, masked: str) -> bool:
        enc_orig = self._cipher.encrypt_b64(original)
        script = """
        if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
        redis.call('HSET', KEYS[1], 'orig', ARGV[1], 'masked', ARGV[2])
        redis.call('EXPIRE', KEYS[1], ARGV[3])
        return 1
        """
        try:
            created = await self._client.eval(
                script, 1, f"pii:{key}", enc_orig, masked, self.ttl
            )
        except RedisError:
            logger.exception("redis set-if-absent failed")
            raise
        return bool(created)
