"""Хранилище пар (original, masked) по payload_id.

- InMemoryStore — для одного воркера.
- RedisStore    — для нескольких, с graceful degradation.
- Original шифруется Fernet'ом на запись и расшифровывается на чтение.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import time
from typing import Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("pii.store")

Pair = Tuple[str, str]


class Cipher:
    def __init__(self, key: Optional[str] = None) -> None:
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

    def decrypt_b64(self, token: str) -> Optional[str]:
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

    async def get(self, key: str) -> Optional[Pair]:
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
            return None
        return original, masked

    async def set(self, key: str, original: str, masked: str) -> None:
        enc_orig = self._cipher.encrypt_b64(original)
        async with self._lock:
            self._data[key] = (enc_orig, masked, time.time() + self.ttl)


class RedisStore:
    def __init__(self, url: str, cipher: Cipher, ttl: int = 3600) -> None:
        import redis.asyncio as redis

        self._client = redis.from_url(url, decode_responses=True)
        self._cipher = cipher
        self.ttl = ttl
        self._fallback = InMemoryStore(cipher, ttl=ttl)
        self._redis_ok = True

    async def _check(self) -> bool:
        if not self._redis_ok:
            return False
        try:
            await self._client.ping()
            return True
        except Exception:
            logger.warning("redis unavailable, falling back to memory")
            self._redis_ok = False
            return False

    async def get(self, key: str) -> Optional[Pair]:
        if await self._check():
            try:
                data = await self._client.hgetall(f"pii:{key}")
                if data:
                    original = self._cipher.decrypt_b64(data.get("orig", ""))
                    if original is None:
                        return None
                    return original, data.get("masked", "")
            except Exception:
                logger.warning("redis get failed")
                self._redis_ok = False
        return await self._fallback.get(key)

    async def set(self, key: str, original: str, masked: str) -> None:
        enc_orig = self._cipher.encrypt_b64(original)
        if await self._check():
            try:
                pipe = self._client.pipeline()
                pipe.hset(f"pii:{key}", mapping={"orig": enc_orig, "masked": masked})
                pipe.expire(f"pii:{key}", self.ttl)
                await pipe.execute()
                return
            except Exception:
                logger.warning("redis set failed")
                self._redis_ok = False
        await self._fallback.set(key, original, masked)
