#!/usr/bin/env bash
set -euo pipefail

mkdir -p pii_service/app
cd pii_service

: > app/__init__.py

cat > app/config.py << 'EOF'
"""Загрузка и валидация конфигурации сервиса."""
from __future__ import annotations

import os
from typing import Any, Dict

import yaml

DEFAULT_CONFIG: Dict[str, Any] = {
    "systems": {
        "default": {
            "enabled": True,
            "types": ["ALL"],
            "demask": True,
        }
    }
}

VALID_TYPES = {
    "EMAIL", "CARD", "PHONE", "PASSPORT", "DRIVER", "INN", "CVV", "PIN",
    "DATE", "DATE_TEXT", "FIO", "ADDRESS", "CITIZENSHIP", "BIRTH_PLACE",
    "ISSUER", "DEPT_CODE", "CARDHOLDER", "ALL",
}


def _validate(cfg: Dict[str, Any]) -> Dict[str, Any]:
    systems = cfg.get("systems") or {}
    if not isinstance(systems, dict):
        raise ValueError("config.systems must be a mapping")
    for name, sc in systems.items():
        if not isinstance(sc, dict):
            raise ValueError(f"config.systems.{name} must be a mapping")
        sc.setdefault("enabled", True)
        sc.setdefault("demask", True)
        types = sc.setdefault("types", ["ALL"])
        if not isinstance(types, list):
            raise ValueError(f"config.systems.{name}.types must be a list")
        unknown = [t for t in types if t not in VALID_TYPES]
        if unknown:
            raise ValueError(f"unknown PII types for {name}: {unknown}")
    return cfg


def load_config() -> Dict[str, Any]:
    path = os.getenv("CONFIG_PATH", "config.yaml")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return _validate(raw)
    return DEFAULT_CONFIG
EOF

cat > app/store.py << 'EOF'
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
EOF

cat > app/masking.py << 'EOF'
"""Идентификация и маскирование ПД в тексте."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

ALL_TYPES: Tuple[str, ...] = (
    "EMAIL", "CARD", "PHONE", "PASSPORT", "DRIVER", "INN", "CVV", "PIN",
    "DATE", "DATE_TEXT", "FIO", "ADDRESS", "CITIZENSHIP", "BIRTH_PLACE",
    "ISSUER", "DEPT_CODE", "CARDHOLDER",
)
ALL_TYPES_SET = set(ALL_TYPES)


def _mask_digits(text: str, keep_first: int = 0, keep_last: int = 0) -> str:
    positions = [i for i, ch in enumerate(text) if ch.isdigit()]
    total = len(positions)
    keep = set()
    if keep_first:
        keep.update(positions[:keep_first])
    if keep_last:
        keep.update(positions[total - keep_last:])
    return "".join(ch if (not ch.isdigit() or i in keep) else "*" for i, ch in enumerate(text))


def _mask_email(text: str) -> str:
    if "@" not in text:
        return text
    local, domain = text.split("@", 1)
    local_masked = (local[0] + "***") if len(local) > 1 else "*"
    parts = domain.split(".")
    if len(parts) >= 2:
        domain_masked = parts[0][:1] + "***." + ".".join(parts[1:])
    else:
        domain_masked = domain[:1] + "***"
    return f"{local_masked}@{domain_masked}"


def _relative_replace(match: "re.Match[str]", group: int, replacement: str) -> str:
    full = match.group(0)
    g_start, g_end = match.span(group)
    rel_start = g_start - match.start()
    rel_end = g_end - match.start()
    return full[:rel_start] + replacement + full[rel_end:]


def _luhn_ok(digits: str) -> bool:
    s = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b")

PHONE_RE = re.compile(
    r"(?:(?:\+7|8|7)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"
    r"|\b\d{3}[\s\-]\d{3}[\s\-]\d{2}[\s\-]\d{2}\b)"
)

CARD_RE = re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7}\b")

CVV_RE = re.compile(r"(?i)\b(?:cvv|cvc|cvv2|cvc2|код\s+проверки)\b\s{0,4}[:#]?\s{0,4}(\d{3})\b")
PIN_RE = re.compile(r"(?i)\b(?:пин[\s\-]?код|pin)\b\s{0,4}[:#]?\s{0,4}(\d{4})\b")

PASSPORT_RE = re.compile(
    r"(?i)(?:серия\s{1,4})?(\d{2})\s{0,4}(\d{2})\s{0,4}(?:номер\s{1,4})?(\d{4})\s{0,4}(\d{2})\b"
)
DRIVER_RE = re.compile(
    r"(?i)(?:в/у|водительское\s+удостоверение|серия\s{1,4})?(\d{2})\s{0,4}(\d{2})\s{0,4}(\d{6})\b"
)

INN_RE = re.compile(r"(?<!\d)(?:\d{10}|\d{12})(?!\d)")

DATE_NUM_RE = re.compile(
    r"\b(\d{2})[./\-](\d{2})[./\-](\d{4})\b|\b(\d{4})[./\-](\d{2})[./\-](\d{2})\b"
)
DATE_TEXT_RE = re.compile(
    r"\b(\d{1,2})\s+(января|февраля|марта|апреля|мая|июня|июля|августа|"
    r"сентября|октября|ноября|декабря)\s+(\d{4})\b",
    re.IGNORECASE,
)

FIO_RE = re.compile(
    r"\b([А-ЯЁ][а-яё]{1,40}(?:-[А-ЯЁ][а-яё]{1,40})?)\s+"
    r"([А-ЯЁ][а-яё]{1,40}(?:-[А-ЯЁ][а-яё]{1,40})?)\s+"
    r"([А-ЯЁ][а-яё]{1,30}(?:ович|евич|ич|овна|евна|ична|инична))\b"
)

ADDRESS_RE = re.compile(
    r"(?i)\b(г\.|город|ул\.|улица|пер\.|переулок|пр\.|проспект|д\.|дом|"
    r"кв\.|квартира|индекс)\s{0,4}[:#]?\s{0,4}([А-ЯЁа-яё0-9\-]{1,100})"
)

CITIZENSHIP_RE = re.compile(r"(?i)\b(гражданство)\s{0,4}[:#]?\s{0,4}([А-ЯЁа-яё]{1,50}|РФ|Россия)")
BIRTH_PLACE_RE = re.compile(r"(?i)\b(место\s+рождения)\s{0,4}[:#]?\s{0,4}([^,;]{1,200})")
ISSUER_RE = re.compile(r"(?i)\b(орган,?\s*выдавший)\s{0,4}[:#]?\s{0,4}([^,;]{1,200})")
DEPT_CODE_RE = re.compile(r"(?i)\b(код\s+подразделения)\s{0,4}[:#]?\s{0,4}(\d{3}-\d{3})")
CARDHOLDER_RE = re.compile(r"(?i)\b(имя\s+держателя\s+карты)\s{0,4}[:#]?\s{0,4}([A-Za-z\s]{1,100})")


def _mask_card_match(m: "re.Match[str]") -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if len(digits) < 13 or not _luhn_ok(digits):
        return m.group(0)
    return _mask_digits(m.group(0), keep_first=0, keep_last=4)


def _mask_phone_match(m: "re.Match[str]") -> str:
    prefix = 1 if re.match(r"\s*(\+7|8|7)", m.group(0)) else 0
    return _mask_digits(m.group(0), keep_first=prefix, keep_last=2)


def _mask_date_match(m: "re.Match[str]") -> str:
    if re.match(r"^\d{4}", m.group(0)):
        return _mask_digits(m.group(0), keep_first=4)
    return _mask_digits(m.group(0), keep_last=4)


def _mask_date_text_match(m: "re.Match[str]") -> str:
    day, month, year = m.group(1), m.group(2), m.group(3)
    return f"{'*' * len(day)} {'*' * len(month)} {year}"


def _mask_fio_match(m: "re.Match[str]") -> str:
    return " ".join(p[0].upper() + "." for p in m.group(0).split())


def _mask_group(m: "re.Match[str]", group: int) -> str:
    g_start, g_end = m.span(group)
    return _relative_replace(m, group, "*" * (g_end - g_start))


def _mask_dept_code(m: "re.Match[str]") -> str:
    return _relative_replace(m, 2, "***-***")


def _mask_cardholder(m: "re.Match[str]") -> str:
    val = m.group(2)
    masked = " ".join(p[0].upper() + "." for p in val.split() if p)
    return _relative_replace(m, 2, masked)


@dataclass(frozen=True)
class Rule:
    name: str
    regex: "re.Pattern[str]"
    mask_func: Callable[["re.Match[str]"], str]
    priority: int


RULES: Sequence[Rule] = (
    Rule("EMAIL", EMAIL_RE, lambda m: _mask_email(m.group(0)), 100),
    Rule("CARD", CARD_RE, _mask_card_match, 95),
    Rule("PHONE", PHONE_RE, _mask_phone_match, 90),
    Rule("PASSPORT", PASSPORT_RE, lambda m: _mask_digits(m.group(0), keep_first=2, keep_last=2), 85),
    Rule("DRIVER", DRIVER_RE, lambda m: _mask_digits(m.group(0), keep_first=2, keep_last=2), 80),
    Rule("INN", INN_RE, lambda m: _mask_digits(m.group(0), keep_first=2, keep_last=2), 75),
    Rule("CVV", CVV_RE, lambda m: _mask_digits(m.group(0), keep_first=0, keep_last=0), 70),
    Rule("PIN", PIN_RE, lambda m: _mask_digits(m.group(0), keep_first=0, keep_last=0), 70),
    Rule("DATE", DATE_NUM_RE, _mask_date_match, 60),
    Rule("DATE_TEXT", DATE_TEXT_RE, _mask_date_text_match, 60),
    Rule("FIO", FIO_RE, _mask_fio_match, 50),
    Rule("ADDRESS", ADDRESS_RE, lambda m: _mask_group(m, 2), 40),
    Rule("CITIZENSHIP", CITIZENSHIP_RE, lambda m: _mask_group(m, 2), 30),
    Rule("BIRTH_PLACE", BIRTH_PLACE_RE, lambda m: _mask_group(m, 2), 30),
    Rule("ISSUER", ISSUER_RE, lambda m: _mask_group(m, 2), 30),
    Rule("DEPT_CODE", DEPT_CODE_RE, _mask_dept_code, 30),
    Rule("CARDHOLDER", CARDHOLDER_RE, _mask_cardholder, 30),
)

_FIO_SKIP_CTX = re.compile(r"\b(поэт|писатель|художник|композитор|ученый|учёный)\b")
_ADDR_SKIP_CTX = re.compile(r"\b(отделение|банк|офис|филиал)\b")


def _collect_spans(text: str, enabled: set[str]) -> List[Tuple[int, int, int, str, str]]:
    spans: List[Tuple[int, int, int, str, str]] = []
    for rule in RULES:
        if rule.name not in enabled:
            continue
        for m in rule.regex.finditer(text):
            if rule.name == "FIO":
                if _FIO_SKIP_CTX.search(text[max(0, m.start() - 40):m.start()].lower()):
                    continue
            if rule.name == "ADDRESS":
                if _ADDR_SKIP_CTX.search(text[max(0, m.start() - 40):m.start()].lower()):
                    continue
            repl = rule.mask_func(m)
            if repl == m.group(0):
                continue
            spans.append((m.start(), m.end(), rule.priority, rule.name, repl))
    return spans


def _select_non_overlapping(
    spans: Iterable[Tuple[int, int, int, str, str]]
) -> List[Tuple[int, int, int, str, str]]:
    ordered = sorted(spans, key=lambda s: (-s[2], -(s[1] - s[0])))
    accepted: List[Tuple[int, int, int, str, str]] = []
    for span in ordered:
        s, e = span[0], span[1]
        if any(not (e <= a[0] or s >= a[1]) for a in accepted):
            continue
        accepted.append(span)
    return accepted


def mask_text(text: str, enabled_types: Optional[List[str]] = None) -> Tuple[str, List[str]]:
    if enabled_types is None or "ALL" in enabled_types:
        enabled = ALL_TYPES_SET
    else:
        enabled = ALL_TYPES_SET & set(enabled_types)

    accepted = _select_non_overlapping(_collect_spans(text, enabled))
    accepted.sort(key=lambda x: x[0], reverse=True)

    result = text
    found: List[str] = []
    for s, e, _prio, name, repl in accepted:
        result = result[:s] + repl + result[e:]
        found.append(name)
    return result, found
EOF

cat > app/main.py << 'EOF'
"""FastAPI-приложение: POST /process, GET /health, GET /metrics."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)

from .config import load_config
from .masking import ALL_TYPES_SET, mask_text
from .store import Cipher, InMemoryStore, RedisStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("pii")

MAX_PAYLOAD_CHARS = int(os.getenv("MAX_PAYLOAD_CHARS", "400000"))
MASK_TIMEOUT_SECONDS = float(os.getenv("MASK_TIMEOUT_SECONDS", "5"))

app = FastAPI(title="PII Security Module", version="1.2.0")

REQUESTS = Counter("pii_requests_total", "Total requests", ["system", "direction"])
LATENCY = Histogram("pii_latency_seconds", "Request latency", ["system", "direction"])
MASKED_TYPES = Counter("pii_masked_types_total", "Masked PII types", ["system", "type"])
ERRORS = Counter("pii_errors_total", "Errors", ["system", "kind"])

CONFIG = load_config()
SYSTEMS = CONFIG.get("systems", {})

_CIPHER = Cipher()
_redis_url = os.getenv("REDIS_URL")
STORE = RedisStore(_redis_url, _CIPHER) if _redis_url else InMemoryStore(_CIPHER)


class ProcessRequest(BaseModel):
    payload: str = Field(..., max_length=MAX_PAYLOAD_CHARS)
    payload_id: str = Field(..., min_length=1, max_length=256)


class ProcessResponse(BaseModel):
    result: str


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _get_system_cfg(system_id: str):
    cfg = SYSTEMS.get(system_id)
    if not cfg or not cfg.get("enabled", False):
        raise HTTPException(status_code=403, detail="System not allowed")
    return cfg


@app.post("/process", response_model=ProcessResponse)
async def process(req: ProcessRequest, request: Request) -> ProcessResponse:
    start = time.perf_counter()
    system_id = request.headers.get("X-System-Id", "default")
    cfg = _get_system_cfg(system_id)

    enabled_types = cfg.get("types", ["ALL"])
    enabled_set = ALL_TYPES_SET if "ALL" in enabled_types else (ALL_TYPES_SET & set(enabled_types))

    try:
        existing = await STORE.get(req.payload_id)
    except Exception:
        ERRORS.labels(system=system_id, kind="store_get").inc()
        logger.exception("store.get failed")
        existing = None

    if existing:
        original, masked = existing
        if req.payload == masked and cfg.get("demask", True):
            REQUESTS.labels(system=system_id, direction="demask").inc()
            LATENCY.labels(system=system_id, direction="demask").observe(time.perf_counter() - start)
            return ProcessResponse(result=original)
        if req.payload == original:
            REQUESTS.labels(system=system_id, direction="mask").inc()
            LATENCY.labels(system=system_id, direction="mask").observe(time.perf_counter() - start)
            return ProcessResponse(result=masked)

    try:
        masked, types = await asyncio.wait_for(
            asyncio.to_thread(mask_text, req.payload, list(enabled_set)),
            timeout=MASK_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        ERRORS.labels(system=system_id, kind="mask_timeout").inc()
        raise HTTPException(status_code=504, detail="masking timeout") from None
    except Exception:
        ERRORS.labels(system=system_id, kind="mask").inc()
        logger.exception("mask failed")
        raise HTTPException(status_code=500, detail="masking failed") from None

    try:
        await STORE.set(req.payload_id, req.payload, masked)
    except Exception:
        ERRORS.labels(system=system_id, kind="store_set").inc()
        logger.exception("store.set failed")

    for t in types:
        MASKED_TYPES.labels(system=system_id, type=t).inc()

    logger.info(
        "process ok system=%s pid_hash=%s types=%s",
        system_id, _short_hash(req.payload_id), types,
    )
    REQUESTS.labels(system=system_id, direction="mask").inc()
    LATENCY.labels(system=system_id, direction="mask").observe(time.perf_counter() - start)
    return ProcessResponse(result=masked)


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
EOF

cat > config.yaml << 'EOF'
systems:
  default:
    enabled: true
    types: ["ALL"]
    demask: true

  crm:
    enabled: true
    types: ["FIO", "PHONE", "EMAIL", "PASSPORT", "CARD"]
    demask: true
EOF

cat > requirements.txt << 'EOF'
fastapi==0.115.0
uvicorn[standard]==0.30.6
pydantic==2.8.2
redis==5.0.8
prometheus-client==0.20.0
PyYAML==6.0.2
cryptography==43.0.1
EOF

cat > Dockerfile << 'EOF'
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY config.yaml .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
EOF

cat > .dockerignore << 'EOF'
__pycache__/
*.pyc
.venv/
venv/
env/
.git/
.idea/
.vscode/
coverage/
*.zip
EOF

cat > .env.example << 'EOF'
PII_ENCRYPTION_KEY=
MAX_PAYLOAD_CHARS=400000
MASK_TIMEOUT_SECONDS=5
REDIS_URL=redis://redis:6379/0
EOF

cat > docker-compose.yml << 'EOF'
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  pii:
    build: .
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379/0
      - PII_ENCRYPTION_KEY=${PII_ENCRYPTION_KEY:-}
      - MAX_PAYLOAD_CHARS=${MAX_PAYLOAD_CHARS:-400000}
      - MASK_TIMEOUT_SECONDS=${MASK_TIMEOUT_SECONDS:-5}
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
    depends_on:
      - redis
EOF

cat > README.md << 'EOF'
# PII Security Module

Прокси-сервис для маскирования и демаскирования персональных данных
перед отправкой в LLM и обратно. Реализует контракт POST /process.

## Запуск

    docker compose up --build

Сервис: http://localhost:8000

## Контракт

    POST /process
    {"payload": "...", "payload_id": "..."}
    -> {"result": "..."}

Первый запрос с новым payload_id — маскирование.
Повторный с тем же payload_id и маской — демаскирование.

## Настройка

Правила систем в config.yaml. Для новой системы добавьте секцию
в systems: enabled, types (список типов ПД или ALL), demask.

## Наблюдаемость

/health — статус, /metrics — Prometheus (latency, rps, ошибки).
EOF

echo "OK: files created"
find . -type f -not -path '*/.*' | sort
