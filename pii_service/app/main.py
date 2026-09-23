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
