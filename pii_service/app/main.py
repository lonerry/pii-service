"""FastAPI-приложение: POST /process, GET /health, GET /metrics."""
from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)
from pydantic import BaseModel, Field

from .config import load_config
from .engine import (
    DemaskDenied,
    MaskingFailed,
    MaskingTimeout,
    PayloadConflict,
    Processor,
    StoreUnavailable,
    SystemNotAllowed,
    storage_key,
)
from .engine.errors import RecordDecryptFailed
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

_redis_url = os.getenv("REDIS_URL")
_encryption_key = os.getenv("PII_ENCRYPTION_KEY")
if _redis_url and not _encryption_key:
    raise RuntimeError("PII_ENCRYPTION_KEY is required when REDIS_URL is configured")
_CIPHER = Cipher(_encryption_key)
STORE = RedisStore(_redis_url, _CIPHER) if _redis_url else InMemoryStore(_CIPHER)
PROCESSOR = Processor(
    STORE,
    SYSTEMS,
    mask_timeout_seconds=MASK_TIMEOUT_SECONDS,
)


class ProcessRequest(BaseModel):
    payload: str = Field(..., max_length=MAX_PAYLOAD_CHARS)
    payload_id: str = Field(..., min_length=1, max_length=256)


class EntitySpan(BaseModel):
    type: str
    start: int
    end: int


class ProcessResponse(BaseModel):
    result: str
    types: list[str] = Field(default_factory=list)
    entities: list[EntitySpan] = Field(default_factory=list)
    elapsed_ms: int = 0
    direction: str = "mask"
    mask_mode: str = "format"


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _storage_key(system_id: str, payload_id: str) -> str:
    """Backward-compatible import for callers of the former route helper."""
    return storage_key(system_id, payload_id)


@app.post("/process", response_model=ProcessResponse)
async def process(req: ProcessRequest, request: Request) -> ProcessResponse:
    start = time.perf_counter()
    system_id = request.headers.get("X-System-Id", "default")
    mask_mode = request.headers.get("X-Mask-Mode", "").strip().lower() or None
    if mask_mode not in {None, "format", "synthetic", "token"}:
        raise HTTPException(status_code=400, detail="invalid X-Mask-Mode")
    try:
        outcome = await PROCESSOR.process(
            system_id, req.payload_id, req.payload, mask_mode=mask_mode
        )
    except SystemNotAllowed:
        raise HTTPException(status_code=403, detail="System not allowed") from None
    except (PayloadConflict, DemaskDenied):
        raise HTTPException(status_code=409, detail="payload_id conflict") from None
    except RecordDecryptFailed:
        ERRORS.labels(system=system_id, kind="store_decrypt").inc()
        raise HTTPException(
            status_code=503,
            detail="stored payload cannot be decrypted; mask again with a new payload_id",
        ) from None
    except MaskingTimeout:
        ERRORS.labels(system=system_id, kind="mask_timeout").inc()
        raise HTTPException(status_code=504, detail="masking timeout") from None
    except MaskingFailed:
        ERRORS.labels(system=system_id, kind="mask").inc()
        logger.exception("mask failed")
        raise HTTPException(status_code=500, detail="masking failed") from None
    except StoreUnavailable as exc:
        kind = "store_get" if exc.operation == "get" else "store_set"
        ERRORS.labels(system=system_id, kind=kind).inc()
        logger.exception("store.%s failed", exc.operation)
        raise HTTPException(status_code=503, detail="storage unavailable") from None

    for pii_type in outcome.types:
        MASKED_TYPES.labels(system=system_id, type=pii_type).inc()

    logger.info(
        "process ok system=%s pid_hash=%s types=%s",
        system_id,
        _short_hash(req.payload_id),
        outcome.types,
    )
    REQUESTS.labels(system=system_id, direction=outcome.direction).inc()
    LATENCY.labels(system=system_id, direction=outcome.direction).observe(
        time.perf_counter() - start
    )
    effective_mode = mask_mode or PROCESSOR.policy_for(system_id).masking_policy.mode
    return ProcessResponse(
        result=outcome.result,
        types=list(outcome.types),
        entities=[EntitySpan(**entity) for entity in outcome.entities],
        elapsed_ms=round((time.perf_counter() - start) * 1000),
        direction=outcome.direction,
        mask_mode=effective_mode,
    )


@app.get("/systems")
async def systems() -> dict[str, dict[str, bool]]:
    return {
        system_id: {"demask": bool(config.get("demask", True))}
        for system_id, config in SYSTEMS.items()
        if config.get("enabled", False)
    }


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


_STATIC_DIR = Path(__file__).with_name("static")
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def frontend() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")
