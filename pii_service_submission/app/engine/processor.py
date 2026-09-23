"""Framework-independent orchestration for reversible PII processing."""
from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any, Literal, Protocol

from ..masking import highlight_entities, mask_text
from ..pii.policy import Policy
from ..store import Pair
from .errors import (
    DemaskDenied,
    MaskingFailed,
    MaskingTimeout,
    PayloadConflict,
    RecordDecryptFailed,
    StoreUnavailable,
    SystemNotAllowed,
)
from .policy import ProcessingPolicy, build_policy

Direction = Literal["mask", "demask"]
Masker = Callable[
    [str, list[str] | None, Policy],
    tuple[str, list[str], list[tuple[int, int, str]]],
]


class RecordStore(Protocol):
    async def get(self, key: str) -> Pair | None: ...

    async def set_if_absent(
        self, key: str, original: str, masked: str
    ) -> bool: ...


@dataclass(frozen=True)
class ProcessResult:
    """Successful processing outcome for adapters and observability."""

    result: str
    direction: Direction
    types: tuple[str, ...] = ()
    entities: tuple[dict[str, Any], ...] = ()
    created: bool = False


def _same_payload(left: str, right: str) -> bool:
    if left == right:
        return True
    norm = lambda value: value.replace("\r\n", "\n").replace("\r", "\n")
    return norm(left) == norm(right)


def storage_key(system_id: str, payload_id: str) -> str:
    """Return a collision-safe, opaque key scoped to system and operation."""
    encoded = json.dumps(
        [system_id, "process", payload_id],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def process_existing(
    record: Pair, payload: str, allow_demask: bool
) -> ProcessResult:
    """Apply the only valid transitions for an existing record."""
    original, masked = record
    if _same_payload(payload, original):
        return ProcessResult(result=masked, direction="mask")
    if _same_payload(payload, masked):
        if not allow_demask:
            raise DemaskDenied
        return ProcessResult(result=original, direction="demask")
    raise PayloadConflict


class Processor:
    """Coordinates policy, masking, and first-writer-wins persistence."""

    def __init__(
        self,
        store: RecordStore,
        systems: Mapping[str, Mapping[str, Any]],
        *,
        mask_timeout_seconds: float = 5.0,
        masker: Masker = mask_text,
    ) -> None:
        self._store = store
        self._systems = systems
        self._mask_timeout_seconds = mask_timeout_seconds
        self._masker = masker

    def policy_for(self, system_id: str) -> ProcessingPolicy:
        config = self._systems.get(system_id)
        if not config or not config.get("enabled", False):
            raise SystemNotAllowed
        return build_policy(config)

    async def _read(self, key: str) -> Pair | None:
        try:
            return await self._store.get(key)
        except RecordDecryptFailed:
            raise
        except Exception as exc:
            raise StoreUnavailable("get") from exc

    async def _mask(
        self, payload: str, policy: ProcessingPolicy
    ) -> tuple[str, list[str], list[dict]]:
        try:
            masked, types, spans = await asyncio.wait_for(
                asyncio.to_thread(
                    self._masker,
                    payload,
                    list(policy.enabled_types),
                    policy.masking_policy,
                ),
                timeout=self._mask_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise MaskingTimeout from exc
        except Exception as exc:
            raise MaskingFailed from exc
        entities = [
            {"type": etype, "start": start, "end": end}
            for start, end, etype in spans
        ]
        return masked, types, entities

    def _with_mask_mode(
        self, policy: ProcessingPolicy, mask_mode: str | None
    ) -> ProcessingPolicy:
        if mask_mode not in {"format", "synthetic", "token"}:
            return policy
        masking = replace(policy.masking_policy, mode=mask_mode)
        return replace(policy, masking_policy=masking)

    async def process(
        self,
        system_id: str,
        payload_id: str,
        payload: str,
        *,
        mask_mode: str | None = None,
    ) -> ProcessResult:
        policy = self._with_mask_mode(self.policy_for(system_id), mask_mode)
        key = storage_key(system_id, payload_id)
        existing = await self._read(key)
        if existing is not None:
            result = process_existing(existing, payload, policy.allow_demask)
            entities: tuple[dict[str, Any], ...] = ()
            if result.direction == "mask":
                entities = tuple(
                    await asyncio.to_thread(
                        highlight_entities,
                        payload,
                        list(policy.enabled_types),
                        policy.masking_policy,
                    )
                )
            return ProcessResult(
                result=result.result,
                direction=result.direction,
                types=result.types,
                entities=entities,
            )

        masked, types, entities = await self._mask(payload, policy)
        try:
            created = await self._store.set_if_absent(key, payload, masked)
        except Exception as exc:
            raise StoreUnavailable("set") from exc

        if created:
            return ProcessResult(
                result=masked,
                direction="mask",
                types=tuple(types),
                entities=tuple(entities),
                created=True,
            )

        winner = await self._read(key)
        if winner is None:
            raise StoreUnavailable("get")
        result = process_existing(winner, payload, policy.allow_demask)
        return ProcessResult(
            result=result.result,
            direction=result.direction,
            types=tuple(types),
            entities=tuple(entities),
        )
