
from __future__ import annotations

import logging
from collections import Counter

from .pii.apply import apply_candidates
from .pii.candidates import KEEP, MASK, Candidate
from .pii.pipeline import analyze, analyze_for_masking
from .pii.policy import DEFAULT_POLICY, Policy
from .pii.synthetic import synthetic_value
from .pii.tokens import apply_token_masks
from .pii.transform import mask_value
from .pii.types import ALL_TYPES_SET, DATE_TYPES
from .pii.verify import final_leak_guard as _final_leak_guard
from .pii.verify import verify_masked

logger = logging.getLogger("pii.masking")

def apply_masks(
    text: str,
    cands: list[Candidate],
    *,
    mode: str = "format",
) -> tuple[str, list[str], list[tuple[int, int, str]]]:
    """Один проход по исходной строке; spans не пересекаются и сверяются с текстом."""

    def replace(candidate: Candidate) -> str:
        if mode == "synthetic":
            return synthetic_value(candidate.etype, candidate.text)
        return mask_value(candidate.etype, candidate.text)

    return apply_candidates(text, cands, replace, logger=logger)


def mask_text(
    text: str,
    enabled_types: list[str] | None = None,
    policy: Policy = DEFAULT_POLICY,
) -> tuple[str, list[str], list[tuple[int, int, str]]]:
    if enabled_types is None or "ALL" in enabled_types:
        enabled = set(ALL_TYPES_SET)
    else:
        enabled = ALL_TYPES_SET & set(enabled_types)
    # DATE и DATE_TEXT — одна сущность «дата» в двух записях
    if enabled & DATE_TYPES:
        enabled |= DATE_TYPES
    candidates, decisions = analyze_for_masking(text, enabled, policy=policy)
    mode = policy.mode
    if policy.detection_profile == "strict" and mode != "synthetic":
        mode = "token"
    if mode == "token":
        result, found, spans = apply_token_masks(text, candidates)
    else:
        result, found, spans = apply_masks(text, candidates, mode=mode)
    # Synthetic output must stay readable placeholders, not leak-guard asterisks.
    if mode != "synthetic":
        result, found, spans = _final_leak_guard(result, found, spans, enabled)
        allowed_residuals = Counter(
            (candidate.etype, candidate.text)
            for candidate in decisions
            if candidate.action == KEEP
        )
        verify_masked(
            result,
            enabled,
            policy,
            set(found),
            allowed_residuals=allowed_residuals,
        )
    return result, found, spans


def highlight_entities(
    text: str,
    enabled_types: list[str] | None = None,
    policy: Policy = DEFAULT_POLICY,
) -> list[dict]:
    """Span metadata for UI highlighting (types and offsets only)."""
    if enabled_types is None or "ALL" in enabled_types:
        enabled = set(ALL_TYPES_SET)
    else:
        enabled = ALL_TYPES_SET & set(enabled_types)
    if enabled & DATE_TYPES:
        enabled |= DATE_TYPES
    candidates = analyze(text, enabled, policy=policy)
    present = frozenset(c.etype for c in candidates)
    entities: list[dict] = []
    for candidate in candidates:
        action, _ = policy.decide(candidate, enabled, present)
        if action != MASK:
            continue
        entities.append(
            {
                "type": candidate.etype,
                "start": candidate.start,
                "end": candidate.end,
            }
        )
    return entities
