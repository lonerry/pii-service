"""Fail-closed residual PII verification."""
from __future__ import annotations

import logging
import re
from collections import Counter

from .candidates import MASK
from .detectors import (
    CARD_RE,
    CVV_RE,
    INN_RE,
    PIN_RE,
    SNILS_RE,
    inn_ok,
    luhn_ok,
    snils_ok,
)
from .pipeline import evaluate
from .policy import Policy
from .tokens import hide_markers

logger = logging.getLogger("pii.verify")

CRITICAL_TYPES = frozenset(
    {"PHONE", "EMAIL", "CARD", "CVV", "PIN", "INN", "PASSPORT", "DRIVER"}
)
_ACCOUNT_CTX = re.compile(
    r"(?i)(?:номер\s+сч[её]та|расч[её]тн\w+\s+сч\w*|р/с|account(?:\s+number)?)\W*$"
)


def _account_context_before(text: str, start: int) -> bool:
    return bool(_ACCOUNT_CTX.search(text[max(0, start - 64):start]))


def final_leak_guard(
    text: str,
    found: list[str],
    spans: list[tuple[int, int, str]],
    enabled: set[str],
) -> tuple[str, list[str], list[tuple[int, int, str]]]:
    """Mask any checksum-valid critical value left in the actual output."""
    guard_spans: list[tuple[int, int, str]] = []
    if "CARD" in enabled:
        for match in CARD_RE.finditer(text):
            if _account_context_before(text, match.start()):
                continue
            digits = re.sub(r"\D", "", match.group(0))
            if 13 <= len(digits) <= 19 and luhn_ok(digits):
                guard_spans.append((match.start(), match.end(), "CARD"))
    if "INN" in enabled:
        for match in INN_RE.finditer(text):
            if inn_ok(match.group(0)):
                guard_spans.append((match.start(), match.end(), "INN"))
    if "SNILS" in enabled:
        for match in SNILS_RE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if snils_ok(digits):
                guard_spans.append((match.start(), match.end(), "SNILS"))
    if "CVV" in enabled:
        guard_spans.extend((*match.span(2), "CVV") for match in CVV_RE.finditer(text))
    if "PIN" in enabled:
        guard_spans.extend((*match.span(2), "PIN") for match in PIN_RE.finditer(text))
    if not guard_spans:
        return text, found, spans.copy()

    parts: list[str] = []
    pos = 0
    leaked: list[str] = []
    result_spans = spans.copy()
    for start, end, entity_type in sorted(guard_spans):
        if start < pos:
            continue
        parts.extend((text[pos:start], "*" * (end - start)))
        pos = end
        leaked.append(entity_type)
        result_spans.append((start, end, entity_type))
    parts.append(text[pos:])
    if leaked:
        logger.warning("final leak guard caught %d residual span(s): %s", len(leaked), leaked)
    return "".join(parts), found + leaked, result_spans


def verification_types(
    enabled: set[str], policy: Policy, applied_types: set[str]
) -> set[str]:
    selected = enabled & CRITICAL_TYPES
    if policy.mask_types is not None:
        selected &= set(policy.mask_types)
    return {
        entity_type
        for entity_type in selected
        if not policy.rules.get(entity_type) or entity_type in applied_types
    }


def verify_masked(
    text: str,
    enabled: set[str],
    policy: Policy,
    applied_types: set[str],
    *,
    allowed_residuals: Counter[tuple[str, str]] | None = None,
) -> None:
    selected = verification_types(enabled, policy, applied_types)
    if not selected:
        return
    findings = evaluate(hide_markers(text), selected, policy)
    residuals = Counter(
        (finding.etype, finding.text)
        for finding in findings
        if finding.action == MASK
    )
    if allowed_residuals:
        residuals.subtract(allowed_residuals)
    if any(count > 0 for count in residuals.values()):
        raise RuntimeError("masked output still contains critical PII")
