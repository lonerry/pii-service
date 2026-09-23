"""Single-pass span replacement shared by format and token masking."""
from __future__ import annotations

import logging
from collections.abc import Callable

from .candidates import Candidate

Replacement = Callable[[Candidate], str]


def apply_candidates(
    text: str,
    candidates: list[Candidate],
    replacement_for: Replacement,
    *,
    logger: logging.Logger,
) -> tuple[str, list[str], list[tuple[int, int, str]]]:
    parts: list[str] = []
    found: list[str] = []
    spans: list[tuple[int, int, str]] = []
    pos = 0
    for candidate in sorted(candidates, key=lambda item: item.start):
        if candidate.start < pos or text[candidate.start:candidate.end] != candidate.text:
            logger.error(
                "span mismatch type=%s start=%d end=%d",
                candidate.etype,
                candidate.start,
                candidate.end,
            )
            continue
        replacement = replacement_for(candidate)
        if replacement == candidate.text:
            continue
        parts.extend((text[pos:candidate.start], replacement))
        pos = candidate.end
        found.append(candidate.etype)
        found.extend(
            signal.removeprefix("merged_type:")
            for signal in candidate.signals
            if signal.startswith("merged_type:")
        )
        spans.append((candidate.start, candidate.end, candidate.etype))
    parts.append(text[pos:])
    return "".join(parts), found, spans
