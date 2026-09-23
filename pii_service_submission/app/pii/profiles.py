"""Detection confidence profiles shared by pipeline, policy, and verification."""
from __future__ import annotations

from .candidates import Candidate

VALID_PROFILES = frozenset({"conservative", "balanced", "strict"})
AMBIGUOUS_TYPES = frozenset({"FIO", "ADDRESS"})


def threshold(profile: str, entity_type: str) -> float:
    if profile == "strict":
        return 0.55
    if profile == "conservative":
        return 0.95
    return 0.80 if entity_type in AMBIGUOUS_TYPES else 0.70


def is_present(candidate: Candidate, profile: str) -> bool:
    return (
        candidate.score > 0
        and candidate.effective_score >= threshold(profile, candidate.etype)
    )
