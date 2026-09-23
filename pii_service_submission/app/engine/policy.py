"""Build processing policy from a system's validated configuration."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..pii.policy import Policy
from ..pii.types import ALL_TYPES_SET


@dataclass(frozen=True)
class ProcessingPolicy:
    """All policy decisions needed by one processing operation."""

    enabled_types: frozenset[str]
    masking_policy: Policy
    allow_demask: bool


def _selected_types(values: object) -> frozenset[str]:
    selected = values if isinstance(values, list) else ["ALL"]
    if "ALL" in selected:
        return frozenset(ALL_TYPES_SET)
    return frozenset(ALL_TYPES_SET & set(selected))


def build_policy(config: Mapping[str, Any]) -> ProcessingPolicy:
    """Translate a validated system config into immutable domain policy."""
    enabled_types = _selected_types(
        config.get("detect_types") or config.get("types", ["ALL"])
    )
    configured_mask_types = config.get("mask_types")
    mask_types = (
        _selected_types(configured_mask_types)
        if configured_mask_types is not None
        else None
    )
    rules = {
        rule["type"]: frozenset(rule.get("requires", []))
        for rule in config.get("rules", [])
    }
    return ProcessingPolicy(
        enabled_types=enabled_types,
        masking_policy=Policy(
            detection_profile=config.get("detection_profile", "balanced"),
            mode=config.get("mask_mode", "format"),
            mask_types=mask_types,
            rules=rules,
        ),
        allow_demask=bool(config.get("demask", True)),
    )
