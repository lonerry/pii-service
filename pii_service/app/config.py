"""Загрузка и валидация конфигурации сервиса."""
from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from .pii.detectors import REGISTRY
from .pii.profiles import VALID_PROFILES

DEFAULT_CONFIG: dict[str, Any] = {
    "systems": {
        "default": {
            "enabled": True,
            "types": ["ALL"],
            "demask": True,
        }
    }
}

VALID_TYPES = set(REGISTRY.supported_types) | {"ALL"}


def _type_list(system: dict[str, Any], system_name: str, key: str) -> list[str] | None:
    selected = system.get(key)
    if selected is None:
        return None
    if not isinstance(selected, list):
        raise TypeError(f"config.systems.{system_name}.{key} must be a list")
    unknown = [entity_type for entity_type in selected if entity_type not in VALID_TYPES]
    if unknown:
        raise ValueError(f"unknown PII types for {system_name}.{key}: {unknown}")
    return selected


def _expand_types(values: list[str]) -> set[str]:
    if "ALL" in values:
        return set(REGISTRY.supported_types)
    return set(values)


def _validate_rules(
    system: dict[str, Any],
    system_name: str,
    detect_types: set[str],
    mask_types: set[str],
) -> None:
    rules = system.setdefault("rules", [])
    if not isinstance(rules, list):
        raise TypeError(f"config.systems.{system_name}.rules must be a list")
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") not in VALID_TYPES:
            raise ValueError(f"invalid policy rule for {system_name}")
        requires = rule.setdefault("requires", [])
        if not isinstance(requires, list) or any(
            entity_type not in VALID_TYPES for entity_type in requires
        ):
            raise ValueError(f"invalid policy rule requirements for {system_name}")
        if rule["type"] not in mask_types or not set(requires).issubset(detect_types):
            raise ValueError(f"policy rule uses disabled types for {system_name}")


def _validate_system(name: str, system: dict[str, Any]) -> None:
    for key in ("enabled", "demask"):
        value = system.setdefault(key, True)
        if not isinstance(value, bool):
            raise TypeError(f"config.systems.{name}.{key} must be a boolean")

    profile = system.setdefault("detection_profile", "balanced")
    if profile not in VALID_PROFILES:
        raise ValueError(f"invalid detection_profile for {name}: {profile}")
    mask_mode = system.setdefault("mask_mode", "format")
    if mask_mode not in {"format", "token", "synthetic"}:
        raise ValueError(f"invalid mask_mode for {name}: {mask_mode}")

    types = system.setdefault("types", ["ALL"])
    if not isinstance(types, list):
        raise TypeError(f"config.systems.{name}.types must be a list")
    _type_list(system, name, "types")
    detect_types = _expand_types(_type_list(system, name, "detect_types") or types)
    mask_types = _expand_types(_type_list(system, name, "mask_types") or types)
    if not mask_types.issubset(detect_types):
        raise ValueError(f"mask_types must be a subset of detect_types for {name}")
    _validate_rules(system, name, detect_types, mask_types)


def _validate(cfg: dict[str, Any]) -> dict[str, Any]:
    systems = cfg.get("systems", {})
    if not isinstance(systems, dict):
        raise TypeError("config.systems must be a mapping")
    for name, system in systems.items():
        if not isinstance(system, dict):
            raise TypeError(f"config.systems.{name} must be a mapping")
        _validate_system(str(name), system)
    return cfg


def load_config() -> dict[str, Any]:
    path = Path(os.getenv("CONFIG_PATH", "config.yaml"))
    if path.exists():
        with path.open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raise TypeError("config root must be a mapping")
        return _validate(raw)
    return deepcopy(DEFAULT_CONFIG)
