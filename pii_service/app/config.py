"""Загрузка и валидация конфигурации сервиса."""
from __future__ import annotations

import os
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


def _validate(cfg: dict[str, Any]) -> dict[str, Any]:
    systems = cfg.get("systems") or {}
    if not isinstance(systems, dict):
        raise TypeError("config.systems must be a mapping")
    for name, sc in systems.items():
        if not isinstance(sc, dict):
            raise TypeError(f"config.systems.{name} must be a mapping")
        sc.setdefault("enabled", True)
        sc.setdefault("demask", True)
        profile = sc.setdefault("detection_profile", "balanced")
        if profile not in VALID_PROFILES:
            raise ValueError(f"invalid detection_profile for {name}: {profile}")
        mask_mode = sc.setdefault("mask_mode", "format")
        if mask_mode not in {"format", "token", "synthetic"}:
            raise ValueError(f"invalid mask_mode for {name}: {mask_mode}")
        types = sc.setdefault("types", ["ALL"])
        if not isinstance(types, list):
            raise TypeError(f"config.systems.{name}.types must be a list")
        unknown = [t for t in types if t not in VALID_TYPES]
        if unknown:
            raise ValueError(f"unknown PII types for {name}: {unknown}")
        for key in ("detect_types", "mask_types"):
            selected = sc.get(key)
            if selected is None:
                continue
            if not isinstance(selected, list):
                raise TypeError(f"config.systems.{name}.{key} must be a list")
            unknown = [typ for typ in selected if typ not in VALID_TYPES]
            if unknown:
                raise ValueError(f"unknown PII types for {name}.{key}: {unknown}")
        detect_types = set(sc.get("detect_types") or types)
        mask_types = set(sc.get("mask_types") or types)
        if "ALL" in detect_types:
            detect_types = set(REGISTRY.supported_types)
        if "ALL" in mask_types:
            mask_types = set(REGISTRY.supported_types)
        if not mask_types.issubset(detect_types):
            raise ValueError(f"mask_types must be a subset of detect_types for {name}")
        rules = sc.setdefault("rules", [])
        if not isinstance(rules, list):
            raise TypeError(f"config.systems.{name}.rules must be a list")
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("type") not in VALID_TYPES:
                raise ValueError(f"invalid policy rule for {name}")
            requires = rule.setdefault("requires", [])
            if not isinstance(requires, list) or any(typ not in VALID_TYPES for typ in requires):
                raise ValueError(f"invalid policy rule requirements for {name}")
            if rule["type"] not in mask_types or not set(requires).issubset(detect_types):
                raise ValueError(f"policy rule uses disabled types for {name}")
    return cfg


def load_config() -> dict[str, Any]:
    path = os.getenv("CONFIG_PATH", "config.yaml")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return _validate(raw)
    return DEFAULT_CONFIG
