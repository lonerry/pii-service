"""Загрузка и валидация конфигурации сервиса."""
from __future__ import annotations

import os
from typing import Any, Dict

import yaml

DEFAULT_CONFIG: Dict[str, Any] = {
    "systems": {
        "default": {
            "enabled": True,
            "types": ["ALL"],
            "demask": True,
        }
    }
}

VALID_TYPES = {
    "EMAIL", "CARD", "PHONE", "PASSPORT", "DRIVER", "INN", "CVV", "PIN",
    "DATE", "DATE_TEXT", "FIO", "ADDRESS", "CITIZENSHIP", "BIRTH_PLACE",
    "ISSUER", "DEPT_CODE", "CARDHOLDER", "ALL",
}


def _validate(cfg: Dict[str, Any]) -> Dict[str, Any]:
    systems = cfg.get("systems") or {}
    if not isinstance(systems, dict):
        raise ValueError("config.systems must be a mapping")
    for name, sc in systems.items():
        if not isinstance(sc, dict):
            raise ValueError(f"config.systems.{name} must be a mapping")
        sc.setdefault("enabled", True)
        sc.setdefault("demask", True)
        types = sc.setdefault("types", ["ALL"])
        if not isinstance(types, list):
            raise ValueError(f"config.systems.{name}.types must be a list")
        unknown = [t for t in types if t not in VALID_TYPES]
        if unknown:
            raise ValueError(f"unknown PII types for {name}: {unknown}")
    return cfg


def load_config() -> Dict[str, Any]:
    path = os.getenv("CONFIG_PATH", "config.yaml")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return _validate(raw)
    return DEFAULT_CONFIG
