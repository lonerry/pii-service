"""Единый реестр поддерживаемых типов ПД и их свойств."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class TypeSpec:
    priority: int
    free_text: bool = False
    mask_words: bool = False


TYPE_SPECS: Mapping[str, TypeSpec] = MappingProxyType({
    "EMAIL": TypeSpec(95), "CARD": TypeSpec(100), "PHONE": TypeSpec(80),
    "PASSPORT": TypeSpec(90), "DRIVER": TypeSpec(90), "INN": TypeSpec(85),
    "CVV": TypeSpec(78), "PIN": TypeSpec(78), "DATE": TypeSpec(70),
    "DATE_TEXT": TypeSpec(70), "FIO": TypeSpec(44),
    "ADDRESS": TypeSpec(45, free_text=True),
    "CITIZENSHIP": TypeSpec(40, free_text=True, mask_words=True),
    "BIRTH_PLACE": TypeSpec(50, free_text=True, mask_words=True),
    "ISSUER": TypeSpec(50, free_text=True, mask_words=True),
    "DEPT_CODE": TypeSpec(75), "CARDHOLDER": TypeSpec(60),
    "SNILS": TypeSpec(92), "ACCOUNT": TypeSpec(97),
    "CARD_LAST4": TypeSpec(98), "KPP": TypeSpec(84),
    "OGRN": TypeSpec(83), "MONEY": TypeSpec(72), "BIK": TypeSpec(82),
})

ALL_TYPES = tuple(TYPE_SPECS)
ALL_TYPES_SET = frozenset(TYPE_SPECS)
DATE_TYPES = frozenset({"DATE", "DATE_TEXT"})
UNKNOWN_TYPE_SPEC = TypeSpec(priority=0)


def spec_for(etype: str) -> TypeSpec:
    """Сохранить fail-closed поведение для неизвестного типа кандидата."""
    return TYPE_SPECS.get(etype, UNKNOWN_TYPE_SPEC)
