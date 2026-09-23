"""Policy Engine (Nightfall-style): Detector → Context → Policy → MASK/KEEP.

Detectors и regex ничего не решают; действие определяется здесь по
(тип, confidence, owner, role) и разрешённым для системы типам.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from .candidates import (
    CARD_ISSUE_DATE,
    DATE_OF_BIRTH,
    INTERNAL_ID,
    KEEP,
    MASK,
    NON_PERSONAL_OWNERS,
    PASSPORT_DATE,
    PIN_SET_DATE,
    PUBLIC,
    UNKNOWN,
    Candidate,
)
from .profiles import threshold


@dataclass(frozen=True)
class Policy:
    detection_profile: str = "balanced"
    mode: str = "format"
    mask_types: frozenset[str] | None = None
    rules: Mapping[str, frozenset[str]] = field(default_factory=dict)
    # owner-ы, при которых значение НЕ маскируется
    keep_owners: dict[str, frozenset[str]] = field(default_factory=lambda: {
        "ADDRESS": NON_PERSONAL_OWNERS,
        "PHONE": NON_PERSONAL_OWNERS,
        "EMAIL": NON_PERSONAL_OWNERS,
        # FIO: маскируем всегда, кроме PUBLIC — а PUBLIC требует ОБА одновременно:
        # справочник известных персон И контекст профессии/биографии рядом (см. context.py).
        # «Голый» текст (только имя и больше ничего) НЕ освобождает от маски — по явному
        # решению маскировать ФИО всегда, если это не точно установленная публичная персона.
        "FIO": frozenset({PUBLIC}),
        # INN/KPP/OGRN: маскируем всегда, включая реквизиты организации/поставщика/ООО —
        # owner ORGANIZATION больше не освобождает от маски.
    })
    default_keep_owners: frozenset[str] = frozenset({INTERNAL_ID})
    sensitive_date_roles: frozenset[str] = frozenset(
        {DATE_OF_BIRTH, PASSPORT_DATE, CARD_ISSUE_DATE, PIN_SET_DATE})

    def decide(
        self, c: Candidate, enabled: Iterable[str], present_types: frozenset[str] = frozenset()
    ) -> tuple[str, str]:
        if c.etype not in enabled:
            return KEEP, "type_disabled"
        if self.mask_types is not None and c.etype not in self.mask_types:
            return KEEP, "mask_type_disabled"
        required = self.rules.get(c.etype)
        if required and not required.issubset(present_types):
            return KEEP, "rule_requires"
        if c.etype == "MONEY":
            return KEEP, "not_pii"
        if c.owner in self.keep_owners.get(c.etype, self.default_keep_owners):
            return KEEP, f"owner:{c.owner}"
        if c.etype in ("DATE", "DATE_TEXT"):
            if c.role in self.sensitive_date_roles:
                return MASK, f"role:{c.role}"
            return KEEP, f"role:{c.role}"
        if c.etype == "ADDRESS" and c.owner == UNKNOWN and not c.labeled and not re.search(r"\d", c.text):
            # только город/улица без дома и без явной метки — не адрес конкретного лица
            return KEEP, "address_too_generic"
        required_score = threshold(self.detection_profile, c.etype)
        if c.score <= 0:
            return KEEP, "ctx_suppressed"
        if c.effective_score < required_score:
            return KEEP, "low_score"
        return MASK, "policy"


DEFAULT_POLICY = Policy()
