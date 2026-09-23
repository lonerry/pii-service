"""Общие структуры pipeline: кандидат ПД и решение политики.

Detector находит только candidate (тип + span + confidence). Решение
MASK/KEEP принимает Policy Engine по результатам context/owner resolver-ов.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass
from dataclasses import field as dc_field
from enum import Enum


class Owner(str, Enum):
    CUSTOMER = "CUSTOMER"
    EMPLOYEE_PERSONAL = "EMPLOYEE_PERSONAL"
    BANK_BRANCH = "BANK_BRANCH"
    ORGANIZATION = "ORGANIZATION"
    PUBLIC = "PUBLIC"
    UNKNOWN = "UNKNOWN"
    INTERNAL_ID = "INTERNAL_ID"


class DateRole(str, Enum):
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    PASSPORT_DATE = "PASSPORT_DATE"
    MEETING_DATE = "MEETING_DATE"
    DELIVERY_DATE = "DELIVERY_DATE"
    CARD_ISSUE_DATE = "CARD_ISSUE_DATE"
    PIN_SET_DATE = "PIN_SET_DATE"
    OTHER = "OTHER"


class Action(str, Enum):
    MASK = "MASK"
    KEEP = "KEEP"


CUSTOMER = Owner.CUSTOMER
EMPLOYEE_PERSONAL = Owner.EMPLOYEE_PERSONAL
BANK_BRANCH = Owner.BANK_BRANCH
ORGANIZATION = Owner.ORGANIZATION
PUBLIC = Owner.PUBLIC
UNKNOWN = Owner.UNKNOWN
INTERNAL_ID = Owner.INTERNAL_ID
NON_PERSONAL_OWNERS = frozenset({BANK_BRANCH, ORGANIZATION, PUBLIC, INTERNAL_ID})

DATE_OF_BIRTH = DateRole.DATE_OF_BIRTH
PASSPORT_DATE = DateRole.PASSPORT_DATE
MEETING_DATE = DateRole.MEETING_DATE
DELIVERY_DATE = DateRole.DELIVERY_DATE
CARD_ISSUE_DATE = DateRole.CARD_ISSUE_DATE
PIN_SET_DATE = DateRole.PIN_SET_DATE
OTHER = DateRole.OTHER

MASK = Action.MASK
KEEP = Action.KEEP


@dataclass
class Candidate:
    start: int
    end: int
    etype: str               # тип из pii.types.ALL_TYPES
    text: str                # == original[start:end]
    score: float             # confidence детектора, 0..1
    source: str              # имя детектора
    anchor: int = -1         # начало метки ("CVV", "адрес клиента"), если детектор её видел
    labeled: bool = False    # детектор нашёл явную метку типа рядом со значением
    field: str | None = None   # имя поля структурированного входа
    owner: Owner = UNKNOWN
    role: DateRole = OTHER
    signals: list[str] = dc_field(default_factory=list)
    action: Action = KEEP
    # Google DLP / MS Purview style: именованные "улики" (+/-), а не разрозненные
    # if/elif-мутации score. Detector кладёт базовые (regex/checksum/format),
    # context.py — контекстные (label, owner, negative_context). Итог — effective_score.
    # Пустой evidence (для типов, ещё не переведённых на эту схему) → effective_score == score,
    # т.е. обратная совместимость без единой правки в остальных ~20 типах.
    evidence: dict[str, float] = dc_field(default_factory=dict)

    @property
    def effective_score(self) -> float:
        return max(0.0, min(1.0, self.score + sum(self.evidence.values())))

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Candidate) -> bool:
        return self.start < other.end and other.start < self.end


class SpanIndex:
    """Индекс интервалов для проверки пересечений за ~O(log n).

    Длина кандидата ограничена (значения свободных полей ≤ ~300 символов),
    поэтому при поиске достаточно просмотреть интервалы, начинающиеся не
    дальше MAX_SPAN левее запроса.
    """

    MAX_SPAN = 1000

    def __init__(self, spans=()) -> None:
        self._s: list[int] = []
        self._e: list[int] = []
        for s, e in spans:
            self.add(s, e)

    def add(self, s: int, e: int) -> None:
        i = bisect.bisect_left(self._s, s)
        self._s.insert(i, s)
        self._e.insert(i, e)

    def overlaps(self, s: int, e: int) -> bool:
        j = bisect.bisect_left(self._s, e) - 1
        while j >= 0 and self._s[j] >= s - self.MAX_SPAN:
            if self._e[j] > s:
                return True
            j -= 1
        return False

    def contains_point(self, p: int) -> bool:
        return self.overlaps(p, p + 1)
