"""Detection driven by structured field names."""
from __future__ import annotations

import re
from collections.abc import Sequence

from ..candidates import Candidate
from ..structure import Field, classify_key
from .common import _cand
from .freetext import _trim

_FREE_FIELD_TYPES = {"FIO", "ADDRESS", "BIRTH_PLACE", "ISSUER", "CARDHOLDER", "CITIZENSHIP", "CVV", "PIN",
                     "PASSPORT", "DRIVER", "DEPT_CODE", "SNILS", "INN"}


def detect_field_values(text: str, fields: Sequence[Field]) -> list[Candidate]:
    """Structured-field detection: значение поля, имя которого описывает тип ПД."""
    out = []
    for f in fields:
        info = classify_key(f.key)
        if info.etype not in _FREE_FIELD_TYPES:
            continue
        s, e = _trim(text, f.start, f.end)
        val = text[s:e]
        if not val or val.lower() in ("null", "none", "true", "false", "-", "n/a"):
            continue
        if info.etype in ("CVV", "PIN", "DEPT_CODE", "SNILS", "INN", "PASSPORT", "DRIVER") and not re.fullmatch(
            r"[\d\s\-№A-ZА-Я]{3,20}", val
        ):
            continue
        c = _cand(text, s, e, info.etype, 0.85, "structured_field", anchor=f.start, labeled=True)
        c.field = f.key
        out.append(c)
    return out
