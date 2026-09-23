"""Email and phone detectors."""
from __future__ import annotations

import re

from ..candidates import Candidate
from .common import _cand, _digits

EMAIL_RE = re.compile(
    r"(?<![\w.%+\-])[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}?(?:@|%40)"
    r"(?:[A-Za-z0-9А-Яа-яЁё](?:[A-Za-z0-9А-Яа-яЁё\-]{0,61}[A-Za-z0-9А-Яа-яЁё])?\.)+"
    r"(?:[A-Za-z]{2,24}|рф|РФ|рус|РУС|москва|онлайн)(?![\w\-])"
)

PHONE_RE = re.compile(
    r"(?<![\w+])(?:"
    r"(?:\+7|%2[Bb]7|8|7)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"
    r"|\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{2}[\s\-]\d{2}"
    r"|\+(?:3[0-9]{1,2}|9[0-9]{1,2}|1|4[0-9])[\s\-]?\(?\d{2,4}\)?(?:[\s\-]?\d){6,9}"
    r")(?![\d\-])"
)

def detect_email(text: str) -> list[Candidate]:
    if "@" not in text and "%40" not in text:
        return []
    return [_cand(text, m.start(), m.end(), "EMAIL", 0.95, "email_regex") for m in EMAIL_RE.finditer(text)]


def detect_phone(text: str) -> list[Candidate]:
    out = []
    for m in PHONE_RE.finditer(text):
        d = _digits(m.group(0))
        if len(d) < 10 or len(d) > 13:
            continue
        s, e = m.span()
        # «(495) 123-45-67» — скобка без префикса
        score = 0.9 if m.group(0).lstrip().startswith(("+", "8", "7", "(")) else 0.7
        out.append(_cand(text, s, e, "PHONE", score, "phone_regex"))
    return out
