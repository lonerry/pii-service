"""Numeric, written, and context-sensitive date detectors."""
from __future__ import annotations

import re

from ..candidates import Candidate
from ..windows import FUZZY_DATE_RIGHT
from .common import _cand

MONTH_FULL_TO_NUM = {
    "января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5, "июня": 6,
    "июля": 7, "августа": 8, "сентября": 9, "октября": 10, "ноября": 11, "декабря": 12,
}
MONTH_ABBR_TO_NUM = {
    "янв": 1, "фев": 2, "мар": 3, "апр": 4, "май": 5, "мая": 5, "июн": 6,
    "июл": 7, "авг": 8, "сен": 9, "окт": 10, "ноя": 11, "дек": 12,
}
# длинные формы обязаны идти раньше сокращений, иначе "марта" срежется до "мар"
_MONTHS_ANY = "|".join(sorted(MONTH_FULL_TO_NUM.keys(), key=len, reverse=True)) + \
    "|" + "|".join(sorted({k + r"\.?" for k in MONTH_ABBR_TO_NUM}, key=len, reverse=True))


def _month_num(token: str) -> int | None:
    low = token.lower().rstrip(".")
    if low in MONTH_FULL_TO_NUM:
        return MONTH_FULL_TO_NUM[low]
    return MONTH_ABBR_TO_NUM.get(low)


DATE_NUM_RE = re.compile(
    r"(?<![\d.\-/])(?:"
    r"(\d{1,2})[./\-\s](\d{1,2})[./\-\s](\d{4})"        # DD.MM.YYYY / MM/DD/YYYY (US)
    r"|(\d{1,2})[./\-\s](\d{1,2})[./\-\s](\d{2})(?!\d)"  # DD.MM.YY
    r"|(\d{4})[./\-\s](\d{2})[./\-\s](\d{2})"           # YYYY-MM-DD
    r")(?![\d])"
)
# день + месяц (буквами) + опциональный год (2 или 4 цифры)
DATE_TEXT_RE = re.compile(
    rf"(?i)(?<![\d])(\d{{1,2}})[\s\-]+({_MONTHS_ANY})(?![а-яё])"
    rf"(?:[\s\-]+(\d{{2,4}}))?(?:\s*(?:г\.|года|год\b))?"
)

# день+месяц без года (только в сильном контексте «паспорт выдан»/«дата выдачи паспорта»)
_PASSPORT_ISSUE_CTX_RE = re.compile(
    r"(?i)паспорт\w*\s+выдан\w*|дата\s+выдачи\s+паспорта|дата\s+рождения(?:\s*\([^)]*\))?"
)
DATE_DM_NUM_RE = re.compile(r"(?<![\d.\-/])(\d{1,2})[./\-\s](\d{1,2})(?!\d)(?![./\-]\d)")

# OCR/confusable-варианты месяца («15 Mмм 1990») — только в сильном контексте.
_STRONG_DOB_CTX_RE = re.compile(r"(?i)дата\s+рождения|дата\s+выдачи\s+паспорта|паспорт\w*\s+выдан\w*")
_MIXED_DATE_TEXT_RE = re.compile(r"(?<!\d)(\d{1,2})[\s\-]+([A-Za-zА-Яа-яЁё]{2,6})[\s\-]+(\d{4})(?!\d)")

def _valid_date(d: int, mth: int, y: int | None) -> bool:
    if not (1 <= d <= 31 and 1 <= mth <= 12):
        return False
    return y is None or 1900 <= y <= 2100


def _expand_year(y: int) -> int:
    """Двузначный год → полный (00-30 => 2000+, 31-99 => 1900+)."""
    if y >= 100:
        return y
    return 2000 + y if y <= 30 else 1900 + y


def _numeric_dates(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    for m in DATE_NUM_RE.finditer(text):
        if m.group(1):
            day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        elif m.group(4):
            day, month, year = int(m.group(4)), int(m.group(5)), _expand_year(int(m.group(6)))
        else:
            year, month, day = int(m.group(7)), int(m.group(8)), int(m.group(9))
        if not _valid_date(day, month, year) and _valid_date(month, day, year):
            day, month = month, day
        if not _valid_date(day, month, year):
            continue
        c = _cand(text, m.start(), m.end(), "DATE", 0.9, "date_numeric")
        c.signals.append(f"year:{year}")
        out.append(c)
    return out


def _written_dates(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    for m in DATE_TEXT_RE.finditer(text):
        day = int(m.group(1))
        month = _month_num(m.group(2))
        if month is None or not 1 <= day <= 31:
            continue
        year_raw = m.group(3)
        if year_raw:
            year = _expand_year(int(year_raw))
            if not _valid_date(day, month, year):
                continue
            end = m.end(3)
            signal = f"year:{year}"
        else:
            end = m.end(2)
            signal = "no_year"
        c = _cand(text, m.start(), end, "DATE_TEXT", 0.85 if year_raw else 0.5, "date_text")
        c.signals.append(signal)
        out.append(c)
    return out


def _passport_day_month_dates(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    for context in _PASSPORT_ISSUE_CTX_RE.finditer(text):
        start = context.end()
        match = DATE_DM_NUM_RE.search(text, start, min(len(text), start + 30))
        if match is None:
            continue
        day, month = int(match.group(1)), int(match.group(2))
        if not (1 <= day <= 31 and 1 <= month <= 12):
            continue
        c = _cand(text, match.start(), match.end(), "DATE", 0.85, "passport_dm_date",
                  anchor=context.start(), labeled=True)
        c.signals.append("passport_issue_dm")
        out.append(c)
    return out


def _contextual_fuzzy_dates(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    for context in _STRONG_DOB_CTX_RE.finditer(text):
        start = context.end()
        match = _MIXED_DATE_TEXT_RE.search(text, start, min(len(text), start + FUZZY_DATE_RIGHT))
        if match is None:
            continue
        day, year = int(match.group(1)), int(match.group(3))
        if not (1 <= day <= 31 and 1900 <= year <= 2100):
            continue
        c = _cand(text, match.start(), match.end(), "DATE_TEXT", 0.8, "dob_fuzzy_month",
                  anchor=context.start(), labeled=True)
        c.signals.append(f"year:{year}")
        out.append(c)
    return out


def detect_dates(text: str) -> list[Candidate]:
    """Собрать даты из независимых форматных стратегий."""
    return (_numeric_dates(text) + _written_dates(text) +
            _passport_day_month_dates(text) + _contextual_fuzzy_dates(text))
