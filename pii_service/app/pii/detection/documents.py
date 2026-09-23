"""Identity-document detectors."""
from __future__ import annotations

import re

from ..candidates import Candidate, SpanIndex
from ..windows import DOCUMENT_HINT, left_window
from .common import _cand

DOC10_RE = re.compile(
    r"(?<![\d\w])(\d{2}\s?\d{2}|\d{2}\s?[А-ЯA-Z]{2})[\s№]{0,3}(\d{4}\s?\d{2}|\d{6})(?![\d\w])"
)
PASSPORT_LABELED_RE = re.compile(
    r"(?i)(?:сери[ейя]+\s*(?:и\s+номер\w*\s*)?(?:паспорта\s*)?[:№]?\s*)"
    r"(\d{2}\s?\d{2})[\s,;.]*(?:и\s+)?(?:(?:№|номер\w*|n)\s*[:№]?\s*)(\d{6})(?!\d)"
)
PASSPORT_NUM_ONLY_RE = re.compile(r"(?i)(?:номер\s+паспорта|паспорт\s*(?:№|номер))\s*[:№]?\s*(\d{6})(?!\d)")
PASSPORT_SERIES_ONLY_RE = re.compile(r"(?i)серия\s+паспорта\s*[:№]?\s*(\d{2}\s?\d{2})(?!\d)")
# «Данные паспорта: серия 45 12» — «паспорт» упомянут раньше, не сразу перед «серия»,
# и номер вообще отсутствует (только серия).
_PASSPORT_CTX_RE = re.compile(r"(?i)паспорт\w*|документ\w*")
SERIES_ONLY_CTX_RE = re.compile(r"(?i)(?<![\w])сери[ейя]+\s*[:№]?\s*(\d{2}\s?\d{2})(?!\d)")
FOREIGN_PASSPORT_RE = re.compile(
    r"(?i)(загран\w*|заграничн\w+\s+паспорт\w*|international\s+passport)[\s:№]{0,8}(\d{2}\s?\d{7})(?!\d)"
)
MILITARY_ID_RE = re.compile(r"(?i)(военн\w+\s+билет\w*)[\s:№]{0,8}([А-Я]{2}\s?\d{7})(?!\d)")
DEPT_CODE_RE = re.compile(r"(?<![\d\-])\d{3}\s?-\s?\d{3}(?![\d\-])")

_DRIVER_HINT = re.compile(r"(?i)(?:в/у|\bву\b|водительск\w*|удостоверени\w*|прав[аы]?\b|driver|licen[cs]e)")
_PASSPORT_HINT = re.compile(r"(?i)(?:паспорт\w*|серия|выдан\w*|passport)")
def _document_hint(win: str) -> tuple[str, re.Match[str] | None]:
    """Тип документа по ближайшей метке в той же клаузе."""
    driver = list(_DRIVER_HINT.finditer(win))
    passport = list(_PASSPORT_HINT.finditer(win))
    if driver and (not passport or driver[-1].end() > passport[-1].end()):
        return "DRIVER", driver[-1]
    return "PASSPORT", passport[-1] if passport else None


def detect_documents(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    for m in PASSPORT_LABELED_RE.finditer(text):
        win, _ = left_window(text, m.start(), DOCUMENT_HINT, skip_abbreviations=False)
        etype, _ = _document_hint(win)
        out.append(_cand(text, m.start(1), m.end(2), etype, 0.95, "doc_series_number",
                         anchor=m.start(), labeled=True))
    for rx, etype, src in ((PASSPORT_NUM_ONLY_RE, "PASSPORT", "passport_number_label"),
                           (PASSPORT_SERIES_ONLY_RE, "PASSPORT", "passport_series_label")):
        for m in rx.finditer(text):
            out.append(_cand(text, m.start(1), m.end(1), etype, 0.9, src, anchor=m.start(), labeled=True))
    # «Данные паспорта: серия 45 12» — «паспорт» упомянут раньше в тексте, номер отсутствует
    taken_series = SpanIndex((c.start, c.end) for c in out)
    for m in SERIES_ONLY_CTX_RE.finditer(text):
        s, e = m.span(1)
        if taken_series.overlaps(s, e):
            continue
        win, _ = left_window(text, m.start(), DOCUMENT_HINT, skip_abbreviations=False)
        if not _PASSPORT_CTX_RE.search(win):
            continue
        out.append(_cand(text, s, e, "PASSPORT", 0.8, "passport_series_ctx", anchor=m.start(), labeled=True))
    for rx, etype in ((FOREIGN_PASSPORT_RE, "PASSPORT"), (MILITARY_ID_RE, "PASSPORT")):
        for m in rx.finditer(text):
            out.append(_cand(text, m.start(2), m.end(2), etype, 0.9, "doc_labeled",
                             anchor=m.start(1), labeled=True))
    for m in DOC10_RE.finditer(text):
        s, e = m.span()
        raw = m.group(0)
        letters = any(ch.isalpha() for ch in m.group(1))
        win, win_lo = left_window(text, s, DOCUMENT_HINT, skip_abbreviations=False)
        etype, hint = _document_hint(win)
        if letters:
            etype = "DRIVER"
            hint = next(reversed(list(_DRIVER_HINT.finditer(win))), None)
        spaced = " " in raw
        # «45 06 123456» / «4506 123456» — типичная запись документа; 10 цифр подряд
        # без контекста (часто ИНН юрлица / внутренний ID) — слабый кандидат.
        score = 0.7 if spaced else 0.45
        c = _cand(text, s, e, etype, score, "doc10_regex")
        if hint is not None:
            c.anchor = win_lo + hint.start()
            c.labeled = True
            c.score = 0.9
        out.append(c)
    return out


def detect_dept_code(text: str) -> list[Candidate]:
    out = []
    for m in DEPT_CODE_RE.finditer(text):
        out.append(_cand(text, m.start(), m.end(), "DEPT_CODE", 0.4, "dept_code_regex"))
    return out
