"""Payment-card, tax, banking, and monetary detectors."""
from __future__ import annotations

import re

from ..candidates import Candidate, SpanIndex
from ..heuristics import (
    INN_EV_CHECKSUM,
    INN_EV_DASHED_SHAPE,
    INN_EV_FORMAT10,
    INN_EV_FORMAT12,
    INN_EV_LABEL,
    INN_EV_REGEX,
)
from .common import _cand, _digits, inn_ok, luhn_ok, snils_ok

CARD_RE = re.compile(r"(?<![\d\-])\d{4}(?:[\s\-]?\d{4}){2}[\s\-]?\d{1,7}(?![\d\-])")
CARD_LAST4_LABEL_RE = re.compile(
    r"(?i)(?<![\w])последн\w*\s+4\s+цифр\w*(?:\s+(?:номера\s+)?карты)?(?![\w])[\s:№=\-–—]*(\d{4})(?!\d)"
)

# [cс]vv/[cс]vc — допускаем кириллическую «с» вместо латинской «c» (частый confusable/опечатка).
_CVV_LABEL = (r"[cс]vv2?|[cс]vc2?|цвв|сививи|си-?в-?и-?в-?и|[cс]vv\s*/\s*[cс]vc|[cс]vc\s*/\s*[cс]vv|"
              r"код\s+проверки(?:\s+подлинности)?|"
              r"защитный\s+код(?:\s+карты)?|код\s+безопасности(?:\s+карты)?|"
              r"security\s+code|card\s+verification(?:\s+code)?|трёхзначный\s+код|трехзначный\s+код|"
              r"код\s+на\s+обороте(?:\s+карты)?")
# значение МОЖЕТ стоять до метки: «258 cvv», «код 258 сvv»
CVV_BEFORE_RE = re.compile(
    rf"(?i)(?<!\d)(\d{{3,4}})(?!\d)[ \t]*(?:код[ \t]+)?(?:{_CVV_LABEL})(?![\w])"
)
# между меткой и значением допускаем до 3 слов-уточнений
# («CVV указан код 123», «CVV значение 123», «CVV равен 123»)
CVV_RE = re.compile(
    rf"(?i)(?<![\w])({_CVV_LABEL})(?![\w])(?:[\s\-–—]+\w+){{0,3}}?[\s:#№=\-–—]*(?:карты\s+)?(\d{{3,4}})(?!\d)"
)
_PIN_LABEL = (r"п\.\s?и\.\s?н\.\s?к\.\s?о\.\s?д\.?|"  # «п.и.н.к.о.д.» — по буквам через точку
              r"пин[\s\-]*код(?:а)?|pin[\s\-]?code|pin[\s\-]?код|пин|pin|"
              r"код\s+доступа\s+к\s+карт[еыа]|pin\s+карты|пин\s+карты")
# между меткой и значением допускаем до 3 слов-уточнений («ПИН первой карты: 1234»)
# и произвольное количество пробелов перед значением («Пин Код:    1234»)
PIN_RE = re.compile(
    rf"(?i)(?<![\w])({_PIN_LABEL})(?![\w])(?:[\s\-–—]+\w+){{0,3}}?[\s:#№=\-–—.]*(\d{{4,6}})(?!\d)"
)

# 2+2+6 цифр (паспорт РФ / в/у нового образца), либо 2 цифры + 2 буквы + 6 цифр (в/у старого).
# номер документа также встречается в разбивке 4+2 с пробелом («45 10 1234 56»),
# а не только слитными 6 цифрами.

INN_RE = re.compile(r"(?<![\d\w])(?:\d{12}|\d{10})(?![\d\w])")
# ИНН с проборными группами: «7712 3456 7859» (10 или 12 цифр)
INN_SPACED_RE = re.compile(r"(?i)(?<![\w])инн\W{0,3}((?:\d{2,4}\s){1,3}\d{2,4})(?!\d)")
# «инн7712345678» — метка и цифры склеены без разделителя вообще
INN_GLUED_RE = re.compile(r"(?i)(?<![\wа-яё])(?:инн|inn)(\d{12}|\d{10})(?!\d)")
# «ИНН/КПП 7712345671/771201001» — оба значения через слэш одним блоком
INN_KPP_COMBINED_RE = re.compile(
    r"(?i)(?<![\w])инн\s*/\s*кпп(?![\w])[\s:№=\-–—]*(\d{10})\s*/\s*(\d{9})(?!\d)"
)
KPP_RE = re.compile(r"(?i)(?<![\w])кпп(?![\w])[\s:№=\-–—]*(\d{9})(?!\d)")
OGRN_RE = re.compile(r"(?i)(?<![\w])огрн(?:ип)?(?![\w])[\s:№=\-–—]*(\d{13,15})(?!\d)")
BIK_RE = re.compile(r"(?i)(?<![\w])бик(?![\w])[\s:№=\-–—]*(\d{9})(?!\d)")
# «5004-0567-8951» — 12 цифр, сгруппированных дефисами по 4 (без метки «ИНН»);
# по формату — чувствительный идентификатор того же класса, что и ИНН.
INN_DASHED_RE = re.compile(r"(?<![\d\-])\d{4}-\d{4}-\d{4}(?![\d\-])")

# Денежные суммы с явным денежным контекстом (валюта до или после числа).
MONEY_RE = re.compile(
    r"(?i)(?<![\w])(?:\d[\d\s.,]{0,18}\d|\d)\s*(?:руб(?:лей|ля|ль)?\.?|₽|usd|eur|€)(?![\w])"
    r"|(?<![\w])(?:\$|€)\s*(?:\d[\d\s.,]{0,18}\d|\d)(?![\w])"
)
SNILS_RE = re.compile(r"(?<![\d\-])\d{3}[\-\s]\d{3}[\-\s]\d{3}[\-\s]\d{2}(?![\d\-])")

# Банковский счёт (20 цифр РФ) с явной меткой.
ACCOUNT_LABEL_RE = re.compile(
    r"(?i)(?<![\w])(?:р/с|расч[её]тный\s+сч[её]т|номер\s+сч[её]та|сч[её]т|account(?:\s+number)?|iban)"
    r"(?![\w])[\s:№=\-–—]{0,6}((?:\d{16,26}|\d{4}(?:[\s\-]\d{4}){3}))(?!\d)"
)

def detect_card(text: str) -> list[Candidate]:
    out = []
    for m in CARD_RE.finditer(text):
        d = _digits(m.group(0))
        if not 13 <= len(d) <= 19:
            continue
        ok = luhn_ok(d)
        # Luhn-невалидный номер остаётся кандидатом только с явным карточным контекстом
        # (решает context resolver): опечатка в номере карты — всё ещё ПД.
        c = _cand(text, m.start(), m.end(), "CARD", 0.95 if ok else 0.35, "card_luhn" if ok else "card_regex")
        c.signals.append("luhn_ok" if ok else "luhn_fail")
        out.append(c)
        if ok:
            # «4276380012345678 1234» — 4 цифры сразу после валидной карты — вероятный PIN
            tail = text[m.end():m.end() + 8]
            pm = re.match(r"\s+(\d{4})(?!\d)", tail)
            if pm:
                s = m.end() + pm.start(1)
                e = m.end() + pm.end(1)
                out.append(_cand(text, s, e, "PIN", 0.75, "card_adjacent_pin",
                                 anchor=m.start(), labeled=True))
    return out


def detect_card_last4(text: str) -> list[Candidate]:
    out = []
    for m in CARD_LAST4_LABEL_RE.finditer(text):
        out.append(_cand(text, m.start(1), m.end(1), "CARD_LAST4", 0.9, "card_last4_label",
                         anchor=m.start(), labeled=True))
    return out


_CVV_LABEL_RE = re.compile(rf"(?i){_CVV_LABEL}")


def detect_cvv_pin(text: str) -> list[Candidate]:
    out = []
    low_hint = text.lower()
    taken = SpanIndex()
    if _CVV_LABEL_RE.search(text):
        for m in CVV_RE.finditer(text):
            s, e = m.span(2)
            out.append(_cand(text, s, e, "CVV", 0.9, "cvv_label", anchor=m.start(1), labeled=True))
            taken.add(s, e)
        # значение до метки: «258 cvv», «код 258 сvv»
        for m in CVV_BEFORE_RE.finditer(text):
            s, e = m.span(1)
            if taken.overlaps(s, e):
                continue
            if e - s == 4 and re.search(
                r"(?i)(?:дата\s+рождения|рождени\w*)\D{0,16}$",
                text[max(0, s - 32):s],
            ):
                continue
            out.append(_cand(text, s, e, "CVV", 0.9, "cvv_before_label", anchor=m.start(), labeled=True))
            taken.add(s, e)
    if "пин" in low_hint or "pin" in low_hint or "код доступа" in low_hint or "п.и.н" in low_hint:
        for m in PIN_RE.finditer(text):
            s, e = m.span(2)
            out.append(_cand(text, s, e, "PIN", 0.75, "pin_label", anchor=m.start(1), labeled=True))
    return out

def _inn_candidate(text: str, start: int, end: int, source: str, *,
                   anchor: int = -1, labeled: bool = False,
                   dashed: bool = False) -> Candidate:
    digits = _digits(text[start:end])
    valid = inn_ok(digits)
    if source == "inn_format":
        source = "inn_checksum" if valid else source
    c = _cand(text, start, end, "INN", 0.0, source, anchor=anchor, labeled=labeled)
    c.evidence["regex"] = INN_EV_REGEX
    is_twelve = len(digits) == 12
    c.evidence["format_12" if is_twelve else "format_10"] = INN_EV_FORMAT12 if is_twelve else INN_EV_FORMAT10
    if labeled and not dashed:
        c.evidence["label"] = INN_EV_LABEL
    if dashed:
        c.evidence["dashed_shape"] = INN_EV_DASHED_SHAPE
    c.signals.append("inn12" if is_twelve else "inn10")
    if valid:
        c.evidence["checksum"] = INN_EV_CHECKSUM
        c.signals.append("checksum_ok")
    return c


def detect_inn(text: str) -> list[Candidate]:
    """ИНН по четырём форматам с общей оценкой regex, формата и checksum."""
    out: list[Candidate] = []
    taken = SpanIndex()
    formats = (
        (INN_RE, 0, "inn_format", False, False),
        (INN_SPACED_RE, 1, "inn_spaced", True, False),
        (INN_GLUED_RE, 1, "inn_glued", True, False),
        (INN_DASHED_RE, 0, "inn_dashed", True, True),
    )
    for regex, group, source, labeled, dashed in formats:
        for match in regex.finditer(text):
            start, end = match.span(group)
            if taken.overlaps(start, end):
                continue
            digits = _digits(text[start:end])
            if len(digits) not in (10, 12):
                continue
            anchor = match.start() if labeled and not dashed else -1
            out.append(_inn_candidate(text, start, end, source, anchor=anchor,
                                      labeled=labeled, dashed=dashed))
            taken.add(start, end)
    return out


def detect_money(text: str) -> list[Candidate]:
    out = []
    for m in MONEY_RE.finditer(text):
        out.append(_cand(text, m.start(), m.end(), "MONEY", 0.85, "money_regex", labeled=True))
    return out


def detect_kpp_ogrn(text: str) -> list[Candidate]:
    """КПП/ОГРН/БИК — банковские/организационные реквизиты; маскируются всегда."""
    out = []
    taken = SpanIndex()
    for m in INN_KPP_COMBINED_RE.finditer(text):
        out.append(_cand(text, m.start(1), m.end(1), "INN", 0.9, "inn_kpp_combined",
                         anchor=m.start(), labeled=True))
        out.append(_cand(text, m.start(2), m.end(2), "KPP", 0.9, "inn_kpp_combined",
                         anchor=m.start(), labeled=True))
        taken.add(m.start(2), m.end(2))
    for m in KPP_RE.finditer(text):
        s, e = m.span(1)
        if taken.overlaps(s, e):
            continue
        out.append(_cand(text, s, e, "KPP", 0.85, "kpp_label", anchor=m.start(), labeled=True))
    for m in OGRN_RE.finditer(text):
        out.append(_cand(text, m.start(1), m.end(1), "OGRN", 0.85, "ogrn_label",
                         anchor=m.start(), labeled=True))
    for m in BIK_RE.finditer(text):
        out.append(_cand(text, m.start(1), m.end(1), "BIK", 0.85, "bik_label",
                         anchor=m.start(), labeled=True))
    return out


def detect_account(text: str) -> list[Candidate]:
    out = []
    for m in ACCOUNT_LABEL_RE.finditer(text):
        out.append(_cand(text, m.start(1), m.end(1), "ACCOUNT", 0.9, "account_label",
                         anchor=m.start(), labeled=True))
    return out


def detect_snils(text: str) -> list[Candidate]:
    out = []
    for m in SNILS_RE.finditer(text):
        d = _digits(m.group(0))
        ok = snils_ok(d)
        out.append(_cand(text, m.start(), m.end(), "SNILS", 0.9 if ok else 0.5, "snils"))
    return out
