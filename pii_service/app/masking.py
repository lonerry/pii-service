"""Идентификация и маскирование ПД в тексте."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

ALL_TYPES: Tuple[str, ...] = (
    "EMAIL", "CARD", "PHONE", "PASSPORT", "DRIVER", "INN", "CVV", "PIN",
    "DATE", "DATE_TEXT", "FIO", "ADDRESS", "CITIZENSHIP", "BIRTH_PLACE",
    "ISSUER", "DEPT_CODE", "CARDHOLDER",
)
ALL_TYPES_SET = set(ALL_TYPES)


def _mask_digits(text: str, keep_first: int = 0, keep_last: int = 0) -> str:
    positions = [i for i, ch in enumerate(text) if ch.isdigit()]
    total = len(positions)
    keep = set()
    if keep_first:
        keep.update(positions[:keep_first])
    if keep_last:
        keep.update(positions[total - keep_last:])
    return "".join(ch if (not ch.isdigit() or i in keep) else "*" for i, ch in enumerate(text))


def _mask_email(text: str) -> str:
    if "@" not in text:
        return text
    local, domain = text.split("@", 1)
    local_masked = (local[0] + "***") if len(local) > 1 else "*"
    parts = domain.split(".")
    if len(parts) >= 2:
        domain_masked = parts[0][:1] + "***." + ".".join(parts[1:])
    else:
        domain_masked = domain[:1] + "***"
    return f"{local_masked}@{domain_masked}"


def _relative_replace(match: "re.Match[str]", group: int, replacement: str) -> str:
    full = match.group(0)
    g_start, g_end = match.span(group)
    rel_start = g_start - match.start()
    rel_end = g_end - match.start()
    return full[:rel_start] + replacement + full[rel_end:]


def _luhn_ok(digits: str) -> bool:
    s = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b")

PHONE_RE = re.compile(
    r"(?:(?:\+7|8|7)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"
    r"|\b\d{3}[\s\-]\d{3}[\s\-]\d{2}[\s\-]\d{2}\b)"
)

CARD_RE = re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7}\b")

CVV_RE = re.compile(r"(?i)\b(?:cvv|cvc|cvv2|cvc2|код\s+проверки)\b\s{0,4}[:#]?\s{0,4}(\d{3})\b")
PIN_RE = re.compile(r"(?i)\b(?:пин[\s\-]?код|pin)\b\s{0,4}[:#]?\s{0,4}(\d{4})\b")

PASSPORT_RE = re.compile(
    r"(?i)(?:серия\s{1,4})?(\d{2})\s{0,4}(\d{2})\s{0,4}(?:номер\s{1,4})?(\d{4})\s{0,4}(\d{2})\b"
)
DRIVER_RE = re.compile(
    r"(?i)(?:в/у|водительское\s+удостоверение|серия\s{1,4})?(\d{2})\s{0,4}(\d{2})\s{0,4}(\d{6})\b"
)

INN_RE = re.compile(r"(?<!\d)(?:\d{10}|\d{12})(?!\d)")

DATE_NUM_RE = re.compile(
    r"\b(\d{2})[./\-](\d{2})[./\-](\d{4})\b|\b(\d{4})[./\-](\d{2})[./\-](\d{2})\b"
)
DATE_TEXT_RE = re.compile(
    r"\b(\d{1,2})\s+(января|февраля|марта|апреля|мая|июня|июля|августа|"
    r"сентября|октября|ноября|декабря)\s+(\d{4})\b",
    re.IGNORECASE,
)

FIO_RE = re.compile(
    r"\b([А-ЯЁ][а-яё]{1,40}(?:-[А-ЯЁ][а-яё]{1,40})?)\s+"
    r"([А-ЯЁ][а-яё]{1,40}(?:-[А-ЯЁ][а-яё]{1,40})?)\s+"
    r"([А-ЯЁ][а-яё]{1,30}(?:ович|евич|ич|овна|евна|ична|инична))\b"
)

ADDRESS_RE = re.compile(
    r"(?i)\b(г\.|город|ул\.|улица|пер\.|переулок|пр\.|проспект|д\.|дом|"
    r"кв\.|квартира|индекс)\s{0,4}[:#]?\s{0,4}([А-ЯЁа-яё0-9\-]{1,100})"
)

CITIZENSHIP_RE = re.compile(r"(?i)\b(гражданство)\s{0,4}[:#]?\s{0,4}([А-ЯЁа-яё]{1,50}|РФ|Россия)")
BIRTH_PLACE_RE = re.compile(r"(?i)\b(место\s+рождения)\s{0,4}[:#]?\s{0,4}([^,;]{1,200})")
ISSUER_RE = re.compile(r"(?i)\b(орган,?\s*выдавший)\s{0,4}[:#]?\s{0,4}([^,;]{1,200})")
DEPT_CODE_RE = re.compile(r"(?i)\b(код\s+подразделения)\s{0,4}[:#]?\s{0,4}(\d{3}-\d{3})")
CARDHOLDER_RE = re.compile(r"(?i)\b(имя\s+держателя\s+карты)\s{0,4}[:#]?\s{0,4}([A-Za-z\s]{1,100})")


def _mask_card_match(m: "re.Match[str]") -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if len(digits) < 13 or not _luhn_ok(digits):
        return m.group(0)
    return _mask_digits(m.group(0), keep_first=0, keep_last=4)


def _mask_phone_match(m: "re.Match[str]") -> str:
    prefix = 1 if re.match(r"\s*(\+7|8|7)", m.group(0)) else 0
    return _mask_digits(m.group(0), keep_first=prefix, keep_last=2)


def _mask_date_match(m: "re.Match[str]") -> str:
    if re.match(r"^\d{4}", m.group(0)):
        return _mask_digits(m.group(0), keep_first=4)
    return _mask_digits(m.group(0), keep_last=4)


def _mask_date_text_match(m: "re.Match[str]") -> str:
    day, month, year = m.group(1), m.group(2), m.group(3)
    return f"{'*' * len(day)} {'*' * len(month)} {year}"


def _mask_fio_match(m: "re.Match[str]") -> str:
    return " ".join(p[0].upper() + "." for p in m.group(0).split())


def _mask_group(m: "re.Match[str]", group: int) -> str:
    g_start, g_end = m.span(group)
    return _relative_replace(m, group, "*" * (g_end - g_start))


def _mask_dept_code(m: "re.Match[str]") -> str:
    return _relative_replace(m, 2, "***-***")


def _mask_cardholder(m: "re.Match[str]") -> str:
    val = m.group(2)
    masked = " ".join(p[0].upper() + "." for p in val.split() if p)
    return _relative_replace(m, 2, masked)


@dataclass(frozen=True)
class Rule:
    name: str
    regex: "re.Pattern[str]"
    mask_func: Callable[["re.Match[str]"], str]
    priority: int


RULES: Sequence[Rule] = (
    Rule("EMAIL", EMAIL_RE, lambda m: _mask_email(m.group(0)), 100),
    Rule("CARD", CARD_RE, _mask_card_match, 95),
    Rule("PHONE", PHONE_RE, _mask_phone_match, 90),
    Rule("PASSPORT", PASSPORT_RE, lambda m: _mask_digits(m.group(0), keep_first=2, keep_last=2), 85),
    Rule("DRIVER", DRIVER_RE, lambda m: _mask_digits(m.group(0), keep_first=2, keep_last=2), 80),
    Rule("INN", INN_RE, lambda m: _mask_digits(m.group(0), keep_first=2, keep_last=2), 75),
    Rule("CVV", CVV_RE, lambda m: _mask_digits(m.group(0), keep_first=0, keep_last=0), 70),
    Rule("PIN", PIN_RE, lambda m: _mask_digits(m.group(0), keep_first=0, keep_last=0), 70),
    Rule("DATE", DATE_NUM_RE, _mask_date_match, 60),
    Rule("DATE_TEXT", DATE_TEXT_RE, _mask_date_text_match, 60),
    Rule("FIO", FIO_RE, _mask_fio_match, 50),
    Rule("ADDRESS", ADDRESS_RE, lambda m: _mask_group(m, 2), 40),
    Rule("CITIZENSHIP", CITIZENSHIP_RE, lambda m: _mask_group(m, 2), 30),
    Rule("BIRTH_PLACE", BIRTH_PLACE_RE, lambda m: _mask_group(m, 2), 30),
    Rule("ISSUER", ISSUER_RE, lambda m: _mask_group(m, 2), 30),
    Rule("DEPT_CODE", DEPT_CODE_RE, _mask_dept_code, 30),
    Rule("CARDHOLDER", CARDHOLDER_RE, _mask_cardholder, 30),
)

_FIO_SKIP_CTX = re.compile(r"\b(поэт|писатель|художник|композитор|ученый|учёный)\b")
_ADDR_SKIP_CTX = re.compile(r"\b(отделение|банк|офис|филиал)\b")


def _collect_spans(text: str, enabled: set[str]) -> List[Tuple[int, int, int, str, str]]:
    spans: List[Tuple[int, int, int, str, str]] = []
    for rule in RULES:
        if rule.name not in enabled:
            continue
        for m in rule.regex.finditer(text):
            if rule.name == "FIO":
                if _FIO_SKIP_CTX.search(text[max(0, m.start() - 40):m.start()].lower()):
                    continue
            if rule.name == "ADDRESS":
                if _ADDR_SKIP_CTX.search(text[max(0, m.start() - 40):m.start()].lower()):
                    continue
            repl = rule.mask_func(m)
            if repl == m.group(0):
                continue
            spans.append((m.start(), m.end(), rule.priority, rule.name, repl))
    return spans


def _select_non_overlapping(
    spans: Iterable[Tuple[int, int, int, str, str]]
) -> List[Tuple[int, int, int, str, str]]:
    ordered = sorted(spans, key=lambda s: (-s[2], -(s[1] - s[0])))
    accepted: List[Tuple[int, int, int, str, str]] = []
    for span in ordered:
        s, e = span[0], span[1]
        if any(not (e <= a[0] or s >= a[1]) for a in accepted):
            continue
        accepted.append(span)
    return accepted


def mask_text(text: str, enabled_types: Optional[List[str]] = None) -> Tuple[str, List[str]]:
    if enabled_types is None or "ALL" in enabled_types:
        enabled = ALL_TYPES_SET
    else:
        enabled = ALL_TYPES_SET & set(enabled_types)

    accepted = _select_non_overlapping(_collect_spans(text, enabled))
    accepted.sort(key=lambda x: x[0], reverse=True)

    result = text
    found: List[str] = []
    for s, e, _prio, name, repl in accepted:
        result = result[:s] + repl + result[e:]
        found.append(name)
    return result, found
