"""Context suppression and frozen-anchor promotion.

This module is the confidence stage of the context subsystem.  The public
entry point remains :func:`app.pii.context.resolve`, which invokes this stage
only after structured-field, owner, date-role, and relation evidence has been
resolved.
"""
from __future__ import annotations

import re
from collections.abc import Sequence

from .candidates import Candidate

CONFIDENCE_HIGH = 0.95
NAME_CANDIDATE_CONFIDENCE = 0.60
ANCHOR_PROMOTION = 0.22
MULTIPLE_TYPES_PROMOTION = 0.08
NEGATIVE_PENALTY = 1.0
CONTEXT_WINDOW_BYTES = 512
MAX_RECORD_BYTES = 2048
MAX_RECORD_LINES = 8

AMBIGUOUS_TYPES = frozenset({"FIO", "ADDRESS"})
ANCHOR_TYPES = frozenset({"FIO", "PHONE", "EMAIL", "PASSPORT", "CARD", "INN"})

PERSON_HEADER = re.compile(
    r"(?i)^[\s\u00a0]*(?:фио|клиент|получатель|пациент|заявитель|владелец)[\s\u00a0]*[:：]"
)
FIELD_HEADER = re.compile(
    r"(?i)^[\s\u00a0]*(?:имя|фамилия|отчество|город|адрес(?:[\s\u00a0]+(?:проживания|регистрации))?|"
    r"место[\s\u00a0]+жительства|телефон|email|почта|паспорт|инн|карта|дата[\s\u00a0]+рождения)[\s\u00a0]*[:：]"
)
NEGATIVE_CONTEXT = re.compile(
    r"(?i)(?:^|[^\w])(?:поэт\w*|писател\w*|автор\w*|роман|офис\w*|отделени\w*|филиал\w*|"
    r"склад\w*|компани\w*|организаци\w*|магазин\w*|завод\w*|представительств\w*|"
    r"пункт\s+выдачи|банкомат\w*)(?:$|[^\w])"
)

_TRAP_NAMES = frozenset({
    "пушкин", "александр сергеевич пушкин", "александр пушкин",
    "толстой", "лев толстой", "лев николаевич толстой",
    "достоевский", "чехов", "гоголь", "лермонтов", "есенин",
    "маяковский", "пастернак", "ахматова", "цветаева",
    "блок", "тютчев", "фет", "некрасов", "тургенев",
    "гончаров", "островский", "салтыков-щедрин", "бунин",
    "куприн", "горький", "шолохов", "солженицын", "бродский",
    "кутузов", "наполеон",
})

_ADDR_ABBREV = frozenset({"г", "гор", "ул", "д", "кв", "стр", "пер", "пр", "наб"})


def _logical_records(text: str) -> list[tuple[int, int]]:
    records: list[tuple[int, int]] = []
    active, lines = False, 0
    pos = 0
    n = len(text)
    while pos < n:
        end = n
        for i, ch in enumerate(text[pos:], pos):
            if ch in "\n\r\u2028\u2029":
                end = i
                break
        line = text[pos:end]
        prefix = line[:CONTEXT_WINDOW_BYTES]
        person = bool(PERSON_HEADER.match(prefix))
        join = (
            active
            and not person
            and bool(FIELD_HEADER.match(prefix))
            and lines < MAX_RECORD_LINES
            and records
            and end - records[-1][0] <= MAX_RECORD_BYTES
        )
        if join:
            records[-1] = (records[-1][0], end)
            lines += 1
        else:
            records.append((pos, end))
            active, lines = person, 1
        pos = end
        if pos < n:
            pos += 1
            if pos < n and text[pos - 1] == "\r" and text[pos] == "\n":
                pos += 1
    return records


def _record_window(
    text: str,
    candidate: Candidate,
    records: Sequence[tuple[int, int]],
) -> tuple[int, int]:
    lo, hi = candidate.start, candidate.end
    for record_start, record_end in records:
        if record_start <= candidate.start < record_end:
            lo, hi = record_start, record_end
            break
    if candidate.start - lo > CONTEXT_WINDOW_BYTES:
        lo = max(0, candidate.start - CONTEXT_WINDOW_BYTES)
    if hi - candidate.end > CONTEXT_WINDOW_BYTES:
        hi = min(len(text), candidate.end + CONTEXT_WINDOW_BYTES)
    return lo, hi


def sentence_boundary(text: str, index: int) -> bool:
    char = text[index]
    if char in "!?|{}":
        return True
    if char != ".":
        return False
    if index + 1 < len(text) and not text[index + 1].isspace():
        return False
    start = index
    for _ in range(5):
        if start <= 0:
            break
        start -= 1
        while start > 0 and not text[start - 1].isalpha():
            start -= 1
        word_start = start
        while start > 0 and text[start - 1].isalpha():
            start -= 1
        token = text[start:word_start + (index - word_start)].lower().strip(".")
        if token in _ADDR_ABBREV:
            return False
        break
    return True


def _context_window(
    text: str,
    candidate: Candidate,
    records: Sequence[tuple[int, int]],
) -> tuple[int, int]:
    lo, hi = _record_window(text, candidate, records)
    for index in range(candidate.start - 1, lo - 1, -1):
        if sentence_boundary(text, index):
            lo = index + 1
            break
    for index in range(candidate.end, hi):
        if sentence_boundary(text, index):
            hi = index
            break
    return lo, hi


def _local_window(
    text: str,
    candidate: Candidate,
    records: Sequence[tuple[int, int]],
) -> tuple[int, int]:
    lo, hi = _context_window(text, candidate, records)
    chunk = text[lo:candidate.start]
    for separator in ",;\n\r\u2028\u2029":
        index = chunk.rfind(separator)
        if index >= 0:
            lo += index + 1
            break
    tail = text[candidate.end:hi]
    for separator in ",;\n\r\u2028\u2029":
        index = tail.find(separator)
        if index >= 0:
            hi = candidate.end + index
            break
    return lo, hi


def _negative_outside_value(
    text: str,
    candidate: Candidate,
    lo: int,
    hi: int,
) -> bool:
    return bool(
        NEGATIVE_CONTEXT.search(text[lo:candidate.start])
        or NEGATIVE_CONTEXT.search(text[candidate.end:hi])
    )


def _is_trap_name(value: str) -> bool:
    return value.strip().lower() in _TRAP_NAMES


def _suppress_context(
    text: str,
    candidates: Sequence[Candidate],
    records: Sequence[tuple[int, int]],
) -> None:
    for candidate in candidates:
        if candidate.etype not in AMBIGUOUS_TYPES:
            continue
        lo, hi = _local_window(text, candidate, records)
        negative = "trap_name" in candidate.signals or _is_trap_name(candidate.text)
        if not candidate.labeled and _negative_outside_value(text, candidate, lo, hi):
            negative = True
        if negative:
            candidate.score = max(0.0, candidate.score - NEGATIVE_PENALTY)
            candidate.signals.append("ctx_suppressed")


def _negative_outside_names(
    text: str,
    lo: int,
    hi: int,
    candidates: Sequence[Candidate],
) -> bool:
    cursor = lo
    for candidate in candidates:
        if candidate.start >= hi:
            break
        if candidate.end <= lo:
            continue
        if candidate.etype != "FIO" or candidate.score < NAME_CANDIDATE_CONFIDENCE:
            continue
        if candidate.start > cursor and NEGATIVE_CONTEXT.search(text[cursor:candidate.start]):
            return True
        cursor = min(hi, candidate.end)
    return bool(NEGATIVE_CONTEXT.search(text[cursor:hi]))


def _context_anchors(
    text: str,
    candidates: Sequence[Candidate],
    records: Sequence[tuple[int, int]],
) -> tuple[Candidate, ...]:
    anchors: list[Candidate] = []
    for candidate in candidates:
        if candidate.score < CONFIDENCE_HIGH or candidate.etype not in ANCHOR_TYPES:
            continue
        lo, hi = _local_window(text, candidate, records)
        if not candidate.labeled and _negative_outside_names(text, lo, hi, candidates):
            continue
        anchors.append(candidate)
    # A tuple makes the one-way nature explicit: promotion cannot add anchors.
    return tuple(anchors)


def _nearby_anchor_types(
    candidate: Candidate,
    anchors: Sequence[Candidate],
    lo: int,
    hi: int,
) -> set[str]:
    seen: set[str] = set()
    for anchor in anchors:
        if anchor.start >= hi:
            break
        if anchor.end <= lo or anchor.etype == candidate.etype:
            continue
        if anchor.end <= hi and (
            anchor.end <= candidate.start or anchor.start >= candidate.end
        ):
            seen.add(anchor.etype)
    return seen


def _promote_context(
    text: str,
    candidates: Sequence[Candidate],
    records: Sequence[tuple[int, int]],
    anchors: Sequence[Candidate],
) -> None:
    for candidate in candidates:
        if (
            candidate.score <= 0
            or candidate.score >= CONFIDENCE_HIGH
            or candidate.etype not in AMBIGUOUS_TYPES
        ):
            continue
        lo, hi = _context_window(text, candidate, records)
        seen = _nearby_anchor_types(candidate, anchors, lo, hi)
        if not seen:
            if "requires_anchor" in candidate.signals:
                candidate.score = 0.0
                candidate.signals.append("ctx_no_anchor")
            continue
        candidate.score = min(
            CONFIDENCE_HIGH,
            candidate.score
            + ANCHOR_PROMOTION
            + (MULTIPLE_TYPES_PROMOTION if len(seen) > 1 else 0.0),
        )
        candidate.signals.append("ctx_promoted")


def resolve(text: str, candidates: Sequence[Candidate]) -> None:
    """Run suppress -> frozen anchors -> promote on deterministically ordered input."""
    if not candidates:
        return
    records = _logical_records(text)
    _suppress_context(text, candidates, records)
    anchors = _context_anchors(text, candidates, records)
    _promote_context(text, candidates, records, anchors)
