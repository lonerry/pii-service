"""Окна контекста и границы клауз для детекторов и resolver-а."""
from __future__ import annotations

import re

CONTEXT_LEFT = 100
CONTEXT_RIGHT = 40
DOCUMENT_HINT = 60
DOCUMENT_CONTEXT = 150
DATE_ROLE = 60
RIGHT_OWNER = 30
ID_LABEL_DISTANCE = 40
RELATION_LEFT = 160
FUZZY_DATE_RIGHT = 40
LATIN_FIO_LEFT = 60
LATIN_FIO_RIGHT = 50
ADDRESS_COMPONENT = 60
ISSUER_VALUE = 160
OTHER_FREE_VALUE = 100

CLAUSE_BREAK = re.compile(r"[\n;]|[.!?](?=\s+[А-ЯЁA-Z])")
_ABBREVIATION = re.compile(r"(?:\b\w{1,3}|[А-ЯЁ])$")


def left_window(text: str, pos: int, size: int = CONTEXT_LEFT,
                *, skip_abbreviations: bool = True) -> tuple[str, int]:
    """Левый фрагмент после последней границы клаузы и его смещение."""
    lo = max(0, pos - size)
    win = text[lo:pos]
    last_end = 0
    for match in CLAUSE_BREAK.finditer(win):
        if skip_abbreviations and match.group() == "." and _ABBREVIATION.search(win[:match.start()]):
            continue
        last_end = match.end()
    lo += last_end
    return text[lo:pos], lo
