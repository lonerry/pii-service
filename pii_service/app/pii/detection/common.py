"""Shared detector types, candidate construction, and validators."""
from __future__ import annotations

from collections.abc import Callable, Sequence

from ..candidates import Candidate


def luhn_ok(digits: str) -> bool:
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


def inn_ok(d: str) -> bool:
    def chk(ds: str, coefs: Sequence[int]) -> int:
        return sum(int(c) * k for c, k in zip(ds, coefs)) % 11 % 10

    if len(d) == 10:
        return chk(d, (2, 4, 10, 3, 5, 9, 4, 6, 8)) == int(d[9])
    if len(d) == 12:
        return (chk(d, (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) == int(d[10])
                and chk(d, (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) == int(d[11]))
    return False


def snils_ok(d: str) -> bool:
    if len(d) != 11:
        return False
    s = sum(int(c) * (9 - i) for i, c in enumerate(d[:9]))
    ctrl = s % 101 if s > 101 else (0 if s in (100, 101) else s)
    if ctrl == 100:
        ctrl = 0
    return ctrl == int(d[9:])


def _digits(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def _cand(text: str, s: int, e: int, etype: str, score: float, source: str,
          anchor: int = -1, labeled: bool = False) -> Candidate:
    return Candidate(s, e, etype, text[s:e], score, source, anchor=anchor if anchor >= 0 else s,
                     labeled=labeled)

Detector = Callable[[str], list[Candidate]]
