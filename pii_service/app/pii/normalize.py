"""Detection-only Unicode normalization.

Every replacement is one Unicode code point, so Python string offsets remain
valid for the original input. The original text is always used for masking.
"""
from __future__ import annotations


def normalize_text(text: str) -> str:
    out: list[str] = []
    changed = False
    for char in text:
        replacement = _normalize_char(char)
        out.append(replacement)
        changed |= replacement != char
    return "".join(out) if changed else text


def _normalize_char(char: str) -> str:
    if char in {"\r", "\u2028", "\u2029"}:
        return "\n"
    if char.isspace() and char != "\n":
        return " "
    if char in {"\u2010", "\u2011", "\u2212", "\uff0d"}:
        return "-"
    if "\uff10" <= char <= "\uff19":
        return chr(ord("0") + ord(char) - ord("\uff10"))
    if char == "\uff0b":
        return "+"
    if char == "\uff1a":
        return ":"
    return char
