"""Format-preserving masking strategies."""
from __future__ import annotations

from collections.abc import Callable


def _is_digit(ch: str) -> bool:
    return len(ch) == 1 and ch.isdigit()


def _is_letter(ch: str) -> bool:
    return len(ch) == 1 and ch.isalpha()


def mask_all_digits(value: str) -> str:
    return "".join("*" if _is_digit(ch) else ch for ch in value)


def mask_all_alpha_numeric(value: str) -> str:
    return "".join("*" if (_is_digit(ch) or _is_letter(ch)) else ch for ch in value)


def mask_words(value: str) -> str:
    return "".join("*" if _is_letter(ch) else ch for ch in value)


STRATEGIES: dict[str, Callable[[str], str]] = {
    # Format mode: hide every letter and digit inside the span (keep spaces/punctuation).
    "FIO": mask_words,
    "CARDHOLDER": mask_words,
    "DATE": mask_all_digits,
    "DATE_TEXT": mask_all_digits,
    "BIRTH_PLACE": mask_words,
    "PASSPORT": mask_all_digits,
    "CITIZENSHIP": mask_words,
    "ISSUER": mask_all_alpha_numeric,
    "DEPT_CODE": mask_all_digits,
    "DRIVER": mask_all_digits,
    "ADDRESS": mask_all_alpha_numeric,
    "EMAIL": mask_all_alpha_numeric,
    "PHONE": mask_all_digits,
    "INN": mask_all_digits,
    "SNILS": mask_all_digits,
    "CARD": mask_all_digits,
    "CVV": mask_all_digits,
    "PIN": mask_all_digits,
}


def mask_value(etype: str, value: str) -> str:
    strategy = STRATEGIES.get(etype)
    if strategy is not None:
        return strategy(value)
    return mask_all_alpha_numeric(value)
