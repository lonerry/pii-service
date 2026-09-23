"""Format-preserving masking strategies."""
from __future__ import annotations

from collections.abc import Callable


def _is_digit(ch: str) -> bool:
    return len(ch) == 1 and ch.isdigit()


def _is_letter(ch: str) -> bool:
    return len(ch) == 1 and ch.isalpha()


def mask_full_name(value: str) -> str:
    words = value.split()
    if not words:
        return value
    return " ".join(f"{w[0]}." for w in words if w)


def _date_digit_runs(value: str) -> tuple[int, int, int]:
    digit_total = 0
    year_start, year_end = -1, -1
    i = 0
    while i < len(value):
        if _is_digit(value[i]):
            j = i
            while j < len(value) and _is_digit(value[j]):
                j += 1
            run_len = j - i
            digit_total += run_len
            if run_len == 4:
                year_start, year_end = i, j
            i = j
        else:
            i += 1
    return digit_total, year_start, year_end


def mask_date(value: str) -> str:
    digit_total, year_start, year_end = _date_digit_runs(value)
    if digit_total == 0:
        return mask_words(value)
    keep_year = year_start >= 0 and digit_total > (year_end - year_start)
    out: list[str] = []
    for i, ch in enumerate(value):
        if keep_year and year_start <= i < year_end:
            out.append(ch)
            continue
        if not keep_year and year_start >= 0 and year_start + 2 <= i < year_end:
            out.append(ch)
            continue
        out.append("*" if _is_digit(ch) else ch)
    return "".join(out)


def _mask_digits_keep_edges(value: str, keep_first: int, keep_last: int) -> str:
    digits = sum(1 for ch in value if _is_digit(ch))
    out: list[str] = []
    digit_idx = 0
    for ch in value:
        if _is_digit(ch):
            if digit_idx < keep_first or digit_idx >= digits - keep_last:
                out.append(ch)
            else:
                out.append("*")
            digit_idx += 1
        else:
            out.append(ch)
    return "".join(out)


def mask_passport(value: str) -> str:
    digits = sum(1 for ch in value if _is_digit(ch))
    if digits <= 4:
        return mask_all_digits(value)
    return _mask_digits_keep_edges(value, 2, 2)


def mask_driver_license(value: str) -> str:
    return mask_passport(value)


def mask_card_number(value: str) -> str:
    return _mask_digits_keep_edges(value, 4, 4)


def mask_digits_keep_edges(value: str) -> str:
    return mask_passport(value)


def mask_all_digits(value: str) -> str:
    return "".join("*" if _is_digit(ch) else ch for ch in value)


def mask_all_alpha_numeric(value: str) -> str:
    return "".join("*" if (_is_digit(ch) or _is_letter(ch)) else ch for ch in value)


def mask_phone(value: str) -> str:
    total_digits = sum(1 for ch in value if _is_digit(ch))
    out: list[str] = []
    digit_idx = 0
    for ch in value:
        if _is_digit(ch):
            if digit_idx < 1 or digit_idx >= total_digits - 2:
                out.append(ch)
            else:
                out.append("*")
            digit_idx += 1
        else:
            out.append(ch)
    return "".join(out)


def mask_email(value: str) -> str:
    at = value.find("@")
    if at < 0:
        return mask_words(value)
    local = value[:at]
    domain = value[at + 1 :]
    dot = domain.rfind(".")
    masked_local = (local[0] + "*" * (len(local) - 1)) if local else "*"
    if dot > 0:
        masked_domain = "*" * dot + domain[dot:]
    else:
        masked_domain = "*" * len(domain)
    return f"{masked_local}@{masked_domain}"


def mask_words(value: str) -> str:
    return "".join("*" if _is_letter(ch) else ch for ch in value)


STRATEGIES: dict[str, Callable[[str], str]] = {
    "FIO": mask_full_name,
    "CARDHOLDER": mask_full_name,
    "DATE": mask_date,
    "DATE_TEXT": mask_date,
    "BIRTH_PLACE": mask_words,
    "PASSPORT": mask_passport,
    "CITIZENSHIP": mask_words,
    "ISSUER": mask_all_alpha_numeric,
    "DEPT_CODE": mask_digits_keep_edges,
    "DRIVER": mask_driver_license,
    "ADDRESS": mask_all_alpha_numeric,
    "EMAIL": mask_email,
    "PHONE": mask_phone,
    "INN": mask_digits_keep_edges,
    "SNILS": mask_digits_keep_edges,
    "CARD": mask_card_number,
    "CVV": mask_all_digits,
    "PIN": mask_all_digits,
}


def mask_value(etype: str, value: str) -> str:
    strategy = STRATEGIES.get(etype)
    if strategy is not None:
        return strategy(value)
    return mask_all_alpha_numeric(value)
