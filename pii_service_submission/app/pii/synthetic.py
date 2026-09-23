"""Deterministic synthetic placeholders for playground-friendly masking."""
from __future__ import annotations

import hashlib

_POOLS: dict[str, tuple[str, ...]] = {
    "FIO": (
        "Клиент А. Б. В.",
        "Получатель Г. Д. Е.",
        "Заявитель Ж. З. И.",
    ),
    "PHONE": ("+7 (000) 000-00-00", "+7 (111) 222-33-44"),
    "EMAIL": ("user@example.local", "client@demo.test"),
    "PASSPORT": ("0000 000000", "4500 000000"),
    "DRIVER": ("0000 000000", "7700 000000"),
    # Must fail Luhn, otherwise final_leak_guard (format mode) would star them out.
    "CARD": ("0000 0000 0000 0001", "4111 0000 0000 0001"),
    "CVV": ("000", "123"),
    "PIN": ("0000", "1234"),
    "INN": ("0000000001", "7700000002"),
    "SNILS": ("000-000-000 01", "111-222-333 01"),
    "ADDRESS": (
        "г. Город, ул. Примерная, д. 0",
        "г. Нейтральный, пр. Демо, д. 1",
    ),
    "DATE": ("01.01.1900", "15.06.2000"),
    "DATE_TEXT": ("1 января 1900 г.", "15 июня 2000 г."),
    "BIRTH_PLACE": ("г. Город", "г. Нейтральный"),
    "CITIZENSHIP": ("РФ", "—"),
    "ISSUER": ("Орган выдачи документа", "УФМС (синт.)"),
    "DEPT_CODE": ("000-000", "100-200"),
    "CARDHOLDER": ("CARD HOLDER", "DEMO USER"),
}


def _pick(etype: str, value: str) -> str:
    pool = _POOLS.get(etype, ("[данные]",))
    digest = hashlib.sha256(f"{etype}\0{value}".encode()).digest()
    return pool[digest[0] % len(pool)]


def synthetic_value(etype: str, value: str) -> str:
    return _pick(etype, value)

