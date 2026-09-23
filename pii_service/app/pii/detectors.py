"""Public detector facade and stable detector registry."""
from __future__ import annotations

from .detection.common import Detector, inn_ok, luhn_ok, snils_ok
from .detection.contacts import detect_email, detect_phone
from .detection.dates import detect_dates
from .detection.documents import detect_dept_code, detect_documents
from .detection.financial import (
                                  CARD_RE,
                                  CVV_RE,
                                  INN_RE,
                                  PIN_RE,
                                  SNILS_RE,
                                  detect_account,
                                  detect_card,
                                  detect_card_last4,
                                  detect_cvv_pin,
                                  detect_inn,
                                  detect_kpp_ogrn,
                                  detect_money,
                                  detect_snils,
)
from .detection.freetext import detect_address, detect_labeled_freetext
from .detection.names import detect_cardholder, detect_fio
from .detection.structured import detect_field_values
from .registry import Registration, Registry

REGISTRY = Registry((
    Registration(frozenset({"CARDHOLDER"}), detect_cardholder),
    Registration(frozenset({"FIO"}), detect_fio),
    Registration(frozenset({"DATE", "DATE_TEXT"}), detect_dates),
    Registration(frozenset({"BIRTH_PLACE", "ISSUER", "CITIZENSHIP"}), detect_labeled_freetext),
    Registration(frozenset({"PASSPORT", "DRIVER"}), detect_documents),
    Registration(frozenset({"ADDRESS"}), detect_address),
    Registration(frozenset({"EMAIL"}), detect_email),
    Registration(frozenset({"PHONE"}), detect_phone),
    Registration(frozenset({"INN"}), detect_inn),
    Registration(frozenset({"CARD", "PIN"}), detect_card),
    Registration(frozenset({"CVV", "PIN"}), detect_cvv_pin),
    Registration(frozenset({"CARD_LAST4"}), detect_card_last4),
    Registration(frozenset({"KPP", "OGRN", "BIK"}), detect_kpp_ogrn),
    Registration(frozenset({"SNILS"}), detect_snils),
    Registration(frozenset({"DEPT_CODE"}), detect_dept_code),
    Registration(frozenset({"ACCOUNT"}), detect_account),
    Registration(frozenset({"MONEY"}), detect_money),
))
FAST_DETECTORS = tuple(
    registration.detector for registration in REGISTRY.registrations
)

__all__ = [
                                  "CARD_RE",
                                  "CVV_RE",
                                  "FAST_DETECTORS",
                                  "INN_RE",
                                  "PIN_RE",
                                  "REGISTRY",
                                  "SNILS_RE",
                                  "Detector",
                                  "detect_account",
                                  "detect_address",
                                  "detect_card",
                                  "detect_card_last4",
                                  "detect_cardholder",
                                  "detect_cvv_pin",
                                  "detect_dates",
                                  "detect_dept_code",
                                  "detect_documents",
                                  "detect_email",
                                  "detect_field_values",
                                  "detect_fio",
                                  "detect_inn",
                                  "detect_kpp_ogrn",
                                  "detect_labeled_freetext",
                                  "detect_money",
                                  "detect_phone",
                                  "detect_snils",
                                  "inn_ok",
                                  "luhn_ok",
                                  "snils_ok",
]
