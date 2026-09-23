"""Structure Parser: поля JSON / key=value / логов / query string.

Возвращает поля с абсолютными offset-ами значения в исходной строке.
Сам текст не модифицируется (JSON не перепарсивается и не
сериализуется заново), поэтому все spans остаются валидными.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

from .candidates import (
    BANK_BRANCH,
    CUSTOMER,
    DATE_OF_BIRTH,
    DELIVERY_DATE,
    EMPLOYEE_PERSONAL,
    INTERNAL_ID,
    MEETING_DATE,
    ORGANIZATION,
    PASSPORT_DATE,
    PUBLIC,
)


@dataclass(frozen=True)
class Field:
    key: str          # исходное имя поля, lower-case
    start: int        # начало значения
    end: int          # конец значения (exclusive)
    kind: str         # json | kv | colon


@dataclass(frozen=True)
class FieldInfo:
    etype: str | None      # тип ПД, который описывает поле
    owner: str | None      # владелец по имени поля
    date_role: str | None


_JSON_STR = re.compile(r'"([A-Za-zА-Яа-яЁё_][\w.\-]{0,60})"\s*:\s*"((?:[^"\\\n]|\\.){0,2000})"')
_JSON_NUM = re.compile(r'"([A-Za-zА-Яа-яЁё_][\w.\-]{0,60})"\s*:\s*(-?\d[\d.]{0,40})(?=\s*[,}\]])')
_KEY = r"[A-Za-zА-Яа-яЁё_][\w.\-]{0,60}"
# key=value: значение до &, ;, перевода строки, кавычки или следующего "key=".
_KV = re.compile(
    rf"(?<![\w.\-])({_KEY})=(?!=)"
    rf"([^&;\n\"'|]{{1,500}}?)"
    rf"(?=\s*[,&;]?\s*{_KEY}=|[&;\n\"'|]|$)"
)
# key: value — только для «машинных» ключей (snake_case / camelCase),
# русские подписи вида «Адрес клиента: ...» обрабатывает context resolver.
_COLON = re.compile(
    r"(?m)(?<![\w\"])([a-z][a-z0-9]*(?:[_.\-][a-z0-9]+)+|[a-z]+[A-Z][A-Za-z0-9]*)\s*:\s+"
    r"([^\n;|]{1,500}?)(?=\s*[,;]\s*[a-z][\w.\-]*\s*[:=]|[\n;|]|$)"
)


def parse_fields(text: str) -> list[Field]:
    """Быстрый проход: без полей в тексте ничего не ищем."""
    if "=" not in text and ":" not in text:
        return []
    out: list[Field] = []
    seen: set[tuple[int, int]] = set()
    if '"' in text:
        for rx in (_JSON_STR, _JSON_NUM):
            for m in rx.finditer(text):
                s, e = m.span(2)
                if s < e and (s, e) not in seen:
                    seen.add((s, e))
                    out.append(Field(m.group(1).lower(), s, e, "json"))
    if "=" in text:
        for m in _KV.finditer(text):
            s, e = m.span(2)
            while e > s and text[e - 1] in " \t,":
                e -= 1
            if s < e and (s, e) not in seen:
                seen.add((s, e))
                out.append(Field(m.group(1).lower(), s, e, "kv"))
    for m in _COLON.finditer(text):
        s, e = m.span(2)
        while e > s and text[e - 1] in " \t,":
            e -= 1
        if s < e and not any(f.start <= s < f.end for f in out):
            out.append(Field(m.group(1).lower(), s, e, "colon"))
    out.sort(key=lambda f: f.start)
    return out


class FieldIndex:
    """Поиск поля, содержащего позицию, за O(log n)."""

    def __init__(self, fields: list[Field]) -> None:
        self.fields = fields
        self._starts = [f.start for f in fields]

    def find(self, start: int, end: int) -> Field | None:
        i = bisect.bisect_right(self._starts, start) - 1
        while i >= 0:
            f = self.fields[i]
            if f.start <= start and end <= f.end:
                return f
            if f.end < start and i < len(self.fields) - 1:
                break
            i -= 1
        return None


_SPLIT = re.compile(r"[_.\-\s]+|(?<=[a-z])(?=[A-Z])")

_TYPE_TOKENS = (
    # порядок важен: более специфичные раньше
    ({"cvv", "cvc", "cvv2", "cvc2"}, "CVV"),
    ({"pin", "пин", "pincode"}, "PIN"),
    ({"snils", "снилс"}, "SNILS"),
    ({"inn", "инн"}, "INN"),
    ({"cardholder", "holder", "держатель", "держателя"}, "CARDHOLDER"),
    ({"card", "pan", "карта", "карты"}, "CARD"),
    ({"passport", "паспорт", "паспорта"}, "PASSPORT"),
    ({"driver", "license", "licence", "ву", "водительское"}, "DRIVER"),
    ({"issuer", "issued", "выдан", "кем"}, "ISSUER"),
    ({"email", "mail", "e-mail", "почта", "емейл"}, "EMAIL"),
    ({"phone", "tel", "telephone", "mobile", "msisdn", "телефон", "тел"}, "PHONE"),
    ({"address", "addr", "адрес", "street", "улица"}, "ADDRESS"),
    ({"fio", "фио", "fullname", "surname", "lastname", "firstname", "patronymic",
      "middlename", "фамилия", "имя", "отчество", "name"}, "FIO"),
    ({"citizenship", "гражданство", "nationality"}, "CITIZENSHIP"),
)
_DATE_TOKENS = {"date", "dt", "дата", "birthday", "dob"}
_ID_TOKENS = {
    "id", "order", "request", "ticket", "operation", "transaction", "txn", "trace",
    "заказ", "заказа", "заявка", "заявки", "заявления", "заявление", "обращения",
    "обращение", "операции", "операция", "номер", "internal", "внутренний",
    "кабинет", "кабинета", "room", "article", "артикул", "sku", "account", "счет", "счёт",
    "code", "код", "delivery", "доставки", "track", "invoice", "contract", "договор",
    "amount", "sum", "сумма",
}
_OWNER_TOKENS = (
    ({"customer", "client", "клиент", "клиента", "user", "applicant", "заявитель",
      "recipient", "получатель", "holder", "personal", "home", "домашний", "borrower",
      "заемщик", "заёмщик", "payer", "плательщик"}, CUSTOMER),
    ({"employee", "сотрудник", "сотрудника", "staff", "manager"}, EMPLOYEE_PERSONAL),
    ({"branch", "atm", "отделение", "отделения", "филиал", "банкомат", "bank", "банк", "банка"}, BANK_BRANCH),
    ({"support", "office", "company", "org", "organization", "corp", "hotline", "service",
      "офис", "компания", "организация", "official", "info", "sales", "help", "noreply"}, ORGANIZATION),
    ({"public"}, PUBLIC),
)


def classify_key(key: str) -> FieldInfo:
    tokens = {t.lower() for t in _SPLIT.split(key) if t}
    owner = None
    for words, o in _OWNER_TOKENS:
        if tokens & words:
            owner = o
            break
    # дата
    joined = key.lower()
    birth = bool(tokens & {"birth", "dob", "birthday", "рождения", "рожд"}) or "birth" in joined
    is_date = bool(tokens & _DATE_TOKENS) or birth
    if birth and ("place" in tokens or "место" in tokens):
        return FieldInfo("BIRTH_PLACE", owner or CUSTOMER, None)
    if is_date:
        if birth:
            return FieldInfo("DATE", owner or CUSTOMER, DATE_OF_BIRTH)
        if tokens & {"issue", "issued", "выдачи"}:
            return FieldInfo("DATE", owner or CUSTOMER, PASSPORT_DATE)
        if tokens & {"delivery", "доставки", "shipping"}:
            return FieldInfo("DATE", owner, DELIVERY_DATE)
        if tokens & {"meeting", "visit", "встречи", "appointment"}:
            return FieldInfo("DATE", owner, MEETING_DATE)
        return FieldInfo("DATE", owner, None)
    if tokens & {"division", "подразделения", "dept", "department"} and tokens & {"code", "код"}:
        return FieldInfo("DEPT_CODE", owner or CUSTOMER, None)
    etype = None
    for words, t in _TYPE_TOKENS:
        if tokens & words:
            etype = t
            break
    if etype is None and tokens & _ID_TOKENS:
        return FieldInfo(None, INTERNAL_ID, None)
    if etype in ("FIO",) and owner in (BANK_BRANCH, ORGANIZATION) and "name" in tokens:
        # branch_name / company_name — название организации, не ФИО
        return FieldInfo(None, owner, None)
    return FieldInfo(etype, owner, None)
