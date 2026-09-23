"""Context / Relation / Owner resolver (Google DLP-style hotword rules).

Для каждого candidate:
  * positive / negative hotwords в окне слева (в пределах клауза) и справа;
  * proximity: вес hotword-а убывает с расстоянием до метки/значения;
  * exclusion rules: «номер заказа/заявки/обращения…» гасят числовые кандидаты;
  * owner: CUSTOMER / EMPLOYEE_PERSONAL / BANK_BRANCH / ORGANIZATION / PUBLIC / UNKNOWN;
  * role для дат: DATE_OF_BIRTH / PASSPORT_DATE / MEETING_DATE / DELIVERY_DATE / OTHER;
  * relation rules между кандидатами (PIN ↔ карта, дата сразу после ФИО и т.п.).
Имя поля структурированного входа — самый сильный сигнал.
"""
from __future__ import annotations

import re
from collections.abc import Sequence

from . import dictionaries as D
from ._context_vibe import (
    resolve as _resolve_vibe,
)
from .candidates import (
    BANK_BRANCH,
    CARD_ISSUE_DATE,
    CUSTOMER,
    DATE_OF_BIRTH,
    DELIVERY_DATE,
    EMPLOYEE_PERSONAL,
    INTERNAL_ID,
    MEETING_DATE,
    ORGANIZATION,
    OTHER,
    PASSPORT_DATE,
    PIN_SET_DATE,
    PUBLIC,
    UNKNOWN,
    Candidate,
)
from .heuristics import (
    INN_EV_CUSTOMER_OWNER,
    INN_EV_LABEL,
    INN_EV_NEGATIVE_CONTEXT,
    OWNER_DECAY_CUTOFFS,
    OWNER_DECAY_WEIGHTS,
    OWNER_PERSONAL_TIE_FACTOR,
    PERSONAL_OWNER_THRESHOLD,
    PERSONAL_ROLE_RIGHT_WEIGHT,
    PERSONAL_ROLE_WEIGHT,
    PUBLIC_CONTEXT_WEIGHT,
    PUBLIC_KB_WEIGHT,
)
from .morph import hard_non_name, normal_form
from .structure import FieldIndex, classify_key
from .windows import (
    CONTEXT_LEFT,
    CONTEXT_RIGHT,
    DATE_ROLE,
    DOCUMENT_CONTEXT,
    ID_LABEL_DISTANCE,
    RELATION_LEFT,
    RIGHT_OWNER,
    left_window,
)

LEFT_WINDOW = CONTEXT_LEFT
RIGHT_WINDOW = CONTEXT_RIGHT


def _rx(words: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w])(?:{words})", re.IGNORECASE)


# (regex, owner, base weight)
OWNER_HOTWORDS: Sequence[tuple[re.Pattern[str], str, float]] = (
    (_rx(r"клиент\w*|заявител\w*|заёмщи\w*|заемщи\w*|созаёмщи\w*|созаемщи\w*|получател\w*|"
         r"поручител\w*|абонент\w*|пациент\w*|держател\w*|владел\w*|вкладчик\w*|плательщик\w*|"
         r"физ\.?\s*лиц\w*|г-н|г-жа|гражданин\w*|гражданк\w*"), CUSTOMER, 1.2),
    (_rx(r"прожива\w*|проживани\w*|зарегистрир\w*|регистраци\w*|прописк\w*|прописан\w*|"
         r"места?\s+жительства|домашн\w*|личн\w*|мобильн\w*|сотов\w*|моб\.|фактическ\w*|"
         r"я\s+живу|мой|моя|мои|мне|меня|новый\s+телефон|новый\s+адрес|"
         r"адрес\s+доставки|куда\s+доставить"), CUSTOMER, 1.2),
    (_rx(r"сотрудник\w*|работник\w*|менеджер\w*|оператор\w*|специалист\w*|кассир\w*"), EMPLOYEE_PERSONAL, 0.8),
    (_rx(r"отделени\w*|филиал\w*|банкомат\w*|терминал\w*|доп\.?\s*офис\w*|дополнительн\w+\s+офис\w*|"
         r"офис\w*\s+банка|адрес\w*\s+банка|телефон\w*\s+банка|точк\w+\s+обслуживания|всп\b|касс[аы]\b|"
         r"банк[аеу]?\b"), BANK_BRANCH, 1.0),
    (_rx(r"офис\w*|компани\w*|организаци\w*|юридическ\w*|ооо|пао|зао|оао|ао\b|магазин\w*|склад\w*|"
         r"пункт\w*\s+выдачи|пвз|горяч\w+\s+лини\w*|поддержк\w*|служб\w*|call-?цент\w*|колл-?цент\w*|"
         r"контакт-?цент\w*|справочн\w*|официальн\w*|рабоч\w*|при[её]мн\w*|единый\s+номер|бесплатн\w*|"
         r"по\s+вопросам|обращайтесь|звоните|пишите|наш\w*|партн[её]р\w*|ресепшн\w*|секретар\w*"), ORGANIZATION, 1.0),
    (_rx(r"музе\w*|театр\w*|памятник\w*|вокзал\w*|аэропорт\w*|метро|библиотек\w*|университет\w*|"
         r"собор\w*|кремл\w*|достопримечат\w*|стадион\w*|администраци\w*|мэри\w*|министерств\w*"), PUBLIC, 1.0),
)
PERSON_PUBLIC_HOTWORDS = _rx(
    r"поэт\w*|писател\w*|композитор\w*|художник\w*|учён\w*|ученый\w*|философ\w*|полководец\w*|"
    r"полководц\w*|император\w*|импер\w*|цар[ьяюе]\w*|княз\w*|президент\w*|классик\w*|роман\w*|"
    r"произведени\w*|стих\w*|поэм\w*|картин\w*|биографи\w*|велик\w*|имени|в\s+честь|историческ\w*|"
    r"литератур\w*|автор\w*|памятник\w*|музе\w*|творчеств\w*|сочинени\w*|драматург\w*|актёр\w*|"
    r"актер\w*|режисс[её]р\w*|знаменит\w*|известн\w*|поэтом|век[ае]?\b"
)
PERSON_PERSONAL_HOTWORDS = _rx(
    r"клиент\w*|заявител\w*|заёмщи\w*|заемщи\w*|созаёмщи\w*|созаемщи\w*|получател\w*|отправител\w*|"
    r"поручител\w*|держател\w*|вкладчи\w*|бенефициар\w*|наследни\w*|доверенн\w*|владел\w*|плательщик\w*|"
    r"фио|ф\.и\.о\.|фамили\w*|паспорт\w*|дата\s+рождения|телефон\w*|"
    r"проживает|зарегистрир\w*|г-н|г-жа|гражданин\w*|гражданк\w*|сотрудник\w*|менеджер\w*|"
    r"оператор\w*|уважаем\w*|договор\w*|счёт\w*|счет\w*|карт\w*|обратил\w*|обращени\w*|операци\w*"
)

# Exclusion: числовое значение — внутренний идентификатор, а не документ/телефон/карта.
ID_LABEL = _rx(
    r"(?:номер|№|#|id|код)\s*(?:заказа|заявки|заявления|обращения|операции|транзакции|договора|"
    r"сч[её]та|доставки|отправления|посылки|накладной|тикета|кабинета|товара|платежа|чека|"
    r"квитанции|документа\s+основания|записи|клиента\s+в\s+crm)|заказ\w*|заявк\w*|заявлени\w*|"
    r"обращени\w*|операци\w*|транзакци\w*|договор\w*|лицев\w+\s+сч\w*|расч[её]тн\w+\s+сч\w*|"
    r"сч[её]т\w*|артикул\w*|sku|тикет\w*|ticket|order|request|invoice|трек\w*|накладн\w*|"
    r"кабинет\w*|аудитори\w*|комнат\w*|внутренн\w*|сумм\w*|руб\w*|код\s+товара|отправлени\w*|"
    r"доставк\w*|инвентарн\w*|серийн\w+\s+номер|идентификатор\w*|референс\w*|"
    r"(?<![\w])номер(?![\w])\s+\d"
)
TYPE_LABELS: dict[str, re.Pattern[str]] = {
    "PHONE": _rx(r"тел\w*|моб\w*|phone|звонит\w*|позвонит\w*|whatsapp|telegram|сотов\w*|номер\s+телефона|contact"),
    "EMAIL": _rx(r"e-?mail|почт\w*|mail"),
    "CARD": _rx(r"карт\w*|card|pan|visa|mastercard|мир\b|maestro"),
    "PASSPORT": _rx(r"паспорт\w*|серия|выдан\w*|passport"),
    "DRIVER": _rx(r"в/у|ву\b|водительск\w*|удостоверени\w*|прав[аы]?\b|driver"),
    "INN": _rx(r"инн|inn"),
    "SNILS": _rx(r"снилс|snils|страхов\w+\s+номер"),
    "DEPT_CODE": _rx(r"код\s+подразделения|подразделени\w*"),
}
_DOC_CONTEXT_RE = _rx(r"паспорт\w*|документ\w*|выдан\w*")
CARD_CONTEXT = _rx(r"карт\w*|card|банкомат\w*|visa|mastercard|мир\b|cvv|cvc|оплат\w*|платёж\w*|платеж\w*")
INN_ORG = _rx(r"инн\s+(?:банка|организации|компании|юр\.?\s*лица|юридического\s+лица|продавца|поставщика|получателя\s+платежа)|"
              r"поставщик\w*|организаци\w*|юридическ\w*\s+лиц\w*|продавц\w*|подрядчик\w*|исполнител\w*|"
              r"огрн|кпп|реквизит\w*|контрагент\w*|"
              r"ооо|пао|зао|оао|ао\b|банк\b|юрлиц\w*")

DATE_ROLES: Sequence[tuple[re.Pattern[str], str]] = (
    (_rx(r"дат\w*\s+рождени\w*|д\.\s?р\.|д/р|г\.\s?р\.|родил\w*|рожд\w*|birth\w*|dob|born|"
         r"день\s+рождения|возраст\w*"), DATE_OF_BIRTH),
    (_rx(r"дат\w*\s+выдачи|выдан\w*|issued|когда\s+выдан|действителен\s+до|срок\s+действия\s+паспорта"), PASSPORT_DATE),
    (_rx(r"встреч\w*|визит\w*|при[её]м\w*|запис\w*|назнач\w*|консультаци\w*|звон\w*|созвон\w*|"
         r"собеседовани\w*|meeting|appointment"), MEETING_DATE),
    (_rx(r"доставк\w*|достав\w*|отправк\w*|курьер\w*|delivery|shipping|отгрузк\w*"), DELIVERY_DATE),
    (_rx(r"оформлен\w*\s+карт\w*|карт\w*\s+оформлен\w*|выпущен\w*\s+карт\w*|карт\w*\s+выпущен\w*|"
         r"дата\s+выпуска(?:\s+карты)?|дата\s+оформления(?:\s+карты)?"), CARD_ISSUE_DATE),
    (_rx(r"установлен\w*|дата\s+установки(?:\s+пин)?"), PIN_SET_DATE),
)
DOB_RIGHT = _rx(r"г\.\s?р\.|года\s+рождения|г/р|\(д\.\s?р\.\)")

_NUMERIC_TYPES = {"PHONE", "CARD", "PASSPORT", "DRIVER", "INN", "SNILS", "DEPT_CODE"}
_OWNER_TYPES = {"ADDRESS", "PHONE", "EMAIL"}


def _decay(dist: int) -> float:
    for cutoff, weight in zip(OWNER_DECAY_CUTOFFS, OWNER_DECAY_WEIGHTS):
        if dist <= cutoff:
            return weight
    return OWNER_DECAY_WEIGHTS[-1]


def _nearest(rx: re.Pattern[str], win: str) -> int | None:
    """Расстояние от конца последнего совпадения до конца окна."""
    best = None
    for m in rx.finditer(win):
        best = len(win) - m.end()
    return best


def _evidence_boost(c: Candidate, name: str, target: float) -> None:
    """Evidence-замена прямой перезаписи score (Google DLP likelihood / MS Purview
    corroborative evidence): вместо `c.score = X` кладём именованную улику-дельту,
    чтобы effective_score (= score + sum(evidence)) достиг X, не ниже. Итог для вызывающего
    кода идентичен старому `c.score = X`, но теперь видно, ЧЕМ именно обоснован рост score —
    через pipeline.explain() каждая сущность показывает полную raскладку evidence."""
    delta = target - c.score
    if delta > 0:
        c.evidence[name] = max(c.evidence.get(name, 0.0), delta)


# Все owner-hotwords одним регулярным выражением с именованными группами:
# один проход по окну вместо шести.
_OWNER_COMBINED = re.compile(
    "|".join(f"(?P<g{i}>{rx.pattern})" for i, (rx, _o, _b) in enumerate(OWNER_HOTWORDS)),
    re.IGNORECASE,
)
_OWNER_BY_GROUP = {f"g{i}": (o, b) for i, (_rx_, o, b) in enumerate(OWNER_HOTWORDS)}


def _owner_scores(win: str) -> dict[str, float]:
    scores: dict[str, float] = {}
    n = len(win)
    for m in _OWNER_COMBINED.finditer(win):
        owner, base = _OWNER_BY_GROUP[m.lastgroup]
        scores[owner] = scores.get(owner, 0.0) + base * _decay(n - m.end())
    return scores


def _pick_owner(scores: dict[str, float]) -> str:
    if not scores:
        return UNKNOWN
    personal = max(scores.get(CUSTOMER, 0.0), scores.get(EMPLOYEE_PERSONAL, 0.0))
    other_owner, other = max(((o, s) for o, s in scores.items() if o not in (CUSTOMER, EMPLOYEE_PERSONAL)),
                             key=lambda x: x[1], default=(UNKNOWN, 0.0))
    # безопасный bias: при равенстве побеждает персональный контекст
    if personal > 0 and personal >= other * OWNER_PERSONAL_TIE_FACTOR:
        if scores.get(EMPLOYEE_PERSONAL, 0.0) > scores.get(CUSTOMER, 0.0):
            return EMPLOYEE_PERSONAL
        return CUSTOMER
    return other_owner if other > 0 else UNKNOWN


def _apply_field(c: Candidate, fields: FieldIndex | None) -> bool:
    if fields is None:
        return False
    f = fields.find(c.start, c.end)
    if f is None:
        return False
    info = classify_key(f.key)
    c.field = f.key
    c.signals.append("field")
    if info.owner == INTERNAL_ID and c.etype in _NUMERIC_TYPES | {"CVV", "PIN", "DATE", "DATE_TEXT"}:
        c.owner = INTERNAL_ID
        c.signals.append("field_internal_id")
        return True
    if info.etype == c.etype or (info.etype == "DATE" and c.etype in ("DATE", "DATE_TEXT")) or (
            info.etype == "FIO" and c.etype == "CARDHOLDER"):
        _evidence_boost(c, "field_match", 0.9)
        c.labeled = True
    if info.owner:
        c.owner = info.owner
        c.signals.append("field_owner")
    if info.date_role and c.etype in ("DATE", "DATE_TEXT"):
        c.role = info.date_role
        c.signals.append("field_date_role")
    return True


def _numeric_exclusion(c: Candidate, win: str) -> bool:
    """True, если ближайшая метка — ID заказа/заявки, а не метка самого типа."""
    id_d = _nearest(ID_LABEL, win)
    if id_d is None or id_d > ID_LABEL_DISTANCE:
        return False
    type_rx = TYPE_LABELS.get(c.etype)
    type_d = _nearest(type_rx, win) if type_rx is not None else None
    return type_d is None or id_d < type_d


def _resolve_date(c: Candidate, text: str, win: str) -> None:
    if c.role != OTHER:
        return
    best: tuple[int, str] | None = None
    for rx, role in DATE_ROLES:
        d = _nearest(rx, win)
        if d is not None and d <= DATE_ROLE and (best is None or d < best[0]):
            best = (d, role)
    if best is not None:
        c.role = best[1]
        c.signals.append("date_hotword")
    if DOB_RIGHT.match(text, c.end, min(len(text), c.end + 20)) or DOB_RIGHT.search(text[c.end:c.end + 20]):
        c.role = DATE_OF_BIRTH
        c.signals.append("dob_right")


def _public_person(c: Candidate) -> bool:
    toks = re.findall(r"[А-ЯЁ][а-яё\-]+", c.text)
    norms = [normal_form(t) for t in toks]
    lows = [t.lower() for t in toks]
    for i, n in enumerate(norms):
        key = n if n in D.PUBLIC_PERSONS else (lows[i] if lows[i] in D.PUBLIC_PERSONS else None)
        if key is None:
            continue
        firsts = D.PUBLIC_PERSONS[key]
        others = set(norms[:i] + norms[i + 1:]) | set(lows[:i] + lows[i + 1:])
        # «Пушкин» / «Александр Пушкин» / «Александр Сергеевич Пушкин» (отчество — любое);
        # «Иван Пушкин» — однофамилец, не публичная персона
        if not others or not firsts or others & firsts:
            return True
    return False


_BARE_STRIP = " \t\r\n,!?;:\"'()«»„“”-–—"  # без "." — это может быть точка инициала («Иванов И.»)
# слово-имя: возможны внутренние дефисы/апострофы («Жан-Батист», «О'Коннор»); инициал — одна
# буква с точкой (морфологией не проверяем — «И» без точки сама по себе не слово).
_BARE_NAME_WORD_RE = re.compile(r"^[А-ЯЁ][а-яё]{0,30}(?:['\-][А-ЯЁ][а-яё]{1,30})*\.?$")
_BARE_NAME_INITIAL_RE = re.compile(r"^[А-ЯЁ]\.$")


def _is_bare_name_only(text: str, c: Candidate) -> bool:
    """Весь текст состоит только из слов-имён (и, возможно, инициалов) — не персональные
    данные конкретного человека вне контекста, даже если сама ФИО-сущность нашлась
    частично (например «Гарсия» из «Лопес Гарсия», где полное имя не распозналось морфологией).
    Роль-слова («клиент», «бенефициар» и т.п.) — обычные известные словарю слова, поэтому
    hard_non_name() их отсеивает и не даёт спутать с «голым» именем."""
    toks = [t for t in re.split(r"[\s/]+", text.strip(_BARE_STRIP)) if t]
    if not toks:
        return False
    for t in toks:
        if _BARE_NAME_INITIAL_RE.match(t):
            continue
        if not _BARE_NAME_WORD_RE.match(t) or hard_non_name(t.rstrip(".")):
            return False
    return True


def _resolve_numeric_evidence(c: Candidate, text: str, win: str, has_card: bool) -> None:
    et = c.etype
    if et == "CARD" and "luhn_fail" in c.signals:
        d = _nearest(TYPE_LABELS["CARD"], win)
        if d is not None and d <= 30:
            _evidence_boost(c, "label", 0.75)
            c.signals.append("card_label")
    elif et in ("PASSPORT", "DRIVER") and not c.labeled:
        d = _nearest(TYPE_LABELS[et], win)
        if d is not None and d <= DATE_ROLE:
            _evidence_boost(c, "label", 0.9)
    elif et == "INN":
        d = _nearest(TYPE_LABELS["INN"], win)
        if d is not None and d <= 25:
            c.evidence.setdefault("label", INN_EV_LABEL)
            c.labeled = True
        if len(c.text) == 10 and INN_ORG.search(win[-DATE_ROLE:]):
            c.owner = ORGANIZATION
    elif et == "SNILS":
        d = _nearest(TYPE_LABELS["SNILS"], win)
        if d is not None and d <= RIGHT_WINDOW:
            _evidence_boost(c, "label", 0.95)
    elif et == "DEPT_CODE" and not c.labeled:
        d = _nearest(TYPE_LABELS["DEPT_CODE"], win)
        doc_ctx = _DOC_CONTEXT_RE.search(text[max(0, c.start - DOCUMENT_CONTEXT):c.start]) is not None
        if d is not None and d <= 25:
            _evidence_boost(c, "label", 0.95)
        elif doc_ctx:
            _evidence_boost(c, "doc_context", 0.7)
    elif et == "PIN":
        if has_card or CARD_CONTEXT.search(text[max(0, c.start - DOCUMENT_CONTEXT):c.end + DATE_ROLE]):
            _evidence_boost(c, "card_context", 0.95)
            c.signals.append("card_context")
    elif et == "CVV":
        c.signals.append("card_context" if has_card else "cvv_label_only")


def _resolve_contact_owner(c: Candidate, win: str, right: str, in_field: bool) -> None:
    if c.owner == UNKNOWN or not in_field:
        owner = _pick_owner(_owner_scores(win))
        if not (in_field and c.owner != UNKNOWN):
            c.owner = owner
    if c.owner == UNKNOWN:
        r_owner = _pick_owner({o: score for o, score in _owner_scores(right[:RIGHT_OWNER]).items()
                               if o not in (CUSTOMER, EMPLOYEE_PERSONAL)})
        if r_owner != UNKNOWN:
            c.owner = r_owner
            c.signals.append("right_context")
    if c.owner == UNKNOWN:
        if c.etype == "PHONE" and D.is_official_phone(c.text):
            c.owner = ORGANIZATION
            c.signals.append("dict_official_phone")
        elif c.etype == "EMAIL" and D.is_org_email(c.text):
            c.owner = ORGANIZATION
            c.signals.append("dict_org_email")
        elif c.etype == "ADDRESS" and D.is_branch_address(c.text) and not re.search(r"(?i)\bкв\b|квартир", c.text):
            c.owner = BANK_BRANCH
            c.signals.append("dict_branch")
    if c.etype == "ADDRESS" and re.search(r"(?i)(?<![\w])(?:кв\.?|квартира)\s*\d", c.text) and c.owner in (UNKNOWN, PUBLIC):
        c.owner = CUSTOMER
        _evidence_boost(c, "apartment", 0.8)
        c.signals.append("apartment")


def _resolve_person_owner(c: Candidate, text: str, win: str, right: str) -> None:
    personal_score = 0.0
    if _nearest(PERSON_PERSONAL_HOTWORDS, win) is not None:
        personal_score += PERSONAL_ROLE_WEIGHT
        c.evidence["personal_role"] = PERSONAL_ROLE_WEIGHT
    if _nearest(PERSON_PERSONAL_HOTWORDS, right) is not None:
        personal_score += PERSONAL_ROLE_RIGHT_WEIGHT
        c.evidence["personal_role_right"] = PERSONAL_ROLE_RIGHT_WEIGHT

    public_score = 0.0
    dict_pub = _public_person(c)
    pub_d = _nearest(PERSON_PUBLIC_HOTWORDS, win)
    if dict_pub:
        public_score += PUBLIC_KB_WEIGHT
        c.evidence["public_kb_match"] = PUBLIC_KB_WEIGHT
    if pub_d is not None and pub_d <= RIGHT_WINDOW:
        public_score += PUBLIC_CONTEXT_WEIGHT
        c.evidence["public_context"] = PUBLIC_CONTEXT_WEIGHT
    if PERSON_PUBLIC_HOTWORDS.search(right):
        public_score += PUBLIC_CONTEXT_WEIGHT
        c.evidence["public_context_right"] = PUBLIC_CONTEXT_WEIGHT

    if personal_score >= PERSONAL_OWNER_THRESHOLD:
        c.owner = CUSTOMER
        c.signals.append("personal_evidence")
    elif dict_pub:
        c.owner = PUBLIC
        c.signals.append("public_person")
    elif _is_bare_name_only(text, c):
        c.owner = UNKNOWN
        c.signals.append("bare_name_only")
    else:
        c.owner = CUSTOMER


def _resolve_candidate(c: Candidate, text: str, fields: FieldIndex | None, has_card: bool) -> None:
    in_field = _apply_field(c, fields)
    if c.owner == INTERNAL_ID:
        return
    win, _ = left_window(text, c.start)
    right = text[c.end:c.end + RIGHT_WINDOW]
    if c.etype in ("KPP", "OGRN"):
        c.owner = ORGANIZATION
        return
    if c.etype == "ACCOUNT":
        c.owner = INTERNAL_ID
        return
    if c.etype in _NUMERIC_TYPES and not c.labeled and _numeric_exclusion(c, win):
        c.owner = INTERNAL_ID
        c.signals.append("id_label")
        if c.etype == "INN":
            c.evidence["negative_context"] = INN_EV_NEGATIVE_CONTEXT
        return
    if c.etype == "CARD" and not c.labeled:
        acct = _rx(r"р/с|расч[её]тн\w+\s+сч\w*|номер\s+сч[её]та|сч[её]т\b|account")
        d = _nearest(acct, win)
        if d is not None and d <= DATE_ROLE:
            c.owner = INTERNAL_ID
            c.signals.append("account_context")
            return

    _resolve_numeric_evidence(c, text, win, has_card)
    if c.etype in ("DATE", "DATE_TEXT"):
        _resolve_date(c, text, win)
    elif c.etype in _OWNER_TYPES:
        _resolve_contact_owner(c, win, right, in_field)
    elif c.etype == "FIO":
        _resolve_person_owner(c, text, win, right)
    elif c.owner == UNKNOWN:
        c.owner = CUSTOMER
        if c.etype == "INN":
            c.evidence["owner_customer"] = INN_EV_CUSTOMER_OWNER


def _resolve_evidence(text: str, cands: list[Candidate], fields: FieldIndex | None) -> None:
    """Resolve structured fields, owner/date roles, and candidate relations."""
    has_card = any(c.etype == "CARD" and "luhn_ok" in c.signals for c in cands)
    for c in cands:
        _resolve_candidate(c, text, fields, has_card)
    _relations(text, cands)


def resolve(text: str, cands: list[Candidate], fields: FieldIndex | None) -> None:
    """Resolve all context in one directed, deterministic pass.

    Owner/role and structured-field evidence is finalized first. Confidence
    handling then suppresses ambiguous candidates, freezes the
    surviving strong anchors, and finally promotes from that frozen set.
    """
    if not cands:
        return
    ordered = sorted(cands, key=lambda c: (c.start, c.end, c.etype, c.source))
    _resolve_evidence(text, ordered, fields)
    _resolve_vibe(text, ordered)


def _relations(text: str, cands: list[Candidate]) -> None:
    ordered = sorted(cands, key=lambda c: c.start)
    for i, c in enumerate(ordered):
        # «Сидоров Иван Петрович, 12.03.1985» — дата сразу после ФИО без другой роли
        if c.etype in ("DATE", "DATE_TEXT") and c.role == OTHER and i > 0:
            p = ordered[i - 1]
            gap = text[p.end:c.start]
            if p.etype == "FIO" and p.owner != PUBLIC and len(gap) <= 4 and re.fullmatch(r"[\s,(\-–—]*", gap):
                year = next((int(s[5:]) for s in c.signals if s.startswith("year:")), 0)
                if 1900 <= year <= 2015:
                    c.role = DATE_OF_BIRTH
                    c.signals.append("rel_after_person")
        # контакт без владельца, но в одном клаузе с ФИО клиента → CUSTOMER
        if c.etype in _OWNER_TYPES and c.owner == UNKNOWN:
            _, lo = left_window(text, c.start, RELATION_LEFT)
            for p in ordered[:i][::-1]:
                if p.end < lo:
                    break
                if p.etype == "FIO" and p.owner in (CUSTOMER, UNKNOWN):
                    c.owner = CUSTOMER
                    c.signals.append("rel_person_contact")
                    break
