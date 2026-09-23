"""Address and labeled free-text detectors and span helpers."""
from __future__ import annotations

import re

from ..candidates import Candidate, SpanIndex
from ..windows import ADDRESS_COMPONENT, ISSUER_VALUE, OTHER_FREE_VALUE
from .common import _cand
from .dates import DATE_NUM_RE, DATE_TEXT_RE

ADDRESS_LABEL_RE = re.compile(
    r"(?i)(?<![\w])(?:(?:фактический|домашний|почтовый|юридический|новый|прежний|старый)\s+)?"
    r"(?:адрес[а-я]*|проживает|проживающ[а-я]*|зарегистрирова[а-я]*|прописан[а-я]*|"
    r"место\s+жительства|место\s+регистрации|прописка|регистрация|отделени[а-я]*|филиал[а-я]*)"
    r"(?:\s+(?:клиент\w*|заявител\w*|заёмщик\w*|заемщик\w*|получател\w*|проживани\w*|регистраци\w*|"
    r"сотрудник\w*|отделени\w*|офис\w*|банк\w*|компани\w*|организаци\w*|доставк\w*|филиал\w*|"
    r"банкомат\w*|места|жительства|фактическ\w*|постоянн\w*|временн\w*|почтов\w*|электронн\w*|"
    r"почты|регистрации|пребывания|нашего|нового|магазин\w*|склад\w*|пункт\w*|выдачи|и|для|"
    r"корреспонденции|по\s+прописке|по\s+месту\s+жительства)){0,4}"
    r"(?:\s+(?:находится|расположен\w*))?(?:\s+по\s+адресу)?(?![\w])\s*[:\-–—]?\s*"
)
_ADDR_COMPONENT = (
    r"(?:(?:г|с|д|к|ш|пр|пл|м)\.|(?:гор|пос|пгт|дер|обл|респ|р-н|ул|пр-т|просп|пер|б-р|бул|наб|мкр|мкрн|"
    r"пр-во|проезд|туп|дом|корп|стр|кв|оф|оф-ра|пом|лит|зд)\.?|"
    r"город|города|городе|городов|городам|городах|городом|"
    r"посёлок|поселок|посёлка|посёлке|посёлков|поселка|"
    r"деревня|деревни|деревне|деревень|деревнями|"
    r"село|села|селе|селам|селах|"
    r"область|области|областей|областью|"
    r"край|края|краях|краем|краев|"
    r"республика|республики|республике|республик|республикой|"
    r"район|района|районе|районов|районом|"
    r"улица|улицы|улице|улиц|улицей|ул\.|"
    r"проспект|проспекта|проспекте|проспектов|проспектом|пр\.|просп\.|"
    r"переулок|переулка|переулке|переулков|переулком|пер\.|"
    r"бульвар|бульвара|бульваре|бульваров|бульваром|б-р\.|"
    r"шоссе|шоссей|шоссе|"
    r"набережная|набережной|набережных|"
    r"площадь|площади|площадей|площадью|"
    r"микрорайон|микрорайона|микрорайоне|микрорайонов|микрорайоном|мкр\.|мкрн\.|"
    r"тупик|тупика|тупике|тупиков|туп\.|"
    r"дом|дома|доме|домов|домом|д\.|"
    r"корпус|корпуса|корпусе|корпусов|корпусом|корп\.|"
    r"строение|строения|строении|строений|строением|стр\.|"
    r"квартира|квартиры|квартире|квартир|квартирой|кв\.|"
    r"офис|офиса|офисе|офисов|офисом|оф\.|"
    r"помещение|помещения|помещении|помещений|помещением|пом\.|"
    r"литер|литера|литере|литеров|литером|лит\.|"
    r"здание|здания|здании|зданий|зданием|зд\.|"
    r"сквер|сквера|сквере|скверов|сквером|"
    r"парк|парка|парке|парков|парком|"
    r"аллея|аллеи|аллее|аллей|аллеей)"
)
ADDRESS_MARKER_RE = re.compile(
    rf"(?i)(?<![\w\-]){_ADDR_COMPONENT}(?![\w\-])"
)
# «Офис компании: ...», «корпус банка» — не начало адреса, если за маркером нет номера
_WEAK_START = re.compile(r"(?i)^(?:оф|офис|пом|помещение|корп|корпус|стр|строение|лит|дом|кв|квартира)\.?$")
_POSTCODE_RE = re.compile(r"(?<!\d)[1-6]\d{5}(?!\d)")
# явная метка «индекс»/«почтовый индекс» + 6-значный индекс
INDEX_LABEL_RE = re.compile(r"(?i)(?<![\w])(?:почтов\w*\s+)?индекс\w*(?![\w])[\s:№=\-–—]*([1-6]\d{5})(?!\d)")
# индекс перед адресным маркером без улицы/дома («630099, г. Москва») — сам факт индекса
# уже достаточно специфичен, чтобы считать цепочку адресом.
_POSTCODE_BEFORE_RE = re.compile(r"(?<!\d)([1-6]\d{5})\s*,\s*$")

FREE_LABELS = (
    ("BIRTH_PLACE", re.compile(
        r"(?i)(?<![\w])(место\s+рождения|уроженец|уроженка|родил(?:ся|ась)\s+в)(?![\w])[\s:\-–—]*")),
    ("ISSUER", re.compile(
        r"(?i)(?<![\w])(орган,?\s*выдавший(?:\s+документ)?|кем\s+выдан[а-я]?|выдан[а-я]*|выдал[а-я]*|issued\s+by)"
        r"(?![\w])[\s:\-–—]*(?=[А-ЯЁA-Z«\"]|отдел|отделени|управлени|территориальн|гу\b|уфмс|овд|увд|мвд|мо\b)")),
    ("CITIZENSHIP", re.compile(r"(?i)(?<![\w])(гражданство)(?![\w])[\s:\-–—]*")),
)
_ISSUER_ORG = re.compile(
    r"(?i)(?:овд|увд|уфмс|офмс|мвд|гувд|гу\s|ту\s|тп\s|мо\s|гибдд|мрэо|рэо|отдел|отделени|управлени|"
    r"паспортн|территориальн|полиции|милиции|россии|рф)"
)

# Где заканчивается значение свободного поля (адрес, орган выдачи и т.п.).
_NEXT_LABEL = re.compile(
    r"(?i),?\s*(?:тел(?:ефон)?\.?|моб\.?|e-?mail|email|почта|эл\.\s*почта|паспорт|серия|дата|д\.р\.|"
    r"код\s+подразделения|код|инн|снилс|карта|номер|родил|выдан|место\s+рождения|гражданство|фио|"
    r"имя|получатель|отправитель|новый|новая|предыдущ\w*|созаём\w*|созаем\w*|клиент\w*|сотрудник\w*|"
    r"cvv|cvc|pin|пин|счёт|счет|сумма|заказ|заявк\w*|обращени\w*|кабинет|доставк\w*|"
    r"и\s+телефон|а\s+также)(?![\w])"
)
_ABBREV_BEFORE_DOT = re.compile(
    r"(?i)(?:\b(?:г|гор|ул|д|кв|пр|пер|обл|респ|р-н|р-на|р-не|стр|корп|к|пос|с|наб|пл|мкр|б-р|ш|оф|им|"
    r"т|им|ст|гр|рф|тер|пгт|дер|просп|пом|лит)|[А-ЯЁA-Z])$"
)


def value_extent(text: str, start: int, limit: int = 200) -> int:
    """Конец свободного значения, начинающегося в start."""
    end = min(len(text), start + limit)
    i = start
    while i < end:
        ch = text[i]
        if ch in "\n;|\"«»(){}[]<>&=":
            return i
        # «г. Москва», «ул. Тверская» — точка сокращения, не конец значения
        if (
            ch == "."
            and (i + 1 >= len(text) or text[i + 1] in " \t\n")
            and not _ABBREV_BEFORE_DOT.search(text[max(start, i - 6):i])
        ):
            return i
        if ch in "—–" and i > start and text[i - 1] == " ":
            return i
        if ch == "," or ch in " \t":
            m = _NEXT_LABEL.match(text, i)
            if m and i > start:
                return i
        i += 1
    return end


def _trim(text: str, s: int, e: int) -> tuple[int, int]:
    while s < e and text[s] in " \t,:;-–—":
        s += 1
    while e > s and text[e - 1] in " \t,:;.-–—":
        # не отрезаем точку сокращения «кв.» — только финальную пунктуацию
        if text[e - 1] == "." and _ABBREV_BEFORE_DOT.search(text[max(s, e - 6):e - 1]):
            break
        e -= 1
    return s, e

def _address_like(value: str) -> bool:
    """Значение после метки «адрес»/«проживает» действительно похоже на адрес."""
    if not value or not (value[0].isupper() or value[0].isdigit() or ADDRESS_MARKER_RE.match(value)):
        return False  # «зарегистрирован в системе ...»
    if DATE_NUM_RE.fullmatch(value) or DATE_TEXT_RE.fullmatch(value):
        return False
    if ADDRESS_MARKER_RE.search(value) or _POSTCODE_RE.search(value):
        return True
    caps = re.findall(r"[А-ЯЁ][а-яё\-]{2,}", value)
    # «Москва, Тверская 10» / «Екатеринбург, Восточная, 19»
    return bool(caps) and (bool(re.search(r"\d", value)) or ("," in value and len(caps) >= 2))


def detect_address(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    labeled_spans = SpanIndex()
    low = text.lower()
    if any(k in low for k in ("адрес", "прожива", "зарегистр", "прописк", "прописан", "жительства", "регистрац", "отделени", "филиал")):
        for m in ADDRESS_LABEL_RE.finditer(text):
            vs = m.end()
            if vs >= len(text) or not (text[vs].isalnum()):
                continue
            ve = value_extent(text, vs)
            vs, ve = _trim(text, vs, ve)
            if ve - vs < 3:
                continue
            val = text[vs:ve]
            if "@" in val and not _address_like(val.split("@")[0]):
                continue
            if not _address_like(val):
                continue
            out.append(_cand(text, vs, ve, "ADDRESS", 0.85, "address_label", anchor=m.start(), labeled=True))
            labeled_spans.add(vs, ve)
    # Явная метка «индекс»/«почтовый индекс»: «Индекс: 630099» — даже без остального адреса.
    for m in INDEX_LABEL_RE.finditer(text):
        s, e = m.span(1)
        if labeled_spans.overlaps(s, e):
            continue
        out.append(_cand(text, s, e, "ADDRESS", 0.85, "address_index_label", anchor=m.start(), labeled=True))
        labeled_spans.add(s, e)
    # Без метки: цепочка из >=2 адресных компонентов («г. Москва, ул. Тверская, д. 5»).
    markers = list(ADDRESS_MARKER_RE.finditer(text))
    i = 0
    while i < len(markers):
        m0 = markers[i]
        if labeled_spans.contains_point(m0.start()) or (
                _WEAK_START.match(m0.group(0)) and not re.match(r"\s*№?\s*\d", text[m0.end():m0.end() + 6])):
            i += 1
            continue
        s = m0.start()
        comp = 1
        # индекс сразу перед маркером («630099, г. Москва») — считаем доп. компонентом,
        # сам индекс уже достаточно специфичен, и включаем его в границы адреса.
        pre_pm = _POSTCODE_BEFORE_RE.search(text[max(0, s - 9):s])
        if pre_pm:
            s = s - len(text[max(0, s - 9):s]) + pre_pm.start()
            comp += 1
        e = value_extent(text, m0.end(), ADDRESS_COMPONENT)
        j = i + 1
        while j < len(markers) and markers[j].start() <= e + 3:
            comp += 1
            e = max(e, value_extent(text, markers[j].end(), ADDRESS_COMPONENT))
            j += 1
        s, e = _trim(text, s, e)
        val = text[s:e]
        has_house = bool(re.search(r"\d", val))
        if (
            (comp >= 2 or (has_house and re.match(r"(?i)(?:ул|улица|пр|проспект|пер|переулок|б-р|бульвар|ш|шоссе|наб)", val)))
            and e - s >= 5
            and not labeled_spans.overlaps(s, e)
        ):
            out.append(_cand(text, s, e, "ADDRESS", 0.75 if comp >= 2 else 0.6, "address_markers"))
        i = j
    return out


def detect_labeled_freetext(text: str) -> list[Candidate]:
    out = []
    low = text.lower()
    for etype, rx in FREE_LABELS:
        if etype == "BIRTH_PLACE" and not any(k in low for k in ("рожд", "урожен", "родил")):
            continue
        if etype == "ISSUER" and not any(k in low for k in ("выда", "issued")):
            continue
        if etype == "CITIZENSHIP" and "гражданств" not in low:
            continue
        for m in rx.finditer(text):
            vs = m.end()
            ve = value_extent(text, vs, ISSUER_VALUE if etype == "ISSUER" else OTHER_FREE_VALUE)
            if etype == "ISSUER":
                # «МО МВД России «Тушинское»» — название органа в кавычках сразу после
                # текста без метки продолжает то же значение, а не обрывает его.
                qm = re.match(r'\s*[«"]', text[ve:ve + 3])
                if qm:
                    close = text.find("»" if text[ve + qm.end() - 1] == "«" else '"', ve + qm.end())
                    if close != -1:
                        ve = close + 1
            if etype == "CITIZENSHIP":
                vm = re.match(r"(?:РФ|[А-ЯЁа-яё\-]{2,40}(?:\s+[А-ЯЁа-яё\-]{2,40})?)", text[vs:ve])
                if not vm:
                    continue
                ve = vs + vm.end()
            vs, ve = _trim(text, vs, ve)
            if ve - vs < 2:
                continue
            val = text[vs:ve]
            if etype == "ISSUER" and (re.match(r"\d", val) or not _ISSUER_ORG.search(val)):
                continue
            out.append(_cand(text, vs, ve, etype, 0.85, f"{etype.lower()}_label", anchor=m.start(), labeled=True))
    return out
