"""Personal-name and cardholder detectors."""
from __future__ import annotations

import re

from ..candidates import Candidate, SpanIndex
from ..morph import STOP_WORDS, labeled_non_name, person_like, word_tags
from ..windows import LATIN_FIO_LEFT, LATIN_FIO_RIGHT
from .common import _cand

_CAP = r"[А-ЯЁа-яё]{2,30}(?:-[А-ЯЁа-яё]{2,30})?"
FIO_SEQ_RE = re.compile(rf"(?<![\w-])({_CAP})(?:\s+({_CAP}))(?:\s+({_CAP}))?(?:\s+({_CAP}))?(?![\w-])")
# Фамилия + 1-2 инициала в любом порядке: «Иванов И.», «Иванов И.О.», «И. Иванов», «И.О. Иванов»,
# «иванов и.», «ИВАНОВ И.» — регистр не важен, финальный фильтр — морфология (word_tags).
_INIT = r"[А-ЯЁа-яё]\.\s?"
FIO_INITIALS_RE = re.compile(
    rf"(?<![\w-])(?:({_CAP})\s+(?:{_INIT}){{1,2}}|(?:{_INIT}){{1,2}}\s*({_CAP}))(?![\w-])"
)
FIO_LABEL_RE = re.compile(
    r"(?i)(?<![\w])(фио|ф\.и\.о\.|фамилия(?:,\s*имя(?:,?\s*отчество)?)?|предыдущая\s+фамилия|"
    r"девичья\s+фамилия|имя(?:\s+и\s+отчество)?|отчество|клиент(?:ка)?|получатель|отправитель|"
    r"заявитель|созаёмщи(?:к|ца)|созаемщи(?:к|ца)|заёмщи(?:к|ца)|заемщи(?:к|ца)|поручитель|"
    r"вкладчи\w*|бенефициар\w*|наследни\w*|доверенн\w*\s+лиц\w*|владел\w*\s+счет\w*|"
    r"держател\w*(?:\s+карты)?|владел\w*\s+карты|плательщик\w*|"
    r"г-н|г-жа|гражданин|гражданка|господин|госпожа)(?![\w])[\s:]*"
)
# После явной роли-метки допускаем любые регистры («клиент Иван», «клиент ИВАНОВ И.», «клиент иванов и. п.»)
_FIO_LABEL_TOK = r"(?:[А-ЯЁа-яё]\.|[А-ЯЁа-яё]{2,30}(?:-[А-ЯЁа-яё]{2,30})?)"
_FIO_LABEL_VALUE_RE = re.compile(
    rf"({_FIO_LABEL_TOK})(?:\s?({_FIO_LABEL_TOK}))?(?:\s?({_FIO_LABEL_TOK}))?"
)
# Роль-слово может стоять не прямо перед значением («плательщик перевода указан: иванов»):
# ищем роль-слово, затем ':' в пределах короткого окна, значение — сразу после двоеточия.
_PERSON_ROLE_WORDS_RE = re.compile(
    r"(?i)(?<![\w])(?:плательщик\w*|клиент\w*|заявител\w*|заёмщи\w*|заемщи\w*|созаёмщи\w*|"
    r"созаемщи\w*|получател\w*|отправител\w*|поручител\w*|держател\w*|вкладчи\w*|бенефициар\w*|"
    r"наследни\w*|владел\w*)(?![\w])"
)
_ROLE_COLON_GAP = 40

# Латиница / транслит ФИО в банковском контексте: «Sidorova Anna», «PETROV PETR».
_LATIN_TOK = r"(?:[A-Z][a-z]{1,30}|[A-Z]{2,30})(?:-(?:[A-Z][a-z]{1,30}|[A-Z]{2,30}))?"
FIO_LATIN_SEQ_RE = re.compile(rf"(?<![\w-])({_LATIN_TOK})\s+({_LATIN_TOK})(?:\s+({_LATIN_TOK}))?(?![\w-])")
_LATIN_STOP = frozenset({
    "THE", "AND", "FOR", "CARD", "BANK", "PAYMENT", "TRANSFER", "ACCOUNT", "VISA", "MASTERCARD",
    "MIR", "SWIFT", "IBAN", "LTD", "INC", "OOO", "OK", "SMS", "OTP", "CVV", "CVC", "PIN", "ATM",
})
_LATIN_FIO_CONTEXT_RE = re.compile(
    r"(?i)(?<![\w])(?:карт\w*|операци\w*|банк\w*|счет\w*|счёт\w*|оплат\w*|платеж\w*|платёж\w*|"
    r"перевод\w*|транзакци\w*|плательщик\w*|клиент\w*|заявител\w*|заёмщи\w*|заемщи\w*|"
    r"получател\w*|отправител\w*|поручител\w*|держател\w*|вкладчи\w*|бенефициар\w*|владел\w*)(?![\w])"
)

CARDHOLDER_LABEL_RE = re.compile(
    r"(?i)(?<![\w])(имя\s+держателя(?:\s+карты)?|держатель(?:\s+карты)?|cardholder(?:\s+name)?|"
    r"card\s*holder(?:\s+name)?|имя\s+на\s+карте|name\s+on\s+card)(?![\w])[\s:#=\-]*"
)
CARDHOLDER_VALUE_RE = re.compile(
    r"[A-Z][A-Z'\-]{1,30}(?:\s+[A-Z][A-Z'\-]{1,30}){1,2}(?![A-Za-z])"
    r"|[А-ЯЁ][А-ЯЁ\-]{1,30}(?:\s+[А-ЯЁ][А-ЯЁ\-]{1,30}){1,2}(?![А-Яа-яЁё])"
    r"|[A-Z][a-z'\-]{1,30}(?:\s+[A-Z][a-z'\-]{1,30}){1,2}(?![A-Za-z])"
    r"|[А-ЯЁ][а-яё\-]{1,30}(?:\s+[А-ЯЁ][а-яё\-]{1,30}){1,2}(?![А-Яа-яЁё])"
)

# Адрес: явная метка + значение.

def _sentence_start(text: str, pos: int) -> bool:
    j = pos - 1
    while j >= 0 and text[j] in " \t\"«(":
        j -= 1
    return j < 0 or text[j] in ".!?\n:;"


def _add_fio(out: list[Candidate], taken: SpanIndex, candidate: Candidate) -> None:
    out.append(candidate)
    taken.add(candidate.start, candidate.end)


def _fio_initials(text: str, out: list[Candidate], taken: SpanIndex) -> None:
    for match in FIO_INITIALS_RE.finditer(text):
        surname = match.group(1) or match.group(2)
        tags = word_tags(surname)
        if surname.lower() in STOP_WORDS or (tags[3] and not tags[1]):
            continue
        _add_fio(out, taken, _cand(text, match.start(), match.end(), "FIO", 0.85, "fio_initials"))


def _fio_sequences(text: str, out: list[Candidate], taken: SpanIndex) -> None:
    for match in FIO_SEQ_RE.finditer(text):
        if taken.overlaps(match.start(), match.end()):
            continue
        tokens = [group for group in match.groups() if group]
        starts = [match.start(i + 1) for i in range(len(tokens))]
        best: tuple[float, int, int] | None = None
        for i in range(len(tokens)):
            for j in range(len(tokens), i + 1, -1):
                score = person_like(tuple(tokens[i:j]))
                if score is not None:
                    best = score, starts[i], starts[j - 1] + len(tokens[j - 1])
                    break
            if best:
                break
        if best is None:
            continue
        score, start, end = best
        if _sentence_start(text, start) and score < 0.8:
            score -= 0.1
        _add_fio(out, taken, _cand(text, start, end, "FIO", score, "fio_morph"))


def _name_prefix_length(match: re.Match[str]) -> int:
    """Число начальных токенов имени до первого однозначного не-имени."""
    count = 0
    for token in (group for group in match.groups() if group):
        if labeled_non_name(token):
            break
        count += 1
    return count


def _fio_labels(text: str, out: list[Candidate], taken: SpanIndex) -> None:
    for label in FIO_LABEL_RE.finditer(text):
        value = _FIO_LABEL_VALUE_RE.match(text, label.end())
        if value is None or taken.contains_point(value.start()):
            continue
        count = _name_prefix_length(value)
        if count:
            _add_fio(out, taken, _cand(text, value.start(), value.end(count), "FIO", 0.8,
                                       "fio_label", anchor=label.start(), labeled=True))


def _fio_role_colons(text: str, out: list[Candidate], taken: SpanIndex) -> None:
    for role in _PERSON_ROLE_WORDS_RE.finditer(text):
        segment_end = min(len(text), role.end() + _ROLE_COLON_GAP)
        colon = re.search(r":\s*", text[role.end():segment_end])
        if colon is None:
            continue
        value_start = role.end() + colon.end()
        if taken.contains_point(value_start):
            continue
        value = _FIO_LABEL_VALUE_RE.match(text, value_start)
        if value is None:
            continue
        count = _name_prefix_length(value)
        if count and not taken.overlaps(value.start(), value.end(count)):
            _add_fio(out, taken, _cand(text, value.start(), value.end(count), "FIO", 0.75,
                                       "fio_role_colon", anchor=role.start(), labeled=True))


def _fio_latin(text: str, out: list[Candidate], taken: SpanIndex) -> None:
    for match in FIO_LATIN_SEQ_RE.finditer(text):
        if taken.overlaps(match.start(), match.end()):
            continue
        tokens = [group for group in match.groups() if group]
        if any(token.upper() in _LATIN_STOP for token in tokens):
            continue
        left = text[max(0, match.start() - LATIN_FIO_LEFT):match.start()]
        right = text[match.end():match.end() + LATIN_FIO_RIGHT]
        if _LATIN_FIO_CONTEXT_RE.search(left) or _LATIN_FIO_CONTEXT_RE.search(right):
            _add_fio(out, taken, _cand(text, match.start(), match.end(), "FIO", 0.7, "fio_latin"))


def _fio_single_words(text: str, out: list[Candidate], taken: SpanIndex) -> None:
    for match in re.finditer(rf"(?<![\w-]){_CAP}(?![\w-])", text):
        start, end = match.span()
        if taken.overlaps(start, end) or match.group().lower() in STOP_WORDS:
            continue
        is_name, is_surn, is_patr, other = word_tags(match.group())
        if not other and (is_name or is_surn or is_patr):
            cand = _cand(text, start, end, "FIO", 0.6, "fio_single_word")
            cand.signals.append("requires_anchor")
            _add_fio(out, taken, cand)


def detect_fio(text: str) -> list[Candidate]:
    """Применить стратегии ФИО по убыванию специфичности."""
    out: list[Candidate] = []
    taken = SpanIndex()
    for strategy in (_fio_initials, _fio_sequences, _fio_labels, _fio_role_colons,
                     _fio_latin, _fio_single_words):
        strategy(text, out, taken)
    return out


def detect_cardholder(text: str) -> list[Candidate]:
    out = []
    for m in CARDHOLDER_LABEL_RE.finditer(text):
        vm = CARDHOLDER_VALUE_RE.match(text, m.end())
        if not vm:
            continue
        out.append(_cand(text, vm.start(), vm.end(), "CARDHOLDER", 0.9, "cardholder_label",
                         anchor=m.start(), labeled=True))
    return out
