"""Unit-тесты компонентов: validators, structure parser, span resolver, offsets, chunking."""
import random
from itertools import pairwise

import pytest

from app.masking import ALL_TYPES_SET, apply_masks, mask_text
from app.pii.candidates import MASK, Candidate, SpanIndex
from app.pii.detectors import inn_ok, luhn_ok, snils_ok
from app.pii.pipeline import analyze, chunks
from app.pii.resolver import select
from app.pii.structure import classify_key, parse_fields


def test_validators():
    assert luhn_ok("4271041077800454")
    assert not luhn_ok("1234567890123456")
    assert inn_ok("7707083893") and inn_ok("500100732259")
    assert not inn_ok("7707083894")
    assert snils_ok("11223344595")


def test_field_classification():
    assert classify_key("customer_phone").etype == "PHONE"
    assert classify_key("customer_phone").owner == "CUSTOMER"
    assert classify_key("branch_address").owner == "BANK_BRANCH"
    assert classify_key("support_email").owner == "ORGANIZATION"
    assert classify_key("birth_date").date_role == "DATE_OF_BIRTH"
    assert classify_key("deliveryDate").date_role == "DELIVERY_DATE"
    assert classify_key("номер_обращения").owner == "INTERNAL_ID"


def test_structure_offsets_are_absolute():
    text = 'log: {"customer_phone": "+7 912 345 67 89"} a=1&branch_address=г. Москва&x=2\nuser_email: a@b.ru'
    for f in parse_fields(text):
        assert text[f.start:f.end].strip() != ""
        assert f.start >= 0 and f.end <= len(text)
    keys = {f.key for f in parse_fields(text)}
    assert {"customer_phone", "branch_address", "user_email"} <= keys


def test_resolver_merges_overlaps_like_reference_engine():
    text = "адрес: ул. Ленина, д. 5 +7 912 345 67 89"
    addr = Candidate(7, len(text), "ADDRESS", text[7:], 0.8, "t", action=MASK)
    s = text.index("+7")
    phone = Candidate(s, len(text), "PHONE", text[s:], 0.9, "t", action=MASK)
    out = select(text, [addr, phone])
    assert len(out) == 1
    assert out[0].etype == "PHONE"
    assert (out[0].start, out[0].end) == (addr.start, len(text))
    assert "merged_type:ADDRESS" in out[0].signals
    assert not any(a.overlaps(b) for a in out for b in out if a is not b)


def test_span_index():
    idx = SpanIndex([(10, 20), (30, 40)])
    assert idx.overlaps(15, 16) and idx.overlaps(35, 50) and not idx.overlaps(20, 30)


def test_apply_masks_checks_offsets():
    text = "тел +7 912 345 67 89"
    bad = Candidate(0, 3, "PHONE", "xxx", 0.9, "t", action=MASK)
    with pytest.raises(ValueError, match="do not match"):
        apply_masks(text, [bad])


def test_spans_valid_and_non_overlapping_on_random_text():
    rnd = random.Random(7)
    parts = ["Клиент Иванов Иван Иванович", "+7 912 345 67 89", "ivan@mail.ru", "12.03.1990",
             "дата рождения 01.02.1985", "г. Москва, ул. Лесная, д. 12, кв. 3", "паспорт 45 06 123456",
             "отделение банка: ул. Тверская, д. 5", "CVV 123", "номер заказа 4506123456", "обычный текст",
             "Пушкин", "ИНН 500100732259", "\n", "; ", ", "]
    for _ in range(50):
        text = " ".join(rnd.choice(parts) for _ in range(30))
        cands = analyze(text, ALL_TYPES_SET)
        prev_end = -1
        for c in sorted(cands, key=lambda c: c.start):
            assert text[c.start:c.end] == c.text
            assert c.start >= prev_end
            prev_end = c.end
        mask_text(text)


def test_chunking_keeps_absolute_offsets():
    block = "Клиент Иванов Иван Иванович, тел +7 912 345 67 89, дата рождения 01.02.1985.\n"
    text = block * 3000
    bounds = list(chunks(text, 5000))
    assert bounds[0][0] == 0 and bounds[-1][1] == len(text)
    assert all(a[1] == b[0] for a, b in pairwise(bounds))
    out, types, spans = mask_text(text)
    assert types.count("PHONE") == 3000 and types.count("FIO") == 3000
    assert "345 67" not in out and "Иванов" not in out
    for s, e, t in spans:
        assert 0 <= s < e <= len(text)
