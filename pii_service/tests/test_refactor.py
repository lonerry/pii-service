"""Регрессии для реестра типов и чистоты safety-net маскирования."""

import yaml

from app.config import _validate, load_config
from app.masking import _final_leak_guard, apply_masks, mask_text
from app.pii.candidates import Action, Candidate, DateRole, Owner
from app.pii.policy import Policy
from app.pii.types import ALL_TYPES_SET, TYPE_SPECS


def test_every_registered_type_is_valid_in_config():
    config = {"systems": {"all_types": {"types": list(ALL_TYPES_SET)}}}
    assert _validate(config)["systems"]["all_types"]["types"] == list(ALL_TYPES_SET)
    assert all(spec.priority > 0 for spec in TYPE_SPECS.values())
    assert {"ACCOUNT", "CARD_LAST4", "KPP", "OGRN", "MONEY", "BIK"} <= ALL_TYPES_SET


def test_load_config_accepts_all_registered_types(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"systems": {"test": {"types": list(ALL_TYPES_SET)}}}), encoding="utf-8")
    monkeypatch.setenv("CONFIG_PATH", str(path))
    assert set(load_config()["systems"]["test"]["types"]) == ALL_TYPES_SET


def test_guard_does_not_mutate_caller_spans():
    original = [(0, 3, "FIO")]
    _, _, updated = _final_leak_guard("Код 4271041077800454", [], original, {"CARD"})
    assert original == [(0, 3, "FIO")]
    assert updated is not original
    assert updated[-1][2] == "CARD"


def test_unknown_candidate_still_masks_all():
    candidate = Candidate(0, 6, "UNREGISTERED", "secret", 1.0, "test", action=Action.MASK)
    assert apply_masks("secret", [candidate])[0] == "******"


def test_domain_values_remain_string_compatible():
    assert Owner.CUSTOMER == "CUSTOMER"
    assert DateRole.DATE_OF_BIRTH == "DATE_OF_BIRTH"
    assert Action.MASK == "MASK"


def test_detection_normalization_matches_reference_engine():
    masked, types, _ = mask_text("телефон:\u00a0＋７\u2011９１２\u2011３４５\u2011６７\u2011８９")
    assert "PHONE" in types
    assert "３４５" not in masked


def test_strict_profile_uses_opaque_hmac_tokens():
    masked, types, _ = mask_text(
        "телефон +7 912 345 67 89",
        policy=Policy(detection_profile="strict"),
    )
    assert types == ["PHONE"]
    assert masked.startswith("телефон <PHONE_")
    assert masked.endswith("_0>")
