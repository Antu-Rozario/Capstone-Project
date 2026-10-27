import re

from ueba.controls import load_control_mapping
from ueba.detection import RULES


def test_every_rule_maps_to_at_least_one_technique_and_one_control() -> None:
    mapping = load_control_mapping()
    assert set(mapping.rules) == set(RULES)
    for rule in RULES:
        entry = mapping.lookup(rule)
        assert entry["attack"] and entry["nist"], rule


def test_ids_are_well_formed() -> None:
    mapping = load_control_mapping()
    for rule in RULES:
        entry = mapping.lookup(rule)
        for t in entry["attack"]:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", t["id"]), t
            assert t["name"]
        for c in entry["nist"]:
            assert re.fullmatch(r"[A-Z]{2}-\d+(\(\d+\))?", c["id"]), c
            assert c["name"]


def test_unverified_draft_status_is_carried_with_every_lookup() -> None:
    mapping = load_control_mapping()
    entry = mapping.lookup("MASS_DOWNLOAD")
    assert entry["verified"] is mapping.verified
    assert entry["finding_type"] == "MASS_DOWNLOAD"
    if not mapping.verified:
        assert "verif" in entry["note"].lower()
