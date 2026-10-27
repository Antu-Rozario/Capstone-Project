from pathlib import Path
from typing import Any

import pytest

from ueba.review import ReviewStore, authorised_actions

CASE: dict[str, Any] = {
    "case_id": "CASE-U0042-2026-09-22",
    "recommended_actions": [
        {"action": "Document the Finding.", "requires_approval": False, "policy_ref": "p#a"},
        {"action": "Temporarily restrict removable media.", "requires_approval": True, "policy_ref": "p#b"},
    ],
}


def test_new_case_is_pending_and_only_unrestricted_actions_are_authorised(tmp_path: Path) -> None:
    store = ReviewStore(tmp_path / "reviews.json")
    assert store.status(CASE["case_id"]) == "pending_review"
    assert [a["action"] for a in authorised_actions(CASE, store.latest(CASE["case_id"]))] == ["Document the Finding."]


def test_approval_unlocks_sensitive_actions(tmp_path: Path) -> None:
    store = ReviewStore(tmp_path / "reviews.json")
    store.record(CASE["case_id"], "approved", reviewer="R. Analyst", notes="Manager unaware of project.")
    assert store.status(CASE["case_id"]) == "approved"
    assert len(authorised_actions(CASE, store.latest(CASE["case_id"]))) == 2


@pytest.mark.parametrize("decision", ["rejected", "needs_more_info"])
def test_other_decisions_keep_sensitive_actions_locked(tmp_path: Path, decision: str) -> None:
    store = ReviewStore(tmp_path / "reviews.json")
    store.record(CASE["case_id"], decision, reviewer="R. Analyst")
    assert len(authorised_actions(CASE, store.latest(CASE["case_id"]))) == 1


def test_decisions_persist_and_history_is_kept(tmp_path: Path) -> None:
    path = tmp_path / "reviews.json"
    ReviewStore(path).record(CASE["case_id"], "needs_more_info", reviewer="A")
    ReviewStore(path).record(CASE["case_id"], "approved", reviewer="B", notes="confirmed")
    reloaded = ReviewStore(path)
    history = reloaded.history(CASE["case_id"])
    assert [d.decision for d in history] == ["needs_more_info", "approved"]
    assert reloaded.latest(CASE["case_id"]).reviewer == "B"  # type: ignore[union-attr]
    assert history[-1].timestamp >= history[0].timestamp


def test_invalid_reviews_are_rejected(tmp_path: Path) -> None:
    store = ReviewStore(tmp_path / "reviews.json")
    with pytest.raises(ValueError):
        store.record(CASE["case_id"], "maybe", reviewer="A")
    with pytest.raises(ValueError):
        store.record(CASE["case_id"], "approved", reviewer="  ")
