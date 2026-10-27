import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from ueba.dashboard import Dataset
from ueba.generator import GeneratorConfig
from ueba.rag import build_index
from ueba.rating import (
    CRITERIA,
    RatingStore,
    analyse,
    build_rating_set,
    krippendorff_alpha_interval,
    load_rating_set,
    save_rating_set,
)
from ueba.studies import synthetic_dataset

POLICIES = Path(__file__).resolve().parents[1] / "policies"


class EchoLLM:
    name = "echo-llm"

    def write(self, system: str, facts: dict[str, Any]) -> dict[str, Any]:
        return {"summary": f"{facts['subject']} is {facts['risk_level']} risk and needs human review.",
                "possible_benign_explanations": facts["candidate_benign_explanations"][:2]}


@pytest.fixture(scope="module")
def ds() -> Dataset:
    return synthetic_dataset(GeneratorConfig(n_users=60, seed=11))


@pytest.fixture(scope="module")
def rating_set(ds: Dataset) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    return build_rating_set([ds], build_index(POLICIES, backend="tfidf"),
                            {"template": None, "echo-llm": EchoLLM()}, users_per_dataset=4, seed=1)


def test_every_user_is_written_by_every_writer(rating_set: tuple[list[dict[str, Any]], dict[str, dict[str, str]]]) -> None:
    items, key = rating_set
    assert len(items) == 8 and set(key) == {i["item_id"] for i in items}
    by_case: dict[str, set[str]] = {}
    for item_id, k in key.items():
        by_case.setdefault(k["case_id"], set()).add(k["writer"])
    assert all(w == {"template", "echo-llm"} for w in by_case.values())


def test_items_are_blind(rating_set: tuple[list[dict[str, Any]], dict[str, dict[str, str]]]) -> None:
    items, _ = rating_set
    text = json.dumps(items)
    assert "echo-llm" not in text and "generated_by" not in text and "template" not in text
    for item in items:
        assert item["summary"] and item["evidence"] and item["possible_benign_explanations"] is not None


def test_order_is_shuffled_reproducibly(ds: Dataset) -> None:
    retriever = build_index(POLICIES, backend="tfidf")
    a, _ = build_rating_set([ds], retriever, {"template": None, "echo-llm": EchoLLM()}, users_per_dataset=4, seed=1)
    b, _ = build_rating_set([ds], retriever, {"template": None, "echo-llm": EchoLLM()}, users_per_dataset=4, seed=1)
    assert [i["item_id"] for i in a] == [i["item_id"] for i in b]
    assert [i["item_id"] for i in a] != sorted(i["item_id"] for i in a) or len(a) < 3


def test_save_and_load_keep_the_key_in_a_separate_file(
    rating_set: tuple[list[dict[str, Any]], dict[str, dict[str, str]]], tmp_path: Path
) -> None:
    items, key = rating_set
    save_rating_set(items, key, tmp_path)
    assert (tmp_path / "items.json").exists() and (tmp_path / "key.json").exists()
    assert "echo-llm" not in (tmp_path / "items.json").read_text()
    items2, key2 = load_rating_set(tmp_path)
    assert items2 == items and key2 == key


def test_rating_store_validates_and_persists(tmp_path: Path) -> None:
    store = RatingStore(tmp_path / "ratings.json")
    scores = {c: 4 for c in CRITERIA}
    store.record("Rater A", "item-1", scores, unsupported_claim=False, comment="ok")
    with pytest.raises(ValueError):
        store.record("Rater A", "item-2", {**scores, "clarity": 7}, unsupported_claim=False)
    with pytest.raises(ValueError):
        store.record(" ", "item-2", scores, unsupported_claim=False)
    with pytest.raises(ValueError):
        store.record("Rater A", "item-2", {"clarity": 3}, unsupported_claim=False)
    reloaded = RatingStore(tmp_path / "ratings.json")
    assert reloaded.done_by("Rater A") == {"item-1"}
    assert reloaded.ratings()[0]["scores"]["clarity"] == 4


def test_krippendorff_alpha_is_one_for_perfect_agreement_and_low_for_noise() -> None:
    perfect = np.array([[1, 2, 3, 4, 5], [1, 2, 3, 4, 5], [1, 2, 3, 4, 5]], dtype=float)
    assert krippendorff_alpha_interval(perfect) == pytest.approx(1.0)
    rng = np.random.default_rng(0)
    noise = rng.integers(1, 6, size=(3, 40)).astype(float)
    assert krippendorff_alpha_interval(noise) < 0.3
    with_missing = perfect.copy()
    with_missing[0, 0] = np.nan
    assert krippendorff_alpha_interval(with_missing) == pytest.approx(1.0)


def test_analyse_unblinds_and_summarises_per_writer(
    rating_set: tuple[list[dict[str, Any]], dict[str, dict[str, str]]], tmp_path: Path
) -> None:
    items, key = rating_set
    store = RatingStore(tmp_path / "ratings.json")
    for rater in ["A", "B"]:
        for item in items:
            good = key[item["item_id"]]["writer"] == "template"
            store.record(rater, item["item_id"], {c: 5 if good else 3 for c in CRITERIA}, unsupported_claim=not good)
    result = analyse(items, key, store.ratings())
    per = result["per_writer"].set_index("writer")
    assert per.loc["template", "clarity"] == 5 and per.loc["echo-llm", "clarity"] == 3
    assert per.loc["echo-llm", "unsupported_claim_rate"] == 1.0
    assert per.loc["template", "ratings"] == 8
    assert result["raters"] == 2
    assert result["alpha"]["clarity"] == pytest.approx(1.0)
