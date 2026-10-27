import json
from pathlib import Path

import pandas as pd
import pytest

from ueba.dashboard import (
    action_status,
    available_datasets,
    daily_activity,
    filter_ranking,
    headline_metrics,
    load_dataset,
)
from ueba.detection import DetectionResult, run_detection
from ueba.generator import GeneratorConfig, SyntheticData, generate, save_processed
from ueba.review import ReviewDecision


@pytest.fixture(scope="module")
def synth() -> SyntheticData:
    return generate(GeneratorConfig(n_users=60, seed=11))


@pytest.fixture(scope="module")
def result(synth: SyntheticData) -> DetectionResult:
    return run_detection(synth.events, synth.users, synth.baseline_end)


def test_available_datasets_lists_processed_folders(tmp_path: Path, synth: SyntheticData) -> None:
    save_processed(synth, tmp_path / "synthetic")
    (tmp_path / "empty").mkdir()
    assert available_datasets(tmp_path) == {"synthetic": tmp_path / "synthetic"}
    assert available_datasets(tmp_path / "missing") == {}


def test_load_dataset_reads_baseline_end_from_generator_config(tmp_path: Path, synth: SyntheticData) -> None:
    save_processed(synth, tmp_path / "synthetic")
    ds = load_dataset(tmp_path / "synthetic")
    assert ds.name == "synthetic"
    assert ds.baseline_end == synth.baseline_end
    assert ds.labels is not None and len(ds.events) == len(synth.events)


def test_load_dataset_reads_baseline_end_from_meta_json(tmp_path: Path, synth: SyntheticData) -> None:
    folder = tmp_path / "cert_like"
    save_processed(synth, folder)
    (folder / "config.json").unlink()
    (folder / "meta.json").write_text(json.dumps({"baseline_end": "2010-06-01"}))
    assert load_dataset(folder).baseline_end == pd.Timestamp("2010-06-01")


def test_load_dataset_without_a_baseline_end_is_an_error(tmp_path: Path, synth: SyntheticData) -> None:
    folder = tmp_path / "bare"
    save_processed(synth, folder)
    (folder / "config.json").unlink()
    with pytest.raises(ValueError, match="baseline"):
        load_dataset(folder)


def test_daily_activity_pairs_each_day_with_the_users_baseline(synth: SyntheticData, result: DetectionResult) -> None:
    user = str(synth.labels.loc[synth.labels["scenario"] == "mass_download", "user_id"].iloc[0])
    daily = daily_activity(result, user)
    assert {"day", "transfers", "after_hours_events", "transfers_baseline", "after_hours_baseline", "in_baseline"} <= set(daily.columns)
    assert daily["transfers"].max() > daily["transfers_baseline"].iloc[0]
    assert daily["in_baseline"].any() and (~daily["in_baseline"]).any()


def test_filter_ranking_by_level_and_department(result: DetectionResult) -> None:
    r = filter_ranking(result.ranking, levels=["High"], departments=None)
    assert (r["risk_level"] == "High").all() and len(r) > 0
    dept = str(result.ranking["department"].iloc[0])
    r = filter_ranking(result.ranking, levels=None, departments=[dept])
    assert (r["department"] == dept).all()


def test_headline_metrics_count_levels(result: DetectionResult) -> None:
    m = headline_metrics(result)
    assert m["users"] == len(result.ranking)
    assert m["High"] + m["Medium"] + m["Low"] == m["users"]
    assert m["findings"] == len(result.findings)


def test_action_status_locks_sensitive_actions_until_approved() -> None:
    case = {"recommended_actions": [
        {"action": "Document.", "requires_approval": False, "policy_ref": "a"},
        {"action": "Restrict USB.", "requires_approval": True, "policy_ref": "b"},
    ]}
    pending = action_status(case, None)
    assert [r["status"] for r in pending] == ["authorised", "locked: needs approval"]
    approved = ReviewDecision("c", "approved", "R", "", "2026-10-26T00:00:00+00:00")
    assert [r["status"] for r in action_status(case, approved)] == ["authorised", "authorised"]
