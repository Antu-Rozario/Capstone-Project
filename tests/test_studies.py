from pathlib import Path
from typing import Any

import pandas as pd
import pytest

from ueba.dashboard import Dataset
from ueba.generator import GeneratorConfig
from ueba.rag import build_index
from ueba.studies import (
    SWEEP_LEVELS,
    rq1_detectors,
    rq2_sensitivity,
    rq3_fairness,
    rq4_narratives,
    synthetic_dataset,
)

POLICIES = Path(__file__).resolve().parents[1] / "policies"


@pytest.fixture(scope="module")
def ds() -> Dataset:
    return synthetic_dataset(GeneratorConfig(n_users=60, seed=11))


def test_rq1_compares_detectors_on_combined_and_ml_only_ranking(ds: Dataset) -> None:
    df = rq1_detectors([ds], ["baseline_zscore", "isolation_forest"])
    assert list(df["detector"]) == ["baseline_zscore", "isolation_forest"]
    for col in ["precision", "recall", "f1", "precision_at_k", "ml_auc", "ml_precision_at_k", "seconds"]:
        assert df[col].between(0, 1e6).all(), col
    assert df["ml_auc"].between(0, 1).all()


def test_sweep_levels_cover_every_anomalous_scenario() -> None:
    assert set(SWEEP_LEVELS) == {"mass_download", "after_hours", "cross_department_sensitive", "new_device_transfer", "slow_drip"}
    assert len({len(v[1]) for v in SWEEP_LEVELS.values()}) == 1  # same number of levels for each scenario


def test_rq2_recall_does_not_drop_as_intensity_rises() -> None:
    df = rq2_sensitivity(seeds=[11], levels=[0, len(SWEEP_LEVELS["mass_download"][1]) - 1], n_users=60)
    assert {"scenario", "level", "intensity", "seed", "recall", "rule_recall", "ml_recall"} <= set(df.columns)
    # reference rows: how often normal users and hard negatives cross the same thresholds (false-flag rates)
    refs = df[df["scenario"].isin(["(reference) normal users", "(reference) hard negatives"])]
    assert len(refs) == 4 and (refs["users"] > 0).all()
    md = df[df["scenario"] == "mass_download"].sort_values("level")
    assert md["recall"].iloc[-1] >= md["recall"].iloc[0]
    assert md["recall"].iloc[-1] == 1.0


def test_rq3_reports_false_positive_rates_by_department_and_hard_negative(ds: Dataset) -> None:
    df = rq3_fairness([ds])
    assert set(df["group_type"]) == {"department", "hard_negative"}
    assert df["fp_rate"].between(0, 1).all()
    assert (df["flagged"] <= df["users"]).all()


class GoodLLM:
    name = "good-llm"

    def write(self, system: str, facts: dict[str, Any]) -> dict[str, Any]:
        return {"summary": f"{facts['subject']} is {facts['risk_level']} risk and needs human review.",
                "possible_benign_explanations": facts["candidate_benign_explanations"][:2]}


def test_rq4_scores_each_narrative_writer(ds: Dataset) -> None:
    retriever = build_index(POLICIES, backend="tfidf")
    df = rq4_narratives(ds, retriever, {"template": None, "good-llm": GoodLLM()}, n_cases=3)
    assert list(df["writer"]) == ["template", "good-llm"]
    assert (df["cases"] == 3).all()
    for col in ["rubric_pass_rate", "clear", "evidence_based", "actionable", "safe", "unsupported_rate",
                "benign_grounded_rate", "fallback_rate", "mean_seconds"]:
        assert col in df.columns
    assert df.loc[df["writer"] == "good-llm", "fallback_rate"].iloc[0] == 0.0
    assert isinstance(df, pd.DataFrame)
