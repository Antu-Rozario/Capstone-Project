import pandas as pd
import pytest

from ueba.evaluation import detection_metrics

RANKING = pd.DataFrame(
    {
        "user_id": ["A", "B", "C", "D", "E", "F"],
        "risk_score": [90, 70, 40, 35, 10, 0],
        "risk_level": ["High", "High", "Medium", "Medium", "Low", "Low"],
        "department": ["X", "X", "Y", "Y", "X", "Y"],
    }
)
LABELS = pd.DataFrame(
    {
        "user_id": ["A", "B", "C", "D", "E", "F"],
        "scenario": ["mass_download", "normal", "after_hours", "benign_on_call", "after_hours", "normal"],
        "is_anomalous": [True, False, True, False, True, False],
    }
)


def test_precision_recall_f1_at_the_medium_threshold() -> None:
    m = detection_metrics(RANKING, LABELS)
    # flagged = A,B,C,D ; anomalous = A,C,E
    assert (m["tp"], m["fp"], m["fn"]) == (2, 2, 1)
    assert m["precision"] == pytest.approx(0.5)
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["f1"] == pytest.approx(2 * 0.5 * (2 / 3) / (0.5 + 2 / 3))


def test_precision_at_k_uses_the_number_of_anomalous_users() -> None:
    m = detection_metrics(RANKING, LABELS)
    assert m["k"] == 3
    assert m["precision_at_k"] == pytest.approx(2 / 3)  # top 3 = A,B,C


def test_per_scenario_rates_include_hard_negatives_as_false_positive_rates() -> None:
    m = detection_metrics(RANKING, LABELS)
    assert m["per_scenario"]["after_hours"] == {"users": 2, "flagged": 1, "rate": 0.5}
    assert m["per_scenario"]["benign_on_call"] == {"users": 1, "flagged": 1, "rate": 1.0}
    assert m["hard_negative_fp_rate"] == pytest.approx(1.0)
    assert m["normal_fp_rate"] == pytest.approx(0.5)


def test_high_only_threshold_is_stricter() -> None:
    m = detection_metrics(RANKING, LABELS, flag_levels=("High",))
    assert (m["tp"], m["fp"]) == (1, 1)


def test_fp_rate_by_department_supports_the_fairness_check() -> None:
    m = detection_metrics(RANKING, LABELS)
    # non-anomalous: B (X, flagged), D (Y, flagged), F (Y, not flagged)
    assert m["fp_rate_by_department"] == {"X": 1.0, "Y": 0.5}


def test_no_flags_gives_zero_precision_not_an_error() -> None:
    ranking = RANKING.assign(risk_level="Low")
    m = detection_metrics(ranking, LABELS)
    assert m["precision"] == 0.0 and m["recall"] == 0.0 and m["f1"] == 0.0
