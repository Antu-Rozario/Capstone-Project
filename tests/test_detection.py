import pandas as pd
import pytest

from tests.helpers import make_events, make_users
from ueba.detection import (
    RISK_LEVELS,
    RULES,
    SCENARIO_RULE,
    DetectionResult,
    Finding,
    build_ranking,
    run_detection,
)

RISK_SCORE_FOR_ONE_MEDIUM = 100 * 0.75 * 0.45
from ueba.generator import GeneratorConfig, SyntheticData, generate


@pytest.fixture(scope="module")
def synth() -> SyntheticData:
    return generate(GeneratorConfig(n_users=60, seed=11))


@pytest.fixture(scope="module")
def result(synth: SyntheticData) -> DetectionResult:
    return run_detection(synth.events, synth.users, synth.baseline_end)


def rules_for(result: DetectionResult, user_id: str) -> set[str]:
    return {f.rule for f in result.findings if f.user_id == user_id}


def users_with(synth: SyntheticData, scenario: str) -> list[str]:
    return synth.labels.loc[synth.labels["scenario"] == scenario, "user_id"].tolist()


# --- rules on the synthetic testbed (FR-3 done-when) -----------------------------


@pytest.mark.parametrize("scenario", list(SCENARIO_RULE))
def test_every_injected_scenario_user_gets_the_matching_finding(
    synth: SyntheticData, result: DetectionResult, scenario: str
) -> None:
    for user in users_with(synth, scenario):
        assert SCENARIO_RULE[scenario] in rules_for(result, user), (scenario, user)


def test_on_call_staff_are_not_flagged_for_after_hours(synth: SyntheticData, result: DetectionResult) -> None:
    for user in users_with(synth, "benign_on_call"):
        assert "AFTER_HOURS" not in rules_for(result, user)


def test_quarter_end_rush_is_not_a_mass_download(synth: SyntheticData, result: DetectionResult) -> None:
    for user in users_with(synth, "benign_quarter_end"):
        assert "MASS_DOWNLOAD" not in rules_for(result, user)


def test_new_hires_are_not_flagged_for_using_their_own_pc(synth: SyntheticData, result: DetectionResult) -> None:
    for user in users_with(synth, "benign_new_hire"):
        assert "NEW_DEVICE_TRANSFER" not in rules_for(result, user)


def test_findings_only_come_from_the_detection_window(synth: SyntheticData, result: DetectionResult) -> None:
    assert result.findings
    assert all(f.first_day >= synth.baseline_end for f in result.findings)


def test_findings_carry_observed_versus_expected_evidence(synth: SyntheticData, result: DetectionResult) -> None:
    user = users_with(synth, "mass_download")[0]
    f = next(f for f in result.findings if f.user_id == user and f.rule == "MASS_DOWNLOAD")
    assert f.observed > f.threshold >= f.expected
    assert f.severity in {"high", "medium", "low"}
    assert f.n_days >= 1 and f.last_day >= f.first_day
    assert str(int(f.observed)) in f.description and "baseline" in f.description
    assert set(f.to_dict()) >= {"user_id", "rule", "severity", "observed", "expected", "description"}


# --- ranking and risk score -----------------------------------------------------


def test_ranking_has_every_user_sorted_by_risk(synth: SyntheticData, result: DetectionResult) -> None:
    r = result.ranking
    assert set(r["user_id"]) == set(synth.users["user_id"])
    assert r["risk_score"].between(0, 100).all()
    assert r["risk_score"].is_monotonic_decreasing
    assert set(r["risk_level"]).issubset(RISK_LEVELS)
    assert {"department", "role", "rules", "n_findings", "ml_score"}.issubset(r.columns)


def test_anomalous_users_dominate_the_top_of_the_ranking(synth: SyntheticData, result: DetectionResult) -> None:
    anomalous = set(synth.labels.loc[synth.labels["is_anomalous"], "user_id"])
    top = set(result.ranking.head(len(anomalous))["user_id"])
    assert len(top & anomalous) / len(anomalous) >= 0.8


def test_users_without_findings_are_low_risk(result: DetectionResult) -> None:
    quiet = result.ranking[result.ranking["n_findings"] == 0]
    assert (quiet["risk_level"] == "Low").all()


def _finding(user_id: str, rule: str, severity: str) -> Finding:
    day = pd.Timestamp("2026-01-22")
    return Finding(user_id, rule, severity, day, day, day, 1, 5.0, 0.0, 0.0, "user", "test")


def test_supporting_rules_never_flag_a_user_on_their_own() -> None:
    # Error analysis on CERT: exe copies and other-PC logons alone were mostly false positives.
    for rule in ["EXECUTABLE_TO_USB", "OTHER_USER_PC"]:
        assert RULES[rule].severity(5.0, 0.0) == "low"
    users = make_users([{"user_id": u, "department": "X", "role": "R"} for u in ["U1", "U2"]])
    features = pd.DataFrame({"user_id": ["U1", "U2"], "day": [pd.Timestamp("2026-01-22")] * 2})
    findings = [
        _finding("U1", "EXECUTABLE_TO_USB", "low"),
        _finding("U2", "EXECUTABLE_TO_USB", "low"),
        _finding("U2", "NEW_USB_USER", "medium"),
    ]
    most_unusual = pd.Series([1.0, 1.0], index=features.index)  # even with the top ML score
    ranking = build_ranking(users, findings, most_unusual, features).set_index("user_id")
    assert ranking.loc["U1", "risk_level"] == "Low"
    assert ranking.loc["U2", "risk_level"] in {"Medium", "High"}
    assert ranking.loc["U2", "risk_score"] > RISK_SCORE_FOR_ONE_MEDIUM


# --- rule applicability ---------------------------------------------------------


def test_rules_needing_fields_a_source_lacks_are_marked_not_applicable() -> None:
    users = make_users([{"user_id": "U0001", "department": "Sales", "role": "Rep", "assigned_pc": "PC-0001"}])
    rows = [
        {"user_id": "U0001", "timestamp": f"2026-01-{d:02d} 10:00", "sensitivity": "unknown", "file_department": "unknown"}
        for d in range(1, 29)
    ]
    res = run_detection(make_events(rows), users, pd.Timestamp("2026-01-20"))
    assert res.applicable_rules["CROSS_DEPT_SENSITIVE"] is False
    assert res.applicable_rules["MASS_DOWNLOAD"] is True
    assert set(res.applicable_rules) == set(RULES)


def test_after_hours_rule_fires_on_a_hand_built_case() -> None:
    users = make_users([{"user_id": "U0001", "department": "Sales", "role": "Rep", "assigned_pc": "PC-0001"}])
    rows = [{"user_id": "U0001", "timestamp": f"2026-01-{d:02d} 1{h}:00"} for d in range(1, 21) for h in range(5)]
    rows += [{"user_id": "U0001", "timestamp": f"2026-01-22 23:{m:02d}"} for m in range(0, 50, 5)]
    res = run_detection(make_events(rows), users, pd.Timestamp("2026-01-21"))
    finding = next(f for f in res.findings if f.rule == "AFTER_HOURS")
    assert isinstance(finding, Finding)
    assert finding.observed == 10 and finding.first_day == pd.Timestamp("2026-01-22")
