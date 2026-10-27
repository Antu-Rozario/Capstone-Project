"""Rules, Findings, Risk Score and ranking (FR-3).

Each rule compares one daily feature with the user's Baseline and emits at most one
Finding per user: the worst Detection-Window day, observed vs expected, the threshold
it crossed and how many days it fired. Findings describe activity only.

The Risk Score (0-100) combines the rule Findings (75%) with one ML detector (25%);
users without any Finding stay Low however unusual the ML detector thinks they are,
so every non-Low user has explainable evidence. "low"-severity rules (other-PC logons,
executable copies) are supporting evidence: on their own they cannot lift a user out of Low.

Run: .venv/bin/python -m ueba.detection data/processed/synthetic
"""

from __future__ import annotations

import argparse
import json
import math
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from ueba.baselines import compute_baselines
from ueba.detectors import score_user_days
from ueba.features import ROLLING_DAYS, build_daily_features
from ueba.schema import UNKNOWN

SEVERITY_WEIGHT: dict[str, float] = {"high": 0.7, "medium": 0.45, "low": 0.2}
SEVERITY_ORDER = ["high", "medium", "low"]
RISK_LEVELS = ["High", "Medium", "Low"]
RULE_SHARE, ML_SHARE = 0.75, 0.25
# Only days more unusual than 99% of normal days count towards the ML component.
ML_FLOOR = 0.99

# Which rule a correctly detected synthetic Scenario should trigger.
SCENARIO_RULE: dict[str, str] = {
    "mass_download": "MASS_DOWNLOAD",
    "after_hours": "AFTER_HOURS",
    "cross_department_sensitive": "CROSS_DEPT_SENSITIVE",
    "new_device_transfer": "NEW_DEVICE_TRANSFER",
    "slow_drip": "SUSTAINED_INCREASE",
}


@dataclass(frozen=True)
class Rule:
    name: str
    feature: str
    unit: str
    requires: str  # what the data must contain for the rule to be applicable
    # (baseline mean, baseline std) -> threshold the observed value must exceed
    threshold: Callable[[float, float], float]
    # (observed, baseline mean) -> severity
    severity: Callable[[float, float], str]
    expected_scale: float = 1.0  # expected = mean * scale (14 for the rolling total)
    baseline_feature: str = ""  # baseline to compare against; defaults to `feature`

    @property
    def baseline_of(self) -> str:
        return self.baseline_feature or self.feature


def _never_seen(mean: float, std: float, otherwise: float) -> float:
    """Zero threshold (any occurrence) if the user never did this in the Baseline; else `otherwise`."""
    return 0.0 if mean < 0.05 else otherwise


RULES: dict[str, Rule] = {
    r.name: r
    for r in [
        Rule(
            "MASS_DOWNLOAD", "transfers", "file transfers in one day", "file",
            threshold=lambda m, s: max(m + 5 * s, 3 * m, 25.0),
            severity=lambda o, m: "high" if o >= 10 * max(m, 1.0) else "medium",
        ),
        Rule(
            "AFTER_HOURS", "after_hours_events", "activities outside 07:00-19:00", "any",
            threshold=lambda m, s: max(m + 4 * s, 5.0),
            severity=lambda o, m: "high" if o >= 20 else "medium",
        ),
        Rule(
            "CROSS_DEPT_SENSITIVE", "sensitive_other_dept", "accesses to other departments' confidential or restricted files",
            "sensitivity",
            threshold=lambda m, s: max(m + 4 * s, 5.0),
            severity=lambda o, m: "high" if o >= 10 else "medium",
        ),
        Rule(
            "NEW_DEVICE_TRANSFER", "new_device_transfers", "transfers from a device not seen in the baseline", "file",
            threshold=lambda m, s: max(m + 4 * s, 5.0),
            severity=lambda o, m: "high" if o >= 20 else "medium",
        ),
        Rule(
            "SUSTAINED_INCREASE", "rolling_transfers_14d", f"file transfers over {ROLLING_DAYS} days", "file",
            threshold=lambda m, s: max(ROLLING_DAYS * m + 4 * math.sqrt(ROLLING_DAYS) * s, 1.8 * ROLLING_DAYS * m, 20.0),
            severity=lambda o, m: "medium",
            expected_scale=ROLLING_DAYS,
            baseline_feature="transfers",  # daily baseline, scaled to the window
        ),
        Rule(
            "NEW_USB_USER", "usb_connects", "USB device connections", "device",
            threshold=lambda m, s: _never_seen(m, s, max(m + 4 * s, 3.0)),
            severity=lambda o, m: "medium",
        ),
        Rule(
            "OTHER_USER_PC", "other_pc_logons", "logons to another user's assigned PC", "logon",
            threshold=lambda m, s: _never_seen(m, s, max(m + 4 * s, 2.0)),
            severity=lambda o, m: "low"  # supporting evidence only (CERT error analysis),
        ),
        Rule(
            "EXECUTABLE_TO_USB", "exe_to_usb", "executable files copied to removable media", "file",
            threshold=lambda m, s: _never_seen(m, s, max(m + 4 * s, 2.0)),
            severity=lambda o, m: "low"  # supporting evidence only (CERT error analysis),
        ),
    ]
}


@dataclass(frozen=True)
class Finding:
    user_id: str
    rule: str
    severity: str
    first_day: pd.Timestamp
    last_day: pd.Timestamp
    worst_day: pd.Timestamp
    n_days: int
    observed: float
    expected: float
    threshold: float
    baseline_source: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("first_day", "last_day", "worst_day"):
            d[k] = d[k].date().isoformat()
        return d


@dataclass(frozen=True)
class DetectionResult:
    features: pd.DataFrame
    baselines: pd.DataFrame
    findings: list[Finding]
    ml_scores: pd.Series  # per Detection-Window user-day
    ranking: pd.DataFrame
    applicable_rules: dict[str, bool]
    detector: str
    baseline_end: pd.Timestamp

    def findings_for(self, user_id: str) -> list[Finding]:
        return [f for f in self.findings if f.user_id == user_id]


def applicable_rules(events: pd.DataFrame) -> dict[str, bool]:
    files = events[events["event_type"] == "file"]
    known = ~files["sensitivity"].isin(["", UNKNOWN]) & ~files["file_department"].isin(["", UNKNOWN])
    has = {
        "any": not events.empty,
        "file": not files.empty,
        "sensitivity": bool(known.any()),
        "device": bool((events["event_type"] == "device").any()),
        "logon": bool((events["event_type"] == "logon").any()),
    }
    return {name: has[rule.requires] for name, rule in RULES.items()}


def _describe(rule: Rule, observed: float, expected: float, threshold: float, worst: pd.Timestamp, n_days: int) -> str:
    when = "on" if rule.expected_scale == 1 else "in the window ending"
    return (
        f"{observed:.0f} {rule.unit} {when} {worst.date().isoformat()}, against a baseline of "
        f"{expected:.1f} (threshold {threshold:.1f}). Seen on {n_days} day{'s' if n_days != 1 else ''}."
    )


def evaluate_rules(features: pd.DataFrame, baselines: pd.DataFrame, applicable: dict[str, bool]) -> list[Finding]:
    detection = features[~features["in_baseline"]]
    findings: list[Finding] = []
    for name, rule in RULES.items():
        if not applicable[name]:
            continue
        mean = detection["user_id"].map(baselines[f"{rule.baseline_of}_mean"]).to_numpy()
        std = detection["user_id"].map(baselines[f"{rule.baseline_of}_std"]).to_numpy()
        threshold = np.array([rule.threshold(m, s) for m, s in zip(mean, std)])
        observed = detection[rule.feature].to_numpy()
        fired = detection.assign(_obs=observed, _thr=threshold, _mean=mean)[observed > threshold]
        for user_id, days in fired.groupby("user_id"):
            worst = days.iloc[int(days["_obs"].to_numpy().argmax())]
            obs, m, thr = float(worst["_obs"]), float(worst["_mean"]), float(worst["_thr"])
            expected = m * rule.expected_scale
            findings.append(
                Finding(
                    user_id=str(user_id),
                    rule=name,
                    severity=rule.severity(obs, m),
                    first_day=days["day"].min(),
                    last_day=days["day"].max(),
                    worst_day=worst["day"],
                    n_days=len(days),
                    observed=obs,
                    expected=expected,
                    threshold=thr,
                    baseline_source=str(baselines["baseline_source"].get(str(user_id), "user")),
                    description=_describe(rule, obs, expected, thr, worst["day"], len(days)),
                )
            )
    return findings


def risk_level(score: float) -> str:
    return "High" if score >= 60 else "Medium" if score >= 30 else "Low"


def build_ranking(
    users: pd.DataFrame, findings: list[Finding], ml_scores: pd.Series, features: pd.DataFrame
) -> pd.DataFrame:
    ml_user = ml_scores.groupby(features.loc[ml_scores.index, "user_id"]).max() if len(ml_scores) else pd.Series(dtype=float)
    by_user: dict[str, list[Finding]] = {}
    for f in findings:
        by_user.setdefault(f.user_id, []).append(f)

    rows = []
    for _, user in users.iterrows():
        uid = str(user["user_id"])
        user_findings = sorted(by_user.get(uid, []), key=lambda f: (SEVERITY_ORDER.index(f.severity), -f.observed))
        rule_part = 1.0 - float(np.prod([1 - SEVERITY_WEIGHT[f.severity] for f in user_findings]))
        ml = float(ml_user.get(uid, 0.0))
        # ML can raise a score but never create one: it needs a medium/high Finding to attach to.
        has_primary = any(f.severity != "low" for f in user_findings)
        ml_part = min(max((ml - ML_FLOOR) / (1 - ML_FLOOR), 0.0), 1.0) if has_primary else 0.0
        score = round(100 * (RULE_SHARE * rule_part + ML_SHARE * ml_part), 1)
        rows.append(
            {
                "user_id": uid,
                "department": user.get("department", UNKNOWN),
                "role": user.get("role", UNKNOWN),
                "risk_score": score,
                "risk_level": risk_level(score),
                "n_findings": len(user_findings),
                "rules": ", ".join(f.rule for f in user_findings),
                "ml_score": round(ml, 4),
                "top_finding": f"{user_findings[0].rule}: {user_findings[0].description}" if user_findings else "",
            }
        )
    ranking = pd.DataFrame(rows)
    return ranking.sort_values(["risk_score", "ml_score", "user_id"], ascending=[False, False, True]).reset_index(drop=True)


def run_detection(
    events: pd.DataFrame,
    users: pd.DataFrame,
    baseline_end: pd.Timestamp,
    detector: str = "isolation_forest",
    seed: int = 0,
) -> DetectionResult:
    baseline_end = pd.Timestamp(baseline_end)
    features = build_daily_features(events, users, baseline_end)
    baselines = compute_baselines(features)
    applicable = applicable_rules(events)
    findings = evaluate_rules(features, baselines, applicable)
    ml_scores = score_user_days(features, detector, seed=seed)
    ranking = build_ranking(users, findings, ml_scores, features)
    return DetectionResult(features, baselines, findings, ml_scores, ranking, applicable, detector, baseline_end)


def save_result(result: DetectionResult, out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result.ranking.to_csv(out_dir / "ranking.csv", index=False)
    (out_dir / "findings.json").write_text(json.dumps([f.to_dict() for f in result.findings], indent=2))
    meta = {"detector": result.detector, "baseline_end": str(result.baseline_end.date()), "applicable_rules": result.applicable_rules}
    (out_dir / "detection_meta.json").write_text(json.dumps(meta, indent=2))


def _default_baseline_end(data_dir: Path) -> pd.Timestamp:
    from ueba.dashboard import baseline_end_for

    try:
        return baseline_end_for(data_dir)
    except ValueError as exc:
        raise SystemExit(f"{exc} (or pass --baseline-end)") from exc


def main(argv: list[str] | None = None) -> None:
    from ueba.evaluation import detection_metrics

    parser = argparse.ArgumentParser(description="Run baselines, rules and an ML detector over a processed dataset.")
    parser.add_argument("data_dir", type=Path, help="e.g. data/processed/synthetic or data/processed/cert_r4.2")
    parser.add_argument("--baseline-end", help="first day of the Detection Window (YYYY-MM-DD)")
    parser.add_argument("--detector", default="isolation_forest")
    parser.add_argument("--out", type=Path, help="default: data/results/<dataset>")
    args = parser.parse_args(argv)

    data_dir: Path = args.data_dir
    baseline_end = pd.Timestamp(args.baseline_end) if args.baseline_end else _default_baseline_end(data_dir)
    events = pd.read_parquet(data_dir / "events.parquet")
    users = pd.read_parquet(data_dir / "users.parquet")
    result = run_detection(events, users, baseline_end, args.detector)
    out = args.out or Path("data/results") / data_dir.name
    save_result(result, out)

    print(f"detector={args.detector} baseline_end={baseline_end.date()} findings={len(result.findings)}")
    print("rules not applicable:", [r for r, ok in result.applicable_rules.items() if not ok] or "none")
    print(result.ranking.head(15)[["user_id", "department", "risk_score", "risk_level", "rules"]].to_string(index=False))
    labels_path = data_dir / "labels.parquet"
    if labels_path.exists():
        metrics = detection_metrics(result.ranking, pd.read_parquet(labels_path))
        (out / "metrics.json").write_text(json.dumps(metrics, indent=2))
        print(json.dumps({k: v for k, v in metrics.items() if k != "per_scenario"}, indent=2))
        print("per scenario:", json.dumps(metrics["per_scenario"], indent=2))
    print(f"written to {out}")


if __name__ == "__main__":
    main()
