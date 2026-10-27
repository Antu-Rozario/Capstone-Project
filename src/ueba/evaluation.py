"""Detection metrics against Ground-truth Labels (FR-8, RQ1, RQ3)."""

from __future__ import annotations

from typing import Any

import pandas as pd

HARD_NEGATIVE_PREFIX = "benign_"


def _ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def detection_metrics(
    ranking: pd.DataFrame,
    labels: pd.DataFrame,
    flag_levels: tuple[str, ...] = ("High", "Medium"),
) -> dict[str, Any]:
    """User-level metrics. A user is "flagged" when their risk level is in `flag_levels`."""
    df = ranking.merge(labels[["user_id", "scenario", "is_anomalous"]], on="user_id", how="inner")
    flagged = df["risk_level"].isin(flag_levels)
    anomalous = df["is_anomalous"].astype(bool)

    tp = int((flagged & anomalous).sum())
    fp = int((flagged & ~anomalous).sum())
    fn = int((~flagged & anomalous).sum())
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    k = int(anomalous.sum())
    top_k = df.sort_values("risk_score", ascending=False, kind="stable").head(k)
    per_scenario = {
        str(s): {"users": int(len(g)), "flagged": int(flagged[g.index].sum()), "rate": _ratio(int(flagged[g.index].sum()), len(g))}
        for s, g in df.groupby("scenario")
    }
    hard_neg = df["scenario"].str.startswith(HARD_NEGATIVE_PREFIX)
    normal = df["scenario"] == "normal"
    not_anom = df[~anomalous]
    fp_by_dept: dict[str, float] = {}
    if "department" in df:
        fp_by_dept = {
            str(d): _ratio(int(flagged[g.index].sum()), len(g)) for d, g in not_anom.groupby("department")
        }

    return {
        "flag_levels": list(flag_levels),
        "users": int(len(df)),
        "anomalous": k,
        "flagged": int(flagged.sum()),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "k": k,
        "precision_at_k": _ratio(int(top_k["is_anomalous"].sum()), k),
        "hard_negative_fp_rate": _ratio(int((flagged & hard_neg).sum()), int(hard_neg.sum())),
        "normal_fp_rate": _ratio(int((flagged & normal).sum()), int(normal.sum())),
        "fp_rate_by_department": fp_by_dept,
        "per_scenario": per_scenario,
    }
