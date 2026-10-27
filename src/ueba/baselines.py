"""Per-user Baselines learned from the Baseline Window, with Peer Group fallback (FR-3)."""

from __future__ import annotations

import pandas as pd

from ueba.features import FEATURE_COLUMNS

MIN_BASELINE_DAYS = 7
# Counts are integers: a std below 1 would make a single extra event look extreme.
STD_FLOOR = 1.0


def compute_baselines(features: pd.DataFrame) -> pd.DataFrame:
    """One row per user: `<feature>_mean`, `<feature>_std`, `baseline_days`, `baseline_source`.

    Users with fewer than MIN_BASELINE_DAYS baseline days (e.g. new hires) take their
    department's average instead (`baseline_source == "peer"`).
    """
    base = features[features["in_baseline"]]
    grouped = base.groupby("user_id")[FEATURE_COLUMNS]
    stats = grouped.mean().add_suffix("_mean").join(grouped.std().add_suffix("_std"))
    stats["baseline_days"] = base.groupby("user_id").size()

    users = features.groupby("user_id")["department"].first().to_frame()
    out = users.join(stats)
    out["baseline_days"] = out["baseline_days"].fillna(0).astype(int)
    out["baseline_source"] = "user"

    stat_cols = [c for c in stats.columns if c != "baseline_days"]
    enough = out["baseline_days"] >= MIN_BASELINE_DAYS
    peer = out[enough].groupby("department")[stat_cols].mean()
    overall = out.loc[enough, stat_cols].mean()
    thin = ~enough
    if thin.any():
        for col in stat_cols:
            out.loc[thin, col] = out.loc[thin, "department"].map(peer[col]).astype(float).fillna(overall[col])
        out.loc[thin, "baseline_source"] = "peer"

    out[stat_cols] = out[stat_cols].fillna(0.0)
    for feat in FEATURE_COLUMNS:
        out[f"{feat}_std"] = out[f"{feat}_std"].clip(lower=STD_FLOOR)
    return out


def zscores(features: pd.DataFrame, baselines: pd.DataFrame) -> pd.DataFrame:
    """How many baseline standard deviations each day's feature sits above the user's mean."""
    b = baselines.loc[features["user_id"]]
    z = pd.DataFrame(index=features.index)
    for feat in FEATURE_COLUMNS:
        z[feat] = (features[feat].to_numpy() - b[f"{feat}_mean"].to_numpy()) / b[f"{feat}_std"].to_numpy()
    return z
