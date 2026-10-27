"""Pure helpers behind the Streamlit dashboard (FR-7), kept free of Streamlit so they can be unit-tested."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pandas as pd

from ueba.detection import DetectionResult
from ueba.review import ReviewDecision, authorised_actions

DEFAULT_DATA_ROOT = Path("data/processed")


@dataclass(frozen=True)
class Dataset:
    name: str
    path: Path
    events: pd.DataFrame
    users: pd.DataFrame
    labels: pd.DataFrame | None
    baseline_end: pd.Timestamp


def available_datasets(root: Path = DEFAULT_DATA_ROOT) -> dict[str, Path]:
    root = Path(root)
    if not root.is_dir():
        return {}
    return {p.name: p for p in sorted(root.iterdir()) if (p / "events.parquet").exists()}


def baseline_end_for(folder: Path) -> pd.Timestamp:
    """From the generator's config.json (synthetic) or a loader's meta.json (CERT)."""
    config, meta = folder / "config.json", folder / "meta.json"
    if config.exists():
        c = json.loads(config.read_text())
        return pd.Timestamp(c["start_date"]) + pd.Timedelta(days=c["baseline_days"])
    if meta.exists():
        return pd.Timestamp(json.loads(meta.read_text())["baseline_end"])
    raise ValueError(f"no baseline end recorded for {folder}: add meta.json with a baseline_end")


def load_dataset(folder: Path) -> Dataset:
    folder = Path(folder)
    labels_path = folder / "labels.parquet"
    return Dataset(
        name=folder.name,
        path=folder,
        events=pd.read_parquet(folder / "events.parquet"),
        users=pd.read_parquet(folder / "users.parquet"),
        labels=pd.read_parquet(labels_path) if labels_path.exists() else None,
        baseline_end=baseline_end_for(folder),
    )


def daily_activity(result: DetectionResult, user_id: str) -> pd.DataFrame:
    """One row per day for the user's activity chart, with their baseline means alongside."""
    f = result.features[result.features["user_id"] == user_id]
    b = result.baselines
    return pd.DataFrame(
        {
            "day": f["day"].to_numpy(),
            "transfers": f["transfers"].to_numpy(),
            "after_hours_events": f["after_hours_events"].to_numpy(),
            "file_events": f["file_events"].to_numpy(),
            "transfers_baseline": float(cast(float, b.at[user_id, "transfers_mean"])),
            "after_hours_baseline": float(cast(float, b.at[user_id, "after_hours_events_mean"])),
            "in_baseline": f["in_baseline"].to_numpy(),
        }
    )


def filter_ranking(ranking: pd.DataFrame, levels: list[str] | None, departments: list[str] | None) -> pd.DataFrame:
    r = ranking
    if levels:
        r = r[r["risk_level"].isin(levels)]
    if departments:
        r = r[r["department"].isin(departments)]
    return r


def headline_metrics(result: DetectionResult) -> dict[str, int]:
    counts = result.ranking["risk_level"].value_counts()
    return {
        "users": len(result.ranking),
        "High": int(counts.get("High", 0)),
        "Medium": int(counts.get("Medium", 0)),
        "Low": int(counts.get("Low", 0)),
        "findings": len(result.findings),
    }


def action_status(case: dict[str, Any], decision: ReviewDecision | None) -> list[dict[str, Any]]:
    allowed = {a["action"] for a in authorised_actions(case, decision)}
    return [
        {**a, "status": "authorised" if a["action"] in allowed else "locked: needs approval"}
        for a in case["recommended_actions"]
    ]
