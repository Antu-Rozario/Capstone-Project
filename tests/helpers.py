"""Tiny hand-built event tables for unit tests."""

from __future__ import annotations

from typing import Any

import pandas as pd

from ueba.schema import EVENT_COLUMNS


def make_events(rows: list[dict[str, Any]]) -> pd.DataFrame:
    defaults: dict[str, Any] = {
        "source": "test",
        "event_type": "file",
        "department": "Finance",
        "role": "Analyst",
        "file_id": "Finance/budget/0001.xlsx",
        "file_type": "document",
        "file_category": "budget",
        "file_department": "Finance",
        "sensitivity": "internal",
        "action": "view",
        "device_id": "PC-0001",
        "bytes": 1000,
    }
    full = []
    for i, row in enumerate(rows):
        r = {**defaults, **row}
        r["event_id"] = f"E{i:05d}"
        r["timestamp"] = pd.Timestamp(r["timestamp"])
        if r["event_type"] != "file":
            for col in ["file_id", "file_type", "file_category", "file_department", "sensitivity"]:
                r[col] = ""
        full.append(r)
    df = pd.DataFrame(full)
    df["bytes"] = df["bytes"].astype("Int64")
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)[EVENT_COLUMNS]


def make_users(rows: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(rows)
