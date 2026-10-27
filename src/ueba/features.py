"""Daily per-user behaviour features, shared by the rules and the ML detectors (FR-3).

One row per user per calendar day, from the user's first activity to the end of the
data, with quiet days present as zeros so baselines see them. `left_organisation`
is deliberately never a feature: in CERT it leaks the label.
"""

from __future__ import annotations

import pandas as pd

from ueba.schema import SENSITIVE_LEVELS, TRANSFER_ACTIONS, UNKNOWN

COMPANY_HOURS = (7, 19)  # [start, end)
ROLLING_DAYS = 14

FEATURE_COLUMNS: list[str] = [
    "file_events",
    "transfers",
    "after_hours_events",
    "sensitive_other_dept",
    "new_device_transfers",
    "usb_connects",
    "other_pc_logons",
    "exe_to_usb",
    "distinct_files",
    "rolling_transfers_14d",
]

_COUNT_COLUMNS = [c for c in FEATURE_COLUMNS if c not in ("distinct_files", "rolling_transfers_14d")]

# Ending a session is not "activity"; counting late logoffs would flag people who stay until 19:05.
_SESSION_END_ACTIONS = {"logoff", "usb_disconnect"}


def build_daily_features(events: pd.DataFrame, users: pd.DataFrame, baseline_end: pd.Timestamp) -> pd.DataFrame:
    ev = events.copy()
    ev["day"] = ev["timestamp"].dt.normalize()
    is_file = ev["event_type"] == "file"
    hour = ev["timestamp"].dt.hour

    assigned = users.set_index("user_id")["assigned_pc"] if "assigned_pc" in users else pd.Series(dtype=str)
    assigned_pcs = set(assigned.dropna()) - {UNKNOWN}

    # Devices a user is known to use: their assigned PC plus anything seen in the Baseline Window.
    baseline_devices = ev.loc[ev["timestamp"] < baseline_end].groupby("user_id")["device_id"].agg(set)
    known = ev["user_id"].map(baseline_devices).apply(lambda s: s if isinstance(s, set) else set())
    own_pc = ev["user_id"].map(assigned)
    device_known = [dev in k or dev == pc for dev, k, pc in zip(ev["device_id"], known, own_pc)]

    transfer = is_file & ev["action"].isin(TRANSFER_ACTIONS)
    ev["file_events"] = is_file
    ev["transfers"] = transfer
    ev["after_hours_events"] = ((hour < COMPANY_HOURS[0]) | (hour >= COMPANY_HOURS[1])) & ~ev["action"].isin(_SESSION_END_ACTIONS)
    ev["sensitive_other_dept"] = (
        is_file
        & ev["sensitivity"].isin(SENSITIVE_LEVELS)
        & ~ev["file_department"].isin(["", UNKNOWN])
        & (ev["file_department"] != ev["department"])
    )
    ev["new_device_transfers"] = transfer & ~pd.Series(device_known, index=ev.index)
    ev["usb_connects"] = ev["action"] == "usb_connect"
    ev["other_pc_logons"] = (ev["action"] == "logon") & ev["device_id"].isin(assigned_pcs) & (ev["device_id"] != own_pc)
    ev["exe_to_usb"] = is_file & (ev["action"] == "copy_to_usb") & (ev["file_type"] == "executable")

    daily = ev.groupby(["user_id", "day"])[_COUNT_COLUMNS].sum().astype(int)
    daily["distinct_files"] = ev[is_file].groupby(["user_id", "day"])["file_id"].nunique()

    # Full calendar grid per user so quiet days count as zeros.
    first_day = ev.groupby("user_id")["day"].min()
    last_day = ev["day"].max()
    grid = pd.MultiIndex.from_tuples(
        [(u, d) for u, start in first_day.items() for d in pd.date_range(start, last_day, freq="D")],
        names=["user_id", "day"],
    )
    daily = daily.reindex(grid, fill_value=0).fillna(0)
    daily["distinct_files"] = daily["distinct_files"].astype(int)
    daily["rolling_transfers_14d"] = (
        daily.groupby(level="user_id")["transfers"].rolling(ROLLING_DAYS, min_periods=1).sum().droplevel(0).astype(int)
    )
    daily = daily.reset_index()

    directory = users.set_index("user_id")
    first_seen = ev.groupby("user_id")[["department", "role"]].first()
    for col in ["department", "role"]:
        source = directory[col] if col in directory else first_seen[col]
        daily[col] = daily["user_id"].map(source).fillna(daily["user_id"].map(first_seen[col]))
    daily["in_baseline"] = daily["day"] < baseline_end
    return daily[["user_id", "day", "department", "role", "in_baseline", *FEATURE_COLUMNS]]
