import pandas as pd

from tests.helpers import make_events, make_users
from ueba.features import FEATURE_COLUMNS, build_daily_features

BASELINE_END = pd.Timestamp("2026-01-10")
USERS = make_users(
    [
        {"user_id": "U0001", "department": "Finance", "role": "Analyst", "assigned_pc": "PC-0001"},
        {"user_id": "U0002", "department": "Sales", "role": "Rep", "assigned_pc": "PC-0002"},
    ]
)


def features_for(rows: list[dict[str, object]]) -> pd.DataFrame:
    return build_daily_features(make_events(rows), USERS, BASELINE_END).set_index(["user_id", "day"])


def test_one_row_per_user_day_from_first_activity_including_quiet_days() -> None:
    f = features_for(
        [
            {"user_id": "U0001", "timestamp": "2026-01-05 10:00"},
            {"user_id": "U0001", "timestamp": "2026-01-08 10:00"},
        ]
    )
    days = f.loc["U0001"].index
    assert days.min() == pd.Timestamp("2026-01-05")
    assert pd.Timestamp("2026-01-06") in days  # quiet day is present with zeros
    assert f.loc[("U0001", pd.Timestamp("2026-01-06")), "file_events"] == 0
    assert bool(f.loc[("U0001", pd.Timestamp("2026-01-05")), "in_baseline"]) is True
    assert set(FEATURE_COLUMNS).issubset(f.columns)


def test_transfers_and_distinct_files_are_counted() -> None:
    f = features_for(
        [
            {"user_id": "U0001", "timestamp": "2026-01-05 10:00", "action": "download", "file_id": "a"},
            {"user_id": "U0001", "timestamp": "2026-01-05 11:00", "action": "copy_to_usb", "file_id": "a"},
            {"user_id": "U0001", "timestamp": "2026-01-05 12:00", "action": "upload_external", "file_id": "b"},
            {"user_id": "U0001", "timestamp": "2026-01-05 13:00", "action": "view", "file_id": "c"},
        ]
    )
    row = f.loc[("U0001", pd.Timestamp("2026-01-05"))]
    assert row["transfers"] == 3
    assert row["file_events"] == 4
    assert row["distinct_files"] == 3


def test_after_hours_counts_activity_outside_0700_to_1900() -> None:
    f = features_for(
        [
            {"user_id": "U0001", "timestamp": "2026-01-05 06:59"},
            {"user_id": "U0001", "timestamp": "2026-01-05 07:00"},
            {"user_id": "U0001", "timestamp": "2026-01-05 18:59"},
            {"user_id": "U0001", "timestamp": "2026-01-05 19:00"},
            {"user_id": "U0001", "timestamp": "2026-01-05 23:30", "event_type": "logon", "action": "logon"},
        ]
    )
    assert f.loc[("U0001", pd.Timestamp("2026-01-05")), "after_hours_events"] == 3


def test_sensitive_access_counts_only_other_departments_known_sensitive_files() -> None:
    f = features_for(
        [
            {"user_id": "U0001", "timestamp": "2026-01-05 10:00", "file_department": "HR", "sensitivity": "restricted"},
            {"user_id": "U0001", "timestamp": "2026-01-05 10:01", "file_department": "HR", "sensitivity": "confidential"},
            {"user_id": "U0001", "timestamp": "2026-01-05 10:02", "file_department": "HR", "sensitivity": "public"},
            {"user_id": "U0001", "timestamp": "2026-01-05 10:03", "file_department": "Finance", "sensitivity": "restricted"},
            {"user_id": "U0001", "timestamp": "2026-01-05 10:04", "file_department": "unknown", "sensitivity": "unknown"},
        ]
    )
    assert f.loc[("U0001", pd.Timestamp("2026-01-05")), "sensitive_other_dept"] == 2


def test_new_device_transfers_use_devices_not_seen_in_the_baseline() -> None:
    f = features_for(
        [
            {"user_id": "U0001", "timestamp": "2026-01-05 10:00", "device_id": "PC-0001"},
            {"user_id": "U0001", "timestamp": "2026-01-06 10:00", "device_id": "PC-0099"},  # seen in baseline
            {"user_id": "U0001", "timestamp": "2026-01-12 10:00", "device_id": "PC-0099", "action": "download"},
            {"user_id": "U0001", "timestamp": "2026-01-12 10:01", "device_id": "UNMANAGED-1", "action": "download"},
            {"user_id": "U0001", "timestamp": "2026-01-12 10:02", "device_id": "UNMANAGED-1", "action": "copy_to_usb"},
            {"user_id": "U0001", "timestamp": "2026-01-12 10:03", "device_id": "UNMANAGED-1", "action": "view"},
        ]
    )
    assert f.loc[("U0001", pd.Timestamp("2026-01-12")), "new_device_transfers"] == 2


def test_usb_connects_exe_copies_and_logons_to_another_users_pc() -> None:
    f = features_for(
        [
            {"user_id": "U0001", "timestamp": "2026-01-05 09:00", "event_type": "logon", "action": "logon", "device_id": "PC-0001"},
            {"user_id": "U0001", "timestamp": "2026-01-05 10:00", "event_type": "logon", "action": "logon", "device_id": "PC-0002"},
            {"user_id": "U0001", "timestamp": "2026-01-05 11:00", "event_type": "logon", "action": "logon", "device_id": "PC-SHARED"},
            {"user_id": "U0001", "timestamp": "2026-01-05 12:00", "event_type": "device", "action": "usb_connect"},
            {"user_id": "U0001", "timestamp": "2026-01-05 12:30", "event_type": "device", "action": "usb_disconnect"},
            {"user_id": "U0001", "timestamp": "2026-01-05 12:10", "action": "copy_to_usb", "file_type": "executable"},
            {"user_id": "U0001", "timestamp": "2026-01-05 12:11", "action": "copy_to_usb", "file_type": "document"},
        ]
    )
    row = f.loc[("U0001", pd.Timestamp("2026-01-05"))]
    assert row["usb_connects"] == 1
    assert row["exe_to_usb"] == 1
    assert row["other_pc_logons"] == 1  # PC-0002 is U0002's; a shared PC does not count


def test_rolling_transfers_sum_the_last_14_days() -> None:
    rows = [
        {"user_id": "U0001", "timestamp": f"2026-01-{d:02d} 10:00", "action": "download"} for d in range(1, 21)
    ]
    f = features_for(rows)
    assert f.loc[("U0001", pd.Timestamp("2026-01-20")), "rolling_transfers_14d"] == 14
    assert f.loc[("U0001", pd.Timestamp("2026-01-03")), "rolling_transfers_14d"] == 3


def test_departure_is_never_a_feature() -> None:
    users = USERS.assign(left_organisation=[True, False])
    f = build_daily_features(make_events([{"user_id": "U0001", "timestamp": "2026-01-05 10:00"}]), users, BASELINE_END)
    assert "left_organisation" not in f.columns
