from pathlib import Path

import pandas as pd
import pytest

from ueba.generator import (
    ANOMALOUS_SCENARIOS,
    HARD_NEGATIVES,
    GeneratorConfig,
    Intensity,
    SyntheticData,
    generate,
    save_processed,
)
from ueba.schema import ACTIONS, EVENT_COLUMNS, LABEL_COLUMNS, SENSITIVE_LEVELS, SENSITIVITY_LEVELS, TRANSFER_ACTIONS, UNKNOWN


def cfg(**overrides: object) -> GeneratorConfig:
    params: dict[str, object] = dict(n_users=60, seed=7)
    params.update(overrides)
    return GeneratorConfig(**params)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def data() -> SyntheticData:
    return generate(cfg())


def users_with(data: SyntheticData, scenario: str) -> list[str]:
    return data.labels.loc[data.labels["scenario"] == scenario, "user_id"].tolist()


def injected(data: SyntheticData) -> pd.DataFrame:
    return data.events[data.events["event_id"].isin(data.injected_event_ids)]


def daily_transfers(data: SyntheticData, user_id: str) -> pd.Series:
    ev = data.events[(data.events["user_id"] == user_id) & data.events["action"].isin(TRANSFER_ACTIONS)]
    return ev.groupby(ev["timestamp"].dt.normalize()).size()


# --- schema and reproducibility -------------------------------------------------


def test_events_follow_shared_schema(data: SyntheticData) -> None:
    ev = data.events
    assert list(ev.columns) == EVENT_COLUMNS
    assert (ev["source"] == "synthetic").all()
    assert set(ev["event_type"]) == {"file", "logon"}
    assert set(ev["action"]).issubset(ACTIONS)
    assert pd.api.types.is_datetime64_any_dtype(ev["timestamp"])
    assert ev["event_id"].is_unique
    assert ev["timestamp"].is_monotonic_increasing


def test_file_events_have_every_brief_field_known(data: SyntheticData) -> None:
    files = data.events[data.events["event_type"] == "file"]
    assert set(files["sensitivity"]).issubset(set(SENSITIVITY_LEVELS) - {UNKNOWN})
    for col in ["file_id", "file_type", "file_category", "file_department", "department", "role", "device_id"]:
        assert (files[col] != UNKNOWN).all() and (files[col] != "").all(), col


def test_same_seed_reproduces_same_data() -> None:
    a, b = generate(cfg()), generate(cfg())
    pd.testing.assert_frame_equal(a.events, b.events)
    pd.testing.assert_frame_equal(a.labels, b.labels)
    pd.testing.assert_frame_equal(a.users, b.users)


def test_different_seed_gives_different_data() -> None:
    assert not generate(cfg(seed=1)).events.equals(generate(cfg(seed=2)).events)


def test_users_are_pseudonymous_and_names_stay_in_directory(data: SyntheticData) -> None:
    assert data.events["user_id"].str.fullmatch(r"U\d{4}").all()
    assert "display_name" in data.users.columns
    names = set(data.users["display_name"])
    assert not data.events.isin(names).any().any()


# --- labels ---------------------------------------------------------------------


def test_labels_cover_every_user_with_every_scenario(data: SyntheticData) -> None:
    labels = data.labels
    assert list(labels.columns) == LABEL_COLUMNS
    assert set(labels["user_id"]) == set(data.users["user_id"])
    assert set(ANOMALOUS_SCENARIOS).issubset(set(labels["scenario"]))
    assert set(HARD_NEGATIVES).issubset(set(labels["scenario"]))
    assert labels["is_anomalous"].sum() == 3 * len(ANOMALOUS_SCENARIOS)
    assert not labels.loc[labels["scenario"].isin(HARD_NEGATIVES), "is_anomalous"].any()


def test_anomaly_windows_and_injections_are_after_the_baseline(data: SyntheticData) -> None:
    anomalous = data.labels[data.labels["is_anomalous"]]
    assert (anomalous["window_start"] >= data.baseline_end).all()
    assert (anomalous["window_end"] > anomalous["window_start"]).all()
    inj = injected(data)
    assert not inj.empty
    assert (inj["timestamp"] >= data.baseline_end).all()
    assert set(inj["user_id"]).issubset(set(anomalous["user_id"]))


def test_detection_window_contains_a_quarter_end() -> None:
    data = generate(cfg())
    window = pd.date_range(data.baseline_end, data.period_end, inclusive="left")
    assert any(d.is_quarter_end for d in window)


# --- scenarios ------------------------------------------------------------------


def test_mass_download_spike_scales_with_intensity() -> None:
    def spike(multiplier: float) -> int:
        d = generate(cfg(intensity=Intensity(mass_download_multiplier=multiplier)))
        return min(int(daily_transfers(d, u).max()) for u in users_with(d, "mass_download"))

    assert spike(100) > spike(10) > 0


def test_after_hours_injections_are_at_night(data: SyntheticData) -> None:
    inj = injected(data)
    users = users_with(data, "after_hours")
    hours = inj[inj["user_id"].isin(users)]["timestamp"].dt.hour
    assert not hours.empty
    assert ((hours >= 22) | (hours < 4)).all()


def test_cross_department_injections_touch_other_departments_sensitive_files(data: SyntheticData) -> None:
    inj = injected(data)
    rows = inj[inj["user_id"].isin(users_with(data, "cross_department_sensitive")) & (inj["event_type"] == "file")]
    assert not rows.empty
    assert (rows["file_department"] != rows["department"]).all()
    assert rows["sensitivity"].isin(SENSITIVE_LEVELS).all()


def test_new_device_transfers_come_from_an_unassigned_device(data: SyntheticData) -> None:
    inj = injected(data)
    assigned = data.users.set_index("user_id")["assigned_pc"]
    rows = inj[inj["user_id"].isin(users_with(data, "new_device_transfer")) & (inj["event_type"] == "file")]
    assert not rows.empty
    assert (rows["device_id"] != rows["user_id"].map(assigned)).all()
    assert rows["action"].isin(TRANSFER_ACTIONS).all()


def test_slow_drip_raises_transfers_on_most_days_without_a_spike(data: SyntheticData) -> None:
    for user in users_with(data, "slow_drip"):
        daily = daily_transfers(data, user)
        before = daily[daily.index < data.baseline_end]
        after = daily[daily.index >= data.baseline_end]
        assert after.mean() >= before.mean() + 3
        assert after.max() < 40  # far below a mass download


def test_usb_and_external_uploads_also_occur_in_normal_behaviour(data: SyntheticData) -> None:
    # otherwise "any USB copy" would be a free giveaway for detectors
    normal = data.labels.loc[data.labels["scenario"] == "normal", "user_id"]
    ev = data.events[data.events["user_id"].isin(normal) & (data.events["timestamp"] < data.baseline_end)]
    usb_users = ev.loc[ev["action"] == "copy_to_usb", "user_id"].nunique()
    assert 0.1 * len(normal) <= usb_users <= 0.5 * len(normal)
    assert (ev["action"] == "upload_external").any()


# --- hard negatives -------------------------------------------------------------


def test_on_call_night_work_is_already_part_of_their_baseline(data: SyntheticData) -> None:
    for user in users_with(data, "benign_on_call"):
        ev = data.events[(data.events["user_id"] == user) & (data.events["timestamp"] < data.baseline_end)]
        night = ev["timestamp"].dt.hour.between(0, 5) | (ev["timestamp"].dt.hour >= 21)
        assert night.sum() >= 10


def test_new_hires_have_no_activity_before_they_start(data: SyntheticData) -> None:
    labels = data.labels.set_index("user_id")
    for user in users_with(data, "benign_new_hire"):
        start = labels.loc[user, "window_start"]
        ev = data.events[data.events["user_id"] == user]
        assert start >= data.baseline_end
        assert not ev.empty and (ev["timestamp"] >= start).all()


def test_finance_downloads_surge_at_quarter_end(data: SyntheticData) -> None:
    finance = data.users.loc[data.users["department"] == "Finance", "user_id"]
    ev = data.events[data.events["user_id"].isin(finance) & data.events["action"].isin(TRANSFER_ACTIONS)]
    per_day = ev.groupby(ev["timestamp"].dt.normalize()).size()
    quarter_end = per_day[[d.is_quarter_end for d in per_day.index]]
    assert not quarter_end.empty
    assert quarter_end.mean() > 2.5 * per_day.median()


# --- config ---------------------------------------------------------------------


def test_config_round_trips_through_a_dict_for_sweeps() -> None:
    c = cfg(intensity=Intensity(mass_download_multiplier=5, slow_drip_extra_per_day=2))
    assert GeneratorConfig.from_dict(c.to_dict()) == c


@pytest.mark.parametrize(
    "bad",
    [
        dict(n_users=10),  # too few users for every scenario
        dict(baseline_days=0),
        dict(baseline_days=60, days=42),
    ],
)
def test_invalid_config_is_rejected(bad: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        generate(cfg(**bad))


def test_save_processed_round_trips(data: SyntheticData, tmp_path: Path) -> None:
    save_processed(data, tmp_path)
    for name in ["events", "users", "labels", "injected_events", "config"]:
        assert any(tmp_path.glob(f"{name}.*")), name
    pd.testing.assert_frame_equal(pd.read_parquet(tmp_path / "events.parquet"), data.events)
    pd.testing.assert_frame_equal(pd.read_parquet(tmp_path / "labels.parquet"), data.labels)
