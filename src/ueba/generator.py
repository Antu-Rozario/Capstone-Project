"""Synthetic file-access testbed with labelled, intensity-controlled anomalies (FR-2).

Normal behaviour is generated for every user over the whole period. Anomalous
Scenarios are injected only into the Detection Window, after `baseline_days`, so
detectors learn "normal" from the Baseline Window and are scored on the rest.

Unlike CERT r4.2, every file event carries the fields the brief asks for:
file category, owning department, sensitivity and a full set of file actions.
Hard Negatives (unusual but legitimate behaviour) measure false positives.

Run: .venv/bin/python -m ueba.generator --out data/processed/synthetic
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from faker import Faker

from ueba.schema import EVENT_COLUMNS, LABEL_COLUMNS, SENSITIVITY_LEVELS

SOURCE = "synthetic"

ANOMALOUS_SCENARIOS: list[str] = [
    "mass_download",
    "after_hours",
    "cross_department_sensitive",
    "new_device_transfer",
    "slow_drip",
]
HARD_NEGATIVES: list[str] = ["benign_on_call", "benign_quarter_end", "benign_new_hire"]

DEPARTMENTS: list[str] = ["Finance", "HR", "Engineering", "Legal", "Sales", "IT"]

# File categories each department owns, with the file extension typical for each.
DEPARTMENT_CATEGORIES: dict[str, dict[str, str]] = {
    "Finance": {"financial_report": "pdf", "invoice": "pdf", "budget": "xlsx"},
    "HR": {"hr_record": "docx", "payroll": "xlsx", "recruiting": "docx"},
    "Engineering": {"source_code": "txt", "design_doc": "docx", "test_data": "zip"},
    "Legal": {"contract": "pdf", "litigation": "docx", "compliance": "pdf"},
    "Sales": {"customer_list": "xlsx", "pricing": "xlsx", "proposal": "docx"},
    "IT": {"it_config": "txt", "access_log": "txt", "runbook": "docx"},
}
FILE_TYPE_BY_EXTENSION: dict[str, str] = {"pdf": "document", "docx": "document", "xlsx": "document", "txt": "text", "zip": "archive"}

ROLES: dict[str, list[str]] = {
    "Finance": ["Analyst", "Accountant", "Controller"],
    "HR": ["HR Partner", "Recruiter", "Payroll Specialist"],
    "Engineering": ["Engineer", "Senior Engineer", "QA Engineer"],
    "Legal": ["Counsel", "Paralegal"],
    "Sales": ["Account Executive", "Sales Manager"],
    "IT": ["Sysadmin", "Helpdesk", "Security Engineer"],
}

NORMAL_ACTIONS: dict[str, float] = {"view": 0.6, "edit": 0.25, "download": 0.1, "print": 0.04, "delete": 0.01}
OWN_SENSITIVITY_P = [0.25, 0.5, 0.2, 0.05]  # public, internal, confidential, restricted
OTHER_SENSITIVITY_P = [0.6, 0.38, 0.02, 0.0]
KNOWN_SENSITIVITY = SENSITIVITY_LEVELS[:4]
BUSINESS_HOURS = (7.0, 19.0)
SESSION_GAP_HOURS = 3.0


@dataclass(frozen=True)
class Intensity:
    """How strongly each anomalous Scenario departs from normal. Sweep these for RQ2."""

    mass_download_multiplier: float = 50.0  # x the user's normal daily transfers, on one day
    after_hours_nights: int = 4
    after_hours_events_per_night: int = 25
    cross_department_days: int = 3
    cross_department_accesses_per_day: int = 12
    new_device_days: int = 2
    new_device_transfers_per_day: int = 30
    slow_drip_extra_per_day: int = 5  # extra transfers on every Detection-Window weekday


@dataclass(frozen=True)
class GeneratorConfig:
    n_users: int = 120
    days: int = 42
    baseline_days: int = 28
    # 2026-08-20 + 28 days = 2026-09-17, so the Detection Window ends on the 2026-09-30 quarter end.
    start_date: str = "2026-08-20"
    n_per_scenario: int = 3
    n_on_call: int = 3
    n_new_hire: int = 3
    quarter_end_surge: bool = True
    seed: int = 42
    intensity: Intensity = field(default_factory=Intensity)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GeneratorConfig:
        d = dict(d)
        d["intensity"] = Intensity(**d.get("intensity", {}))
        return cls(**d)

    def validate(self) -> None:
        needed = self.n_per_scenario * len(ANOMALOUS_SCENARIOS) + self.n_on_call + self.n_new_hire
        if self.n_users < needed + len(DEPARTMENTS):
            raise ValueError(f"n_users must be at least {needed + len(DEPARTMENTS)} to fit every scenario plus normal users")
        if not 0 < self.baseline_days < self.days:
            raise ValueError("baseline_days must be between 1 and days - 1")


@dataclass(frozen=True)
class SyntheticData:
    events: pd.DataFrame
    users: pd.DataFrame
    labels: pd.DataFrame
    injected_event_ids: frozenset[str]
    config: GeneratorConfig

    @property
    def baseline_end(self) -> pd.Timestamp:
        return pd.Timestamp(self.config.start_date) + pd.Timedelta(days=self.config.baseline_days)

    @property
    def period_end(self) -> pd.Timestamp:
        return pd.Timestamp(self.config.start_date) + pd.Timedelta(days=self.config.days)


class _Builder:
    """Accumulates file events; logon sessions are derived from them at the end."""

    def __init__(self, rng: np.random.Generator) -> None:
        self.rng = rng
        self.rows: list[dict[str, Any]] = []

    def file_event(
        self,
        user: dict[str, Any],
        ts: pd.Timestamp,
        *,
        action: str,
        file_department: str,
        sensitivity: str,
        device_id: str | None = None,
        injected: bool = False,
    ) -> None:
        rng = self.rng
        categories = DEPARTMENT_CATEGORIES[file_department]
        category = str(rng.choice(list(categories)))
        ext = categories[category]
        self.rows.append(
            {
                "event_type": "file",
                "user_id": user["user_id"],
                "department": user["department"],
                "role": user["role"],
                "file_id": f"{file_department}/{category}/{int(rng.integers(1, 500)):04d}.{ext}",
                "file_type": FILE_TYPE_BY_EXTENSION[ext],
                "file_category": category,
                "file_department": file_department,
                "sensitivity": sensitivity,
                "timestamp": ts,
                "action": action,
                "device_id": device_id or user["assigned_pc"],
                "bytes": int(rng.lognormal(11, 1.2)),
                "injected": injected,
            }
        )


def _business_ts(rng: np.random.Generator, day: pd.Timestamp, lo: float = 9.0, hi: float = 17.0) -> pd.Timestamp:
    return day + pd.Timedelta(hours=float(rng.uniform(lo, hi)))


def _night_ts(rng: np.random.Generator, day: pd.Timestamp) -> pd.Timestamp:
    hour = float(rng.uniform(22, 23.99)) if rng.random() < 0.5 else float(rng.uniform(0, 3.99))
    return day + pd.Timedelta(hours=hour)


def _normal_day(b: _Builder, user: dict[str, Any], day: pd.Timestamp) -> None:
    rng = b.rng
    on_call = user["scenario"] == "benign_on_call"
    weekend = day.day_of_week >= 5
    if weekend and rng.random() > (0.5 if on_call else 0.08):
        return
    n = int(rng.poisson(user["activity_rate"] * (0.3 if weekend else 1.0)))
    for _ in range(n):
        hour = float(np.clip(rng.normal(user["start_hour"] + 4.5, 2.2), BUSINESS_HOURS[0], BUSINESS_HOURS[1] - 0.01))
        ts = day + pd.Timedelta(hours=hour)
        if on_call and rng.random() < 0.25:
            ts = _night_ts(rng, day)
        own = rng.random() < 0.85
        dept = user["department"] if own else DEPARTMENTS[int(rng.integers(len(DEPARTMENTS)))]
        action = str(rng.choice(list(NORMAL_ACTIONS), p=list(NORMAL_ACTIONS.values())))
        if user["usb_user"] and rng.random() < 0.03:
            action = "copy_to_usb"
        elif user["external_sharer"] and rng.random() < 0.02:
            action = "upload_external"
        b.file_event(
            user,
            ts,
            action=action,
            file_department=dept,
            sensitivity=str(rng.choice(KNOWN_SENSITIVITY, p=OWN_SENSITIVITY_P if dept == user["department"] else OTHER_SENSITIVITY_P)),
        )


def _pick_days(rng: np.random.Generator, days: list[pd.Timestamp], k: int) -> list[pd.Timestamp]:
    idx = sorted(rng.choice(len(days), size=min(k, len(days)), replace=False))
    return [days[i] for i in idx]


def _inject(b: _Builder, user: dict[str, Any], scenario: str, days: list[pd.Timestamp], it: Intensity) -> None:
    rng = b.rng
    own = str(user["department"])
    others = [d for d in DEPARTMENTS if d != own]

    if scenario == "mass_download":
        day = _pick_days(rng, days, 1)[0]
        normal_daily_transfers = user["activity_rate"] * (NORMAL_ACTIONS["download"])
        for _ in range(max(1, round(it.mass_download_multiplier * normal_daily_transfers))):
            b.file_event(
                user, _business_ts(rng, day),
                action=str(rng.choice(["download", "copy_to_usb"], p=[0.7, 0.3])),
                file_department=own,
                sensitivity=str(rng.choice(KNOWN_SENSITIVITY, p=[0.1, 0.4, 0.35, 0.15])),
                injected=True,
            )
    elif scenario == "after_hours":
        for day in _pick_days(rng, days, it.after_hours_nights):
            for _ in range(it.after_hours_events_per_night):
                b.file_event(
                    user, _night_ts(rng, day),
                    action=str(rng.choice(["view", "download", "edit"], p=[0.5, 0.4, 0.1])),
                    file_department=own,
                    sensitivity=str(rng.choice(["internal", "confidential", "restricted"], p=[0.3, 0.5, 0.2])),
                    injected=True,
                )
    elif scenario == "cross_department_sensitive":
        for day in _pick_days(rng, days, it.cross_department_days):
            for _ in range(it.cross_department_accesses_per_day):
                b.file_event(
                    user, _business_ts(rng, day),
                    action=str(rng.choice(["view", "download"], p=[0.6, 0.4])),
                    file_department=others[int(rng.integers(len(others)))],
                    sensitivity=str(rng.choice(["confidential", "restricted"])),
                    injected=True,
                )
    elif scenario == "new_device_transfer":
        device = f"UNMANAGED-{int(rng.integers(1000, 9999))}"
        for day in _pick_days(rng, days, it.new_device_days):
            for _ in range(it.new_device_transfers_per_day):
                b.file_event(
                    user, _business_ts(rng, day, 8, 20),
                    action=str(rng.choice(["upload_external", "copy_to_usb", "download"], p=[0.5, 0.3, 0.2])),
                    file_department=own,
                    sensitivity=str(rng.choice(["internal", "confidential", "restricted"], p=[0.3, 0.4, 0.3])),
                    device_id=device,
                    injected=True,
                )
    elif scenario == "slow_drip":
        for day in days:
            for _ in range(it.slow_drip_extra_per_day):
                b.file_event(
                    user, _business_ts(rng, day),
                    action=str(rng.choice(["download", "copy_to_usb"], p=[0.8, 0.2])),
                    file_department=own,
                    sensitivity=str(rng.choice(["internal", "confidential"], p=[0.6, 0.4])),
                    injected=True,
                )
    else:
        raise ValueError(f"unknown scenario: {scenario}")


def _quarter_end_surge(b: _Builder, user: dict[str, Any], quarter_end_days: list[pd.Timestamp]) -> None:
    rng = b.rng
    for day in quarter_end_days:
        for _ in range(int(rng.integers(6, 12))):
            b.file_event(
                user, _business_ts(rng, day, 8, 18),
                action="download",
                file_department="Finance",
                sensitivity=str(rng.choice(["internal", "confidential"], p=[0.5, 0.5])),
            )


def _logon_sessions(files: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    """One logon/logoff pair around each burst of activity (gap > SESSION_GAP_HOURS starts a new session)."""
    rows: list[dict[str, Any]] = []
    for (user_id, device), g in files.sort_values("timestamp").groupby(["user_id", "device_id"], sort=True):
        ts = g["timestamp"]
        session = (ts.diff() > pd.Timedelta(hours=SESSION_GAP_HOURS)).cumsum()
        first = g.iloc[0]
        for _, s in ts.groupby(session):
            base = {"event_type": "logon", "user_id": user_id, "department": first["department"], "role": first["role"],
                    "device_id": device, "injected": False}
            rows.append({**base, "action": "logon", "timestamp": s.min() - pd.Timedelta(minutes=float(rng.uniform(2, 15)))})
            rows.append({**base, "action": "logoff", "timestamp": s.max() + pd.Timedelta(minutes=float(rng.uniform(2, 20)))})
    return pd.DataFrame(rows)


def _make_users(cfg: GeneratorConfig, rng: np.random.Generator) -> list[dict[str, Any]]:
    fake = Faker()
    fake.seed_instance(cfg.seed)
    users = []
    for i in range(cfg.n_users):
        dept = DEPARTMENTS[i % len(DEPARTMENTS)]
        users.append(
            {
                "user_id": f"U{i + 1:04d}",
                "display_name": fake.name(),
                "department": dept,
                "role": ROLES[dept][int(rng.integers(len(ROLES[dept])))],
                "assigned_pc": f"PC-{i + 1:04d}",
                "start_hour": float(rng.uniform(7.5, 10.0)),
                "activity_rate": float(rng.uniform(10, 30)),
                # About a quarter of users use USB drives normally (as in CERT); Sales shares externally.
                "usb_user": bool(rng.random() < 0.25),
                "external_sharer": bool(dept == "Sales" and rng.random() < 0.5),
                "scenario": "normal",
            }
        )
    return users


def _assign_scenarios(cfg: GeneratorConfig, users: list[dict[str, Any]], rng: np.random.Generator) -> None:
    order = [int(i) for i in rng.permutation(len(users))]
    n_anom = cfg.n_per_scenario * len(ANOMALOUS_SCENARIOS)
    for k, i in enumerate(order[:n_anom]):
        users[i]["scenario"] = ANOMALOUS_SCENARIOS[k % len(ANOMALOUS_SCENARIOS)]
    rest = order[n_anom:]
    it_first = [i for i in rest if users[i]["department"] == "IT"] + [i for i in rest if users[i]["department"] != "IT"]
    on_call = it_first[: cfg.n_on_call]
    for i in on_call:
        users[i]["scenario"] = "benign_on_call"
    new_hires = [i for i in rest if i not in on_call][: cfg.n_new_hire]
    for i in new_hires:
        users[i]["scenario"] = "benign_new_hire"


def generate(cfg: GeneratorConfig | None = None) -> SyntheticData:
    cfg = cfg or GeneratorConfig()
    cfg.validate()
    rng = np.random.default_rng(cfg.seed)

    start = pd.Timestamp(cfg.start_date)
    all_days = [start + pd.Timedelta(days=d) for d in range(cfg.days)]
    baseline_end = start + pd.Timedelta(days=cfg.baseline_days)
    detection_days = [d for d in all_days if d >= baseline_end]
    detection_weekdays = [d for d in detection_days if d.day_of_week < 5] or detection_days
    quarter_end_days = [d for d in detection_days if d.is_quarter_end]

    users = _make_users(cfg, rng)
    _assign_scenarios(cfg, users, rng)

    b = _Builder(rng)
    windows: dict[str, tuple[pd.Timestamp | None, pd.Timestamp | None]] = {}
    for user in users:
        scenario = user["scenario"]
        active_from = start
        if scenario == "benign_new_hire":
            active_from = baseline_end + pd.Timedelta(days=int(rng.integers(0, 3)))
            windows[user["user_id"]] = (active_from, start + pd.Timedelta(days=cfg.days))
        for day in all_days:
            if day >= active_from:
                _normal_day(b, user, day)
        if user["department"] == "Finance" and cfg.quarter_end_surge:
            _quarter_end_surge(b, user, [d for d in quarter_end_days if d >= active_from])
        if scenario in ANOMALOUS_SCENARIOS:
            n_before = len(b.rows)
            _inject(b, user, scenario, detection_weekdays, cfg.intensity)
            stamps = [r["timestamp"] for r in b.rows[n_before:]]
            windows[user["user_id"]] = (min(stamps), max(stamps))

    files = pd.DataFrame(b.rows)
    events = pd.concat([files, _logon_sessions(files, rng)], ignore_index=True)
    events = events.sort_values(["timestamp", "user_id", "event_type"], kind="stable").reset_index(drop=True)
    events.insert(0, "event_id", [f"{SOURCE}-{i:08d}" for i in range(len(events))])
    events["source"] = SOURCE
    for col in ["file_id", "file_type", "file_category", "file_department", "sensitivity"]:
        events[col] = events[col].fillna("")
    events["bytes"] = events["bytes"].astype("Int64")
    injected_ids = frozenset(events.loc[events["injected"].astype(bool), "event_id"])
    events = events[EVENT_COLUMNS]

    labels = _labels(users, windows, quarter_end_days, cfg.quarter_end_surge)
    users_df = pd.DataFrame(users)[["user_id", "display_name", "department", "role", "assigned_pc"]]
    return SyntheticData(events=events, users=users_df, labels=labels, injected_event_ids=injected_ids, config=cfg)


def _labels(
    users: list[dict[str, Any]],
    windows: dict[str, tuple[pd.Timestamp | None, pd.Timestamp | None]],
    quarter_end_days: list[pd.Timestamp],
    surge: bool,
) -> pd.DataFrame:
    rows = []
    for user in users:
        scenario = user["scenario"]
        start, end = windows.get(user["user_id"], (None, None))
        if scenario == "normal" and user["department"] == "Finance" and surge and quarter_end_days:
            scenario = "benign_quarter_end"
            start, end = quarter_end_days[0], quarter_end_days[-1] + pd.Timedelta(days=1)
        rows.append(
            {
                "user_id": user["user_id"],
                "scenario": scenario,
                "is_anomalous": scenario in ANOMALOUS_SCENARIOS,
                "window_start": start,
                "window_end": end,
            }
        )
    labels = pd.DataFrame(rows)
    labels["window_start"] = pd.to_datetime(labels["window_start"])
    labels["window_end"] = pd.to_datetime(labels["window_end"])
    return labels[LABEL_COLUMNS]


def save_processed(data: SyntheticData, out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data.events.to_parquet(out_dir / "events.parquet", index=False)
    data.users.to_parquet(out_dir / "users.parquet", index=False)
    data.labels.to_parquet(out_dir / "labels.parquet", index=False)
    pd.DataFrame({"event_id": sorted(data.injected_event_ids)}).to_parquet(out_dir / "injected_events.parquet", index=False)
    (out_dir / "config.json").write_text(json.dumps(data.config.to_dict(), indent=2))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate the synthetic file-access testbed.")
    parser.add_argument("--out", type=Path, default=Path("data/processed/synthetic"))
    parser.add_argument("--config", type=Path, help="JSON file with GeneratorConfig fields (for Intensity sweeps)")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--users", type=int)
    args = parser.parse_args(argv)

    cfg = GeneratorConfig.from_dict(json.loads(args.config.read_text())) if args.config else GeneratorConfig()
    overrides = {k: v for k, v in {"seed": args.seed, "n_users": args.users}.items() if v is not None}
    if overrides:
        cfg = GeneratorConfig.from_dict({**cfg.to_dict(), **overrides})

    data = generate(cfg)
    save_processed(data, args.out)
    counts = data.events["event_type"].value_counts().to_dict()
    print(f"events: {len(data.events):,} {counts}  injected: {len(data.injected_event_ids):,}")
    print(data.labels["scenario"].value_counts().to_string())
    print(f"written to {args.out}")


if __name__ == "__main__":
    main()
