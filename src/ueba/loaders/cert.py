"""Loader for the CERT Insider Threat Test Dataset (release r4.2) into the shared event schema.

What CERT r4.2 records, and how we map it:

* ``file.csv``: every row is a file copy to removable media, so ``action`` is always
  ``copy_to_usb``. Filenames are random with no path, so only ``file_type`` (from the
  extension) is derivable; category, owning department and sensitivity are ``unknown``.
  The ``content`` column is never read (metadata only).
* ``device.csv``: USB connect / disconnect.
* ``logon.csv``: logon / logoff, used for after-hours and other-user's-PC context.
* ``LDAP/*.csv``: monthly directory snapshots, giving department, role and departures.
  Names, emails and supervisors are dropped.
* ``answers/insiders.csv``: ground-truth labels for the chosen release.

``http.csv``, ``email.csv`` and ``psychometric.csv`` are deliberately never read.
CERT user IDs are replaced by pseudonyms (``U0001``...). The CERT licence forbids
redistribution, so processed output belongs under the git-ignored ``data/`` folder.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from ueba.schema import EVENT_COLUMNS, LABEL_COLUMNS, UNKNOWN

CERT_DATE_FORMAT = "%m/%d/%Y %H:%M:%S"

# First labelled insider activity in r4.2 is 2010-06-10, so Jan-May 2010 is a clean Baseline Window.
BASELINE_END: dict[str, str] = {"4.2": "2010-06-01"}

FILE_TYPE_BY_EXTENSION: dict[str, str] = {
    "doc": "document",
    "docx": "document",
    "xls": "document",
    "xlsx": "document",
    "ppt": "document",
    "pptx": "document",
    "pdf": "document",
    "txt": "text",
    "jpg": "image",
    "jpeg": "image",
    "png": "image",
    "zip": "archive",
    "exe": "executable",
}

# CERT spells this functional unit "Adminstration".
DEPARTMENT_FIXES: dict[str, str] = {"Adminstration": "Administration"}


@dataclass(frozen=True)
class CertData:
    events: pd.DataFrame
    users: pd.DataFrame
    labels: pd.DataFrame


def _strip_prefix(value: object) -> str:
    """'5 - SalesAndMarketing' -> 'SalesAndMarketing'. Blank units (e.g. the President) -> unknown."""
    if not isinstance(value, str) or not value.strip():
        return UNKNOWN
    name = value.split(" - ", 1)[-1].strip()
    return DEPARTMENT_FIXES.get(name, name)


def _read_ldap(ldap_dir: Path) -> pd.DataFrame:
    snapshots = []
    for path in sorted(ldap_dir.glob("*.csv")):
        snap = pd.read_csv(path, usecols=["user_id", "role", "functional_unit", "department", "team"])
        snap["month"] = path.stem
        snapshots.append(snap)
    if not snapshots:
        raise FileNotFoundError(f"no LDAP snapshots found in {ldap_dir}")
    ldap = pd.concat(snapshots, ignore_index=True)
    final_month = ldap["month"].max()
    latest = ldap.sort_values("month").groupby("user_id").tail(1).set_index("user_id")
    first_seen = ldap.groupby("user_id")["month"].min()
    return pd.DataFrame(
        {
            "cert_user_id": latest.index,
            "department": latest["functional_unit"].map(_strip_prefix).to_numpy(),
            "sub_department": latest["department"].map(_strip_prefix).to_numpy(),
            "role": latest["role"].to_numpy(),
            "first_seen_month": first_seen.loc[latest.index].to_numpy(),
            "last_seen_month": latest["month"].to_numpy(),
            "left_organisation": (latest["month"] < final_month).to_numpy(),
        }
    )


def _read_events(path: Path, columns: list[str]) -> pd.DataFrame:
    df = pd.read_csv(path, usecols=columns)
    df["timestamp"] = pd.to_datetime(df.pop("date"), format=CERT_DATE_FORMAT)
    return df


def _file_type(filename: pd.Series) -> pd.Series:
    ext = filename.str.extract(r"\.([A-Za-z0-9]+)$")[0].str.lower()
    return ext.map(FILE_TYPE_BY_EXTENSION).fillna("other")


def load_cert(release_dir: Path, answers_dir: Path, release: str = "4.2") -> CertData:
    release_dir, answers_dir = Path(release_dir), Path(answers_dir)
    source = f"cert_r{release}"

    logon = _read_events(release_dir / "logon.csv", ["date", "user", "pc", "activity"])
    logon["event_type"] = "logon"
    logon["action"] = logon["activity"].str.lower()

    device = _read_events(release_dir / "device.csv", ["date", "user", "pc", "activity"])
    device["event_type"] = "device"
    device["action"] = "usb_" + device["activity"].str.lower()

    files = _read_events(release_dir / "file.csv", ["date", "user", "pc", "filename"])
    files["event_type"] = "file"
    files["action"] = "copy_to_usb"
    files["file_id"] = files["filename"]
    files["file_type"] = _file_type(files["filename"])

    raw = pd.concat([logon, device, files], ignore_index=True)

    # Directory: every user seen in LDAP or in any event log, pseudonymised in sorted order.
    users = _read_ldap(release_dir / "LDAP")
    missing = sorted(set(raw["user"]) - set(users["cert_user_id"]))
    if missing:
        extra = pd.DataFrame({"cert_user_id": missing})
        users = pd.concat([users, extra], ignore_index=True)
    users = users.sort_values("cert_user_id").reset_index(drop=True)
    users.insert(0, "user_id", [f"U{i + 1:04d}" for i in range(len(users))])
    users[["department", "sub_department", "role"]] = users[["department", "sub_department", "role"]].fillna(UNKNOWN)

    logon_pcs = logon[logon["action"] == "logon"].groupby("user")["pc"].agg(lambda s: s.value_counts().index[0])
    users["assigned_pc"] = users["cert_user_id"].map(logon_pcs).fillna(UNKNOWN)

    by_cert = users.set_index("cert_user_id")
    events = pd.DataFrame(
        {
            "source": source,
            "event_type": raw["event_type"],
            "user_id": raw["user"].map(by_cert["user_id"]),
            "department": raw["user"].map(by_cert["department"]),
            "role": raw["user"].map(by_cert["role"]),
            "file_id": raw["file_id"].fillna(""),
            "file_type": raw["file_type"].fillna(""),
            "file_category": UNKNOWN,
            "file_department": UNKNOWN,
            "sensitivity": UNKNOWN,
            "timestamp": raw["timestamp"],
            "action": raw["action"],
            "device_id": raw["pc"],
            "bytes": pd.Series(pd.NA, index=raw.index, dtype="Int64"),
        }
    )
    events.loc[events["event_type"] != "file", ["file_category", "file_department", "sensitivity"]] = ""
    events = events.sort_values(["timestamp", "user_id", "event_type"], kind="stable").reset_index(drop=True)
    events.insert(0, "event_id", [f"{source}-{i:08d}" for i in range(len(events))])
    events = events[EVENT_COLUMNS]

    labels = _load_labels(answers_dir / "insiders.csv", release, users)
    return CertData(events=events, users=users, labels=labels)


def _load_labels(insiders_csv: Path, release: str, users: pd.DataFrame) -> pd.DataFrame:
    insiders = pd.read_csv(insiders_csv, dtype={"dataset": str})
    insiders = insiders[insiders["dataset"] == release]
    by_cert = insiders.set_index("user")
    labels = pd.DataFrame({"user_id": users["user_id"], "cert_user_id": users["cert_user_id"]})
    is_insider = labels["cert_user_id"].isin(by_cert.index)
    labels["scenario"] = "normal"
    labels.loc[is_insider, "scenario"] = (
        "cert_scenario_" + labels.loc[is_insider, "cert_user_id"].map(by_cert["scenario"]).astype(str)
    )
    labels["is_anomalous"] = is_insider
    labels["window_start"] = pd.to_datetime(labels["cert_user_id"].map(by_cert["start"]), format=CERT_DATE_FORMAT)
    labels["window_end"] = pd.to_datetime(labels["cert_user_id"].map(by_cert["end"]), format=CERT_DATE_FORMAT)
    return labels[LABEL_COLUMNS].reset_index(drop=True)


def save_processed(data: CertData, out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data.events.to_parquet(out_dir / "events.parquet", index=False)
    data.users.to_parquet(out_dir / "users.parquet", index=False)
    data.labels.to_parquet(out_dir / "labels.parquet", index=False)
    source = str(data.events["source"].iloc[0]) if len(data.events) else "cert"
    release = source.removeprefix("cert_r")
    meta = {"source": source, "baseline_end": BASELINE_END.get(release)}
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Convert a CERT insider-threat release into the UEBA event schema.")
    parser.add_argument("release_dir", type=Path, help="e.g. data/cert/r4.2")
    parser.add_argument("answers_dir", type=Path, help="e.g. data/cert/answers")
    parser.add_argument("out_dir", type=Path, help="e.g. data/processed/cert_r4.2")
    parser.add_argument("--release", default="4.2")
    args = parser.parse_args(argv)

    data = load_cert(args.release_dir, args.answers_dir, args.release)
    save_processed(data, args.out_dir)
    counts = data.events["event_type"].value_counts().to_dict()
    print(f"events: {len(data.events):,} {counts}")
    print(f"users: {len(data.users):,}  labelled anomalous: {int(data.labels['is_anomalous'].sum())}")
    print(f"written to {args.out_dir}")


if __name__ == "__main__":
    main()
