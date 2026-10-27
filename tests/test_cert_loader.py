import json
from pathlib import Path

import pandas as pd
import pytest

from ueba.loaders.cert import CertData, load_cert, save_processed
from ueba.schema import EVENT_COLUMNS, UNKNOWN

FIXTURE = Path(__file__).parent / "fixtures" / "cert_mini"


@pytest.fixture(scope="module")
def cert() -> CertData:
    return load_cert(FIXTURE / "r4.2", FIXTURE / "answers", release="4.2")


def _cert_id(cert: CertData, user_id: str) -> str:
    return str(cert.users.set_index("user_id").loc[user_id, "cert_user_id"])


def _uid(cert: CertData, cert_user_id: str) -> str:
    return str(cert.users.set_index("cert_user_id").loc[cert_user_id, "user_id"])


def test_events_follow_shared_schema(cert: CertData) -> None:
    assert list(cert.events.columns) == EVENT_COLUMNS
    assert pd.api.types.is_datetime64_any_dtype(cert.events["timestamp"])
    assert cert.events["event_id"].is_unique
    assert (cert.events["source"] == "cert_r4.2").all()
    assert cert.events["timestamp"].is_monotonic_increasing


def test_all_three_event_types_are_loaded(cert: CertData) -> None:
    counts = cert.events["event_type"].value_counts().to_dict()
    assert counts == {"logon": 7, "file": 3, "device": 2}


def test_file_rows_are_usb_copies_with_type_from_extension(cert: CertData) -> None:
    files = cert.events[cert.events["event_type"] == "file"].set_index("file_id")
    assert (files["action"] == "copy_to_usb").all()
    assert files.loc["ABCD1234.doc", "file_type"] == "document"
    assert files.loc["EFGH5678.exe", "file_type"] == "executable"
    assert files.loc["IJKL9012.zip", "file_type"] == "archive"


def test_fields_cert_does_not_record_are_unknown_not_guessed(cert: CertData) -> None:
    files = cert.events[cert.events["event_type"] == "file"]
    assert (files["sensitivity"] == UNKNOWN).all()
    assert (files["file_category"] == UNKNOWN).all()
    assert (files["file_department"] == UNKNOWN).all()
    assert files["bytes"].isna().all()


def test_device_and_logon_actions_are_mapped(cert: CertData) -> None:
    ev = cert.events
    assert set(ev.loc[ev["event_type"] == "device", "action"]) == {"usb_connect", "usb_disconnect"}
    assert set(ev.loc[ev["event_type"] == "logon", "action"]) == {"logon", "logoff"}


def test_users_are_pseudonymised_and_identities_dropped(cert: CertData) -> None:
    assert cert.events["user_id"].str.fullmatch(r"U\d{4}").all()
    assert not cert.events.isin(["AAA0001", "BBB0002", "CCC0003"]).any().any()
    assert "employee_name" not in cert.users.columns
    assert "email" not in cert.users.columns
    assert "supervisor" not in cert.users.columns


def test_file_contents_are_never_loaded(cert: CertData) -> None:
    text = cert.events.astype(str).to_string()
    assert "keywords" not in text
    assert "D0-CF-11-E0" not in text


def test_directory_uses_latest_ldap_snapshot_and_flags_departures(cert: CertData) -> None:
    users = cert.users.set_index("cert_user_id")
    assert users.loc["BBB0002", "role"] == "SalesManager"
    assert users.loc["BBB0002", "department"] == "SalesAndMarketing"
    assert users.loc["AAA0001", "department"] == "Administration"
    assert users.loc["AAA0001", "last_seen_month"] == "2010-01"
    assert bool(users.loc["AAA0001", "left_organisation"]) is True
    assert bool(users.loc["CCC0003", "left_organisation"]) is False


def test_users_without_a_functional_unit_get_unknown_department(cert: CertData) -> None:
    # e.g. the President sits above every functional unit in CERT's directory
    users = cert.users.set_index("cert_user_id")
    assert users.loc["DDD0004", "department"] == UNKNOWN
    assert users.loc["DDD0004", "role"] == "President"


def test_assigned_pc_is_the_users_most_used_logon_pc(cert: CertData) -> None:
    users = cert.users.set_index("cert_user_id")
    assert users.loc["AAA0001", "assigned_pc"] == "PC-0001"
    assert users.loc["BBB0002", "assigned_pc"] == "PC-0002"


def test_labels_cover_every_user_and_only_this_release(cert: CertData) -> None:
    labels = cert.labels.set_index("user_id")
    assert set(labels.index) == set(cert.users["user_id"])
    aaa = labels.loc[_uid(cert, "AAA0001")]
    assert bool(aaa["is_anomalous"]) is True
    assert aaa["scenario"] == "cert_scenario_3"
    assert aaa["window_start"] == pd.Timestamp("2010-01-05 23:00:00")
    # BBB0002 is an insider only in release 4.1, so it must be normal here
    bbb = labels.loc[_uid(cert, "BBB0002")]
    assert bool(bbb["is_anomalous"]) is False
    assert bbb["scenario"] == "normal"


def test_events_carry_department_and_role(cert: CertData) -> None:
    row = cert.events[cert.events["user_id"] == _uid(cert, "CCC0003")].iloc[0]
    assert row["department"] == "ResearchAndEngineering"
    assert row["role"] == "Scientist"


def test_save_processed_round_trips(cert: CertData, tmp_path: Path) -> None:
    save_processed(cert, tmp_path)
    for name in ["events", "users", "labels"]:
        assert (tmp_path / f"{name}.parquet").exists()
    meta = json.loads((tmp_path / "meta.json").read_text())
    assert meta["baseline_end"] == "2010-06-01" and meta["source"] == "cert_r4.2"
    events = pd.read_parquet(tmp_path / "events.parquet")
    pd.testing.assert_frame_equal(events, cert.events)
    assert _cert_id(cert, cert.users["user_id"].iloc[0]).isalnum()
