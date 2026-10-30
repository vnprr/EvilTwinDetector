"""State database: alert lifecycle, change-only event log, replay, read-only access."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from builders import FIXTURES
from wiguard.analysis import analyze_pcap
from wiguard.correlation import Classification
from wiguard.detection import TrustedProfileStore, enroll
from wiguard.runtime import StateReader, StateWriter, StoreError, replay_pcap

REAL = "00:11:22:aa:00:01"
TWIN = "02:de:ad:be:ef:01"


@pytest.fixture
def profiles(tmp_path, config):
    baseline = analyze_pcap(FIXTURES / "enroll_home.pcap", config, trusted_profiles=[])
    trusted = enroll(baseline.access_points, min_frames=50, enrolled_at=0.0)
    TrustedProfileStore(tmp_path / "profiles.json").save(trusted)
    return trusted


@pytest.fixture
def attack(config, profiles):
    return analyze_pcap(FIXTURES / "classic_evil_twin.pcap", config, trusted_profiles=profiles)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "state.db"


def test_alert_lifecycle_open_update_resolve(db_path, attack) -> None:
    t = attack.evaluated_at
    with StateWriter.open(db_path) as store:
        first = store.record(attack, observed_at=t, resolve_after=300)
        again = store.record(attack, observed_at=t + 5, resolve_after=300)
        quiet = replace(attack, alerts=[], events=[])
        early = store.record(quiet, observed_at=t + 100, resolve_after=300)
        late = store.record(quiet, observed_at=t + 400, resolve_after=300)
        alerts = {alert["bssid"]: alert for alert in store.alerts()}
        kinds = [entry["kind"] for entry in store.timeline()]

    assert (first.alerts_opened, first.events_logged) == (2, 2)
    assert (again.alerts_opened, again.events_logged) == (0, 0)  # same evidence: no new rows
    assert (early.alerts_resolved, late.alerts_resolved) == (0, 2)
    assert alerts[TWIN]["classification"] == "evil_twin"
    assert alerts[TWIN]["updates"] == 2
    assert alerts[TWIN]["status"] == "resolved"
    assert kinds.count("alert_opened") == 2 and kinds.count("alert_resolved") == 2


def test_a_worse_verdict_escalates_the_open_alert(db_path, attack) -> None:
    (twin,) = [alert for alert in attack.alerts if alert.bssid == TWIN]
    weaker = replace(twin, classification=Classification.SUSPICIOUS, score=0.7)
    with StateWriter.open(db_path) as store:
        store.record(replace(attack, alerts=[weaker]), observed_at=1.0, resolve_after=300)
        summary = store.record(replace(attack, alerts=[twin]), observed_at=2.0, resolve_after=300)
        (row,) = store.alerts(bssid=TWIN)
    assert summary.alerts_escalated == 1
    assert (row["classification"], row["score"]) == ("evil_twin", 0.865)


def test_metrics_are_sampled_only_when_an_ap_was_heard(db_path, attack) -> None:
    with StateWriter.open(db_path) as store:
        store.record(attack, observed_at=1.0, resolve_after=300)
        store.record(attack, observed_at=2.0, resolve_after=300)
        assert len(store.ap_metrics(REAL)) == 1


def test_timeline_returns_the_latest_entries_or_those_after_an_id(db_path, attack) -> None:
    with StateWriter.open(db_path) as store:
        store.record(attack, observed_at=1.0, resolve_after=300)
        all_ids = [entry["id"] for entry in store.timeline()]
        assert [e["id"] for e in store.timeline(limit=2)] == all_ids[-2:]
        assert [e["id"] for e in store.timeline(after_id=all_ids[0], limit=2)] == all_ids[1:3]


def test_the_reader_cannot_write(db_path, attack) -> None:
    with StateWriter.open(db_path) as writer:
        writer.record(attack, observed_at=1.0, resolve_after=300)
    assert not hasattr(StateReader, "record")  # no write methods at all ...
    with StateReader.open(db_path) as reader, pytest.raises(sqlite3.OperationalError):
        reader._db.execute("DELETE FROM alerts")  # ... and the connection itself is read-only


def test_a_request_may_use_its_store_from_another_thread(db_path, attack) -> None:
    # FastAPI opens the store in one worker thread and runs the endpoint in another.
    with StateWriter.open(db_path) as store:
        store.record(attack, observed_at=1.0, resolve_after=300)
    store = StateReader.open(db_path)
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(lambda: store.stats()["alerts"]).result() == 2
        pool.submit(store.close).result()


def test_missing_database_reads_as_empty(tmp_path) -> None:
    with StateReader.open(tmp_path / "none.db") as store:
        assert store.stats()["access_points"] == 0
    assert not (tmp_path / "none.db").exists()


def test_foreign_database_is_refused(tmp_path) -> None:
    path = tmp_path / "old.db"
    sqlite3.connect(path).execute(
        "CREATE TABLE metadata (key TEXT, value TEXT)"
    ).connection.commit()
    with pytest.raises(StoreError, match="schema version"):
        StateReader.open(path)


def test_replay_follows_the_sensor_flush_schedule(tmp_path, config, profiles) -> None:
    config = config.with_overrides(
        {"detection.identity.trusted_profiles_path": tmp_path / "profiles.json"}
    )
    with StateWriter.open(tmp_path / "replay.db") as store:
        replay_pcap(FIXTURES / "classic_evil_twin.pcap", config, store, step_seconds=1.0)
        (twin,) = store.alerts(bssid=TWIN)
        assert store.status()["mode"] == "replay"
        assert len(store.ap_metrics(REAL)) > 3  # one sample per update: a trend
    # The twin starts beaconing 1 s into the capture and needs `min_frames` frames;
    # the deauth storm starts at 3 s. The alert opens early and escalates later.
    start = 1_767_225_600.0
    assert twin["classification"] == "evil_twin"
    assert twin["first_seen"] - start < 4.0
    assert twin["updates"] > 3
