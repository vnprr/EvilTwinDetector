"""State database (alert lifecycle, change-only event log) and the read-only API."""

from __future__ import annotations

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from builders import FIXTURES
from wiguard.analysis import analyze_pcap
from wiguard.api import create_app
from wiguard.correlation import Classification
from wiguard.detection import TrustedProfileStore, enroll
from wiguard.runtime import RuntimeStore, StoreError, replay_pcap

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
    with RuntimeStore.open(db_path) as store:
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
    with RuntimeStore.open(db_path) as store:
        store.record(replace(attack, alerts=[weaker]), observed_at=1.0, resolve_after=300)
        summary = store.record(replace(attack, alerts=[twin]), observed_at=2.0, resolve_after=300)
        (row,) = store.alerts(bssid=TWIN)
    assert summary.alerts_escalated == 1
    assert (row["classification"], row["score"]) == ("evil_twin", 0.865)


def test_metrics_are_sampled_only_when_an_ap_was_heard(db_path, attack) -> None:
    with RuntimeStore.open(db_path) as store:
        store.record(attack, observed_at=1.0, resolve_after=300)
        store.record(attack, observed_at=2.0, resolve_after=300)
        assert len(store.ap_metrics(REAL)) == 1


def test_timeline_returns_the_latest_entries_or_those_after_an_id(db_path, attack) -> None:
    with RuntimeStore.open(db_path) as store:
        store.record(attack, observed_at=1.0, resolve_after=300)
        all_ids = [entry["id"] for entry in store.timeline()]
        assert [e["id"] for e in store.timeline(limit=2)] == all_ids[-2:]
        assert [e["id"] for e in store.timeline(after_id=all_ids[0], limit=2)] == all_ids[1:3]


def test_readonly_store_cannot_write(db_path, attack) -> None:
    with RuntimeStore.open(db_path) as store:
        store.record(attack, observed_at=1.0, resolve_after=300)
    with RuntimeStore.open_readonly(db_path) as store, pytest.raises(sqlite3.OperationalError):
        store.record(attack, observed_at=2.0, resolve_after=300)


def test_a_request_may_use_its_store_from_another_thread(db_path, attack) -> None:
    # FastAPI opens the store in one worker thread and runs the endpoint in another.
    with RuntimeStore.open(db_path) as store:
        store.record(attack, observed_at=1.0, resolve_after=300)
    store = RuntimeStore.open_readonly(db_path)
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(lambda: store.stats()["alerts"]).result() == 2
        pool.submit(store.close).result()


def test_missing_database_reads_as_empty(tmp_path) -> None:
    with RuntimeStore.open_readonly(tmp_path / "none.db") as store:
        assert store.stats()["access_points"] == 0
    assert not (tmp_path / "none.db").exists()


def test_foreign_database_is_refused(tmp_path) -> None:
    path = tmp_path / "old.db"
    sqlite3.connect(path).execute(
        "CREATE TABLE metadata (key TEXT, value TEXT)"
    ).connection.commit()
    with pytest.raises(StoreError, match="schema version"):
        RuntimeStore.open_readonly(path)


def test_replay_follows_the_sensor_flush_schedule(tmp_path, config, profiles) -> None:
    config = config.with_overrides(
        {"detection.identity.trusted_profiles_path": tmp_path / "profiles.json"}
    )
    with RuntimeStore.open(tmp_path / "replay.db") as store:
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


# --- API ------------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path, config, db_path, attack, profiles):
    with RuntimeStore.open(db_path) as store:
        store.record(attack, observed_at=attack.evaluated_at, resolve_after=300)
        store.set_status({"mode": "live", "observed_at": time.time(), "flush_interval_seconds": 5})
    config = config.with_overrides(
        {"detection.identity.trusted_profiles_path": tmp_path / "profiles.json"}
    )
    return TestClient(create_app(config, state_path=db_path))


def test_api_lists_aps_with_their_verdict(client) -> None:
    body = client.get("/api/aps").json()
    aps = {ap["bssid"]: ap for ap in body["items"]}
    assert body["count"] == 2
    assert (aps[TWIN]["status"], aps[TWIN]["trusted"]) == ("evil_twin", False)
    assert (aps[REAL]["status"], aps[REAL]["trusted"]) == ("suspicious", True)


def test_api_ap_detail_metrics_and_timeline(client) -> None:
    detail = client.get(f"/api/aps/{TWIN}").json()
    assert detail["alerts"][0]["classification"] == "evil_twin"
    assert detail["summary"]["bssid"] == TWIN
    assert client.get(f"/api/aps/{REAL}/metrics").json()["count"] == 1
    assert client.get(f"/api/aps/{TWIN}/timeline").json()["count"] >= 2
    assert client.get("/api/aps/00:00:00:00:00:00").status_code == 404


def test_api_alerts_with_filters_and_detail(client) -> None:
    assert client.get("/api/alerts?classification=evil_twin").json()["count"] == 1
    assert client.get("/api/alerts?status=resolved").json()["count"] == 0
    assert client.get("/api/alerts?status=bogus").status_code == 422
    alert_id = client.get("/api/alerts?classification=evil_twin").json()["items"][0]["id"]
    detail = client.get(f"/api/alerts/{alert_id}").json()
    assert "Evil Twin" in detail["alert"]["explanation"]
    assert client.get("/api/alerts/999").status_code == 404


def test_api_system_endpoints(client) -> None:
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/api/stats").json()["open_alerts"] == 2
    assert client.get("/api/sensor").json()["state"] == "online"
    assert client.get("/api/trusted-profiles").json()["enrolled"] == 1
    config = client.get("/api/config").json()
    assert config["detection"]["correlation"]["evil_twin_threshold"] == 0.8
    assert client.get("/api/events?module=deauth_storm").json()["items"][0]["ssid"] == "HomeNet"


def test_api_csv_export(client) -> None:
    response = client.get("/api/export/alerts.csv")
    assert response.headers["content-type"].startswith("text/csv")
    header, *rows = response.text.strip().splitlines()
    assert header.startswith("id,bssid,ssid,status,classification")
    assert len(rows) == 2


def test_api_live_websocket_sends_new_timeline_entries(client) -> None:
    with client.websocket_connect("/ws/live?after_id=0") as socket:
        message = socket.receive_json()
    assert message["items"] and message["latest_id"] == message["items"][-1]["id"]


def test_api_reports_an_unusable_database(tmp_path, config) -> None:
    path = tmp_path / "old.db"
    sqlite3.connect(path).execute(
        "CREATE TABLE metadata (key TEXT, value TEXT)"
    ).connection.commit()
    response = TestClient(create_app(config, state_path=path)).get("/api/aps")
    assert response.status_code == 503


@pytest.mark.parametrize(
    ("status", "state"),
    [
        (None, "unknown"),
        ({"mode": "replay", "observed_at": 1.0, "source": "x.pcap"}, "replay"),
        ({"mode": "live", "observed_at": 1.0, "flush_interval_seconds": 5}, "stale"),
    ],
)
def test_sensor_states(tmp_path, config, status, state) -> None:
    path = tmp_path / "s.db"
    with RuntimeStore.open(path) as store:
        if status is not None:
            store.set_status(status)
    response = TestClient(create_app(config, state_path=path)).get("/api/sensor")
    assert response.json()["state"] == state
