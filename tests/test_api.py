"""The read-only HTTP API, on a database replayed from the classic Evil Twin scenario."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from builders import FIXTURES
from wiguard.analysis import analyze_pcap
from wiguard.api import create_app
from wiguard.detection import TrustedProfileStore, enroll
from wiguard.runtime import StateWriter

REAL = "00:11:22:aa:00:01"
TWIN = "02:de:ad:be:ef:01"
OPENAPI = Path(__file__).parents[1] / "dashboard" / "openapi.json"


@pytest.fixture
def client(tmp_path, config) -> TestClient:
    baseline = analyze_pcap(FIXTURES / "enroll_home.pcap", config, trusted_profiles=[])
    profiles = enroll(baseline.access_points, min_frames=50, enrolled_at=0.0)
    TrustedProfileStore(tmp_path / "profiles.json").save(profiles)
    attack = analyze_pcap(FIXTURES / "classic_evil_twin.pcap", config, trusted_profiles=profiles)
    with StateWriter.open(tmp_path / "state.db") as store:
        store.record(attack, observed_at=attack.evaluated_at, resolve_after=300)
        store.set_status({"mode": "live", "observed_at": time.time(), "flush_interval_seconds": 5})
    config = config.with_overrides(
        {"detection.identity.trusted_profiles_path": tmp_path / "profiles.json"}
    )
    return TestClient(create_app(config, state_path=tmp_path / "state.db"))


def test_access_points_carry_their_verdict(client) -> None:
    aps = {ap["bssid"]: ap for ap in client.get("/api/aps").json()}
    assert (aps[TWIN]["status"], aps[TWIN]["trusted"]) == ("evil_twin", False)
    assert (aps[REAL]["status"], aps[REAL]["trusted"]) == ("suspicious", True)


def test_access_point_detail_metrics_and_timeline(client) -> None:
    detail = client.get(f"/api/aps/{TWIN}").json()
    assert detail["alerts"][0]["classification"] == "evil_twin"
    assert detail["summary"]["bssid"] == TWIN
    assert len(client.get(f"/api/aps/{REAL}/metrics").json()) == 1
    assert len(client.get(f"/api/aps/{TWIN}/timeline").json()) >= 2
    assert client.get("/api/aps/00:00:00:00:00:00").status_code == 404


def test_alerts_with_filters_and_evidence(client) -> None:
    (twin,) = client.get("/api/alerts?classification=evil_twin").json()
    assert client.get("/api/alerts?status=resolved").json() == []
    assert client.get("/api/alerts?status=bogus").status_code == 422
    detail = client.get(f"/api/alerts/{twin['id']}").json()
    assert "Evil Twin" in detail["alert"]["explanation"]
    linked = [e for e in detail["alert"]["evidence"] if e["context"].get("linked_from") == REAL]
    assert linked and linked[0]["signals"][0]["severity"] == "high"
    assert client.get("/api/alerts/999").status_code == 404


def test_system_endpoints(client) -> None:
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/api/stats").json()["open_alerts"] == 2
    assert client.get("/api/sensor").json()["state"] == "online"
    assert len(client.get("/api/trusted-profiles").json()["profiles"]) == 1
    settings = client.get("/api/config").json()["settings"]
    assert settings["detection"]["correlation"]["evil_twin_threshold"] == 0.8
    (storm,) = client.get("/api/events?module=deauth_storm").json()
    assert storm["ssid"] == "HomeNet"


def test_csv_export(client) -> None:
    response = client.get("/api/export/alerts.csv")
    assert response.headers["content-type"].startswith("text/csv")
    header, *rows = response.text.strip().splitlines()
    assert header.startswith("id,bssid,ssid,status,classification")
    assert len(rows) == 2


def test_live_websocket_sends_timeline_entries(client) -> None:
    with client.websocket_connect("/api/live?after_id=0") as socket:
        entries = socket.receive_json()
    assert entries and all("message" in entry for entry in entries)


def test_unusable_database_is_reported(tmp_path, config) -> None:
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE metadata (key TEXT, value TEXT)")
    assert TestClient(create_app(config, state_path=path)).get("/api/aps").status_code == 503


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
    with StateWriter.open(path) as store:
        if status is not None:
            store.set_status(status)
    response = TestClient(create_app(config, state_path=path)).get("/api/sensor")
    assert response.json()["state"] == state


def test_dashboard_types_are_generated_from_the_current_api(config) -> None:
    """dashboard/openapi.json must match the API; regenerate with `npm run api:types`."""
    assert json.loads(OPENAPI.read_text()) == create_app(config).openapi()
