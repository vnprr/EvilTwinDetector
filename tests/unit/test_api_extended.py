"""Tests for the config/sensor/baseline/export API endpoints."""

from __future__ import annotations

import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from fastapi.testclient import TestClient

from wiguard.analysis import analyze_pcap
from wiguard.api import create_app
from wiguard.config import load_config
from wiguard.detection import IdentityBaseline, IdentityBaselineStore
from wiguard.runtime import RuntimeStore

FIXTURE_DIR = Path("tests/pcap_fixtures/synthetic")


def _seed(state_path: Path) -> None:
    payload = analyze_pcap(FIXTURE_DIR / "correlated_duplicate_deauth.pcap")
    with RuntimeStore(state_path) as store:
        store.record_analysis_result(payload, observed_at=1000.0)


class ConfigEndpointTest(unittest.TestCase):
    def test_config_endpoint_reflects_effective_config(self) -> None:
        config = load_config(None)
        config = replace(
            config,
            detection=replace(
                config.detection,
                deauth_storm=replace(config.detection.deauth_storm, deauth_rate_threshold=7.0),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            client = TestClient(
                create_app(state_path=Path(directory) / "s.db", cors_origins=(), config=config)
            )
            response = client.get("/api/config")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["detection"]["deauth_storm"]["deauth_rate_threshold"], 7.0
        )


class SensorEndpointTest(unittest.TestCase):
    def test_unknown_when_no_runtime_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = TestClient(
                create_app(state_path=Path(directory) / "s.db", cors_origins=())
            )
            response = client.get("/api/sensor")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "unknown")

    def test_online_and_stale_states(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "s.db"
            with RuntimeStore(state_path) as store:
                store.set_runtime_status(
                    {"observed_at": time.time(), "flush_interval_seconds": 5.0}
                )
            client = TestClient(create_app(state_path=state_path, cors_origins=()))
            online = client.get("/api/sensor").json()

            with RuntimeStore(state_path) as store:
                store.set_runtime_status(
                    {"observed_at": time.time() - 3600.0, "flush_interval_seconds": 5.0}
                )
            stale = client.get("/api/sensor").json()

        self.assertEqual(online["state"], "online")
        self.assertLess(online["stale_seconds"], 15.0)
        self.assertEqual(stale["state"], "stale")


class BaselineEndpointTest(unittest.TestCase):
    def test_empty_when_no_baseline_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(None)
            config = replace(
                config,
                detection=replace(
                    config.detection,
                    identity=replace(
                        config.detection.identity,
                        baseline_path=str(Path(directory) / "missing.json"),
                    ),
                ),
            )
            client = TestClient(
                create_app(state_path=Path(directory) / "s.db", cors_origins=(), config=config)
            )
            response = client.get("/api/baseline")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["enrolled"], 0)

    def test_reports_enrolled_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / "baselines.json"
            IdentityBaselineStore(baseline_path).save(
                [
                    IdentityBaseline(
                        bssid="ca:fe:00:00:00:01",
                        ssid="LAB-WIFI",
                        frames=60,
                        dominant_ie_fingerprint="abc123",
                        avg_rssi_dbm=-50.0,
                        rssi_stddev=1.0,
                        clock_skew_ppm=2.0,
                        sequence_reset_count=0,
                    )
                ]
            )
            config = load_config(None)
            config = replace(
                config,
                detection=replace(
                    config.detection,
                    identity=replace(
                        config.detection.identity, baseline_path=str(baseline_path)
                    ),
                ),
            )
            client = TestClient(
                create_app(state_path=Path(directory) / "s.db", cors_origins=(), config=config)
            )
            response = client.get("/api/baseline")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["enrolled"], 1)
        self.assertEqual(payload["baselines"][0]["bssid"], "ca:fe:00:00:00:01")


class ExportEndpointTest(unittest.TestCase):
    def test_alerts_csv_has_header_and_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "s.db"
            _seed(state_path)
            client = TestClient(create_app(state_path=state_path, cors_origins=()))
            response = client.get("/api/export/alerts.csv")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/csv"))
        self.assertIn("attachment", response.headers["content-disposition"])
        lines = [line for line in response.text.splitlines() if line]
        self.assertTrue(lines[0].startswith("alert_key,"))
        self.assertGreaterEqual(len(lines), 2)

    def test_aps_and_events_csv_have_headers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "s.db"
            _seed(state_path)
            client = TestClient(create_app(state_path=state_path, cors_origins=()))
            aps = client.get("/api/export/aps.csv")
            events = client.get("/api/export/events.csv")
        self.assertEqual(aps.status_code, 200)
        self.assertTrue(aps.text.splitlines()[0].startswith("bssid,"))
        self.assertEqual(events.status_code, 200)
        self.assertTrue(events.text.splitlines()[0].startswith("event_id,"))


if __name__ == "__main__":
    unittest.main()
