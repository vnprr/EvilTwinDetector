"""Tests for AP metric-sample history, the metrics endpoint and pcap replay."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from wiguard.api import create_app
from wiguard.replay import main as replay_main
from wiguard.runtime import RuntimeStore

FIXTURE_DIR = Path("tests/pcap_fixtures/synthetic")
BSSID = "ca:fe:00:00:00:01"


class MetricSampleStoreTest(unittest.TestCase):
    def test_samples_are_chronological_and_limited(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with RuntimeStore(Path(directory) / "s.db") as store:
                for index, observed_at in enumerate((30.0, 10.0, 20.0)):
                    store.insert_ap_metric_sample(
                        {
                            "bssid": BSSID,
                            "last_rssi_dbm": -40 - index,
                            "avg_rssi_dbm": -45.0,
                            "rssi_stddev": 1.0,
                            "clock_estimate": {"skew_ppm": 2.0 + index},
                            "frames": 10 * (index + 1),
                        },
                        observed_at=observed_at,
                    )
                all_samples = store.ap_metric_samples(BSSID)
                limited = store.ap_metric_samples(BSSID, limit=2)

        self.assertEqual([s["observed_at"] for s in all_samples], [10.0, 20.0, 30.0])
        # limit returns the most recent, still in chronological order.
        self.assertEqual([s["observed_at"] for s in limited], [20.0, 30.0])
        self.assertEqual(all_samples[0]["clock_skew_ppm"], 3.0)


class MetricsEndpointTest(unittest.TestCase):
    def test_metrics_endpoint_returns_samples(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "s.db"
            with RuntimeStore(state_path) as store:
                for observed_at in (100.0, 200.0):
                    store.insert_ap_metric_sample(
                        {"bssid": BSSID, "last_rssi_dbm": -50, "avg_rssi_dbm": -50.0,
                         "rssi_stddev": 0.5, "clock_estimate": {"skew_ppm": 1.0}, "frames": 5},
                        observed_at=observed_at,
                    )
            client = TestClient(create_app(state_path=state_path, cors_origins=()))
            response = client.get(f"/api/aps/{BSSID}/metrics")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 2)
        self.assertEqual(payload["items"][0]["observed_at"], 100.0)


class ReplayTest(unittest.TestCase):
    def test_replay_populates_db_and_marks_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "replay.db"
            exit_code = replay_main(
                [
                    str(FIXTURE_DIR / "correlated_duplicate_deauth.pcap"),
                    "--state-path",
                    str(state_path),
                    "--min-clock-samples",
                    "5",
                ]
            )
            self.assertEqual(exit_code, 0)
            with RuntimeStore(state_path) as store:
                status = store.runtime_status()
                samples = store.ap_metric_samples(BSSID)
            client = TestClient(create_app(state_path=state_path, cors_origins=()))
            sensor = client.get("/api/sensor").json()
            alerts = client.get("/api/alerts").json()

        self.assertEqual(status["mode"], "replay")
        self.assertGreaterEqual(len(samples), 1)
        self.assertEqual(sensor["state"], "replay")
        self.assertGreaterEqual(alerts["count"], 1)


if __name__ == "__main__":
    unittest.main()
