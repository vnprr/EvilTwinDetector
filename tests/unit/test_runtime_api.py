from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from wiguard.api import create_app
from wiguard.analysis import analyze_pcap
from wiguard.runtime import RuntimeStore


FIXTURE_DIR = Path("tests/pcap_fixtures/synthetic")


class RuntimeAPITest(unittest.TestCase):
    def test_health_initializes_empty_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "empty.db"
            client = TestClient(create_app(state_path=state_path, cors_origins=()))

            response = client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["ap_count"], 0)
        self.assertEqual(payload["alert_count"], 0)

    def test_ap_list_and_detail_return_seeded_snapshot_with_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "runtime.db"
            self._seed_correlated_fixture(state_path)
            client = TestClient(create_app(state_path=state_path, cors_origins=()))

            list_response = client.get("/api/aps")
            detail_response = client.get("/api/aps/ca:fe:00:00:00:01")

        self.assertEqual(list_response.status_code, 200)
        aps = list_response.json()["items"]
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0]["status"], "evil_twin")
        self.assertEqual(detail_response.status_code, 200)
        detail = detail_response.json()
        self.assertEqual(detail["status"], "evil_twin")
        self.assertEqual(detail["snapshot"]["bssid"], "ca:fe:00:00:00:01")

    def test_alert_list_filters_and_detail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "runtime.db"
            self._seed_correlated_fixture(state_path)
            client = TestClient(create_app(state_path=state_path, cors_origins=()))

            alerts_response = client.get("/api/alerts", params={"classification": "evil_twin"})
            empty_response = client.get("/api/alerts", params={"classification": "info"})
            alert_key = alerts_response.json()["items"][0]["alert_key"]
            detail_response = client.get(f"/api/alerts/{alert_key}")

        self.assertEqual(alerts_response.status_code, 200)
        self.assertEqual(alerts_response.json()["count"], 1)
        self.assertEqual(empty_response.status_code, 200)
        self.assertEqual(empty_response.json()["count"], 0)
        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(detail_response.json()["alert"]["classification"], "evil_twin")
        self.assertTrue(detail_response.json()["timeline"])

    def test_ap_timeline_is_filtered_by_bssid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "runtime.db"
            self._seed_correlated_fixture(state_path)
            with RuntimeStore(state_path) as store:
                store.insert_detection_event(
                    {
                        "module": "identity_verification",
                        "bssid": "de:ad:be:ef:00:01",
                        "ssid": "OtherNet",
                        "score": 0.5,
                        "signal_names": ("other_signal",),
                        "evidence": {},
                    },
                    observed_at=3000.0,
                )
            client = TestClient(create_app(state_path=state_path, cors_origins=()))

            response = client.get("/api/aps/ca:fe:00:00:00:01/timeline")

        self.assertEqual(response.status_code, 200)
        events = response.json()["items"]
        self.assertTrue(events)
        self.assertTrue(
            all(event["bssid"] == "ca:fe:00:00:00:01" for event in events)
        )

    def test_missing_resources_return_404(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = TestClient(
                create_app(state_path=Path(directory) / "runtime.db", cors_origins=())
            )

            ap_response = client.get("/api/aps/00:00:00:00:00:00")
            alert_response = client.get("/api/alerts/missing-alert")

        self.assertEqual(ap_response.status_code, 404)
        self.assertIn("AP not found", ap_response.json()["detail"])
        self.assertEqual(alert_response.status_code, 404)
        self.assertIn("Alert not found", alert_response.json()["detail"])

    def test_clean_fixture_replay_returns_no_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "runtime.db"
            payload = analyze_pcap(FIXTURE_DIR / "clean_single_ap.pcap")
            with RuntimeStore(state_path) as store:
                store.record_analysis_result(payload, observed_at=4000.0)
            client = TestClient(create_app(state_path=state_path, cors_origins=()))

            response = client.get("/api/alerts")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 0)

    def test_events_endpoint_paginates_raw_detection_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "runtime.db"
            self._seed_correlated_fixture(state_path)
            client = TestClient(create_app(state_path=state_path, cors_origins=()))

            response = client.get("/api/events", params={"limit": 1})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["limit"], 1)
        self.assertEqual(len(response.json()["items"]), 1)

    @staticmethod
    def _seed_correlated_fixture(state_path: Path) -> None:
        payload = analyze_pcap(FIXTURE_DIR / "correlated_duplicate_deauth.pcap")
        with RuntimeStore(state_path) as store:
            store.record_analysis_result(payload, observed_at=1000.0)


if __name__ == "__main__":
    unittest.main()
