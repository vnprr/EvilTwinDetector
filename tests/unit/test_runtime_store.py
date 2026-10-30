from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wiguard.correlation import CorrelatedAlert, DetectionEvent
from wiguard.runtime import RuntimeStore
from wiguard.runtime.store import SCHEMA_VERSION


def detection_event() -> DetectionEvent:
    return DetectionEvent(
        module="identity_verification",
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="RuntimeNet",
        score=0.9,
        signal_names=("duplicate_bssid_residual_clusters",),
        evidence={"samples": 40},
    )


def correlated_alert() -> CorrelatedAlert:
    event = detection_event()
    return CorrelatedAlert(
        alert_id="alert-1",
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="RuntimeNet",
        final_score=0.9,
        classification="evil_twin",
        contributing_modules=("identity_verification",),
        explanation="RuntimeNet duplicate BSSID evidence",
        timeline=(event,),
    )


class RuntimeStoreTest(unittest.TestCase):
    def test_schema_initialization_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RuntimeStore(Path(directory) / "wiguard.db")
            try:
                store.initialize_schema()
                store.initialize_schema()

                self.assertEqual(store.schema_version(), SCHEMA_VERSION)
                self.assertEqual(store.ap_snapshots(), [])
                self.assertEqual(store.detection_events(), [])
                self.assertEqual(store.correlated_alerts(), [])
            finally:
                store.close()

    def test_ap_snapshot_upsert_preserves_first_seen_and_updates_last_seen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with RuntimeStore(Path(directory) / "wiguard.db") as store:
                store.upsert_ap_snapshot(
                    {
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "ssid": "RuntimeNet",
                        "channels": [1],
                        "frames": 10,
                        "last_rssi_dbm": -50,
                    },
                    observed_at=100.0,
                )
                store.upsert_ap_snapshot(
                    {
                        "bssid": "aa:bb:cc:dd:ee:ff",
                        "ssid": "RuntimeNet",
                        "channels": [1, 6],
                        "frames": 15,
                        "last_rssi_dbm": -47,
                    },
                    observed_at=130.0,
                )

                rows = store.ap_snapshots()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(rows[0]["first_seen"], 100.0)
        self.assertEqual(rows[0]["last_seen"], 130.0)
        self.assertEqual(rows[0]["snapshot_count"], 2)
        self.assertEqual(rows[0]["total_frames"], 15)
        self.assertEqual(rows[0]["last_rssi_dbm"], -47)

    def test_detection_event_is_persisted_with_signal_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with RuntimeStore(Path(directory) / "wiguard.db") as store:
                event_id = store.insert_detection_event(detection_event(), observed_at=200.0)
                events = store.detection_events()
                timeline = store.timeline_events()

        self.assertEqual(event_id, 1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["module"], "identity_verification")
        self.assertEqual(events[0]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(events[0]["signal_names"], ["duplicate_bssid_residual_clusters"])
        self.assertEqual(timeline[0]["event_type"], "detection_event")

    def test_correlated_alert_lifecycle_deduplicates_repeats_in_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with RuntimeStore(Path(directory) / "wiguard.db") as store:
                first = store.upsert_correlated_alert(
                    correlated_alert(),
                    observed_at=300.0,
                    cooldown_seconds=120.0,
                )
                second = store.upsert_correlated_alert(
                    correlated_alert(),
                    observed_at=330.0,
                    cooldown_seconds=120.0,
                )
                rows = store.correlated_alerts()
                timeline = store.timeline_events()

        self.assertFalse(first.cooldown_suppressed)
        self.assertTrue(second.cooldown_suppressed)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 2)
        self.assertEqual(rows[0]["first_seen"], 300.0)
        self.assertEqual(rows[0]["last_seen"], 330.0)
        self.assertEqual(rows[0]["status"], "open")
        self.assertEqual(timeline[0]["event_type"], "correlated_alert_opened")
        self.assertEqual(len(timeline), 1)


if __name__ == "__main__":
    unittest.main()
