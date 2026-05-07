from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wiguard.analysis import analyze_pcap
from wiguard.runtime import RuntimeStore


FIXTURE_DIR = Path("tests/pcap_fixtures/synthetic")


class RuntimeStoreReplayTest(unittest.TestCase):
    def test_correlated_fixture_replay_writes_expected_alert_lifecycle(self) -> None:
        payload = analyze_pcap(FIXTURE_DIR / "correlated_duplicate_deauth.pcap")
        with tempfile.TemporaryDirectory() as directory:
            with RuntimeStore(Path(directory) / "wiguard.db") as store:
                records = store.record_analysis_result(payload, observed_at=1000.0)
                alerts = store.correlated_alerts()
                events = store.detection_events()
                snapshots = store.ap_snapshots()

        self.assertEqual(len(records), 1)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["classification"], "evil_twin")
        self.assertEqual(
            alerts[0]["contributing_modules"],
            ["deauth_storm", "identity_verification"],
        )
        self.assertGreaterEqual(len(events), 2)
        self.assertEqual(len(snapshots), 1)

    def test_clean_fixture_replay_does_not_write_correlated_alerts(self) -> None:
        payload = analyze_pcap(FIXTURE_DIR / "clean_single_ap.pcap")
        with tempfile.TemporaryDirectory() as directory:
            with RuntimeStore(Path(directory) / "wiguard.db") as store:
                records = store.record_analysis_result(payload, observed_at=2000.0)
                alerts = store.correlated_alerts()
                events = store.detection_events()
                snapshots = store.ap_snapshots()

        self.assertEqual(records, [])
        self.assertEqual(alerts, [])
        self.assertEqual(events, [])
        self.assertEqual(len(snapshots), 1)


if __name__ == "__main__":
    unittest.main()
