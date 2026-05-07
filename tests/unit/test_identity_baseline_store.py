from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from wiguard.detection import APIdentityVerifier, IdentityBaseline, IdentityBaselineStore

from tests.unit.test_identity_verifier import summary


class IdentityBaselineStoreTest(unittest.TestCase):
    def test_round_trips_identity_baselines_as_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity-baselines.json"
            store = IdentityBaselineStore(path)

            self.assertEqual(store.load(), ())
            baseline = IdentityBaseline.from_summary(summary(frames=50))
            metadata = store.save([baseline])
            loaded = IdentityBaselineStore(path).load()

            self.assertEqual(metadata.baselines_saved, 1)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0], baseline)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(len(payload["baselines"]), 1)

    def test_monitor_mode_does_not_auto_learn_unknown_bssid(self) -> None:
        verifier = APIdentityVerifier(
            min_baseline_frames=10,
            auto_baseline=False,
        )

        alert = verifier.update(summary(frames=10))

        self.assertFalse(alert.triggered)
        self.assertIsNone(verifier.baseline_for("aa:bb:cc:dd:ee:ff"))

    def test_loaded_baseline_can_trigger_identity_alert(self) -> None:
        baseline = IdentityBaseline.from_summary(summary(frames=50))
        verifier = APIdentityVerifier(
            min_baseline_frames=10,
            baselines=[baseline],
            auto_baseline=False,
        )

        alert = verifier.update(summary(ie_hash="changed", frames=50))

        self.assertTrue(alert.triggered)
        self.assertEqual({signal.name for signal in alert.signals}, {"ie_fingerprint_changed"})


if __name__ == "__main__":
    unittest.main()
