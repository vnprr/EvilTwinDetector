from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wiguard.evaluation import evaluate_manifest, load_manifest
from wiguard.evaluation.synthetic import write_synthetic_fixtures


class EvaluationHarnessTest(unittest.TestCase):
    def test_generated_synthetic_fixtures_match_expected_detection_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = write_synthetic_fixtures(Path(directory))

            report = evaluate_manifest(manifest_path)

            self.assertTrue(report["success"])
            self.assertEqual(report["scenarios"], 5)
            self.assertEqual(report["failed"], 0)
            by_name = {item["name"]: item for item in report["results"]}
            self.assertEqual(by_name["clean_single_ap"]["observed_classification"], "clean")
            self.assertIn(
                "identity_verification",
                by_name["duplicate_bssid_clock_split"]["observed_modules"],
            )
            self.assertIn(
                "deauth_storm",
                by_name["deauth_burst"]["observed_modules"],
            )
            self.assertEqual(
                by_name["correlated_duplicate_deauth"]["observed_classification"],
                "evil_twin",
            )

    def test_synthetic_manifest_points_to_existing_pcaps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = write_synthetic_fixtures(Path(directory))
            manifest = load_manifest(manifest_path)

            self.assertTrue(manifest.scenarios)
            for scenario in manifest.scenarios:
                self.assertTrue(scenario.pcap.exists(), scenario.pcap)


if __name__ == "__main__":
    unittest.main()
