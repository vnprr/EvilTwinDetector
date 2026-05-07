from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from wiguard.evaluation import load_manifest


class FixtureManifestTest(unittest.TestCase):
    def test_loads_valid_manifest_and_resolves_relative_pcap_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenarios": [
                            {
                                "name": "clean",
                                "pcap": "clean.pcap",
                                "expected_classification": "clean",
                                "expected_modules": [],
                                "expected_signals": [],
                                "description": "baseline",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            loaded = load_manifest(manifest)

            self.assertEqual(loaded.schema_version, 1)
            self.assertEqual(len(loaded.scenarios), 1)
            self.assertEqual(loaded.scenarios[0].name, "clean")
            self.assertEqual(loaded.scenarios[0].pcap, (root / "clean.pcap").resolve())

    def test_missing_required_field_raises_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenarios": [
                            {
                                "name": "broken",
                                "expected_classification": "clean",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "pcap"):
                load_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
