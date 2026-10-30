"""Tests for the WiGuard configuration loader.

These tests pin down the property the project most needs from config.yaml:
that it is a real single source of truth. A value set in the file must change
detector behaviour, unknown keys must fail loudly, and the built-in defaults
must stay in sync with the detectors they mirror.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from wiguard.analysis import analyze_pcap
from wiguard.config import (
    ConfigError,
    DEFAULT_MODULE_WEIGHTS,
    WiGuardConfig,
    load_config,
)
from wiguard.correlation import DetectionEvent
from wiguard.correlation.engine import DEFAULT_MODULE_WEIGHTS as ENGINE_WEIGHTS

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "pcap_fixtures" / "synthetic"


def _write(text: str) -> Path:
    tmp = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    tmp.write(text)
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


class ConfigLoadingTests(unittest.TestCase):
    def test_missing_file_returns_defaults(self) -> None:
        config = load_config(Path("/nonexistent/config.yaml"))
        self.assertIsInstance(config, WiGuardConfig)
        self.assertEqual(config.detection.deauth_storm.deauth_rate_threshold, 10.0)
        self.assertIsNone(config.source_path)

    def test_missing_required_file_raises(self) -> None:
        with self.assertRaises(ConfigError):
            load_config(Path("/nonexistent/config.yaml"), required=True)

    def test_merges_overrides_and_keeps_defaults(self) -> None:
        path = _write(
            """
            detection:
              deauth_storm:
                deauth_rate_threshold: 42.0
              correlation:
                min_final_score: 0.5
            """
        )
        config = load_config(path)
        # Overridden values take effect.
        self.assertEqual(config.detection.deauth_storm.deauth_rate_threshold, 42.0)
        self.assertEqual(config.detection.correlation.min_final_score, 0.5)
        # Unspecified values keep their defaults.
        self.assertEqual(config.detection.deauth_storm.disassoc_rate_threshold, 5.0)
        self.assertEqual(config.source_path, str(path))

    def test_rejects_unknown_key(self) -> None:
        path = _write("detection:\n  deauth_storm:\n    typo_threshold: 1.0\n")
        with self.assertRaises(ConfigError) as ctx:
            load_config(path)
        self.assertIn("typo_threshold", str(ctx.exception))

    def test_rejects_unknown_top_level_section(self) -> None:
        path = _write("nonsense:\n  foo: 1\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_rejects_out_of_range_ratio(self) -> None:
        path = _write("detection:\n  correlation:\n    min_final_score: 1.5\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_rejects_wrong_type(self) -> None:
        path = _write("capture:\n  dwell_seconds: not-a-number\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_duplicate_invariant_enforced_at_load(self) -> None:
        path = _write(
            "detection:\n  identity:\n    duplicate_bssid:\n"
            "      min_cluster_samples: 8\n      min_samples: 10\n"
        )
        with self.assertRaises(ConfigError):
            load_config(path)


class ConfigSyncTests(unittest.TestCase):
    def test_module_weights_match_engine_defaults(self) -> None:
        self.assertEqual(DEFAULT_MODULE_WEIGHTS, ENGINE_WEIGHTS)

    def test_builders_reflect_config(self) -> None:
        config = load_config(None)
        config = replace(
            config,
            detection=replace(
                config.detection,
                deauth_storm=replace(
                    config.detection.deauth_storm, deauth_rate_threshold=99.0
                ),
                correlation=replace(
                    config.detection.correlation, min_final_score=0.42
                ),
            ),
        )
        self.assertEqual(config.build_deauth_detector().deauth_rate_threshold, 99.0)
        self.assertEqual(config.build_correlation_engine().min_final_score, 0.42)

    def test_public_dict_is_json_friendly(self) -> None:
        public = load_config(None).to_public_dict()
        self.assertIsInstance(public["detection"]["correlation"]["module_weights"], dict)
        self.assertIsInstance(public["capture"]["channels_2ghz"], list)


class ConfigAffectsDetectionTests(unittest.TestCase):
    """The core guarantee: changing a threshold changes detector output."""

    def _base(self) -> WiGuardConfig:
        config = load_config(None)
        # Short fixtures: lower the clock-sample requirement like the evaluator.
        return replace(
            config, features=replace(config.features, clock_skew_min_samples=5)
        )

    def test_deauth_threshold_changes_detection(self) -> None:
        base = self._base()
        low = replace(
            base,
            detection=replace(
                base.detection,
                deauth_storm=replace(
                    base.detection.deauth_storm,
                    deauth_rate_threshold=0.001,
                    disassoc_rate_threshold=0.001,
                    broadcast_rate_threshold=0.001,
                    unicast_rate_threshold=0.001,
                ),
            ),
        )
        high = replace(
            base,
            detection=replace(
                base.detection,
                deauth_storm=replace(
                    base.detection.deauth_storm,
                    deauth_rate_threshold=1e9,
                    disassoc_rate_threshold=1e9,
                    broadcast_rate_threshold=1e9,
                    unicast_rate_threshold=1e9,
                ),
            ),
        )
        fixture = FIXTURE_DIR / "deauth_burst.pcap"
        alerts_low = analyze_pcap(fixture, wiguard_config=low)["deauth_alerts"]
        alerts_high = analyze_pcap(fixture, wiguard_config=high)["deauth_alerts"]
        self.assertGreater(len(alerts_low), 0)
        self.assertEqual(len(alerts_high), 0)

    def test_correlation_min_final_score_filters(self) -> None:
        # A single mid-strength identity signal: final score = 0.5 * 0.45 = 0.225.
        event = DetectionEvent(
            module="identity_verification",
            bssid="aa:bb:cc:dd:ee:ff",
            ssid="LAB-WIFI",
            score=0.5,
            signal_names=("ie_fingerprint_changed",),
            evidence={"signals": []},
        )
        permissive = replace(
            load_config(None).detection.correlation, min_final_score=0.2
        )
        strict = replace(
            load_config(None).detection.correlation, min_final_score=0.3
        )
        base = load_config(None)
        permissive_engine = replace(
            base, detection=replace(base.detection, correlation=permissive)
        ).build_correlation_engine()
        strict_engine = replace(
            base, detection=replace(base.detection, correlation=strict)
        ).build_correlation_engine()
        self.assertEqual(len(permissive_engine.correlate([event])), 1)
        self.assertEqual(len(strict_engine.correlate([event])), 0)


if __name__ == "__main__":
    unittest.main()
