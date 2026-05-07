from __future__ import annotations

import unittest

from wiguard.features import BeaconTimingAnalyzer, FeatureExtractor

from tests.unit.test_ie_fingerprint import beacon_with_tim


class BeaconTimingAnalyzerTest(unittest.TestCase):
    def test_estimates_jitter_against_nearest_declared_interval_multiple(self) -> None:
        analyzer = BeaconTimingAnalyzer()
        extractor = FeatureExtractor()
        timestamps = (1_000_000, 1_102_400, 1_204_850, 1_409_600)

        for timestamp in timestamps:
            packet = beacon_with_tim(b"\x00\x01")
            packet["Dot11Beacon"].timestamp = timestamp
            vector = extractor.extract(packet, observed_monotonic=timestamp / 1_000_000)
            assert vector is not None
            analyzer.add(vector)

        summary = analyzer.summary()

        self.assertEqual(summary.samples, 3)
        self.assertEqual(summary.expected_interval_us, 102_400.0)
        self.assertEqual(summary.estimated_missed_beacons, 1)
        self.assertEqual(summary.jitter_max_abs_us, 50.0)


if __name__ == "__main__":
    unittest.main()
