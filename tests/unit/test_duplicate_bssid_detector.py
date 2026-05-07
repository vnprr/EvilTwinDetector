from __future__ import annotations

import unittest

from wiguard.detection import DuplicateBSSIDDetector
from wiguard.features import APFeatureVector, IEFingerprint


def vector(
    *,
    index: int,
    source: str = "a",
    offset_us: int = 0,
    sequence_number: int | None = None,
    rssi_dbm: int | None = -45,
    ie_hash: str = "ie-a",
) -> APFeatureVector:
    local_time_us = 1_000_000.0 + index * 102_400.0
    return APFeatureVector(
        frame_type="beacon",
        observed_monotonic=local_time_us / 1_000_000.0,
        ssid="TwinNet",
        bssid="aa:bb:cc:dd:ee:ff",
        channel=6,
        rssi_dbm=rssi_dbm,
        ap_tsf=int(local_time_us + offset_us),
        radiotap_tsf=int(local_time_us),
        sequence_number=sequence_number if sequence_number is not None else index,
        beacon_interval_tu=100,
        capabilities=0x0411,
        ie_fingerprint=IEFingerprint(
            sequence_signature=(0, 1, 48),
            stable_sequence_signature=(0, 1, 48),
            key_elements=(),
            vendor_ouis=(),
            hash=f"{ie_hash}-{source}",
        ),
    )


class DuplicateBSSIDDetectorTest(unittest.TestCase):
    def test_keeps_single_clock_trend_quiet(self) -> None:
        detector = DuplicateBSSIDDetector(
            min_samples=20,
            min_cluster_samples=8,
            residual_gap_threshold_us=10_000.0,
        )

        for index in range(30):
            alert = detector.update(
                vector(
                    index=index,
                    source="a",
                    offset_us=3_000,
                    sequence_number=100 + index,
                    ie_hash="stable",
                )
            )

        self.assertIsNone(alert)
        self.assertEqual(detector.alerts(), [])

    def test_detects_two_same_bssid_transmitters_with_clock_sequence_rssi_and_ie_evidence(self) -> None:
        detector = DuplicateBSSIDDetector(
            min_samples=20,
            min_cluster_samples=8,
            residual_gap_threshold_us=10_000.0,
            intercept_delta_threshold_us=10_000.0,
            rssi_delta_db=10.0,
            sequence_transition_threshold=4,
        )

        for index in range(12):
            detector.update(
                vector(
                    index=index * 2,
                    source="a",
                    offset_us=0,
                    sequence_number=100 + index,
                    rssi_dbm=-40,
                    ie_hash="enterprise",
                )
            )
            detector.update(
                vector(
                    index=index * 2 + 1,
                    source="b",
                    offset_us=60_000,
                    sequence_number=500 + index,
                    rssi_dbm=-66,
                    ie_hash="hostapd",
                )
            )

        alerts = detector.alerts()

        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0].triggered)
        names = {signal.name for signal in alerts[0].signals}
        self.assertIn("duplicate_bssid_residual_clusters", names)
        self.assertIn("duplicate_bssid_clock_profile_split", names)
        self.assertIn("duplicate_bssid_sequence_interleaving", names)
        self.assertIn("duplicate_bssid_rssi_split", names)
        self.assertIn("duplicate_bssid_ie_split", names)
        self.assertEqual(alerts[0].score, 1.0)

    def test_skips_when_there_are_too_few_samples(self) -> None:
        detector = DuplicateBSSIDDetector(min_samples=20, min_cluster_samples=8)

        for index in range(10):
            detector.update(vector(index=index, source="a", offset_us=0))

        self.assertEqual(detector.alerts(), [])

    def test_skips_when_one_residual_cluster_is_too_small(self) -> None:
        detector = DuplicateBSSIDDetector(
            min_samples=20,
            min_cluster_samples=8,
            residual_gap_threshold_us=10_000.0,
        )

        for index in range(19):
            detector.update(
                vector(
                    index=index,
                    source="a",
                    offset_us=0,
                    sequence_number=100 + index,
                )
            )
        detector.update(
            vector(
                index=20,
                source="b",
                offset_us=80_000,
                sequence_number=600,
                rssi_dbm=-70,
                ie_hash="hostapd",
            )
        )

        self.assertEqual(detector.alerts(), [])


if __name__ == "__main__":
    unittest.main()
