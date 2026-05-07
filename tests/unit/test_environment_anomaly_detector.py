from __future__ import annotations

import unittest

from wiguard.detection import EnvironmentAnomalyDetector
from wiguard.features import APFeatureSummary, BeaconTimingStats, SequenceAnalysis


def summary(
    bssid: str,
    *,
    ssid: str = "CorpNet",
    ie_hash: str = "corp-ie",
    stable_ie_ids: tuple[int, ...] = (0, 1, 48, 127, 191, 221),
    key_ie_ids: tuple[int, ...] = (1, 48, 127, 191, 221),
    vendor_ouis: tuple[str, ...] = ("00:11:22",),
    interval_tu: float = 100.0,
    frames: int = 50,
) -> APFeatureSummary:
    return APFeatureSummary(
        bssid=bssid,
        ssid=ssid,
        channels=(1,),
        frames=frames,
        last_rssi_dbm=-45,
        avg_rssi_dbm=-45.0,
        rssi_stddev=1.0,
        dominant_ie_fingerprint=ie_hash,
        ie_fingerprint_hashes=(ie_hash,),
        stable_ie_ids_union=stable_ie_ids,
        key_ie_ids_union=key_ie_ids,
        vendor_ouis=vendor_ouis,
        clock_estimate=None,
        beacon_timing=BeaconTimingStats(
            samples=10,
            expected_interval_us=interval_tu * 1024.0,
            jitter_mean_us=0.0,
            jitter_stddev_us=10.0,
            jitter_max_abs_us=25.0,
            estimated_missed_beacons=0,
        ),
        sequence_analysis=SequenceAnalysis(
            samples=50,
            last_sequence_number=100,
            duplicate_count=0,
            wrap_count=0,
            reset_count=0,
            large_gap_count=0,
            max_forward_gap=1,
        ),
        last_sequence_number=100,
    )


class EnvironmentAnomalyDetectorTest(unittest.TestCase):
    def test_keeps_homogeneous_same_ssid_group_quiet(self) -> None:
        detector = EnvironmentAnomalyDetector(min_frames=1)
        alerts = detector.analyze(
            [
                summary("00:11:22:33:44:01"),
                summary("00:11:22:33:44:02"),
                summary("00:11:22:33:44:03"),
            ]
        )

        self.assertEqual(alerts, [])

    def test_detects_same_ssid_minority_fingerprint_vendor_and_ie_shape(self) -> None:
        detector = EnvironmentAnomalyDetector(min_frames=1)
        alerts = detector.analyze(
            [
                summary("00:11:22:33:44:01"),
                summary("00:11:22:33:44:02"),
                summary(
                    "aa:bb:cc:dd:ee:ff",
                    ie_hash="hostapd-like",
                    stable_ie_ids=(0, 1),
                    key_ie_ids=(1,),
                    vendor_ouis=("aa:bb:cc",),
                ),
            ]
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(alerts[0].score, 1.0)
        names = {signal.name for signal in alerts[0].signals}
        self.assertIn("same_ssid_ie_fingerprint_outlier", names)
        self.assertIn("same_ssid_vendor_oui_outlier", names)
        self.assertIn("same_ssid_ie_shape_outlier", names)

    def test_detects_same_ssid_beacon_interval_outlier(self) -> None:
        detector = EnvironmentAnomalyDetector(min_frames=1)
        alerts = detector.analyze(
            [
                summary("00:11:22:33:44:01"),
                summary("00:11:22:33:44:02"),
                summary("00:11:22:33:44:03", interval_tu=200.0),
            ]
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].bssid, "00:11:22:33:44:03")
        self.assertEqual({signal.name for signal in alerts[0].signals}, {"same_ssid_beacon_interval_outlier"})

    def test_skips_groups_without_enough_same_ssid_peers(self) -> None:
        detector = EnvironmentAnomalyDetector(min_frames=1, min_same_ssid_peers=3)
        alerts = detector.analyze(
            [
                summary("00:11:22:33:44:01"),
                summary(
                    "aa:bb:cc:dd:ee:ff",
                    ie_hash="hostapd-like",
                    vendor_ouis=("aa:bb:cc",),
                ),
            ]
        )

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
