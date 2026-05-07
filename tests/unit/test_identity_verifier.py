from __future__ import annotations

import unittest

from wiguard.detection import APIdentityVerifier
from wiguard.features import APFeatureSummary, BeaconTimingStats, ClockSkewEstimate, SequenceAnalysis


def summary(
    *,
    ie_hash: str = "ie-a",
    rssi: float = -45.0,
    skew_ppm: float | None = 1.0,
    reset_count: int = 0,
    frames: int = 100,
) -> APFeatureSummary:
    return APFeatureSummary(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="IdentityNet",
        channels=(1,),
        frames=frames,
        last_rssi_dbm=int(rssi),
        avg_rssi_dbm=rssi,
        rssi_stddev=1.0,
        dominant_ie_fingerprint=ie_hash,
        ie_fingerprint_hashes=(ie_hash,),
        stable_ie_ids_union=(0, 1, 48, 221),
        key_ie_ids_union=(1, 48, 221),
        vendor_ouis=("00:11:22",),
        clock_estimate=(
            ClockSkewEstimate(
                sample_count=100,
                slope=1.0 + skew_ppm / 1_000_000.0,
                skew_ppm=skew_ppm,
                intercept_us=0.0,
                r_squared=0.99999,
                residual_stddev_us=10.0,
            )
            if skew_ppm is not None
            else None
        ),
        beacon_timing=BeaconTimingStats(
            samples=99,
            expected_interval_us=102_400.0,
            jitter_mean_us=0.0,
            jitter_stddev_us=10.0,
            jitter_max_abs_us=25.0,
            estimated_missed_beacons=0,
        ),
        sequence_analysis=SequenceAnalysis(
            samples=100,
            last_sequence_number=100,
            duplicate_count=0,
            wrap_count=0,
            reset_count=reset_count,
            large_gap_count=0,
            max_forward_gap=1,
        ),
        last_sequence_number=100,
    )


class APIdentityVerifierTest(unittest.TestCase):
    def test_baselines_without_alerting_on_first_stable_summary(self) -> None:
        verifier = APIdentityVerifier(min_baseline_frames=10)

        alert = verifier.update(summary(frames=10))

        self.assertFalse(alert.triggered)
        self.assertIsNotNone(verifier.baseline_for("aa:bb:cc:dd:ee:ff"))

    def test_detects_ie_clock_rssi_and_sequence_changes(self) -> None:
        verifier = APIdentityVerifier(
            min_baseline_frames=10,
            clock_skew_delta_ppm=5.0,
            rssi_shift_db=10.0,
        )
        verifier.update(summary(frames=10))

        alert = verifier.update(
            summary(
                ie_hash="ie-b",
                rssi=-25.0,
                skew_ppm=10.0,
                reset_count=1,
            )
        )

        self.assertTrue(alert.triggered)
        names = {signal.name for signal in alert.signals}
        self.assertIn("ie_fingerprint_changed", names)
        self.assertIn("clock_skew_changed", names)
        self.assertIn("rssi_shifted", names)
        self.assertIn("sequence_reset_seen", names)
        self.assertEqual(alert.score, 1.0)


if __name__ == "__main__":
    unittest.main()
