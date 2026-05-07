from __future__ import annotations

import unittest

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

from wiguard.detection import DeauthStormDetector
from wiguard.features import ManagementFrameCounter


def deauth_packet(destination: str):
    return (
        RadioTap(ChannelFrequency=2412)
        / Dot11(
            type=0,
            subtype=12,
            addr1=destination,
            addr2="aa:bb:cc:dd:ee:ff",
            addr3="aa:bb:cc:dd:ee:ff",
        )
        / Dot11Deauth(reason=7)
    )


class DeauthStormDetectorTest(unittest.TestCase):
    def test_detects_broadcast_deauth_flood(self) -> None:
        counter = ManagementFrameCounter(recent_window_seconds=10.0)
        detector = DeauthStormDetector(
            deauth_rate_threshold=0.3,
            broadcast_rate_threshold=0.3,
            unicast_rate_threshold=99.0,
        )
        alert = None
        for index in range(4):
            stats = counter.update(
                deauth_packet("ff:ff:ff:ff:ff:ff"),
                observed_monotonic=100.0 + index,
            )
            assert stats is not None
            alert = detector.update(stats)

        assert alert is not None
        self.assertTrue(alert.triggered)
        names = {signal.name for signal in alert.signals}
        self.assertIn("management_frame_rate_high", names)
        self.assertIn("broadcast_flood", names)
        self.assertNotIn("targeted_unicast_burst", names)

    def test_detects_targeted_unicast_burst(self) -> None:
        counter = ManagementFrameCounter(recent_window_seconds=10.0)
        detector = DeauthStormDetector(
            deauth_rate_threshold=99.0,
            broadcast_rate_threshold=99.0,
            unicast_rate_threshold=0.3,
        )
        alert = None
        for index in range(4):
            stats = counter.update(
                deauth_packet("00:11:22:33:44:55"),
                observed_monotonic=200.0 + index,
            )
            assert stats is not None
            alert = detector.update(stats)

        assert alert is not None
        self.assertTrue(alert.triggered)
        self.assertEqual({signal.name for signal in alert.signals}, {"targeted_unicast_burst"})


if __name__ == "__main__":
    unittest.main()
