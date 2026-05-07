from __future__ import annotations

import unittest

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, RadioTap

from wiguard.features import ManagementFrameCounter


class ManagementFrameCounterTest(unittest.TestCase):
    def test_counts_deauth_and_disassociation_frames(self) -> None:
        counter = ManagementFrameCounter(recent_window_seconds=10.0)
        deauth = (
            RadioTap(ChannelFrequency=2412)
            / Dot11(
                type=0,
                subtype=12,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="aa:bb:cc:dd:ee:ff",
                addr3="aa:bb:cc:dd:ee:ff",
            )
            / Dot11Deauth(reason=7)
        )
        disassoc = (
            RadioTap(ChannelFrequency=2412)
            / Dot11(
                type=0,
                subtype=10,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="aa:bb:cc:dd:ee:ff",
                addr3="aa:bb:cc:dd:ee:ff",
            )
            / Dot11Disas(reason=8)
        )

        deauth_stats = counter.update(deauth, observed_monotonic=100.0)
        counter.update(deauth, observed_monotonic=101.0)
        disassoc_stats = counter.update(disassoc, observed_monotonic=101.0)

        self.assertIsNotNone(deauth_stats)
        self.assertEqual(deauth_stats.bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(deauth_stats.channel, 1)
        self.assertEqual(deauth_stats.broadcast_total, 1)
        self.assertEqual(deauth_stats.unicast_total, 0)
        self.assertEqual(deauth_stats.source_macs, ("aa:bb:cc:dd:ee:ff",))
        self.assertIsNotNone(disassoc_stats)
        summaries = counter.summaries(now=102.0)
        totals = {(item.frame_type, item.total) for item in summaries}
        self.assertIn(("deauthentication", 2), totals)
        self.assertIn(("disassociation", 1), totals)


if __name__ == "__main__":
    unittest.main()
