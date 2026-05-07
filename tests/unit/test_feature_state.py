from __future__ import annotations

import unittest

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from wiguard.features import APFeatureStateManager, FeatureExtractor


def feature_packet(index: int):
    local_tsf = 1_000_000 + index * 100_000
    return (
        RadioTap(dBm_AntSignal=-40 - index, mac_timestamp=local_tsf)
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="aa:bb:cc:dd:ee:ff",
            addr3="aa:bb:cc:dd:ee:ff",
            SC=index << 4,
        )
        / Dot11Beacon(timestamp=local_tsf, beacon_interval=100, cap=0x0411)
        / Dot11Elt(ID=0, info=b"FeatureNet")
        / Dot11Elt(ID=1, info=b"\x82\x84")
        / Dot11Elt(ID=221, info=bytes.fromhex("aabbcc0102"))
    )


class FeatureStateTest(unittest.TestCase):
    def test_summarizes_ie_hash_and_clock_estimate(self) -> None:
        extractor = FeatureExtractor()
        manager = APFeatureStateManager(min_clock_samples=3)
        for index in range(3):
            vector = extractor.extract(feature_packet(index), observed_monotonic=1.0 + float(index) / 10.0)
            assert vector is not None
            manager.update(vector)

        summary = manager.summaries()[0]

        self.assertEqual(summary.ssid, "FeatureNet")
        self.assertEqual(summary.vendor_ouis, ("aa:bb:cc",))
        self.assertEqual(len(summary.ie_fingerprint_hashes), 1)
        self.assertIn(1, summary.stable_ie_ids_union)
        self.assertIn(221, summary.key_ie_ids_union)
        self.assertEqual(summary.sequence_analysis.samples, 3)
        self.assertEqual(summary.beacon_timing.samples, 2)
        self.assertIsNotNone(summary.clock_estimate)
        assert summary.clock_estimate is not None
        self.assertGreater(summary.clock_estimate.r_squared, 0.999)


if __name__ == "__main__":
    unittest.main()
