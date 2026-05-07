from __future__ import annotations

import unittest

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from wiguard.features import FeatureExtractor, build_ie_fingerprint


def beacon_with_tim(tim_value: bytes):
    return (
        RadioTap(dBm_AntSignal=-40, mac_timestamp=1000)
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="aa:bb:cc:dd:ee:ff",
            addr3="aa:bb:cc:dd:ee:ff",
            SC=0x2000,
        )
        / Dot11Beacon(timestamp=123456, beacon_interval=100, cap=0x0411)
        / Dot11Elt(ID=0, info=b"StableNet")
        / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
        / Dot11Elt(ID=5, info=tim_value)
        / Dot11Elt(ID=48, info=b"\x01\x00\x00\x0f\xac\x04")
        / Dot11Elt(ID=221, info=bytes.fromhex("001122010203"))
    )


class IEFingerprintTest(unittest.TestCase):
    def test_dynamic_tim_does_not_change_hash(self) -> None:
        first = build_ie_fingerprint(beacon_with_tim(b"\x00\x01"))
        second = build_ie_fingerprint(beacon_with_tim(b"\x99\x88\x77"))

        self.assertNotEqual(first.sequence_signature, first.stable_sequence_signature)
        self.assertEqual(first.hash, second.hash)
        self.assertEqual(first.vendor_ouis, ("00:11:22",))

    def test_feature_extractor_adds_ie_fingerprint(self) -> None:
        vector = FeatureExtractor().extract(beacon_with_tim(b"\x00\x01"), observed_monotonic=1.0)

        self.assertIsNotNone(vector)
        assert vector is not None
        self.assertEqual(vector.bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(vector.ie_fingerprint.vendor_ouis, ("00:11:22",))
        self.assertTrue(vector.ie_fingerprint.hash)


if __name__ == "__main__":
    unittest.main()
