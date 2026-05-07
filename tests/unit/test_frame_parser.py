from __future__ import annotations

import unittest

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from wiguard.capture.frame_parser import parse_ap_observation


class FrameParserTest(unittest.TestCase):
    def test_parses_beacon_observation(self) -> None:
        packet = (
            RadioTap(dBm_AntSignal=-42, mac_timestamp=123456)
            / Dot11(
                type=0,
                subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="aa:bb:cc:dd:ee:ff",
                addr3="aa:bb:cc:dd:ee:ff",
                SC=0x1230,
            )
            / Dot11Beacon(timestamp=987654321, beacon_interval=100, cap=0x0411)
            / Dot11Elt(ID=0, info=b"TestNet")
            / Dot11Elt(ID=3, info=bytes([6]))
        )

        observation = parse_ap_observation(packet, observed_monotonic=42.0)

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(observation.frame_type, "beacon")
        self.assertEqual(observation.ssid, "TestNet")
        self.assertEqual(observation.bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(observation.channel, 6)
        self.assertEqual(observation.rssi_dbm, -42)
        self.assertEqual(observation.ap_tsf, 987654321)
        self.assertEqual(observation.radiotap_tsf, 123456)
        self.assertEqual(observation.sequence_number, 0x123)
        self.assertTrue(observation.has_clock_inputs)


if __name__ == "__main__":
    unittest.main()
