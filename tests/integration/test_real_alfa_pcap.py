from __future__ import annotations

from pathlib import Path
import unittest

from scapy.all import rdpcap

from wiguard.capture.frame_parser import parse_ap_observation
from wiguard.features import FeatureExtractor


PCAP = Path("/tmp/wiguard_alfa_beacons.pcap")


@unittest.skipUnless(PCAP.exists(), "real Alfa pcap fixture not present")
class RealAlfaPcapTest(unittest.TestCase):
    def test_real_capture_contains_tsf_ready_beacons(self) -> None:
        packets = rdpcap(str(PCAP))
        observations = [
            observation
            for packet in packets
            if (observation := parse_ap_observation(packet, observed_monotonic=1.0)) is not None
        ]

        self.assertGreaterEqual(len(observations), 1)
        self.assertTrue(all(observation.ap_tsf is not None for observation in observations))
        self.assertTrue(all(observation.radiotap_tsf is not None for observation in observations))
        self.assertTrue(any(observation.rssi_dbm is not None for observation in observations))

    def test_real_capture_produces_feature_vectors(self) -> None:
        extractor = FeatureExtractor()
        packets = rdpcap(str(PCAP))
        vectors = [
            vector
            for packet in packets
            if (vector := extractor.extract(packet, observed_monotonic=1.0)) is not None
        ]

        self.assertGreaterEqual(len(vectors), 1)
        self.assertTrue(all(vector.ie_fingerprint.hash for vector in vectors))
        self.assertTrue(any(vector.ie_fingerprint.stable_sequence_signature for vector in vectors))


if __name__ == "__main__":
    unittest.main()
