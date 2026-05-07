"""Feature extraction from raw Scapy packets."""

from __future__ import annotations

from typing import Any

from wiguard.capture.frame_parser import parse_ap_observation

from .ie_fingerprint import build_ie_fingerprint
from .models import APFeatureVector


class FeatureExtractor:
    """Convert beacon/probe-response frames into AP feature vectors."""

    def extract(self, packet: Any, *, observed_monotonic: float | None = None) -> APFeatureVector | None:
        observation = parse_ap_observation(packet, observed_monotonic=observed_monotonic)
        if observation is None:
            return None
        return APFeatureVector(
            frame_type=observation.frame_type,
            observed_monotonic=observation.observed_monotonic,
            ssid=observation.ssid,
            bssid=observation.bssid,
            channel=observation.channel,
            rssi_dbm=observation.rssi_dbm,
            ap_tsf=observation.ap_tsf,
            radiotap_tsf=observation.radiotap_tsf,
            sequence_number=observation.sequence_number,
            beacon_interval_tu=observation.beacon_interval_tu,
            capabilities=observation.capabilities,
            ie_fingerprint=build_ie_fingerprint(packet),
        )
