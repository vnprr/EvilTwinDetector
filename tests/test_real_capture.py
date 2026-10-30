"""Sanity checks on a real monitor-mode capture (skipped unless one is provided).

WIGUARD_REAL_PCAP=/path/to/capture.pcap pytest tests/test_real_capture.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from wiguard.analysis import analyze_pcap

PCAP = Path(os.environ.get("WIGUARD_REAL_PCAP", "/tmp/wiguard_alfa_beacons.pcap"))

pytestmark = pytest.mark.skipif(not PCAP.is_file(), reason="no real capture available")


def test_real_capture_yields_complete_ap_profiles(config) -> None:
    result = analyze_pcap(PCAP, config, trusted_profiles=[])
    assert result.frames.beacons > 0
    assert result.access_points
    for ap in result.access_points:
        assert ap.dominant_ie_fingerprint is not None
        assert ap.last_rssi_dbm is not None
        assert ap.channels
