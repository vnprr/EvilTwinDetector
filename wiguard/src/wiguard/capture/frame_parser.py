"""Parse Scapy 802.11 packets into WiGuard observations."""

from __future__ import annotations

import time
from typing import Any

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap

from .models import AccessPointObservation


def monotonic_raw() -> float:
    clock_id = getattr(time, "CLOCK_MONOTONIC_RAW", None)
    if clock_id is None:
        return time.monotonic()
    return time.clock_gettime(clock_id)


def parse_ap_observation(packet: Any, *, observed_monotonic: float | None = None) -> AccessPointObservation | None:
    """Return a normalized AP observation for beacon/probe-response frames."""

    if not packet.haslayer(RadioTap) or not packet.haslayer(Dot11):
        return None

    if packet.haslayer(Dot11Beacon):
        frame_layer = packet[Dot11Beacon]
        frame_type = "beacon"
    elif packet.haslayer(Dot11ProbeResp):
        frame_layer = packet[Dot11ProbeResp]
        frame_type = "probe_response"
    else:
        return None

    dot11 = packet[Dot11]
    bssid = dot11.addr3 or dot11.addr2
    if not bssid:
        return None

    return AccessPointObservation(
        frame_type=frame_type,
        observed_monotonic=observed_monotonic if observed_monotonic is not None else monotonic_raw(),
        ssid=_decode_ssid(_dot11_elt_info(packet, 0)),
        bssid=bssid.lower(),
        channel=_decode_channel(_dot11_elt_info(packet, 3)) or _channel_from_radiotap(packet),
        rssi_dbm=_rssi(packet),
        ap_tsf=getattr(frame_layer, "timestamp", None),
        radiotap_tsf=_radiotap_tsf(packet),
        sequence_number=_sequence_number(dot11),
        beacon_interval_tu=getattr(frame_layer, "beacon_interval", None),
        capabilities=getattr(frame_layer, "cap", None),
    )


def _dot11_elt_info(packet: Any, elt_id: int) -> bytes | None:
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == elt_id:
            return bytes(getattr(elt, "info", b""))
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def _decode_ssid(raw: bytes | None) -> str:
    if not raw:
        return "<hidden>"
    return raw.decode("utf-8", errors="replace")


def _decode_channel(raw: bytes | None) -> int | None:
    if not raw:
        return None
    return raw[0]


def _rssi(packet: Any) -> int | None:
    radiotap = packet[RadioTap]
    value = getattr(radiotap, "dBm_AntSignal", None)
    if value is None:
        value = radiotap.fields.get("dBm_AntSignal")
    return value if isinstance(value, int) else None


def _radiotap_tsf(packet: Any) -> int | None:
    fields = packet[RadioTap].fields
    for key in ("mac_timestamp", "timestamp", "TSFT"):
        value = fields.get(key)
        if isinstance(value, int):
            return value
    return None


def _sequence_number(dot11: Dot11) -> int | None:
    sequence_control = getattr(dot11, "SC", None)
    if sequence_control is None:
        return None
    return int(sequence_control) >> 4


def _channel_from_radiotap(packet: Any) -> int | None:
    frequency = getattr(packet[RadioTap], "ChannelFrequency", None)
    if not isinstance(frequency, int):
        return None
    if 2412 <= frequency <= 2472:
        return (frequency - 2407) // 5
    if frequency == 2484:
        return 14
    if 5000 <= frequency <= 5900:
        return (frequency - 5000) // 5
    return None
