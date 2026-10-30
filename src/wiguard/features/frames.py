"""Turn captured 802.11 packets into the two frame records WiGuard analyses.

Every packet is parsed exactly once, here. Live capture and offline pcap
analysis go through the same function, and both use the packet's capture
timestamp (``packet.time``, set by libpcap/the kernel) as the local clock, so a
recorded capture replays exactly as it was seen live.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11ProbeResp,
    RadioTap,
)

from .ie import IEFingerprint, InformationElement, build_ie_fingerprint

BROADCAST = "ff:ff:ff:ff:ff:ff"
_SSID_ID = 0
_DS_PARAMETER_SET_ID = 3
_HT_OPERATION_ID = 61


@dataclass(frozen=True, slots=True)
class BeaconFrame:
    """A beacon or probe response: the AP describing itself."""

    timestamp: float
    """Capture time in seconds (local reference clock)."""
    kind: Literal["beacon", "probe_response"]
    bssid: str
    ssid: str
    """Advertised network name; empty for a hidden SSID."""
    channel: int | None
    rssi_dbm: int | None
    ap_tsf_us: int | None
    """The AP's own TSF timer from the frame body, in microseconds."""
    sequence_number: int | None
    beacon_interval_tu: int | None
    ie: IEFingerprint


@dataclass(frozen=True, slots=True)
class DisruptionFrame:
    """A deauthentication or disassociation frame."""

    timestamp: float
    kind: Literal["deauthentication", "disassociation"]
    bssid: str
    source: str
    destination: str
    channel: int | None
    reason: int | None

    @property
    def is_broadcast(self) -> bool:
        return self.destination == BROADCAST


Frame = BeaconFrame | DisruptionFrame


def parse_frame(packet: Any) -> Frame | None:
    """Return the frame record for a packet, or ``None`` if WiGuard ignores it."""

    if not packet.haslayer(Dot11):
        return None
    dot11 = packet[Dot11]
    timestamp = float(getattr(packet, "time", 0.0) or 0.0)

    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        return _beacon_frame(packet, dot11, timestamp)
    if packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas):
        return _disruption_frame(packet, dot11, timestamp)
    return None


def frequency_to_channel(frequency_mhz: int) -> int | None:
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if frequency_mhz == 2484:
        return 14
    if 5000 <= frequency_mhz <= 5900:
        return (frequency_mhz - 5000) // 5
    return None


def _beacon_frame(packet: Any, dot11: Any, timestamp: float) -> BeaconFrame | None:
    bssid = _mac(dot11.addr3) or _mac(dot11.addr2)
    if bssid is None:
        return None
    is_beacon = packet.haslayer(Dot11Beacon)
    body = packet[Dot11Beacon] if is_beacon else packet[Dot11ProbeResp]
    elements = _information_elements(bytes(body.payload))
    by_id = {element.id: element.body for element in reversed(elements)}
    return BeaconFrame(
        timestamp=timestamp,
        kind="beacon" if is_beacon else "probe_response",
        bssid=bssid,
        ssid=_decode_ssid(by_id.get(_SSID_ID, b"")),
        channel=_advertised_channel(by_id) or _radiotap_channel(packet),
        rssi_dbm=_rssi(packet),
        ap_tsf_us=_int_or_none(getattr(body, "timestamp", None)),
        sequence_number=_sequence_number(dot11),
        beacon_interval_tu=_int_or_none(getattr(body, "beacon_interval", None)),
        ie=build_ie_fingerprint(elements),
    )


def _disruption_frame(packet: Any, dot11: Any, timestamp: float) -> DisruptionFrame:
    is_deauth = packet.haslayer(Dot11Deauth)
    body = packet[Dot11Deauth] if is_deauth else packet[Dot11Disas]
    unknown = "00:00:00:00:00:00"
    return DisruptionFrame(
        timestamp=timestamp,
        kind="deauthentication" if is_deauth else "disassociation",
        bssid=_mac(dot11.addr3) or _mac(dot11.addr2) or unknown,
        source=_mac(dot11.addr2) or unknown,
        destination=_mac(dot11.addr1) or unknown,
        channel=_radiotap_channel(packet),
        reason=_int_or_none(getattr(body, "reason", None)),
    )


def _information_elements(raw: bytes) -> tuple[InformationElement, ...]:
    """Split the IE area into (id, length, body) records.

    Parsed from raw bytes rather than from Scapy's per-element classes: those
    stop at the first element they cannot dissect (vendor extensions often
    are), which would silently drop the rest of the fingerprint. A truncated
    last element is ignored.
    """

    elements = []
    offset = 0
    while offset + 2 <= len(raw):
        element_id, length = raw[offset], raw[offset + 1]
        body = raw[offset + 2 : offset + 2 + length]
        if len(body) < length:
            break
        elements.append(InformationElement(id=element_id, body=body))
        offset += 2 + length
    return tuple(elements)


def _decode_ssid(raw: bytes) -> str:
    # Hidden networks send an empty or all-zero SSID.
    if not raw.strip(b"\x00"):
        return ""
    return raw.decode("utf-8", errors="replace")


def _advertised_channel(by_id: dict[int, bytes]) -> int | None:
    """Channel the AP announces (DS Parameter Set on 2.4 GHz, HT Operation on 5 GHz)."""
    for element_id in (_DS_PARAMETER_SET_ID, _HT_OPERATION_ID):
        body = by_id.get(element_id)
        if body:
            return body[0]
    return None


def _radiotap_channel(packet: Any) -> int | None:
    if not packet.haslayer(RadioTap):
        return None
    frequency = getattr(packet[RadioTap], "ChannelFrequency", None)
    return frequency_to_channel(frequency) if isinstance(frequency, int) else None


def _rssi(packet: Any) -> int | None:
    if not packet.haslayer(RadioTap):
        return None
    value = getattr(packet[RadioTap], "dBm_AntSignal", None)
    return value if isinstance(value, int) else None


def _sequence_number(dot11: Any) -> int | None:
    sequence_control = getattr(dot11, "SC", None)
    return None if sequence_control is None else int(sequence_control) >> 4


def _mac(value: object) -> str | None:
    return value.lower() if isinstance(value, str) and value else None


def _int_or_none(value: object) -> int | None:
    return int(value) if isinstance(value, int) else None
