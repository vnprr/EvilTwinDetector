"""Management frame counters for deauth/disassociation signals."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from typing import Any

from scapy.layers.dot11 import Dot11, RadioTap

from wiguard.capture.frame_parser import monotonic_raw


DEAUTH_SUBTYPE = 12
DISASSOC_SUBTYPE = 10


@dataclass(frozen=True)
class ManagementFrameStats:
    frame_type: str
    bssid: str
    channel: int | None
    total: int
    broadcast_total: int
    unicast_total: int
    recent_per_second: float
    recent_broadcast_per_second: float
    recent_unicast_per_second: float
    source_macs: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ManagementFrameCounter:
    """Count deauth/disassociation frames per BSSID and channel."""

    def __init__(self, *, recent_window_seconds: float = 10.0) -> None:
        self.recent_window_seconds = recent_window_seconds
        self._totals: defaultdict[tuple[str, str, int | None], int] = defaultdict(int)
        self._broadcast_totals: defaultdict[tuple[str, str, int | None], int] = defaultdict(int)
        self._unicast_totals: defaultdict[tuple[str, str, int | None], int] = defaultdict(int)
        self._recent: defaultdict[tuple[str, str, int | None], deque[float]] = defaultdict(deque)
        self._recent_broadcast: defaultdict[tuple[str, str, int | None], deque[float]] = defaultdict(deque)
        self._recent_unicast: defaultdict[tuple[str, str, int | None], deque[float]] = defaultdict(deque)
        self._source_macs: defaultdict[tuple[str, str, int | None], Counter[str]] = defaultdict(Counter)

    def update(self, packet: Any, *, observed_monotonic: float | None = None) -> ManagementFrameStats | None:
        if not packet.haslayer(Dot11):
            return None
        dot11 = packet[Dot11]
        if getattr(dot11, "type", None) != 0:
            return None
        subtype = getattr(dot11, "subtype", None)
        if subtype == DEAUTH_SUBTYPE:
            frame_type = "deauthentication"
        elif subtype == DISASSOC_SUBTYPE:
            frame_type = "disassociation"
        else:
            return None

        timestamp = observed_monotonic if observed_monotonic is not None else monotonic_raw()
        bssid = (dot11.addr3 or dot11.addr2 or dot11.addr1 or "<unknown>").lower()
        source = (dot11.addr2 or "<unknown>").lower()
        destination = (dot11.addr1 or "<unknown>").lower()
        channel = _channel(packet)
        key = (frame_type, bssid, channel)
        self._totals[key] += 1
        self._source_macs[key][source] += 1
        recent = self._recent[key]
        recent.append(timestamp)
        self._trim(recent, timestamp)
        if _is_broadcast(destination):
            self._broadcast_totals[key] += 1
            broadcast_recent = self._recent_broadcast[key]
            broadcast_recent.append(timestamp)
            self._trim(broadcast_recent, timestamp)
        else:
            self._unicast_totals[key] += 1
            unicast_recent = self._recent_unicast[key]
            unicast_recent.append(timestamp)
            self._trim(unicast_recent, timestamp)
        return self._stats_for(key)

    def summaries(self, *, now: float | None = None) -> list[ManagementFrameStats]:
        timestamp = now if now is not None else monotonic_raw()
        summaries = []
        for key, recent in self._recent.items():
            self._trim(recent, timestamp)
            self._trim(self._recent_broadcast[key], timestamp)
            self._trim(self._recent_unicast[key], timestamp)
            summaries.append(self._stats_for(key))
        return sorted(summaries, key=lambda item: (item.frame_type, item.bssid, item.channel or -1))

    def _stats_for(self, key: tuple[str, str, int | None]) -> ManagementFrameStats:
        frame_type, bssid, channel = key
        return ManagementFrameStats(
            frame_type=frame_type,
            bssid=bssid,
            channel=channel,
            total=self._totals[key],
            broadcast_total=self._broadcast_totals[key],
            unicast_total=self._unicast_totals[key],
            recent_per_second=len(self._recent[key]) / self.recent_window_seconds,
            recent_broadcast_per_second=len(self._recent_broadcast[key]) / self.recent_window_seconds,
            recent_unicast_per_second=len(self._recent_unicast[key]) / self.recent_window_seconds,
            source_macs=tuple(sorted(self._source_macs[key])),
        )

    def _trim(self, recent: deque[float], now: float) -> None:
        threshold = now - self.recent_window_seconds
        while recent and recent[0] < threshold:
            recent.popleft()


def _channel(packet: Any) -> int | None:
    if not packet.haslayer(RadioTap):
        return None
    radiotap = packet[RadioTap]
    frequency = getattr(radiotap, "ChannelFrequency", None)
    if frequency is None:
        frequency = radiotap.fields.get("ChannelFrequency")
    if not isinstance(frequency, int):
        return None
    if 2412 <= frequency <= 2472:
        return (frequency - 2407) // 5
    if frequency == 2484:
        return 14
    if 5000 <= frequency <= 5900:
        return (frequency - 5000) // 5
    return None


def _is_broadcast(mac: str) -> bool:
    return mac.lower() == "ff:ff:ff:ff:ff:ff"
