"""Sliding-window rates of deauthentication/disassociation frames per BSSID.

Both frame types end a client's connection. A burst of them is how an attacker
pushes clients off the real AP so that they reconnect to a twin. Without
Protected Management Frames (802.11w) such frames are trivially forged.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field

from .frames import DisruptionFrame


@dataclass(frozen=True, slots=True)
class DisruptionStats:
    """Totals and current sliding-window rates for one (kind, BSSID) stream."""

    kind: str
    bssid: str
    channels: tuple[int, ...]
    first_seen: float
    last_seen: float
    total: int
    broadcast_total: int
    rate_per_s: float
    broadcast_rate_per_s: float
    unicast_rate_per_s: float
    sources: tuple[str, ...]
    reasons: tuple[int, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "bssid": self.bssid,
            "channels": list(self.channels),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total": self.total,
            "broadcast_total": self.broadcast_total,
            "rate_per_s": round(self.rate_per_s, 3),
            "broadcast_rate_per_s": round(self.broadcast_rate_per_s, 3),
            "unicast_rate_per_s": round(self.unicast_rate_per_s, 3),
            "sources": list(self.sources),
            "reasons": list(self.reasons),
        }


@dataclass
class _Stream:
    first_seen: float
    last_seen: float = 0.0
    total: int = 0
    broadcast_total: int = 0
    recent: deque[tuple[float, bool]] = field(default_factory=deque)
    recent_broadcast: int = 0
    channels: set[int] = field(default_factory=set)
    sources: Counter[str] = field(default_factory=Counter)
    reasons: set[int] = field(default_factory=set)


class DisruptionCounter:
    """Count deauthentication/disassociation frames in a sliding time window."""

    def __init__(self, *, window_seconds: float = 10.0) -> None:
        self.window_seconds = window_seconds
        self._streams: dict[tuple[str, str], _Stream] = {}

    def add(self, frame: DisruptionFrame) -> DisruptionStats:
        key = (frame.kind, frame.bssid)
        stream = self._streams.setdefault(key, _Stream(first_seen=frame.timestamp))
        stream.last_seen = frame.timestamp
        stream.total += 1
        stream.broadcast_total += frame.is_broadcast
        stream.recent.append((frame.timestamp, frame.is_broadcast))
        stream.recent_broadcast += frame.is_broadcast
        stream.sources[frame.source] += 1
        if frame.channel is not None:
            stream.channels.add(frame.channel)
        if frame.reason is not None:
            stream.reasons.add(frame.reason)
        return self._stats(key, stream, now=frame.timestamp)

    def summaries(self, *, now: float | None = None) -> list[DisruptionStats]:
        """Current stats per stream; ``now`` defaults to each stream's last frame."""
        return [
            self._stats(key, stream, now=stream.last_seen if now is None else now)
            for key, stream in sorted(self._streams.items())
        ]

    def _stats(self, key: tuple[str, str], stream: _Stream, *, now: float) -> DisruptionStats:
        cutoff = now - self.window_seconds
        while stream.recent and stream.recent[0][0] < cutoff:
            _, was_broadcast = stream.recent.popleft()
            stream.recent_broadcast -= was_broadcast
        broadcast = stream.recent_broadcast
        unicast = len(stream.recent) - broadcast
        kind, bssid = key
        return DisruptionStats(
            kind=kind,
            bssid=bssid,
            channels=tuple(sorted(stream.channels)),
            first_seen=stream.first_seen,
            last_seen=stream.last_seen,
            total=stream.total,
            broadcast_total=stream.broadcast_total,
            rate_per_s=len(stream.recent) / self.window_seconds,
            broadcast_rate_per_s=broadcast / self.window_seconds,
            unicast_rate_per_s=unicast / self.window_seconds,
            sources=tuple(sorted(stream.sources)),
            reasons=tuple(sorted(stream.reasons)),
        )
