"""Deauthentication/disassociation storm detection.

A storm is tracked as one *episode* per BSSID: from the first frame that pushed
a rate over its threshold to the last such frame. The detector reports each
episode once, however many frames it contains, so a flood of thousands of
frames becomes one piece of evidence rather than thousands of alerts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wiguard.features import DisruptionStats

from .events import DetectionEvent, Module, Severity, Signal

EPISODE_GAP_SECONDS = 60.0
"""A quiet period this long ends an episode; later storm frames start a new one."""


@dataclass
class _Episode:
    bssid: str
    first_seen: float
    last_seen: float
    signals: dict[str, Signal] = field(default_factory=dict)
    peak_rate_per_s: float = 0.0
    frames: int = 0
    channels: set[int] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)


class DeauthStormDetector:
    def __init__(
        self,
        *,
        deauth_rate_threshold: float = 10.0,
        disassoc_rate_threshold: float = 5.0,
        broadcast_rate_threshold: float = 5.0,
        unicast_rate_threshold: float = 5.0,
    ) -> None:
        self.rate_thresholds = {
            "deauthentication": deauth_rate_threshold,
            "disassociation": disassoc_rate_threshold,
        }
        self.broadcast_rate_threshold = broadcast_rate_threshold
        self.unicast_rate_threshold = unicast_rate_threshold
        self._episodes: dict[str, _Episode] = {}

    def add(self, stats: DisruptionStats) -> None:
        """Feed the current sliding-window stats after each disruption frame."""

        signals = self._signals(stats)
        if not signals:
            return
        episode = self._episodes.get(stats.bssid)
        if episode is None or stats.last_seen - episode.last_seen > EPISODE_GAP_SECONDS:
            episode = _Episode(stats.bssid, first_seen=stats.last_seen, last_seen=stats.last_seen)
            self._episodes[stats.bssid] = episode
        episode.last_seen = stats.last_seen
        episode.frames += 1
        episode.peak_rate_per_s = max(episode.peak_rate_per_s, stats.rate_per_s)
        episode.channels.update(stats.channels)
        episode.sources.update(stats.sources)
        for signal in signals:
            # Keep the strongest observation of each signal for the evidence.
            previous = episode.signals.get(signal.name)
            if previous is None or _rate(signal) >= _rate(previous):
                episode.signals[signal.name] = signal

    def evaluate(self) -> list[DetectionEvent]:
        """One event per BSSID: its most recent storm episode."""

        events = []
        for bssid, episode in sorted(self._episodes.items()):
            events.append(
                DetectionEvent(
                    module=Module.DEAUTH,
                    bssid=bssid,
                    ssid="",
                    signals=tuple(episode.signals.values()),
                    last_seen=episode.last_seen,
                    context={
                        "first_seen": episode.first_seen,
                        "duration_s": round(episode.last_seen - episode.first_seen, 3),
                        "storm_frames": episode.frames,
                        "peak_rate_per_s": round(episode.peak_rate_per_s, 3),
                        "channels": sorted(episode.channels),
                        "sources": sorted(episode.sources),
                    },
                )
            )
        return events

    def _signals(self, stats: DisruptionStats) -> list[Signal]:
        signals = []
        threshold = self.rate_thresholds[stats.kind]
        if stats.rate_per_s >= threshold:
            signals.append(
                Signal(
                    name="management_frame_rate_high",
                    severity=Severity.HIGH,
                    message=f"{stats.kind.capitalize()} frame rate exceeds the threshold",
                    details={
                        "kind": stats.kind,
                        "rate_per_s": round(stats.rate_per_s, 3),
                        "threshold_per_s": threshold,
                    },
                )
            )
        if stats.broadcast_rate_per_s >= self.broadcast_rate_threshold:
            signals.append(
                Signal(
                    name="broadcast_flood",
                    severity=Severity.HIGH,
                    message="Clients are being disconnected with broadcast frames",
                    details={
                        "kind": stats.kind,
                        "rate_per_s": round(stats.broadcast_rate_per_s, 3),
                        "threshold_per_s": self.broadcast_rate_threshold,
                    },
                )
            )
        if stats.unicast_rate_per_s >= self.unicast_rate_threshold:
            signals.append(
                Signal(
                    name="targeted_unicast_burst",
                    severity=Severity.MEDIUM,
                    message="Individual clients are being disconnected in a burst",
                    details={
                        "kind": stats.kind,
                        "rate_per_s": round(stats.unicast_rate_per_s, 3),
                        "threshold_per_s": self.unicast_rate_threshold,
                    },
                )
            )
        return signals


def _rate(signal: Signal) -> float:
    value = signal.details.get("rate_per_s", 0.0)
    return float(value) if isinstance(value, int | float) else 0.0
