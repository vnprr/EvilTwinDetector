"""Deauthentication/disassociation storm detection."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from wiguard.features import ManagementFrameStats


@dataclass(frozen=True)
class DeauthStormSignal:
    name: str
    severity: str
    message: str
    details: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DeauthStormAlert:
    bssid: str
    channel: int | None
    frame_type: str
    score: float
    signals: tuple[DeauthStormSignal, ...]

    @property
    def triggered(self) -> bool:
        return bool(self.signals)

    def to_dict(self) -> dict[str, object]:
        return {
            "module": "deauth_storm",
            "bssid": self.bssid,
            "channel": self.channel,
            "frame_type": self.frame_type,
            "score": self.score,
            "signals": [signal.to_dict() for signal in self.signals],
        }


class DeauthStormDetector:
    """Detect anomalous management-frame bursts."""

    def __init__(
        self,
        *,
        deauth_rate_threshold: float = 10.0,
        disassoc_rate_threshold: float = 5.0,
        broadcast_rate_threshold: float = 5.0,
        unicast_rate_threshold: float = 5.0,
    ) -> None:
        self.deauth_rate_threshold = deauth_rate_threshold
        self.disassoc_rate_threshold = disassoc_rate_threshold
        self.broadcast_rate_threshold = broadcast_rate_threshold
        self.unicast_rate_threshold = unicast_rate_threshold

    def update(self, stats: ManagementFrameStats) -> DeauthStormAlert:
        signals = tuple(self._signals(stats))
        score = min(1.0, sum(_signal_weight(signal) for signal in signals))
        return DeauthStormAlert(
            bssid=stats.bssid,
            channel=stats.channel,
            frame_type=stats.frame_type,
            score=round(score, 3),
            signals=signals,
        )

    def _signals(self, stats: ManagementFrameStats) -> list[DeauthStormSignal]:
        signals: list[DeauthStormSignal] = []
        frame_threshold = (
            self.deauth_rate_threshold
            if stats.frame_type == "deauthentication"
            else self.disassoc_rate_threshold
        )
        if stats.recent_per_second >= frame_threshold:
            signals.append(
                DeauthStormSignal(
                    name="management_frame_rate_high",
                    severity="high",
                    message=f"{stats.frame_type} frame rate exceeds threshold",
                    details={
                        "rate_per_second": round(stats.recent_per_second, 3),
                        "threshold_per_second": frame_threshold,
                        "total": stats.total,
                        "source_macs": stats.source_macs,
                    },
                )
            )
        if stats.recent_broadcast_per_second >= self.broadcast_rate_threshold:
            signals.append(
                DeauthStormSignal(
                    name="broadcast_flood",
                    severity="high",
                    message="Broadcast management-frame flood observed",
                    details={
                        "broadcast_rate_per_second": round(stats.recent_broadcast_per_second, 3),
                        "threshold_per_second": self.broadcast_rate_threshold,
                        "broadcast_total": stats.broadcast_total,
                    },
                )
            )
        if stats.recent_unicast_per_second >= self.unicast_rate_threshold:
            signals.append(
                DeauthStormSignal(
                    name="targeted_unicast_burst",
                    severity="medium",
                    message="Targeted unicast management-frame burst observed",
                    details={
                        "unicast_rate_per_second": round(stats.recent_unicast_per_second, 3),
                        "threshold_per_second": self.unicast_rate_threshold,
                        "unicast_total": stats.unicast_total,
                    },
                )
            )
        return signals


def _signal_weight(signal: DeauthStormSignal) -> float:
    if signal.severity == "high":
        return 0.45
    if signal.severity == "medium":
        return 0.25
    return 0.1
