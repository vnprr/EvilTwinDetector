"""AP Identity Verification detection module."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from wiguard.features import APFeatureSummary


@dataclass(frozen=True)
class IdentitySignal:
    name: str
    severity: str
    message: str
    details: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class IdentityAlert:
    bssid: str
    ssid: str
    score: float
    signals: tuple[IdentitySignal, ...]

    @property
    def triggered(self) -> bool:
        return bool(self.signals)

    def to_dict(self) -> dict[str, object]:
        return {
            "module": "identity_verification",
            "bssid": self.bssid,
            "ssid": self.ssid,
            "score": self.score,
            "signals": [signal.to_dict() for signal in self.signals],
        }


@dataclass(frozen=True)
class IdentityBaseline:
    bssid: str
    ssid: str
    frames: int
    dominant_ie_fingerprint: str | None
    avg_rssi_dbm: float | None
    rssi_stddev: float | None
    clock_skew_ppm: float | None
    sequence_reset_count: int

    @classmethod
    def from_summary(cls, summary: APFeatureSummary) -> "IdentityBaseline":
        return cls(
            bssid=summary.bssid.lower(),
            ssid=summary.ssid,
            frames=summary.frames,
            dominant_ie_fingerprint=summary.dominant_ie_fingerprint,
            avg_rssi_dbm=summary.avg_rssi_dbm,
            rssi_stddev=summary.rssi_stddev,
            clock_skew_ppm=(
                summary.clock_estimate.skew_ppm if summary.clock_estimate is not None else None
            ),
            sequence_reset_count=summary.sequence_analysis.reset_count,
        )

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "IdentityBaseline":
        return cls(
            bssid=str(payload["bssid"]).lower(),
            ssid=str(payload["ssid"]),
            frames=int(payload.get("frames", 0)),
            dominant_ie_fingerprint=_optional_str(payload.get("dominant_ie_fingerprint")),
            avg_rssi_dbm=_optional_float(payload.get("avg_rssi_dbm")),
            rssi_stddev=_optional_float(payload.get("rssi_stddev")),
            clock_skew_ppm=_optional_float(payload.get("clock_skew_ppm")),
            sequence_reset_count=int(payload.get("sequence_reset_count", 0)),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class APIdentityVerifier:
    """Compare AP feature summaries against a per-BSSID baseline."""

    def __init__(
        self,
        *,
        min_baseline_frames: int = 50,
        clock_skew_delta_ppm: float = 5.0,
        rssi_shift_db: float = 12.0,
        baselines: Iterable[IdentityBaseline] | None = None,
        auto_baseline: bool = True,
    ) -> None:
        self.min_baseline_frames = min_baseline_frames
        self.clock_skew_delta_ppm = clock_skew_delta_ppm
        self.rssi_shift_db = rssi_shift_db
        self.auto_baseline = auto_baseline
        self._baselines: dict[str, IdentityBaseline] = {}
        for baseline in baselines or ():
            self._baselines[baseline.bssid.lower()] = baseline

    def update(self, summary: APFeatureSummary) -> IdentityAlert:
        bssid = summary.bssid.lower()
        baseline = self._baselines.get(bssid)
        if baseline is None:
            if self.auto_baseline and summary.frames >= self.min_baseline_frames:
                self._baselines[bssid] = IdentityBaseline.from_summary(summary)
            return IdentityAlert(bssid=summary.bssid, ssid=summary.ssid, score=0.0, signals=())

        signals = tuple(self._signals(baseline, summary))
        score = min(1.0, sum(_signal_weight(signal) for signal in signals))
        return IdentityAlert(
            bssid=summary.bssid,
            ssid=summary.ssid,
            score=round(score, 3),
            signals=signals,
        )

    def force_baseline(self, summary: APFeatureSummary) -> IdentityBaseline:
        baseline = IdentityBaseline.from_summary(summary)
        self._baselines[summary.bssid.lower()] = baseline
        return baseline

    def baseline_for(self, bssid: str) -> IdentityBaseline | None:
        return self._baselines.get(bssid.lower())

    def baselines(self) -> tuple[IdentityBaseline, ...]:
        return tuple(sorted(self._baselines.values(), key=lambda baseline: baseline.bssid))

    def _signals(
        self,
        baseline: IdentityBaseline,
        summary: APFeatureSummary,
    ) -> list[IdentitySignal]:
        signals: list[IdentitySignal] = []
        if (
            baseline.dominant_ie_fingerprint is not None
            and summary.dominant_ie_fingerprint is not None
            and baseline.dominant_ie_fingerprint != summary.dominant_ie_fingerprint
        ):
            signals.append(
                IdentitySignal(
                    name="ie_fingerprint_changed",
                    severity="high",
                    message="IE fingerprint changed for an existing BSSID",
                    details={
                        "baseline": baseline.dominant_ie_fingerprint,
                        "current": summary.dominant_ie_fingerprint,
                    },
                )
            )

        if baseline.clock_skew_ppm is not None and summary.clock_estimate is not None:
            delta_ppm = summary.clock_estimate.skew_ppm - baseline.clock_skew_ppm
            if abs(delta_ppm) >= self.clock_skew_delta_ppm:
                signals.append(
                    IdentitySignal(
                        name="clock_skew_changed",
                        severity="high",
                        message="Clock skew changed beyond threshold for an existing BSSID",
                        details={
                            "baseline_ppm": round(baseline.clock_skew_ppm, 3),
                            "current_ppm": round(summary.clock_estimate.skew_ppm, 3),
                            "delta_ppm": round(delta_ppm, 3),
                            "threshold_ppm": self.clock_skew_delta_ppm,
                        },
                    )
                )

        if baseline.avg_rssi_dbm is not None and summary.avg_rssi_dbm is not None:
            delta_db = summary.avg_rssi_dbm - baseline.avg_rssi_dbm
            tolerance = max(self.rssi_shift_db, (baseline.rssi_stddev or 0.0) * 4.0)
            if abs(delta_db) >= tolerance:
                signals.append(
                    IdentitySignal(
                        name="rssi_shifted",
                        severity="medium",
                        message="RSSI profile shifted strongly for an existing BSSID",
                        details={
                            "baseline_dbm": baseline.avg_rssi_dbm,
                            "current_dbm": summary.avg_rssi_dbm,
                            "delta_db": round(delta_db, 2),
                            "threshold_db": round(tolerance, 2),
                        },
                    )
                )

        reset_delta = summary.sequence_analysis.reset_count - baseline.sequence_reset_count
        if reset_delta > 0:
            signals.append(
                IdentitySignal(
                    name="sequence_reset_seen",
                    severity="medium",
                    message="Sequence-number reset/backward jump increased for an existing BSSID",
                    details={
                        "baseline_reset_count": baseline.sequence_reset_count,
                        "current_reset_count": summary.sequence_analysis.reset_count,
                        "delta": reset_delta,
                    },
                )
            )
        return signals


def _signal_weight(signal: IdentitySignal) -> float:
    if signal.severity == "high":
        return 0.45
    if signal.severity == "medium":
        return 0.25
    return 0.1


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    return float(value)


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)
