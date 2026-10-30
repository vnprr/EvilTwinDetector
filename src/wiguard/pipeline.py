"""The detection pipeline: packets in, explained alerts out.

One class wires feature extraction, the four detectors and correlation
together. Live scanning, the long-running sensor, offline pcap analysis and the
evaluation harness all use it, so every mode detects exactly the same things.

    packet ─► parse_frame ─► AP profiles ──────────► identity / environment ─┐
                         ├─► duplicate-BSSID samples ─► duplicate-BSSID ────┼─► correlation
                         └─► disruption counter ──────► deauth storm ───────┘
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Any

from wiguard.config import WiGuardConfig
from wiguard.correlation import CorrelatedAlert, CorrelationEngine
from wiguard.detection import (
    DeauthStormDetector,
    DetectionEvent,
    DuplicateBSSIDDetector,
    EnvironmentAnomalyDetector,
    IdentityVerifier,
    TrustedProfile,
    TrustedProfileStore,
)
from wiguard.features import (
    APSummary,
    APTracker,
    BeaconFrame,
    DisruptionCounter,
    DisruptionFrame,
    DisruptionStats,
    Frame,
    parse_frame,
)


@dataclass
class FrameCounts:
    packets: int = 0
    beacons: int = 0
    probe_responses: int = 0
    disruption: int = 0

    def to_dict(self) -> dict[str, int]:
        return dict(vars(self))


@dataclass(frozen=True)
class PipelineResult:
    """A complete picture at one moment: APs, evidence and verdicts."""

    evaluated_at: float
    frames: FrameCounts
    access_points: list[APSummary]
    disruption: list[DisruptionStats]
    events: list[DetectionEvent]
    alerts: list[CorrelatedAlert]
    trusted_profiles: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "evaluated_at": self.evaluated_at,
            "frames": self.frames.to_dict(),
            "trusted_profiles": self.trusted_profiles,
            "access_points": [ap.to_dict() for ap in self.access_points],
            "disruption": [stats.to_dict() for stats in self.disruption],
            "events": [event.to_dict() for event in self.events],
            "alerts": [alert.to_dict() for alert in self.alerts],
            "notes": list(self.notes),
        }


class DetectionPipeline:
    def __init__(self, config: WiGuardConfig, trusted_profiles: Iterable[TrustedProfile] = ()):
        features, detection = config.features, config.detection
        identity, duplicate = detection.identity, detection.duplicate_bssid
        correlation = detection.correlation

        self.trusted_profiles = list(trusted_profiles)
        self.frames = FrameCounts()
        self.last_timestamp = 0.0
        self.aps = APTracker(
            window_size=features.window_size, clock_min_samples=features.clock_min_samples
        )
        self.disruption = DisruptionCounter(window_seconds=features.disruption_window_seconds)
        self.identity = IdentityVerifier(
            self.trusted_profiles,
            min_frames=identity.min_frames,
            clock_skew_delta_ppm=identity.clock_skew_delta_ppm,
            rssi_shift_db=identity.rssi_shift_db,
        )
        self.duplicate = DuplicateBSSIDDetector(
            window_size=features.window_size,
            min_samples=duplicate.min_samples,
            min_cluster_samples=duplicate.min_cluster_samples,
            residual_gap_us=duplicate.residual_gap_us,
            separation_factor=duplicate.separation_factor,
            min_transitions=duplicate.min_transitions,
            rssi_split_db=duplicate.rssi_split_db,
        )
        self.deauth = DeauthStormDetector(**detection.deauth_storm.model_dump())
        self.environment = EnvironmentAnomalyDetector(**detection.environment_anomaly.model_dump())
        self.correlation = CorrelationEngine(
            module_weights=correlation.module_weights,
            suspicious_threshold=correlation.suspicious_threshold,
            evil_twin_threshold=correlation.evil_twin_threshold,
            min_score=correlation.min_score,
        )

    @classmethod
    def from_config(cls, config: WiGuardConfig) -> DetectionPipeline:
        """Pipeline with the trusted profiles found at the configured path (if any)."""
        store = TrustedProfileStore(config.detection.identity.trusted_profiles_path)
        return cls(config, store.load())

    def process(self, packet: Any) -> Frame | None:
        self.frames.packets += 1
        frame = parse_frame(packet)
        if frame is not None:
            self.add_frame(frame)
        return frame

    def add_frame(self, frame: Frame) -> None:
        self.last_timestamp = max(self.last_timestamp, frame.timestamp)
        match frame:
            case BeaconFrame():
                if frame.kind == "beacon":
                    self.frames.beacons += 1
                else:
                    self.frames.probe_responses += 1
                self.aps.add(frame)
                self.duplicate.add(frame)
            case DisruptionFrame():
                self.frames.disruption += 1
                self.deauth.add(self.disruption.add(frame))

    def evaluate(
        self, *, now: float | None = None, evidence_window: float | None = None
    ) -> PipelineResult:
        """Run every detector on the current state and correlate the results.

        ``evidence_window`` (seconds) ignores evidence whose latest frame is
        older than that, so an AP or a storm that has gone quiet stops
        counting; ``None`` keeps everything (offline analysis of a capture).
        """

        evaluated_at = self.last_timestamp if now is None else now
        summaries = self.aps.summaries()
        ssid_of = {summary.bssid: summary.ssid for summary in summaries}
        events = [
            # Deauth frames carry no SSID; name the network from the AP profile.
            event if event.ssid else replace(event, ssid=ssid_of.get(event.bssid, ""))
            for event in (
                *self.identity.evaluate(summaries),
                *self.duplicate.evaluate(),
                *self.environment.evaluate(summaries),
                *self.deauth.evaluate(),
            )
            if evidence_window is None or evaluated_at - event.last_seen <= evidence_window
        ]
        notes = []
        if not self.trusted_profiles:
            notes.append(
                "No trusted profiles enrolled: identity checks against known APs are off "
                "(run `wiguard enroll` during a known-good period)."
            )
        return PipelineResult(
            evaluated_at=evaluated_at,
            frames=FrameCounts(**self.frames.to_dict()),
            access_points=summaries,
            disruption=self.disruption.summaries(),
            events=events,
            alerts=self.correlation.correlate(events, ssid_of=ssid_of),
            trusted_profiles=len(self.trusted_profiles),
            notes=notes,
        )
