"""Reusable offline PCAP analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scapy.all import rdpcap

from wiguard.correlation import CorrelationEngine, events_from_alerts
from wiguard.detection import (
    APIdentityVerifier,
    DeauthStormDetector,
    DuplicateBSSIDDetector,
    EnvironmentAnomalyDetector,
    IdentityBaselineStore,
)
from wiguard.features import APFeatureStateManager, FeatureExtractor, ManagementFrameCounter


@dataclass(frozen=True)
class PcapAnalysisConfig:
    min_clock_samples: int = 5
    window_size: int = 300
    identity_baseline: Path | None = None
    identity_learn: bool = False
    identity_min_baseline_frames: int = 50
    identity_clock_skew_delta_ppm: float = 5.0
    identity_rssi_shift_db: float = 12.0
    duplicate_min_samples: int = 30
    duplicate_min_cluster_samples: int = 8
    duplicate_residual_gap_us: float = 10_000.0


def analyze_pcap(pcap: Path | str, *, config: PcapAnalysisConfig | None = None) -> dict[str, object]:
    """Run the full offline WiGuard detection pipeline on one pcap."""

    pcap_path = Path(pcap)
    config = config or PcapAnalysisConfig()
    extractor = FeatureExtractor()
    ap_state = APFeatureStateManager(
        window_size=config.window_size,
        min_clock_samples=config.min_clock_samples,
    )
    management_counter = ManagementFrameCounter()
    deauth_detector = DeauthStormDetector()
    environment_detector = EnvironmentAnomalyDetector()
    correlation_engine = CorrelationEngine()
    duplicate_detector = DuplicateBSSIDDetector(
        min_samples=config.duplicate_min_samples,
        min_cluster_samples=config.duplicate_min_cluster_samples,
        residual_gap_threshold_us=config.duplicate_residual_gap_us,
        clock_skew_delta_ppm=config.identity_clock_skew_delta_ppm,
        rssi_delta_db=config.identity_rssi_shift_db,
    )
    identity_store = (
        IdentityBaselineStore(config.identity_baseline)
        if config.identity_baseline is not None
        else None
    )
    identity_baselines = identity_store.load() if identity_store is not None else ()
    identity_verifier = (
        APIdentityVerifier(
            min_baseline_frames=config.identity_min_baseline_frames,
            clock_skew_delta_ppm=config.identity_clock_skew_delta_ppm,
            rssi_shift_db=config.identity_rssi_shift_db,
            baselines=identity_baselines,
            auto_baseline=False,
        )
        if identity_store is not None
        else None
    )
    packets = rdpcap(str(pcap_path))
    feature_vectors = 0
    management_frames = 0
    deauth_alerts = []

    for packet in packets:
        observed = float(getattr(packet, "time", 0.0) or 0.0)
        vector = extractor.extract(packet, observed_monotonic=observed)
        if vector is not None:
            ap_state.update(vector)
            duplicate_detector.update(vector)
            feature_vectors += 1
        stats = management_counter.update(packet, observed_monotonic=observed)
        if stats is not None:
            management_frames += 1
            alert = deauth_detector.update(stats)
            if alert.triggered:
                deauth_alerts.append(alert)

    ap_summaries = ap_state.summaries()
    environment_alerts = environment_detector.analyze(ap_summaries)
    duplicate_bssid_alerts = duplicate_detector.alerts()
    identity_alerts = []
    identity_metadata = None
    if identity_verifier is not None:
        if config.identity_learn:
            for summary in ap_summaries:
                if summary.frames >= config.identity_min_baseline_frames:
                    identity_verifier.force_baseline(summary)
        else:
            identity_alerts = [
                alert
                for alert in (identity_verifier.update(summary) for summary in ap_summaries)
                if alert.triggered
            ]
        if identity_store is not None and config.identity_learn:
            identity_metadata = identity_store.save(identity_verifier.baselines()).to_dict()
        elif identity_store is not None:
            identity_metadata = identity_store.metadata.to_dict()

    ssid_by_bssid = {summary.bssid: summary.ssid for summary in ap_summaries}
    correlated_alerts = correlation_engine.correlate(
        events_from_alerts(
            identity_alerts=identity_alerts + duplicate_bssid_alerts,
            deauth_alerts=deauth_alerts[-50:],
            environment_alerts=environment_alerts,
            ssid_by_bssid=ssid_by_bssid,
        )
    )
    return {
        "pcap": str(pcap_path),
        "packets": len(packets),
        "ap_feature_vectors": feature_vectors,
        "management_frames": management_frames,
        "access_points": [summary.to_dict() for summary in ap_summaries],
        "management": [summary.to_dict() for summary in management_counter.summaries(now=0.0)],
        "deauth_alerts": [alert.to_dict() for alert in deauth_alerts[-50:]],
        "identity_alerts": [
            alert.to_dict() for alert in identity_alerts + duplicate_bssid_alerts
        ],
        "duplicate_bssid_alerts": [
            alert.to_dict() for alert in duplicate_bssid_alerts
        ],
        "identity_baseline": identity_metadata,
        "environment_alerts": [alert.to_dict() for alert in environment_alerts],
        "correlated_alerts": [alert.to_dict() for alert in correlated_alerts],
    }
