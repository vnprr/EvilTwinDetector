"""Reusable offline PCAP analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scapy.all import rdpcap

from wiguard.config import WiGuardConfig
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
    """Legacy flat analysis config.

    Retained for existing callers/tests. For full, file-driven configuration of
    every detector (including deauth/environment/correlation thresholds) pass a
    :class:`wiguard.config.WiGuardConfig` to :func:`analyze_pcap` instead.
    """

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


def analyze_pcap(
    pcap: Path | str,
    *,
    config: PcapAnalysisConfig | None = None,
    wiguard_config: WiGuardConfig | None = None,
) -> dict[str, object]:
    """Run the full offline WiGuard detection pipeline on one pcap.

    When ``wiguard_config`` is given, every detector is built from it, so the
    deauth, environment and correlation thresholds in ``config.yaml`` take
    effect here. Otherwise the legacy flat ``PcapAnalysisConfig`` is used, which
    keeps the historical behaviour (and fixture-friendly ``min_clock_samples``)
    unchanged.
    """

    pcap_path = Path(pcap)
    extractor = FeatureExtractor()

    if wiguard_config is not None:
        ap_state = wiguard_config.build_feature_state()
        management_counter = wiguard_config.build_management_counter()
        deauth_detector = wiguard_config.build_deauth_detector()
        environment_detector = wiguard_config.build_environment_detector()
        correlation_engine = wiguard_config.build_correlation_engine()
        duplicate_detector = wiguard_config.build_duplicate_detector()
        identity_store = wiguard_config.identity_baseline_store()
        identity_learn = wiguard_config.detection.identity.auto_learn
        identity_min_baseline_frames = wiguard_config.detection.identity.min_baseline_frames
        identity_baselines = identity_store.load() if identity_store is not None else ()
        identity_verifier = (
            wiguard_config.build_identity_verifier(identity_baselines)
            if identity_store is not None
            else None
        )
    else:
        config = config or PcapAnalysisConfig()
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
        identity_learn = config.identity_learn
        identity_min_baseline_frames = config.identity_min_baseline_frames
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
        if identity_learn:
            for summary in ap_summaries:
                if summary.frames >= identity_min_baseline_frames:
                    identity_verifier.force_baseline(summary)
        else:
            identity_alerts = [
                alert
                for alert in (identity_verifier.update(summary) for summary in ap_summaries)
                if alert.triggered
            ]
        if identity_store is not None and identity_learn:
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
