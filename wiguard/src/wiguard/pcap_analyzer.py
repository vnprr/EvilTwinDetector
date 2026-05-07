"""Offline pcap analyzer for WiGuard feature extraction."""

from __future__ import annotations

import argparse
import json
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze a pcap with WiGuard feature extraction")
    parser.add_argument("pcap", type=Path, help="pcap/pcapng file to analyze")
    parser.add_argument("--min-clock-samples", type=int, default=5, help="minimum samples for clock-skew estimate")
    parser.add_argument("--window-size", type=int, default=300, help="rolling window size")
    parser.add_argument("--identity-baseline", type=Path, default=None, help="trusted AP identity baseline JSON path")
    parser.add_argument("--identity-learn", action="store_true", help="learn or refresh trusted identity baselines from this pcap")
    parser.add_argument("--identity-min-baseline-frames", type=int, default=50, help="minimum frames required to learn an identity baseline")
    parser.add_argument("--identity-clock-skew-delta-ppm", type=float, default=5.0, help="clock-skew delta threshold for identity alerts")
    parser.add_argument("--identity-rssi-shift-db", type=float, default=12.0, help="RSSI shift threshold for identity alerts")
    parser.add_argument("--duplicate-min-samples", type=int, default=30, help="minimum same-BSSID TSF samples for duplicate detection")
    parser.add_argument("--duplicate-min-cluster-samples", type=int, default=8, help="minimum samples in each residual cluster")
    parser.add_argument("--duplicate-residual-gap-us", type=float, default=10_000.0, help="minimum TSF residual gap for duplicate-BSSID detection")
    args = parser.parse_args(argv)
    if args.identity_learn and args.identity_baseline is None:
        parser.error("--identity-learn requires --identity-baseline")

    extractor = FeatureExtractor()
    ap_state = APFeatureStateManager(
        window_size=args.window_size,
        min_clock_samples=args.min_clock_samples,
    )
    management_counter = ManagementFrameCounter()
    deauth_detector = DeauthStormDetector()
    environment_detector = EnvironmentAnomalyDetector()
    correlation_engine = CorrelationEngine()
    duplicate_detector = DuplicateBSSIDDetector(
        min_samples=args.duplicate_min_samples,
        min_cluster_samples=args.duplicate_min_cluster_samples,
        residual_gap_threshold_us=args.duplicate_residual_gap_us,
        clock_skew_delta_ppm=args.identity_clock_skew_delta_ppm,
        rssi_delta_db=args.identity_rssi_shift_db,
    )
    identity_store = IdentityBaselineStore(args.identity_baseline) if args.identity_baseline else None
    identity_baselines = identity_store.load() if identity_store is not None else ()
    identity_verifier = (
        APIdentityVerifier(
            min_baseline_frames=args.identity_min_baseline_frames,
            clock_skew_delta_ppm=args.identity_clock_skew_delta_ppm,
            rssi_shift_db=args.identity_rssi_shift_db,
            baselines=identity_baselines,
            auto_baseline=False,
        )
        if identity_store is not None
        else None
    )
    packets = rdpcap(str(args.pcap))
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
        if args.identity_learn:
            for summary in ap_summaries:
                if summary.frames >= args.identity_min_baseline_frames:
                    identity_verifier.force_baseline(summary)
        else:
            identity_alerts = [
                alert
                for alert in (identity_verifier.update(summary) for summary in ap_summaries)
                if alert.triggered
            ]
        if identity_store is not None and args.identity_learn:
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
    payload = {
        "pcap": str(args.pcap),
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
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
