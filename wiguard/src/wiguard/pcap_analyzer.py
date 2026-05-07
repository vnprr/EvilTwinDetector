"""Offline pcap analyzer for WiGuard feature extraction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from wiguard.analysis import PcapAnalysisConfig, analyze_pcap


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

    payload = analyze_pcap(
        args.pcap,
        config=PcapAnalysisConfig(
            min_clock_samples=args.min_clock_samples,
            window_size=args.window_size,
            identity_baseline=args.identity_baseline,
            identity_learn=args.identity_learn,
            identity_min_baseline_frames=args.identity_min_baseline_frames,
            identity_clock_skew_delta_ppm=args.identity_clock_skew_delta_ppm,
            identity_rssi_shift_db=args.identity_rssi_shift_db,
            duplicate_min_samples=args.duplicate_min_samples,
            duplicate_min_cluster_samples=args.duplicate_min_cluster_samples,
            duplicate_residual_gap_us=args.duplicate_residual_gap_us,
        ),
    )
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
