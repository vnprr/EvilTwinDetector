"""Offline pcap analyzer for WiGuard feature extraction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scapy.all import rdpcap

from wiguard.features import APFeatureStateManager, FeatureExtractor, ManagementFrameCounter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze a pcap with WiGuard feature extraction")
    parser.add_argument("pcap", type=Path, help="pcap/pcapng file to analyze")
    parser.add_argument("--min-clock-samples", type=int, default=5, help="minimum samples for clock-skew estimate")
    parser.add_argument("--window-size", type=int, default=300, help="rolling window size")
    args = parser.parse_args(argv)

    extractor = FeatureExtractor()
    ap_state = APFeatureStateManager(
        window_size=args.window_size,
        min_clock_samples=args.min_clock_samples,
    )
    management_counter = ManagementFrameCounter()
    packets = rdpcap(str(args.pcap))
    feature_vectors = 0
    management_frames = 0

    for packet in packets:
        observed = float(getattr(packet, "time", 0.0) or 0.0)
        vector = extractor.extract(packet, observed_monotonic=observed)
        if vector is not None:
            ap_state.update(vector)
            feature_vectors += 1
        if management_counter.update(packet, observed_monotonic=observed) is not None:
            management_frames += 1

    payload = {
        "pcap": str(args.pcap),
        "packets": len(packets),
        "ap_feature_vectors": feature_vectors,
        "management_frames": management_frames,
        "access_points": [summary.to_dict() for summary in ap_state.summaries()],
        "management": [summary.to_dict() for summary in management_counter.summaries(now=0.0)],
    }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
