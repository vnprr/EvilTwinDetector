"""Replay a saved pcap into a WiGuard runtime database for offline review.

This is the reproducible, hardware-free path the dashboard visualises: run the
full offline detection pipeline on a capture and persist the result to SQLite,
exactly as the live sensor would, but marked as ``mode: replay`` so the API and
dashboard show it is an imported snapshot rather than a live feed.
"""

from __future__ import annotations

import argparse
import time
from dataclasses import replace
from pathlib import Path

from wiguard.analysis import analyze_pcap
from wiguard.config import DEFAULT_CONFIG_PATH, load_config
from wiguard.runtime.store import DEFAULT_STATE_PATH, RuntimeStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay a pcap into a WiGuard runtime database (offline, read-only analysis)."
    )
    parser.add_argument("pcap", type=Path, help="pcap file to analyse")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="path to config.yaml")
    parser.add_argument("--state-path", type=Path, default=None, help="SQLite runtime state path (default from config)")
    parser.add_argument(
        "--min-clock-samples",
        type=int,
        default=None,
        help="override clock-skew sample minimum (useful for short captures)",
    )
    args = parser.parse_args(argv)

    if not args.pcap.exists():
        parser.error(f"pcap not found: {args.pcap}")

    config = load_config(args.config)
    if args.min_clock_samples is not None:
        config = replace(
            config,
            features=replace(config.features, clock_skew_min_samples=args.min_clock_samples),
        )
    state_path = args.state_path if args.state_path is not None else Path(config.runtime.state_path)

    observed_at = time.time()
    payload = analyze_pcap(args.pcap, wiguard_config=config)
    with RuntimeStore(state_path) as store:
        records = store.record_analysis_result(
            payload,
            observed_at=observed_at,
            alert_cooldown_seconds=config.runtime.alert_cooldown_seconds,
        )
        store.set_runtime_status(
            {
                "mode": "replay",
                "observed_at": observed_at,
                "source": str(args.pcap),
                "config_source": config.source_path,
                "ap_snapshots": len(payload.get("access_points", [])),
                "correlated_alerts": len(payload.get("correlated_alerts", [])),
            }
        )

    print(
        f"Replayed {args.pcap} -> {state_path}: "
        f"{len(payload.get('access_points', []))} APs, "
        f"{len(records)} correlated alerts."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
