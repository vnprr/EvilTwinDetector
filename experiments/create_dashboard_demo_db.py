"""Create a small WiGuard runtime database for dashboard demos."""

from __future__ import annotations

import argparse
from pathlib import Path

from wiguard.analysis import analyze_pcap
from wiguard.runtime import RuntimeStore


DEFAULT_FIXTURE = Path("tests/pcap_fixtures/synthetic/correlated_duplicate_deauth.pcap")
DEFAULT_OUTPUT = Path("/tmp/wiguard_dashboard_demo.db")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a dashboard demo runtime database")
    parser.add_argument("--pcap", type=Path, default=DEFAULT_FIXTURE, help="fixture PCAP to replay")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="SQLite runtime DB path")
    args = parser.parse_args(argv)
    if args.output.exists():
        args.output.unlink()
    payload = analyze_pcap(args.pcap)
    with RuntimeStore(args.output) as store:
        records = store.record_analysis_result(payload, observed_at=1_800_000_000.0)
        stats = store.stats()
    print(f"wrote {args.output}")
    print(f"alerts={len(records)} aps={stats['ap_count']} events={stats['raw_event_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
