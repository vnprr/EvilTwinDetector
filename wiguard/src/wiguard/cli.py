"""Command line interface for WiGuard."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from wiguard.capture import CaptureConfig, WiGuardCaptureEngine
from wiguard.capture.models import DEFAULT_ALFA_INTERFACE, DEFAULT_INTERNAL_INTERFACE, default_channels
from wiguard.features import APFeatureStateManager, FeatureExtractor, ManagementFrameCounter
from wiguard.state import APStateManager


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Passive WiGuard AP scanner")
    parser.add_argument("--iface", default=DEFAULT_ALFA_INTERFACE, help="external Alfa capture interface")
    parser.add_argument("--internal-iface", default=DEFAULT_INTERNAL_INTERFACE, help="internal Wi-Fi interface that must stay connected")
    parser.add_argument("--duration", type=float, default=20.0, help="scan duration in seconds")
    parser.add_argument("--dwell", type=float, default=0.5, help="seconds to dwell on each channel")
    parser.add_argument("--monitor-settle", type=float, default=0.25, help="seconds to wait after entering monitor mode")
    parser.add_argument("--channel-settle", type=float, default=0.05, help="seconds to wait after changing channel")
    parser.add_argument("--channels", default=None, help="comma-separated channel list; default scans 2.4 GHz and 5 GHz")
    parser.add_argument("--max-observations", type=int, default=None, help="stop after this many AP observations")
    parser.add_argument("--json", action="store_true", help="print final AP state as JSON")
    parser.add_argument("--quiet", action="store_true", help="suppress live channel/status output")
    parser.add_argument("--features", action="store_true", help="include feature extraction summaries in JSON output")
    parser.add_argument("--min-clock-samples", type=int, default=50, help="minimum TSF samples for live clock-skew estimate")
    args = parser.parse_args(argv)

    channels = _parse_channels(args.channels) if args.channels else default_channels()
    config = CaptureConfig(
        interface=args.iface,
        internal_interface=args.internal_iface,
        channels=channels,
        dwell_seconds=args.dwell,
        monitor_settle_seconds=args.monitor_settle,
        channel_settle_seconds=args.channel_settle,
    )
    manager = APStateManager()
    engine = WiGuardCaptureEngine(config, state_manager=manager)
    feature_extractor = FeatureExtractor() if args.features else None
    feature_state = APFeatureStateManager(min_clock_samples=args.min_clock_samples) if args.features else None
    management_counter = ManagementFrameCounter() if args.features else None

    def on_channel(channel: int, ok: bool, error: str | None) -> None:
        if args.quiet or args.json:
            return
        if ok:
            print(f"[channel {channel:>3}] listening on {args.iface}")
        else:
            print(f"[channel {channel:>3}] skipped: {error}", file=sys.stderr)

    def on_observation(_observation, state_manager: APStateManager) -> None:
        if args.quiet or args.json:
            return
        _print_table(state_manager)

    def on_packet(packet) -> None:
        if feature_extractor is None or feature_state is None or management_counter is None:
            return
        vector = feature_extractor.extract(packet)
        if vector is not None:
            feature_state.update(vector)
        management_counter.update(packet)

    try:
        engine.run(
            duration_seconds=args.duration,
            max_observations=args.max_observations,
            on_observation=on_observation,
            on_channel=on_channel,
            on_packet=on_packet if args.features else None,
        )
    except KeyboardInterrupt:
        print("\nInterrupted; interface restore attempted.", file=sys.stderr)
    if args.json:
        payload = {
            "capture": engine.stats.to_dict(),
            "access_points": [summary.to_dict() for summary in manager.summaries()],
        }
        if args.features and feature_state is not None and management_counter is not None:
            payload["feature_access_points"] = [
                summary.to_dict() for summary in feature_state.summaries()
            ]
            payload["management"] = [
                summary.to_dict() for summary in management_counter.summaries()
            ]
        print(json.dumps(payload, indent=2))
    else:
        _print_table(manager, final=True)
    return 0


def _parse_channels(raw: str) -> tuple[int, ...]:
    channels = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        channels.append(int(item))
    if not channels:
        raise argparse.ArgumentTypeError("at least one channel is required")
    return tuple(channels)


def _print_table(manager: APStateManager, *, final: bool = False) -> None:
    summaries = manager.summaries()
    if final:
        print("\nFinal AP state")
    print("SSID                          BSSID              CH     RSSI       FRAMES  TSF")
    print("----------------------------  -----------------  -----  ---------  ------  ---")
    for summary in summaries[-25:]:
        ssid = summary.ssid[:28]
        channels = ",".join(str(ch) for ch in summary.channels) or "?"
        rssi = "?" if summary.last_rssi_dbm is None else f"{summary.last_rssi_dbm} dBm"
        tsf = "yes" if summary.last_ap_tsf is not None else "no"
        print(
            f"{ssid:<28}  {summary.bssid:<17}  {channels:<5}  {rssi:<9}  {summary.frames:>6}  {tsf}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
