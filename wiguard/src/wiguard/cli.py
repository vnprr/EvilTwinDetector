"""Command line interface for WiGuard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wiguard.capture import CaptureConfig, WiGuardCaptureEngine
from wiguard.capture.models import DEFAULT_ALFA_INTERFACE, DEFAULT_INTERNAL_INTERFACE, default_channels
from wiguard.correlation import CorrelationEngine, events_from_alerts
from wiguard.detection import (
    APIdentityVerifier,
    DeauthStormDetector,
    EnvironmentAnomalyDetector,
    IdentityBaselineStore,
)
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
    parser.add_argument("--identity-baseline", type=Path, default=None, help="trusted AP identity baseline JSON path")
    parser.add_argument("--identity-learn", action="store_true", help="learn or refresh trusted identity baselines from this scan")
    parser.add_argument("--identity-min-baseline-frames", type=int, default=50, help="minimum frames required to learn an identity baseline")
    parser.add_argument("--identity-clock-skew-delta-ppm", type=float, default=5.0, help="clock-skew delta threshold for identity alerts")
    parser.add_argument("--identity-rssi-shift-db", type=float, default=12.0, help="RSSI shift threshold for identity alerts")
    args = parser.parse_args(argv)
    if args.identity_learn and args.identity_baseline is None:
        parser.error("--identity-learn requires --identity-baseline")

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
    deauth_detector = DeauthStormDetector() if args.features else None
    environment_detector = EnvironmentAnomalyDetector() if args.features else None
    correlation_engine = CorrelationEngine() if args.features else None
    identity_store = (
        IdentityBaselineStore(args.identity_baseline)
        if args.features and args.identity_baseline is not None
        else None
    )
    identity_baselines = identity_store.load() if identity_store is not None else ()
    identity_verifier = (
        APIdentityVerifier(
            min_baseline_frames=args.identity_min_baseline_frames,
            clock_skew_delta_ppm=args.identity_clock_skew_delta_ppm,
            rssi_shift_db=args.identity_rssi_shift_db,
            baselines=identity_baselines,
            auto_baseline=False,
        )
        if args.features and identity_store is not None
        else None
    )
    deauth_alerts = []

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
        if (
            feature_extractor is None
            or feature_state is None
            or management_counter is None
            or deauth_detector is None
        ):
            return
        vector = feature_extractor.extract(packet)
        if vector is not None:
            feature_state.update(vector)
        stats = management_counter.update(packet)
        if stats is not None:
            alert = deauth_detector.update(stats)
            if alert.triggered:
                deauth_alerts.append(alert)

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
            feature_summaries = feature_state.summaries()
            environment_alerts = (
                environment_detector.analyze(feature_summaries)
                if environment_detector is not None
                else []
            )
            identity_alerts = []
            identity_metadata = None
            if identity_verifier is not None:
                if args.identity_learn:
                    for summary in feature_summaries:
                        if summary.frames >= args.identity_min_baseline_frames:
                            identity_verifier.force_baseline(summary)
                else:
                    identity_alerts = [
                        alert
                        for alert in (identity_verifier.update(summary) for summary in feature_summaries)
                        if alert.triggered
                    ]
                if identity_store is not None and args.identity_learn:
                    identity_metadata = identity_store.save(identity_verifier.baselines()).to_dict()
                elif identity_store is not None:
                    identity_metadata = identity_store.metadata.to_dict()
            ssid_by_bssid = {summary.bssid: summary.ssid for summary in feature_summaries}
            correlated_alerts = (
                correlation_engine.correlate(
                    events_from_alerts(
                        identity_alerts=identity_alerts,
                        deauth_alerts=deauth_alerts[-50:],
                        environment_alerts=environment_alerts,
                        ssid_by_bssid=ssid_by_bssid,
                    )
                )
                if correlation_engine is not None
                else []
            )
            payload["feature_access_points"] = [
                summary.to_dict() for summary in feature_summaries
            ]
            payload["management"] = [
                summary.to_dict() for summary in management_counter.summaries()
            ]
            payload["deauth_alerts"] = [alert.to_dict() for alert in deauth_alerts[-50:]]
            payload["identity_alerts"] = [alert.to_dict() for alert in identity_alerts]
            payload["identity_baseline"] = identity_metadata
            payload["environment_alerts"] = [alert.to_dict() for alert in environment_alerts]
            payload["correlated_alerts"] = [alert.to_dict() for alert in correlated_alerts]
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
