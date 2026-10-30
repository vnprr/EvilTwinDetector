"""Command line interface for WiGuard."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from wiguard.capture import WiGuardCaptureEngine
from wiguard.config import DEFAULT_CONFIG_PATH, load_config
from wiguard.correlation import events_from_alerts
from wiguard.detection import IdentityBaselineStore
from wiguard.features import FeatureExtractor
from wiguard.state import APStateManager


def main(argv: list[str] | None = None) -> int:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="path to config.yaml")
    pre_args, _ = pre.parse_known_args(argv)
    cfg = load_config(pre_args.config)

    parser = argparse.ArgumentParser(
        parents=[pre],
        description="Passive WiGuard AP scanner. Detector thresholds come from config.yaml.",
    )
    parser.add_argument("--iface", default=cfg.capture.interface, help="external Alfa capture interface")
    parser.add_argument("--internal-iface", default=cfg.capture.internal_interface, help="internal Wi-Fi interface that must stay connected")
    parser.add_argument("--duration", type=float, default=20.0, help="scan duration in seconds")
    parser.add_argument("--dwell", type=float, default=cfg.capture.dwell_seconds, help="seconds to dwell on each channel")
    parser.add_argument("--monitor-settle", type=float, default=cfg.capture.monitor_settle_seconds, help="seconds to wait after entering monitor mode")
    parser.add_argument("--channel-settle", type=float, default=cfg.capture.channel_settle_seconds, help="seconds to wait after changing channel")
    parser.add_argument("--channels", default=None, help="comma-separated channel list; default from config")
    parser.add_argument("--max-observations", type=int, default=None, help="stop after this many AP observations")
    parser.add_argument("--json", action="store_true", help="print final AP state as JSON")
    parser.add_argument("--quiet", action="store_true", help="suppress live channel/status output")
    parser.add_argument("--features", action="store_true", help="include feature extraction summaries in JSON output")
    parser.add_argument("--min-clock-samples", type=int, default=cfg.features.clock_skew_min_samples, help="minimum TSF samples for live clock-skew estimate (overrides config)")
    parser.add_argument("--identity-baseline", type=Path, default=None, help="trusted AP identity baseline JSON path; identity checks run only when set")
    parser.add_argument("--identity-learn", action="store_true", help="learn or refresh trusted identity baselines from this scan")
    args = parser.parse_args(argv)
    if args.identity_learn and args.identity_baseline is None:
        parser.error("--identity-learn requires --identity-baseline")

    cfg = replace(
        cfg,
        features=replace(cfg.features, clock_skew_min_samples=args.min_clock_samples),
    )

    channels = _parse_channels(args.channels) if args.channels else None
    config = cfg.capture_config(
        interface=args.iface,
        internal_interface=args.internal_iface,
        channels=channels,
        dwell_seconds=args.dwell,
    )
    config = replace(
        config,
        monitor_settle_seconds=args.monitor_settle,
        channel_settle_seconds=args.channel_settle,
    )
    manager = APStateManager(window_size=cfg.state.rolling_window_size)
    engine = WiGuardCaptureEngine(config, state_manager=manager)
    feature_extractor = FeatureExtractor() if args.features else None
    feature_state = cfg.build_feature_state() if args.features else None
    management_counter = cfg.build_management_counter() if args.features else None
    deauth_detector = cfg.build_deauth_detector() if args.features else None
    environment_detector = cfg.build_environment_detector() if args.features else None
    correlation_engine = cfg.build_correlation_engine() if args.features else None
    duplicate_detector = cfg.build_duplicate_detector() if args.features else None
    identity_store = (
        IdentityBaselineStore(args.identity_baseline)
        if args.features and args.identity_baseline is not None
        else None
    )
    identity_baselines = identity_store.load() if identity_store is not None else ()
    identity_verifier = (
        cfg.build_identity_verifier(identity_baselines, auto_baseline=False)
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
            or duplicate_detector is None
        ):
            return
        vector = feature_extractor.extract(packet)
        if vector is not None:
            feature_state.update(vector)
            duplicate_detector.update(vector)
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
            duplicate_bssid_alerts = (
                duplicate_detector.alerts()
                if duplicate_detector is not None
                else []
            )
            identity_alerts = []
            identity_metadata = None
            if identity_verifier is not None:
                if args.identity_learn:
                    for summary in feature_summaries:
                        if summary.frames >= cfg.detection.identity.min_baseline_frames:
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
                        identity_alerts=identity_alerts + duplicate_bssid_alerts,
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
            payload["identity_alerts"] = [
                alert.to_dict() for alert in identity_alerts + duplicate_bssid_alerts
            ]
            payload["duplicate_bssid_alerts"] = [
                alert.to_dict() for alert in duplicate_bssid_alerts
            ]
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
