"""The ``wiguard`` command.

    wiguard scan       short live scan, prints APs and alerts
    wiguard sensor     long-running sensor writing the state database
    wiguard enroll     record trusted AP profiles (live or from a pcap)
    wiguard analyze    analyse a saved capture
    wiguard replay     analyse a capture into a state database for the dashboard
    wiguard api        serve the read-only API
    wiguard fixtures   generate / evaluate the synthetic test scenarios

Every command reads ``config.yaml`` (or ``--config``); flags override it.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from wiguard.capture import AdapterError
from wiguard.config import ConfigError, WiGuardConfig, load_config
from wiguard.detection import ProfileError
from wiguard.pipeline import PipelineResult
from wiguard.runtime import StoreError

VERDICT_ORDER = {"evil_twin": 0, "suspicious": 1, "info": 2}


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config).with_overrides(_overrides(args))
        return args.handler(args, config)
    except ConfigError as error:
        parser.exit(2, f"wiguard: configuration error: {error}\n")
    except (AdapterError, ProfileError, StoreError, OSError) as error:
        parser.exit(1, f"wiguard: {error}\n")


# --- commands -------------------------------------------------------------------


def _scan(args: argparse.Namespace, config: WiGuardConfig) -> int:
    from wiguard.capture import ChannelHoppingCapture
    from wiguard.pipeline import DetectionPipeline

    pipeline = DetectionPipeline.from_config(config)
    capture = ChannelHoppingCapture(config.capture)
    if not args.json:
        print(f"Scanning {len(config.capture.channels)} channels for {args.duration:g} s ...")
    capture.run(pipeline.process, duration_seconds=args.duration)
    _emit(pipeline.evaluate(), as_json=args.json, extra={"capture": capture.stats.to_dict()})
    return 0


def _sensor(args: argparse.Namespace, config: WiGuardConfig) -> int:
    from wiguard.runtime import RecordSummary, Sensor

    def report(summary: RecordSummary) -> None:
        if args.json:
            print(
                json.dumps({"event": "flush", "at": time.time(), **summary.to_dict()}), flush=True
            )
        elif not args.quiet and (summary.alerts_opened or summary.alerts_escalated):
            print(
                f"{time.strftime('%H:%M:%S')}  {summary.open_alerts} open alert(s): "
                f"+{summary.alerts_opened} new, {summary.alerts_escalated} escalated",
                flush=True,
            )

    sensor = Sensor(config, on_flush=report)
    if not args.json and not args.quiet:
        print(f"Sensor writing to {sensor.state_path} (Ctrl+C to stop).")
    final = sensor.run(duration_seconds=args.duration)
    if not args.json and not args.quiet:
        print(f"Stopped: {final.access_points} APs, {final.open_alerts} open alert(s).")
    return 0


def _enroll(args: argparse.Namespace, config: WiGuardConfig) -> int:
    from wiguard.detection import TrustedProfileStore, enroll

    result = _analyse_source(args, config, trusted_profiles=[])
    identity = config.detection.identity
    profiles = enroll(
        result.access_points,
        min_frames=args.min_frames or identity.enrollment_min_frames,
        enrolled_at=time.time(),
    )
    if args.ssid:
        profiles = [profile for profile in profiles if profile.ssid in args.ssid]
    store = TrustedProfileStore(args.output or identity.trusted_profiles_path)
    store.save(profiles)
    print(f"Enrolled {len(profiles)} trusted profile(s) into {store.path}:")
    for profile in profiles:
        skew = "-" if profile.clock_skew_ppm is None else f"{profile.clock_skew_ppm:+.1f} ppm"
        name = profile.ssid or "<hidden>"
        print(f"  {name:<28} {profile.bssid}  {profile.frames:>5} frames  {skew}")
    skipped = len(result.access_points) - len(profiles)
    if skipped:
        print(f"Skipped {skipped} AP(s) (too few frames or not in --ssid).")
    return 0


def _analyze(args: argparse.Namespace, config: WiGuardConfig) -> int:
    from wiguard.analysis import analyze_pcap

    _emit(analyze_pcap(args.pcap, config), as_json=args.json)
    return 0


def _replay(args: argparse.Namespace, config: WiGuardConfig) -> int:
    from wiguard.runtime import RuntimeStore, replay_pcap

    with RuntimeStore.open(config.runtime.state_path) as store:
        summary = replay_pcap(args.pcap, config, store, step_seconds=args.step)
    print(
        f"Replayed {args.pcap} into {config.runtime.state_path}: "
        f"{summary.access_points} APs, {summary.open_alerts} open alert(s)."
    )
    return 0


def _api(args: argparse.Namespace, config: WiGuardConfig) -> int:
    import uvicorn

    from wiguard.api import create_app

    uvicorn.run(create_app(config), host=config.api.host, port=config.api.port)
    return 0


def _fixtures_generate(args: argparse.Namespace, config: WiGuardConfig) -> int:
    from wiguard.evaluation import write_synthetic_fixtures

    print(write_synthetic_fixtures(args.directory))
    return 0


def _fixtures_evaluate(args: argparse.Namespace, config: WiGuardConfig) -> int:
    from wiguard.evaluation import evaluate_manifest

    report = evaluate_manifest(args.manifest, config)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for result in report["results"]:
            mark = "PASS" if result["passed"] else "FAIL"
            print(f"{mark}  {result['name']:<30} expected {result['expected']:<11} "
                  f"got {result['observed']:<11} score {result['score']:.3f}")  # fmt: skip
        print(f"{report['passed']}/{report['scenarios']} scenarios passed.")
    return 0 if report["success"] else 1


# --- helpers --------------------------------------------------------------------


def _analyse_source(
    args: argparse.Namespace, config: WiGuardConfig, **kwargs: Any
) -> PipelineResult:
    """Analyse ``--pcap`` if given, otherwise capture live for ``--duration``."""
    from wiguard.analysis import analyze_pcap

    if args.pcap:
        return analyze_pcap(args.pcap, config, **kwargs)
    from wiguard.capture import ChannelHoppingCapture
    from wiguard.pipeline import DetectionPipeline

    pipeline = DetectionPipeline(config, kwargs.get("trusted_profiles", ()))
    print(f"Capturing for {args.duration:g} s; keep the environment known-good ...")
    ChannelHoppingCapture(config.capture).run(pipeline.process, duration_seconds=args.duration)
    return pipeline.evaluate()


def _emit(result: PipelineResult, *, as_json: bool, extra: dict[str, Any] | None = None) -> None:
    if as_json:
        print(json.dumps({**result.to_dict(), **(extra or {})}, indent=2))
        return
    frames = result.frames
    print(f"\n{frames.packets} packets, {frames.beacons} beacons, "
          f"{frames.disruption} deauth/disassoc, {len(result.access_points)} APs, "
          f"{result.trusted_profiles} trusted profile(s)\n")  # fmt: skip
    print(f"{'SSID':<28} {'BSSID':<17} {'CH':<7} {'RSSI':>5} {'FRAMES':>7} {'SKEW ppm':>9}")
    for ap in result.access_points:
        channels = ",".join(map(str, ap.channels)) or "?"
        rssi = "?" if ap.avg_rssi_dbm is None else f"{ap.avg_rssi_dbm:.0f}"
        skew = "-" if ap.clock_skew_ppm is None else f"{ap.clock_skew_ppm:+.1f}"
        print(f"{(ap.ssid or '<hidden>')[:28]:<28} {ap.bssid:<17} {channels[:7]:<7} "
              f"{rssi:>5} {ap.frames:>7} {skew:>9}")  # fmt: skip
    print()
    if not result.alerts:
        print("No alerts.")
    for alert in sorted(result.alerts, key=lambda a: VERDICT_ORDER[a.classification.value]):
        label = alert.classification.value.upper().replace("_", " ")
        print(f"[{label} {alert.score:.3f}] {alert.explanation}")
    for note in result.notes:
        print(f"Note: {note}")


def _overrides(args: argparse.Namespace) -> dict[str, Any]:
    channels = getattr(args, "channels", None)
    return {
        "capture.interface": getattr(args, "iface", None),
        "capture.channels": [int(c) for c in channels.split(",") if c.strip()]
        if channels
        else None,
        "capture.dwell_seconds": getattr(args, "dwell", None),
        "runtime.state_path": getattr(args, "state_path", None),
        "api.host": getattr(args, "host", None),
        "api.port": getattr(args, "port", None),
        "detection.identity.trusted_profiles_path": getattr(args, "profiles", None),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wiguard", description="Passive Evil Twin detector.")
    parser.add_argument("--config", type=Path,
                        help="configuration file (default: ./config.yaml if present)")  # fmt: skip
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    capture = argparse.ArgumentParser(add_help=False)
    capture.add_argument("--iface", help="monitor-mode capture interface")
    capture.add_argument("--channels", help="comma-separated channels, e.g. 1,6,11")
    capture.add_argument("--dwell", type=float, help="seconds per channel")

    profiles = argparse.ArgumentParser(add_help=False)
    profiles.add_argument("--profiles", type=Path, help="trusted profiles file")

    state = argparse.ArgumentParser(add_help=False)
    state.add_argument("--state-path", type=Path, help="SQLite state database")

    output = argparse.ArgumentParser(add_help=False)
    output.add_argument("--json", action="store_true", help="machine-readable output")

    scan = commands.add_parser("scan", parents=[capture, profiles, output],
                               help="short live scan (needs root)")  # fmt: skip
    scan.add_argument("--duration", type=float, default=30.0, help="seconds (default 30)")
    scan.set_defaults(handler=_scan)

    sensor = commands.add_parser("sensor", parents=[capture, profiles, state, output],
                                 help="long-running sensor (needs root)")  # fmt: skip
    sensor.add_argument("--duration", type=float, help="stop after this many seconds")
    sensor.add_argument("--quiet", action="store_true", help="print nothing while running")
    sensor.set_defaults(handler=_sensor)

    enroll = commands.add_parser("enroll", parents=[capture],
                                 help="record trusted profiles of your own APs")  # fmt: skip
    source = enroll.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", type=Path, help="known-good capture to enroll from")
    source.add_argument("--duration", type=float, help="capture live for this many seconds")
    enroll.add_argument("--ssid", action="append", help="only enroll this SSID (repeatable)")
    enroll.add_argument("--min-frames", type=int, help="frames an AP needs to be enrolled")
    enroll.add_argument("--output", type=Path, help="profiles file (default from config)")
    enroll.set_defaults(handler=_enroll)

    analyze = commands.add_parser("analyze", parents=[profiles, output],
                                  help="analyse a saved capture")  # fmt: skip
    analyze.add_argument("pcap", type=Path)
    analyze.set_defaults(handler=_analyze)

    replay = commands.add_parser("replay", parents=[profiles, state],
                                 help="analyse a capture into a state database")  # fmt: skip
    replay.add_argument("pcap", type=Path)
    replay.add_argument("--step", type=float, help="seconds of capture time between updates "
                        "(default: the sensor's flush interval)")  # fmt: skip
    replay.set_defaults(handler=_replay)

    api = commands.add_parser("api", parents=[profiles, state], help="serve the read-only API")
    api.add_argument("--host")
    api.add_argument("--port", type=int)
    api.set_defaults(handler=_api)

    fixtures = commands.add_parser("fixtures", help="synthetic test scenarios")
    actions = fixtures.add_subparsers(dest="action", required=True, metavar="ACTION")
    generate = actions.add_parser("generate", help="write scenario pcaps and manifest")
    generate.add_argument("directory", type=Path)
    generate.set_defaults(handler=_fixtures_generate)
    evaluate = actions.add_parser("evaluate", parents=[output], help="score every scenario")
    evaluate.add_argument("manifest", type=Path)
    evaluate.set_defaults(handler=_fixtures_evaluate)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
