"""Long-running passive WiGuard sensor runtime."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from wiguard.capture import CaptureConfig, WiGuardCaptureEngine
from wiguard.config import DEFAULT_CONFIG_PATH, WiGuardConfig, load_config
from wiguard.correlation import events_from_alerts
from wiguard.detection import IdentityBaselineStore
from wiguard.features import FeatureExtractor
from wiguard.runtime.store import DEFAULT_STATE_PATH, RuntimeStore


@dataclass(frozen=True)
class SensorRuntimeConfig:
    """Operational configuration for a passive sensor run.

    Detector thresholds live in ``wiguard_config`` (loaded from ``config.yaml``);
    the fields here are the run-level knobs the CLI exposes.
    """

    capture: CaptureConfig
    wiguard_config: WiGuardConfig = field(default_factory=WiGuardConfig)
    state_path: Path = DEFAULT_STATE_PATH
    duration_seconds: float | None = None
    flush_interval_seconds: float = 5.0
    alert_cooldown_seconds: float = 300.0
    runtime_window_seconds: float = 300.0
    identity_baseline: Path | None = None
    identity_learn: bool = False
    json_events: bool = False
    quiet: bool = False


class WiGuardSensor:
    """Run capture, detection, correlation, and persistence as one passive sensor."""

    def __init__(self, config: SensorRuntimeConfig) -> None:
        self.config = config
        cfg = config.wiguard_config
        self.identity_min_baseline_frames = cfg.detection.identity.min_baseline_frames
        self.ap_state = cfg.build_ap_state()
        self.engine = WiGuardCaptureEngine(config.capture, state_manager=self.ap_state)
        self.feature_extractor = FeatureExtractor()
        self.feature_state = cfg.build_feature_state()
        self.management_counter = cfg.build_management_counter()
        self.deauth_detector = cfg.build_deauth_detector()
        self.environment_detector = cfg.build_environment_detector()
        self.correlation_engine = cfg.build_correlation_engine()
        self.duplicate_detector = cfg.build_duplicate_detector()
        self.identity_store = (
            IdentityBaselineStore(config.identity_baseline)
            if config.identity_baseline is not None
            else None
        )
        identity_baselines = self.identity_store.load() if self.identity_store is not None else ()
        self.identity_verifier = (
            cfg.build_identity_verifier(identity_baselines, auto_baseline=False)
            if self.identity_store is not None
            else None
        )
        self.deauth_alerts = deque(maxlen=200)
        self.last_flush_monotonic = 0.0

    def run(self) -> dict[str, object]:
        with RuntimeStore(self.config.state_path) as store:
            self.last_flush_monotonic = time.monotonic()

            def on_channel(channel: int, ok: bool, error: str | None) -> None:
                if self.config.quiet or self.config.json_events:
                    return
                if ok:
                    print(f"[channel {channel:>3}] sensor listening")
                else:
                    print(f"[channel {channel:>3}] skipped: {error}", file=sys.stderr)

            def on_packet(packet: Any) -> None:
                self._process_packet(packet)
                if self._flush_due():
                    self.flush(store)

            try:
                self.engine.run(
                    duration_seconds=self.config.duration_seconds,
                    on_channel=on_channel,
                    on_packet=on_packet,
                )
            except KeyboardInterrupt:
                print("\nInterrupted; interface restore attempted.", file=sys.stderr)
            finally:
                self.flush(store)

            payload = self._final_payload(store)
            if not self.config.quiet and not self.config.json_events:
                print(
                    "Sensor stopped: "
                    f"{payload['ap_snapshots']} APs, "
                    f"{payload['correlated_alerts']} correlated alerts, "
                    f"state={self.config.state_path}"
                )
            return payload

    def flush(self, store: RuntimeStore) -> dict[str, object]:
        observed_at = time.time()
        feature_summaries = self.feature_state.summaries()
        for summary in feature_summaries:
            store.upsert_ap_snapshot(summary, observed_at=observed_at)
            store.insert_ap_metric_sample(summary, observed_at=observed_at)

        duplicate_alerts = self.duplicate_detector.alerts()
        environment_alerts = self.environment_detector.analyze(feature_summaries)
        identity_alerts = self._identity_alerts(feature_summaries)
        ssid_by_bssid = {summary.bssid: summary.ssid for summary in feature_summaries}
        events = events_from_alerts(
            identity_alerts=identity_alerts + duplicate_alerts,
            deauth_alerts=self._recent_deauth_alerts(),
            environment_alerts=environment_alerts,
            ssid_by_bssid=ssid_by_bssid,
        )
        event_ids = [
            store.insert_detection_event(event, observed_at=observed_at)
            for event in events
        ]
        correlated_alerts = self.correlation_engine.correlate(events)
        records = [
            store.upsert_correlated_alert(
                alert,
                observed_at=observed_at,
                cooldown_seconds=self.config.alert_cooldown_seconds,
            )
            for alert in correlated_alerts
        ]
        if self.config.identity_learn and self.identity_store is not None:
            self.identity_store.save(self.identity_verifier.baselines())
        store.set_runtime_status(self._runtime_status(observed_at, feature_summaries, records))
        self.last_flush_monotonic = time.monotonic()
        payload = {
            "event": "sensor_flush",
            "observed_at": observed_at,
            "ap_snapshots": len(feature_summaries),
            "raw_detection_events": len(event_ids),
            "correlated_alerts": [record.to_dict() for record in records],
        }
        if self.config.json_events:
            print(json.dumps(payload, sort_keys=True), flush=True)
        return payload

    def _process_packet(self, packet: Any) -> None:
        vector = self.feature_extractor.extract(packet)
        if vector is not None:
            self.feature_state.update(vector)
            self.duplicate_detector.update(vector)
        stats = self.management_counter.update(packet)
        if stats is not None:
            alert = self.deauth_detector.update(stats)
            if alert.triggered:
                self.deauth_alerts.append((time.monotonic(), alert))

    def _identity_alerts(self, feature_summaries) -> list[object]:
        if self.identity_verifier is None:
            return []
        if self.config.identity_learn:
            for summary in feature_summaries:
                if summary.frames >= self.identity_min_baseline_frames:
                    self.identity_verifier.force_baseline(summary)
            return []
        return [
            alert
            for alert in (self.identity_verifier.update(summary) for summary in feature_summaries)
            if alert.triggered
        ]

    def _flush_due(self) -> bool:
        return (
            time.monotonic() - self.last_flush_monotonic
            >= self.config.flush_interval_seconds
        )

    def _recent_deauth_alerts(self) -> list[object]:
        now = time.monotonic()
        while (
            self.deauth_alerts
            and now - self.deauth_alerts[0][0] > self.config.runtime_window_seconds
        ):
            self.deauth_alerts.popleft()
        return [alert for _observed, alert in self.deauth_alerts]

    def _runtime_status(
        self,
        observed_at: float,
        feature_summaries,
        records,
    ) -> dict[str, object]:
        return {
            "observed_at": observed_at,
            "capture": self.engine.stats.to_dict(),
            "interface": self.config.capture.interface,
            "internal_interface": self.config.capture.internal_interface,
            "channels": list(self.config.capture.channels),
            "flush_interval_seconds": self.config.flush_interval_seconds,
            "ap_snapshots": len(feature_summaries),
            "correlated_alerts_this_flush": len(records),
            "identity_baseline": str(self.config.identity_baseline)
            if self.config.identity_baseline is not None
            else None,
            "config_source": self.config.wiguard_config.source_path,
        }

    def _final_payload(self, store: RuntimeStore) -> dict[str, object]:
        return {
            "capture": self.engine.stats.to_dict(),
            "state_path": str(self.config.state_path),
            "ap_snapshots": len(store.ap_snapshots()),
            "raw_detection_events": len(store.detection_events()),
            "correlated_alerts": len(store.correlated_alerts()),
            "timeline_events": len(store.timeline_events()),
        }


def main(argv: list[str] | None = None) -> int:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="path to config.yaml")
    pre_args, _ = pre.parse_known_args(argv)
    cfg = load_config(pre_args.config)

    parser = argparse.ArgumentParser(
        parents=[pre],
        description="Run the long-running passive WiGuard sensor. "
        "Detector thresholds come from config.yaml; flags below override run-level options.",
    )
    parser.add_argument("--iface", default=cfg.capture.interface, help="external Alfa capture interface")
    parser.add_argument("--internal-iface", default=cfg.capture.internal_interface, help="internal Wi-Fi interface that must stay connected")
    parser.add_argument("--duration", type=float, default=None, help="sensor duration in seconds; omit for continuous mode")
    parser.add_argument("--dwell", type=float, default=cfg.capture.dwell_seconds, help="seconds to dwell on each channel")
    parser.add_argument("--channels", default=None, help="comma-separated channel list; default from config")
    parser.add_argument("--state-path", type=Path, default=Path(cfg.runtime.state_path), help="SQLite runtime state path")
    parser.add_argument("--flush-interval", type=float, default=cfg.runtime.flush_interval_seconds, help="seconds between state flushes")
    parser.add_argument("--alert-cooldown", type=float, default=cfg.runtime.alert_cooldown_seconds, help="seconds to deduplicate repeated correlated alerts")
    parser.add_argument("--runtime-window", type=float, default=cfg.runtime.window_seconds, help="seconds of recent management-frame evidence to correlate")
    parser.add_argument("--window-size", type=int, default=cfg.state.rolling_window_size, help="rolling feature window size (overrides config)")
    parser.add_argument("--min-clock-samples", type=int, default=cfg.features.clock_skew_min_samples, help="minimum TSF samples for clock-skew estimate (overrides config)")
    parser.add_argument("--identity-baseline", type=Path, default=None, help="trusted AP identity baseline JSON path; identity checks run only when set")
    parser.add_argument("--identity-learn", action="store_true", help="learn or refresh trusted identity baselines during this run")
    parser.add_argument("--json-events", action="store_true", help="emit one JSON line per sensor flush")
    parser.add_argument("--quiet", action="store_true", help="suppress status output")
    args = parser.parse_args(argv)
    if args.identity_learn and args.identity_baseline is None:
        parser.error("--identity-learn requires --identity-baseline")
    if args.flush_interval <= 0:
        parser.error("--flush-interval must be positive")
    if args.runtime_window <= 0:
        parser.error("--runtime-window must be positive")

    # Fold run-level overrides back into the config so the detectors that read
    # window/clock-sample settings observe the overridden values too.
    cfg = replace(
        cfg,
        state=replace(cfg.state, rolling_window_size=args.window_size),
        features=replace(
            cfg.features,
            clock_skew_window_size=args.window_size,
            clock_skew_min_samples=args.min_clock_samples,
        ),
    )

    capture = cfg.capture_config(
        interface=args.iface,
        internal_interface=args.internal_iface,
        channels=_parse_channels(args.channels) if args.channels else None,
        dwell_seconds=args.dwell,
    )
    sensor = WiGuardSensor(
        SensorRuntimeConfig(
            capture=capture,
            wiguard_config=cfg,
            state_path=args.state_path,
            duration_seconds=args.duration,
            flush_interval_seconds=args.flush_interval,
            alert_cooldown_seconds=args.alert_cooldown,
            runtime_window_seconds=args.runtime_window,
            identity_baseline=args.identity_baseline,
            identity_learn=args.identity_learn,
            json_events=args.json_events,
            quiet=args.quiet,
        )
    )
    payload = sensor.run()
    if args.json_events:
        print(json.dumps({"event": "sensor_stopped", **payload}, sort_keys=True))
    elif args.quiet:
        print(json.dumps(payload, indent=2))
    return 0


def _parse_channels(raw: str) -> tuple[int, ...]:
    channels = tuple(int(item.strip()) for item in raw.split(",") if item.strip())
    if not channels:
        raise argparse.ArgumentTypeError("at least one channel is required")
    return channels


if __name__ == "__main__":
    raise SystemExit(main())
