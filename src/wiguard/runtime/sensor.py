"""The long-running sensor: live capture -> pipeline -> SQLite, every few seconds."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from wiguard.capture import ChannelHoppingCapture
from wiguard.config import WiGuardConfig
from wiguard.pipeline import DetectionPipeline

from .writer import RecordSummary, StateWriter

log = logging.getLogger(__name__)

FlushCallback = Callable[[RecordSummary], None]


class Sensor:
    """Capture continuously and flush the pipeline's verdicts to the state database.

    Packet timestamps come from the capture (``packet.time``); the flush
    schedule and the database use the wall clock, which is the same clock for
    a live capture.
    """

    def __init__(
        self,
        config: WiGuardConfig,
        *,
        state_path: Path | None = None,
        on_flush: FlushCallback | None = None,
    ) -> None:
        self.config = config
        self.state_path = state_path or config.runtime.state_path
        self.pipeline = DetectionPipeline.from_config(config)
        self.capture = ChannelHoppingCapture(config.capture)
        self.on_flush = on_flush
        self._next_flush = 0.0

    def run(self, *, duration_seconds: float | None = None) -> RecordSummary:
        with StateWriter.open(self.state_path) as store:
            self._next_flush = time.time() + self.config.runtime.flush_interval_seconds

            def tick(*_: Any) -> None:
                if time.time() >= self._next_flush:
                    self.flush(store)

            def on_packet(packet: Any) -> None:
                self.pipeline.process(packet)
                tick()

            try:
                self.capture.run(on_packet, duration_seconds=duration_seconds, on_hop=tick)
            finally:
                summary = self.flush(store)
        return summary

    def flush(self, store: StateWriter) -> RecordSummary:
        runtime = self.config.runtime
        now = time.time()
        result = self.pipeline.evaluate(now=now, evidence_window=runtime.evidence_window_seconds)
        summary = store.record(result, observed_at=now, resolve_after=runtime.alert_resolve_seconds)
        store.set_status(
            {
                "mode": "live",
                "observed_at": now,
                "flush_interval_seconds": runtime.flush_interval_seconds,
                "interface": self.config.capture.interface,
                "internal_interface": self.config.capture.internal_interface,
                "channels": list(self.config.capture.channels),
                "capture": self.capture.stats.to_dict(),
                "frames": result.frames.to_dict(),
                "trusted_profiles": result.trusted_profiles,
                "config_source": self.config.source_path,
            }
        )
        self._next_flush = now + runtime.flush_interval_seconds
        if summary.alerts_opened or summary.alerts_escalated or summary.alerts_resolved:
            log.info(
                "%d open alert(s): %d new, %d escalated, %d resolved",
                summary.open_alerts, summary.alerts_opened, summary.alerts_escalated,
                summary.alerts_resolved,
            )  # fmt: skip
        else:
            log.debug("Flush: %d APs, %d open alert(s)", summary.access_points, summary.open_alerts)
        if self.on_flush is not None:
            self.on_flush(summary)
        return summary
