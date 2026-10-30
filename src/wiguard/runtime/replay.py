"""Replay a saved capture into a state database, exactly as the sensor would have.

The pipeline is evaluated and recorded every ``step_seconds`` of *capture*
time, the same schedule the live sensor follows in wall-clock time. Alert
lifecycles, metric histories and timeline timestamps therefore look as they
would have looked live, and an alert's ``first_seen`` minus the attack start
is the time to detection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scapy.utils import PcapReader

from wiguard.config import WiGuardConfig
from wiguard.pipeline import DetectionPipeline

from .writer import RecordSummary, StateWriter


def replay_pcap(
    pcap: Path | str,
    config: WiGuardConfig,
    store: StateWriter,
    *,
    step_seconds: float | None = None,
) -> RecordSummary:
    runtime = config.runtime
    step = step_seconds or runtime.flush_interval_seconds
    pipeline = DetectionPipeline.from_config(config)

    def flush(at: float) -> RecordSummary:
        result = pipeline.evaluate(now=at, evidence_window=runtime.evidence_window_seconds)
        return store.record(result, observed_at=at, resolve_after=runtime.alert_resolve_seconds)

    next_flush: float | None = None
    with PcapReader(str(pcap)) as reader:
        for packet in reader:
            pipeline.process(packet)
            now = pipeline.last_timestamp
            if next_flush is None:
                next_flush = now + step
            elif now >= next_flush:
                flush(now)
                next_flush = now + step
    summary = flush(pipeline.last_timestamp)
    status: dict[str, Any] = {
        "mode": "replay",
        "observed_at": pipeline.last_timestamp,
        "source": str(pcap),
        "step_seconds": step,
        "frames": pipeline.frames.to_dict(),
        "trusted_profiles": len(pipeline.trusted_profiles),
        "config_source": config.source_path,
    }
    store.set_status(status)
    return summary
