"""Offline analysis: run the detection pipeline over a saved capture."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from scapy.utils import PcapReader

from wiguard.config import WiGuardConfig
from wiguard.detection import TrustedProfile
from wiguard.pipeline import DetectionPipeline, PipelineResult


def analyze_pcap(
    pcap: Path | str,
    config: WiGuardConfig | None = None,
    *,
    trusted_profiles: Iterable[TrustedProfile] | None = None,
) -> PipelineResult:
    """Analyse ``pcap`` exactly as the live sensor would have seen it.

    Packets are streamed, so captures larger than memory work too. Trusted
    profiles default to the ones at the configured path.
    """

    config = config or WiGuardConfig()
    if trusted_profiles is None:
        pipeline = DetectionPipeline.from_config(config)
    else:
        pipeline = DetectionPipeline(config, trusted_profiles)
    with PcapReader(str(pcap)) as reader:
        for packet in reader:
            pipeline.process(packet)
    return pipeline.evaluate()
