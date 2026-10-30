"""The capture loop, with the adapter and ``sniff`` replaced by stand-ins (no radio needed)."""

from __future__ import annotations

from typing import Any

import pytest
from scapy.utils import rdpcap

from builders import FIXTURES
from wiguard.analysis import analyze_pcap
from wiguard.capture import ChannelHoppingCapture, engine
from wiguard.config import CaptureSettings, WiGuardConfig
from wiguard.pipeline import DetectionPipeline


class FakeAdapter:
    def __init__(self, interface: str, internal_interface: str) -> None:
        self.calls: list[str] = []

    def preflight(self, *, require_internal_connected: bool = True) -> None:
        self.calls.append("preflight")

    def enter_monitor(self) -> None:
        self.calls.append("monitor")

    def restore_managed(self) -> None:
        self.calls.append("managed")

    def set_channel(self, channel: int) -> str | None:
        return None

    def internal_connected(self) -> bool:
        return True


@pytest.fixture
def capture(monkeypatch: pytest.MonkeyPatch) -> ChannelHoppingCapture:
    """A capture whose first dwell delivers a synthetic Evil Twin scenario."""
    packets = list(rdpcap(str(FIXTURES / "classic_evil_twin.pcap")))

    def fake_sniff(*, prn: Any, **_: Any) -> None:
        while packets:
            prn(packets.pop(0))

    monkeypatch.setattr(engine, "MonitorAdapter", FakeAdapter)
    monkeypatch.setattr(engine, "sniff", fake_sniff)
    settings = CaptureSettings(channels=(6, 11), monitor_settle_seconds=0, channel_settle_seconds=0)
    return ChannelHoppingCapture(settings)


def test_saved_capture_replays_to_the_same_verdicts(capture, tmp_path) -> None:
    config = WiGuardConfig()
    live = DetectionPipeline.from_config(config)
    saved = tmp_path / "run.pcap"

    stats = capture.run(live.process, duration_seconds=0.05, save_to=saved)

    assert stats.packets == len(rdpcap(str(saved))) == 310
    replayed = analyze_pcap(saved, config, trusted_profiles=[])
    verdicts = {(a.bssid, a.classification, a.score) for a in live.evaluate().alerts}
    assert verdicts  # the deauthentication storm alone raises an alert
    assert verdicts == {(a.bssid, a.classification, a.score) for a in replayed.alerts}
    assert capture.adapter.calls == ["preflight", "monitor", "managed"]  # type: ignore[attr-defined]


def test_nothing_is_written_without_save_to(capture, tmp_path) -> None:
    capture.run(lambda packet: None, duration_seconds=0.05)
    assert list(tmp_path.iterdir()) == []
