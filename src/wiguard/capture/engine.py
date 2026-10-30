"""Passive channel-hopping capture on the monitor-mode adapter."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from scapy.sendrecv import sniff

from wiguard.config import CaptureSettings

from .adapter import AdapterError, MonitorAdapter

log = logging.getLogger(__name__)

PacketCallback = Callable[[Any], object]
HopCallback = Callable[[int, str | None], None]
"""Called after every channel change with the channel and an error (or ``None``)."""


@dataclass
class CaptureStats:
    hops: int = 0
    failed_hops: int = 0
    packets: int = 0
    interrupted: bool = False
    channel_errors: dict[int, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ChannelHoppingCapture:
    """Cycle through the configured channels and hand every packet to a callback.

    The adapter is put into monitor mode on start and restored on exit, and the
    host's own Wi-Fi connection is checked before and after the run. Ctrl+C
    ends the capture early; whatever was captured so far is kept.
    """

    def __init__(self, settings: CaptureSettings) -> None:
        self.settings = settings
        self.adapter = MonitorAdapter(settings.interface, settings.internal_interface)
        self.stats = CaptureStats()

    def run(
        self,
        on_packet: PacketCallback,
        *,
        duration_seconds: float | None = None,
        on_hop: HopCallback | None = None,
    ) -> CaptureStats:
        settings = self.settings
        self.adapter.preflight(require_internal_connected=settings.require_internal_connected)
        deadline = None if duration_seconds is None else time.monotonic() + duration_seconds
        self.adapter.enter_monitor()
        time.sleep(settings.monitor_settle_seconds)

        def handle(packet: Any) -> None:
            self.stats.packets += 1
            on_packet(packet)

        try:
            while not _expired(deadline):
                for channel in settings.channels:
                    if _expired(deadline):
                        break
                    error = self.adapter.set_channel(channel)
                    self.stats.hops += 1
                    if error is not None:
                        self.stats.failed_hops += 1
                        if channel not in self.stats.channel_errors:
                            log.warning("Cannot tune to channel %d: %s", channel, error)
                        self.stats.channel_errors[channel] = error
                    if on_hop is not None:
                        on_hop(channel, error)
                    if error is not None:
                        continue
                    time.sleep(settings.channel_settle_seconds)
                    sniff(
                        iface=settings.interface,
                        timeout=_dwell(settings.dwell_seconds, deadline),
                        store=False,
                        prn=handle,
                        chainCC=True,  # let Ctrl+C stop the whole capture, not one dwell
                    )
        except KeyboardInterrupt:
            self.stats.interrupted = True
            log.info("Capture interrupted; keeping what was captured.")
        finally:
            if settings.restore_managed_on_exit:
                self.adapter.restore_managed()
            if settings.require_internal_connected and not self.adapter.internal_connected():
                raise AdapterError(
                    f"internal Wi-Fi {settings.internal_interface} is no longer connected"
                )
        return self.stats


def _expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def _dwell(dwell_seconds: float, deadline: float | None) -> float:
    if deadline is None:
        return dwell_seconds
    return max(0.05, min(dwell_seconds, deadline - time.monotonic()))
