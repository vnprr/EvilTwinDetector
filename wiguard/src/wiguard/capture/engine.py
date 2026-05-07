"""Passive Wi-Fi capture engine."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from scapy.all import sniff

from wiguard.state import APStateManager

from .adapter import AdapterError, AlfaMonitorAdapter
from .frame_parser import monotonic_raw, parse_ap_observation
from .models import AccessPointObservation, CaptureConfig


ObservationCallback = Callable[[AccessPointObservation, APStateManager], None]
ChannelCallback = Callable[[int, bool, str | None], None]


@dataclass
class CaptureStats:
    channels_attempted: int = 0
    channels_tuned: int = 0
    channel_errors: list[dict[str, object]] = field(default_factory=list)
    packets_seen: int = 0
    observations_seen: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class WiGuardCaptureEngine:
    """Capture AP management frames with safe monitor-mode lifecycle."""

    def __init__(
        self,
        config: CaptureConfig,
        *,
        state_manager: APStateManager | None = None,
    ) -> None:
        self.config = config
        self.state_manager = state_manager if state_manager is not None else APStateManager()
        self.adapter = AlfaMonitorAdapter(config.interface, config.internal_interface)
        self.stats = CaptureStats()

    def run(
        self,
        *,
        duration_seconds: float | None = None,
        max_observations: int | None = None,
        on_observation: ObservationCallback | None = None,
        on_channel: ChannelCallback | None = None,
    ) -> APStateManager:
        self.adapter.preflight(
            require_internal_connected=self.config.require_internal_wifi_connected
        )
        observations = 0
        deadline = None if duration_seconds is None else time.monotonic() + duration_seconds
        self.adapter.enter_monitor()
        time.sleep(self.config.monitor_settle_seconds)
        try:
            while deadline is None or time.monotonic() < deadline:
                for channel in self.config.channels:
                    if deadline is not None and time.monotonic() >= deadline:
                        break
                    self.stats.channels_attempted += 1
                    set_channel = self.adapter.set_channel(channel)
                    if set_channel.returncode != 0:
                        self.stats.channel_errors.append(
                            {
                                "channel": channel,
                                "returncode": set_channel.returncode,
                                "stderr": set_channel.stderr.strip(),
                            }
                        )
                        if on_channel is not None:
                            on_channel(channel, False, set_channel.stderr.strip())
                        continue
                    self.stats.channels_tuned += 1
                    if on_channel is not None:
                        on_channel(channel, True, None)
                    time.sleep(self.config.channel_settle_seconds)
                    timeout = self._bounded_timeout(deadline)
                    stop_requested = False

                    def handle_packet(packet) -> None:
                        nonlocal observations, stop_requested
                        self.stats.packets_seen += 1
                        observation = parse_ap_observation(
                            packet,
                            observed_monotonic=monotonic_raw(),
                        )
                        if observation is None:
                            return
                        self.state_manager.update(observation)
                        observations += 1
                        self.stats.observations_seen += 1
                        if on_observation is not None:
                            on_observation(observation, self.state_manager)
                        if max_observations is not None and observations >= max_observations:
                            stop_requested = True

                    sniff(
                        iface=self.config.interface,
                        timeout=timeout,
                        store=False,
                        prn=handle_packet,
                        stop_filter=lambda _packet: stop_requested,
                    )
                    if max_observations is not None and observations >= max_observations:
                        return self.state_manager
        finally:
            if self.config.restore_managed_on_exit:
                self.adapter.restore_managed()
            if (
                self.config.require_internal_wifi_connected
                and not self.adapter.internal_wifi_connected()
            ):
                raise AdapterError(
                    f"internal Wi-Fi {self.config.internal_interface} is no longer connected"
                )
        return self.state_manager

    def _bounded_timeout(self, deadline: float | None) -> float:
        if deadline is None:
            return self.config.dwell_seconds
        return max(0.05, min(self.config.dwell_seconds, deadline - time.monotonic()))
