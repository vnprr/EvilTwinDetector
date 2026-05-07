"""Data models used by the capture subsystem."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


DEFAULT_ALFA_INTERFACE = "wlx00c0cab6d8f3"
DEFAULT_INTERNAL_INTERFACE = "wlo1"
DEFAULT_CHANNELS_2GHZ = tuple(range(1, 14))
DEFAULT_CHANNELS_5GHZ = (
    36,
    40,
    44,
    48,
    52,
    56,
    60,
    64,
    100,
    104,
    108,
    112,
    116,
    120,
    124,
    128,
    132,
    136,
    140,
    144,
    149,
    153,
    157,
    161,
    165,
)


def default_channels() -> tuple[int, ...]:
    return DEFAULT_CHANNELS_2GHZ + DEFAULT_CHANNELS_5GHZ


@dataclass(frozen=True)
class CaptureConfig:
    """Runtime configuration for passive capture."""

    interface: str = DEFAULT_ALFA_INTERFACE
    internal_interface: str = DEFAULT_INTERNAL_INTERFACE
    channels: tuple[int, ...] = field(default_factory=default_channels)
    dwell_seconds: float = 0.5
    monitor_settle_seconds: float = 0.25
    channel_settle_seconds: float = 0.05
    require_internal_wifi_connected: bool = True
    restore_managed_on_exit: bool = True

    @classmethod
    def from_channels(
        cls,
        channels: Iterable[int],
        *,
        interface: str = DEFAULT_ALFA_INTERFACE,
        internal_interface: str = DEFAULT_INTERNAL_INTERFACE,
        dwell_seconds: float = 0.5,
        monitor_settle_seconds: float = 0.25,
        channel_settle_seconds: float = 0.05,
    ) -> "CaptureConfig":
        return cls(
            interface=interface,
            internal_interface=internal_interface,
            channels=tuple(channels),
            dwell_seconds=dwell_seconds,
            monitor_settle_seconds=monitor_settle_seconds,
            channel_settle_seconds=channel_settle_seconds,
        )


@dataclass(frozen=True)
class AccessPointObservation:
    """A normalized observation extracted from one 802.11 AP management frame."""

    frame_type: str
    observed_monotonic: float
    ssid: str
    bssid: str
    channel: int | None
    rssi_dbm: int | None
    ap_tsf: int | None
    radiotap_tsf: int | None
    sequence_number: int | None
    beacon_interval_tu: int | None
    capabilities: int | None

    @property
    def has_clock_inputs(self) -> bool:
        return self.ap_tsf is not None and self.observed_monotonic > 0
