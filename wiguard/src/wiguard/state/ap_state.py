"""Rolling state for observed access points."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from statistics import mean, pstdev

from wiguard.capture.models import AccessPointObservation


@dataclass(frozen=True)
class APSummary:
    bssid: str
    ssid: str
    channels: tuple[int, ...]
    frames: int
    last_rssi_dbm: int | None
    avg_rssi_dbm: float | None
    rssi_stddev: float | None
    last_ap_tsf: int | None
    last_radiotap_tsf: int | None
    last_sequence_number: int | None
    first_seen_monotonic: float
    last_seen_monotonic: float
    clock_samples: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class APState:
    bssid: str
    window_size: int = 300
    ssids: set[str] = field(default_factory=set)
    channels: set[int] = field(default_factory=set)
    rssi_values: deque[int] = field(default_factory=deque)
    frames: int = 0
    first_seen_monotonic: float | None = None
    last_seen_monotonic: float | None = None
    last_rssi_dbm: int | None = None
    last_ap_tsf: int | None = None
    last_radiotap_tsf: int | None = None
    last_sequence_number: int | None = None
    clock_samples: int = 0

    def update(self, observation: AccessPointObservation) -> None:
        self.frames += 1
        self.ssids.add(observation.ssid)
        if observation.channel is not None:
            self.channels.add(observation.channel)
        if observation.rssi_dbm is not None:
            self.last_rssi_dbm = observation.rssi_dbm
            self.rssi_values.append(observation.rssi_dbm)
            while len(self.rssi_values) > self.window_size:
                self.rssi_values.popleft()
        self.last_ap_tsf = observation.ap_tsf
        self.last_radiotap_tsf = observation.radiotap_tsf
        self.last_sequence_number = observation.sequence_number
        if observation.has_clock_inputs:
            self.clock_samples += 1
        if self.first_seen_monotonic is None:
            self.first_seen_monotonic = observation.observed_monotonic
        self.last_seen_monotonic = observation.observed_monotonic

    def summary(self) -> APSummary:
        rssi_mean = mean(self.rssi_values) if self.rssi_values else None
        rssi_stddev = pstdev(self.rssi_values) if len(self.rssi_values) > 1 else None
        ssid = sorted(self.ssids)[-1] if self.ssids else "<unknown>"
        return APSummary(
            bssid=self.bssid,
            ssid=ssid,
            channels=tuple(sorted(self.channels)),
            frames=self.frames,
            last_rssi_dbm=self.last_rssi_dbm,
            avg_rssi_dbm=round(rssi_mean, 1) if rssi_mean is not None else None,
            rssi_stddev=round(rssi_stddev, 2) if rssi_stddev is not None else None,
            last_ap_tsf=self.last_ap_tsf,
            last_radiotap_tsf=self.last_radiotap_tsf,
            last_sequence_number=self.last_sequence_number,
            first_seen_monotonic=self.first_seen_monotonic or 0.0,
            last_seen_monotonic=self.last_seen_monotonic or 0.0,
            clock_samples=self.clock_samples,
        )


class APStateManager:
    def __init__(self, *, window_size: int = 300) -> None:
        self.window_size = window_size
        self._states: dict[str, APState] = {}

    def update(self, observation: AccessPointObservation) -> APState:
        state = self._states.get(observation.bssid)
        if state is None:
            state = APState(bssid=observation.bssid, window_size=self.window_size)
            self._states[observation.bssid] = state
        state.update(observation)
        return state

    def summaries(self) -> list[APSummary]:
        return sorted(
            (state.summary() for state in self._states.values()),
            key=lambda item: (item.ssid, item.bssid),
        )

    def __len__(self) -> int:
        return len(self._states)
