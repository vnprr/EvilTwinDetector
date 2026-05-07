"""Feature-level AP state aggregation."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from statistics import mean, pstdev

from .clock import ClockSkewEstimate, ClockSkewEstimator
from .models import APFeatureVector
from .sequence import SequenceAnalysis, SequenceAnalyzer
from .timing import BeaconTimingAnalyzer, BeaconTimingStats


@dataclass(frozen=True)
class APFeatureSummary:
    bssid: str
    ssid: str
    channels: tuple[int, ...]
    frames: int
    last_rssi_dbm: int | None
    avg_rssi_dbm: float | None
    rssi_stddev: float | None
    dominant_ie_fingerprint: str | None
    ie_fingerprint_hashes: tuple[str, ...]
    stable_ie_ids_union: tuple[int, ...]
    key_ie_ids_union: tuple[int, ...]
    vendor_ouis: tuple[str, ...]
    clock_estimate: ClockSkewEstimate | None
    beacon_timing: BeaconTimingStats
    sequence_analysis: SequenceAnalysis
    last_sequence_number: int | None

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["clock_estimate"] = (
            self.clock_estimate.to_dict() if self.clock_estimate is not None else None
        )
        return payload


@dataclass
class APFeatureState:
    bssid: str
    window_size: int = 300
    min_clock_samples: int = 50
    ssids: set[str] = field(default_factory=set)
    channels: set[int] = field(default_factory=set)
    rssi_values: deque[int] = field(default_factory=deque)
    ie_hash_counts: Counter[str] = field(default_factory=Counter)
    stable_ie_ids: set[int] = field(default_factory=set)
    key_ie_ids: set[int] = field(default_factory=set)
    vendor_ouis: set[str] = field(default_factory=set)
    frames: int = 0
    last_rssi_dbm: int | None = None
    last_sequence_number: int | None = None
    clock: ClockSkewEstimator | None = None
    timing: BeaconTimingAnalyzer | None = None
    sequence: SequenceAnalyzer | None = None

    def __post_init__(self) -> None:
        self.clock = ClockSkewEstimator(
            min_samples=self.min_clock_samples,
            window_size=self.window_size,
        )
        self.timing = BeaconTimingAnalyzer(window_size=self.window_size)
        self.sequence = SequenceAnalyzer()

    def update(self, vector: APFeatureVector) -> None:
        self.frames += 1
        self.ssids.add(vector.ssid)
        if vector.channel is not None:
            self.channels.add(vector.channel)
        if vector.rssi_dbm is not None:
            self.last_rssi_dbm = vector.rssi_dbm
            self.rssi_values.append(vector.rssi_dbm)
            while len(self.rssi_values) > self.window_size:
                self.rssi_values.popleft()
        self.ie_hash_counts[vector.ie_fingerprint.hash] += 1
        self.stable_ie_ids.update(vector.ie_fingerprint.stable_sequence_signature)
        self.key_ie_ids.update(element.id for element in vector.ie_fingerprint.key_elements)
        self.vendor_ouis.update(vector.ie_fingerprint.vendor_ouis)
        self.last_sequence_number = vector.sequence_number
        assert self.clock is not None
        self.clock.add(vector)
        assert self.timing is not None
        self.timing.add(vector)
        assert self.sequence is not None
        self.sequence.add(vector.sequence_number)

    def summary(self) -> APFeatureSummary:
        rssi_mean = mean(self.rssi_values) if self.rssi_values else None
        rssi_stddev = pstdev(self.rssi_values) if len(self.rssi_values) > 1 else None
        ssid = sorted(self.ssids)[-1] if self.ssids else "<unknown>"
        dominant = self.ie_hash_counts.most_common(1)[0][0] if self.ie_hash_counts else None
        assert self.clock is not None
        assert self.timing is not None
        assert self.sequence is not None
        return APFeatureSummary(
            bssid=self.bssid,
            ssid=ssid,
            channels=tuple(sorted(self.channels)),
            frames=self.frames,
            last_rssi_dbm=self.last_rssi_dbm,
            avg_rssi_dbm=round(rssi_mean, 1) if rssi_mean is not None else None,
            rssi_stddev=round(rssi_stddev, 2) if rssi_stddev is not None else None,
            dominant_ie_fingerprint=dominant,
            ie_fingerprint_hashes=tuple(sorted(self.ie_hash_counts)),
            stable_ie_ids_union=tuple(sorted(self.stable_ie_ids)),
            key_ie_ids_union=tuple(sorted(self.key_ie_ids)),
            vendor_ouis=tuple(sorted(self.vendor_ouis)),
            clock_estimate=self.clock.estimate(),
            beacon_timing=self.timing.summary(),
            sequence_analysis=self.sequence.summary(),
            last_sequence_number=self.last_sequence_number,
        )


class APFeatureStateManager:
    def __init__(self, *, window_size: int = 300, min_clock_samples: int = 50) -> None:
        self.window_size = window_size
        self.min_clock_samples = min_clock_samples
        self._states: dict[str, APFeatureState] = {}

    def update(self, vector: APFeatureVector) -> APFeatureState:
        state = self._states.get(vector.bssid)
        if state is None:
            state = APFeatureState(
                bssid=vector.bssid,
                window_size=self.window_size,
                min_clock_samples=self.min_clock_samples,
            )
            self._states[vector.bssid] = state
        state.update(vector)
        return state

    def summaries(self) -> list[APFeatureSummary]:
        return sorted(
            (state.summary() for state in self._states.values()),
            key=lambda item: (item.ssid, item.bssid),
        )

    def __len__(self) -> int:
        return len(self._states)
