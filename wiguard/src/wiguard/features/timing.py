"""Beacon timing and jitter analysis."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from statistics import mean, pstdev

from .models import APFeatureVector


@dataclass(frozen=True)
class BeaconTimingStats:
    samples: int
    expected_interval_us: float | None
    jitter_mean_us: float | None
    jitter_stddev_us: float | None
    jitter_max_abs_us: float | None
    estimated_missed_beacons: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class BeaconTimingAnalyzer:
    """Measure beacon interval jitter using AP TSF deltas."""

    def __init__(self, *, window_size: int = 300) -> None:
        self.window_size = window_size
        self._last_tsf: int | None = None
        self._last_interval_tu: int | None = None
        self._jitters: deque[float] = deque(maxlen=window_size)
        self._estimated_missed_beacons = 0

    def add(self, vector: APFeatureVector) -> BeaconTimingStats:
        if vector.frame_type != "beacon" or vector.ap_tsf is None:
            return self.summary()
        if vector.beacon_interval_tu is not None:
            self._last_interval_tu = vector.beacon_interval_tu
        if self._last_tsf is None:
            self._last_tsf = vector.ap_tsf
            return self.summary()
        if self._last_interval_tu is None or self._last_interval_tu <= 0:
            self._last_tsf = vector.ap_tsf
            return self.summary()

        delta = vector.ap_tsf - self._last_tsf
        self._last_tsf = vector.ap_tsf
        if delta <= 0:
            return self.summary()

        expected_us = self._last_interval_tu * 1024.0
        interval_count = max(1, round(delta / expected_us))
        self._estimated_missed_beacons += max(0, interval_count - 1)
        self._jitters.append(delta - interval_count * expected_us)
        return self.summary()

    def summary(self) -> BeaconTimingStats:
        expected_us = (
            self._last_interval_tu * 1024.0
            if self._last_interval_tu is not None and self._last_interval_tu > 0
            else None
        )
        jitter_mean = mean(self._jitters) if self._jitters else None
        jitter_stddev = pstdev(self._jitters) if len(self._jitters) > 1 else None
        jitter_max_abs = max((abs(value) for value in self._jitters), default=None)
        return BeaconTimingStats(
            samples=len(self._jitters),
            expected_interval_us=expected_us,
            jitter_mean_us=round(jitter_mean, 3) if jitter_mean is not None else None,
            jitter_stddev_us=round(jitter_stddev, 3) if jitter_stddev is not None else None,
            jitter_max_abs_us=round(jitter_max_abs, 3) if jitter_max_abs is not None else None,
            estimated_missed_beacons=self._estimated_missed_beacons,
        )
