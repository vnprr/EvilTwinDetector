"""Beacon interval and jitter, measured on the AP's own TSF clock."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from statistics import mean, pstdev

TU_US = 1024.0
"""One 802.11 time unit (TU) in microseconds."""


@dataclass(frozen=True, slots=True)
class BeaconTimingStats:
    beacon_interval_tu: int | None
    samples: int
    jitter_mean_us: float | None
    jitter_stddev_us: float | None
    jitter_max_abs_us: float | None
    missed_beacons: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class BeaconTimingAnalyzer:
    """Compare consecutive beacon TSF deltas with the advertised interval.

    Channel hopping means many beacons are never heard, so a delta is first
    rounded to a whole number of intervals; the remainder is the jitter.
    """

    def __init__(self, *, window_size: int = 300) -> None:
        self._last_tsf_us: int | None = None
        self._interval_tu: int | None = None
        self._jitters_us: deque[float] = deque(maxlen=window_size)
        self._missed = 0

    def add(self, ap_tsf_us: int, beacon_interval_tu: int | None) -> None:
        if beacon_interval_tu:
            self._interval_tu = beacon_interval_tu
        previous, self._last_tsf_us = self._last_tsf_us, ap_tsf_us
        if previous is None or not self._interval_tu:
            return
        delta = ap_tsf_us - previous
        if delta <= 0:
            return
        expected = self._interval_tu * TU_US
        intervals = max(1, round(delta / expected))
        self._missed += intervals - 1
        self._jitters_us.append(delta - intervals * expected)

    def stats(self) -> BeaconTimingStats:
        jitters = self._jitters_us
        return BeaconTimingStats(
            beacon_interval_tu=self._interval_tu,
            samples=len(jitters),
            jitter_mean_us=round(mean(jitters), 3) if jitters else None,
            jitter_stddev_us=round(pstdev(jitters), 3) if len(jitters) > 1 else None,
            jitter_max_abs_us=round(max(map(abs, jitters)), 3) if jitters else None,
            missed_beacons=self._missed,
        )
