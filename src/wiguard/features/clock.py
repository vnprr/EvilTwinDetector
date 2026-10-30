"""Clock-skew estimation from AP TSF timestamps.

Every AP stamps its beacons with its own TSF timer (microseconds). That timer
is driven by the AP's crystal oscillator, which runs slightly fast or slow.
Plotting the AP's TSF against our local capture clock gives an almost perfect
straight line; its slope minus one, in parts per million, is the AP's clock
skew. Two different devices practically never share the same skew, which is
what makes it useful for telling a copied AP from the original.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LinearFit:
    """Least-squares fit ``y = slope * x + intercept`` (x, y in microseconds)."""

    samples: int
    slope: float
    intercept_us: float
    r_squared: float
    residual_stddev_us: float

    @property
    def skew_ppm(self) -> float:
        return (self.slope - 1.0) * 1_000_000.0

    def predict(self, x: float) -> float:
        return self.slope * x + self.intercept_us

    def to_dict(self) -> dict[str, float | int]:
        return {
            "samples": self.samples,
            "skew_ppm": round(self.skew_ppm, 3),
            "intercept_us": round(self.intercept_us, 3),
            "r_squared": round(self.r_squared, 6),
            "residual_stddev_us": round(self.residual_stddev_us, 3),
        }


def fit_line(xs: Sequence[float], ys: Sequence[float]) -> LinearFit | None:
    """Ordinary least squares; ``None`` if there are too few distinct points."""

    n = len(xs)
    if n < 2 or n != len(ys):
        return None
    x_mean = sum(xs) / n
    y_mean = sum(ys) / n
    ss_xx = sum((x - x_mean) ** 2 for x in xs)
    if ss_xx == 0:
        return None
    ss_xy = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys, strict=True))
    slope = ss_xy / ss_xx
    intercept = y_mean - slope * x_mean
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys, strict=True))
    ss_tot = sum((y - y_mean) ** 2 for y in ys)
    return LinearFit(
        samples=n,
        slope=slope,
        intercept_us=intercept,
        r_squared=1.0 if ss_tot == 0 else 1.0 - ss_res / ss_tot,
        residual_stddev_us=math.sqrt(ss_res / n),
    )


class ClockSkewEstimator:
    """Rolling clock-skew estimate for one AP.

    A TSF value lower than the previous one cannot come from the same running
    clock: the AP restarted (its TSF starts again from zero) or another device
    transmits with this BSSID. Mixing samples from both sides would produce a
    meaningless slope, so the estimate starts over.
    """

    def __init__(self, *, min_samples: int = 50, window_size: int = 300) -> None:
        if min_samples < 2:
            raise ValueError("min_samples must be at least 2")
        if window_size < min_samples:
            raise ValueError("window_size must be >= min_samples")
        self.min_samples = min_samples
        self.resets = 0
        self._samples: deque[tuple[float, float]] = deque(maxlen=window_size)

    def add(self, local_time_s: float, ap_tsf_us: int) -> None:
        if self._samples and ap_tsf_us < self._samples[-1][1]:
            self._samples.clear()
            self.resets += 1
        self._samples.append((local_time_s * 1_000_000.0, float(ap_tsf_us)))

    def estimate(self) -> LinearFit | None:
        if len(self._samples) < self.min_samples:
            return None
        # Rebase on the first sample: raw values are ~1e15 and would lose
        # precision in the squared sums.
        x0, y0 = self._samples[0]
        return fit_line(
            [x - x0 for x, _ in self._samples],
            [y - y0 for _, y in self._samples],
        )

    def __len__(self) -> int:
        return len(self._samples)
