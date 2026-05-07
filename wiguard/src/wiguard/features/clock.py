"""Clock skew estimation from AP TSF samples."""

from __future__ import annotations

import math
from collections import deque
from dataclasses import asdict, dataclass

from .models import APFeatureVector


@dataclass(frozen=True)
class ClockSkewEstimate:
    sample_count: int
    slope: float
    skew_ppm: float
    # Intercept in the coordinate system rebased to the first sample.
    intercept_us: float
    r_squared: float
    residual_stddev_us: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ClockSkewEstimator:
    """Rolling least-squares estimator for TSF vs local monotonic time."""

    def __init__(self, *, min_samples: int = 50, window_size: int = 300) -> None:
        if min_samples < 2:
            raise ValueError("min_samples must be at least 2")
        if window_size < min_samples:
            raise ValueError("window_size must be >= min_samples")
        self.min_samples = min_samples
        self.window_size = window_size
        self._samples: deque[tuple[float, float]] = deque(maxlen=window_size)

    def add(self, feature: APFeatureVector) -> ClockSkewEstimate | None:
        if feature.has_clock_inputs and feature.ap_tsf is not None:
            self.add_sample(feature.clock_local_time_us, float(feature.ap_tsf))
        return self.estimate()

    def add_sample(self, local_time_us: float, ap_tsf_us: float) -> None:
        self._samples.append((local_time_us, ap_tsf_us))

    def estimate(self) -> ClockSkewEstimate | None:
        if len(self._samples) < self.min_samples:
            return None

        x0, y0 = self._samples[0]
        xs = [sample[0] - x0 for sample in self._samples]
        ys = [sample[1] - y0 for sample in self._samples]
        x_mean = sum(xs) / len(xs)
        y_mean = sum(ys) / len(ys)
        centered_x = [value - x_mean for value in xs]
        centered_y = [value - y_mean for value in ys]
        ss_xx = sum(value * value for value in centered_x)
        if ss_xx == 0:
            return None
        slope = sum(x * y for x, y in zip(centered_x, centered_y)) / ss_xx
        intercept = y_mean - slope * x_mean
        residuals = [y - (slope * x + intercept) for x, y in zip(xs, ys)]
        ss_res = sum(value * value for value in residuals)
        ss_tot = sum(value * value for value in centered_y)
        r_squared = 1.0 if ss_tot == 0 else 1.0 - (ss_res / ss_tot)
        residual_stddev = math.sqrt(ss_res / len(residuals))
        return ClockSkewEstimate(
            sample_count=len(self._samples),
            slope=slope,
            skew_ppm=(slope - 1.0) * 1_000_000.0,
            intercept_us=intercept,
            r_squared=r_squared,
            residual_stddev_us=residual_stddev,
        )

    def __len__(self) -> int:
        return len(self._samples)
