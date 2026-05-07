"""Simultaneous duplicate-BSSID detection from rolling TSF samples."""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from statistics import mean

from wiguard.features import APFeatureVector

from .identity import IdentityAlert, IdentitySignal


@dataclass(frozen=True)
class DuplicateBSSIDSample:
    ssid: str
    bssid: str
    local_time_us: float
    ap_tsf_us: float
    sequence_number: int | None
    rssi_dbm: int | None
    ie_fingerprint_hash: str


@dataclass(frozen=True)
class _LinearFit:
    sample_count: int
    slope: float
    skew_ppm: float
    intercept_us: float
    residual_stddev_us: float


class DuplicateBSSIDDetector:
    """Detect two simultaneous transmitters that reuse one BSSID.

    The v1 heuristic intentionally avoids heavyweight clustering dependencies:
    fit one TSF-vs-local-time line, split residuals at the largest gap, and only
    alert when that split has an independent confirmation signal.
    """

    def __init__(
        self,
        *,
        window_size: int = 300,
        min_samples: int = 30,
        min_cluster_samples: int = 8,
        residual_gap_threshold_us: float = 10_000.0,
        clock_skew_delta_ppm: float = 5.0,
        intercept_delta_threshold_us: float = 10_000.0,
        rssi_delta_db: float = 10.0,
        sequence_transition_threshold: int = 4,
    ) -> None:
        if min_cluster_samples < 2:
            raise ValueError("min_cluster_samples must be at least 2")
        if min_samples < min_cluster_samples * 2:
            raise ValueError("min_samples must be at least twice min_cluster_samples")
        self.window_size = window_size
        self.min_samples = min_samples
        self.min_cluster_samples = min_cluster_samples
        self.residual_gap_threshold_us = residual_gap_threshold_us
        self.clock_skew_delta_ppm = clock_skew_delta_ppm
        self.intercept_delta_threshold_us = intercept_delta_threshold_us
        self.rssi_delta_db = rssi_delta_db
        self.sequence_transition_threshold = sequence_transition_threshold
        self._samples: defaultdict[str, deque[DuplicateBSSIDSample]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

    def update(self, vector: APFeatureVector) -> IdentityAlert | None:
        sample = _sample_from_vector(vector)
        if sample is None:
            return None
        self._samples[sample.bssid].append(sample)
        return self.alert_for(sample.bssid)

    def alerts(self) -> list[IdentityAlert]:
        alerts = [
            alert
            for bssid in sorted(self._samples)
            if (alert := self.alert_for(bssid)) is not None and alert.triggered
        ]
        return sorted(alerts, key=lambda alert: (-alert.score, alert.ssid, alert.bssid))

    def alert_for(self, bssid: str) -> IdentityAlert | None:
        samples = tuple(self._samples.get(bssid.lower(), ()))
        if len(samples) < self.min_samples:
            return None
        candidate = _split_by_largest_residual_gap(samples)
        if candidate is None:
            return None
        lower_cluster, upper_cluster, residual_gap_us, all_fit, lower_fit, upper_fit = candidate
        if len(lower_cluster) < self.min_cluster_samples or len(upper_cluster) < self.min_cluster_samples:
            return None
        if residual_gap_us < self.residual_gap_threshold_us:
            return None

        signals = [
            IdentitySignal(
                name="duplicate_bssid_residual_clusters",
                severity="high",
                message="One BSSID has two separated TSF residual clusters",
                details={
                    "samples": len(samples),
                    "lower_cluster_samples": len(lower_cluster),
                    "upper_cluster_samples": len(upper_cluster),
                    "residual_gap_us": round(residual_gap_us, 3),
                    "threshold_us": self.residual_gap_threshold_us,
                    "global_skew_ppm": round(all_fit.skew_ppm, 3),
                    "global_residual_stddev_us": round(all_fit.residual_stddev_us, 3),
                },
            )
        ]
        confirmation_signals = self._confirmation_signals(
            all_samples=samples,
            lower_cluster=lower_cluster,
            upper_cluster=upper_cluster,
            lower_fit=lower_fit,
            upper_fit=upper_fit,
        )
        if not confirmation_signals:
            return None
        signals.extend(confirmation_signals)
        score = min(1.0, sum(_signal_weight(signal) for signal in signals))
        ssid = _dominant_ssid(samples)
        return IdentityAlert(
            bssid=bssid.lower(),
            ssid=ssid,
            score=round(score, 3),
            signals=tuple(signals),
        )

    def _confirmation_signals(
        self,
        *,
        all_samples: tuple[DuplicateBSSIDSample, ...],
        lower_cluster: tuple[DuplicateBSSIDSample, ...],
        upper_cluster: tuple[DuplicateBSSIDSample, ...],
        lower_fit: _LinearFit,
        upper_fit: _LinearFit,
    ) -> list[IdentitySignal]:
        signals: list[IdentitySignal] = []
        skew_delta_ppm = upper_fit.skew_ppm - lower_fit.skew_ppm
        intercept_delta_us = upper_fit.intercept_us - lower_fit.intercept_us
        if (
            abs(skew_delta_ppm) >= self.clock_skew_delta_ppm
            or abs(intercept_delta_us) >= self.intercept_delta_threshold_us
        ):
            signals.append(
                IdentitySignal(
                    name="duplicate_bssid_clock_profile_split",
                    severity="high",
                    message="Residual clusters have distinct clock profiles",
                    details={
                        "lower_skew_ppm": round(lower_fit.skew_ppm, 3),
                        "upper_skew_ppm": round(upper_fit.skew_ppm, 3),
                        "delta_skew_ppm": round(skew_delta_ppm, 3),
                        "skew_threshold_ppm": self.clock_skew_delta_ppm,
                        "lower_intercept_us": round(lower_fit.intercept_us, 3),
                        "upper_intercept_us": round(upper_fit.intercept_us, 3),
                        "delta_intercept_us": round(intercept_delta_us, 3),
                        "intercept_threshold_us": self.intercept_delta_threshold_us,
                    },
                )
            )

        sequence_signal = self._sequence_signal(all_samples, lower_cluster, upper_cluster)
        if sequence_signal is not None:
            signals.append(sequence_signal)

        rssi_signal = self._rssi_signal(lower_cluster, upper_cluster)
        if rssi_signal is not None:
            signals.append(rssi_signal)

        ie_signal = self._ie_signal(lower_cluster, upper_cluster)
        if ie_signal is not None:
            signals.append(ie_signal)
        return signals

    def _sequence_signal(
        self,
        samples: tuple[DuplicateBSSIDSample, ...],
        lower_cluster: tuple[DuplicateBSSIDSample, ...],
        upper_cluster: tuple[DuplicateBSSIDSample, ...],
    ) -> IdentitySignal | None:
        lower_set = set(lower_cluster)
        upper_set = set(upper_cluster)
        timeline = sorted(samples, key=lambda sample: sample.local_time_us)
        transitions = 0
        backward_jumps = 0
        previous_label = None
        previous_sequence = None
        for sample in timeline:
            if sample in lower_set:
                label = "lower"
            elif sample in upper_set:
                label = "upper"
            else:
                continue
            if previous_label is not None and label != previous_label:
                transitions += 1
            if sample.sequence_number is not None and previous_sequence is not None:
                if sample.sequence_number < previous_sequence and not _looks_like_wrap(
                    previous_sequence,
                    sample.sequence_number,
                ):
                    backward_jumps += 1
            if sample.sequence_number is not None:
                previous_sequence = sample.sequence_number
            previous_label = label
        if transitions < self.sequence_transition_threshold or backward_jumps < 1:
            return None
        return IdentitySignal(
            name="duplicate_bssid_sequence_interleaving",
            severity="medium",
            message="Sequence numbers interleave across residual clusters",
            details={
                "cluster_transitions": transitions,
                "transition_threshold": self.sequence_transition_threshold,
                "backward_sequence_jumps": backward_jumps,
            },
        )

    def _rssi_signal(
        self,
        lower_cluster: tuple[DuplicateBSSIDSample, ...],
        upper_cluster: tuple[DuplicateBSSIDSample, ...],
    ) -> IdentitySignal | None:
        lower_rssi = [sample.rssi_dbm for sample in lower_cluster if sample.rssi_dbm is not None]
        upper_rssi = [sample.rssi_dbm for sample in upper_cluster if sample.rssi_dbm is not None]
        if not lower_rssi or not upper_rssi:
            return None
        lower_mean = mean(lower_rssi)
        upper_mean = mean(upper_rssi)
        delta_db = upper_mean - lower_mean
        if abs(delta_db) < self.rssi_delta_db:
            return None
        return IdentitySignal(
            name="duplicate_bssid_rssi_split",
            severity="medium",
            message="Residual clusters have distinct RSSI profiles",
            details={
                "lower_avg_rssi_dbm": round(lower_mean, 2),
                "upper_avg_rssi_dbm": round(upper_mean, 2),
                "delta_db": round(delta_db, 2),
                "threshold_db": self.rssi_delta_db,
            },
        )

    def _ie_signal(
        self,
        lower_cluster: tuple[DuplicateBSSIDSample, ...],
        upper_cluster: tuple[DuplicateBSSIDSample, ...],
    ) -> IdentitySignal | None:
        lower_hash = _dominant_ie_hash(lower_cluster)
        upper_hash = _dominant_ie_hash(upper_cluster)
        if lower_hash is None or upper_hash is None or lower_hash == upper_hash:
            return None
        return IdentitySignal(
            name="duplicate_bssid_ie_split",
            severity="high",
            message="Residual clusters have different IE fingerprints",
            details={
                "lower_dominant_ie_fingerprint": lower_hash,
                "upper_dominant_ie_fingerprint": upper_hash,
            },
        )


def _sample_from_vector(vector: APFeatureVector) -> DuplicateBSSIDSample | None:
    if vector.ap_tsf is None or vector.observed_monotonic <= 0:
        return None
    return DuplicateBSSIDSample(
        ssid=vector.ssid,
        bssid=vector.bssid.lower(),
        local_time_us=vector.clock_local_time_us,
        ap_tsf_us=float(vector.ap_tsf),
        sequence_number=vector.sequence_number,
        rssi_dbm=vector.rssi_dbm,
        ie_fingerprint_hash=vector.ie_fingerprint.hash,
    )


def _split_by_largest_residual_gap(
    samples: tuple[DuplicateBSSIDSample, ...],
) -> tuple[
    tuple[DuplicateBSSIDSample, ...],
    tuple[DuplicateBSSIDSample, ...],
    float,
    _LinearFit,
    _LinearFit,
    _LinearFit,
] | None:
    reference_x = samples[0].local_time_us
    reference_y = samples[0].ap_tsf_us
    all_fit = _fit(samples, reference_x=reference_x, reference_y=reference_y)
    if all_fit is None:
        return None
    residuals = [
        (
            _residual(
                sample,
                fit=all_fit,
                reference_x=reference_x,
                reference_y=reference_y,
            ),
            sample,
        )
        for sample in samples
    ]
    ordered = sorted(residuals, key=lambda item: item[0])
    gaps = [
        (ordered[index + 1][0] - ordered[index][0], index)
        for index in range(len(ordered) - 1)
    ]
    if not gaps:
        return None
    residual_gap_us, split_index = max(gaps, key=lambda item: item[0])
    lower_cluster = tuple(sample for _, sample in ordered[: split_index + 1])
    upper_cluster = tuple(sample for _, sample in ordered[split_index + 1 :])
    lower_fit = _fit(lower_cluster, reference_x=reference_x, reference_y=reference_y)
    upper_fit = _fit(upper_cluster, reference_x=reference_x, reference_y=reference_y)
    if lower_fit is None or upper_fit is None:
        return None
    return lower_cluster, upper_cluster, residual_gap_us, all_fit, lower_fit, upper_fit


def _fit(
    samples: tuple[DuplicateBSSIDSample, ...],
    *,
    reference_x: float,
    reference_y: float,
) -> _LinearFit | None:
    if len(samples) < 2:
        return None
    xs = [sample.local_time_us - reference_x for sample in samples]
    ys = [sample.ap_tsf_us - reference_y for sample in samples]
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
    residual_stddev = math.sqrt(sum(value * value for value in residuals) / len(residuals))
    return _LinearFit(
        sample_count=len(samples),
        slope=slope,
        skew_ppm=(slope - 1.0) * 1_000_000.0,
        intercept_us=intercept,
        residual_stddev_us=residual_stddev,
    )


def _residual(
    sample: DuplicateBSSIDSample,
    *,
    fit: _LinearFit,
    reference_x: float,
    reference_y: float,
) -> float:
    x = sample.local_time_us - reference_x
    y = sample.ap_tsf_us - reference_y
    return y - (fit.slope * x + fit.intercept_us)


def _dominant_ssid(samples: tuple[DuplicateBSSIDSample, ...]) -> str:
    return Counter(sample.ssid for sample in samples).most_common(1)[0][0]


def _dominant_ie_hash(samples: tuple[DuplicateBSSIDSample, ...]) -> str | None:
    hashes = [sample.ie_fingerprint_hash for sample in samples if sample.ie_fingerprint_hash]
    if not hashes:
        return None
    return Counter(hashes).most_common(1)[0][0]


def _looks_like_wrap(previous: int, current: int) -> bool:
    return previous >= 3500 and current <= 600


def _signal_weight(signal: IdentitySignal) -> float:
    if signal.name == "duplicate_bssid_residual_clusters":
        return 0.35
    if signal.severity == "high":
        return 0.3
    if signal.severity == "medium":
        return 0.2
    return 0.1
