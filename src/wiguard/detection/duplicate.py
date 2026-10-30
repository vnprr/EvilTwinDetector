"""Detect two transmitters that use the same BSSID at the same time.

A twin that copies the victim's MAC address is invisible to any check based on
names and addresses. It still cannot copy the victim's hardware clock or its
radio channel at the same moment, which leaves two observable traces:

* **Two clocks.** Fitting the BSSID's TSF timestamps against local time
  normally yields one line. Two devices yield two tight, separated bands of
  residuals. To tell a twin from an AP restart (which also produces two bands,
  one after the other), the bands must *interleave in time*.
* **Two channels.** One radio uses one channel. The same BSSID beaconing on two
  channels during overlapping time spans means two radios.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from statistics import mean

from wiguard.features import BeaconFrame, LinearFit, fit_line, is_backward_jump

from .events import DetectionEvent, Module, Severity, Signal


@dataclass(frozen=True, slots=True)
class _Sample:
    time_us: float
    tsf_us: float | None
    channel: int | None
    sequence_number: int | None
    rssi_dbm: int | None
    ie_hash: str | None
    ssid: str


@dataclass(frozen=True, slots=True)
class _ClockSplit:
    lower: tuple[_Sample, ...]
    upper: tuple[_Sample, ...]
    gap_us: float
    lower_fit: LinearFit
    upper_fit: LinearFit


class DuplicateBSSIDDetector:
    def __init__(
        self,
        *,
        window_size: int = 300,
        min_samples: int = 30,
        min_cluster_samples: int = 8,
        residual_gap_us: float = 10_000.0,
        separation_factor: float = 4.0,
        min_transitions: int = 4,
        rssi_split_db: float = 10.0,
    ) -> None:
        if min_cluster_samples < 2:
            raise ValueError("min_cluster_samples must be at least 2")
        if min_samples < 2 * min_cluster_samples:
            raise ValueError("min_samples must be at least twice min_cluster_samples")
        self.min_samples = min_samples
        self.min_cluster_samples = min_cluster_samples
        self.residual_gap_us = residual_gap_us
        self.separation_factor = separation_factor
        self.min_transitions = min_transitions
        self.rssi_split_db = rssi_split_db
        self._samples: defaultdict[str, deque[_Sample]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

    def add(self, frame: BeaconFrame) -> None:
        self._samples[frame.bssid].append(
            _Sample(
                time_us=frame.timestamp * 1_000_000.0,
                tsf_us=float(frame.ap_tsf_us) if frame.ap_tsf_us is not None else None,
                channel=frame.channel,
                sequence_number=frame.sequence_number,
                rssi_dbm=frame.rssi_dbm,
                ie_hash=frame.ie.hash if frame.kind == "beacon" else None,
                ssid=frame.ssid,
            )
        )

    def evaluate(self) -> list[DetectionEvent]:
        events = []
        for bssid, window in sorted(self._samples.items()):
            samples = tuple(window)
            signals = [
                signal
                for signal in (self._channel_conflict(samples), *self._clock_signals(samples))
                if signal is not None
            ]
            if signals:
                events.append(
                    DetectionEvent(
                        module=Module.IDENTITY,
                        bssid=bssid,
                        ssid=_dominant_ssid(samples),
                        signals=tuple(signals),
                        last_seen=samples[-1].time_us / 1_000_000.0,
                        context={"detector": "duplicate_bssid", "samples": len(samples)},
                    )
                )
        return events

    def _channel_conflict(self, samples: Sequence[_Sample]) -> Signal | None:
        by_channel: defaultdict[int, list[float]] = defaultdict(list)
        for sample in samples:
            if sample.channel is not None:
                by_channel[sample.channel].append(sample.time_us)
        busy = sorted(
            (item for item in by_channel.items() if len(item[1]) >= self.min_cluster_samples),
            key=lambda item: len(item[1]),
            reverse=True,
        )
        if len(busy) < 2:
            return None
        (channel_a, first), (channel_b, second) = busy[0], busy[1]
        overlap_us = min(first[-1], second[-1]) - max(first[0], second[0])
        if overlap_us <= 0:
            return None  # one channel after the other: a legitimate channel switch
        channels = sorted((channel_a, channel_b))
        return Signal(
            name="duplicate_bssid_channel_conflict",
            severity=Severity.HIGH,
            message="The BSSID beacons on two channels at the same time",
            details={
                "channels": channels,
                "overlap_s": round(overlap_us / 1_000_000.0, 3),
                "samples_per_channel": {str(ch): len(by_channel[ch]) for ch in channels},
            },
        )

    def _clock_signals(self, samples: Sequence[_Sample]) -> list[Signal | None]:
        timed = [sample for sample in samples if sample.tsf_us is not None]
        if len(timed) < self.min_samples:
            return []
        split = self._split_clocks(timed)
        if split is None:
            return []
        labels = {id(sample): "lower" for sample in split.lower}
        labels.update({id(sample): "upper" for sample in split.upper})
        transitions = sum(
            1
            for previous, current in pairwise(timed)
            if labels[id(previous)] != labels[id(current)]
        )
        if transitions < self.min_transitions:
            return []  # two clocks one after another: an AP restart, not a twin
        clock_signal = Signal(
            name="duplicate_bssid_clock_split",
            severity=Severity.HIGH,
            message="Two interleaved clocks transmit with this BSSID",
            details={
                "samples": len(timed),
                "cluster_sizes": [len(split.lower), len(split.upper)],
                "residual_gap_us": round(split.gap_us, 1),
                "threshold_us": self.residual_gap_us,
                "skews_ppm": [
                    round(split.lower_fit.skew_ppm, 3),
                    round(split.upper_fit.skew_ppm, 3),
                ],
                "cluster_transitions": transitions,
            },
        )
        return [
            clock_signal,
            _sequence_conflict(timed, labels),
            self._rssi_split(split),
            _ie_split(split),
        ]

    def _split_clocks(self, samples: Sequence[_Sample]) -> _ClockSplit | None:
        """Split the residuals of one global TSF fit at their largest gap."""

        x0, y0 = samples[0].time_us, samples[0].tsf_us or 0.0
        xs = [sample.time_us - x0 for sample in samples]
        ys = [(sample.tsf_us or 0.0) - y0 for sample in samples]
        fit = fit_line(xs, ys)
        if fit is None:
            return None
        ranked = sorted(
            zip((y - fit.predict(x) for x, y in zip(xs, ys, strict=True)), samples, strict=True),
            key=lambda item: item[0],
        )
        gap, index = max((ranked[i + 1][0] - ranked[i][0], i) for i in range(len(ranked) - 1))
        lower = tuple(sample for _, sample in ranked[: index + 1])
        upper = tuple(sample for _, sample in ranked[index + 1 :])
        if min(len(lower), len(upper)) < self.min_cluster_samples or gap < self.residual_gap_us:
            return None
        lower_fit, upper_fit = _cluster_fit(lower, x0, y0), _cluster_fit(upper, x0, y0)
        if lower_fit is None or upper_fit is None:
            return None
        # Each band must be a tight line of its own, far narrower than the gap
        # between the bands; otherwise the "gap" is just noise.
        spread = max(lower_fit.residual_stddev_us, upper_fit.residual_stddev_us)
        if gap < self.separation_factor * spread:
            return None
        return _ClockSplit(lower, upper, gap, lower_fit, upper_fit)

    def _rssi_split(self, split: _ClockSplit) -> Signal | None:
        lower = [s.rssi_dbm for s in split.lower if s.rssi_dbm is not None]
        upper = [s.rssi_dbm for s in split.upper if s.rssi_dbm is not None]
        if not lower or not upper:
            return None
        delta = mean(upper) - mean(lower)
        if abs(delta) < self.rssi_split_db:
            return None
        return Signal(
            name="duplicate_bssid_rssi_split",
            severity=Severity.MEDIUM,
            message="The two clocks arrive with clearly different signal strength",
            details={
                "avg_rssi_dbm": [round(mean(lower), 1), round(mean(upper), 1)],
                "delta_db": round(delta, 1),
                "threshold_db": self.rssi_split_db,
            },
        )


def _cluster_fit(samples: Sequence[_Sample], x0: float, y0: float) -> LinearFit | None:
    return fit_line(
        [sample.time_us - x0 for sample in samples],
        [(sample.tsf_us or 0.0) - y0 for sample in samples],
    )


def _sequence_conflict(samples: Sequence[_Sample], labels: dict[int, str]) -> Signal | None:
    """Count backward sequence jumps that happen exactly when the clock switches."""

    jumps = sum(
        1
        for previous, current in pairwise(samples)
        if labels[id(previous)] != labels[id(current)]
        and previous.sequence_number is not None
        and current.sequence_number is not None
        and is_backward_jump(previous.sequence_number, current.sequence_number)
    )
    if not jumps:
        return None
    return Signal(
        name="duplicate_bssid_sequence_conflict",
        severity=Severity.MEDIUM,
        message="Sequence numbers jump backwards whenever the other clock transmits",
        details={"backward_jumps_at_switch": jumps},
    )


def _ie_split(split: _ClockSplit) -> Signal | None:
    lower, upper = _dominant_ie(split.lower), _dominant_ie(split.upper)
    if lower is None or upper is None or lower == upper:
        return None
    return Signal(
        name="duplicate_bssid_ie_split",
        severity=Severity.HIGH,
        message="The two clocks also carry different IE fingerprints",
        details={"ie_fingerprints": [lower, upper]},
    )


def _dominant_ie(samples: Sequence[_Sample]) -> str | None:
    hashes = Counter(sample.ie_hash for sample in samples if sample.ie_hash)
    return hashes.most_common(1)[0][0] if hashes else None


def _dominant_ssid(samples: Sequence[_Sample]) -> str:
    names = Counter(sample.ssid for sample in samples if sample.ssid)
    return names.most_common(1)[0][0] if names else ""
