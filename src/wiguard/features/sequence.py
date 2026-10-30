"""802.11 sequence-number continuity.

Each transmitter numbers its frames with a 12-bit counter (0..4095) that only
moves forward and wraps around. A counter that jumps backwards means the
device restarted, or that a second device is transmitting with the same BSSID.

Direction is decided with serial-number arithmetic (RFC 1982): a step of less
than half the counter range forward is forward progress (possibly across the
wrap), anything else is a backward jump.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

SEQUENCE_MODULUS = 4096
_HALF_RANGE = SEQUENCE_MODULUS // 2


def forward_distance(previous: int, current: int) -> int:
    return (current - previous) % SEQUENCE_MODULUS


def is_backward_jump(previous: int, current: int) -> bool:
    return forward_distance(previous, current) > _HALF_RANGE


@dataclass(frozen=True, slots=True)
class SequenceStats:
    samples: int
    duplicates: int
    wraps: int
    backward_jumps: int
    large_gaps: int
    max_forward_gap: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


class SequenceAnalyzer:
    """Track sequence-number continuity for one BSSID."""

    def __init__(self, *, large_gap_threshold: int = 32) -> None:
        self.large_gap_threshold = large_gap_threshold
        self._last: int | None = None
        self._samples = 0
        self._duplicates = 0
        self._wraps = 0
        self._backward_jumps = 0
        self._large_gaps = 0
        self._max_forward_gap = 0

    def add(self, sequence_number: int) -> None:
        current = sequence_number % SEQUENCE_MODULUS
        self._samples += 1
        previous, self._last = self._last, current
        if previous is None:
            return
        gap = forward_distance(previous, current)
        if gap == 0:
            self._duplicates += 1
        elif gap > _HALF_RANGE:
            self._backward_jumps += 1
        else:
            if current < previous:
                self._wraps += 1
            self._max_forward_gap = max(self._max_forward_gap, gap)
            if gap > self.large_gap_threshold:
                self._large_gaps += 1

    def stats(self) -> SequenceStats:
        return SequenceStats(
            samples=self._samples,
            duplicates=self._duplicates,
            wraps=self._wraps,
            backward_jumps=self._backward_jumps,
            large_gaps=self._large_gaps,
            max_forward_gap=self._max_forward_gap,
        )
