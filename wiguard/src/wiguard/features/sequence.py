"""802.11 sequence-number analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass


SEQUENCE_MODULUS = 4096


@dataclass(frozen=True)
class SequenceAnalysis:
    samples: int
    last_sequence_number: int | None
    duplicate_count: int
    wrap_count: int
    reset_count: int
    large_gap_count: int
    max_forward_gap: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class SequenceAnalyzer:
    """Track sequence-number continuity for one BSSID."""

    def __init__(self, *, large_gap_threshold: int = 32) -> None:
        self.large_gap_threshold = large_gap_threshold
        self.samples = 0
        self.last_sequence_number: int | None = None
        self.duplicate_count = 0
        self.wrap_count = 0
        self.reset_count = 0
        self.large_gap_count = 0
        self.max_forward_gap = 0

    def add(self, sequence_number: int | None) -> SequenceAnalysis:
        if sequence_number is None:
            return self.summary()
        sequence_number = sequence_number % SEQUENCE_MODULUS
        self.samples += 1
        if self.last_sequence_number is None:
            self.last_sequence_number = sequence_number
            return self.summary()

        previous = self.last_sequence_number
        forward_gap = (sequence_number - previous) % SEQUENCE_MODULUS
        if forward_gap == 0:
            self.duplicate_count += 1
        elif sequence_number < previous and _looks_like_wrap(previous, sequence_number):
            self.wrap_count += 1
            self.max_forward_gap = max(self.max_forward_gap, forward_gap)
        elif sequence_number < previous:
            self.reset_count += 1
        else:
            self.max_forward_gap = max(self.max_forward_gap, forward_gap)
            if forward_gap > self.large_gap_threshold:
                self.large_gap_count += 1
        self.last_sequence_number = sequence_number
        return self.summary()

    def summary(self) -> SequenceAnalysis:
        return SequenceAnalysis(
            samples=self.samples,
            last_sequence_number=self.last_sequence_number,
            duplicate_count=self.duplicate_count,
            wrap_count=self.wrap_count,
            reset_count=self.reset_count,
            large_gap_count=self.large_gap_count,
            max_forward_gap=self.max_forward_gap,
        )


def _looks_like_wrap(previous: int, current: int) -> bool:
    return previous >= 3500 and current <= 600
