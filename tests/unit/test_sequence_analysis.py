from __future__ import annotations

import unittest

from wiguard.features import SequenceAnalyzer


class SequenceAnalyzerTest(unittest.TestCase):
    def test_tracks_duplicates_gaps_wraps_and_resets(self) -> None:
        analyzer = SequenceAnalyzer(large_gap_threshold=10)
        for value in (10, 11, 11, 25, 4094, 2, 100):
            analyzer.add(value)
        summary = analyzer.add(20)

        self.assertEqual(summary.samples, 8)
        self.assertEqual(summary.duplicate_count, 1)
        self.assertEqual(summary.large_gap_count, 3)
        self.assertEqual(summary.wrap_count, 1)
        self.assertEqual(summary.reset_count, 1)
        self.assertEqual(summary.last_sequence_number, 20)


if __name__ == "__main__":
    unittest.main()
