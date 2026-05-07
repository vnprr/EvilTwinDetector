from __future__ import annotations

import unittest

from wiguard.features import ClockSkewEstimator


class ClockSkewEstimatorTest(unittest.TestCase):
    def test_estimates_positive_ppm_skew(self) -> None:
        estimator = ClockSkewEstimator(min_samples=5, window_size=10)
        estimate = None
        for index in range(5):
            local_us = index * 100_000.0
            ap_tsf = 50_000.0 + local_us * 1.000020
            estimator.add_sample(local_us, ap_tsf)
            estimate = estimator.estimate()

        self.assertIsNotNone(estimate)
        assert estimate is not None
        self.assertAlmostEqual(estimate.slope, 1.000020, places=6)
        self.assertAlmostEqual(estimate.skew_ppm, 20.0, places=2)
        self.assertGreater(estimate.r_squared, 0.999999)
        self.assertLess(estimate.residual_stddev_us, 0.001)


if __name__ == "__main__":
    unittest.main()
