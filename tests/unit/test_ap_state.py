from __future__ import annotations

import unittest

from wiguard.capture.models import AccessPointObservation
from wiguard.state import APStateManager


class APStateManagerTest(unittest.TestCase):
    def test_aggregates_access_point_observations(self) -> None:
        manager = APStateManager(window_size=3)
        for index, rssi in enumerate((-50, -48, -46, -44), start=1):
            manager.update(
                AccessPointObservation(
                    frame_type="beacon",
                    observed_monotonic=float(index),
                    ssid="Lab",
                    bssid="aa:bb:cc:dd:ee:ff",
                    channel=1,
                    rssi_dbm=rssi,
                    ap_tsf=1000 * index,
                    radiotap_tsf=2000 * index,
                    sequence_number=index,
                    beacon_interval_tu=100,
                    capabilities=0x0411,
                )
            )

        summaries = manager.summaries()

        self.assertEqual(len(summaries), 1)
        summary = summaries[0]
        self.assertEqual(summary.frames, 4)
        self.assertEqual(summary.channels, (1,))
        self.assertEqual(summary.last_rssi_dbm, -44)
        self.assertEqual(summary.avg_rssi_dbm, -46.0)
        self.assertEqual(summary.clock_samples, 4)


if __name__ == "__main__":
    unittest.main()
