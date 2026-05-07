from __future__ import annotations

import unittest

from wiguard.correlation import CorrelationEngine, events_from_alerts
from wiguard.detection import (
    DeauthStormAlert,
    DeauthStormSignal,
    EnvironmentAnomalyAlert,
    EnvironmentSignal,
    IdentityAlert,
    IdentitySignal,
)


def deauth_alert() -> DeauthStormAlert:
    return DeauthStormAlert(
        bssid="aa:bb:cc:dd:ee:ff",
        channel=6,
        frame_type="deauthentication",
        score=0.45,
        signals=(
            DeauthStormSignal(
                name="broadcast_flood",
                severity="high",
                message="Broadcast flood",
                details={"rate_per_second": 12.0},
            ),
        ),
    )


def environment_alert() -> EnvironmentAnomalyAlert:
    return EnvironmentAnomalyAlert(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="CorpNet",
        score=0.8,
        peer_count=4,
        signals=(
            EnvironmentSignal(
                name="same_ssid_ie_fingerprint_outlier",
                severity="high",
                message="IE fingerprint outlier",
                details={"peer_count": 4},
            ),
            EnvironmentSignal(
                name="same_ssid_vendor_oui_outlier",
                severity="high",
                message="Vendor outlier",
                details={"peer_count": 4},
            ),
        ),
    )


def identity_alert() -> IdentityAlert:
    return IdentityAlert(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="CorpNet",
        score=0.9,
        signals=(
            IdentitySignal(
                name="clock_skew_changed",
                severity="high",
                message="Clock skew changed",
                details={"delta_ppm": 9.2},
            ),
        ),
    )


class CorrelationEngineTest(unittest.TestCase):
    def test_correlates_deauth_and_environment_into_suspicious_alert(self) -> None:
        engine = CorrelationEngine()
        events = events_from_alerts(
            deauth_alerts=[deauth_alert()],
            environment_alerts=[environment_alert()],
            ssid_by_bssid={"aa:bb:cc:dd:ee:ff": "CorpNet"},
        )

        alerts = engine.correlate(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].classification, "suspicious")
        self.assertGreaterEqual(alerts[0].final_score, 0.45)
        self.assertEqual(
            alerts[0].contributing_modules,
            ("deauth_storm", "environment_anomaly"),
        )
        self.assertIn("management-frame storm", alerts[0].explanation)

    def test_escalates_three_independent_modules_to_evil_twin(self) -> None:
        engine = CorrelationEngine()
        events = events_from_alerts(
            identity_alerts=[identity_alert()],
            deauth_alerts=[deauth_alert()],
            environment_alerts=[environment_alert()],
        )

        alerts = engine.correlate(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].classification, "evil_twin")
        self.assertEqual(alerts[0].final_score, 1.0)
        self.assertEqual(
            alerts[0].contributing_modules,
            ("deauth_storm", "environment_anomaly", "identity_verification"),
        )

    def test_skips_events_below_minimum_final_score(self) -> None:
        engine = CorrelationEngine(min_final_score=0.9)
        events = events_from_alerts(deauth_alerts=[deauth_alert()])

        alerts = engine.correlate(events)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
