from __future__ import annotations

import json
from dataclasses import replace

import pytest

from builders import START, beacon, deauth, ie
from wiguard.detection import (
    DeauthStormDetector,
    DuplicateBSSIDDetector,
    EnvironmentAnomalyDetector,
    IdentityVerifier,
    Module,
    Severity,
    TrustedProfileStore,
    enroll,
)
from wiguard.features import APTracker, DisruptionCounter

HOME = "00:11:22:33:44:55"
TWIN = "02:de:ad:be:ef:01"


def summaries(*frames):
    tracker = APTracker(window_size=300, clock_min_samples=20)
    for frame in frames:
        tracker.add(frame)
    return tracker.summaries()


def names(events) -> set[str]:
    return {name for event in events for name in event.signal_names}


# --- identity verification against trusted profiles ---------------------------------


@pytest.fixture
def trusted():
    return enroll(summaries(*(beacon(i, skew_ppm=-7.0) for i in range(60))), min_frames=50)


def test_enroll_skips_aps_with_too_few_frames() -> None:
    aps = summaries(*(beacon(i) for i in range(60)), *(beacon(i, bssid=TWIN) for i in range(5)))
    assert [profile.bssid for profile in enroll(aps, min_frames=50)] == [HOME]


def test_same_ap_matches_its_profile(trusted) -> None:
    current = summaries(*(beacon(i, at=START + 900 + i * 0.1024, skew_ppm=-7.0) for i in range(60)))
    assert IdentityVerifier(trusted).evaluate(current) == []


def test_drift_from_the_profile_is_reported(trusted) -> None:
    current = summaries(
        *(beacon(i, skew_ppm=15.0, rssi_dbm=-70, fingerprint=ie("other")) for i in range(60))
    )
    (event,) = IdentityVerifier(trusted).evaluate(current)
    assert event.module is Module.IDENTITY
    assert {"ie_fingerprint_changed", "clock_skew_changed", "rssi_shifted"} <= set(
        event.signal_names
    )
    assert event.strength == Severity.HIGH.strength


def test_unknown_bssid_advertising_a_trusted_ssid_is_reported(trusted) -> None:
    current = summaries(*(beacon(i, bssid=TWIN) for i in range(20)))
    (event,) = IdentityVerifier(trusted).evaluate(current)
    assert (event.bssid, event.signal_names) == (TWIN, ("unknown_bssid_for_trusted_ssid",))


def test_unrelated_networks_and_short_sightings_are_ignored(trusted) -> None:
    current = summaries(
        *(beacon(i, bssid=TWIN, ssid="Neighbour") for i in range(20)),
        *(beacon(i, bssid="02:00:00:00:00:09") for i in range(3)),
    )
    assert IdentityVerifier(trusted, min_frames=10).evaluate(current) == []


def test_profile_store_round_trip(tmp_path, trusted) -> None:
    store = TrustedProfileStore(tmp_path / "profiles.json")
    assert store.load() == []
    store.save(trusted)
    assert store.load() == trusted


def test_profile_store_rejects_another_schema(tmp_path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"schema_version": 1, "baselines": []}))
    with pytest.raises(ValueError, match="re-run `wiguard enroll`"):
        TrustedProfileStore(path).load()


# --- duplicate BSSID ------------------------------------------------------------------


def duplicate_detector() -> DuplicateBSSIDDetector:
    return DuplicateBSSIDDetector(min_samples=20, min_cluster_samples=8)


def test_one_clock_is_quiet() -> None:
    detector = duplicate_detector()
    for i in range(60):
        detector.add(beacon(i, skew_ppm=3.0))
    assert detector.evaluate() == []


def test_two_interleaved_clocks_are_a_twin() -> None:
    detector = duplicate_detector()
    for i in range(30):
        detector.add(beacon(i, sequence_number=i))
        detector.add(
            beacon(i, at=START + i * 0.1024 + 0.05, tsf_offset_us=7e8, skew_ppm=20.0,
                   sequence_number=2000 + i, rssi_dbm=-70, fingerprint=ie("twin"))
        )  # fmt: skip

    (event,) = detector.evaluate()
    assert event.bssid == HOME
    assert set(event.signal_names) == {
        "duplicate_bssid_clock_split",
        "duplicate_bssid_sequence_conflict",
        "duplicate_bssid_rssi_split",
        "duplicate_bssid_ie_split",
    }


def test_restart_is_not_a_twin() -> None:
    # Two clean clock segments one after the other: the AP rebooted.
    detector = duplicate_detector()
    for i in range(30):
        detector.add(beacon(i))
    for i in range(30, 60):
        detector.add(beacon(i, tsf_offset_us=0, sequence_number=i - 30))
    assert detector.evaluate() == []


def test_same_bssid_on_two_channels_at_once() -> None:
    detector = duplicate_detector()
    for i in range(20):
        detector.add(beacon(i, channel=6))
        detector.add(beacon(i, at=START + i * 0.1024 + 0.05, channel=1))
    (event,) = detector.evaluate()
    assert event.signal_names == ("duplicate_bssid_channel_conflict",)


def test_channel_switch_is_not_a_conflict() -> None:
    detector = duplicate_detector()
    for i in range(20):
        detector.add(beacon(i, channel=6))
    for i in range(20, 40):
        detector.add(beacon(i, channel=11))
    assert detector.evaluate() == []


def test_duplicate_detector_validates_its_parameters() -> None:
    with pytest.raises(ValueError):
        DuplicateBSSIDDetector(min_samples=10, min_cluster_samples=8)


# --- deauthentication storms ---------------------------------------------------------


def run_storm(detector: DeauthStormDetector, start: float, frames: int, every: float) -> None:
    counter = DisruptionCounter(window_seconds=10.0)
    for i in range(frames):
        detector.add(counter.add(deauth(start + i * every)))


def test_a_flood_becomes_one_event() -> None:
    detector = DeauthStormDetector()
    run_storm(detector, START, frames=300, every=0.02)

    (event,) = detector.evaluate()
    assert event.module is Module.DEAUTH
    assert set(event.signal_names) == {"management_frame_rate_high", "broadcast_flood"}
    assert event.context["peak_rate_per_s"] >= 10


def test_a_trickle_is_not_a_storm() -> None:
    detector = DeauthStormDetector()
    run_storm(detector, START, frames=20, every=1.0)
    assert detector.evaluate() == []


def test_a_storm_after_a_quiet_gap_starts_a_new_episode() -> None:
    detector = DeauthStormDetector()
    run_storm(detector, START, frames=300, every=0.02)
    run_storm(detector, START + 600, frames=300, every=0.02)
    (event,) = detector.evaluate()
    assert event.context["first_seen"] >= START + 600


# --- environment (same-SSID peers) ------------------------------------------------------------


def corp(n: int, **kwargs):
    return [beacon(i, bssid=f"00:11:22:cc:00:0{n}", ssid="CorpNet", **kwargs) for i in range(10)]


def test_uniform_same_ssid_group_is_quiet() -> None:
    aps = summaries(*corp(1), *corp(2), *corp(3))
    assert EnvironmentAnomalyDetector().evaluate(aps) == []


def test_outlier_in_a_same_ssid_group() -> None:
    outlier = corp(4, fingerprint=ie("other", vendor="aa:bb:cc"), interval_tu=200)
    aps = summaries(*corp(1), *corp(2), *corp(3), *outlier)
    (event,) = EnvironmentAnomalyDetector().evaluate(aps)
    assert event.bssid == "00:11:22:cc:00:04"
    assert set(event.signal_names) == {
        "same_ssid_ie_fingerprint_outlier",
        "same_ssid_vendor_oui_outlier",
        "same_ssid_beacon_interval_outlier",
    }


def test_two_aps_are_too_few_for_a_majority() -> None:
    outlier = corp(2, fingerprint=ie("other", vendor="aa:bb:cc"))
    assert EnvironmentAnomalyDetector().evaluate(summaries(*corp(1), *outlier)) == []


def test_hidden_ssids_are_not_grouped() -> None:
    aps = summaries(*(replace(frame, ssid="") for n in (1, 2, 3) for frame in corp(n)))
    assert EnvironmentAnomalyDetector().evaluate(aps) == []
