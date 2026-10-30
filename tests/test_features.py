from __future__ import annotations

import pytest
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11EltRSN,
    Dot11ProbeResp,
    RadioTap,
)

from builders import START, beacon, deauth, ie
from wiguard.features import (
    APTracker,
    BeaconFrame,
    BeaconTimingAnalyzer,
    ClockSkewEstimator,
    DisruptionCounter,
    DisruptionFrame,
    InformationElement,
    SequenceAnalyzer,
    build_ie_fingerprint,
    fit_line,
    frequency_to_channel,
    parse_frame,
)

BSSID = "aa:bb:cc:dd:ee:ff"


def radiotap(rssi: int = -42, frequency: int = 2437) -> RadioTap:
    return RadioTap(
        present="TSFT+Channel+dBm_AntSignal",
        mac_timestamp=1,
        ChannelFrequency=frequency,
        ChannelFlags="2GHz+CCK",
        dBm_AntSignal=rssi,
    )


def wire(packet, at: float = START):
    """Serialise and re-dissect, as a packet read from a pcap would be."""
    parsed = RadioTap(bytes(packet))
    parsed.time = at
    return parsed


# --- frame parsing -----------------------------------------------------------


def test_parses_a_beacon() -> None:
    packet = wire(
        radiotap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID, SC=0x1230)
        / Dot11Beacon(timestamp=987_654_321, beacon_interval=100, cap="ESS")
        / Dot11Elt(ID=0, info=b"TestNet")
        / Dot11Elt(ID=1, info=b"\x82\x84")
        / Dot11Elt(ID=3, info=bytes([6]))
        / Dot11EltRSN()
        / Dot11Elt(ID=221, info=b"\x00\x50\xf2\x02\x01\x01")
    )

    frame = parse_frame(packet)

    assert isinstance(frame, BeaconFrame)
    assert (frame.kind, frame.ssid, frame.bssid) == ("beacon", "TestNet", BSSID)
    assert (frame.channel, frame.rssi_dbm) == (6, -42)
    assert (frame.ap_tsf_us, frame.sequence_number, frame.beacon_interval_tu) == (
        987_654_321,
        0x123,
        100,
    )
    assert frame.timestamp == START
    assert frame.ie.ie_ids == (0, 1, 3, 48, 221)
    assert frame.ie.vendor_ouis == ("00:50:f2",)


def test_probe_response_hidden_ssid_and_channel_from_ht_operation() -> None:
    packet = wire(
        radiotap(frequency=5180)
        / Dot11(type=0, subtype=5, addr1="00:00:00:00:00:01", addr2=BSSID, addr3=BSSID)
        / Dot11ProbeResp(timestamp=5, beacon_interval=100)
        / Dot11Elt(ID=0, info=b"\x00\x00\x00")
        / Dot11Elt(ID=61, info=bytes([40]) + bytes(21))
    )

    frame = parse_frame(packet)

    assert isinstance(frame, BeaconFrame)
    assert frame.kind == "probe_response"
    assert frame.ssid == ""
    assert frame.channel == 40


def test_malformed_element_does_not_hide_the_following_ones() -> None:
    # An RSN element too short for Scapy's RSN dissector, followed by a vendor element.
    packet = wire(
        radiotap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID)
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=b"Net")
        / Dot11Elt(ID=48, info=b"\x01\x00\x00\x0f\xac\x04")
        / Dot11Elt(ID=221, info=b"\xaa\xbb\xcc\x01")
    )

    frame = parse_frame(packet)

    assert isinstance(frame, BeaconFrame)
    assert frame.ie.ie_ids == (0, 48, 221)
    assert frame.ie.vendor_ouis == ("aa:bb:cc",)


def test_parses_a_deauthentication_frame() -> None:
    packet = wire(
        radiotap()
        / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID)
        / Dot11Deauth(reason=7)
    )

    frame = parse_frame(packet)

    assert isinstance(frame, DisruptionFrame)
    assert (frame.kind, frame.bssid, frame.reason, frame.channel) == (
        "deauthentication",
        BSSID,
        7,
        6,
    )
    assert frame.is_broadcast


def test_ignores_other_frames() -> None:
    assert parse_frame(wire(radiotap() / Dot11(type=2, subtype=0))) is None


@pytest.mark.parametrize(
    ("frequency", "channel"),
    [(2412, 1), (2472, 13), (2484, 14), (5180, 36), (5825, 165), (900, None)],
)
def test_frequency_to_channel(frequency: int, channel: int | None) -> None:
    assert frequency_to_channel(frequency) == channel


# --- IE fingerprint -------------------------------------------------------------


def elements(*pairs: tuple[int, bytes]) -> tuple[InformationElement, ...]:
    return tuple(InformationElement(id=i, body=body) for i, body in pairs)


def test_fingerprint_ignores_elements_that_change_every_beacon() -> None:
    base = [(0, b"Net"), (1, b"\x82\x84"), (48, b"\x01\x00")]
    with_tim = build_ie_fingerprint(elements(*base, (5, b"\x00\x01\x00\x00")))
    other_tim = build_ie_fingerprint(elements(*base, (5, b"\x01\x02\x00\x00")))
    assert with_tim.hash == other_tim.hash
    assert 5 not in with_tim.ie_ids


def test_fingerprint_changes_with_key_element_content() -> None:
    first = build_ie_fingerprint(elements((0, b"Net"), (1, b"\x82\x84")))
    second = build_ie_fingerprint(elements((0, b"Net"), (1, b"\x8c\x12")))
    assert first.hash != second.hash


# --- clock --------------------------------------------------------------------


def test_fit_line_is_exact_for_a_line() -> None:
    fit = fit_line([0.0, 1.0, 2.0, 3.0], [5.0, 7.0, 9.0, 11.0])
    assert fit is not None
    assert fit.slope == pytest.approx(2.0)
    assert fit.intercept_us == pytest.approx(5.0)
    assert fit.r_squared == pytest.approx(1.0)
    assert fit_line([1.0, 1.0], [2.0, 3.0]) is None


def test_clock_skew_estimate_recovers_the_skew() -> None:
    estimator = ClockSkewEstimator(min_samples=10, window_size=100)
    for frame in (beacon(i, skew_ppm=-12.5) for i in range(60)):
        estimator.add(frame.timestamp, frame.ap_tsf_us or 0)
    fit = estimator.estimate()
    assert fit is not None
    assert fit.skew_ppm == pytest.approx(-12.5, abs=0.1)


def test_clock_estimator_starts_over_when_tsf_goes_backwards() -> None:
    estimator = ClockSkewEstimator(min_samples=5, window_size=100)
    for i in range(10):
        estimator.add(START + i, 1_000_000 + i * 1_000_000)
    estimator.add(START + 10, 50)  # AP restarted: TSF back near zero
    assert estimator.resets == 1
    assert len(estimator) == 1
    assert estimator.estimate() is None


# --- sequence numbers and beacon timing -------------------------------------------------------


def test_sequence_analyzer_counts_wraps_backward_jumps_and_gaps() -> None:
    analyzer = SequenceAnalyzer(large_gap_threshold=10)
    for value in (10, 11, 11, 25, 4094, 2, 100, 20):
        analyzer.add(value)
    stats = analyzer.stats()
    assert stats.samples == 8
    assert stats.duplicates == 1  # 11 -> 11
    assert stats.wraps == 1  # 4094 -> 2
    assert stats.backward_jumps == 2  # 25 -> 4094 and 100 -> 20
    assert stats.large_gaps == 2  # 11 -> 25 and 2 -> 100


def test_beacon_timing_counts_missed_beacons_and_jitter() -> None:
    analyzer = BeaconTimingAnalyzer()
    interval_us = 100 * 1024
    for tsf in (0, interval_us, 3 * interval_us + 40, 4 * interval_us):
        analyzer.add(tsf, 100)
    stats = analyzer.stats()
    assert stats.beacon_interval_tu == 100
    assert stats.missed_beacons == 1
    assert stats.jitter_max_abs_us == 40


# --- AP profiles ------------------------------------------------------------------------


def test_tracker_aggregates_one_profile_per_bssid() -> None:
    tracker = APTracker(window_size=50, clock_min_samples=10)
    for i in range(30):
        tracker.add(beacon(i, rssi_dbm=-40 - i % 3, skew_ppm=4.0))
    tracker.add(beacon(30, ssid="", kind="probe_response", fingerprint=ie("probe")))

    (summary,) = tracker.summaries()
    assert summary.frames == 31
    assert summary.ssid == "HomeNet"  # a hidden-SSID frame does not rename the AP
    assert summary.dominant_ie_fingerprint == "ie-a"  # IE statistics use beacons only
    assert summary.ie_fingerprints == ("ie-a",)
    assert summary.avg_rssi_dbm == pytest.approx(-41.1, abs=0.05)
    assert summary.clock_skew_ppm == pytest.approx(4.0, abs=1.0)  # 3 s of µs timestamps
    assert summary.timing.beacon_interval_tu == 100
    assert summary.first_seen == START


# --- deauth/disassoc rates ---------------------------------------------------------------


def test_disruption_rates_use_a_sliding_window() -> None:
    counter = DisruptionCounter(window_seconds=10.0)
    for i in range(50):
        stats = counter.add(deauth(START + i * 0.1))
    assert stats.rate_per_s == pytest.approx(5.0)
    assert stats.broadcast_rate_per_s == pytest.approx(5.0)
    stats = counter.add(deauth(START + 30, destination="00:00:00:00:00:01"))
    assert stats.total == 51
    assert stats.rate_per_s == pytest.approx(0.1)  # the burst left the window
    assert stats.unicast_rate_per_s == pytest.approx(0.1)
