"""Property-based tests: invariants that must hold for *any* input, not just chosen examples."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap
from scapy.packet import Raw

from builders import START, deauth, event
from wiguard.correlation import CorrelationEngine
from wiguard.detection import Module, Severity
from wiguard.features import DisruptionCounter, fit_line, is_backward_jump, parse_frame

ENGINE = CorrelationEngine()
BSSID = "aa:bb:cc:dd:ee:ff"

elements = st.lists(st.tuples(st.integers(0, 255), st.binary(max_size=255)), max_size=12)
evidence = st.lists(
    st.builds(
        event,
        st.sampled_from(list(Module)),
        st.sampled_from(list(Severity)),
        bssid=st.just("aa:aa:aa:aa:aa:aa"),
    ),
    max_size=6,
)


def beacon_with_ie_area(raw: bytes):
    packet = RadioTap(
        bytes(
            RadioTap()
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID)
            / Dot11Beacon(timestamp=1)
            / Raw(load=raw)
        )
    )
    packet.time = START
    return packet


@given(st.binary(max_size=400))
def test_parser_survives_arbitrary_ie_bytes(raw: bytes) -> None:
    frame = parse_frame(beacon_with_ie_area(raw))
    assert frame is not None and frame.bssid == BSSID


@given(elements)
def test_well_formed_ies_are_all_recovered(pairs: list[tuple[int, bytes]]) -> None:
    raw = b"".join(bytes([element_id, len(body)]) + body for element_id, body in pairs)
    frame = parse_frame(beacon_with_ie_area(raw))
    assert frame is not None
    stable = [element_id for element_id, _ in pairs if element_id not in {5, 11, 37, 40}]
    assert list(frame.ie.ie_ids) == stable


@given(st.integers(0, 4095), st.integers(1, 4095))
def test_sequence_direction_follows_serial_number_arithmetic(start: int, step: int) -> None:
    assert is_backward_jump(start, (start + step) % 4096) == (step > 2048)


@given(st.floats(0.999, 1.001), st.floats(-1e9, 1e9), st.integers(3, 50), st.floats(1e4, 1e6))
def test_fit_line_recovers_an_exact_line(
    slope: float, intercept: float, points: int, spacing: float
) -> None:
    xs = [i * spacing for i in range(points)]
    fit = fit_line(xs, [slope * x + intercept for x in xs])
    assert fit is not None
    assert fit.slope == pytest.approx(slope, rel=1e-9, abs=1e-12)


@given(evidence)
def test_score_is_bounded(events) -> None:
    assert 0.0 <= ENGINE.score(events) <= 1.0


@given(evidence, evidence)
def test_more_evidence_never_lowers_the_score(events, more) -> None:
    assert ENGINE.score(events + more) >= ENGINE.score(events)


@given(evidence)
def test_score_does_not_depend_on_event_order(events) -> None:
    assert ENGINE.score(events) == ENGINE.score(list(reversed(events)))


@given(st.lists(st.tuples(st.floats(0, 60), st.booleans()), min_size=1, max_size=200))
def test_disruption_rates_add_up(frames: list[tuple[float, bool]]) -> None:
    counter = DisruptionCounter(window_seconds=10.0)
    for offset, broadcast in sorted(frames):
        destination = "ff:ff:ff:ff:ff:ff" if broadcast else "00:00:00:00:00:01"
        stats = counter.add(deauth(START + offset, destination=destination))
    assert stats.broadcast_rate_per_s >= 0 and stats.unicast_rate_per_s >= 0
    assert stats.rate_per_s == pytest.approx(stats.broadcast_rate_per_s + stats.unicast_rate_per_s)
    assert stats.total == len(frames)
