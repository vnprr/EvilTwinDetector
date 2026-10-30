from __future__ import annotations

import pytest

from builders import event
from wiguard.correlation import Classification, CorrelationEngine
from wiguard.detection import Module, Severity

ENGINE = CorrelationEngine()
TWIN = "aa:aa:aa:aa:aa:aa"
REAL = "bb:bb:bb:bb:bb:bb"


def verdict(*events):
    return ENGINE.classify(ENGINE.score(events))


# The default weights must satisfy the design rules documented in correlation.py.


@pytest.mark.parametrize("module", list(Module))
def test_one_module_at_full_strength_is_suspicious_but_never_evil_twin(module) -> None:
    assert verdict(event(module)) is Classification.SUSPICIOUS


@pytest.mark.parametrize("pair", [(a, b) for a in Module for b in Module if a < b])
def test_two_modules_at_full_strength_are_evil_twin(pair) -> None:
    assert verdict(*(event(module) for module in pair)) is Classification.EVIL_TWIN


@pytest.mark.parametrize("module", list(Module))
def test_one_module_with_medium_signals_is_info(module) -> None:
    assert verdict(event(module, Severity.MEDIUM)) is Classification.INFO


@pytest.mark.parametrize("pair", [(a, b) for a in Module for b in Module if a < b])
def test_two_modules_with_medium_signals_are_suspicious(pair) -> None:
    assert verdict(*(event(m, Severity.MEDIUM) for m in pair)) is Classification.SUSPICIOUS


def test_score_is_a_noisy_or_of_module_evidence() -> None:
    identity, deauth = event(Module.IDENTITY), event(Module.DEAUTH, Severity.MEDIUM)
    expected = 1 - (1 - 0.70 * 1.0) * (1 - 0.55 * 0.6)
    assert ENGINE.score([identity, deauth]) == pytest.approx(expected, abs=1e-3)


def test_signals_of_one_module_are_not_counted_twice() -> None:
    once = ENGINE.score([event(Module.DEAUTH)])
    twice = ENGINE.score([event(Module.DEAUTH, name="a"), event(Module.DEAUTH, name="b")])
    assert once == twice


def test_deauth_against_the_real_ap_corroborates_the_twin() -> None:
    twin = event(Module.IDENTITY, bssid=TWIN, ssid="HomeNet", name="unknown_bssid_for_trusted_ssid")
    storm = event(Module.DEAUTH, bssid=REAL, ssid="", name="broadcast_flood")

    alerts = {a.bssid: a for a in ENGINE.correlate([twin, storm], ssid_of={REAL: "HomeNet"})}

    assert alerts[TWIN].classification is Classification.EVIL_TWIN
    assert alerts[TWIN].modules == (Module.DEAUTH, Module.IDENTITY)
    assert REAL in alerts[TWIN].explanation
    assert alerts[REAL].classification is Classification.SUSPICIOUS


def test_storms_on_other_networks_are_not_linked() -> None:
    twin = event(Module.IDENTITY, bssid=TWIN, ssid="HomeNet")
    storm = event(Module.DEAUTH, bssid=REAL, ssid="OtherNet")
    alerts = {a.bssid: a for a in ENGINE.correlate([twin, storm], ssid_of={})}
    assert alerts[TWIN].modules == (Module.IDENTITY,)


def test_alerts_below_min_score_are_dropped() -> None:
    engine = CorrelationEngine(min_score=0.5)
    assert engine.correlate([event(Module.DEAUTH, Severity.MEDIUM)], ssid_of={}) == []


def test_explanation_names_the_evidence() -> None:
    (alert,) = ENGINE.correlate(
        [event(Module.ENVIRONMENT, name="same_ssid_vendor_oui_outlier")], ssid_of={}
    )
    assert "differs from the other APs" in alert.explanation
    assert "same_ssid_vendor_oui_outlier" in alert.explanation
    assert alert.explanation.endswith("Worth checking.")
