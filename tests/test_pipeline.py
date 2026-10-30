"""The full pipeline on the synthetic scenarios (pcap files in tests/pcap_fixtures)."""

from __future__ import annotations

import json

import pytest

from builders import FIXTURES, MANIFEST, START, beacon, deauth
from wiguard.analysis import analyze_pcap
from wiguard.evaluation import (
    evaluate_manifest,
    evaluate_scenario,
    load_manifest,
    write_synthetic_fixtures,
)
from wiguard.pipeline import DetectionPipeline


@pytest.mark.parametrize("scenario", load_manifest(MANIFEST), ids=lambda s: s.name)
def test_scenario_verdict(scenario, config) -> None:
    result = evaluate_scenario(scenario, config)
    assert result.passed, result


def test_evaluation_report_has_a_diagonal_confusion_matrix(config) -> None:
    report = evaluate_manifest(MANIFEST, config)
    matrix = report["confusion_matrix"]["rows_expected_columns_observed"]
    assert report["success"]
    assert sum(matrix[i][i] for i in range(4)) == report["scenarios"]


def test_committed_fixtures_match_the_generator(tmp_path) -> None:
    write_synthetic_fixtures(tmp_path)
    assert json.loads((tmp_path / "manifest.json").read_text()) == json.loads(MANIFEST.read_text())
    for pcap in FIXTURES.glob("*.pcap"):
        assert (tmp_path / pcap.name).read_bytes() == pcap.read_bytes(), pcap.name


def test_analysis_without_profiles_explains_what_is_missing(config) -> None:
    result = analyze_pcap(FIXTURES / "classic_evil_twin.pcap", config, trusted_profiles=[])
    assert result.trusted_profiles == 0
    assert any("wiguard enroll" in note for note in result.notes)
    assert result.frames.beacons == 160 and result.frames.disruption == 150


def test_deauth_events_are_named_after_the_network(config) -> None:
    pipeline = DetectionPipeline(config)
    for i in range(20):
        pipeline.add_frame(beacon(i))
    for i in range(200):
        pipeline.add_frame(deauth(START + 3 + i * 0.02))
    (storm,) = pipeline.evaluate().events
    assert storm.ssid == "HomeNet"


def test_evidence_window_drops_evidence_that_went_quiet(config) -> None:
    pipeline = DetectionPipeline(config)
    for i in range(200):
        pipeline.add_frame(deauth(START + i * 0.02))
    for i in range(40):  # same BSSID on two channels: duplicate-BSSID evidence
        pipeline.add_frame(beacon(i, channel=6 if i % 2 else 1))
    assert len(pipeline.evaluate(now=START + 60, evidence_window=300).events) == 2
    assert pipeline.evaluate(now=START + 3600, evidence_window=300).events == []
    assert len(pipeline.evaluate(now=START + 3600).events) == 2  # offline: keep everything


def test_a_threshold_in_the_config_changes_the_verdict(config) -> None:
    pcap = FIXTURES / "deauth_storm_only.pcap"
    assert analyze_pcap(pcap, config, trusted_profiles=[]).alerts
    relaxed = config.with_overrides(
        {
            "detection.deauth_storm.deauth_rate_threshold": 1000,
            "detection.deauth_storm.broadcast_rate_threshold": 1000,
        }
    )
    assert analyze_pcap(pcap, relaxed, trusted_profiles=[]).alerts == []
