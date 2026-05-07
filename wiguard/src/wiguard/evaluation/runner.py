"""Run WiGuard detection evaluation against fixture manifests."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from wiguard.analysis import PcapAnalysisConfig, analyze_pcap

from .fixtures import FixtureScenario, load_manifest


@dataclass(frozen=True)
class ScenarioEvaluation:
    name: str
    pcap: str
    expected_classification: str
    observed_classification: str
    passed: bool
    expected_modules: tuple[str, ...]
    observed_modules: tuple[str, ...]
    missing_modules: tuple[str, ...]
    expected_signals: tuple[str, ...]
    observed_signals: tuple[str, ...]
    missing_signals: tuple[str, ...]
    correlated_alerts: int
    raw_alerts: int

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        for key in (
            "expected_modules",
            "observed_modules",
            "missing_modules",
            "expected_signals",
            "observed_signals",
            "missing_signals",
        ):
            payload[key] = list(payload[key])
        return payload


def evaluate_manifest(
    manifest_path: Path | str,
    *,
    analysis_config: PcapAnalysisConfig | None = None,
) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    config = analysis_config or PcapAnalysisConfig()
    scenario_results = [
        _evaluate_scenario(scenario, analysis_config=config)
        for scenario in manifest.scenarios
    ]
    passed = sum(1 for result in scenario_results if result.passed)
    return {
        "manifest": str(manifest.path),
        "schema_version": manifest.schema_version,
        "scenarios": len(scenario_results),
        "passed": passed,
        "failed": len(scenario_results) - passed,
        "success": passed == len(scenario_results),
        "results": [result.to_dict() for result in scenario_results],
    }


def _evaluate_scenario(
    scenario: FixtureScenario,
    *,
    analysis_config: PcapAnalysisConfig,
) -> ScenarioEvaluation:
    if not scenario.pcap.exists():
        raise FileNotFoundError(f"{scenario.name}: pcap does not exist: {scenario.pcap}")
    payload = analyze_pcap(scenario.pcap, config=analysis_config)
    observed_modules = _observed_modules(payload)
    observed_signals = _observed_signals(payload)
    observed_classification = _observed_classification(payload)
    missing_modules = tuple(
        module for module in scenario.expected_modules if module not in observed_modules
    )
    missing_signals = tuple(
        signal for signal in scenario.expected_signals if signal not in observed_signals
    )
    passed = (
        observed_classification == scenario.expected_classification
        and not missing_modules
        and not missing_signals
    )
    return ScenarioEvaluation(
        name=scenario.name,
        pcap=str(scenario.pcap),
        expected_classification=scenario.expected_classification,
        observed_classification=observed_classification,
        passed=passed,
        expected_modules=scenario.expected_modules,
        observed_modules=observed_modules,
        missing_modules=missing_modules,
        expected_signals=scenario.expected_signals,
        observed_signals=observed_signals,
        missing_signals=missing_signals,
        correlated_alerts=len(payload.get("correlated_alerts", [])),
        raw_alerts=_raw_alert_count(payload),
    )


def _observed_classification(payload: dict[str, object]) -> str:
    correlated = _list(payload.get("correlated_alerts"))
    if any(_dict(alert).get("classification") == "evil_twin" for alert in correlated):
        return "evil_twin"
    if correlated or _raw_alert_count(payload) > 0:
        return "suspicious"
    return "clean"


def _observed_modules(payload: dict[str, object]) -> tuple[str, ...]:
    modules: set[str] = set()
    for alert in _all_raw_alerts(payload):
        module = _dict(alert).get("module")
        if isinstance(module, str):
            modules.add(module)
    for alert in _list(payload.get("correlated_alerts")):
        for module in _list(_dict(alert).get("contributing_modules")):
            if isinstance(module, str):
                modules.add(module)
    return tuple(sorted(modules))


def _observed_signals(payload: dict[str, object]) -> tuple[str, ...]:
    signals: set[str] = set()
    for alert in _all_raw_alerts(payload):
        for signal in _list(_dict(alert).get("signals")):
            name = _dict(signal).get("name")
            if isinstance(name, str):
                signals.add(name)
    for alert in _list(payload.get("correlated_alerts")):
        for event in _list(_dict(alert).get("timeline")):
            for name in _list(_dict(event).get("signal_names")):
                if isinstance(name, str):
                    signals.add(name)
    return tuple(sorted(signals))


def _raw_alert_count(payload: dict[str, object]) -> int:
    return len(_all_raw_alerts(payload))


def _all_raw_alerts(payload: dict[str, object]) -> list[object]:
    alerts: list[object] = []
    for key in (
        "identity_alerts",
        "deauth_alerts",
        "environment_alerts",
    ):
        alerts.extend(_list(payload.get(key)))
    return alerts


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate WiGuard detector fixtures")
    parser.add_argument("manifest", type=Path, help="fixture manifest JSON")
    args = parser.parse_args(argv)
    payload = evaluate_manifest(args.manifest)
    print(json.dumps(payload, indent=2))
    return 0 if payload["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
