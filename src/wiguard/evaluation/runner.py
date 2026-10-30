"""Run every scenario of a manifest through the pipeline and score the verdicts."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from wiguard.analysis import analyze_pcap
from wiguard.config import WiGuardConfig
from wiguard.correlation import CorrelatedAlert
from wiguard.detection import enroll

from .fixtures import VERDICTS, Scenario, load_manifest


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    expected: str
    observed: str
    score: float
    passed: bool
    missing_modules: tuple[str, ...]
    missing_signals: tuple[str, ...]
    explanation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate_scenario(scenario: Scenario, config: WiGuardConfig) -> ScenarioResult:
    profiles = []
    if scenario.enrollment_pcap is not None:
        baseline = analyze_pcap(scenario.enrollment_pcap, config, trusted_profiles=[])
        profiles = enroll(
            baseline.access_points,
            min_frames=config.detection.identity.enrollment_min_frames,
            enrolled_at=baseline.evaluated_at,
        )
    result = analyze_pcap(scenario.pcap, config, trusted_profiles=profiles)
    verdict = _verdict(result.alerts, scenario.target_bssid)
    modules = {module.value for module in verdict.modules} if verdict else set()
    signals = set(verdict.signal_names) if verdict else set()
    observed = verdict.classification.value if verdict else "clean"
    missing_modules = tuple(m for m in scenario.expected_modules if m not in modules)
    missing_signals = tuple(s for s in scenario.expected_signals if s not in signals)
    return ScenarioResult(
        name=scenario.name,
        expected=scenario.expected_classification,
        observed=observed,
        score=verdict.score if verdict else 0.0,
        passed=observed == scenario.expected_classification
        and not missing_modules
        and not missing_signals,
        missing_modules=missing_modules,
        missing_signals=missing_signals,
        explanation=verdict.explanation if verdict else "",
    )


def evaluate_manifest(
    manifest: Path | str, config: WiGuardConfig | None = None
) -> dict[str, object]:
    config = config or WiGuardConfig()
    results = [evaluate_scenario(scenario, config) for scenario in load_manifest(manifest)]
    pairs = Counter((result.expected, result.observed) for result in results)
    passed = sum(result.passed for result in results)
    return {
        "manifest": str(manifest),
        "scenarios": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "success": passed == len(results),
        "confusion_matrix": {
            "labels": list(VERDICTS),
            "rows_expected_columns_observed": [
                [pairs[(expected, observed)] for observed in VERDICTS] for expected in VERDICTS
            ],
        },
        "results": [result.to_dict() for result in results],
    }


def _verdict(alerts: list[CorrelatedAlert], target: str | None) -> CorrelatedAlert | None:
    candidates = [alert for alert in alerts if target is None or alert.bssid == target]
    return max(candidates, key=lambda alert: alert.score, default=None)
