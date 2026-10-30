"""Scenario-based evaluation of the detection pipeline."""

from .fixtures import Scenario, load_manifest
from .runner import ScenarioResult, evaluate_manifest, evaluate_scenario
from .synthetic import write_synthetic_fixtures

__all__ = [
    "Scenario",
    "ScenarioResult",
    "evaluate_manifest",
    "evaluate_scenario",
    "load_manifest",
    "write_synthetic_fixtures",
]
