"""Evaluation harness for WiGuard detection fixtures."""

from .fixtures import FixtureManifest, FixtureScenario, load_manifest

__all__ = [
    "FixtureManifest",
    "FixtureScenario",
    "evaluate_manifest",
    "load_manifest",
]


def evaluate_manifest(*args, **kwargs):
    from .runner import evaluate_manifest as _evaluate_manifest

    return _evaluate_manifest(*args, **kwargs)
