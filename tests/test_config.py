from __future__ import annotations

from pathlib import Path

import pytest

from wiguard.config import ConfigError, WiGuardConfig, load_config
from wiguard.detection import Module

REPO_CONFIG = Path(__file__).parents[1] / "config.yaml"


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return path


def test_repository_config_is_valid() -> None:
    config = load_config(REPO_CONFIG)
    assert config.source_path == str(REPO_CONFIG)
    assert config.detection.correlation.module_weights[Module.IDENTITY] == 0.70


def test_file_values_override_defaults(tmp_path: Path) -> None:
    config = load_config(
        write(tmp_path, "detection:\n  deauth_storm:\n    deauth_rate_threshold: 3\n")
    )
    assert config.detection.deauth_storm.deauth_rate_threshold == 3.0
    assert config.detection.deauth_storm.disassoc_rate_threshold == 5.0  # default kept


def test_missing_default_file_means_defaults(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_config() == WiGuardConfig()


def test_missing_named_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("capture:\n  dwel_seconds: 1\n", "capture.dwel_seconds"),
        ("detection:\n  correlation:\n    min_score: 1.5\n", "min_score"),
        ("features:\n  window_size: 10\n  clock_min_samples: 50\n", "window_size"),
        ("detection:\n  duplicate_bssid:\n    min_samples: 10\n", "twice min_cluster_samples"),
        (
            "detection:\n  correlation:\n    suspicious_threshold: 0.9\n",
            "suspicious_threshold < evil_twin_threshold",
        ),
        ("detection:\n  correlation:\n    module_weights:\n      ml: 0.5\n", "module_weights"),
        ("capture:\n  channels: []\n", "at least one channel"),
        ("- just\n- a list\n", "(root)"),
    ],
)
def test_invalid_values_are_rejected(tmp_path: Path, text: str, problem: str) -> None:
    with pytest.raises(ConfigError, match=problem.replace("(", r"\(").replace(")", r"\)")):
        load_config(write(tmp_path, text))


def test_partial_module_weights_keep_the_other_defaults(tmp_path: Path) -> None:
    text = "detection:\n  correlation:\n    module_weights:\n      deauth_storm: 0.3\n"
    weights = load_config(write(tmp_path, text)).detection.correlation.module_weights
    assert weights[Module.DEAUTH] == 0.3
    assert weights[Module.IDENTITY] == 0.70


def test_overrides_are_validated_and_none_is_skipped() -> None:
    config = WiGuardConfig().with_overrides({"api.port": 9000, "capture.interface": None})
    assert config.api.port == 9000
    assert config.capture.interface == WiGuardConfig().capture.interface
    with pytest.raises(ConfigError):
        WiGuardConfig().with_overrides({"api.port": 0})
    with pytest.raises(ConfigError, match="unknown config key"):
        WiGuardConfig().with_overrides({"api.prot": 1})
