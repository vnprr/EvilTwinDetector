"""Scenario manifests: which capture to analyse and what verdict to expect."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VERDICTS = ("clean", "info", "suspicious", "evil_twin")
MANIFEST_SCHEMA_VERSION = 2


@dataclass(frozen=True)
class Scenario:
    name: str
    pcap: Path
    expected_classification: str
    description: str = ""
    enrollment_pcap: Path | None = None
    """Known-good capture to enroll trusted profiles from before the analysis."""
    target_bssid: str | None = None
    """The AP the verdict is about; ``None`` means the strongest alert overall."""
    expected_modules: tuple[str, ...] = ()
    expected_signals: tuple[str, ...] = ()


def load_manifest(path: Path | str) -> list[Scenario]:
    manifest_path = Path(path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            f"{manifest_path}: expected schema_version {MANIFEST_SCHEMA_VERSION}, "
            f"got {payload.get('schema_version')!r}"
        )
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError(f"{manifest_path}: 'scenarios' must be a non-empty list")
    return [_scenario(item, manifest_path.parent) for item in scenarios]


def _scenario(item: dict[str, Any], base: Path) -> Scenario:
    name = item.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"scenario without a name: {item!r}")
    expected = item.get("expected_classification")
    if expected not in VERDICTS:
        raise ValueError(f"{name}: expected_classification must be one of {VERDICTS}")
    enrollment = item.get("enrollment_pcap")
    return Scenario(
        name=name,
        pcap=base / str(item["pcap"]),
        expected_classification=expected,
        description=str(item.get("description", "")),
        enrollment_pcap=base / enrollment if enrollment else None,
        target_bssid=str(item["target_bssid"]).lower() if item.get("target_bssid") else None,
        expected_modules=tuple(item.get("expected_modules", [])),
        expected_signals=tuple(item.get("expected_signals", [])),
    )
