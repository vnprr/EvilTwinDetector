"""Fixture manifest parsing for repeatable detection evaluation."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


EXPECTED_CLASSIFICATIONS = frozenset({"clean", "suspicious", "evil_twin"})


@dataclass(frozen=True)
class FixtureScenario:
    name: str
    pcap: Path
    expected_classification: str
    expected_modules: tuple[str, ...]
    expected_signals: tuple[str, ...]
    description: str
    source: str
    limitations: str

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["pcap"] = str(self.pcap)
        payload["expected_modules"] = list(self.expected_modules)
        payload["expected_signals"] = list(self.expected_signals)
        return payload


@dataclass(frozen=True)
class FixtureManifest:
    schema_version: int
    path: Path
    scenarios: tuple[FixtureScenario, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "path": str(self.path),
            "scenarios": [scenario.to_dict() for scenario in self.scenarios],
        }


def load_manifest(path: Path | str) -> FixtureManifest:
    manifest_path = Path(path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    schema_version = _required_int(payload, "schema_version", context=str(manifest_path))
    if schema_version != 1:
        raise ValueError(f"{manifest_path}: unsupported schema_version {schema_version}")
    raw_scenarios = payload.get("scenarios")
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise ValueError(f"{manifest_path}: scenarios must be a non-empty list")
    scenarios = tuple(
        _parse_scenario(item, manifest_path=manifest_path, index=index)
        for index, item in enumerate(raw_scenarios)
    )
    return FixtureManifest(
        schema_version=schema_version,
        path=manifest_path,
        scenarios=scenarios,
    )


def _parse_scenario(
    payload: object,
    *,
    manifest_path: Path,
    index: int,
) -> FixtureScenario:
    context = f"{manifest_path}: scenarios[{index}]"
    if not isinstance(payload, dict):
        raise ValueError(f"{context}: scenario must be an object")
    name = _required_str(payload, "name", context=context)
    pcap_raw = _required_str(payload, "pcap", context=context)
    expected_classification = _required_str(payload, "expected_classification", context=context)
    if expected_classification not in EXPECTED_CLASSIFICATIONS:
        raise ValueError(
            f"{context}: expected_classification must be one of "
            f"{sorted(EXPECTED_CLASSIFICATIONS)}"
        )
    return FixtureScenario(
        name=name,
        pcap=(manifest_path.parent / pcap_raw).resolve(),
        expected_classification=expected_classification,
        expected_modules=_optional_str_tuple(payload, "expected_modules", context=context),
        expected_signals=_optional_str_tuple(payload, "expected_signals", context=context),
        description=str(payload.get("description", "")),
        source=str(payload.get("source", "")),
        limitations=str(payload.get("limitations", "")),
    )


def _required_str(payload: dict[str, object], key: str, *, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context}: missing required string field {key!r}")
    return value


def _required_int(payload: dict[str, object], key: str, *, context: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise ValueError(f"{context}: missing required integer field {key!r}")
    return value


def _optional_str_tuple(
    payload: dict[str, object],
    key: str,
    *,
    context: str,
) -> tuple[str, ...]:
    value = payload.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{context}: {key!r} must be a list of strings")
    return tuple(value)
