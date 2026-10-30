"""Scenario manifests: which capture to analyse and what verdict to expect."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["clean", "info", "suspicious", "evil_twin"]
VERDICTS: tuple[Verdict, ...] = get_args(Verdict)


class Scenario(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    description: str = ""
    pcap: Path
    enrollment_pcap: Path | None = None
    """Known-good capture to enroll trusted profiles from before the analysis."""
    expected_classification: Verdict
    target_bssid: str | None = None
    """The AP the verdict is about; ``None`` means the strongest alert overall."""
    expected_modules: tuple[str, ...] = ()
    expected_signals: tuple[str, ...] = ()


class Manifest(BaseModel):
    schema_version: Literal[2] = 2
    source: str = ""
    limitations: str = ""
    scenarios: list[Scenario] = Field(min_length=1)


def load_manifest(path: Path | str) -> list[Scenario]:
    """Scenarios with their capture paths resolved relative to the manifest."""
    path = Path(path)
    manifest = Manifest.model_validate_json(path.read_bytes())
    return [
        scenario.model_copy(
            update={
                "pcap": path.parent / scenario.pcap,
                "enrollment_pcap": scenario.enrollment_pcap
                and path.parent / scenario.enrollment_pcap,
            }
        )
        for scenario in manifest.scenarios
    ]
