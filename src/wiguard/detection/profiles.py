"""Trusted AP profiles: how the operator's own APs looked during enrollment.

Enrollment is never automatic: silently learning whatever is on the air would
also learn an attacker who is already present. Profiles are recorded by an
explicit ``wiguard enroll`` and stored as a small, human-readable JSON file.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from wiguard.features import APSummary

PROFILE_SCHEMA_VERSION: Literal[2] = 2


class ProfileError(ValueError):
    """The trusted-profile file cannot be read."""


class TrustedProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    bssid: str
    ssid: str
    frames: int
    ie_fingerprint: str | None
    avg_rssi_dbm: float | None
    rssi_stddev: float | None
    clock_skew_ppm: float | None
    sequence_backward_jumps: int
    enrolled_at: float

    @classmethod
    def from_summary(cls, summary: APSummary, *, enrolled_at: float) -> TrustedProfile:
        return cls(
            bssid=summary.bssid,
            ssid=summary.ssid,
            frames=summary.frames,
            ie_fingerprint=summary.dominant_ie_fingerprint,
            avg_rssi_dbm=summary.avg_rssi_dbm,
            rssi_stddev=summary.rssi_stddev,
            clock_skew_ppm=summary.clock_skew_ppm,
            sequence_backward_jumps=summary.sequence.backward_jumps,
            enrolled_at=enrolled_at,
        )


class _ProfileFile(BaseModel):
    schema_version: Literal[2] = PROFILE_SCHEMA_VERSION
    profiles: list[TrustedProfile]


def enroll(
    summaries: Iterable[APSummary], *, min_frames: int, enrolled_at: float | None = None
) -> list[TrustedProfile]:
    """Turn APs observed during a known-good period into trusted profiles."""

    timestamp = time.time() if enrolled_at is None else enrolled_at
    return [
        TrustedProfile.from_summary(summary, enrolled_at=timestamp)
        for summary in summaries
        if summary.frames >= min_frames
    ]


class TrustedProfileStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def load(self) -> list[TrustedProfile]:
        """The stored profiles; none if nothing has been enrolled yet."""
        if not self.path.is_file():
            return []
        try:
            return _ProfileFile.model_validate_json(self.path.read_bytes()).profiles
        except ValidationError as error:
            raise ProfileError(
                f"{self.path} is not a trusted-profile file of schema "
                f"{PROFILE_SCHEMA_VERSION}; re-run `wiguard enroll` ({error.error_count()} "
                "problem(s))"
            ) from error

    def save(self, profiles: Iterable[TrustedProfile]) -> None:
        content = _ProfileFile(profiles=sorted(profiles, key=lambda profile: profile.bssid))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_text(content.model_dump_json(indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)  # atomic: a crash never leaves half a file
