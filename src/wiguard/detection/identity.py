"""Identity verification against trusted AP profiles.

The operator enrolls the APs of their own networks during a known-good period
(``wiguard enroll``). Each trusted profile stores how that AP looked: its IE
fingerprint, clock skew, RSSI level and sequence behaviour. Later observations
are compared with it:

* a trusted BSSID whose fingerprint or clock changed is probably a copy that
  reuses the same MAC address;
* an unknown BSSID advertising a trusted SSID is a second AP impersonating the
  network name — the classic Evil Twin setup.

Enrollment is never automatic: silently learning whatever is on the air would
also learn an attacker who is already present.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from operator import attrgetter
from pathlib import Path
from typing import Any

from wiguard.features import APSummary

from .events import DetectionEvent, Module, Severity, Signal

PROFILE_SCHEMA_VERSION = 2


class ProfileError(ValueError):
    """The trusted-profile file cannot be read."""


@dataclass(frozen=True, slots=True)
class TrustedProfile:
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

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TrustedProfile:
        return cls(
            bssid=str(payload["bssid"]).lower(),
            ssid=str(payload.get("ssid") or ""),
            frames=int(payload.get("frames") or 0),
            ie_fingerprint=_optional(str, payload.get("ie_fingerprint")),
            avg_rssi_dbm=_optional(float, payload.get("avg_rssi_dbm")),
            rssi_stddev=_optional(float, payload.get("rssi_stddev")),
            clock_skew_ppm=_optional(float, payload.get("clock_skew_ppm")),
            sequence_backward_jumps=int(payload.get("sequence_backward_jumps") or 0),
            enrolled_at=float(payload.get("enrolled_at") or 0.0),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


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
    """Trusted profiles persisted as a small, human-readable JSON file."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> list[TrustedProfile]:
        if not self.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ProfileError(f"{self.path}: not valid JSON ({error})") from error
        version = payload.get("schema_version") if isinstance(payload, dict) else None
        if version != PROFILE_SCHEMA_VERSION:
            raise ProfileError(
                f"{self.path}: unsupported trusted-profile schema {version!r} "
                f"(expected {PROFILE_SCHEMA_VERSION}); re-run `wiguard enroll`"
            )
        return [TrustedProfile.from_dict(item) for item in payload.get("profiles", [])]

    def save(self, profiles: Iterable[TrustedProfile]) -> None:
        payload = {
            "schema_version": PROFILE_SCHEMA_VERSION,
            "profiles": [
                profile.to_dict() for profile in sorted(profiles, key=attrgetter("bssid"))
            ],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)


class IdentityVerifier:
    """Compare current AP summaries with the trusted profiles."""

    def __init__(
        self,
        profiles: Iterable[TrustedProfile] = (),
        *,
        min_frames: int = 10,
        clock_skew_delta_ppm: float = 5.0,
        rssi_shift_db: float = 12.0,
    ) -> None:
        self.profiles = {profile.bssid: profile for profile in profiles}
        self.trusted_ssids = {profile.ssid for profile in self.profiles.values() if profile.ssid}
        self.min_frames = min_frames
        self.clock_skew_delta_ppm = clock_skew_delta_ppm
        self.rssi_shift_db = rssi_shift_db

    def evaluate(self, summaries: Sequence[APSummary]) -> list[DetectionEvent]:
        events = []
        for summary in summaries:
            if summary.frames < self.min_frames:
                continue
            profile = self.profiles.get(summary.bssid)
            if profile is not None:
                signals = self._drift_signals(profile, summary)
            elif summary.ssid in self.trusted_ssids:
                signals = [self._unknown_bssid_signal(summary)]
            else:
                continue
            if signals:
                events.append(
                    DetectionEvent(
                        module=Module.IDENTITY,
                        bssid=summary.bssid,
                        ssid=summary.ssid,
                        signals=tuple(signals),
                        last_seen=summary.last_seen,
                        context={"detector": "trusted_profile"},
                    )
                )
        return events

    def _unknown_bssid_signal(self, summary: APSummary) -> Signal:
        known = sorted(bssid for bssid, p in self.profiles.items() if p.ssid == summary.ssid)
        return Signal(
            name="unknown_bssid_for_trusted_ssid",
            severity=Severity.HIGH,
            message="A BSSID that is not enrolled advertises a trusted network name",
            details={"trusted_bssids": known, "channels": list(summary.channels)},
        )

    def _drift_signals(self, profile: TrustedProfile, summary: APSummary) -> list[Signal]:
        signals: list[Signal] = []
        current_ie = summary.dominant_ie_fingerprint
        if profile.ie_fingerprint and current_ie and current_ie != profile.ie_fingerprint:
            signals.append(
                Signal(
                    name="ie_fingerprint_changed",
                    severity=Severity.HIGH,
                    message="IE fingerprint differs from the trusted profile",
                    details={"trusted": profile.ie_fingerprint, "current": current_ie},
                )
            )

        current_skew = summary.clock_skew_ppm
        if profile.clock_skew_ppm is not None and current_skew is not None:
            delta = current_skew - profile.clock_skew_ppm
            if abs(delta) >= self.clock_skew_delta_ppm:
                signals.append(
                    Signal(
                        name="clock_skew_changed",
                        severity=Severity.HIGH,
                        message="Clock skew differs from the trusted profile",
                        details={
                            "trusted_ppm": round(profile.clock_skew_ppm, 3),
                            "current_ppm": round(current_skew, 3),
                            "delta_ppm": round(delta, 3),
                            "threshold_ppm": self.clock_skew_delta_ppm,
                        },
                    )
                )

        if profile.avg_rssi_dbm is not None and summary.avg_rssi_dbm is not None:
            delta = summary.avg_rssi_dbm - profile.avg_rssi_dbm
            # Tolerate at least four standard deviations of the enrolled RSSI.
            tolerance = max(self.rssi_shift_db, 4.0 * (profile.rssi_stddev or 0.0))
            if abs(delta) >= tolerance:
                signals.append(
                    Signal(
                        name="rssi_shifted",
                        severity=Severity.MEDIUM,
                        message="Signal strength moved far from the trusted profile",
                        details={
                            "trusted_dbm": profile.avg_rssi_dbm,
                            "current_dbm": summary.avg_rssi_dbm,
                            "delta_db": round(delta, 2),
                            "threshold_db": round(tolerance, 2),
                        },
                    )
                )

        jumps = summary.sequence.backward_jumps
        if jumps > profile.sequence_backward_jumps:
            signals.append(
                Signal(
                    name="sequence_backward_jump",
                    severity=Severity.MEDIUM,
                    message="Sequence numbers jumped backwards (restart or second transmitter)",
                    details={"trusted": profile.sequence_backward_jumps, "current": jumps},
                )
            )
        return signals


def _optional[T](convert: Callable[[Any], T], value: object) -> T | None:
    return None if value is None else convert(value)
