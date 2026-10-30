"""The common output format of every detector.

A detector does not decide whether something is an Evil Twin. It reports
*signals* (named, explained observations with a severity) grouped into one
*detection event* per AP. The correlation engine weighs events from different
detectors into the final verdict.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class Module(StrEnum):
    """Independent evidence sources. Correlation weighs each one separately."""

    IDENTITY = "identity_verification"
    DEAUTH = "deauth_storm"
    ENVIRONMENT = "environment_anomaly"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def strength(self) -> float:
        """How strongly one signal of this severity supports its module's finding."""
        return _STRENGTH[self]


_STRENGTH = {Severity.LOW: 0.3, Severity.MEDIUM: 0.6, Severity.HIGH: 1.0}


@dataclass(frozen=True, slots=True)
class Signal:
    name: str
    severity: Severity
    message: str
    details: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "severity": self.severity.value,
            "message": self.message,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    """Everything one detector currently holds against one BSSID."""

    module: Module
    bssid: str
    ssid: str
    signals: tuple[Signal, ...]
    last_seen: float
    """Capture time of the most recent frame behind this evidence."""
    context: Mapping[str, object] = field(default_factory=dict)

    @property
    def strength(self) -> float:
        """Strength of the strongest signal.

        Signals of one detector usually share a cause (e.g. a broadcast flood
        also raises the overall frame rate), so they are not added up: that
        would count the same cause several times.
        """
        return max((signal.severity.strength for signal in self.signals), default=0.0)

    @property
    def signal_names(self) -> tuple[str, ...]:
        return tuple(signal.name for signal in self.signals)

    def to_dict(self) -> dict[str, object]:
        return {
            "module": self.module.value,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "strength": self.strength,
            "signal_names": list(self.signal_names),
            "signals": [signal.to_dict() for signal in self.signals],
            "last_seen": self.last_seen,
            "context": dict(self.context),
        }
