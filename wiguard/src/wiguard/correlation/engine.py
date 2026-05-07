"""Correlation of raw module alerts into user-facing WiGuard alerts."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass

from wiguard.detection import (
    DeauthStormAlert,
    EnvironmentAnomalyAlert,
    IdentityAlert,
)


DEFAULT_MODULE_WEIGHTS = {
    "identity_verification": 0.45,
    "deauth_storm": 0.35,
    "environment_anomaly": 0.35,
    "active_verification": 0.6,
}


@dataclass(frozen=True)
class DetectionEvent:
    module: str
    bssid: str
    ssid: str | None
    score: float
    signal_names: tuple[str, ...]
    evidence: dict[str, object]

    @classmethod
    def from_identity_alert(cls, alert: IdentityAlert) -> "DetectionEvent":
        return cls(
            module="identity_verification",
            bssid=alert.bssid,
            ssid=alert.ssid,
            score=alert.score,
            signal_names=tuple(signal.name for signal in alert.signals),
            evidence={"signals": [signal.to_dict() for signal in alert.signals]},
        )

    @classmethod
    def from_deauth_alert(
        cls,
        alert: DeauthStormAlert,
        *,
        ssid: str | None = None,
    ) -> "DetectionEvent":
        return cls(
            module="deauth_storm",
            bssid=alert.bssid,
            ssid=ssid,
            score=alert.score,
            signal_names=tuple(signal.name for signal in alert.signals),
            evidence={
                "channel": alert.channel,
                "frame_type": alert.frame_type,
                "signals": [signal.to_dict() for signal in alert.signals],
            },
        )

    @classmethod
    def from_environment_alert(cls, alert: EnvironmentAnomalyAlert) -> "DetectionEvent":
        return cls(
            module="environment_anomaly",
            bssid=alert.bssid,
            ssid=alert.ssid,
            score=alert.score,
            signal_names=tuple(signal.name for signal in alert.signals),
            evidence={
                "peer_count": alert.peer_count,
                "signals": [signal.to_dict() for signal in alert.signals],
            },
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CorrelatedAlert:
    alert_id: str
    bssid: str
    ssid: str
    final_score: float
    classification: str
    contributing_modules: tuple[str, ...]
    explanation: str
    timeline: tuple[DetectionEvent, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "alert_id": self.alert_id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "final_score": self.final_score,
            "classification": self.classification,
            "contributing_modules": list(self.contributing_modules),
            "explanation": self.explanation,
            "timeline": [event.to_dict() for event in self.timeline],
        }


class CorrelationEngine:
    """Combine independent module signals into deduplicated alerts."""

    def __init__(
        self,
        *,
        module_weights: dict[str, float] | None = None,
        min_final_score: float = 0.2,
    ) -> None:
        self.module_weights = dict(DEFAULT_MODULE_WEIGHTS)
        if module_weights is not None:
            self.module_weights.update(module_weights)
        self.min_final_score = min_final_score

    def correlate(self, events: list[DetectionEvent]) -> list[CorrelatedAlert]:
        grouped: defaultdict[str, list[DetectionEvent]] = defaultdict(list)
        for event in events:
            if event.score <= 0.0 or not event.signal_names:
                continue
            grouped[event.bssid.lower()].append(event)

        alerts = []
        for bssid, raw_group in grouped.items():
            group = _dedupe_events_by_module(raw_group)
            modules = tuple(sorted({event.module for event in group}))
            final_score = self._final_score(group, modules)
            if final_score < self.min_final_score:
                continue
            ssid = _first_ssid(group)
            alerts.append(
                CorrelatedAlert(
                    alert_id=_alert_id(bssid, group),
                    bssid=bssid,
                    ssid=ssid,
                    final_score=final_score,
                    classification=_classification(final_score),
                    contributing_modules=modules,
                    explanation=_explanation(ssid, bssid, modules, group),
                    timeline=tuple(sorted(group, key=lambda event: event.module)),
                )
            )
        return sorted(alerts, key=lambda item: (-item.final_score, item.ssid, item.bssid))

    def _final_score(self, events: list[DetectionEvent], modules: tuple[str, ...]) -> float:
        base_score = sum(
            _bounded_score(event.score) * self.module_weights.get(event.module, 0.25)
            for event in events
        )
        multiplier = 1.0 + max(0, len(modules) - 1) * 0.35
        multiplier += _rule_bonus(modules)
        return round(min(1.0, base_score * multiplier), 3)


def _bounded_score(score: float) -> float:
    return min(1.0, max(0.0, score))


def _rule_bonus(modules: tuple[str, ...]) -> float:
    module_set = set(modules)
    bonus = 0.0
    if {"deauth_storm", "environment_anomaly"} <= module_set:
        bonus += 0.25
    if {"identity_verification", "deauth_storm"} <= module_set:
        bonus += 0.25
    if {"identity_verification", "environment_anomaly"} <= module_set:
        bonus += 0.2
    if {"identity_verification", "deauth_storm", "environment_anomaly"} <= module_set:
        bonus += 0.3
    return bonus


def _classification(score: float) -> str:
    if score >= 0.8:
        return "evil_twin"
    if score >= 0.45:
        return "suspicious"
    return "info"


def _dedupe_events_by_module(events: list[DetectionEvent]) -> list[DetectionEvent]:
    deduped = []
    for module in sorted({event.module for event in events}):
        module_events = [event for event in events if event.module == module]
        best = max(module_events, key=lambda event: event.score)
        signal_names = tuple(sorted({name for event in module_events for name in event.signal_names}))
        if len(module_events) == 1:
            evidence = best.evidence
        else:
            evidence = {
                "deduplicated_events": len(module_events),
                "events": [event.evidence for event in module_events],
            }
        deduped.append(
            DetectionEvent(
                module=module,
                bssid=best.bssid,
                ssid=best.ssid,
                score=best.score,
                signal_names=signal_names,
                evidence=evidence,
            )
        )
    return deduped


def _first_ssid(events: list[DetectionEvent]) -> str:
    for event in events:
        if event.ssid:
            return event.ssid
    return "<unknown>"


def _alert_id(bssid: str, events: list[DetectionEvent]) -> str:
    canonical = {
        "bssid": bssid,
        "events": [
            {
                "module": event.module,
                "score": round(event.score, 3),
                "signals": event.signal_names,
            }
            for event in sorted(events, key=lambda item: (item.module, item.signal_names))
        ],
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"wiguard:{raw}"))


def _explanation(
    ssid: str,
    bssid: str,
    modules: tuple[str, ...],
    events: list[DetectionEvent],
) -> str:
    module_set = set(modules)
    if {"identity_verification", "deauth_storm", "environment_anomaly"} <= module_set:
        return (
            f"{ssid} / {bssid} triggered identity, deauth, and same-SSID environment "
            "signals at the same time. This is a high-confidence Evil Twin pattern."
        )
    if {"deauth_storm", "environment_anomaly"} <= module_set:
        return (
            f"{ssid} / {bssid} shows management-frame storm activity together with a "
            "same-SSID fingerprint anomaly. This combination is suspicious and should "
            "be checked first."
        )
    if "identity_verification" in module_set:
        return (
            f"{ssid} / {bssid} changed identity-level features: "
            f"{_signal_summary(events)}."
        )
    if "environment_anomaly" in module_set:
        return (
            f"{ssid} / {bssid} differs from same-SSID peers: "
            f"{_signal_summary(events)}."
        )
    if "deauth_storm" in module_set:
        return (
            f"{ssid} / {bssid} produced unusual deauthentication/disassociation "
            f"activity: {_signal_summary(events)}."
        )
    return f"{ssid} / {bssid} produced detection signals: {_signal_summary(events)}."


def _signal_summary(events: list[DetectionEvent]) -> str:
    names: list[str] = []
    for event in events:
        names.extend(event.signal_names)
    return ", ".join(sorted(set(names))) or "no named signals"


def events_from_alerts(
    *,
    identity_alerts: list[IdentityAlert] | None = None,
    deauth_alerts: list[DeauthStormAlert] | None = None,
    environment_alerts: list[EnvironmentAnomalyAlert] | None = None,
    ssid_by_bssid: dict[str, str] | None = None,
) -> list[DetectionEvent]:
    ssids = {key.lower(): value for key, value in (ssid_by_bssid or {}).items()}
    events: list[DetectionEvent] = []
    for alert in identity_alerts or []:
        if alert.triggered:
            events.append(DetectionEvent.from_identity_alert(alert))
    for alert in deauth_alerts or []:
        if alert.triggered:
            events.append(
                DetectionEvent.from_deauth_alert(
                    alert,
                    ssid=ssids.get(alert.bssid.lower()),
                )
            )
    for alert in environment_alerts or []:
        if alert.triggered:
            events.append(DetectionEvent.from_environment_alert(alert))
    return events
