"""Correlation: combine detection events into one verdict per AP.

Score
-----
Every module ``m`` that holds evidence against an AP contributes
``e_m = w_m * s_m``, where ``s_m`` is the strength of its strongest signal
(1.0 high, 0.6 medium, 0.3 low) and ``w_m`` is how much a full-strength
finding of that module alone should count. The contributions are combined
with a noisy-OR::

    score = 1 - (1 - e_1) * (1 - e_2) * ...

The score grows with every independent module that agrees, never exceeds 1,
and needs no hand-made bonus table. It is a heuristic evidence score, **not**
a calibrated probability.

The default weights are chosen so that these design rules hold:

* one module at full strength  -> ``suspicious`` but never ``evil_twin``;
* two modules at full strength -> ``evil_twin``;
* one module with only medium signals -> ``info``;
* two modules with medium signals -> ``suspicious``.

Network-level linking
---------------------
In the classic attack the twin uses its *own* BSSID, while the deauth storm is
forged with the *real* AP's BSSID to push its clients over. Grouping strictly by
BSSID would never connect the two. So when an AP already has identity or
environment evidence against it, deauth storms against *other* APs of the same
SSID are added to its evidence as linked events.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from wiguard.detection import DetectionEvent, Module

DEFAULT_MODULE_WEIGHTS: dict[Module, float] = {
    Module.IDENTITY: 0.70,
    Module.ENVIRONMENT: 0.60,
    Module.DEAUTH: 0.55,
}


class Classification(StrEnum):
    INFO = "info"
    SUSPICIOUS = "suspicious"
    EVIL_TWIN = "evil_twin"

    @property
    def rank(self) -> int:
        return list(Classification).index(self)


@dataclass(frozen=True, slots=True)
class CorrelatedAlert:
    bssid: str
    ssid: str
    score: float
    classification: Classification
    modules: tuple[Module, ...]
    evidence: tuple[DetectionEvent, ...]
    explanation: str
    last_seen: float

    @property
    def signal_names(self) -> tuple[str, ...]:
        return tuple(sorted({name for event in self.evidence for name in event.signal_names}))

    def to_dict(self) -> dict[str, object]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "score": self.score,
            "classification": self.classification.value,
            "modules": [module.value for module in self.modules],
            "signal_names": list(self.signal_names),
            "explanation": self.explanation,
            "last_seen": self.last_seen,
            "evidence": [event.to_dict() for event in self.evidence],
        }


class CorrelationEngine:
    def __init__(
        self,
        *,
        module_weights: Mapping[Module, float] | None = None,
        suspicious_threshold: float = 0.45,
        evil_twin_threshold: float = 0.80,
        min_score: float = 0.20,
    ) -> None:
        self.module_weights = {**DEFAULT_MODULE_WEIGHTS, **(module_weights or {})}
        self.suspicious_threshold = suspicious_threshold
        self.evil_twin_threshold = evil_twin_threshold
        self.min_score = min_score

    def correlate(
        self, events: Sequence[DetectionEvent], *, ssid_of: Mapping[str, str]
    ) -> list[CorrelatedAlert]:
        """``ssid_of`` maps BSSIDs to SSIDs (deauth frames carry no SSID)."""

        by_bssid: defaultdict[str, list[DetectionEvent]] = defaultdict(list)
        storms_by_ssid: defaultdict[str, list[DetectionEvent]] = defaultdict(list)
        for event in events:
            if not event.ssid and ssid_of.get(event.bssid):
                event = replace(event, ssid=ssid_of[event.bssid])
            by_bssid[event.bssid].append(event)
            if event.module is Module.DEAUTH and event.ssid:
                storms_by_ssid[event.ssid].append(event)

        alerts = []
        for bssid, own in by_bssid.items():
            evidence = own + self._linked_storms(bssid, own, storms_by_ssid)
            alert = self._alert(bssid, evidence)
            if alert is not None:
                alerts.append(alert)
        return sorted(alerts, key=lambda alert: (-alert.score, alert.ssid, alert.bssid))

    def score(self, evidence: Sequence[DetectionEvent]) -> float:
        strongest: dict[Module, float] = {}
        for event in evidence:
            strongest[event.module] = max(strongest.get(event.module, 0.0), event.strength)
        disbelief = math.prod(
            1.0 - self.module_weights.get(module, 0.0) * strength
            for module, strength in strongest.items()
        )
        return round(1.0 - disbelief, 3)

    def classify(self, score: float) -> Classification:
        if score >= self.evil_twin_threshold:
            return Classification.EVIL_TWIN
        if score >= self.suspicious_threshold:
            return Classification.SUSPICIOUS
        return Classification.INFO

    def _linked_storms(
        self,
        bssid: str,
        own: Sequence[DetectionEvent],
        storms_by_ssid: Mapping[str, Sequence[DetectionEvent]],
    ) -> list[DetectionEvent]:
        suspected = [e for e in own if e.module in (Module.IDENTITY, Module.ENVIRONMENT)]
        if not suspected or not suspected[0].ssid:
            return []
        return [
            replace(storm, bssid=bssid, context={**storm.context, "linked_from": storm.bssid})
            for storm in storms_by_ssid.get(suspected[0].ssid, ())
            if storm.bssid != bssid
        ]

    def _alert(self, bssid: str, evidence: list[DetectionEvent]) -> CorrelatedAlert | None:
        score = self.score(evidence)
        if score < self.min_score:
            return None
        classification = self.classify(score)
        ssid = next((event.ssid for event in evidence if event.ssid), "")
        evidence.sort(key=lambda event: (event.module, event.bssid))
        return CorrelatedAlert(
            bssid=bssid,
            ssid=ssid,
            score=score,
            classification=classification,
            modules=tuple(sorted({event.module for event in evidence})),
            evidence=tuple(evidence),
            explanation=explain(ssid, bssid, evidence, classification),
            last_seen=max(event.last_seen for event in evidence),
        )


_VERDICT = {
    Classification.EVIL_TWIN: "Independent signals agree: this is likely an Evil Twin.",
    Classification.SUSPICIOUS: "Worth checking.",
    Classification.INFO: "Weak evidence on its own.",
}


def explain(
    ssid: str, bssid: str, evidence: Sequence[DetectionEvent], classification: Classification
) -> str:
    """One readable paragraph: what was observed, and what it amounts to."""

    findings: list[str] = []
    names = {name for event in evidence for name in event.signal_names}
    if "unknown_bssid_for_trusted_ssid" in names:
        findings.append("is not an enrolled AP, yet advertises a trusted network name")
    duplicate = sorted(name for name in names if name.startswith("duplicate_bssid_"))
    if duplicate:
        findings.append(f"is transmitted by two devices at once ({', '.join(duplicate)})")
    drift = sorted(
        name
        for event in evidence
        if event.context.get("detector") == "trusted_profile"
        for name in event.signal_names
        if name != "unknown_bssid_for_trusted_ssid"
    )
    if drift:
        findings.append(f"no longer matches its trusted profile ({', '.join(drift)})")
    environment = sorted(
        name for e in evidence if e.module is Module.ENVIRONMENT for name in e.signal_names
    )
    if environment:
        findings.append(f"differs from the other APs of this network ({', '.join(environment)})")
    storms = [event for event in evidence if event.module is Module.DEAUTH]
    if any("linked_from" not in event.context for event in storms):
        findings.append("has its clients disconnected by a deauthentication storm")
    linked = sorted({str(e.context["linked_from"]) for e in storms if "linked_from" in e.context})
    if linked:
        findings.append(
            f"appeared while clients of the same network on {', '.join(linked)} "
            "were being disconnected"
        )
    subject = f"{ssid or '<hidden>'} ({bssid})"
    return f"{subject} {_join(findings)}. {_VERDICT[classification]}"


def _join(parts: Sequence[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts) or "produced detection signals"
    return ", ".join(parts[:-1]) + " and " + parts[-1]
