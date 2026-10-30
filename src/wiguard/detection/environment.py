"""Environment anomaly detection: compare APs that share one SSID.

Several APs of one organisation (one SSID, many BSSIDs) usually run the same
hardware and configuration. An AP that advertises the same name but looks
different from the clear majority — another vendor, another IE layout,
another beacon interval — is a likely impersonator. No training data and no
enrollment are needed, which complements the trusted-profile check.

The comparison needs a real majority, so it only runs for SSIDs with at least
``min_same_ssid_aps`` APs; one legitimate AP plus one twin is a job for
identity verification.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Hashable, Iterable, Sequence
from dataclasses import dataclass
from math import ceil

from wiguard.features import APSummary

from .events import DetectionEvent, Module, Severity, Signal


@dataclass(frozen=True, slots=True)
class _Majority:
    value: Hashable
    support: int
    total: int


class EnvironmentAnomalyDetector:
    def __init__(
        self,
        *,
        min_frames: int = 5,
        min_same_ssid_aps: int = 3,
        majority_ratio: float = 0.6,
        vendor_oui_distance_threshold: float = 0.75,
        ie_shape_distance_threshold: float = 0.45,
        beacon_interval_delta_tu: int = 20,
    ) -> None:
        self.min_frames = min_frames
        self.min_same_ssid_aps = min_same_ssid_aps
        self.majority_ratio = majority_ratio
        self.vendor_oui_distance_threshold = vendor_oui_distance_threshold
        self.ie_shape_distance_threshold = ie_shape_distance_threshold
        self.beacon_interval_delta_tu = beacon_interval_delta_tu

    def evaluate(self, summaries: Sequence[APSummary]) -> list[DetectionEvent]:
        groups: defaultdict[str, list[APSummary]] = defaultdict(list)
        for summary in summaries:
            if summary.ssid and summary.frames >= self.min_frames:
                groups[summary.ssid].append(summary)
        events = []
        for group in groups.values():
            if len(group) >= self.min_same_ssid_aps:
                events.extend(self._evaluate_group(group))
        return events

    def _evaluate_group(self, group: Sequence[APSummary]) -> list[DetectionEvent]:
        majority = {
            "ie": self._majority(s.dominant_ie_fingerprint for s in group),
            "vendor": self._majority(s.vendor_ouis for s in group),
            "ie_ids": self._majority(s.ie_ids for s in group),
            "key_ie_ids": self._majority(s.key_ie_ids for s in group),
            "interval": self._majority(s.timing.beacon_interval_tu for s in group),
        }
        events = []
        for summary in group:
            signals = [
                signal
                for signal in (
                    self._fingerprint_outlier(summary, majority["ie"]),
                    self._vendor_outlier(summary, majority["vendor"]),
                    self._shape_outlier(summary, majority["ie_ids"], majority["key_ie_ids"]),
                    self._interval_outlier(summary, majority["interval"]),
                )
                if signal is not None
            ]
            if signals:
                events.append(
                    DetectionEvent(
                        module=Module.ENVIRONMENT,
                        bssid=summary.bssid,
                        ssid=summary.ssid,
                        signals=tuple(signals),
                        last_seen=summary.last_seen,
                        context={"same_ssid_aps": len(group)},
                    )
                )
        return events

    def _majority(self, values: Iterable[Hashable | None]) -> _Majority | None:
        present = [value for value in values if value is not None]
        if not present:
            return None
        value, support = Counter(present).most_common(1)[0]
        if support < max(2, ceil(len(present) * self.majority_ratio)):
            return None
        return _Majority(value, support, len(present))

    def _fingerprint_outlier(self, summary: APSummary, majority: _Majority | None) -> Signal | None:
        current = summary.dominant_ie_fingerprint
        if majority is None or current is None or current == majority.value:
            return None
        return Signal(
            name="same_ssid_ie_fingerprint_outlier",
            severity=Severity.HIGH,
            message="IE fingerprint differs from the same-SSID majority",
            details={
                "majority": majority.value,
                "current": current,
                "majority_support": f"{majority.support}/{majority.total}",
            },
        )

    def _vendor_outlier(self, summary: APSummary, majority: _Majority | None) -> Signal | None:
        if majority is None or not isinstance(majority.value, tuple):
            return None
        distance = _jaccard_distance(summary.vendor_ouis, majority.value)
        if distance < self.vendor_oui_distance_threshold:
            return None
        return Signal(
            name="same_ssid_vendor_oui_outlier",
            severity=Severity.HIGH,
            message="Vendor OUIs differ from the same-SSID majority",
            details={
                "majority": list(majority.value),
                "current": list(summary.vendor_ouis),
                "jaccard_distance": round(distance, 3),
                "threshold": self.vendor_oui_distance_threshold,
            },
        )

    def _shape_outlier(
        self,
        summary: APSummary,
        ie_ids: _Majority | None,
        key_ie_ids: _Majority | None,
    ) -> Signal | None:
        distances = {
            name: _jaccard_distance(current, majority.value)
            for name, current, majority in (
                ("ie_ids", summary.ie_ids, ie_ids),
                ("key_ie_ids", summary.key_ie_ids, key_ie_ids),
            )
            if majority is not None and isinstance(majority.value, tuple)
        }
        if not distances or max(distances.values()) < self.ie_shape_distance_threshold:
            return None
        return Signal(
            name="same_ssid_ie_shape_outlier",
            severity=Severity.MEDIUM,
            message="The set of advertised IEs differs from the same-SSID majority",
            details={
                "jaccard_distances": {key: round(value, 3) for key, value in distances.items()},
                "threshold": self.ie_shape_distance_threshold,
            },
        )

    def _interval_outlier(self, summary: APSummary, majority: _Majority | None) -> Signal | None:
        current = summary.timing.beacon_interval_tu
        if majority is None or current is None or not isinstance(majority.value, int):
            return None
        delta = abs(current - majority.value)
        if delta < self.beacon_interval_delta_tu:
            return None
        return Signal(
            name="same_ssid_beacon_interval_outlier",
            severity=Severity.MEDIUM,
            message="Beacon interval differs from the same-SSID majority",
            details={
                "majority_tu": majority.value,
                "current_tu": current,
                "threshold_tu": self.beacon_interval_delta_tu,
            },
        )


def _jaccard_distance(left: Iterable[Hashable], right: Iterable[Hashable]) -> float:
    a, b = set(left), set(right)
    if not a and not b:
        return 0.0
    return 1.0 - len(a & b) / len(a | b)
