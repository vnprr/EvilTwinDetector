"""Environment anomaly detection through same-SSID peer comparison."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from math import ceil

from wiguard.features import APFeatureSummary


@dataclass(frozen=True)
class EnvironmentSignal:
    name: str
    severity: str
    message: str
    details: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class EnvironmentAnomalyAlert:
    bssid: str
    ssid: str
    score: float
    peer_count: int
    signals: tuple[EnvironmentSignal, ...]

    @property
    def triggered(self) -> bool:
        return bool(self.signals)

    def to_dict(self) -> dict[str, object]:
        return {
            "module": "environment_anomaly",
            "bssid": self.bssid,
            "ssid": self.ssid,
            "score": self.score,
            "peer_count": self.peer_count,
            "signals": [signal.to_dict() for signal in self.signals],
        }


@dataclass(frozen=True)
class _MajorityValue:
    value: object
    support: int
    support_ratio: float


class EnvironmentAnomalyDetector:
    """Find APs that do not look like their same-SSID peers.

    This is a conservative first implementation of Module 3. It does not need
    training data and intentionally focuses on same-SSID groups, where a
    cloned/rogue AP is easier to reason about than in a noisy public RF space.
    """

    def __init__(
        self,
        *,
        min_frames: int = 5,
        min_same_ssid_peers: int = 3,
        majority_ratio: float = 0.6,
        vendor_oui_distance_threshold: float = 0.75,
        ie_shape_distance_threshold: float = 0.45,
        beacon_interval_delta_tu: float = 20.0,
    ) -> None:
        self.min_frames = min_frames
        self.min_same_ssid_peers = min_same_ssid_peers
        self.majority_ratio = majority_ratio
        self.vendor_oui_distance_threshold = vendor_oui_distance_threshold
        self.ie_shape_distance_threshold = ie_shape_distance_threshold
        self.beacon_interval_delta_tu = beacon_interval_delta_tu

    def analyze(self, summaries: Sequence[APFeatureSummary]) -> list[EnvironmentAnomalyAlert]:
        groups = self._same_ssid_groups(summaries)
        alerts: list[EnvironmentAnomalyAlert] = []
        for ssid, group in groups.items():
            if len(group) < self.min_same_ssid_peers:
                continue
            group_alerts = self._analyze_group(ssid, group)
            alerts.extend(group_alerts)
        return sorted(alerts, key=lambda item: (-item.score, item.ssid, item.bssid))

    def _same_ssid_groups(
        self,
        summaries: Sequence[APFeatureSummary],
    ) -> dict[str, list[APFeatureSummary]]:
        groups: defaultdict[str, list[APFeatureSummary]] = defaultdict(list)
        for summary in summaries:
            if summary.frames < self.min_frames:
                continue
            if not summary.ssid or summary.ssid == "<unknown>":
                continue
            groups[summary.ssid].append(summary)
        return dict(groups)

    def _analyze_group(
        self,
        ssid: str,
        group: Sequence[APFeatureSummary],
    ) -> list[EnvironmentAnomalyAlert]:
        majority_ie_hash = self._majority(
            summary.dominant_ie_fingerprint
            for summary in group
            if summary.dominant_ie_fingerprint is not None
        )
        majority_vendor_ouis = self._majority(tuple(summary.vendor_ouis) for summary in group)
        majority_stable_ie_ids = self._majority(tuple(summary.stable_ie_ids_union) for summary in group)
        majority_key_ie_ids = self._majority(tuple(summary.key_ie_ids_union) for summary in group)
        majority_interval_tu = self._majority(
            interval
            for interval in (_beacon_interval_tu(summary) for summary in group)
            if interval is not None
        )

        alerts: list[EnvironmentAnomalyAlert] = []
        for summary in group:
            signals = tuple(
                self._signals(
                    summary,
                    peer_count=len(group),
                    majority_ie_hash=majority_ie_hash,
                    majority_vendor_ouis=majority_vendor_ouis,
                    majority_stable_ie_ids=majority_stable_ie_ids,
                    majority_key_ie_ids=majority_key_ie_ids,
                    majority_interval_tu=majority_interval_tu,
                )
            )
            if not signals:
                continue
            score = min(1.0, sum(_signal_weight(signal) for signal in signals))
            alerts.append(
                EnvironmentAnomalyAlert(
                    bssid=summary.bssid,
                    ssid=ssid,
                    score=round(score, 3),
                    peer_count=len(group),
                    signals=signals,
                )
            )
        return alerts

    def _signals(
        self,
        summary: APFeatureSummary,
        *,
        peer_count: int,
        majority_ie_hash: _MajorityValue | None,
        majority_vendor_ouis: _MajorityValue | None,
        majority_stable_ie_ids: _MajorityValue | None,
        majority_key_ie_ids: _MajorityValue | None,
        majority_interval_tu: _MajorityValue | None,
    ) -> list[EnvironmentSignal]:
        signals: list[EnvironmentSignal] = []
        if (
            majority_ie_hash is not None
            and summary.dominant_ie_fingerprint is not None
            and summary.dominant_ie_fingerprint != majority_ie_hash.value
        ):
            signals.append(
                EnvironmentSignal(
                    name="same_ssid_ie_fingerprint_outlier",
                    severity="high",
                    message="AP IE fingerprint differs from the same-SSID majority profile",
                    details={
                        "peer_count": peer_count,
                        "majority_fingerprint": majority_ie_hash.value,
                        "current_fingerprint": summary.dominant_ie_fingerprint,
                        "majority_support": majority_ie_hash.support,
                        "majority_support_ratio": round(majority_ie_hash.support_ratio, 3),
                    },
                )
            )

        if majority_vendor_ouis is not None:
            current_vendor_ouis = tuple(summary.vendor_ouis)
            distance = _jaccard_distance(current_vendor_ouis, majority_vendor_ouis.value)
            if distance >= self.vendor_oui_distance_threshold:
                signals.append(
                    EnvironmentSignal(
                        name="same_ssid_vendor_oui_outlier",
                        severity="high",
                        message="AP vendor OUI set differs from the same-SSID majority profile",
                        details={
                            "peer_count": peer_count,
                            "majority_vendor_ouis": majority_vendor_ouis.value,
                            "current_vendor_ouis": current_vendor_ouis,
                            "jaccard_distance": round(distance, 3),
                            "threshold": self.vendor_oui_distance_threshold,
                            "majority_support": majority_vendor_ouis.support,
                            "majority_support_ratio": round(majority_vendor_ouis.support_ratio, 3),
                        },
                    )
                )

        shape_signal = self._ie_shape_signal(
            summary,
            peer_count=peer_count,
            majority_stable_ie_ids=majority_stable_ie_ids,
            majority_key_ie_ids=majority_key_ie_ids,
        )
        if shape_signal is not None:
            signals.append(shape_signal)

        current_interval_tu = _beacon_interval_tu(summary)
        if (
            majority_interval_tu is not None
            and current_interval_tu is not None
            and abs(current_interval_tu - majority_interval_tu.value)
            >= self.beacon_interval_delta_tu
        ):
            signals.append(
                EnvironmentSignal(
                    name="same_ssid_beacon_interval_outlier",
                    severity="medium",
                    message="AP beacon interval differs from the same-SSID majority profile",
                    details={
                        "peer_count": peer_count,
                        "majority_interval_tu": majority_interval_tu.value,
                        "current_interval_tu": current_interval_tu,
                        "delta_tu": round(abs(current_interval_tu - majority_interval_tu.value), 3),
                        "threshold_tu": self.beacon_interval_delta_tu,
                        "majority_support": majority_interval_tu.support,
                        "majority_support_ratio": round(majority_interval_tu.support_ratio, 3),
                    },
                )
            )
        return signals

    def _ie_shape_signal(
        self,
        summary: APFeatureSummary,
        *,
        peer_count: int,
        majority_stable_ie_ids: _MajorityValue | None,
        majority_key_ie_ids: _MajorityValue | None,
    ) -> EnvironmentSignal | None:
        distances: dict[str, float] = {}
        majority_details: dict[str, object] = {}
        if majority_stable_ie_ids is not None:
            distances["stable_ie_ids"] = _jaccard_distance(
                summary.stable_ie_ids_union,
                majority_stable_ie_ids.value,
            )
            majority_details["majority_stable_ie_ids"] = majority_stable_ie_ids.value
            majority_details["majority_stable_support"] = majority_stable_ie_ids.support
        if majority_key_ie_ids is not None:
            distances["key_ie_ids"] = _jaccard_distance(
                summary.key_ie_ids_union,
                majority_key_ie_ids.value,
            )
            majority_details["majority_key_ie_ids"] = majority_key_ie_ids.value
            majority_details["majority_key_support"] = majority_key_ie_ids.support
        if not distances:
            return None

        shape_distance = max(distances.values())
        if shape_distance < self.ie_shape_distance_threshold:
            return None
        return EnvironmentSignal(
            name="same_ssid_ie_shape_outlier",
            severity="medium",
            message="AP IE element shape differs from the same-SSID majority profile",
            details={
                "peer_count": peer_count,
                "current_stable_ie_ids": summary.stable_ie_ids_union,
                "current_key_ie_ids": summary.key_ie_ids_union,
                "jaccard_distances": {key: round(value, 3) for key, value in distances.items()},
                "threshold": self.ie_shape_distance_threshold,
                **majority_details,
            },
        )

    def _majority(self, values: Iterable[object]) -> _MajorityValue | None:
        normalized = tuple(value for value in values if value is not None)
        if not normalized:
            return None
        counts = Counter(normalized)
        value, support = counts.most_common(1)[0]
        required_support = max(2, ceil(len(normalized) * self.majority_ratio))
        if support < required_support:
            return None
        return _MajorityValue(
            value=value,
            support=support,
            support_ratio=support / len(normalized),
        )


def _beacon_interval_tu(summary: APFeatureSummary) -> float | None:
    expected_us = summary.beacon_timing.expected_interval_us
    if expected_us is None:
        return None
    return round(expected_us / 1024.0, 3)


def _jaccard_distance(left: Sequence[object], right: object) -> float:
    left_set = set(left)
    right_set = set(right) if isinstance(right, Sequence) and not isinstance(right, str) else {right}
    if not left_set and not right_set:
        return 0.0
    if not left_set or not right_set:
        return 1.0
    return 1.0 - (len(left_set & right_set) / len(left_set | right_set))


def _signal_weight(signal: EnvironmentSignal) -> float:
    if signal.severity == "high":
        return 0.4
    if signal.severity == "medium":
        return 0.25
    return 0.1
