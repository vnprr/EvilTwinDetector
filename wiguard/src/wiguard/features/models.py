"""Feature vector models."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .ie_fingerprint import IEFingerprint


@dataclass(frozen=True)
class APFeatureVector:
    """Per-frame feature vector for AP identity and behavior analysis."""

    frame_type: str
    observed_monotonic: float
    ssid: str
    bssid: str
    channel: int | None
    rssi_dbm: int | None
    ap_tsf: int | None
    radiotap_tsf: int | None
    sequence_number: int | None
    beacon_interval_tu: int | None
    capabilities: int | None
    ie_fingerprint: IEFingerprint

    @property
    def clock_local_time_us(self) -> float:
        return self.observed_monotonic * 1_000_000.0

    @property
    def has_clock_inputs(self) -> bool:
        return self.ap_tsf is not None and self.observed_monotonic > 0

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["ie_fingerprint"] = self.ie_fingerprint.to_dict()
        return payload
