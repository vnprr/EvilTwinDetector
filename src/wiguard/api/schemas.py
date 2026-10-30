"""Response models of the API.

They define the OpenAPI document (served at ``/openapi.json``, browsable at
``/docs``), from which the dashboard's TypeScript types are generated.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

from wiguard.config import WiGuardConfig
from wiguard.detection import TrustedProfile

Verdict = Literal["clean", "info", "suspicious", "evil_twin"]
AlertVerdict = Literal["info", "suspicious", "evil_twin"]


class Health(BaseModel):
    status: Literal["ok"]
    state_path: str
    schema_version: int


class Stats(BaseModel):
    schema_version: int
    access_points: int
    detection_events: int
    alerts: int
    open_alerts: int
    open_alerts_by_classification: dict[str, int]
    timeline_entries: int
    last_update: float | None


class SensorStatus(BaseModel):
    state: Literal["online", "stale", "replay", "unknown"]
    last_update: float | None
    age_seconds: float | None
    stale_after_seconds: float | None
    detail: str
    status: dict[str, Any] | None
    """What the sensor (or replay) last reported about itself."""


class EffectiveConfig(BaseModel):
    source_path: str | None
    """The file the API loaded; ``None`` means built-in defaults."""
    settings: WiGuardConfig


class TrustedProfiles(BaseModel):
    path: str
    profiles: list[TrustedProfile]
    error: str | None = None


class Signal(BaseModel):
    name: str
    severity: Literal["low", "medium", "high"]
    message: str
    details: dict[str, Any]


class Evidence(BaseModel):
    """Everything one detector holds against one AP."""

    module: str
    bssid: str
    ssid: str
    strength: float
    signal_names: list[str]
    signals: list[Signal]
    last_seen: float
    context: dict[str, Any]


class AccessPoint(BaseModel):
    bssid: str
    ssid: str
    channels: list[int]
    first_seen: float
    last_seen: float
    frames: int
    last_rssi_dbm: int | None
    avg_rssi_dbm: float | None
    rssi_stddev: float | None
    clock_skew_ppm: float | None
    dominant_ie_fingerprint: str | None
    vendor_ouis: list[str]
    status: Verdict
    """Verdict of the AP's open alert, or ``clean``."""
    open_alert_id: int | None
    trusted: bool


class Alert(BaseModel):
    id: int
    bssid: str
    ssid: str
    status: Literal["open", "resolved"]
    classification: AlertVerdict
    score: float
    modules: list[str]
    signal_names: list[str]
    explanation: str
    first_seen: float
    last_seen: float
    updates: int
    resolved_at: float | None
    evidence: list[Evidence]


class TimelineEntry(BaseModel):
    id: int
    observed_at: float
    kind: str
    bssid: str | None
    ssid: str | None
    alert_id: int | None
    message: str
    details: dict[str, Any]


class AccessPointDetail(BaseModel):
    access_point: AccessPoint
    summary: dict[str, Any]
    """The full feature summary (IE, clock fit, timing, sequence statistics)."""
    alerts: list[Alert]


class AlertDetail(BaseModel):
    alert: Alert
    timeline: list[TimelineEntry]


class MetricSample(BaseModel):
    observed_at: float
    frames: int
    avg_rssi_dbm: float | None
    rssi_stddev: float | None
    clock_skew_ppm: float | None


class DetectionEventRow(BaseModel):
    id: int
    module: str
    bssid: str
    ssid: str
    strength: float
    signal_names: list[str]
    first_seen: float
    last_seen: float
    event: Evidence
