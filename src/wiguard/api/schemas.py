"""Response models of the read-only API (also its OpenAPI documentation at /docs)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

Verdict = Literal["clean", "info", "suspicious", "evil_twin"]


class Items[T](BaseModel):
    count: int
    items: list[T]


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
    classification: Verdict
    score: float
    modules: list[str]
    signal_names: list[str]
    explanation: str
    first_seen: float
    last_seen: float
    updates: int
    resolved_at: float | None
    evidence: list[dict[str, Any]]


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
    event: dict[str, Any]


class SensorStatus(BaseModel):
    state: Literal["online", "stale", "replay", "unknown"]
    last_update: float | None
    age_seconds: float | None
    stale_after_seconds: float | None
    detail: str
    status: dict[str, Any] | None


class TrustedProfiles(BaseModel):
    path: str
    enrolled: int
    profiles: list[dict[str, Any]]
    error: str | None = None
