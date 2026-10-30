"""API endpoints. Every request reads the state database through a read-only connection."""

from __future__ import annotations

import asyncio
import csv
import io
import time
from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import Response

from wiguard.config import WiGuardConfig
from wiguard.detection import TrustedProfileStore
from wiguard.runtime import StateReader, StoreError

from . import schemas

router = APIRouter(prefix="/api")


def _open_store(request: Request) -> Iterator[StateReader]:
    with StateReader.open(request.app.state.state_path) as reader:
        yield reader


def _config(request: Request) -> WiGuardConfig:
    config: WiGuardConfig = request.app.state.config
    return config


def _profiles(config: Annotated[WiGuardConfig, Depends(_config)]) -> TrustedProfileStore:
    return TrustedProfileStore(config.detection.identity.trusted_profiles_path)


Store = Annotated[StateReader, Depends(_open_store)]
Config = Annotated[WiGuardConfig, Depends(_config)]
Profiles = Annotated[TrustedProfileStore, Depends(_profiles)]
Limit = Annotated[int, Query(ge=1, le=1000)]


# --- system -----------------------------------------------------------------------


@router.get("/health", tags=["system"])
def health(request: Request, db: Store) -> schemas.Health:
    path = str(request.app.state.state_path)
    return schemas.Health(status="ok", state_path=path, schema_version=db.stats()["schema_version"])


@router.get("/stats", tags=["system"])
def stats(db: Store) -> schemas.Stats:
    return schemas.Stats(**db.stats())


@router.get("/sensor", tags=["system"])
def sensor(db: Store, config: Config) -> schemas.SensorStatus:
    return _sensor_status(db.status(), config.runtime.flush_interval_seconds)


@router.get("/config", tags=["system"])
def effective_config(config: Config) -> schemas.EffectiveConfig:
    return schemas.EffectiveConfig(source_path=config.source_path, settings=config)


@router.get("/trusted-profiles", tags=["system"])
def trusted_profiles(profiles: Profiles) -> schemas.TrustedProfiles:
    try:
        return schemas.TrustedProfiles(path=str(profiles.path), profiles=profiles.load())
    except (OSError, ValueError) as error:
        return schemas.TrustedProfiles(path=str(profiles.path), profiles=[], error=str(error))


# --- access points ------------------------------------------------------------------


@router.get("/aps", tags=["access points"])
def access_points(db: Store, profiles: Profiles) -> list[schemas.AccessPoint]:
    open_alerts = {alert["bssid"]: alert for alert in db.alerts(status="open")}
    trusted = _trusted_bssids(profiles)
    return [
        _access_point(row, open_alerts.get(row["bssid"]), trusted) for row in db.access_points()
    ]


@router.get("/aps/{bssid}", tags=["access points"])
def access_point(bssid: str, db: Store, profiles: Profiles) -> schemas.AccessPointDetail:
    row = db.access_point(bssid)
    if row is None:
        raise HTTPException(status_code=404, detail=f"unknown access point {bssid}")
    alerts = db.alerts(bssid=bssid)
    open_alert = next((alert for alert in alerts if alert["status"] == "open"), None)
    return schemas.AccessPointDetail(
        access_point=_access_point(row, open_alert, _trusted_bssids(profiles)),
        summary=row["summary"],
        alerts=[schemas.Alert(**alert) for alert in alerts],
    )


@router.get("/aps/{bssid}/metrics", tags=["access points"])
def ap_metrics(bssid: str, db: Store, limit: Limit = 500) -> list[schemas.MetricSample]:
    return [schemas.MetricSample(**row) for row in db.ap_metrics(bssid, limit=limit)]


@router.get("/aps/{bssid}/timeline", tags=["access points"])
def ap_timeline(bssid: str, db: Store, limit: Limit = 100) -> list[schemas.TimelineEntry]:
    return [schemas.TimelineEntry(**row) for row in db.timeline(bssid=bssid, limit=limit)]


# --- alerts, evidence, timeline --------------------------------------------------------------


@router.get("/alerts", tags=["alerts"])
def alerts(
    db: Store,
    status: Annotated[str | None, Query(pattern="^(open|resolved)$")] = None,
    classification: Annotated[str | None, Query(pattern="^(info|suspicious|evil_twin)$")] = None,
    bssid: str | None = None,
) -> list[schemas.Alert]:
    rows = db.alerts(status=status, classification=classification, bssid=bssid)
    return [schemas.Alert(**row) for row in rows]


@router.get("/alerts/{alert_id}", tags=["alerts"])
def alert(alert_id: int, db: Store) -> schemas.AlertDetail:
    row = db.alert(alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"unknown alert {alert_id}")
    timeline = db.timeline(bssid=row["bssid"], limit=200)
    return schemas.AlertDetail(
        alert=schemas.Alert(**row),
        timeline=[schemas.TimelineEntry(**entry) for entry in timeline],
    )


@router.get("/events", tags=["alerts"])
def events(
    db: Store,
    bssid: str | None = None,
    module: str | None = None,
    limit: Limit = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[schemas.DetectionEventRow]:
    rows = db.events(bssid=bssid, module=module, limit=limit, offset=offset)
    return [schemas.DetectionEventRow(**row) for row in rows]


@router.get("/timeline", tags=["alerts"])
def timeline(
    db: Store,
    bssid: str | None = None,
    after_id: Annotated[int | None, Query(ge=0)] = None,
    limit: Limit = 100,
) -> list[schemas.TimelineEntry]:
    rows = db.timeline(bssid=bssid, after_id=after_id, limit=limit)
    return [schemas.TimelineEntry(**row) for row in rows]


@router.websocket("/live")
async def live(websocket: WebSocket, after_id: int = 0) -> None:
    """Push new timeline entries as they appear (the database is polled every 2 s)."""
    await websocket.accept()
    latest = max(0, after_id)
    try:
        while True:
            with StateReader.open(websocket.app.state.state_path) as db:
                rows = db.timeline(after_id=latest, limit=200)
            if rows:
                latest = rows[-1]["id"]
                await websocket.send_json(rows)
            await asyncio.sleep(2.0)
    except (WebSocketDisconnect, StoreError):
        return


# --- CSV export ----------------------------------------------------------------------


@router.get("/export/alerts.csv", tags=["export"], response_class=Response)
def export_alerts(db: Store) -> Response:
    columns = ["id", "bssid", "ssid", "status", "classification", "score", "modules",
               "signal_names", "first_seen", "last_seen", "updates", "explanation"]  # fmt: skip
    return _csv("wiguard-alerts.csv", columns, db.alerts())


@router.get("/export/aps.csv", tags=["export"], response_class=Response)
def export_access_points(db: Store) -> Response:
    columns = ["bssid", "ssid", "channels", "frames", "first_seen", "last_seen",
               "last_rssi_dbm", "avg_rssi_dbm", "rssi_stddev", "clock_skew_ppm",
               "dominant_ie_fingerprint", "vendor_ouis"]  # fmt: skip
    return _csv("wiguard-access-points.csv", columns, db.access_points())


@router.get("/export/events.csv", tags=["export"], response_class=Response)
def export_events(db: Store) -> Response:
    columns = ["id", "module", "bssid", "ssid", "strength", "signal_names", "first_seen",
               "last_seen"]  # fmt: skip
    return _csv("wiguard-events.csv", columns, db.events(limit=1_000_000))


# --- helpers ---------------------------------------------------------------------------


def _trusted_bssids(profiles: TrustedProfileStore) -> set[str]:
    try:
        return {profile.bssid for profile in profiles.load()}
    except (OSError, ValueError):
        return set()


def _access_point(
    row: dict[str, Any], open_alert: dict[str, Any] | None, trusted: set[str]
) -> schemas.AccessPoint:
    fields = {key: value for key, value in row.items() if key in schemas.AccessPoint.model_fields}
    return schemas.AccessPoint(
        **fields,
        status=open_alert["classification"] if open_alert else "clean",
        open_alert_id=open_alert["id"] if open_alert else None,
        trusted=row["bssid"] in trusted,
    )


def _sensor_status(status: dict[str, Any] | None, flush_interval: float) -> schemas.SensorStatus:
    if status is None or "observed_at" not in status:
        return schemas.SensorStatus(
            state="unknown", last_update=None, age_seconds=None, stale_after_seconds=None,
            detail="Nothing has been recorded in this database yet.", status=status,
        )  # fmt: skip
    observed_at = float(status["observed_at"])
    age = max(0.0, time.time() - observed_at)
    if status.get("mode") == "replay":
        return schemas.SensorStatus(
            state="replay", last_update=observed_at, age_seconds=age, stale_after_seconds=None,
            detail=f"Offline replay of {status.get('source', 'a capture')}, not a live feed.",
            status=status,
        )  # fmt: skip
    stale_after = max(15.0, 3 * float(status.get("flush_interval_seconds", flush_interval)))
    stale = age > stale_after
    return schemas.SensorStatus(
        state="stale" if stale else "online",
        last_update=observed_at,
        age_seconds=age,
        stale_after_seconds=stale_after,
        detail="The sensor has stopped writing updates." if stale else "The sensor is running.",
        status=status,
    )


def _csv(filename: str, columns: list[str], rows: list[dict[str, Any]]) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_cell(row.get(column)) for column in columns])
    return Response(
        buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _cell(value: Any) -> Any:
    if isinstance(value, list):
        return "|".join(str(item) for item in value)
    return "" if value is None else value
