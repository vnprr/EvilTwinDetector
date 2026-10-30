"""Read-only HTTP/WebSocket API over the sensor's state database.

The API never writes: every request opens the database in SQLite read-only
mode, so it cannot interfere with the sensor and cannot change detection.
Starting a capture, enrolling trusted profiles or changing thresholds are
deliberate command-line actions, not something a browser can trigger.
"""

from __future__ import annotations

import asyncio
import csv
import io
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from wiguard.config import WiGuardConfig
from wiguard.detection import TrustedProfileStore
from wiguard.runtime.store import RuntimeStore, StoreError

from . import schemas


def _open_store(request: Request) -> Iterator[RuntimeStore]:
    with RuntimeStore.open_readonly(request.app.state.state_path) as store:
        yield store


Store = Annotated[RuntimeStore, Depends(_open_store)]
Limit = Annotated[int, Query(ge=1, le=1000)]


def create_app(config: WiGuardConfig | None = None, *, state_path: Path | None = None) -> FastAPI:
    config = config or WiGuardConfig()
    state_path = Path(state_path or config.runtime.state_path)
    profiles = TrustedProfileStore(config.detection.identity.trusted_profiles_path)

    app = FastAPI(
        title="WiGuard API",
        version="0.2.0",
        description="Read-only access to WiGuard's access points, alerts and evidence.",
    )
    app.state.state_path = state_path
    app.add_middleware(
        CORSMiddleware, allow_origins=list(config.api.cors_origins), allow_methods=["GET"]
    )

    @app.exception_handler(StoreError)
    async def store_unavailable(_: Request, error: StoreError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(error)})

    def trusted_bssids() -> set[str]:
        try:
            return {profile.bssid for profile in profiles.load()}
        except (OSError, ValueError):
            return set()

    @app.get("/api/health")
    def health(db: Store) -> schemas.Health:
        return schemas.Health(
            status="ok", state_path=str(state_path), schema_version=db.stats()["schema_version"]
        )

    @app.get("/api/stats")
    def stats(db: Store) -> schemas.Stats:
        return schemas.Stats(**db.stats())

    @app.get("/api/config")
    def effective_config() -> dict[str, Any]:
        return {"source_path": config.source_path, **config.model_dump(mode="json")}

    @app.get("/api/sensor")
    def sensor(db: Store) -> schemas.SensorStatus:
        return _sensor_status(db.status(), config.runtime.flush_interval_seconds)

    @app.get("/api/trusted-profiles")
    def trusted_profiles() -> schemas.TrustedProfiles:
        try:
            loaded = profiles.load()
        except (OSError, ValueError) as error:
            return schemas.TrustedProfiles(
                path=str(profiles.path), enrolled=0, profiles=[], error=str(error)
            )
        return schemas.TrustedProfiles(
            path=str(profiles.path),
            enrolled=len(loaded),
            profiles=[profile.to_dict() for profile in loaded],
        )

    @app.get("/api/aps")
    def access_points(db: Store) -> schemas.Items[schemas.AccessPoint]:
        open_alerts = {alert["bssid"]: alert for alert in db.alerts(status="open")}
        trusted = trusted_bssids()
        items = [
            _access_point(row, open_alerts.get(row["bssid"]), trusted) for row in db.access_points()
        ]
        return schemas.Items(count=len(items), items=items)

    @app.get("/api/aps/{bssid}")
    def access_point(bssid: str, db: Store) -> schemas.AccessPointDetail:
        row = db.access_point(bssid)
        if row is None:
            raise HTTPException(status_code=404, detail=f"unknown access point {bssid}")
        alerts = db.alerts(bssid=bssid)
        open_alert = next((alert for alert in alerts if alert["status"] == "open"), None)
        return schemas.AccessPointDetail(
            access_point=_access_point(row, open_alert, trusted_bssids()),
            summary=row["summary"],
            alerts=[schemas.Alert(**alert) for alert in alerts],
        )

    @app.get("/api/aps/{bssid}/metrics")
    def ap_metrics(
        bssid: str, db: Store, limit: Limit = 500
    ) -> schemas.Items[schemas.MetricSample]:
        items = [schemas.MetricSample(**row) for row in db.ap_metrics(bssid, limit=limit)]
        return schemas.Items(count=len(items), items=items)

    @app.get("/api/aps/{bssid}/timeline")
    def ap_timeline(
        bssid: str, db: Store, limit: Limit = 100
    ) -> schemas.Items[schemas.TimelineEntry]:
        items = [schemas.TimelineEntry(**row) for row in db.timeline(bssid=bssid, limit=limit)]
        return schemas.Items(count=len(items), items=items)

    @app.get("/api/alerts")
    def alerts(
        db: Store,
        status: Annotated[str | None, Query(pattern="^(open|resolved)$")] = None,
        classification: Annotated[
            str | None, Query(pattern="^(info|suspicious|evil_twin)$")
        ] = None,
        bssid: str | None = None,
    ) -> schemas.Items[schemas.Alert]:
        rows = db.alerts(status=status, classification=classification, bssid=bssid)
        items = [schemas.Alert(**row) for row in rows]
        return schemas.Items(count=len(items), items=items)

    @app.get("/api/alerts/{alert_id}")
    def alert(alert_id: int, db: Store) -> schemas.AlertDetail:
        row = db.alert(alert_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"unknown alert {alert_id}")
        timeline = db.timeline(bssid=row["bssid"], limit=200)
        return schemas.AlertDetail(
            alert=schemas.Alert(**row),
            timeline=[schemas.TimelineEntry(**entry) for entry in timeline],
        )

    @app.get("/api/events")
    def events(
        db: Store,
        bssid: str | None = None,
        module: str | None = None,
        limit: Limit = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> schemas.Items[schemas.DetectionEventRow]:
        rows = db.events(bssid=bssid, module=module, limit=limit, offset=offset)
        items = [schemas.DetectionEventRow(**row) for row in rows]
        return schemas.Items(count=len(items), items=items)

    @app.get("/api/timeline")
    def timeline(
        db: Store,
        bssid: str | None = None,
        after_id: Annotated[int | None, Query(ge=0)] = None,
        limit: Limit = 100,
    ) -> schemas.Items[schemas.TimelineEntry]:
        rows = db.timeline(bssid=bssid, after_id=after_id, limit=limit)
        items = [schemas.TimelineEntry(**row) for row in rows]
        return schemas.Items(count=len(items), items=items)

    @app.get("/api/export/alerts.csv")
    def export_alerts(db: Store) -> Response:
        columns = ["id", "bssid", "ssid", "status", "classification", "score", "modules",
                   "signal_names", "first_seen", "last_seen", "updates", "explanation"]  # fmt: skip
        return _csv("wiguard-alerts.csv", columns, db.alerts())

    @app.get("/api/export/aps.csv")
    def export_aps(db: Store) -> Response:
        columns = ["bssid", "ssid", "channels", "frames", "first_seen", "last_seen",
                   "last_rssi_dbm", "avg_rssi_dbm", "rssi_stddev", "clock_skew_ppm",
                   "dominant_ie_fingerprint", "vendor_ouis"]  # fmt: skip
        return _csv("wiguard-access-points.csv", columns, db.access_points())

    @app.get("/api/export/events.csv")
    def export_events(db: Store) -> Response:
        columns = ["id", "module", "bssid", "ssid", "strength", "signal_names", "first_seen",
                   "last_seen"]  # fmt: skip
        return _csv("wiguard-events.csv", columns, db.events(limit=1_000_000))

    @app.websocket("/ws/live")
    async def live(websocket: WebSocket, after_id: int = 0) -> None:
        """Push new timeline entries as they appear (polled every two seconds)."""
        await websocket.accept()
        latest = max(0, after_id)
        try:
            while True:
                with RuntimeStore.open_readonly(state_path) as db:
                    rows = db.timeline(after_id=latest, limit=200)
                if rows:
                    latest = rows[-1]["id"]
                    await websocket.send_json({"latest_id": latest, "items": rows})
                await asyncio.sleep(2.0)
        except (WebSocketDisconnect, StoreError):
            return

    return app


def _access_point(
    row: dict[str, Any], open_alert: dict[str, Any] | None, trusted: set[str]
) -> schemas.AccessPoint:
    return schemas.AccessPoint(
        **{key: value for key, value in row.items() if key in schemas.AccessPoint.model_fields},
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
