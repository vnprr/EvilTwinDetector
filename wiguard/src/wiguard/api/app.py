"""FastAPI application for reading WiGuard runtime state."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from wiguard.config import WiGuardConfig
from wiguard.runtime.store import DEFAULT_STATE_PATH, RuntimeStore


DEFAULT_CORS_ORIGINS = ("http://localhost:5173",)
CLASSIFICATION_RANK = {"clean": 0, "info": 1, "suspicious": 2, "evil_twin": 3}


def create_app(
    *,
    state_path: Path | str = DEFAULT_STATE_PATH,
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS,
    config: WiGuardConfig | None = None,
) -> FastAPI:
    """Create the WiGuard read API.

    The API opens short-lived SQLite connections per request, so it can run
    alongside `wiguard-sensor` without holding long read transactions.

    ``config`` is the effective :class:`WiGuardConfig`; it is exposed read-only
    at ``/api/config`` so the operator can see the thresholds the sensor runs
    with. It defaults to built-in defaults (not a disk read) for deterministic
    tests.
    """

    app = FastAPI(
        title="WiGuard Runtime API",
        version="0.1.0",
        description="Read-only API over WiGuard persistent runtime state.",
    )
    app.state.state_path = Path(state_path)
    app.state.cors_origins = tuple(cors_origins)
    app.state.config = config or WiGuardConfig()
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_origins),
            allow_credentials=False,
            allow_methods=["GET"],
            allow_headers=["*"],
        )

    @app.get("/api/health")
    def health() -> dict[str, object]:
        with _store(app) as store:
            stats = store.stats()
            return {
                "status": "ok",
                "state_path": str(app.state.state_path),
                **stats,
            }

    @app.get("/api/stats")
    def stats() -> dict[str, object]:
        with _store(app) as store:
            return {
                "state_path": str(app.state.state_path),
                **store.stats(),
            }

    @app.get("/api/config")
    def config() -> dict[str, object]:
        return app.state.config.to_public_dict()

    @app.get("/api/aps")
    def aps() -> dict[str, object]:
        with _store(app) as store:
            alerts = store.correlated_alerts(status="open")
            items = [
                _ap_summary(snapshot, alerts)
                for snapshot in store.ap_snapshots()
            ]
            return {
                "count": len(items),
                "items": items,
            }

    @app.get("/api/aps/{bssid}")
    def ap_detail(bssid: str) -> dict[str, object]:
        with _store(app) as store:
            snapshot = store.ap_snapshot(bssid)
            if snapshot is None:
                raise HTTPException(status_code=404, detail=f"AP not found: {bssid}")
            alerts = store.correlated_alerts(bssid=bssid)
            return {
                "snapshot": snapshot,
                "status": _status_for_alerts(alerts),
                "alerts": alerts,
            }

    @app.get("/api/aps/{bssid}/timeline")
    def ap_timeline(
        bssid: str,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        after_id: Annotated[int | None, Query(ge=0)] = None,
    ) -> dict[str, object]:
        with _store(app) as store:
            if store.ap_snapshot(bssid) is None and not store.correlated_alerts(bssid=bssid):
                raise HTTPException(status_code=404, detail=f"AP not found: {bssid}")
            events = store.timeline_events(bssid=bssid, after_id=after_id, limit=limit)
            return {
                "bssid": bssid.lower(),
                "count": len(events),
                "items": events,
            }

    @app.get("/api/alerts")
    def alerts(
        classification: str | None = None,
        status: str | None = None,
        ssid: str | None = None,
        bssid: str | None = None,
    ) -> dict[str, object]:
        with _store(app) as store:
            items = store.correlated_alerts(
                classification=classification,
                status=status,
                ssid=ssid,
                bssid=bssid,
            )
            return {
                "count": len(items),
                "items": items,
            }

    @app.get("/api/alerts/{alert_key}")
    def alert_detail(alert_key: str) -> dict[str, object]:
        with _store(app) as store:
            alert = store.correlated_alert(alert_key)
            if alert is None:
                raise HTTPException(status_code=404, detail=f"Alert not found: {alert_key}")
            timeline = store.timeline_events(bssid=alert.get("bssid"))
            return {
                "alert": alert,
                "timeline": timeline,
            }

    @app.get("/api/events")
    def events(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
        bssid: str | None = None,
        module: str | None = None,
    ) -> dict[str, object]:
        with _store(app) as store:
            items = store.detection_events(
                bssid=bssid,
                module=module,
                limit=limit,
                offset=offset,
                descending=True,
            )
            return {
                "count": len(items),
                "limit": limit,
                "offset": offset,
                "items": items,
            }

    @app.get("/api/timeline")
    def timeline(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        after_id: Annotated[int | None, Query(ge=0)] = None,
        bssid: str | None = None,
    ) -> dict[str, object]:
        with _store(app) as store:
            items = store.timeline_events(bssid=bssid, after_id=after_id, limit=limit)
            return {
                "count": len(items),
                "items": items,
            }

    @app.websocket("/ws/live")
    async def live(
        websocket: WebSocket,
        after_id: int = 0,
        interval_seconds: float = 2.0,
    ) -> None:
        await websocket.accept()
        latest_id = max(0, int(after_id))
        try:
            while True:
                with _store(app) as store:
                    events = store.timeline_events(after_id=latest_id, limit=100)
                if events:
                    latest_id = max(int(event["timeline_id"]) for event in events)
                await websocket.send_json(
                    {
                        "event": "timeline_batch",
                        "after_id": after_id,
                        "latest_id": latest_id,
                        "items": events,
                    }
                )
                await asyncio.sleep(max(0.5, interval_seconds))
        except WebSocketDisconnect:
            return

    return app


def _store(app: FastAPI) -> RuntimeStore:
    return RuntimeStore(app.state.state_path)


def _ap_summary(
    snapshot: dict[str, object],
    alerts: list[dict[str, object]],
) -> dict[str, object]:
    bssid = str(snapshot["bssid"]).lower()
    bssid_alerts = [alert for alert in alerts if str(alert.get("bssid")).lower() == bssid]
    last_alert = max(bssid_alerts, key=lambda alert: float(alert.get("last_seen") or 0.0), default=None)
    return {
        "bssid": bssid,
        "ssid": snapshot.get("ssid"),
        "channels": snapshot.get("channels", []),
        "last_rssi_dbm": snapshot.get("last_rssi_dbm"),
        "avg_rssi_dbm": snapshot.get("avg_rssi_dbm"),
        "total_frames": snapshot.get("total_frames"),
        "last_seen": snapshot.get("last_seen"),
        "status": _status_for_alerts(bssid_alerts),
        "last_alert": _compact_alert(last_alert) if last_alert is not None else None,
    }


def _status_for_alerts(alerts: list[dict[str, object]]) -> str:
    if not alerts:
        return "clean"
    classifications = [
        str(alert.get("classification") or "info")
        for alert in alerts
        if str(alert.get("status") or "open") == "open"
    ]
    if not classifications:
        return "clean"
    return max(classifications, key=lambda item: CLASSIFICATION_RANK.get(item, 0))


def _compact_alert(alert: dict[str, object]) -> dict[str, object]:
    return {
        "alert_key": alert.get("alert_key"),
        "classification": alert.get("classification"),
        "final_score": alert.get("final_score"),
        "last_seen": alert.get("last_seen"),
        "count": alert.get("count"),
        "contributing_modules": alert.get("contributing_modules", []),
    }
