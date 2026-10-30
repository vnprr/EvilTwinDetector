"""FastAPI application for reading WiGuard runtime state."""

from __future__ import annotations

import asyncio
import csv
import io
import time
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

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

    @app.get("/api/sensor")
    def sensor() -> dict[str, object]:
        with _store(app) as store:
            status = store.runtime_status()
        now = time.time()
        observed_at = None
        mode = None
        flush_interval = app.state.config.runtime.flush_interval_seconds
        if status is not None:
            observed_at = _as_float(status.get("observed_at"))
            mode = status.get("mode")
            flush_interval = _as_float(status.get("flush_interval_seconds")) or flush_interval
        if observed_at is None:
            return {
                "state": "unknown",
                "mode": mode,
                "detail": "No sensor runtime status recorded yet. "
                "This state database may come from offline pcap replay rather than a live sensor.",
                "runtime_status": status,
                "last_update": None,
                "stale_seconds": None,
            }
        # A replay database is a point-in-time import; staleness is not meaningful.
        if mode == "replay":
            return {
                "state": "replay",
                "mode": mode,
                "runtime_status": status,
                "last_update": observed_at,
                "stale_seconds": max(0.0, now - observed_at),
            }
        stale_seconds = max(0.0, now - observed_at)
        stale_threshold = max(15.0, flush_interval * 3.0)
        return {
            "state": "stale" if stale_seconds > stale_threshold else "online",
            "mode": mode or "live",
            "runtime_status": status,
            "last_update": observed_at,
            "stale_seconds": stale_seconds,
            "stale_threshold_seconds": stale_threshold,
        }

    @app.get("/api/baseline")
    def baseline() -> dict[str, object]:
        identity = app.state.config.detection.identity
        payload: dict[str, object] = {
            "baseline_path": identity.baseline_path,
            "auto_learn": identity.auto_learn,
        }
        store = app.state.config.identity_baseline_store()
        if store is None:
            payload.update({"enrolled": 0, "baselines": [], "detail": "No baseline path configured."})
            return payload
        try:
            baselines = store.load()
        except (OSError, ValueError) as exc:
            payload.update({"enrolled": 0, "baselines": [], "error": str(exc)})
            return payload
        payload.update(
            {
                "enrolled": len(baselines),
                "metadata": store.metadata.to_dict(),
                "baselines": [item.to_dict() for item in baselines],
            }
        )
        return payload

    @app.get("/api/export/alerts.csv")
    def export_alerts() -> Response:
        with _store(app) as store:
            alerts = store.correlated_alerts()
        header = [
            "alert_key", "bssid", "ssid", "classification", "final_score", "count",
            "first_seen", "last_seen", "status", "contributing_modules", "signal_names", "explanation",
        ]
        rows = [
            [
                alert.get("alert_key"), alert.get("bssid"), alert.get("ssid"),
                alert.get("classification"), alert.get("final_score"), alert.get("count"),
                alert.get("first_seen"), alert.get("last_seen"), alert.get("status"),
                "|".join(alert.get("contributing_modules", []) or []),
                "|".join(alert.get("signal_names", []) or []),
                alert.get("explanation"),
            ]
            for alert in alerts
        ]
        return _csv_response(header, rows, "wiguard-alerts.csv")

    @app.get("/api/export/aps.csv")
    def export_aps() -> Response:
        with _store(app) as store:
            snapshots = store.ap_snapshots()
        header = [
            "bssid", "ssid", "channels", "total_frames", "snapshot_count",
            "last_rssi_dbm", "avg_rssi_dbm", "rssi_stddev", "clock_skew_ppm",
            "dominant_ie_fingerprint", "first_seen", "last_seen",
        ]
        rows = [
            [
                snap.get("bssid"), snap.get("ssid"),
                "|".join(str(channel) for channel in snap.get("channels", []) or []),
                snap.get("total_frames"), snap.get("snapshot_count"),
                snap.get("last_rssi_dbm"), snap.get("avg_rssi_dbm"), snap.get("rssi_stddev"),
                snap.get("clock_skew_ppm"), snap.get("dominant_ie_fingerprint"),
                snap.get("first_seen"), snap.get("last_seen"),
            ]
            for snap in snapshots
        ]
        return _csv_response(header, rows, "wiguard-aps.csv")

    @app.get("/api/export/events.csv")
    def export_events() -> Response:
        with _store(app) as store:
            events = store.detection_events(descending=True)
        header = ["event_id", "observed_at", "module", "bssid", "ssid", "score", "signal_names"]
        rows = [
            [
                event.get("event_id"), event.get("observed_at"), event.get("module"),
                event.get("bssid"), event.get("ssid"), event.get("score"),
                "|".join(event.get("signal_names", []) or []),
            ]
            for event in events
        ]
        return _csv_response(header, rows, "wiguard-events.csv")

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

    @app.get("/api/aps/{bssid}/metrics")
    def ap_metrics(
        bssid: str,
        limit: Annotated[int, Query(ge=1, le=5000)] = 500,
    ) -> dict[str, object]:
        with _store(app) as store:
            samples = store.ap_metric_samples(bssid, limit=limit)
        return {
            "bssid": bssid.lower(),
            "count": len(samples),
            "items": samples,
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


def _csv_response(header: list[str], rows: list[list[object]], filename: str) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow(["" if value is None else value for value in row])
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _as_float(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


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
