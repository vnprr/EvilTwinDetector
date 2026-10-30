"""SQLite runtime state: what the sensor saw and concluded, for the API and dashboard.

Writers (the sensor, ``wiguard replay``) call :meth:`RuntimeStore.record` with
a :class:`PipelineResult`. The API opens the same file read-only.

Alerts are *incidents*: one open alert per AP, updated while evidence keeps
coming in, escalated if the verdict gets worse, and resolved after
``resolve_after`` seconds without evidence. Raw detection events are logged
when they first appear or change, not on every flush.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wiguard.correlation import Classification, CorrelatedAlert
from wiguard.detection import DetectionEvent
from wiguard.features import APSummary
from wiguard.pipeline import PipelineResult

SCHEMA_VERSION = 3
METRIC_SAMPLES_PER_AP = 2_000

_SCHEMA = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE access_points (
    bssid TEXT PRIMARY KEY,
    ssid TEXT NOT NULL,
    channels TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    frames INTEGER NOT NULL,
    last_rssi_dbm INTEGER,
    avg_rssi_dbm REAL,
    rssi_stddev REAL,
    clock_skew_ppm REAL,
    dominant_ie_fingerprint TEXT,
    vendor_ouis TEXT NOT NULL,
    summary TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE ap_metrics (
    id INTEGER PRIMARY KEY,
    bssid TEXT NOT NULL,
    observed_at REAL NOT NULL,
    frames INTEGER NOT NULL,
    avg_rssi_dbm REAL,
    rssi_stddev REAL,
    clock_skew_ppm REAL
);
CREATE INDEX ap_metrics_by_bssid ON ap_metrics (bssid, id);

CREATE TABLE detection_events (
    id INTEGER PRIMARY KEY,
    module TEXT NOT NULL,
    bssid TEXT NOT NULL,
    ssid TEXT NOT NULL,
    strength REAL NOT NULL,
    signal_names TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    event TEXT NOT NULL
);
CREATE INDEX detection_events_by_source ON detection_events (module, bssid, id);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    bssid TEXT NOT NULL,
    ssid TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
    classification TEXT NOT NULL,
    score REAL NOT NULL,
    modules TEXT NOT NULL,
    signal_names TEXT NOT NULL,
    explanation TEXT NOT NULL,
    evidence TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    updates INTEGER NOT NULL,
    resolved_at REAL
);
CREATE INDEX alerts_by_bssid ON alerts (bssid, status);

CREATE TABLE timeline (
    id INTEGER PRIMARY KEY,
    observed_at REAL NOT NULL,
    kind TEXT NOT NULL,
    bssid TEXT,
    ssid TEXT,
    alert_id INTEGER,
    message TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX timeline_by_bssid ON timeline (bssid, id);
"""

_JSON_COLUMNS = {"channels", "vendor_ouis", "summary", "signal_names", "modules", "evidence",
                 "event", "details"}  # fmt: skip

Row = dict[str, Any]


class StoreError(RuntimeError):
    """The state database cannot be used (missing schema or wrong version)."""


@dataclass(frozen=True)
class RecordSummary:
    access_points: int
    events_logged: int
    alerts_opened: int
    alerts_escalated: int
    alerts_resolved: int
    open_alerts: int

    def to_dict(self) -> dict[str, int]:
        return dict(vars(self))


def _connect(target: str, *, uri: bool = False) -> sqlite3.Connection:
    # One store (and connection) serves one request or one sensor at a time,
    # but a web framework may run the parts of a request on different worker
    # threads; sharing a connection sequentially across threads is safe.
    return sqlite3.connect(target, uri=uri, check_same_thread=False)


class RuntimeStore:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._db = connection
        self._db.row_factory = sqlite3.Row

    @classmethod
    def open(cls, path: Path | str) -> RuntimeStore:
        """Open (or create) the database for writing."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        store = cls(_connect(str(path)))
        if not store._has_schema():
            with store._db:
                store._db.executescript(_SCHEMA)
                store._set_meta("schema_version", SCHEMA_VERSION)
        store._check_version(path)
        return store

    @classmethod
    def open_readonly(cls, path: Path | str) -> RuntimeStore:
        """Open the database without any write access.

        A database that does not exist yet reads as empty: the API can start
        before the sensor has written anything.
        """
        path = Path(path)
        if not path.is_file():
            store = cls(_connect(":memory:"))
            store._db.executescript(_SCHEMA)
            store._set_meta("schema_version", SCHEMA_VERSION)
            return store
        store = cls(_connect(f"{path.resolve().as_uri()}?mode=ro", uri=True))
        store._check_version(path)
        return store

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> RuntimeStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # --- writing --------------------------------------------------------------

    def record(
        self, result: PipelineResult, *, observed_at: float, resolve_after: float
    ) -> RecordSummary:
        """Persist one pipeline evaluation in a single transaction."""

        with self._db:
            for summary in result.access_points:
                self._upsert_access_point(summary, observed_at)
            events_logged = sum(
                self._log_event(event, observed_at, resolve_after) for event in result.events
            )
            opened = escalated = 0
            for alert in result.alerts:
                outcome = self._upsert_alert(alert, observed_at)
                opened += outcome == "opened"
                escalated += outcome == "escalated"
            resolved = self._resolve_quiet_alerts(
                {alert.bssid for alert in result.alerts}, observed_at, resolve_after
            )
        return RecordSummary(
            access_points=len(result.access_points),
            events_logged=events_logged,
            alerts_opened=opened,
            alerts_escalated=escalated,
            alerts_resolved=resolved,
            open_alerts=self._count("alerts", "status = 'open'"),
        )

    def set_status(self, status: dict[str, Any]) -> None:
        with self._db:
            self._set_meta("sensor_status", status)

    def _upsert_access_point(self, ap: APSummary, observed_at: float) -> None:
        self._db.execute(
            """
            INSERT INTO access_points VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (bssid) DO UPDATE SET
                ssid = excluded.ssid, channels = excluded.channels,
                first_seen = min(first_seen, excluded.first_seen), last_seen = excluded.last_seen,
                frames = excluded.frames, last_rssi_dbm = excluded.last_rssi_dbm,
                avg_rssi_dbm = excluded.avg_rssi_dbm, rssi_stddev = excluded.rssi_stddev,
                clock_skew_ppm = excluded.clock_skew_ppm,
                dominant_ie_fingerprint = excluded.dominant_ie_fingerprint,
                vendor_ouis = excluded.vendor_ouis, summary = excluded.summary,
                updated_at = excluded.updated_at
            """,
            (
                ap.bssid, ap.ssid, _dumps(ap.channels), ap.first_seen, ap.last_seen, ap.frames,
                ap.last_rssi_dbm, ap.avg_rssi_dbm, ap.rssi_stddev, _round(ap.clock_skew_ppm),
                ap.dominant_ie_fingerprint, _dumps(ap.vendor_ouis), _dumps(ap.to_dict()),
                observed_at,
            ),
        )  # fmt: skip
        previous = self._db.execute(
            "SELECT frames FROM ap_metrics WHERE bssid = ? ORDER BY id DESC LIMIT 1", (ap.bssid,)
        ).fetchone()
        if previous is not None and previous["frames"] == ap.frames:
            return  # not heard since the last sample: nothing new to plot
        self._db.execute(
            "INSERT INTO ap_metrics (bssid, observed_at, frames, avg_rssi_dbm, rssi_stddev,"
            " clock_skew_ppm) VALUES (?, ?, ?, ?, ?, ?)",
            (
                ap.bssid,
                observed_at,
                ap.frames,
                ap.avg_rssi_dbm,
                ap.rssi_stddev,
                _round(ap.clock_skew_ppm),
            ),
        )
        self._db.execute(
            """
            DELETE FROM ap_metrics WHERE bssid = ? AND id <= (
                SELECT id FROM ap_metrics WHERE bssid = ? ORDER BY id DESC LIMIT 1 OFFSET ?
            )
            """,
            (ap.bssid, ap.bssid, METRIC_SAMPLES_PER_AP),
        )

    def _log_event(self, event: DetectionEvent, observed_at: float, resolve_after: float) -> bool:
        names = sorted(event.signal_names)
        last = self._db.execute(
            "SELECT id, signal_names, last_seen FROM detection_events"
            " WHERE module = ? AND bssid = ? ORDER BY id DESC LIMIT 1",
            (event.module.value, event.bssid),
        ).fetchone()
        unchanged = last is not None and json.loads(last["signal_names"]) == names
        if unchanged and observed_at - last["last_seen"] <= resolve_after:
            self._db.execute(
                "UPDATE detection_events SET last_seen = ?, strength = ?, event = ? WHERE id = ?",
                (observed_at, event.strength, _dumps(event.to_dict()), last["id"]),
            )
            return False
        self._db.execute(
            "INSERT INTO detection_events (module, bssid, ssid, strength, signal_names,"
            " first_seen, last_seen, event) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.module.value, event.bssid, event.ssid, event.strength, _dumps(names),
                observed_at, observed_at, _dumps(event.to_dict()),
            ),
        )  # fmt: skip
        self._timeline(
            observed_at, "detection", event.bssid, event.ssid, None,
            f"{event.module.value}: {', '.join(names)}", {"strength": event.strength},
        )  # fmt: skip
        return True

    def _upsert_alert(self, alert: CorrelatedAlert, observed_at: float) -> str:
        modules = [module.value for module in alert.modules]
        evidence = _dumps([event.to_dict() for event in alert.evidence])
        current = self._db.execute(
            "SELECT * FROM alerts WHERE bssid = ? AND status = 'open'", (alert.bssid,)
        ).fetchone()
        if current is None:
            cursor = self._db.execute(
                "INSERT INTO alerts (bssid, ssid, status, classification, score, modules,"
                " signal_names, explanation, evidence, first_seen, last_seen, updates)"
                " VALUES (?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    alert.bssid, alert.ssid, alert.classification.value, alert.score,
                    _dumps(modules), _dumps(alert.signal_names), alert.explanation, evidence,
                    observed_at, observed_at,
                ),
            )  # fmt: skip
            self._timeline(
                observed_at, "alert_opened", alert.bssid, alert.ssid, cursor.lastrowid,
                alert.explanation, {"classification": alert.classification.value,
                                    "score": alert.score},
            )  # fmt: skip
            return "opened"

        previous = Classification(current["classification"])
        escalated = alert.classification.rank > previous.rank
        peak = alert.classification if escalated else previous
        self._db.execute(
            """
            UPDATE alerts SET ssid = ?, classification = ?, score = max(score, ?),
                modules = ?, signal_names = ?, explanation = ?, evidence = ?,
                last_seen = ?, updates = updates + 1
            WHERE id = ?
            """,
            (
                alert.ssid or current["ssid"], peak.value, alert.score,
                _dumps(sorted({*json.loads(current["modules"]), *modules})),
                _dumps(sorted({*json.loads(current["signal_names"]), *alert.signal_names})),
                alert.explanation, evidence, observed_at, current["id"],
            ),
        )  # fmt: skip
        if not escalated:
            return "updated"
        self._timeline(
            observed_at, "alert_escalated", alert.bssid, alert.ssid, current["id"],
            alert.explanation, {"from": previous.value, "to": alert.classification.value,
                                "score": alert.score},
        )  # fmt: skip
        return "escalated"

    def _resolve_quiet_alerts(
        self, active_bssids: set[str], observed_at: float, resolve_after: float
    ) -> int:
        quiet = [
            row
            for row in self._db.execute(
                "SELECT id, bssid, ssid FROM alerts WHERE status = 'open' AND last_seen < ?",
                (observed_at - resolve_after,),
            )
            if row["bssid"] not in active_bssids
        ]
        for row in quiet:
            self._db.execute(
                "UPDATE alerts SET status = 'resolved', resolved_at = ? WHERE id = ?",
                (observed_at, row["id"]),
            )
            self._timeline(
                observed_at, "alert_resolved", row["bssid"], row["ssid"], row["id"],
                f"No new evidence for {resolve_after:.0f} s; alert resolved.", {},
            )  # fmt: skip
        return len(quiet)

    def _timeline(
        self,
        observed_at: float,
        kind: str,
        bssid: str | None,
        ssid: str | None,
        alert_id: int | None,
        message: str,
        details: dict[str, Any],
    ) -> None:
        self._db.execute(
            "INSERT INTO timeline (observed_at, kind, bssid, ssid, alert_id, message, details)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (observed_at, kind, bssid, ssid, alert_id, message, _dumps(details)),
        )

    # --- reading ------------------------------------------------------------

    def status(self) -> dict[str, Any] | None:
        value = self._meta("sensor_status")
        return value if isinstance(value, dict) else None

    def access_points(self) -> list[Row]:
        return self._rows("SELECT * FROM access_points ORDER BY ssid, bssid", exclude=("summary",))

    def access_point(self, bssid: str) -> Row | None:
        rows = self._rows("SELECT * FROM access_points WHERE bssid = ?", bssid.lower())
        return rows[0] if rows else None

    def ap_metrics(self, bssid: str, *, limit: int = 500) -> list[Row]:
        rows = self._rows(
            "SELECT observed_at, frames, avg_rssi_dbm, rssi_stddev, clock_skew_ppm"
            " FROM ap_metrics WHERE bssid = ? ORDER BY id DESC LIMIT ?",
            bssid.lower(), limit,
        )  # fmt: skip
        return rows[::-1]

    def events(
        self, *, bssid: str | None = None, module: str | None = None, limit: int = 100,
        offset: int = 0,
    ) -> list[Row]:  # fmt: skip
        where, params = _filters(bssid=bssid.lower() if bssid else None, module=module)
        return self._rows(
            f"SELECT * FROM detection_events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            *params, limit, offset,
        )  # fmt: skip

    def alerts(
        self, *, status: str | None = None, classification: str | None = None,
        bssid: str | None = None,
    ) -> list[Row]:  # fmt: skip
        where, params = _filters(
            status=status, classification=classification, bssid=bssid.lower() if bssid else None
        )
        return self._rows(
            f"SELECT * FROM alerts {where} ORDER BY status = 'resolved', last_seen DESC", *params
        )

    def alert(self, alert_id: int) -> Row | None:
        rows = self._rows("SELECT * FROM alerts WHERE id = ?", alert_id)
        return rows[0] if rows else None

    def timeline(
        self, *, bssid: str | None = None, alert_id: int | None = None,
        after_id: int | None = None, limit: int = 100,
    ) -> list[Row]:  # fmt: skip
        """Timeline entries in chronological order.

        Without ``after_id`` the *latest* ``limit`` entries are returned; with
        it, the entries that follow ``after_id`` (for incremental polling).
        """
        where, params = _filters(bssid=bssid.lower() if bssid else None, alert_id=alert_id)
        if after_id is not None:
            where += (" AND" if where else "WHERE") + " id > ?"
            params.append(after_id)
            return self._rows(f"SELECT * FROM timeline {where} ORDER BY id LIMIT ?", *params, limit)
        rows = self._rows(
            f"SELECT * FROM timeline {where} ORDER BY id DESC LIMIT ?", *params, limit
        )
        return rows[::-1]

    def stats(self) -> dict[str, Any]:
        open_by_class = {
            row["classification"]: row["count"]
            for row in self._db.execute(
                "SELECT classification, count(*) AS count FROM alerts"
                " WHERE status = 'open' GROUP BY classification"
            )
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "access_points": self._count("access_points"),
            "detection_events": self._count("detection_events"),
            "alerts": self._count("alerts"),
            "open_alerts": sum(open_by_class.values()),
            "open_alerts_by_classification": open_by_class,
            "timeline_entries": self._count("timeline"),
            "last_update": self._db.execute("SELECT max(updated_at) FROM access_points").fetchone()[
                0
            ],
        }

    # --- helpers ------------------------------------------------------------

    def _rows(self, query: str, *params: Any, exclude: tuple[str, ...] = ()) -> list[Row]:
        return [
            {
                key: json.loads(row[key]) if key in _JSON_COLUMNS else row[key]
                for key in row.keys()  # noqa: SIM118 - sqlite3.Row is not a mapping
                if key not in exclude
            }
            for row in self._db.execute(query, params)
        ]

    def _count(self, table: str, where: str = "1") -> int:
        return int(self._db.execute(f"SELECT count(*) FROM {table} WHERE {where}").fetchone()[0])

    def _has_schema(self) -> bool:
        return (
            self._db.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'metadata'"
            ).fetchone()
            is not None
        )

    def _check_version(self, path: Path) -> None:
        version = self._meta("schema_version") if self._has_schema() else None
        if version != SCHEMA_VERSION:
            raise StoreError(
                f"{path} has schema version {version}, this WiGuard expects {SCHEMA_VERSION}. "
                "Use a new --state-path or delete the old file."
            )

    def _meta(self, key: str) -> Any:
        row = self._db.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return None if row is None else json.loads(row["value"])

    def _set_meta(self, key: str, value: Any) -> None:
        self._db.execute(
            "INSERT INTO metadata VALUES (?, ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, _dumps(value)),
        )


def _filters(**conditions: Any) -> tuple[str, list[Any]]:
    active = {column: value for column, value in conditions.items() if value is not None}
    if not active:
        return "", []
    return "WHERE " + " AND ".join(f"{column} = ?" for column in active), list(active.values())


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 3)


def _dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)
