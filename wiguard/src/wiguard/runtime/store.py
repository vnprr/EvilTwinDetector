"""SQLite runtime state for WiGuard sensor runs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from wiguard.correlation import CorrelatedAlert, DetectionEvent


SCHEMA_VERSION = 2
DEFAULT_STATE_PATH = Path(".wiguard/wiguard.db")


@dataclass(frozen=True)
class CorrelatedAlertRecord:
    """Lifecycle state returned after a correlated alert upsert."""

    alert_key: str
    alert_id: str
    bssid: str
    ssid: str
    final_score: float
    classification: str
    status: str
    first_seen: float
    last_seen: float
    count: int
    cooldown_suppressed: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class RuntimeStore:
    """Persistent runtime store for AP snapshots and alert timeline state."""

    def __init__(self, path: Path | str = DEFAULT_STATE_PATH) -> None:
        self.path = Path(path)
        if self.path != Path(":memory:"):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(str(self.path))
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self.initialize_schema()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "RuntimeStore":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def initialize_schema(self) -> None:
        """Create the v1 schema. Calling this repeatedly is safe."""

        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ap_snapshots (
                    bssid TEXT PRIMARY KEY,
                    ssid TEXT NOT NULL,
                    channels_json TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    snapshot_count INTEGER NOT NULL,
                    total_frames INTEGER NOT NULL,
                    last_rssi_dbm INTEGER,
                    avg_rssi_dbm REAL,
                    rssi_stddev REAL,
                    clock_skew_ppm REAL,
                    dominant_ie_fingerprint TEXT,
                    vendor_ouis_json TEXT NOT NULL,
                    last_sequence_number INTEGER,
                    payload_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS detection_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at REAL NOT NULL,
                    module TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    ssid TEXT,
                    score REAL NOT NULL,
                    signal_names_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_detection_events_bssid_time
                    ON detection_events (bssid, observed_at);

                CREATE TABLE IF NOT EXISTS correlated_alerts (
                    alert_key TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    ssid TEXT NOT NULL,
                    final_score REAL NOT NULL,
                    classification TEXT NOT NULL,
                    contributing_modules_json TEXT NOT NULL,
                    signal_names_json TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    count INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    timeline_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_correlated_alerts_last_seen
                    ON correlated_alerts (last_seen);

                CREATE TABLE IF NOT EXISTS timeline_events (
                    timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    reference_key TEXT,
                    bssid TEXT,
                    ssid TEXT,
                    message TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_timeline_events_time
                    ON timeline_events (observed_at);

                CREATE TABLE IF NOT EXISTS ap_metric_samples (
                    sample_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    last_rssi_dbm INTEGER,
                    avg_rssi_dbm REAL,
                    rssi_stddev REAL,
                    clock_skew_ppm REAL,
                    total_frames INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_ap_metric_samples_bssid_time
                    ON ap_metric_samples (bssid, observed_at);
                """
            )
            # Additive-only migrations: tables above use CREATE IF NOT EXISTS,
            # so existing databases gain new tables on open. Keep the recorded
            # schema version in step with the code.
            self._connection.execute(
                """
                INSERT INTO metadata (key, value)
                VALUES ('schema_version', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(SCHEMA_VERSION),),
            )

    def schema_version(self) -> int:
        row = self._connection.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        return int(row["value"]) if row is not None else 0

    def set_runtime_status(self, status: dict[str, object]) -> None:
        """Persist the latest sensor runtime status (capture stats, config, time)."""

        with self._connection:
            self._connection.execute(
                """
                INSERT INTO metadata (key, value)
                VALUES ('runtime_status', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (_json(status),),
            )

    def runtime_status(self) -> dict[str, object] | None:
        """Return the last persisted sensor runtime status, if any."""

        row = self._connection.execute(
            "SELECT value FROM metadata WHERE key = 'runtime_status'"
        ).fetchone()
        if row is None:
            return None
        value = _loads(row["value"])
        return value if isinstance(value, dict) else None

    def upsert_ap_snapshot(self, summary: object, *, observed_at: float | None = None) -> None:
        payload = _payload(summary)
        now = _now(observed_at)
        bssid = str(payload["bssid"]).lower()
        ssid = str(payload.get("ssid") or "<unknown>")
        channels = tuple(int(channel) for channel in payload.get("channels", ()) or ())
        first_seen = _optional_float(payload.get("first_seen_monotonic")) or now
        last_seen = _optional_float(payload.get("last_seen_monotonic")) or now
        if first_seen > last_seen:
            first_seen = last_seen
        existing = self._connection.execute(
            "SELECT first_seen, snapshot_count FROM ap_snapshots WHERE bssid = ?",
            (bssid,),
        ).fetchone()
        if existing is not None:
            first_seen = min(float(existing["first_seen"]), first_seen)
            snapshot_count = int(existing["snapshot_count"]) + 1
        else:
            snapshot_count = 1
        clock_skew_ppm = _clock_skew_ppm(payload)
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO ap_snapshots (
                    bssid, ssid, channels_json, first_seen, last_seen, snapshot_count,
                    total_frames, last_rssi_dbm, avg_rssi_dbm, rssi_stddev,
                    clock_skew_ppm, dominant_ie_fingerprint, vendor_ouis_json,
                    last_sequence_number, payload_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid = excluded.ssid,
                    channels_json = excluded.channels_json,
                    first_seen = min(ap_snapshots.first_seen, excluded.first_seen),
                    last_seen = max(ap_snapshots.last_seen, excluded.last_seen),
                    snapshot_count = excluded.snapshot_count,
                    total_frames = excluded.total_frames,
                    last_rssi_dbm = excluded.last_rssi_dbm,
                    avg_rssi_dbm = excluded.avg_rssi_dbm,
                    rssi_stddev = excluded.rssi_stddev,
                    clock_skew_ppm = excluded.clock_skew_ppm,
                    dominant_ie_fingerprint = excluded.dominant_ie_fingerprint,
                    vendor_ouis_json = excluded.vendor_ouis_json,
                    last_sequence_number = excluded.last_sequence_number,
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (
                    bssid,
                    ssid,
                    _json(channels),
                    first_seen,
                    last_seen,
                    snapshot_count,
                    int(payload.get("frames", 0) or 0),
                    _optional_int(payload.get("last_rssi_dbm")),
                    _optional_float(payload.get("avg_rssi_dbm")),
                    _optional_float(payload.get("rssi_stddev")),
                    clock_skew_ppm,
                    _optional_str(payload.get("dominant_ie_fingerprint")),
                    _json(payload.get("vendor_ouis", ()) or ()),
                    _optional_int(payload.get("last_sequence_number")),
                    _json(payload),
                    now,
                ),
            )

    def insert_ap_metric_sample(
        self,
        summary: object,
        *,
        observed_at: float | None = None,
    ) -> None:
        """Append one time-stamped RSSI/clock-skew sample for an AP.

        Unlike ``ap_snapshots`` (one latest row per BSSID), these rows accumulate
        so the dashboard and experiments can plot per-AP trends over time.
        """

        payload = _payload(summary)
        now = _now(observed_at)
        bssid = str(payload["bssid"]).lower()
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO ap_metric_samples (
                    bssid, observed_at, last_rssi_dbm, avg_rssi_dbm,
                    rssi_stddev, clock_skew_ppm, total_frames
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bssid,
                    now,
                    _optional_int(payload.get("last_rssi_dbm")),
                    _optional_float(payload.get("avg_rssi_dbm")),
                    _optional_float(payload.get("rssi_stddev")),
                    _clock_skew_ppm(payload),
                    _optional_int(payload.get("frames")),
                ),
            )

    def ap_metric_samples(
        self,
        bssid: str,
        *,
        limit: int | None = None,
    ) -> list[dict[str, object]]:
        """Return per-AP metric samples in chronological (oldest-first) order."""

        query = (
            "SELECT bssid, observed_at, last_rssi_dbm, avg_rssi_dbm, "
            "rssi_stddev, clock_skew_ppm, total_frames "
            "FROM ap_metric_samples WHERE bssid = ? ORDER BY observed_at DESC"
        )
        params: list[object] = [bssid.lower()]
        if limit is not None:
            query += " LIMIT ?"
            params.append(max(1, limit))
        rows = self._connection.execute(query, params).fetchall()
        return [dict(row) for row in reversed(rows)]

    def insert_detection_event(
        self,
        event: DetectionEvent | dict[str, object],
        *,
        observed_at: float | None = None,
    ) -> int:
        payload = _event_payload(event)
        now = _now(observed_at)
        module = str(payload["module"])
        bssid = str(payload["bssid"]).lower()
        ssid = _optional_str(payload.get("ssid"))
        score = float(payload.get("score", 0.0) or 0.0)
        signal_names = tuple(str(name) for name in payload.get("signal_names", ()) or ())
        evidence = payload.get("evidence", {})
        with self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO detection_events (
                    observed_at, module, bssid, ssid, score, signal_names_json,
                    evidence_json, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    module,
                    bssid,
                    ssid,
                    score,
                    _json(signal_names),
                    _json(evidence),
                    _json(payload),
                ),
            )
            event_id = int(cursor.lastrowid)
            self._insert_timeline_event(
                observed_at=now,
                event_type="detection_event",
                reference_key=str(event_id),
                bssid=bssid,
                ssid=ssid,
                message=f"{module} emitted {', '.join(signal_names) or 'unnamed signal'}",
                payload=payload,
            )
        return event_id

    def upsert_correlated_alert(
        self,
        alert: CorrelatedAlert | dict[str, object],
        *,
        observed_at: float | None = None,
        cooldown_seconds: float = 300.0,
    ) -> CorrelatedAlertRecord:
        payload = _correlated_payload(alert)
        now = _now(observed_at)
        alert_key = _correlated_alert_key(payload)
        alert_id = str(payload["alert_id"])
        bssid = str(payload["bssid"]).lower()
        ssid = str(payload.get("ssid") or "<unknown>")
        modules = tuple(str(module) for module in payload.get("contributing_modules", ()) or ())
        signal_names = _correlated_signal_names(payload)
        final_score = float(payload.get("final_score", 0.0) or 0.0)
        classification = str(payload.get("classification") or "info")
        explanation = str(payload.get("explanation") or "")

        existing = self._connection.execute(
            "SELECT * FROM correlated_alerts WHERE alert_key = ?",
            (alert_key,),
        ).fetchone()
        if existing is None:
            first_seen = now
            count = 1
            status = "open"
            cooldown_suppressed = False
            event_type = "correlated_alert_opened"
        else:
            first_seen = float(existing["first_seen"])
            count = int(existing["count"]) + 1
            status = str(existing["status"])
            cooldown_suppressed = now - float(existing["last_seen"]) < cooldown_seconds
            final_score = max(final_score, float(existing["final_score"]))
            classification = _stronger_classification(
                str(existing["classification"]),
                classification,
            )
            event_type = (
                "correlated_alert_deduplicated"
                if cooldown_suppressed
                else "correlated_alert_repeated"
            )

        with self._connection:
            self._connection.execute(
                """
                INSERT INTO correlated_alerts (
                    alert_key, alert_id, bssid, ssid, final_score, classification,
                    contributing_modules_json, signal_names_json, first_seen,
                    last_seen, count, status, explanation, timeline_json,
                    payload_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_key) DO UPDATE SET
                    alert_id = excluded.alert_id,
                    ssid = excluded.ssid,
                    final_score = max(correlated_alerts.final_score, excluded.final_score),
                    classification = excluded.classification,
                    contributing_modules_json = excluded.contributing_modules_json,
                    signal_names_json = excluded.signal_names_json,
                    last_seen = excluded.last_seen,
                    count = excluded.count,
                    status = excluded.status,
                    explanation = excluded.explanation,
                    timeline_json = excluded.timeline_json,
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (
                    alert_key,
                    alert_id,
                    bssid,
                    ssid,
                    final_score,
                    classification,
                    _json(modules),
                    _json(signal_names),
                    first_seen,
                    now,
                    count,
                    status,
                    explanation,
                    _json(payload.get("timeline", ()) or ()),
                    _json(payload),
                    now,
                ),
            )
            if not cooldown_suppressed:
                self._insert_timeline_event(
                    observed_at=now,
                    event_type=event_type,
                    reference_key=alert_key,
                    bssid=bssid,
                    ssid=ssid,
                    message=explanation or f"{classification} alert for {bssid}",
                    payload=payload,
                )

        return CorrelatedAlertRecord(
            alert_key=alert_key,
            alert_id=alert_id,
            bssid=bssid,
            ssid=ssid,
            final_score=final_score,
            classification=classification,
            status=status,
            first_seen=first_seen,
            last_seen=now,
            count=count,
            cooldown_suppressed=cooldown_suppressed,
        )

    def record_analysis_result(
        self,
        payload: dict[str, object],
        *,
        observed_at: float | None = None,
        alert_cooldown_seconds: float = 300.0,
    ) -> list[CorrelatedAlertRecord]:
        now = _now(observed_at)
        for summary in _list(payload.get("feature_access_points")) or _list(
            payload.get("access_points")
        ):
            self.upsert_ap_snapshot(summary, observed_at=now)
            self.insert_ap_metric_sample(summary, observed_at=now)

        seen_raw_alerts: set[str] = set()
        for alert in _raw_alerts(payload):
            event = _event_payload_from_raw_alert(alert)
            fingerprint = _json(event)
            if fingerprint in seen_raw_alerts:
                continue
            seen_raw_alerts.add(fingerprint)
            self.insert_detection_event(event, observed_at=now)

        records = []
        for alert in _list(payload.get("correlated_alerts")):
            records.append(
                self.upsert_correlated_alert(
                    alert,
                    observed_at=now,
                    cooldown_seconds=alert_cooldown_seconds,
                )
            )
        return records

    def ap_snapshots(self) -> list[dict[str, object]]:
        rows = self._connection.execute(
            "SELECT * FROM ap_snapshots ORDER BY ssid, bssid"
        ).fetchall()
        return [_row_to_payload(row) for row in rows]

    def detection_events(
        self,
        *,
        bssid: str | None = None,
        module: str | None = None,
        limit: int | None = None,
        offset: int = 0,
        descending: bool = False,
    ) -> list[dict[str, object]]:
        filters = []
        params: list[object] = []
        if bssid is not None:
            filters.append("bssid = ?")
            params.append(bssid.lower())
        if module is not None:
            filters.append("module = ?")
            params.append(module)
        query = "SELECT * FROM detection_events"
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY event_id DESC" if descending else " ORDER BY event_id"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([max(0, limit), max(0, offset)])
        rows = self._connection.execute(query, params).fetchall()
        return [_row_to_payload(row) for row in rows]

    def correlated_alerts(
        self,
        *,
        classification: str | None = None,
        status: str | None = None,
        ssid: str | None = None,
        bssid: str | None = None,
    ) -> list[dict[str, object]]:
        filters = []
        params: list[object] = []
        if classification is not None:
            filters.append("classification = ?")
            params.append(classification)
        if status is not None:
            filters.append("status = ?")
            params.append(status)
        if ssid is not None:
            filters.append("ssid = ?")
            params.append(ssid)
        if bssid is not None:
            filters.append("bssid = ?")
            params.append(bssid.lower())
        query = "SELECT * FROM correlated_alerts"
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY last_seen DESC, bssid"
        rows = self._connection.execute(query, params).fetchall()
        return [_row_to_payload(row) for row in rows]

    def correlated_alert(self, alert_key: str) -> dict[str, object] | None:
        row = self._connection.execute(
            "SELECT * FROM correlated_alerts WHERE alert_key = ?",
            (alert_key,),
        ).fetchone()
        return _row_to_payload(row) if row is not None else None

    def ap_snapshot(self, bssid: str) -> dict[str, object] | None:
        row = self._connection.execute(
            "SELECT * FROM ap_snapshots WHERE bssid = ?",
            (bssid.lower(),),
        ).fetchone()
        return _row_to_payload(row) if row is not None else None

    def timeline_events(
        self,
        *,
        bssid: str | None = None,
        after_id: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, object]]:
        filters = []
        params: list[object] = []
        if bssid is not None:
            filters.append("bssid = ?")
            params.append(bssid.lower())
        if after_id is not None:
            filters.append("timeline_id > ?")
            params.append(max(0, after_id))
        query = "SELECT * FROM timeline_events"
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY timeline_id"
        if limit is not None:
            query += " LIMIT ?"
            params.append(max(0, limit))
        rows = self._connection.execute(query, params).fetchall()
        return [_row_to_payload(row) for row in rows]

    def stats(self) -> dict[str, object]:
        classification_rows = self._connection.execute(
            """
            SELECT classification, count(*) AS count
            FROM correlated_alerts
            GROUP BY classification
            ORDER BY classification
            """
        ).fetchall()
        latest_row = self._connection.execute(
            """
            SELECT
                (SELECT max(updated_at) FROM ap_snapshots) AS latest_ap_update,
                (SELECT max(observed_at) FROM detection_events) AS latest_detection_event,
                (SELECT max(last_seen) FROM correlated_alerts) AS latest_correlated_alert,
                (SELECT max(observed_at) FROM timeline_events) AS latest_timeline_event
            """
        ).fetchone()
        return {
            "schema_version": self.schema_version(),
            "ap_count": self._count("ap_snapshots"),
            "raw_event_count": self._count("detection_events"),
            "alert_count": self._count("correlated_alerts"),
            "timeline_event_count": self._count("timeline_events"),
            "classification_counts": {
                str(row["classification"]): int(row["count"])
                for row in classification_rows
            },
            "latest": dict(latest_row) if latest_row is not None else {},
        }

    def _count(self, table: str) -> int:
        row = self._connection.execute(f"SELECT count(*) AS count FROM {table}").fetchone()
        return int(row["count"]) if row is not None else 0

    def _insert_timeline_event(
        self,
        *,
        observed_at: float,
        event_type: str,
        reference_key: str | None,
        bssid: str | None,
        ssid: str | None,
        message: str,
        payload: dict[str, object],
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO timeline_events (
                observed_at, event_type, reference_key, bssid, ssid, message, payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observed_at,
                event_type,
                reference_key,
                bssid,
                ssid,
                message,
                _json(payload),
            ),
        )


def _payload(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return dict(to_dict())
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    raise TypeError(f"unsupported payload type: {type(value)!r}")


def _event_payload(event: DetectionEvent | dict[str, object]) -> dict[str, object]:
    if isinstance(event, DetectionEvent):
        return event.to_dict()
    return dict(event)


def _correlated_payload(alert: CorrelatedAlert | dict[str, object]) -> dict[str, object]:
    if isinstance(alert, CorrelatedAlert):
        return alert.to_dict()
    return dict(alert)


def _event_payload_from_raw_alert(alert: object) -> dict[str, object]:
    payload = _payload(alert)
    signals = _list(payload.get("signals"))
    return {
        "module": str(payload.get("module") or "unknown"),
        "bssid": str(payload["bssid"]).lower(),
        "ssid": _optional_str(payload.get("ssid")),
        "score": float(payload.get("score", 0.0) or 0.0),
        "signal_names": tuple(
            str(signal.get("name"))
            for signal in signals
            if isinstance(signal, dict) and signal.get("name") is not None
        ),
        "evidence": payload,
    }


def _raw_alerts(payload: dict[str, object]) -> list[object]:
    alerts: list[object] = []
    for key in ("identity_alerts", "deauth_alerts", "environment_alerts"):
        alerts.extend(_list(payload.get(key)))
    return alerts


def _correlated_signal_names(payload: dict[str, object]) -> tuple[str, ...]:
    names: set[str] = set()
    for event in _list(payload.get("timeline")):
        if not isinstance(event, dict):
            continue
        for name in _list(event.get("signal_names")):
            if isinstance(name, str):
                names.add(name)
    return tuple(sorted(names))


def _correlated_alert_key(payload: dict[str, object]) -> str:
    canonical = {
        "bssid": str(payload["bssid"]).lower(),
        "modules": sorted(str(module) for module in payload.get("contributing_modules", ()) or ()),
        "signals": list(_correlated_signal_names(payload)),
    }
    raw = _json(canonical)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    return f"alert:{digest}"


def _stronger_classification(current: str, incoming: str) -> str:
    rank = {"info": 0, "suspicious": 1, "evil_twin": 2}
    return incoming if rank.get(incoming, 0) >= rank.get(current, 0) else current


def _clock_skew_ppm(payload: dict[str, object]) -> float | None:
    estimate = payload.get("clock_estimate")
    if isinstance(estimate, dict):
        return _optional_float(estimate.get("skew_ppm"))
    return None


def _row_to_payload(row: sqlite3.Row) -> dict[str, object]:
    payload = dict(row)
    for key in list(payload):
        if key.endswith("_json"):
            payload[key.removesuffix("_json")] = _loads(payload.pop(key))
    return payload


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _loads(value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _now(value: float | None) -> float:
    return time.time() if value is None else float(value)


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    return float(value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return int(value)


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []
