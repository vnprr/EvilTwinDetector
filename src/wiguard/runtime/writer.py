"""Write access to the state database: one pipeline evaluation at a time.

Alerts are *incidents*: one open alert per AP, updated while evidence keeps
coming in, escalated when the verdict gets worse and resolved after
``resolve_after`` seconds without evidence. Detector findings are logged when
they first appear or change, not on every flush.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, Self

from wiguard.correlation import Classification, CorrelatedAlert
from wiguard.detection import DetectionEvent
from wiguard.features import APSummary
from wiguard.pipeline import PipelineResult

from .database import connect, dumps
from .reader import StateReader

METRIC_SAMPLES_PER_AP = 2_000


@dataclass(frozen=True)
class RecordSummary:
    access_points: int
    events_logged: int
    alerts_opened: int
    alerts_escalated: int
    alerts_resolved: int
    open_alerts: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


class StateWriter(StateReader):
    @classmethod
    def open(cls, path: Path | str) -> Self:
        """Open the database for writing, creating it if needed."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        writer = cls(connect(str(path)))
        if not writer._has_schema():
            writer._create_schema()
        writer._check_version(path)
        return writer

    def record(
        self, result: PipelineResult, *, observed_at: float, resolve_after: float
    ) -> RecordSummary:
        """Persist one pipeline evaluation in a single transaction."""

        with self._db:
            for ap in result.access_points:
                self._save_access_point(ap, observed_at)
            logged = sum(
                self._log_event(event, observed_at, resolve_after) for event in result.events
            )
            outcomes = [self._save_alert(alert, observed_at) for alert in result.alerts]
            active = {alert.bssid for alert in result.alerts}
            resolved = self._resolve_quiet_alerts(active, observed_at, resolve_after)
        return RecordSummary(
            access_points=len(result.access_points),
            events_logged=logged,
            alerts_opened=outcomes.count("opened"),
            alerts_escalated=outcomes.count("escalated"),
            alerts_resolved=resolved,
            open_alerts=self._scalar("SELECT count(*) FROM alerts WHERE status = 'open'"),
        )

    def set_status(self, status: dict[str, Any]) -> None:
        with self._db:
            self._set_meta("sensor_status", status)

    # --- access points ------------------------------------------------------------

    def _save_access_point(self, ap: APSummary, observed_at: float) -> None:
        row = {
            "bssid": ap.bssid,
            "ssid": ap.ssid,
            "channels": dumps(ap.channels),
            "first_seen": ap.first_seen,
            "last_seen": ap.last_seen,
            "frames": ap.frames,
            "last_rssi_dbm": ap.last_rssi_dbm,
            "avg_rssi_dbm": ap.avg_rssi_dbm,
            "rssi_stddev": ap.rssi_stddev,
            "clock_skew_ppm": _round(ap.clock_skew_ppm),
            "dominant_ie_fingerprint": ap.dominant_ie_fingerprint,
            "vendor_ouis": dumps(ap.vendor_ouis),
            "summary": dumps(ap.to_dict()),
            "updated_at": observed_at,
        }
        # A sensor restart starts a new profile; keep the earliest time the AP was ever seen.
        updates = ", ".join(
            f"{column} = min(first_seen, excluded.first_seen)"
            if column == "first_seen"
            else f"{column} = excluded.{column}"
            for column in row
            if column != "bssid"
        )
        self._db.execute(
            f"INSERT INTO access_points ({', '.join(row)}) VALUES ({_placeholders(row)})"
            f" ON CONFLICT (bssid) DO UPDATE SET {updates}",
            row,
        )
        self._sample_metrics(ap, observed_at)

    def _sample_metrics(self, ap: APSummary, observed_at: float) -> None:
        last_frames = self._db.execute(
            "SELECT frames FROM ap_metrics WHERE bssid = ? ORDER BY id DESC LIMIT 1", (ap.bssid,)
        ).fetchone()
        if last_frames is not None and last_frames[0] == ap.frames:
            return  # not heard since the last sample: nothing new to plot
        sample = {
            "bssid": ap.bssid,
            "observed_at": observed_at,
            "frames": ap.frames,
            "avg_rssi_dbm": ap.avg_rssi_dbm,
            "rssi_stddev": ap.rssi_stddev,
            "clock_skew_ppm": _round(ap.clock_skew_ppm),
        }
        self._db.execute(
            f"INSERT INTO ap_metrics ({', '.join(sample)}) VALUES ({_placeholders(sample)})", sample
        )
        self._db.execute(  # keep the newest METRIC_SAMPLES_PER_AP samples
            "DELETE FROM ap_metrics WHERE bssid = :bssid AND id <= (SELECT id FROM ap_metrics"
            " WHERE bssid = :bssid ORDER BY id DESC LIMIT 1 OFFSET :keep)",
            {"bssid": ap.bssid, "keep": METRIC_SAMPLES_PER_AP},
        )

    # --- detector findings ----------------------------------------------------------------

    def _log_event(self, event: DetectionEvent, observed_at: float, resolve_after: float) -> bool:
        """Log a finding if it is new or changed; otherwise extend the existing row."""
        names = sorted(event.signal_names)
        last = self._db.execute(
            "SELECT id, signal_names, last_seen FROM detection_events"
            " WHERE module = ? AND bssid = ? ORDER BY id DESC LIMIT 1",
            (event.module.value, event.bssid),
        ).fetchone()
        if (
            last is not None
            and json.loads(last["signal_names"]) == names
            and observed_at - last["last_seen"] <= resolve_after
        ):
            self._db.execute(
                "UPDATE detection_events SET last_seen = ?, strength = ?, event = ? WHERE id = ?",
                (observed_at, event.strength, dumps(event.to_dict()), last["id"]),
            )
            return False
        row = {
            "module": event.module.value,
            "bssid": event.bssid,
            "ssid": event.ssid,
            "strength": event.strength,
            "signal_names": dumps(names),
            "first_seen": observed_at,
            "last_seen": observed_at,
            "event": dumps(event.to_dict()),
        }
        self._db.execute(
            f"INSERT INTO detection_events ({', '.join(row)}) VALUES ({_placeholders(row)})", row
        )
        self._timeline(
            observed_at,
            "detection",
            message=f"{event.module.value}: {', '.join(names)}",
            bssid=event.bssid,
            ssid=event.ssid,
            details={"strength": event.strength},
        )
        return True

    # --- alerts ---------------------------------------------------------------------------

    def _save_alert(
        self, alert: CorrelatedAlert, observed_at: float
    ) -> Literal["opened", "escalated", "updated"]:
        current = self._db.execute(
            "SELECT * FROM alerts WHERE bssid = ? AND status = 'open'", (alert.bssid,)
        ).fetchone()
        modules = [module.value for module in alert.modules]
        evidence = dumps([event.to_dict() for event in alert.evidence])

        if current is None:
            row = {
                "bssid": alert.bssid,
                "ssid": alert.ssid,
                "status": "open",
                "classification": alert.classification.value,
                "score": alert.score,
                "modules": dumps(modules),
                "signal_names": dumps(alert.signal_names),
                "explanation": alert.explanation,
                "evidence": evidence,
                "first_seen": observed_at,
                "last_seen": observed_at,
                "updates": 1,
            }
            cursor = self._db.execute(
                f"INSERT INTO alerts ({', '.join(row)}) VALUES ({_placeholders(row)})", row
            )
            self._timeline(
                observed_at,
                "alert_opened",
                message=alert.explanation,
                bssid=alert.bssid,
                ssid=alert.ssid,
                alert_id=cursor.lastrowid,
                details={"classification": alert.classification.value, "score": alert.score},
            )
            return "opened"

        previous = Classification(current["classification"])
        escalated = alert.classification.rank > previous.rank
        self._db.execute(
            "UPDATE alerts SET ssid = :ssid, classification = :classification,"
            " score = max(score, :score), modules = :modules, signal_names = :signal_names,"
            " explanation = :explanation, evidence = :evidence, last_seen = :last_seen,"
            " updates = updates + 1 WHERE id = :id",
            {
                "id": current["id"],
                "ssid": alert.ssid or current["ssid"],
                "classification": (alert.classification if escalated else previous).value,
                "score": alert.score,
                "modules": dumps(sorted({*json.loads(current["modules"]), *modules})),
                "signal_names": dumps(
                    sorted({*json.loads(current["signal_names"]), *alert.signal_names})
                ),
                "explanation": alert.explanation,
                "evidence": evidence,
                "last_seen": observed_at,
            },
        )
        if not escalated:
            return "updated"
        self._timeline(
            observed_at,
            "alert_escalated",
            message=alert.explanation,
            bssid=alert.bssid,
            ssid=alert.ssid,
            alert_id=current["id"],
            details={
                "from": previous.value,
                "to": alert.classification.value,
                "score": alert.score,
            },
        )
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
                observed_at,
                "alert_resolved",
                message=f"No new evidence for {resolve_after:.0f} s; alert resolved.",
                bssid=row["bssid"],
                ssid=row["ssid"],
                alert_id=row["id"],
            )
        return len(quiet)

    def _timeline(
        self,
        observed_at: float,
        kind: str,
        *,
        message: str,
        bssid: str | None = None,
        ssid: str | None = None,
        alert_id: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._db.execute(
            "INSERT INTO timeline (observed_at, kind, bssid, ssid, alert_id, message, details)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (observed_at, kind, bssid, ssid, alert_id, message, dumps(details or {})),
        )


def _placeholders(row: dict[str, Any]) -> str:
    return ", ".join(f":{column}" for column in row)


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 3)
