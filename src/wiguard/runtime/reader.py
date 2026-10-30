"""Read access to the state database. This is all the API ever gets."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

from .database import SCHEMA_VERSION, Database, Row, connect


class StateReader(Database):
    @classmethod
    def open(cls, path: Path | str) -> Self:
        """Open the database in SQLite read-only mode.

        A database that does not exist yet reads as empty, so the API can start
        before the sensor has written anything.
        """
        path = Path(path)
        if not path.is_file():
            reader = cls(connect(":memory:"))
            reader._create_schema()
            return reader
        reader = cls(connect(f"{path.resolve().as_uri()}?mode=ro", uri=True))
        reader._check_version(path)
        return reader

    def status(self) -> dict[str, Any] | None:
        """What the sensor (or a replay) last reported about itself."""
        value = self._meta("sensor_status")
        return value if isinstance(value, dict) else None

    def access_points(self) -> list[Row]:
        return self._rows(
            "SELECT bssid, ssid, channels, first_seen, last_seen, frames, last_rssi_dbm,"
            " avg_rssi_dbm, rssi_stddev, clock_skew_ppm, dominant_ie_fingerprint, vendor_ouis"
            " FROM access_points ORDER BY ssid, bssid"
        )

    def access_point(self, bssid: str) -> Row | None:
        rows = self._rows(
            "SELECT * FROM access_points WHERE bssid = :bssid", {"bssid": bssid.lower()}
        )
        return rows[0] if rows else None

    def ap_metrics(self, bssid: str, *, limit: int = 500) -> list[Row]:
        """The latest ``limit`` samples, oldest first (ready to plot)."""
        rows = self._rows(
            "SELECT observed_at, frames, avg_rssi_dbm, rssi_stddev, clock_skew_ppm FROM ap_metrics"
            " WHERE bssid = :bssid ORDER BY id DESC LIMIT :limit",
            {"bssid": bssid.lower(), "limit": limit},
        )
        return rows[::-1]

    def events(
        self,
        *,
        bssid: str | None = None,
        module: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Row]:
        where, params = _where(bssid=bssid and bssid.lower(), module=module)
        return self._rows(
            f"SELECT * FROM detection_events {where} ORDER BY id DESC LIMIT :limit OFFSET :offset",
            {**params, "limit": limit, "offset": offset},
        )

    def alerts(
        self,
        *,
        status: str | None = None,
        classification: str | None = None,
        bssid: str | None = None,
    ) -> list[Row]:
        """Open alerts first, then the most recently active."""
        where, params = _where(
            status=status, classification=classification, bssid=bssid and bssid.lower()
        )
        return self._rows(
            f"SELECT * FROM alerts {where} ORDER BY status = 'resolved', last_seen DESC", params
        )

    def alert(self, alert_id: int) -> Row | None:
        rows = self._rows("SELECT * FROM alerts WHERE id = :id", {"id": alert_id})
        return rows[0] if rows else None

    def timeline(
        self,
        *,
        bssid: str | None = None,
        after_id: int | None = None,
        limit: int = 100,
    ) -> list[Row]:
        """Timeline entries in chronological order.

        Without ``after_id``: the *latest* ``limit`` entries. With it: the entries
        that follow ``after_id`` (incremental polling).
        """
        where, params = _where(bssid=bssid and bssid.lower())
        params["limit"] = limit
        if after_id is None:
            query = f"SELECT * FROM timeline {where} ORDER BY id DESC LIMIT :limit"
            return self._rows(query, params)[::-1]
        where += (" AND" if where else "WHERE") + " id > :after_id"
        query = f"SELECT * FROM timeline {where} ORDER BY id LIMIT :limit"
        return self._rows(query, {**params, "after_id": after_id})

    def stats(self) -> dict[str, Any]:
        open_by_class = {
            row["classification"]: row["count"]
            for row in self._rows(
                "SELECT classification, count(*) AS count FROM alerts"
                " WHERE status = 'open' GROUP BY classification"
            )
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "access_points": self._scalar("SELECT count(*) FROM access_points"),
            "detection_events": self._scalar("SELECT count(*) FROM detection_events"),
            "alerts": self._scalar("SELECT count(*) FROM alerts"),
            "open_alerts": sum(open_by_class.values()),
            "open_alerts_by_classification": open_by_class,
            "timeline_entries": self._scalar("SELECT count(*) FROM timeline"),
            "last_update": self._scalar("SELECT max(updated_at) FROM access_points"),
        }


def _where(**conditions: Any) -> tuple[str, dict[str, Any]]:
    """``WHERE a = :a AND b = :b`` for the conditions that are set."""
    active = {column: value for column, value in conditions.items() if value is not None}
    if not active:
        return "", {}
    return "WHERE " + " AND ".join(f"{column} = :{column}" for column in active), active
