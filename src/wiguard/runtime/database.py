"""SQLite plumbing shared by the state reader and writer."""

from __future__ import annotations

import json
import sqlite3
from importlib.resources import files
from pathlib import Path
from typing import Any, Self

SCHEMA_VERSION = 3
SCHEMA = files(__package__).joinpath("schema.sql").read_text(encoding="utf-8")

# Columns stored as JSON text and decoded when read.
JSON_COLUMNS = frozenset(
    {
        "channels",
        "vendor_ouis",
        "summary",
        "signal_names",
        "modules",
        "evidence",
        "event",
        "details",
    }
)

Row = dict[str, Any]


class StoreError(RuntimeError):
    """The state database cannot be used (not a WiGuard database, or another schema version)."""


def connect(target: str, *, uri: bool = False) -> sqlite3.Connection:
    # One connection serves one request or one sensor at a time, but a web
    # framework may run the parts of a request on different worker threads;
    # handing a connection from one thread to the next is safe.
    connection = sqlite3.connect(target, uri=uri, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)


class Database:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._db = connection

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _create_schema(self) -> None:
        with self._db:
            self._db.executescript(SCHEMA)
            self._set_meta("schema_version", SCHEMA_VERSION)

    def _has_schema(self) -> bool:
        query = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'metadata'"
        return self._db.execute(query).fetchone() is not None

    def _check_version(self, path: Path) -> None:
        version = self._meta("schema_version") if self._has_schema() else None
        if version != SCHEMA_VERSION:
            raise StoreError(
                f"{path} has schema version {version}, this WiGuard expects {SCHEMA_VERSION}. "
                "Use a new --state-path or delete the old file."
            )

    def _rows(self, query: str, params: dict[str, Any] | None = None) -> list[Row]:
        return [
            {key: json.loads(row[key]) if key in JSON_COLUMNS else row[key] for key in row.keys()}  # noqa: SIM118
            for row in self._db.execute(query, params or {})
        ]

    def _scalar(self, query: str, params: dict[str, Any] | None = None) -> Any:
        return self._db.execute(query, params or {}).fetchone()[0]

    def _meta(self, key: str) -> Any:
        value = self._db.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return None if value is None else json.loads(value[0])

    def _set_meta(self, key: str, value: Any) -> None:
        self._db.execute(
            "INSERT INTO metadata VALUES (:key, :value)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            {"key": key, "value": dumps(value)},
        )
