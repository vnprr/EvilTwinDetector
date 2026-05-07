"""Persistent storage for trusted AP identity baselines."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from .identity import IdentityBaseline


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class IdentityBaselineStoreMetadata:
    schema_version: int
    path: str
    baselines_loaded: int = 0
    baselines_saved: int = 0
    loaded_at: str | None = None
    saved_at: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class IdentityBaselineStore:
    """Read and write trusted baseline profiles as stable JSON."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.metadata = IdentityBaselineStoreMetadata(
            schema_version=SCHEMA_VERSION,
            path=str(self.path),
        )

    def load(self) -> tuple[IdentityBaseline, ...]:
        if not self.path.exists():
            self.metadata = IdentityBaselineStoreMetadata(
                schema_version=SCHEMA_VERSION,
                path=str(self.path),
                baselines_loaded=0,
                loaded_at=_utc_now(),
            )
            return ()

        payload = json.loads(self.path.read_text(encoding="utf-8"))
        schema_version = int(payload.get("schema_version", 0))
        if schema_version != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported identity baseline schema version {schema_version}; "
                f"expected {SCHEMA_VERSION}"
            )
        baselines = tuple(
            IdentityBaseline.from_dict(item)
            for item in payload.get("baselines", [])
            if isinstance(item, dict)
        )
        self.metadata = IdentityBaselineStoreMetadata(
            schema_version=schema_version,
            path=str(self.path),
            baselines_loaded=len(baselines),
            loaded_at=_utc_now(),
        )
        return baselines

    def save(self, baselines: Iterable[IdentityBaseline]) -> IdentityBaselineStoreMetadata:
        ordered = sorted(baselines, key=lambda baseline: baseline.bssid)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": _utc_now(),
            "baselines": [baseline.to_dict() for baseline in ordered],
        }
        temporary_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temporary_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(self.path)
        self.metadata = IdentityBaselineStoreMetadata(
            schema_version=SCHEMA_VERSION,
            path=str(self.path),
            baselines_loaded=self.metadata.baselines_loaded,
            baselines_saved=len(ordered),
            loaded_at=self.metadata.loaded_at,
            saved_at=payload["generated_at"],
        )
        return self.metadata


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()
