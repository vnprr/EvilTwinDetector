"""The read-only HTTP/WebSocket API over the sensor's state database.

The API never writes: every request opens the database in SQLite read-only
mode, so it cannot interfere with the sensor and cannot change detection.
Starting a capture, enrolling trusted profiles or changing thresholds are
deliberate command-line actions, not something a browser can trigger.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from wiguard import __version__
from wiguard.config import WiGuardConfig
from wiguard.runtime import StoreError

from .routes import router


def create_app(config: WiGuardConfig | None = None, *, state_path: Path | None = None) -> FastAPI:
    config = config or WiGuardConfig()
    app = FastAPI(
        title="WiGuard API",
        version=__version__,
        description="Read-only access to WiGuard's access points, alerts and evidence.",
    )
    app.state.config = config
    app.state.state_path = Path(state_path or config.runtime.state_path)
    app.add_middleware(
        CORSMiddleware, allow_origins=list(config.api.cors_origins), allow_methods=["GET"]
    )
    app.add_exception_handler(StoreError, _store_unavailable)
    app.include_router(router)
    return app


async def _store_unavailable(_: Request, error: Exception) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": str(error)})
