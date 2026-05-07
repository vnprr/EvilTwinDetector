"""Command-line launcher for the WiGuard Runtime API."""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from wiguard.api.app import DEFAULT_CORS_ORIGINS, create_app
from wiguard.runtime.store import DEFAULT_STATE_PATH


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the WiGuard Runtime Store API")
    parser.add_argument("--host", default="127.0.0.1", help="API bind host")
    parser.add_argument("--port", type=int, default=8765, help="API bind port")
    parser.add_argument("--state-path", type=Path, default=DEFAULT_STATE_PATH, help="SQLite runtime state path")
    parser.add_argument(
        "--cors-origin",
        action="append",
        dest="cors_origins",
        default=None,
        help="allowed CORS origin; repeat for multiple origins",
    )
    args = parser.parse_args(argv)
    cors_origins = tuple(args.cors_origins) if args.cors_origins else DEFAULT_CORS_ORIGINS
    app = create_app(state_path=args.state_path, cors_origins=cors_origins)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
