"""Command-line launcher for the WiGuard Runtime API."""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from wiguard.api.app import create_app
from wiguard.config import DEFAULT_CONFIG_PATH, load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the WiGuard Runtime Store API")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="path to config.yaml (defaults applied if missing)",
    )
    parser.add_argument("--host", default=None, help="API bind host (overrides config)")
    parser.add_argument("--port", type=int, default=None, help="API bind port (overrides config)")
    parser.add_argument("--state-path", type=Path, default=None, help="SQLite runtime state path (overrides config)")
    parser.add_argument(
        "--cors-origin",
        action="append",
        dest="cors_origins",
        default=None,
        help="allowed CORS origin; repeat for multiple origins (overrides config)",
    )
    args = parser.parse_args(argv)

    config = load_config(args.config)
    host = args.host or config.api.host
    port = args.port if args.port is not None else config.api.port
    state_path = args.state_path if args.state_path is not None else Path(config.api.state_path)
    cors_origins = tuple(args.cors_origins) if args.cors_origins else config.api.cors_origins

    app = create_app(state_path=state_path, cors_origins=cors_origins, config=config)
    uvicorn.run(app, host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
