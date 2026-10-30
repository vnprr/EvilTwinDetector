"""Read-only HTTP API for the dashboard."""

from .app import create_app

__all__ = ["create_app"]
