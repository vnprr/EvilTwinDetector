"""Alert correlation engine package."""

from .engine import (
    CorrelatedAlert,
    CorrelationEngine,
    DetectionEvent,
    events_from_alerts,
)

__all__ = [
    "CorrelatedAlert",
    "CorrelationEngine",
    "DetectionEvent",
    "events_from_alerts",
]
