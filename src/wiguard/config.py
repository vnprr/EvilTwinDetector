"""WiGuard configuration: one validated model for every tunable value.

``config.yaml`` overrides the defaults defined here; command-line flags
override ``config.yaml``. Unknown keys and out-of-range values are rejected
when the file is loaded, so a typo fails loudly instead of being ignored.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeFloat,
    PositiveFloat,
    PositiveInt,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from wiguard.correlation import DEFAULT_MODULE_WEIGHTS
from wiguard.detection import Module

DEFAULT_CONFIG_PATH = Path("config.yaml")

CHANNELS_2GHZ = tuple(range(1, 14))
CHANNELS_5GHZ = (36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132,
                 136, 140, 144, 149, 153, 157, 161, 165)  # fmt: skip

Ratio = Annotated[float, Field(ge=0.0, le=1.0)]


class ConfigError(ValueError):
    """``config.yaml`` is missing, malformed or contains invalid values."""


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CaptureSettings(_Section):
    interface: str = "wlx00c0cab6d8f3"
    """Monitor-mode capture adapter (external Alfa)."""
    internal_interface: str = "wlo1"
    """The host's own Wi-Fi; WiGuard never touches it."""
    require_internal_connected: bool = True
    channels: tuple[Annotated[int, Field(ge=1, le=196)], ...] = CHANNELS_2GHZ + CHANNELS_5GHZ
    dwell_seconds: PositiveFloat = 0.5
    monitor_settle_seconds: NonNegativeFloat = 0.25
    channel_settle_seconds: NonNegativeFloat = 0.05
    restore_managed_on_exit: bool = True

    @field_validator("channels")
    @classmethod
    def _non_empty(cls, channels: tuple[int, ...]) -> tuple[int, ...]:
        if not channels:
            raise ValueError("at least one channel is required")
        return channels


class FeatureSettings(_Section):
    window_size: PositiveInt = 300
    """Frames kept per AP for rolling statistics (RSSI, clock, duplicates)."""
    clock_min_samples: Annotated[int, Field(ge=2)] = 50
    disruption_window_seconds: PositiveFloat = 10.0

    @model_validator(mode="after")
    def _window_holds_clock(self) -> Self:
        if self.window_size < self.clock_min_samples:
            raise ValueError("window_size must be >= clock_min_samples")
        return self


class IdentitySettings(_Section):
    trusted_profiles_path: Path = Path(".wiguard/trusted-profiles.json")
    enrollment_min_frames: PositiveInt = 50
    min_frames: PositiveInt = 10
    clock_skew_delta_ppm: PositiveFloat = 5.0
    rssi_shift_db: PositiveFloat = 12.0


class DuplicateBssidSettings(_Section):
    min_samples: PositiveInt = 30
    min_cluster_samples: Annotated[int, Field(ge=2)] = 8
    residual_gap_us: PositiveFloat = 10_000.0
    separation_factor: PositiveFloat = 4.0
    min_transitions: PositiveInt = 4
    rssi_split_db: PositiveFloat = 10.0

    @model_validator(mode="after")
    def _enough_samples(self) -> Self:
        if self.min_samples < 2 * self.min_cluster_samples:
            raise ValueError("min_samples must be at least twice min_cluster_samples")
        return self


class DeauthStormSettings(_Section):
    deauth_rate_threshold: PositiveFloat = 10.0
    disassoc_rate_threshold: PositiveFloat = 5.0
    broadcast_rate_threshold: PositiveFloat = 5.0
    unicast_rate_threshold: PositiveFloat = 5.0


class EnvironmentAnomalySettings(_Section):
    min_frames: PositiveInt = 5
    min_same_ssid_aps: Annotated[int, Field(ge=3)] = 3
    majority_ratio: Annotated[float, Field(gt=0.5, le=1.0)] = 0.6
    vendor_oui_distance_threshold: Ratio = 0.75
    ie_shape_distance_threshold: Ratio = 0.45
    beacon_interval_delta_tu: PositiveInt = 20


class CorrelationSettings(_Section):
    module_weights: dict[Module, Ratio] = Field(
        default_factory=lambda: dict(DEFAULT_MODULE_WEIGHTS)
    )
    suspicious_threshold: Ratio = 0.45
    evil_twin_threshold: Ratio = 0.80
    min_score: Ratio = 0.20

    @field_validator("module_weights")
    @classmethod
    def _fill_missing_weights(cls, weights: dict[Module, float]) -> dict[Module, float]:
        return {**DEFAULT_MODULE_WEIGHTS, **weights}

    @model_validator(mode="after")
    def _ordered_thresholds(self) -> Self:
        if not self.min_score <= self.suspicious_threshold < self.evil_twin_threshold:
            raise ValueError("expected min_score <= suspicious_threshold < evil_twin_threshold")
        return self


class DetectionSettings(_Section):
    identity: IdentitySettings = IdentitySettings()
    duplicate_bssid: DuplicateBssidSettings = DuplicateBssidSettings()
    deauth_storm: DeauthStormSettings = DeauthStormSettings()
    environment_anomaly: EnvironmentAnomalySettings = EnvironmentAnomalySettings()
    correlation: CorrelationSettings = CorrelationSettings()


class RuntimeSettings(_Section):
    state_path: Path = Path(".wiguard/wiguard.db")
    flush_interval_seconds: PositiveFloat = 5.0
    evidence_window_seconds: PositiveFloat = 300.0
    """How long a finished deauth storm still counts as current evidence."""
    alert_resolve_seconds: PositiveFloat = 300.0
    """An open alert without new evidence for this long is marked resolved."""


class ApiSettings(_Section):
    host: str = "127.0.0.1"
    port: Annotated[int, Field(ge=1, le=65535)] = 8765
    cors_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")


class WiGuardConfig(_Section):
    capture: CaptureSettings = CaptureSettings()
    features: FeatureSettings = FeatureSettings()
    detection: DetectionSettings = DetectionSettings()
    runtime: RuntimeSettings = RuntimeSettings()
    api: ApiSettings = ApiSettings()

    _source_path: str | None = PrivateAttr(default=None)

    @property
    def source_path(self) -> str | None:
        """The file this configuration was loaded from (``None``: built-in defaults)."""
        return self._source_path

    def with_overrides(self, overrides: dict[str, Any]) -> WiGuardConfig:
        """Return a validated copy with dotted keys replaced, e.g. ``{"api.port": 9000}``.

        ``None`` values are skipped, so optional CLI flags can be passed as-is.
        """

        data = self.model_dump()
        for dotted, value in overrides.items():
            if value is None:
                continue
            *parents, leaf = dotted.split(".")
            section = data
            for key in parents:
                section = section[key]
            if leaf not in section:
                raise ConfigError(f"unknown config key: {dotted}")
            section[leaf] = value
        updated = _validate(data, origin="override")
        updated._source_path = self._source_path
        return updated


def load_config(path: Path | str | None = None) -> WiGuardConfig:
    """Load ``path`` (default ``./config.yaml``).

    A missing default file means built-in defaults; a missing file that was
    named explicitly is an error.
    """

    resolved = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if not resolved.is_file():
        if path is not None:
            raise ConfigError(f"config file not found: {resolved}")
        return WiGuardConfig()
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as error:
        raise ConfigError(f"{resolved}: invalid YAML: {error}") from error
    config = _validate(raw, origin=str(resolved))
    config._source_path = str(resolved)
    return config


def _validate(data: object, *, origin: str) -> WiGuardConfig:
    try:
        return WiGuardConfig.model_validate(data)
    except ValidationError as error:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in item['loc']) or '(root)'}: {item['msg']}"
            for item in error.errors()
        )
        raise ConfigError(f"{origin}: {problems}") from error
