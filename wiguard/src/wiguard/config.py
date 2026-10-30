"""Single source of truth for WiGuard runtime configuration.

Before this module existed, ``config.yaml`` was inert: nothing read it, and
every detection threshold lived only as a hardcoded default inside each
detector constructor. Operators who edited ``config.yaml`` changed nothing,
which also made it impossible to describe WiGuard as "configurable" in the
thesis without misleading the reader.

This module fixes that. It:

* defines every tunable value once, with a documented default;
* loads ``config.yaml`` when present and validates it (rejecting unknown keys
  so typos fail loudly instead of being silently ignored);
* builds the detection components *from* the resolved configuration, so that
  changing a value in ``config.yaml`` actually changes detector behaviour.

Command-line flags still take precedence over the file (the CLIs load the
config first and use its values as their argument defaults), and the file in
turn overrides these built-in defaults.

Detector/feature classes are imported lazily inside the ``build_*`` methods so
that merely importing this module (for example from the read-only API) does
not pull in Scapy or the capture stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from wiguard.capture.models import (
    DEFAULT_ALFA_INTERFACE,
    DEFAULT_CHANNELS_2GHZ,
    DEFAULT_CHANNELS_5GHZ,
    DEFAULT_INTERNAL_INTERFACE,
)


DEFAULT_CONFIG_PATH = Path("config.yaml")

# Weights mirror ``wiguard.correlation.engine.DEFAULT_MODULE_WEIGHTS``. They are
# duplicated here (not imported) so that importing this module stays cheap; the
# ``test_config`` suite asserts the two stay in sync.
DEFAULT_MODULE_WEIGHTS: dict[str, float] = {
    "identity_verification": 0.45,
    "deauth_storm": 0.35,
    "environment_anomaly": 0.35,
    "active_verification": 0.6,
}


class ConfigError(ValueError):
    """Raised when ``config.yaml`` is malformed or contains unknown keys."""


# --------------------------------------------------------------------------- #
# Settings dataclasses — one per config.yaml section.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CaptureSettings:
    interface: str = DEFAULT_ALFA_INTERFACE
    internal_interface: str = DEFAULT_INTERNAL_INTERFACE
    dwell_seconds: float = 0.5
    monitor_settle_seconds: float = 0.25
    channel_settle_seconds: float = 0.05
    restore_managed_on_exit: bool = True
    channels_2ghz: tuple[int, ...] = DEFAULT_CHANNELS_2GHZ
    channels_5ghz: tuple[int, ...] = DEFAULT_CHANNELS_5GHZ

    def channels(self) -> tuple[int, ...]:
        return tuple(self.channels_2ghz) + tuple(self.channels_5ghz)


@dataclass(frozen=True)
class StateSettings:
    rolling_window_size: int = 300


@dataclass(frozen=True)
class RuntimeSettings:
    state_path: str = ".wiguard/wiguard.db"
    flush_interval_seconds: float = 5.0
    alert_cooldown_seconds: float = 300.0
    window_seconds: float = 300.0


@dataclass(frozen=True)
class ApiSettings:
    host: str = "127.0.0.1"
    port: int = 8765
    state_path: str = ".wiguard/wiguard.db"
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)


@dataclass(frozen=True)
class FeatureSettings:
    clock_skew_min_samples: int = 50
    clock_skew_window_size: int = 300
    management_recent_window_seconds: float = 10.0


@dataclass(frozen=True)
class DuplicateBssidSettings:
    min_samples: int = 30
    min_cluster_samples: int = 8
    residual_gap_threshold_us: float = 10_000.0
    intercept_delta_threshold_us: float = 10_000.0
    sequence_transition_threshold: int = 4


@dataclass(frozen=True)
class IdentitySettings:
    baseline_path: str = ".wiguard/identity-baselines.json"
    auto_learn: bool = False
    min_baseline_frames: int = 50
    clock_skew_delta_ppm: float = 5.0
    rssi_shift_db: float = 12.0
    duplicate_bssid: DuplicateBssidSettings = field(default_factory=DuplicateBssidSettings)


@dataclass(frozen=True)
class DeauthStormSettings:
    deauth_rate_threshold: float = 10.0
    disassoc_rate_threshold: float = 5.0
    broadcast_rate_threshold: float = 5.0
    unicast_rate_threshold: float = 5.0


@dataclass(frozen=True)
class EnvironmentAnomalySettings:
    min_frames: int = 5
    min_same_ssid_peers: int = 3
    majority_ratio: float = 0.6
    vendor_oui_distance_threshold: float = 0.75
    ie_shape_distance_threshold: float = 0.45
    beacon_interval_delta_tu: float = 20.0


@dataclass(frozen=True)
class CorrelationSettings:
    min_final_score: float = 0.2
    module_weights: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_MODULE_WEIGHTS)
    )


@dataclass(frozen=True)
class DetectionSettings:
    identity: IdentitySettings = field(default_factory=IdentitySettings)
    deauth_storm: DeauthStormSettings = field(default_factory=DeauthStormSettings)
    environment_anomaly: EnvironmentAnomalySettings = field(
        default_factory=EnvironmentAnomalySettings
    )
    correlation: CorrelationSettings = field(default_factory=CorrelationSettings)


@dataclass(frozen=True)
class SafetySettings:
    require_internal_wifi_connected: bool = True
    # Advisory policy surfaced to the operator (e.g. in the API). WiGuard does
    # not spawn these commands; the entry is a documented guard-rail, not an
    # enforced block.
    forbidden_commands: tuple[str, ...] = ("airmon-ng check kill",)


@dataclass(frozen=True)
class WiGuardConfig:
    """Resolved, validated WiGuard configuration (defaults + config.yaml)."""

    capture: CaptureSettings = field(default_factory=CaptureSettings)
    state: StateSettings = field(default_factory=StateSettings)
    runtime: RuntimeSettings = field(default_factory=RuntimeSettings)
    api: ApiSettings = field(default_factory=ApiSettings)
    features: FeatureSettings = field(default_factory=FeatureSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    safety: SafetySettings = field(default_factory=SafetySettings)
    source_path: str | None = None

    # -- component factories (lazy imports keep this module light) ---------- #

    def capture_config(
        self,
        *,
        interface: str | None = None,
        internal_interface: str | None = None,
        channels: tuple[int, ...] | None = None,
        dwell_seconds: float | None = None,
    ):
        from wiguard.capture.models import CaptureConfig

        return CaptureConfig(
            interface=interface or self.capture.interface,
            internal_interface=internal_interface or self.capture.internal_interface,
            channels=tuple(channels) if channels else self.capture.channels(),
            dwell_seconds=self.capture.dwell_seconds if dwell_seconds is None else dwell_seconds,
            monitor_settle_seconds=self.capture.monitor_settle_seconds,
            channel_settle_seconds=self.capture.channel_settle_seconds,
            require_internal_wifi_connected=self.safety.require_internal_wifi_connected,
            restore_managed_on_exit=self.capture.restore_managed_on_exit,
        )

    def build_ap_state(self):
        from wiguard.state import APStateManager

        return APStateManager(window_size=self.state.rolling_window_size)

    def build_feature_state(self):
        from wiguard.features import APFeatureStateManager

        return APFeatureStateManager(
            window_size=self.features.clock_skew_window_size,
            min_clock_samples=self.features.clock_skew_min_samples,
        )

    def build_management_counter(self):
        from wiguard.features import ManagementFrameCounter

        return ManagementFrameCounter(
            recent_window_seconds=self.features.management_recent_window_seconds
        )

    def build_deauth_detector(self):
        from wiguard.detection import DeauthStormDetector

        d = self.detection.deauth_storm
        return DeauthStormDetector(
            deauth_rate_threshold=d.deauth_rate_threshold,
            disassoc_rate_threshold=d.disassoc_rate_threshold,
            broadcast_rate_threshold=d.broadcast_rate_threshold,
            unicast_rate_threshold=d.unicast_rate_threshold,
        )

    def build_environment_detector(self):
        from wiguard.detection import EnvironmentAnomalyDetector

        e = self.detection.environment_anomaly
        return EnvironmentAnomalyDetector(
            min_frames=e.min_frames,
            min_same_ssid_peers=e.min_same_ssid_peers,
            majority_ratio=e.majority_ratio,
            vendor_oui_distance_threshold=e.vendor_oui_distance_threshold,
            ie_shape_distance_threshold=e.ie_shape_distance_threshold,
            beacon_interval_delta_tu=e.beacon_interval_delta_tu,
        )

    def build_duplicate_detector(self):
        from wiguard.detection import DuplicateBSSIDDetector

        i = self.detection.identity
        dup = i.duplicate_bssid
        return DuplicateBSSIDDetector(
            window_size=self.state.rolling_window_size,
            min_samples=dup.min_samples,
            min_cluster_samples=dup.min_cluster_samples,
            residual_gap_threshold_us=dup.residual_gap_threshold_us,
            clock_skew_delta_ppm=i.clock_skew_delta_ppm,
            intercept_delta_threshold_us=dup.intercept_delta_threshold_us,
            rssi_delta_db=i.rssi_shift_db,
            sequence_transition_threshold=dup.sequence_transition_threshold,
        )

    def build_correlation_engine(self):
        from wiguard.correlation import CorrelationEngine

        c = self.detection.correlation
        return CorrelationEngine(
            module_weights=dict(c.module_weights),
            min_final_score=c.min_final_score,
        )

    def identity_baseline_store(self):
        from wiguard.detection import IdentityBaselineStore

        path = self.detection.identity.baseline_path
        return IdentityBaselineStore(path) if path else None

    def build_identity_verifier(self, baselines, *, auto_baseline: bool = False):
        from wiguard.detection import APIdentityVerifier

        i = self.detection.identity
        return APIdentityVerifier(
            min_baseline_frames=i.min_baseline_frames,
            clock_skew_delta_ppm=i.clock_skew_delta_ppm,
            rssi_shift_db=i.rssi_shift_db,
            baselines=baselines,
            auto_baseline=auto_baseline,
        )

    def to_public_dict(self) -> dict[str, Any]:
        """JSON-serialisable view for the read-only API/dashboard."""

        return _public(self)


# --------------------------------------------------------------------------- #
# Loading and validation.
# --------------------------------------------------------------------------- #


def load_config(
    path: Path | str | None = None,
    *,
    required: bool = False,
) -> WiGuardConfig:
    """Load and validate a :class:`WiGuardConfig`.

    * ``path`` ``None`` resolves to ``config.yaml`` in the working directory if
      it exists, otherwise built-in defaults are returned.
    * An explicit ``path`` that does not exist raises when ``required`` is set,
      and otherwise returns defaults with ``source_path`` left unset.
    """

    resolved = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if not resolved.exists():
        if required and path is not None:
            raise ConfigError(f"config file not found: {resolved}")
        return WiGuardConfig()

    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - passthrough of parser msg
        raise ConfigError(f"{resolved}: invalid YAML: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{resolved}: top-level config must be a mapping")

    config = _build_config(raw)
    return _replace(config, source_path=str(resolved))


def _build_config(raw: Mapping[str, Any]) -> WiGuardConfig:
    _reject_unknown(
        raw,
        {"capture", "state", "runtime", "api", "features", "detection", "safety"},
        "(root)",
    )
    return WiGuardConfig(
        capture=_capture(_section(raw, "capture")),
        state=_state(_section(raw, "state")),
        runtime=_runtime(_section(raw, "runtime")),
        api=_api(_section(raw, "api")),
        features=_features(_section(raw, "features")),
        detection=_detection(_section(raw, "detection")),
        safety=_safety(_section(raw, "safety")),
    )


def _capture(raw: Mapping[str, Any]) -> CaptureSettings:
    allowed = {f.name for f in fields(CaptureSettings)} | {"channels"}
    _reject_unknown(raw, allowed, "capture")
    base = CaptureSettings()
    # ``channels`` may be given either split (2ghz/5ghz) or as a single list.
    if "channels" in raw and ("channels_2ghz" in raw or "channels_5ghz" in raw):
        raise ConfigError("capture: use either 'channels' or 'channels_2ghz'/'channels_5ghz', not both")
    if "channels" in raw:
        channels_2ghz: tuple[int, ...] = _int_tuple(raw["channels"], "capture.channels")
        channels_5ghz: tuple[int, ...] = ()
    else:
        channels_2ghz = _int_tuple(raw.get("channels_2ghz", base.channels_2ghz), "capture.channels_2ghz")
        channels_5ghz = _int_tuple(raw.get("channels_5ghz", base.channels_5ghz), "capture.channels_5ghz")
    return CaptureSettings(
        interface=_str(raw.get("interface", base.interface), "capture.interface"),
        internal_interface=_str(raw.get("internal_interface", base.internal_interface), "capture.internal_interface"),
        dwell_seconds=_positive_float(raw.get("dwell_seconds", base.dwell_seconds), "capture.dwell_seconds"),
        monitor_settle_seconds=_float(raw.get("monitor_settle_seconds", base.monitor_settle_seconds), "capture.monitor_settle_seconds"),
        channel_settle_seconds=_float(raw.get("channel_settle_seconds", base.channel_settle_seconds), "capture.channel_settle_seconds"),
        restore_managed_on_exit=_bool(raw.get("restore_managed_on_exit", base.restore_managed_on_exit), "capture.restore_managed_on_exit"),
        channels_2ghz=channels_2ghz,
        channels_5ghz=channels_5ghz,
    )


def _state(raw: Mapping[str, Any]) -> StateSettings:
    _reject_unknown(raw, {f.name for f in fields(StateSettings)}, "state")
    base = StateSettings()
    return StateSettings(
        rolling_window_size=_positive_int(raw.get("rolling_window_size", base.rolling_window_size), "state.rolling_window_size"),
    )


def _runtime(raw: Mapping[str, Any]) -> RuntimeSettings:
    _reject_unknown(raw, {f.name for f in fields(RuntimeSettings)}, "runtime")
    base = RuntimeSettings()
    return RuntimeSettings(
        state_path=_str(raw.get("state_path", base.state_path), "runtime.state_path"),
        flush_interval_seconds=_positive_float(raw.get("flush_interval_seconds", base.flush_interval_seconds), "runtime.flush_interval_seconds"),
        alert_cooldown_seconds=_positive_float(raw.get("alert_cooldown_seconds", base.alert_cooldown_seconds), "runtime.alert_cooldown_seconds"),
        window_seconds=_positive_float(raw.get("window_seconds", base.window_seconds), "runtime.window_seconds"),
    )


def _api(raw: Mapping[str, Any]) -> ApiSettings:
    _reject_unknown(raw, {f.name for f in fields(ApiSettings)}, "api")
    base = ApiSettings()
    return ApiSettings(
        host=_str(raw.get("host", base.host), "api.host"),
        port=_positive_int(raw.get("port", base.port), "api.port"),
        state_path=_str(raw.get("state_path", base.state_path), "api.state_path"),
        cors_origins=_str_tuple(raw.get("cors_origins", base.cors_origins), "api.cors_origins"),
    )


def _features(raw: Mapping[str, Any]) -> FeatureSettings:
    _reject_unknown(raw, {f.name for f in fields(FeatureSettings)}, "features")
    base = FeatureSettings()
    return FeatureSettings(
        clock_skew_min_samples=_positive_int(raw.get("clock_skew_min_samples", base.clock_skew_min_samples), "features.clock_skew_min_samples"),
        clock_skew_window_size=_positive_int(raw.get("clock_skew_window_size", base.clock_skew_window_size), "features.clock_skew_window_size"),
        management_recent_window_seconds=_positive_float(raw.get("management_recent_window_seconds", base.management_recent_window_seconds), "features.management_recent_window_seconds"),
    )


def _detection(raw: Mapping[str, Any]) -> DetectionSettings:
    _reject_unknown(raw, {"identity", "deauth_storm", "environment_anomaly", "correlation"}, "detection")
    return DetectionSettings(
        identity=_identity(_section(raw, "identity")),
        deauth_storm=_deauth(_section(raw, "deauth_storm")),
        environment_anomaly=_environment(_section(raw, "environment_anomaly")),
        correlation=_correlation(_section(raw, "correlation")),
    )


def _identity(raw: Mapping[str, Any]) -> IdentitySettings:
    allowed = {f.name for f in fields(IdentitySettings)}
    _reject_unknown(raw, allowed, "detection.identity")
    base = IdentitySettings()
    return IdentitySettings(
        baseline_path=_str(raw.get("baseline_path", base.baseline_path), "detection.identity.baseline_path"),
        auto_learn=_bool(raw.get("auto_learn", base.auto_learn), "detection.identity.auto_learn"),
        min_baseline_frames=_positive_int(raw.get("min_baseline_frames", base.min_baseline_frames), "detection.identity.min_baseline_frames"),
        clock_skew_delta_ppm=_positive_float(raw.get("clock_skew_delta_ppm", base.clock_skew_delta_ppm), "detection.identity.clock_skew_delta_ppm"),
        rssi_shift_db=_positive_float(raw.get("rssi_shift_db", base.rssi_shift_db), "detection.identity.rssi_shift_db"),
        duplicate_bssid=_duplicate(_section(raw, "duplicate_bssid")),
    )


def _duplicate(raw: Mapping[str, Any]) -> DuplicateBssidSettings:
    _reject_unknown(raw, {f.name for f in fields(DuplicateBssidSettings)}, "detection.identity.duplicate_bssid")
    base = DuplicateBssidSettings()
    settings = DuplicateBssidSettings(
        min_samples=_positive_int(raw.get("min_samples", base.min_samples), "detection.identity.duplicate_bssid.min_samples"),
        min_cluster_samples=_positive_int(raw.get("min_cluster_samples", base.min_cluster_samples), "detection.identity.duplicate_bssid.min_cluster_samples"),
        residual_gap_threshold_us=_positive_float(raw.get("residual_gap_threshold_us", base.residual_gap_threshold_us), "detection.identity.duplicate_bssid.residual_gap_threshold_us"),
        intercept_delta_threshold_us=_positive_float(raw.get("intercept_delta_threshold_us", base.intercept_delta_threshold_us), "detection.identity.duplicate_bssid.intercept_delta_threshold_us"),
        sequence_transition_threshold=_positive_int(raw.get("sequence_transition_threshold", base.sequence_transition_threshold), "detection.identity.duplicate_bssid.sequence_transition_threshold"),
    )
    # Mirror the invariant enforced by DuplicateBSSIDDetector so a bad config
    # fails at load time with a clear message rather than deep in a run.
    if settings.min_cluster_samples < 2:
        raise ConfigError("detection.identity.duplicate_bssid.min_cluster_samples must be at least 2")
    if settings.min_samples < settings.min_cluster_samples * 2:
        raise ConfigError("detection.identity.duplicate_bssid.min_samples must be at least twice min_cluster_samples")
    return settings


def _deauth(raw: Mapping[str, Any]) -> DeauthStormSettings:
    _reject_unknown(raw, {f.name for f in fields(DeauthStormSettings)}, "detection.deauth_storm")
    base = DeauthStormSettings()
    return DeauthStormSettings(
        deauth_rate_threshold=_positive_float(raw.get("deauth_rate_threshold", base.deauth_rate_threshold), "detection.deauth_storm.deauth_rate_threshold"),
        disassoc_rate_threshold=_positive_float(raw.get("disassoc_rate_threshold", base.disassoc_rate_threshold), "detection.deauth_storm.disassoc_rate_threshold"),
        broadcast_rate_threshold=_positive_float(raw.get("broadcast_rate_threshold", base.broadcast_rate_threshold), "detection.deauth_storm.broadcast_rate_threshold"),
        unicast_rate_threshold=_positive_float(raw.get("unicast_rate_threshold", base.unicast_rate_threshold), "detection.deauth_storm.unicast_rate_threshold"),
    )


def _environment(raw: Mapping[str, Any]) -> EnvironmentAnomalySettings:
    _reject_unknown(raw, {f.name for f in fields(EnvironmentAnomalySettings)}, "detection.environment_anomaly")
    base = EnvironmentAnomalySettings()
    return EnvironmentAnomalySettings(
        min_frames=_positive_int(raw.get("min_frames", base.min_frames), "detection.environment_anomaly.min_frames"),
        min_same_ssid_peers=_positive_int(raw.get("min_same_ssid_peers", base.min_same_ssid_peers), "detection.environment_anomaly.min_same_ssid_peers"),
        majority_ratio=_ratio(raw.get("majority_ratio", base.majority_ratio), "detection.environment_anomaly.majority_ratio"),
        vendor_oui_distance_threshold=_ratio(raw.get("vendor_oui_distance_threshold", base.vendor_oui_distance_threshold), "detection.environment_anomaly.vendor_oui_distance_threshold"),
        ie_shape_distance_threshold=_ratio(raw.get("ie_shape_distance_threshold", base.ie_shape_distance_threshold), "detection.environment_anomaly.ie_shape_distance_threshold"),
        beacon_interval_delta_tu=_positive_float(raw.get("beacon_interval_delta_tu", base.beacon_interval_delta_tu), "detection.environment_anomaly.beacon_interval_delta_tu"),
    )


def _correlation(raw: Mapping[str, Any]) -> CorrelationSettings:
    _reject_unknown(raw, {f.name for f in fields(CorrelationSettings)}, "detection.correlation")
    base = CorrelationSettings()
    weights_raw = raw.get("module_weights")
    if weights_raw is None:
        weights = dict(DEFAULT_MODULE_WEIGHTS)
    else:
        if not isinstance(weights_raw, Mapping):
            raise ConfigError("detection.correlation.module_weights must be a mapping")
        weights = dict(DEFAULT_MODULE_WEIGHTS)
        for key, value in weights_raw.items():
            weights[str(key)] = _nonnegative_float(value, f"detection.correlation.module_weights.{key}")
    return CorrelationSettings(
        min_final_score=_ratio(raw.get("min_final_score", base.min_final_score), "detection.correlation.min_final_score"),
        module_weights=weights,
    )


def _safety(raw: Mapping[str, Any]) -> SafetySettings:
    _reject_unknown(raw, {f.name for f in fields(SafetySettings)}, "safety")
    base = SafetySettings()
    return SafetySettings(
        require_internal_wifi_connected=_bool(raw.get("require_internal_wifi_connected", base.require_internal_wifi_connected), "safety.require_internal_wifi_connected"),
        forbidden_commands=_str_tuple(raw.get("forbidden_commands", base.forbidden_commands), "safety.forbidden_commands"),
    )


# --------------------------------------------------------------------------- #
# Small coercion / validation helpers.
# --------------------------------------------------------------------------- #


def _section(raw: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = raw.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{key}: expected a mapping, got {type(value).__name__}")
    return value


def _reject_unknown(raw: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ConfigError(
            f"{where}: unknown config key(s): {', '.join(unknown)}; "
            f"allowed: {', '.join(sorted(allowed))}"
        )


def _str(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{where}: expected a string, got {type(value).__name__}")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where}: expected a boolean, got {type(value).__name__}")
    return value


def _float(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where}: expected a number, got {type(value).__name__}")
    return float(value)


def _positive_float(value: Any, where: str) -> float:
    number = _float(value, where)
    if number <= 0:
        raise ConfigError(f"{where}: must be greater than 0")
    return number


def _nonnegative_float(value: Any, where: str) -> float:
    number = _float(value, where)
    if number < 0:
        raise ConfigError(f"{where}: must be greater than or equal to 0")
    return number


def _ratio(value: Any, where: str) -> float:
    number = _float(value, where)
    if not 0.0 <= number <= 1.0:
        raise ConfigError(f"{where}: must be between 0 and 1")
    return number


def _int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}: expected an integer, got {type(value).__name__}")
    return value


def _positive_int(value: Any, where: str) -> int:
    number = _int(value, where)
    if number <= 0:
        raise ConfigError(f"{where}: must be greater than 0")
    return number


def _int_tuple(value: Any, where: str) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)):
        raise ConfigError(f"{where}: expected a list of integers")
    return tuple(_int(item, f"{where}[{index}]") for index, item in enumerate(value))


def _str_tuple(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ConfigError(f"{where}: expected a list of strings")
    return tuple(_str(item, f"{where}[{index}]") for index, item in enumerate(value))


def _replace(config: WiGuardConfig, **changes: Any) -> WiGuardConfig:
    from dataclasses import replace

    return replace(config, **changes)


def _public(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _public(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _public(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_public(item) for item in value]
    return value
