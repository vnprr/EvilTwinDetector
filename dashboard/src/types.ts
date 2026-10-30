export type Classification = "clean" | "info" | "suspicious" | "evil_twin";

export type HealthPayload = RuntimeStats & {
  status: string;
  state_path: string;
};

export type RuntimeStats = {
  schema_version: number;
  ap_count: number;
  raw_event_count: number;
  alert_count: number;
  timeline_event_count: number;
  classification_counts: Record<string, number>;
  latest: Record<string, number | null>;
};

export type APListItem = {
  bssid: string;
  ssid: string;
  channels: number[];
  last_rssi_dbm: number | null;
  avg_rssi_dbm: number | null;
  total_frames: number;
  last_seen: number;
  status: Classification;
  last_alert: CompactAlert | null;
};

export type CompactAlert = {
  alert_key: string;
  classification: Classification;
  final_score: number;
  last_seen: number;
  count: number;
  contributing_modules: string[];
};

export type APDetail = {
  snapshot: Record<string, unknown> & {
    bssid: string;
    ssid: string;
    channels?: number[];
    avg_rssi_dbm?: number | null;
    dominant_ie_fingerprint?: string | null;
    payload?: Record<string, unknown>;
    total_frames?: number;
  };
  status: Classification;
  alerts: CorrelatedAlert[];
};

export type CorrelatedAlert = {
  alert_key: string;
  alert_id: string;
  bssid: string;
  ssid: string;
  final_score: number;
  classification: Classification;
  contributing_modules: string[];
  signal_names: string[];
  first_seen: number;
  last_seen: number;
  count: number;
  status: string;
  explanation: string;
  timeline: DetectionEvent[];
  payload?: Record<string, unknown>;
  updated_at: number;
};

export type DetectionEvent = {
  module: string;
  bssid: string;
  ssid: string | null;
  score: number;
  signal_names: string[];
  evidence: Record<string, unknown>;
};

export type TimelineEvent = {
  timeline_id: number;
  observed_at: number;
  event_type: string;
  reference_key: string | null;
  bssid: string | null;
  ssid: string | null;
  message: string;
  payload: Record<string, unknown>;
};

export type SensorStatus = {
  state: "online" | "stale" | "unknown";
  detail?: string;
  last_update: number | null;
  stale_seconds: number | null;
  stale_threshold_seconds?: number;
  runtime_status: {
    observed_at?: number;
    interface?: string;
    internal_interface?: string;
    channels?: number[];
    flush_interval_seconds?: number;
    ap_snapshots?: number;
    config_source?: string | null;
    capture?: Record<string, unknown>;
  } | null;
};

export type BaselineItem = {
  bssid: string;
  ssid: string;
  frames: number;
  dominant_ie_fingerprint: string | null;
  avg_rssi_dbm: number | null;
  rssi_stddev: number | null;
  clock_skew_ppm: number | null;
  sequence_reset_count: number;
};

export type BaselinePayload = {
  baseline_path: string;
  auto_learn: boolean;
  enrolled: number;
  baselines: BaselineItem[];
  metadata?: Record<string, unknown>;
  detail?: string;
  error?: string;
};

export type EffectiveConfig = {
  source_path: string | null;
  capture: Record<string, unknown>;
  runtime: Record<string, number | string>;
  features: Record<string, number>;
  safety: Record<string, unknown>;
  detection: {
    identity: Record<string, unknown>;
    deauth_storm: Record<string, number>;
    environment_anomaly: Record<string, number>;
    correlation: {
      min_final_score: number;
      module_weights: Record<string, number>;
    };
  };
};

export type DetectionEventRow = {
  event_id: number;
  observed_at: number;
  module: string;
  bssid: string;
  ssid: string | null;
  score: number;
  signal_names: string[];
  evidence: Record<string, unknown>;
  payload: Record<string, unknown>;
};
