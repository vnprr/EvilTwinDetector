// Mirrors the response models in src/wiguard/api/schemas.py.

export type Verdict = "clean" | "info" | "suspicious" | "evil_twin";

export type Items<T> = { count: number; items: T[] };

export type AccessPoint = {
  bssid: string;
  ssid: string;
  channels: number[];
  first_seen: number;
  last_seen: number;
  frames: number;
  last_rssi_dbm: number | null;
  avg_rssi_dbm: number | null;
  rssi_stddev: number | null;
  clock_skew_ppm: number | null;
  dominant_ie_fingerprint: string | null;
  vendor_ouis: string[];
  status: Verdict;
  open_alert_id: number | null;
  trusted: boolean;
};

export type AccessPointDetail = {
  access_point: AccessPoint;
  summary: Record<string, unknown>;
  alerts: Alert[];
};

export type SignalDetail = {
  name: string;
  severity: "low" | "medium" | "high";
  message: string;
  details: Record<string, unknown>;
};

export type Evidence = {
  module: string;
  bssid: string;
  ssid: string;
  strength: number;
  signal_names: string[];
  signals: SignalDetail[];
  last_seen: number;
  context: Record<string, unknown>;
};

export type Alert = {
  id: number;
  bssid: string;
  ssid: string;
  status: "open" | "resolved";
  classification: Exclude<Verdict, "clean">;
  score: number;
  modules: string[];
  signal_names: string[];
  explanation: string;
  first_seen: number;
  last_seen: number;
  updates: number;
  resolved_at: number | null;
  evidence: Evidence[];
};

export type AlertDetail = { alert: Alert; timeline: TimelineEntry[] };

export type TimelineEntry = {
  id: number;
  observed_at: number;
  kind: string;
  bssid: string | null;
  ssid: string | null;
  alert_id: number | null;
  message: string;
  details: Record<string, unknown>;
};

export type MetricSample = {
  observed_at: number;
  frames: number;
  avg_rssi_dbm: number | null;
  rssi_stddev: number | null;
  clock_skew_ppm: number | null;
};

export type Stats = {
  schema_version: number;
  access_points: number;
  detection_events: number;
  alerts: number;
  open_alerts: number;
  open_alerts_by_classification: Record<string, number>;
  timeline_entries: number;
  last_update: number | null;
};

export type SensorStatus = {
  state: "online" | "stale" | "replay" | "unknown";
  last_update: number | null;
  age_seconds: number | null;
  stale_after_seconds: number | null;
  detail: string;
  status: Record<string, unknown> | null;
};

export type TrustedProfile = {
  bssid: string;
  ssid: string;
  frames: number;
  ie_fingerprint: string | null;
  avg_rssi_dbm: number | null;
  clock_skew_ppm: number | null;
  enrolled_at: number;
};

export type TrustedProfiles = {
  path: string;
  enrolled: number;
  profiles: TrustedProfile[];
  error: string | null;
};

type Section = Record<string, unknown>;

export type EffectiveConfig = {
  source_path: string | null;
  capture: Section;
  features: Section;
  runtime: Section;
  detection: {
    identity: Section;
    duplicate_bssid: Section;
    deauth_storm: Section;
    environment_anomaly: Section;
    correlation: {
      module_weights: Record<string, number>;
      suspicious_threshold: number;
      evil_twin_threshold: number;
      min_score: number;
    };
  };
};
