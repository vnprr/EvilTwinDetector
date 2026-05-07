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
