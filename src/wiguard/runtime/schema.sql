-- WiGuard state database, schema version 3.
-- Written by the sensor and `wiguard replay`; read (read-only) by the API.

-- Key/value pairs: schema_version, sensor_status (JSON).
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- Latest summary of every AP heard (one row per BSSID).
CREATE TABLE access_points (
    bssid TEXT PRIMARY KEY,
    ssid TEXT NOT NULL,
    channels TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    frames INTEGER NOT NULL,
    last_rssi_dbm INTEGER,
    avg_rssi_dbm REAL,
    rssi_stddev REAL,
    clock_skew_ppm REAL,
    dominant_ie_fingerprint TEXT,
    vendor_ouis TEXT NOT NULL,
    summary TEXT NOT NULL,
    updated_at REAL NOT NULL
);

-- RSSI / clock-skew history for trend charts (capped per AP).
CREATE TABLE ap_metrics (
    id INTEGER PRIMARY KEY,
    bssid TEXT NOT NULL,
    observed_at REAL NOT NULL,
    frames INTEGER NOT NULL,
    avg_rssi_dbm REAL,
    rssi_stddev REAL,
    clock_skew_ppm REAL
);
CREATE INDEX ap_metrics_by_bssid ON ap_metrics (bssid, id);

-- Detector findings, logged when they appear or change (not on every flush).
CREATE TABLE detection_events (
    id INTEGER PRIMARY KEY,
    module TEXT NOT NULL,
    bssid TEXT NOT NULL,
    ssid TEXT NOT NULL,
    strength REAL NOT NULL,
    signal_names TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    event TEXT NOT NULL
);
CREATE INDEX detection_events_by_source ON detection_events (module, bssid, id);

-- Incidents: one open alert per AP; escalated, then resolved when evidence stops.
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    bssid TEXT NOT NULL,
    ssid TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
    classification TEXT NOT NULL,
    score REAL NOT NULL,
    modules TEXT NOT NULL,
    signal_names TEXT NOT NULL,
    explanation TEXT NOT NULL,
    evidence TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    updates INTEGER NOT NULL,
    resolved_at REAL
);
CREATE INDEX alerts_by_bssid ON alerts (bssid, status);

-- Human-readable history: evidence, alert opened / escalated / resolved.
CREATE TABLE timeline (
    id INTEGER PRIMARY KEY,
    observed_at REAL NOT NULL,
    kind TEXT NOT NULL,
    bssid TEXT,
    ssid TEXT,
    alert_id INTEGER,
    message TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX timeline_by_bssid ON timeline (bssid, id);
