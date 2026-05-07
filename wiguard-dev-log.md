# WiGuard Development Log

## 2026-05-07 — Etap 0A, Alfa RTL8812AU Hardware Foundation

- Verified the external Alfa adapter: USB `0bda:8812`, interface `wlx00c0cab6d8f3`, driver `rtw88_8812au`, firmware `52.14.0`.
- Confirmed the internal laptop Wi-Fi `wlo1` stayed connected to `UPC257567143` throughout capture testing.
- Installed required tools and Scapy environment: `iw`, `aircrack-ng`, `tcpdump`, Python virtualenv, Scapy `2.7.0`.
- Confirmed monitor mode support through `iw list`.
- Found that creating a separate monitor interface `wiguardmon0` works, but channel tuning fails with `Device or resource busy (-16)`.
- Confirmed direct monitor mode on `wlx00c0cab6d8f3` works with the kernel `rtw88_8812au` driver.
- Captured 30 beacon frames on channel 1 into `/tmp/wiguard_alfa_beacons.pcap`.
- Validated `30/30` frames have RadioTap, Dot11 beacon, AP TSF, RadioTap TSFT, RSSI, BSSID, and channel data.
- Decision: continue with `rtw88_8812au` for the first prototype; use direct monitor mode on the Alfa adapter and restore it to managed mode on exit.

## 2026-05-07 — Etap 0B, Product Capture Foundation

- Added a Python package skeleton under `wiguard/src/wiguard`.
- Added a safe capture adapter manager that only manipulates the Alfa adapter and checks that `wlo1` remains connected.
- Added frame parsing for beacon and probe response frames with SSID, BSSID, channel, RSSI, AP TSF, RadioTap TSFT, sequence number, and monotonic receive time.
- Added an AP state manager with rolling RSSI/TSF observations.
- Added `wiguard-scan`, a passive CLI scanner with channel hopping and JSON/table output.
- Added unit and integration tests around parser/state behavior and the real Alfa pcap when present.
- Found and fixed a state injection bug in `WiGuardCaptureEngine`: an empty `APStateManager` must not be replaced just because it is falsey through `__len__`.
- Added capture metrics to CLI JSON output: attempted/tuned channels, channel errors, packets seen, observations seen.
- Validated `wiguard-scan` end-to-end with `sudo .venv/bin/wiguard-scan --duration 5 --dwell 2 --channels 1 --json`.
- CLI validation result: 175 packets seen, 166 AP observations parsed, 6 AP states produced, `wlo1` stayed connected, Alfa restored to managed/disconnected.
- Initialized a Git repository on branch `main`; the user later created the initial commit `9ec2e86` (`1st commit`).

## 2026-05-07 — Etap 1A/1B/1D, Feature Extraction Pipeline Start

- Added `FeatureExtractor`, producing `APFeatureVector` for beacon/probe-response frames.
- Added deterministic IE fingerprinting:
  - preserves full IE sequence signatures,
  - excludes dynamic IE IDs `5`, `11`, `37`, and `40` from stable fingerprinting,
  - hashes key stable IE payloads with SHA-256,
  - extracts vendor OUIs from vendor-specific IE `221`.
- Added `ClockSkewEstimator` using rolling least-squares regression of AP TSF vs local monotonic time.
- Added feature-level AP aggregation with IE hash sets, vendor OUI sets, RSSI stats, sequence number tracking, and optional clock-skew estimates.
- Added `ManagementFrameCounter` for deauthentication and disassociation frames per BSSID/channel with recent-rate tracking.
- Added `wiguard-analyze-pcap`, an offline analyzer for repeatable feature extraction from saved pcap files.
- Added live feature mode to `wiguard-scan` via `--features`, while keeping the default scan path lightweight.
- Validated offline analyzer on `/tmp/wiguard_alfa_beacons.pcap`: 10 packets, 10 AP feature vectors, IE fingerprints and vendor OUIs extracted, one AP had enough samples for a clock estimate with the temporary `--min-clock-samples 3` setting.
- Validated live feature mode with `sudo .venv/bin/wiguard-scan --duration 5 --dwell 2 --channels 1 --features --min-clock-samples 5 --json`: 172 packets, 165 observations, 6 AP summaries, 6 feature AP summaries, 5 temporary clock estimates, `wlo1` stayed connected, Alfa restored to managed/disconnected.
- Added unit/integration tests for IE fingerprint stability, feature extraction, clock skew regression, feature aggregation, management frame counting, and real Alfa pcap feature extraction.
- Test status after this stage: `10` tests passing.

Notes:

- Production/default clock-skew threshold remains conservative at `50` samples; low values such as `3` are only for smoke-testing small pcaps.
- The current pcap in `/tmp` is a runtime artifact, not a committed fixture. A curated fixture should be captured and sanitized later under `tests/pcap_fixtures/`.

## 2026-05-07 — Etap 1C Completion + Etap 2 Module 1 Start

- Completed the missing Etap 1C per-beacon feature work:
  - added beacon timing jitter analysis using AP TSF deltas and declared beacon interval,
  - added sequence-number continuity analysis with duplicate, wrap, reset/backward jump, and large-gap counters,
  - expanded AP feature summaries with stable IE ID union and key IE ID union over the rolling profile.
- Validated the expanded feature profile on `/tmp/wiguard_alfa_beacons.pcap`: 10 packets, 10 feature vectors, 5 AP profiles, 5 timing samples, 10 sequence samples.
- Validated the expanded live feature path with `sudo .venv/bin/wiguard-scan --duration 5 --dwell 2 --channels 1 --features --min-clock-samples 5 --json`: 766 packets seen by Scapy, 175 AP observations, 6 AP profiles, 134 timing samples, 175 sequence samples, 5 temporary clock estimates.
- Confirmed after the live run that `wlo1` stayed connected and Alfa returned to `managed` / disconnected.
- Started Etap 2 Module 1 with `APIdentityVerifier`:
  - maintains a per-BSSID identity baseline,
  - emits explainable signals for IE fingerprint changes, clock-skew changes, RSSI shifts, and sequence reset increases,
  - keeps scores deterministic and bounded so the future correlation engine can combine signals instead of treating this as a final verdict.
- Added tests for beacon timing, sequence analysis, and AP identity verification.
- Test status after this stage: `14` tests passing.

Notes:

- `APIdentityVerifier` is not yet wired into the live CLI as a persistent detector because it needs a real baseline lifecycle and correlation policy. The module is ready as a deterministic signal source for the next correlation/detection layer.

## 2026-05-07 — Etap 2 Module 2, Deauth Storm Detection

- Added `DeauthStormDetector` for anomalous deauthentication/disassociation bursts.
- Expanded `ManagementFrameCounter` evidence:
  - total recent management-frame rate per BSSID/channel,
  - broadcast vs unicast totals,
  - broadcast vs unicast recent rates,
  - source MACs observed for the management frames.
- Added explainable deauth storm signals:
  - `management_frame_rate_high`,
  - `broadcast_flood`,
  - `targeted_unicast_burst`.
- Wired deauth storm alerts into:
  - live `wiguard-scan --features --json` output,
  - offline `wiguard-analyze-pcap` output.
- Validated with synthetic broadcast flood and targeted unicast burst tests.
- Validated on `/tmp/wiguard_alfa_beacons.pcap`: 10 packets, 10 feature vectors, 0 management frames, 0 deauth alerts, which is the expected quiet baseline for a beacon-only capture.
- Validated live feature scan after wiring deauth alerts with `sudo .venv/bin/wiguard-scan --duration 4 --dwell 2 --channels 1 --features --min-clock-samples 5 --json`: 154 packets, 146 AP observations, 6 AP profiles, 0 management summaries, 0 deauth alerts.
- Confirmed after the live run that `wlo1` stayed connected and Alfa returned to `managed` / disconnected.
- Test status after this stage: `16` tests passing.

Notes:

- Thresholds are currently static and configurable. Adaptive thresholds for dense environments should come later, after correlation and data collection.
- This module is passive only; it does not generate or inject deauth frames.

## 2026-05-07 — Etap 2 Module 3 Start, Environment Anomaly Detection

- Added the first production-oriented implementation of `EnvironmentAnomalyDetector`.
- Design decision: start with deterministic same-SSID peer comparison instead of adding HDBSCAN/ML immediately.
  - This keeps the detector explainable and dependency-light.
  - It is conservative by default: it only compares SSID groups with enough peers and enough frames per AP.
  - It produces signals for the future correlation engine rather than final standalone verdicts.
- Implemented same-SSID anomaly signals:
  - `same_ssid_ie_fingerprint_outlier`,
  - `same_ssid_vendor_oui_outlier`,
  - `same_ssid_ie_shape_outlier`,
  - `same_ssid_beacon_interval_outlier`.
- Added configurable thresholds under `detection.environment_anomaly` in `config.yaml`.
- Wired environment anomaly output into:
  - live `wiguard-scan --features --json` as `environment_alerts`,
  - offline `wiguard-analyze-pcap` as `environment_alerts`.
- Added unit coverage for:
  - quiet homogeneous same-SSID groups,
  - minority IE fingerprint/vendor/IE-shape outliers,
  - beacon interval outliers,
  - conservative skipping of groups without enough same-SSID peers.
- Validated offline analyzer on `/tmp/wiguard_alfa_beacons.pcap`: 10 packets, 10 feature vectors, 0 management frames, 0 deauth alerts, 0 environment alerts.
- Validated live feature scan with `sudo .venv/bin/wiguard-scan --duration 4 --dwell 2 --channels 1 --features --min-clock-samples 5 --json`: 106 packets, 102 AP observations, 6 AP profiles, 0 management summaries, 0 deauth alerts, 0 environment alerts.
- Confirmed after the live run that `wlo1` stayed connected to `UPC257567143` and Alfa `wlx00c0cab6d8f3` returned to `managed` / disconnected.
- Test status after this stage: `20` tests passing.

Notes:

- Module 3 currently implements peer comparison, not full HDBSCAN clustering. This is intentional for the first reliable product slice; HDBSCAN can be added later once there is enough real capture data to tune distance metrics and avoid noisy false positives.
- The strongest use case is an enterprise or home mesh-style SSID where several legitimate APs share the same beacon/fingerprint family and a rogue AP becomes a minority profile.

## 2026-05-07 — Etap 2 Correlation Engine Start

- Added `CorrelationEngine` under `wiguard.correlation`.
- Added a normalized `DetectionEvent` model so independent modules can feed one common correlation layer.
- Added conversion helpers for:
  - `IdentityAlert`,
  - `DeauthStormAlert`,
  - `EnvironmentAnomalyAlert`.
- Implemented deterministic per-BSSID alert correlation:
  - weighted module scores,
  - nonlinear multi-module multiplier,
  - rule bonuses for key combinations such as `deauth_storm + environment_anomaly` and `identity_verification + deauth_storm + environment_anomaly`,
  - deterministic UUIDv5 alert IDs,
  - `info` / `suspicious` / `evil_twin` classification.
- Wired `correlated_alerts` into:
  - live `wiguard-scan --features --json`,
  - offline `wiguard-analyze-pcap`.
- Added `detection.correlation` configuration defaults to `config.yaml`.
- Added tests proving:
  - deauth + environment produces a `suspicious` correlated alert,
  - identity + deauth + environment escalates to `evil_twin`,
  - low-score evidence is filtered by `min_final_score`.
- Validated offline analyzer after correlation wiring on `/tmp/wiguard_alfa_beacons.pcap`: 10 packets, 10 feature vectors, 0 management frames, 0 deauth alerts, 0 environment alerts, 0 correlated alerts.
- Validated live feature scan after correlation wiring with `sudo .venv/bin/wiguard-scan --duration 4 --dwell 2 --channels 1 --features --min-clock-samples 5 --json`: 143 packets, 141 AP observations, 5 AP profiles, 0 management summaries, 0 deauth alerts, 0 environment alerts, 0 correlated alerts.
- Confirmed after the live run that `wlo1` stayed connected to `UPC257567143` and Alfa `wlx00c0cab6d8f3` returned to `managed` / disconnected.
- Test status after this stage: `23` tests passing.

Notes:

- Correlation is now ready for Module 1 identity alerts once persistent baseline lifecycle is added.
- The engine currently correlates a single analysis window. A later production daemon should add time-window persistence, deduplication over time, and alert escalation history.
