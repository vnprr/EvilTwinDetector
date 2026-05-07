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

## 2026-05-07 — Etap 2 Module 1 Lifecycle, Persistent Identity Baselines

- Added persistent trusted baseline storage for `APIdentityVerifier`:
  - `IdentityBaselineStore`,
  - schema-versioned JSON format,
  - atomic write through a temporary file and replace,
  - load/save metadata included in JSON output.
- Added explicit identity workflow to both live and offline paths:
  - `--identity-baseline PATH` loads trusted baselines,
  - `--identity-learn` learns or refreshes baselines from a known-good scan/pcap,
  - monitor mode does not auto-learn unknown BSSIDs.
- Added identity thresholds to CLI/analyzer:
  - `--identity-min-baseline-frames`,
  - `--identity-clock-skew-delta-ppm`,
  - `--identity-rssi-shift-db`.
- Wired `identity_alerts` into:
  - live `wiguard-scan --features --json`,
  - offline `wiguard-analyze-pcap`,
  - `CorrelationEngine` through normalized `DetectionEvent`.
- Added local baseline path defaults to `config.yaml` and ignored `.wiguard/` in Git.
- Added test coverage for:
  - identity baseline JSON round-trip,
  - monitor mode not auto-learning unknown BSSIDs,
  - loaded baseline triggering an identity alert.
- Validated offline baseline lifecycle with `/tmp/wiguard_alfa_beacons.pcap` and a temporary baseline file:
  - learn pass: 5 AP profiles, 5 baselines saved, 0 identity alerts,
  - monitor pass against the learned baseline: 5 baselines loaded, 0 identity alerts, 0 correlated alerts.
- Validated live baseline learning with `sudo .venv/bin/wiguard-scan --duration 4 --dwell 2 --channels 1 --features --min-clock-samples 5 --identity-baseline /tmp/wiguard_identity_live_baseline.json --identity-learn --identity-min-baseline-frames 1 --json`:
  - 139 packets,
  - 120 AP observations,
  - 5 feature AP profiles,
  - 5 identity baselines saved,
  - 0 identity alerts,
  - 0 deauth/environment/correlated alerts.
- Confirmed after the live run that `wlo1` stayed connected to `UPC257567143` and Alfa `wlx00c0cab6d8f3` returned to `managed` / disconnected.
- Test status after this stage: `26` tests passing.

Notes:

- This is the first point where Module 1 can operate across scan windows instead of only inside unit tests.
- Baseline learning is intentionally explicit because silent auto-learning is dangerous in an Evil Twin detector: an attack-period capture could otherwise become trusted state.

## 2026-05-07 — Etap 2 Module 1A, Simultaneous Duplicate BSSID Detection

- Added `DuplicateBSSIDDetector` as a second `identity_verification` signal source.
- Implemented the first deterministic duplicate-BSSID heuristic:
  - keep rolling same-BSSID AP TSF samples,
  - fit one global TSF vs local-time regression,
  - split residuals at the largest gap,
  - require minimum sample counts in both clusters,
  - require at least one independent confirmation signal before alerting.
- Added duplicate-BSSID identity signals:
  - `duplicate_bssid_residual_clusters`,
  - `duplicate_bssid_clock_profile_split`,
  - `duplicate_bssid_sequence_interleaving`,
  - `duplicate_bssid_rssi_split`,
  - `duplicate_bssid_ie_split`.
- Wired duplicate-BSSID alerts into:
  - live `wiguard-scan --features --json`,
  - offline `wiguard-analyze-pcap`,
  - `identity_alerts`,
  - dedicated `duplicate_bssid_alerts`,
  - `CorrelationEngine` as `identity_verification` evidence.
- Added CLI/analyzer thresholds:
  - `--duplicate-min-samples`,
  - `--duplicate-min-cluster-samples`,
  - `--duplicate-residual-gap-us`.
- Added default duplicate-BSSID thresholds under `detection.identity.duplicate_bssid` in `config.yaml`.
- Added unit coverage for:
  - a clean single-AP clock trend staying quiet,
  - two simultaneous same-BSSID transmitters producing residual, clock, sequence, RSSI, and IE split signals,
  - too few samples staying quiet,
  - too-small residual clusters staying quiet.
- Validated offline analyzer on `/tmp/wiguard_alfa_beacons.pcap`: 10 packets, 10 feature vectors, 0 management frames, 0 identity alerts, 0 duplicate-BSSID alerts, 0 deauth/environment/correlated alerts.
- Validated live feature scan with `sudo .venv/bin/wiguard-scan --duration 4 --dwell 2 --channels 1 --features --min-clock-samples 5 --json`:
  - 84 packets,
  - 84 AP observations,
  - 5 feature AP profiles,
  - 0 identity alerts,
  - 0 duplicate-BSSID alerts,
  - 0 deauth/environment/correlated alerts.
- Confirmed after the live run that `wlo1` stayed connected to `UPC257567143` and Alfa `wlx00c0cab6d8f3` returned to `managed` / disconnected.
- Test status after this stage: `30` tests passing.

Notes:

- The implementation intentionally avoids SciPy/HDBSCAN/Hartigan dip test for now. The v1 detector is dependency-light and explainable, which is better for the first reliable product slice.
- The detector is conservative: residual clustering alone is not enough; it must be confirmed by another physical or frame-level signal.

## 2026-05-07 — Etap 2B, Detection Evaluation Harness & Curated Fixtures

- Added a reusable offline `analyze_pcap` pipeline so CLI analysis, tests, and evaluation use the same detector path.
- Added `wiguard-generate-fixtures` for safe synthetic Scapy PCAP generation.
- Added `wiguard-evaluate-fixtures` for repeatable detector evaluation from a JSON manifest.
- Added schema-versioned fixture manifests with:
  - scenario name,
  - relative pcap path,
  - expected classification,
  - expected modules,
  - expected signals,
  - source and limitations notes.
- Added curated synthetic fixtures for:
  - clean single AP,
  - duplicate BSSID with two clock profiles,
  - same-SSID environment outlier,
  - broadcast deauth burst,
  - correlated duplicate BSSID plus deauth storm.
- Added evaluation output with per-scenario pass/fail status, observed classification, observed modules, observed signals, missing modules, missing signals, and alert counts.
- The harness exposed a real correlation bug: repeated alerts from the same module could stack into an artificially high final score.
- Fixed correlation scoring by deduplicating events per BSSID/module before final score calculation.
- Added tests for:
  - manifest parsing and required-field validation,
  - generated synthetic PCAP existence,
  - full synthetic fixture evaluation,
  - correlation deduplication for repeated same-module alerts.
- Generated committed synthetic fixtures under `tests/pcap_fixtures/synthetic/`.
- Validated fixture benchmark with `wiguard-evaluate-fixtures tests/pcap_fixtures/synthetic/manifest.json`: 5 scenarios, 5 passed, 0 failed.
- Validated local real clean smoke manifest against `/tmp/wiguard_alfa_beacons.pcap`: 1 scenario, 1 passed, observed `clean`, 0 raw alerts, 0 correlated alerts.
- Test status after this stage: `35` tests passing.

Notes:

- Synthetic fixtures validate detector logic and regression behavior, not RF realism.
- Raw real-world pcaps should not be committed without sanitization and written provenance.
- This harness is now the foundation for Etap 5 experiments: detection rate, false-positive analysis, and ablation.

## 2026-05-07 — Etap 2C, Long-Running Sensor Core & Persistent Alert Timeline

- Added a SQLite-backed runtime store at `.wiguard/wiguard.db` for production-style local state.
- Added persistent tables for:
  - AP snapshots,
  - raw detection events,
  - correlated alert lifecycle rows,
  - timeline events.
- Added idempotent schema initialization with an explicit runtime schema version.
- Added `wiguard-sensor` as the first long-running passive sensor command.
- The sensor uses the existing safe capture path and existing detection modules:
  - Alfa interface for monitor capture,
  - internal `wlo1` remains protected,
  - no association, injection, deauth, or active verification.
- Added runtime alert lifecycle metadata:
  - `first_seen`,
  - `last_seen`,
  - `count`,
  - `status`,
  - cooldown-aware deduplication for repeated correlated alerts.
- Added a runtime evidence window so management-frame bursts expire from live correlation instead of persisting forever.
- Added JSON-lines flush output through `--json-events` for future API/dashboard integration.
- Added runtime defaults to `config.yaml`:
  - `runtime.state_path`,
  - `runtime.flush_interval_seconds`,
  - `runtime.alert_cooldown_seconds`,
  - `runtime.window_seconds`.
- Added tests for:
  - idempotent SQLite schema initialization,
  - AP snapshot upsert semantics,
  - raw detection event persistence,
  - correlated alert lifecycle deduplication,
  - replaying suspicious synthetic fixtures into runtime state,
  - clean fixture replay without correlated false positives.
- Validated unit/integration suite: `41` tests passing.
- Validated fixture benchmark with `wiguard-evaluate-fixtures tests/pcap_fixtures/synthetic/manifest.json`: 5 scenarios, 5 passed, 0 failed.
- Validated `wiguard-sensor --help` after refreshing the editable venv install.
- Validated live sensor smoke with `sudo .venv/bin/wiguard-sensor --duration 4 --dwell 1 --channels 1 --state-path /tmp/wiguard_sensor_smoke.db --flush-interval 1 --runtime-window 30 --min-clock-samples 5 --quiet`:
  - 56 packets,
  - 56 AP observations,
  - 5 AP snapshots persisted,
  - 0 raw detection events,
  - 0 correlated alerts,
  - 0 timeline events.
- Confirmed after the live run that `wlo1` stayed connected to `UPC257567143` and Alfa `wlx00c0cab6d8f3` returned to `managed` / disconnected.

Notes:

- This stage turns WiGuard from a scan/analyze prototype into a service-ready sensor core.
- The dashboard/API should read from this runtime state instead of invoking detectors directly.
- Active Verification remains intentionally postponed until the hardware/safety model is expanded.
