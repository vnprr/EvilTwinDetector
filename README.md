# WiGuard

WiGuard is a **passive, evidence-based Evil Twin detector prototype**. The current `main` includes monitor-mode capture, 802.11 feature extraction, identity and duplicate-BSSID signals, deauth/disassociation detection, same-SSID environment comparison, alert correlation, a persistent sensor, a read-only FastAPI API, and a basic React Blue dashboard.

**Status (26 October 2026):** the code last underwent documented local validation on 7 May 2026. Those historical test results must be rerun. A Red Team lab dashboard, automated real-RF experiments, active DHCP/DNS verification and ML are **not currently implemented on `main`**. No remote `claude/*` branch or pull request is available for merge.

## Current project documents

- [Implementation status and Red/Blue execution backlog](docs/PROJECT-ROADMAP.md) — **current operational plan**
- [Engineering thesis outline and experimental methodology](docs/THESIS-PLAN.md) — **current thesis plan**
- [Claude repo audit and testing prompt](docs/CLAUDE-REPO-AUDIT.md) — a runnable audit checklist
- [Historical May 2026 development log](wiguard-dev-log.md)
- [Historical project concept (v2)](wiguard-plan-v2.md) — **not a checklist of shipped features**

The goal is a defensible engineering thesis: rigorously tested passive detection plus a **separate, controlled Red/Blue laboratory**, not an uncontrolled network disruption toolkit. The Red side must be disabled by default and bound to authorized laboratory hardware.

## Current Hardware Decision

- Capture adapter: `wlx00c0cab6d8f3` / Alfa RTL8812AU
- Driver: kernel `rtw88_8812au`
- Internal Wi-Fi: `wlo1`, left connected and untouched
- Working mode: direct monitor mode on `wlx00c0cab6d8f3`
- Avoid: `airmon-ng check kill`

The hardware validation report lives in `docs/hardware/alfa-rtl8812au.md`.

## Run A Passive Scan

```bash
source .venv/bin/activate
sudo .venv/bin/wiguard-scan --duration 20 --dwell 0.5
```

For machine-readable output:

```bash
sudo .venv/bin/wiguard-scan --duration 20 --json
```

For feature-level summaries during live capture:

```bash
sudo .venv/bin/wiguard-scan --duration 20 --features --json
```

To learn a trusted identity baseline from a known-good passive scan:

```bash
sudo .venv/bin/wiguard-scan --duration 60 --features --identity-baseline .wiguard/identity-baselines.json --identity-learn --json
```

To monitor later scans against that trusted baseline:

```bash
sudo .venv/bin/wiguard-scan --duration 20 --features --identity-baseline .wiguard/identity-baselines.json --json
```

The JSON output contains capture metrics plus the aggregated AP state:

```json
{
  "capture": {
    "channels_attempted": 3,
    "channels_tuned": 3,
    "channel_errors": [],
    "packets_seen": 175,
    "observations_seen": 166
  },
  "access_points": [
    {
      "ssid": "ExampleNet",
      "bssid": "aa:bb:cc:dd:ee:ff",
      "channels": [1],
      "frames": 42,
      "last_rssi_dbm": -45,
      "clock_samples": 42
    }
  ]
}
```

The scan is passive. It does not associate, deauthenticate, inject frames, or touch the internal Wi-Fi adapter.

## Run The Sensor Runtime

`wiguard-sensor` is the first long-running runtime mode. It uses the same passive capture and detection pipeline as `wiguard-scan`, then persists AP snapshots, raw detection events, correlated alerts, and timeline events to SQLite.

```bash
sudo .venv/bin/wiguard-sensor --duration 300 --state-path .wiguard/wiguard.db
```

For machine-readable operational output, emit one JSON line per flush:

```bash
sudo .venv/bin/wiguard-sensor --duration 300 --json-events --quiet
```

Important runtime defaults:

- state database: `.wiguard/wiguard.db`
- flush interval: `5` seconds
- correlated alert cooldown: `300` seconds
- runtime correlation window: `300` seconds
- runtime state remains local and ignored by Git

The sensor is still passive. It uses the Alfa adapter for monitor-mode capture, restores it on exit, and keeps `wlo1` as the protected internet interface.

## Run The Runtime API

`wiguard-api` exposes a local read-only FastAPI backend over the SQLite runtime state produced by `wiguard-sensor`.

```bash
.venv/bin/wiguard-api --state-path .wiguard/wiguard.db --host 127.0.0.1 --port 8765
```

Useful endpoints:

- `GET /api/health`
- `GET /api/aps`
- `GET /api/aps/{bssid}`
- `GET /api/aps/{bssid}/timeline`
- `GET /api/alerts`
- `GET /api/alerts/{alert_key}`
- `GET /api/events`
- `GET /api/timeline`
- `GET /api/stats`
- `WS /ws/live`

The API does not start active verification, change thresholds, or touch Wi-Fi interfaces. It only reads persisted runtime state and initializes an empty schema if the database does not exist yet.

## Run The Operator Dashboard

The dashboard is a read-only React operator console backed by `wiguard-api`.

```bash
cd dashboard
npm install
npm run dev -- --host 127.0.0.1
```

The frontend reads `VITE_WIGUARD_API_BASE`, defaulting to `http://127.0.0.1:8765`. For a local demo with synthetic data:

```bash
.venv/bin/python experiments/create_dashboard_demo_db.py --output /tmp/wiguard_dashboard_demo.db
.venv/bin/wiguard-api --state-path /tmp/wiguard_dashboard_demo.db --host 127.0.0.1 --port 8765
```

Then open the Vite URL from `npm run dev`. The first screen is the operator dashboard: AP overview, alert inspection, AP detail, and live activity timeline.

## Analyze A PCAP

Use the offline analyzer for repeatable feature extraction on saved captures:

```bash
.venv/bin/wiguard-analyze-pcap /tmp/wiguard_alfa_beacons.pcap --min-clock-samples 3
```

It extracts:

- IE sequence signatures and stable SHA-256 IE fingerprint hashes
- Vendor OUIs from vendor-specific IE `221`
- RSSI statistics, beacon timing jitter, and sequence-number continuity
- Clock-skew regression when enough TSF samples exist
- Deauthentication and disassociation counters
- Same-SSID environment anomaly signals from peer comparison

## Evaluate Fixtures

Generate safe synthetic fixtures and run the repeatable detector benchmark:

```bash
wiguard-generate-fixtures tests/pcap_fixtures/synthetic
wiguard-evaluate-fixtures tests/pcap_fixtures/synthetic/manifest.json
```

The evaluation report checks expected classifications, modules, and signal names for clean and Evil-Twin-like scenarios. Synthetic fixtures are safe Scapy-generated management frames; raw real-world pcaps should stay outside Git unless they are explicitly sanitized.

## Detection Foundation

The first detection module is `APIdentityVerifier`. It compares a stable per-BSSID baseline against later AP feature summaries and emits explainable signals for:

- IE fingerprint changes
- clock-skew changes beyond a ppm threshold
- strong RSSI profile shifts
- sequence-number resets/backward jumps
- simultaneous duplicate-BSSID residual clusters

Trusted baselines are explicit. Use `--identity-learn` only during a known-good capture; monitor mode does not auto-learn unknown BSSIDs. This avoids silently trusting a suspicious AP seen during an attack window.

`DuplicateBSSIDDetector` is part of identity verification. It uses rolling AP TSF samples to find two residual clusters for one BSSID and requires confirmation from clock profile, sequence interleaving, RSSI split, or IE fingerprint split before alerting.

The second detection module is `DeauthStormDetector`. It consumes management-frame counters and emits explainable signals for:

- high deauthentication/disassociation frame rates
- broadcast deauth floods
- targeted unicast bursts

The third detection module is `EnvironmentAnomalyDetector`. It compares APs that advertise the same SSID and emits conservative peer-comparison signals for:

- IE fingerprint minority profiles
- vendor OUI outliers
- IE element shape outliers
- beacon interval outliers

`CorrelationEngine` combines raw module alerts per BSSID and emits deduplicated `correlated_alerts` with:

- final score from weighted module evidence
- classification: `info`, `suspicious`, or `evil_twin`
- contributing modules
- a short human-readable explanation

Live feature scans and pcap analysis include `deauth_alerts`, `identity_alerts`, `duplicate_bssid_alerts`, `environment_alerts`, and `correlated_alerts` in JSON output.

## Development

```bash
source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests
```
