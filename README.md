# WiGuard

WiGuard is a passive Evil Twin access point detector prototype. The current milestone is the capture foundation: use the external Alfa RTL8812AU adapter in monitor mode, preserve the laptop's internal Wi-Fi connection, parse 802.11 management frames, and expose AP observations with RadioTap, RSSI, channel, and TSF data.

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

## Detection Foundation

The first detection module is `APIdentityVerifier`. It compares a stable per-BSSID baseline against later AP feature summaries and emits explainable signals for:

- IE fingerprint changes
- clock-skew changes beyond a ppm threshold
- strong RSSI profile shifts
- sequence-number resets/backward jumps

Trusted baselines are explicit. Use `--identity-learn` only during a known-good capture; monitor mode does not auto-learn unknown BSSIDs. This avoids silently trusting a suspicious AP seen during an attack window.

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

Live feature scans and pcap analysis include `deauth_alerts`, `environment_alerts`, and `correlated_alerts` in JSON output.

## Development

```bash
source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests
```
