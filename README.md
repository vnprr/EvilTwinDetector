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

## Development

```bash
source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests
```
