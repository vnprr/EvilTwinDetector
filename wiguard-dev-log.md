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
- Initialized a Git repository on branch `main`; no commit created yet.
