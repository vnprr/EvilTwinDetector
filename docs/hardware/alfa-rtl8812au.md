# Alfa RTL8812AU Hardware Report

Status: PASS for Etap 0A. Alfa captures 802.11 beacon frames in monitor mode with RadioTap, AP TSF, RSSI, and RadioTap TSFT while the internal `wlo1` connection stays up.

## Host

- OS: Pop!_OS / Ubuntu 24.04 base
- Kernel: `6.18.7-76061807-generic`
- Internal Wi-Fi: `wlo1`
- Internal Wi-Fi state: connected to `UPC257567143`
- Safety constraint: do not run `airmon-ng check kill`; do not change `wlo1`

## Alfa Adapter

- USB ID: `0bda:8812`
- Device: Realtek RTL8812AU 802.11a/b/g/n/ac 2T2R DB WLAN Adapter
- Vendor database: Realtek Semiconductor Corp.
- OUI database for MAC: ALFA, INC.
- USB product string: `802.11n NIC`
- USB serial: `123456`
- USB bus power: 800 mA max
- Interface: `wlx00c0cab6d8f3`
- MAC: `00:c0:ca:b6:d8:f3`
- Interface state before monitor tests: `DOWN`, disconnected
- PHY observed initially: `phy9`
- PHY observed after reconnect/tool install: `phy13`
- Driver: `rtw88_8812au`
- Driver path: `/sys/bus/usb/drivers/rtw88_8812au`
- Firmware: `52.14.0`, H2C version `0`

## Tooling State

- Present after install: `iw`, `aircrack-ng`, `tcpdump`, `.venv` with Scapy
- Missing before privileged install: `iw`, `aircrack-ng`, `python3-pip`, `python3-venv`, `libpcap-dev`
- Python: `3.12.3`
- Virtualenv Python: `.venv/bin/python`
- Scapy in virtualenv: `2.7.0`

Install command prepared in `experiments/install_alfa_tools.sh`.

## Kernel Notes

The current kernel driver attaches successfully, but the boot log contains repeated early USB/register errors:

- `read register 0x5 failed with -71`
- `write register 0x5 failed with -110`

This makes `rtw88_8812au` worth testing first, but it also justifies a fallback to `aircrack-ng/rtl8812au` DKMS if monitor mode, RadioTap, TSF, or stability fails.

## Monitor Mode / TSF / RadioTap Test

Preflight completed successfully with `.venv/bin/python`:

```json
{
  "ok": true,
  "phase": "preflight",
  "preflight": {
    "alfa_iface": "wlx00c0cab6d8f3",
    "alfa_present": true,
    "alfa_phy": "phy13",
    "alfa_driver": "rtw88_8812au",
    "internal_iface": "wlo1",
    "internal_connected": true,
    "missing": []
  }
}
```

`iw list` confirms `monitor` in supported interface modes for the Alfa PHY.

First privileged run from the user terminal completed safely but did not capture frames:

- Started: `2026-05-07T17:13:13+0200`
- Preferred monitor interface: `wiguardmon0`
- Direct fallback in that run: `false`
- Channels scanned: `0`
- Beacons captured: `0`
- PCAP: none
- Internal Wi-Fi after run: connected

The test script was updated after this result to record per-channel tuning errors and automatically fall back to direct monitor mode on `wlx00c0cab6d8f3` when `wiguardmon0` cannot tune any channel.

Successful privileged run:

- Started: `2026-05-07T17:39:33+0200`
- Result JSON: `/tmp/wiguard_alfa_monitor_tsf_check.json`
- PCAP: `/tmp/wiguard_alfa_beacons.pcap`
- Preferred monitor interface: `wiguardmon0`
- Preferred result: failed to tune channels with `Device or resource busy (-16)`
- Working capture interface: `wlx00c0cab6d8f3`
- Direct fallback used: `true`
- Channels scanned before hitting sample limit: `1`
- Beacons captured: `30`
- RadioTap present: `30/30`
- Dot11 beacon present: `30/30`
- Beacon/AP TSF present: `30/30`
- RadioTap TSFT present: `30/30`
- BSSIDs observed: `20:b8:2b:14:0f:99`, `48:bd:ce:7a:1f:79`, `ac:f8:cc:c9:d9:18`, `b0:4e:26:2b:52:f2`
- Internal Wi-Fi after run: `wlo1` still connected to `UPC257567143`
- Alfa after run: restored to `managed`, disconnected

Re-run command:

```bash
experiments/run_alfa_monitor_tsf_check.sh --dwell-seconds 2 --max-beacons 30
```

Confirmed successful result:

- `internal_wifi_still_connected: true`
- `radiotap_present: true`
- `dot11_beacon_present: true`
- `beacon_tsf_present: true`
- `radiotap_tsf_present: true`
- captured pcap at `/tmp/wiguard_alfa_beacons.pcap`

Important distinction: `beacon_tsf_present` is the AP TSF timestamp from the 802.11 beacon body and is required for clock-skew estimation. `radiotap_tsf_present` is the receiver-side RadioTap TSFT and depends on driver support.

## Current Decision

Continue with the kernel `rtw88_8812au` driver for the first detector prototype. Use direct monitor mode on `wlx00c0cab6d8f3`; do not rely on a simultaneous `wiguardmon0` interface with this driver because channel tuning returns `Device or resource busy (-16)`.

Switch to `aircrack-ng/rtl8812au` DKMS only if later channel-hopping or long-running captures show instability, missing RadioTap/TSF fields, or repeated adapter resets.
