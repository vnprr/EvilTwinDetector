#!/usr/bin/env python3
"""Passive monitor-mode and TSF check for the Alfa RTL8812AU adapter.

The script intentionally targets only the external Alfa adapter. It never
changes the internal Wi-Fi interface used for the active internet connection.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ALFA_IFACE = "wlx00c0cab6d8f3"
INTERNAL_IFACE = "wlo1"
MON_IFACE = "wiguardmon0"
PCAP_PATH = Path("/tmp/wiguard_alfa_beacons.pcap")
CHANNELS = [
    1,
    6,
    11,
    13,
    36,
    40,
    44,
    48,
    52,
    56,
    60,
    64,
    100,
    104,
    108,
    112,
    116,
    120,
    124,
    128,
    132,
    136,
    140,
    144,
    149,
    153,
    157,
    161,
    165,
]


@dataclass
class BeaconSample:
    ssid: str
    bssid: str | None
    channel: int | None
    rssi_dbm: int | None
    beacon_tsf: int | None
    radiotap_tsf: int | None


def run(argv: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=check)


def command_path(name: str) -> str | None:
    return shutil.which(name)


def readlink(path: Path) -> str | None:
    try:
        return os.path.basename(os.path.realpath(path))
    except OSError:
        return None


def nmcli_status() -> list[dict[str, str]]:
    if not command_path("nmcli"):
        return []
    result = run(
        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
        check=False,
    )
    devices = []
    for line in result.stdout.splitlines():
        parts = line.split(":", 3)
        if len(parts) == 4:
            devices.append(
                {
                    "device": parts[0],
                    "type": parts[1],
                    "state": parts[2],
                    "connection": parts[3],
                }
            )
    return devices


def internal_wifi_connected() -> bool:
    return any(
        dev["device"] == INTERNAL_IFACE and dev["state"] == "connected"
        for dev in nmcli_status()
    )


def phy_for_iface(iface: str) -> str | None:
    return readlink(Path("/sys/class/net") / iface / "phy80211")


def driver_for_iface(iface: str) -> str | None:
    return readlink(Path("/sys/class/net") / iface / "device" / "driver")


def iface_exists(iface: str) -> bool:
    return (Path("/sys/class/net") / iface).exists()


def require_preflight() -> dict[str, Any]:
    missing = [
        tool
        for tool in ("iw", "ip", "tcpdump")
        if command_path(tool) is None
    ]
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        missing.append("python package scapy")

    status = {
        "alfa_iface": ALFA_IFACE,
        "alfa_present": iface_exists(ALFA_IFACE),
        "alfa_phy": phy_for_iface(ALFA_IFACE),
        "alfa_driver": driver_for_iface(ALFA_IFACE),
        "internal_iface": INTERNAL_IFACE,
        "internal_connected": internal_wifi_connected(),
        "missing": missing,
    }
    if missing:
        raise RuntimeError(f"Missing dependencies: {', '.join(missing)}")
    if not status["alfa_present"]:
        raise RuntimeError(f"Alfa interface {ALFA_IFACE} is not present")
    if not status["internal_connected"]:
        raise RuntimeError(f"Internal Wi-Fi {INTERNAL_IFACE} is not connected")
    return status


def cleanup_monitor(mon_iface: str) -> None:
    if iface_exists(mon_iface):
        run(["ip", "link", "set", mon_iface, "down"], check=False)
        run(["iw", "dev", mon_iface, "del"], check=False)


def create_monitor_on_phy(phy: str, mon_iface: str) -> str:
    cleanup_monitor(mon_iface)
    run(["iw", "phy", phy, "interface", "add", mon_iface, "type", "monitor"])
    run(["ip", "link", "set", mon_iface, "up"])
    return mon_iface


def direct_monitor_fallback(iface: str) -> str:
    run(["ip", "link", "set", iface, "down"], check=False)
    run(["iw", "dev", iface, "set", "type", "monitor"])
    run(["ip", "link", "set", iface, "up"])
    return iface


def restore_direct_fallback(iface: str) -> None:
    if iface_exists(iface):
        run(["ip", "link", "set", iface, "down"], check=False)
        run(["iw", "dev", iface, "set", "type", "managed"], check=False)
        run(["ip", "link", "set", iface, "up"], check=False)


def dot11_elt_info(packet: Any, elt_id: int) -> bytes | None:
    from scapy.layers.dot11 import Dot11Elt

    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == elt_id:
            return bytes(getattr(elt, "info", b""))
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def decode_ssid(raw: bytes | None) -> str:
    if not raw:
        return "<hidden>"
    return raw.decode("utf-8", errors="replace")


def decode_channel(raw: bytes | None) -> int | None:
    if not raw:
        return None
    return raw[0]


def radiotap_tsf(packet: Any) -> int | None:
    from scapy.layers.dot11 import RadioTap

    fields = packet[RadioTap].fields
    for key in ("mac_timestamp", "timestamp", "TSFT"):
        value = fields.get(key)
        if isinstance(value, int):
            return value
    return None


def capture_beacons(
    iface: str,
    dwell_seconds: float,
    max_beacons: int,
) -> tuple[list[BeaconSample], int, list[dict[str, str | int]]]:
    from scapy.all import sniff, wrpcap
    from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap

    samples: list[BeaconSample] = []
    packets = []
    seen_channels = 0
    channel_errors: list[dict[str, str | int]] = []

    for channel in CHANNELS:
        set_channel = run(["iw", "dev", iface, "set", "channel", str(channel)], check=False)
        if set_channel.returncode != 0:
            channel_errors.append(
                {
                    "channel": channel,
                    "returncode": set_channel.returncode,
                    "stderr": set_channel.stderr.strip(),
                    "stdout": set_channel.stdout.strip(),
                }
            )
            continue
        seen_channels += 1
        batch = sniff(iface=iface, timeout=dwell_seconds, store=True)
        for packet in batch:
            if not (packet.haslayer(RadioTap) and packet.haslayer(Dot11) and packet.haslayer(Dot11Beacon)):
                continue
            packets.append(packet)
            sample = BeaconSample(
                ssid=decode_ssid(dot11_elt_info(packet, 0)),
                bssid=getattr(packet[Dot11], "addr3", None),
                channel=decode_channel(dot11_elt_info(packet, 3)) or channel,
                rssi_dbm=getattr(packet[RadioTap], "dBm_AntSignal", None),
                beacon_tsf=getattr(packet[Dot11Beacon], "timestamp", None),
                radiotap_tsf=radiotap_tsf(packet),
            )
            samples.append(sample)
            if len(samples) >= max_beacons:
                wrpcap(str(PCAP_PATH), packets)
                return samples, seen_channels, channel_errors

    if packets:
        wrpcap(str(PCAP_PATH), packets)
    return samples, seen_channels, channel_errors


def monitor_summary() -> str:
    if not command_path("iw"):
        return ""
    return run(["iw", "dev"], check=False).stdout


def scan_with_preferred_then_fallback(args: argparse.Namespace, preflight: dict[str, Any]) -> dict[str, Any]:
    capture_iface = create_monitor_on_phy(str(preflight["alfa_phy"]), MON_IFACE)
    samples, channels_scanned, channel_errors = capture_beacons(
        capture_iface,
        dwell_seconds=args.dwell_seconds,
        max_beacons=args.max_beacons,
    )
    result = {
        "capture_iface": capture_iface,
        "used_direct_fallback": False,
        "channels_scanned": channels_scanned,
        "channel_errors": channel_errors[:20],
        "preferred_capture_iface": capture_iface,
        "preferred_channels_scanned": channels_scanned,
        "preferred_channel_errors": channel_errors[:20],
        "samples": samples,
        "monitor_summary_after_attempt": monitor_summary(),
    }
    if channels_scanned > 0:
        return result

    cleanup_monitor(MON_IFACE)
    capture_iface = direct_monitor_fallback(ALFA_IFACE)
    samples, channels_scanned, channel_errors = capture_beacons(
        capture_iface,
        dwell_seconds=args.dwell_seconds,
        max_beacons=args.max_beacons,
    )
    result.update(
        {
            "capture_iface": capture_iface,
            "used_direct_fallback": True,
            "channels_scanned": channels_scanned,
            "channel_errors": channel_errors[:20],
            "preferred_capture_iface": result["preferred_capture_iface"],
            "preferred_channels_scanned": result["preferred_channels_scanned"],
            "preferred_channel_errors": result["preferred_channel_errors"],
            "samples": samples,
            "direct_fallback_reason": "preferred monitor interface could not tune any configured channel",
            "monitor_summary_after_fallback": monitor_summary(),
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dwell-seconds", type=float, default=1.0)
    parser.add_argument("--max-beacons", type=int, default=25)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()

    started_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    try:
        preflight = require_preflight()
    except RuntimeError as exc:
        print(json.dumps({"ok": False, "phase": "preflight", "error": str(exc)}, indent=2))
        return 2

    if args.preflight_only:
        print(json.dumps({"ok": True, "phase": "preflight", "preflight": preflight}, indent=2))
        return 0

    if os.geteuid() != 0:
        print(json.dumps({"ok": False, "phase": "privileges", "error": "Run as root for monitor-mode capture"}, indent=2))
        return 3

    used_direct_fallback = False
    try:
        try:
            capture_result = scan_with_preferred_then_fallback(args, preflight)
            used_direct_fallback = bool(capture_result["used_direct_fallback"])
        except subprocess.CalledProcessError as exc:
            used_direct_fallback = True
            capture_iface = direct_monitor_fallback(ALFA_IFACE)
            preflight["preferred_monitor_error"] = exc.stderr.strip() or exc.stdout.strip()
            samples, channels_scanned, channel_errors = capture_beacons(
                capture_iface,
                dwell_seconds=args.dwell_seconds,
                max_beacons=args.max_beacons,
            )
            capture_result = {
                "capture_iface": capture_iface,
                "used_direct_fallback": used_direct_fallback,
                "channels_scanned": channels_scanned,
                "channel_errors": channel_errors[:20],
                "samples": samples,
                "direct_fallback_reason": "preferred monitor interface creation failed",
                "monitor_summary_after_fallback": monitor_summary(),
            }

        samples = capture_result["samples"]
        result = {
            "ok": bool(samples),
            "started_at": started_at,
            "capture_iface": capture_result["capture_iface"],
            "used_direct_fallback": capture_result["used_direct_fallback"],
            "direct_fallback_reason": capture_result.get("direct_fallback_reason"),
            "preferred_capture_iface": capture_result.get("preferred_capture_iface"),
            "preferred_channels_scanned": capture_result.get("preferred_channels_scanned"),
            "preferred_channel_errors": capture_result.get("preferred_channel_errors"),
            "pcap": str(PCAP_PATH) if samples else None,
            "channels_scanned": capture_result["channels_scanned"],
            "channel_errors": capture_result["channel_errors"],
            "beacons": len(samples),
            "radiotap_present": bool(samples),
            "dot11_beacon_present": bool(samples),
            "beacon_tsf_present": any(sample.beacon_tsf is not None for sample in samples),
            "radiotap_tsf_present": any(sample.radiotap_tsf is not None for sample in samples),
            "internal_wifi_still_connected": internal_wifi_connected(),
            "preflight": preflight,
            "monitor_summary_after_attempt": capture_result.get("monitor_summary_after_attempt"),
            "monitor_summary_after_fallback": capture_result.get("monitor_summary_after_fallback"),
            "samples": [asdict(sample) for sample in samples[:10]],
        }
        print(json.dumps(result, indent=2))
        return 0 if samples and result["internal_wifi_still_connected"] else 4
    finally:
        cleanup_monitor(MON_IFACE)
        if used_direct_fallback:
            restore_direct_fallback(ALFA_IFACE)


if __name__ == "__main__":
    raise SystemExit(main())
