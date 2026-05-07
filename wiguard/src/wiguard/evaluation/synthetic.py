"""Generate safe synthetic WiGuard evaluation fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scapy.all import wrpcap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap


def write_synthetic_fixtures(output_dir: Path | str) -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    scenarios = [
        _write_clean_single_ap(output),
        _write_duplicate_bssid(output),
        _write_environment_outlier(output),
        _write_deauth_burst(output),
        _write_correlated_duplicate_deauth(output),
    ]
    manifest = {
        "schema_version": 1,
        "scenarios": scenarios,
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def _write_clean_single_ap(output: Path) -> dict[str, object]:
    pcap = output / "clean_single_ap.pcap"
    packets = [
        _beacon(
            bssid="00:11:22:33:44:55",
            ssid="CleanNet",
            sequence=index,
            observed_time=1.0 + index * 0.1024,
            ap_tsf=1_000_000 + index * 102_400,
            rssi_dbm=-42,
            vendor_oui="001122",
        )
        for index in range(40)
    ]
    wrpcap(str(pcap), packets)
    return _scenario(
        name="clean_single_ap",
        pcap=pcap.name,
        expected_classification="clean",
        description="One stable AP beacon stream with one clock profile.",
        expected_modules=[],
        expected_signals=[],
    )


def _write_duplicate_bssid(output: Path) -> dict[str, object]:
    pcap = output / "duplicate_bssid_clock_split.pcap"
    packets = []
    for index in range(20):
        packets.append(
            _beacon(
                bssid="aa:bb:cc:dd:ee:ff",
                ssid="TwinNet",
                sequence=100 + index,
                observed_time=2.0 + index * 0.2048,
                ap_tsf=2_000_000 + index * 204_800,
                rssi_dbm=-40,
                vendor_oui="001122",
            )
        )
        packets.append(
            _beacon(
                bssid="aa:bb:cc:dd:ee:ff",
                ssid="TwinNet",
                sequence=500 + index,
                observed_time=2.1024 + index * 0.2048,
                ap_tsf=2_102_400 + index * 204_800 + 60_000,
                rssi_dbm=-66,
                vendor_oui="aabbcc",
                supported_rates=b"\x8c\x12\x98",
            )
        )
    wrpcap(str(pcap), packets)
    return _scenario(
        name="duplicate_bssid_clock_split",
        pcap=pcap.name,
        expected_classification="suspicious",
        description="Two simultaneous transmitters reuse one BSSID with separated TSF residual clusters.",
        expected_modules=["identity_verification"],
        expected_signals=[
            "duplicate_bssid_residual_clusters",
            "duplicate_bssid_clock_profile_split",
        ],
    )


def _write_environment_outlier(output: Path) -> dict[str, object]:
    pcap = output / "environment_same_ssid_outlier.pcap"
    packets = []
    for index in range(8):
        packets.append(
            _beacon(
                bssid="00:11:22:33:44:01",
                ssid="CorpNet",
                sequence=100 + index,
                observed_time=10.0 + index * 0.3,
                ap_tsf=10_000_000 + index * 102_400,
                rssi_dbm=-41,
                vendor_oui="001122",
            )
        )
        packets.append(
            _beacon(
                bssid="00:11:22:33:44:02",
                ssid="CorpNet",
                sequence=200 + index,
                observed_time=10.1 + index * 0.3,
                ap_tsf=20_000_000 + index * 102_400,
                rssi_dbm=-45,
                vendor_oui="001122",
            )
        )
        packets.append(
            _beacon(
                bssid="aa:bb:cc:dd:ee:99",
                ssid="CorpNet",
                sequence=300 + index,
                observed_time=10.2 + index * 0.3,
                ap_tsf=30_000_000 + index * 102_400,
                rssi_dbm=-55,
                vendor_oui="aabbcc",
                supported_rates=b"\x8c\x12\x98",
            )
        )
    wrpcap(str(pcap), packets)
    return _scenario(
        name="environment_same_ssid_outlier",
        pcap=pcap.name,
        expected_classification="suspicious",
        description="One same-SSID AP has a minority IE/vendor profile among two peer APs.",
        expected_modules=["environment_anomaly"],
        expected_signals=["same_ssid_ie_fingerprint_outlier"],
    )


def _write_deauth_burst(output: Path) -> dict[str, object]:
    pcap = output / "deauth_burst.pcap"
    packets = [
        _deauth(
            bssid="de:ad:be:ef:00:01",
            observed_time=20.0 + index * 0.02,
        )
        for index in range(120)
    ]
    wrpcap(str(pcap), packets)
    return _scenario(
        name="deauth_burst",
        pcap=pcap.name,
        expected_classification="suspicious",
        description="Broadcast deauthentication burst from one spoofed BSSID.",
        expected_modules=["deauth_storm"],
        expected_signals=["management_frame_rate_high", "broadcast_flood"],
    )


def _write_correlated_duplicate_deauth(output: Path) -> dict[str, object]:
    pcap = output / "correlated_duplicate_deauth.pcap"
    packets = []
    for index in range(20):
        packets.append(
            _beacon(
                bssid="ca:fe:00:00:00:01",
                ssid="TargetNet",
                sequence=100 + index,
                observed_time=30.0 + index * 0.2048,
                ap_tsf=30_000_000 + index * 204_800,
                rssi_dbm=-39,
                vendor_oui="001122",
            )
        )
        packets.append(
            _beacon(
                bssid="ca:fe:00:00:00:01",
                ssid="TargetNet",
                sequence=600 + index,
                observed_time=30.1024 + index * 0.2048,
                ap_tsf=30_102_400 + index * 204_800 + 70_000,
                rssi_dbm=-68,
                vendor_oui="aabbcc",
                supported_rates=b"\x8c\x12\x98",
            )
        )
    packets.extend(
        _deauth(
            bssid="ca:fe:00:00:00:01",
            observed_time=35.0 + index * 0.02,
        )
        for index in range(120)
    )
    wrpcap(str(pcap), packets)
    return _scenario(
        name="correlated_duplicate_deauth",
        pcap=pcap.name,
        expected_classification="evil_twin",
        description="Duplicate-BSSID evidence appears together with broadcast deauth storm evidence.",
        expected_modules=["identity_verification", "deauth_storm"],
        expected_signals=["duplicate_bssid_residual_clusters", "broadcast_flood"],
    )


def _beacon(
    *,
    bssid: str,
    ssid: str,
    sequence: int,
    observed_time: float,
    ap_tsf: int,
    rssi_dbm: int,
    vendor_oui: str,
    supported_rates: bytes = b"\x82\x84\x8b\x96",
    channel: int = 1,
):
    packet = (
        RadioTap(
            dBm_AntSignal=rssi_dbm,
            mac_timestamp=ap_tsf,
            ChannelFrequency=2412,
        )
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
            SC=(sequence % 4096) << 4,
        )
        / Dot11Beacon(timestamp=ap_tsf, beacon_interval=100, cap=0x0411)
        / Dot11Elt(ID=0, info=ssid.encode("utf-8"))
        / Dot11Elt(ID=1, info=supported_rates)
        / Dot11Elt(ID=3, info=bytes([channel]))
        / Dot11Elt(ID=48, info=b"\x01\x00\x00\x0f\xac\x04")
        / Dot11Elt(ID=221, info=bytes.fromhex(vendor_oui) + b"\x01\x02\x03")
    )
    packet.time = observed_time
    return packet


def _deauth(*, bssid: str, observed_time: float):
    packet = (
        RadioTap(ChannelFrequency=2412)
        / Dot11(
            type=0,
            subtype=12,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Deauth(reason=7)
    )
    packet.time = observed_time
    return packet


def _scenario(
    *,
    name: str,
    pcap: str,
    expected_classification: str,
    description: str,
    expected_modules: list[str],
    expected_signals: list[str],
) -> dict[str, object]:
    return {
        "name": name,
        "pcap": pcap,
        "expected_classification": expected_classification,
        "expected_modules": expected_modules,
        "expected_signals": expected_signals,
        "description": description,
        "source": "synthetic Scapy fixture generated by WiGuard",
        "limitations": "Synthetic 802.11 management frames validate detector logic, not RF realism.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate WiGuard synthetic evaluation fixtures")
    parser.add_argument("output_dir", type=Path, help="directory for generated pcaps and manifest")
    args = parser.parse_args(argv)
    manifest = write_synthetic_fixtures(args.output_dir)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
