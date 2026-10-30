"""Synthetic 802.11 captures for regression testing the detectors.

Each scenario is a small pcap of correctly formed beacon and deauthentication
frames (RadioTap with RSSI, channel and TSFT; real RSN and vendor elements),
plus a manifest entry describing the expected verdict. The frames are built
in memory with Scapy and written to files; nothing is transmitted.

These fixtures validate detector logic and catch regressions. They say
nothing about real radio conditions, which only RF experiments can show.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11EltRSN, RadioTap
from scapy.utils import wrpcap

from .fixtures import Manifest, Scenario

BROADCAST = "ff:ff:ff:ff:ff:ff"
START = 1_767_225_600.0  # 2026-01-01T00:00:00Z
TU_S = 1024e-6


@dataclass(frozen=True)
class SimulatedAP:
    bssid: str
    ssid: str
    channel: int = 6
    rssi_dbm: int = -45
    skew_ppm: float = 0.0
    tsf_offset_us: int = 5_000_000_000
    vendor_oui: bytes = b"\x00\x11\x22"
    rates: bytes = b"\x82\x84\x8b\x96\x0c\x12\x18\x24"
    beacon_interval_tu: int = 100

    def beacons(self, *, start: float, count: int, first_sequence: int = 0) -> list[Any]:
        interval = self.beacon_interval_tu * TU_S
        return [
            self.beacon(start + index * interval, sequence=first_sequence + index)
            for index in range(count)
        ]

    def beacon(self, at: float, *, sequence: int) -> Any:
        elapsed_us = (at - START) * 1_000_000.0
        tsf = int(self.tsf_offset_us + elapsed_us * (1.0 + self.skew_ppm / 1_000_000.0))
        packet = (
            _radiotap(self.channel, self.rssi_dbm, at)
            / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=self.bssid, addr3=self.bssid,
                    SC=(sequence % 4096) << 4)
            / Dot11Beacon(timestamp=tsf, beacon_interval=self.beacon_interval_tu, cap="ESS+privacy")
            / Dot11Elt(ID=0, info=self.ssid.encode())
            / Dot11Elt(ID=1, info=self.rates)
            / Dot11Elt(ID=3, info=bytes([self.channel]))
            / Dot11EltRSN()
            / Dot11Elt(ID=221, info=self.vendor_oui + b"\x02\x01\x01")
        )  # fmt: skip
        packet.time = at
        return packet


def deauth_flood(bssid: str, *, start: float, count: int, channel: int = 6) -> list[Any]:
    """Broadcast deauthentication frames forged with ``bssid`` (50 per second)."""
    packets = []
    for index in range(count):
        at = start + index * 0.02
        packet = (
            _radiotap(channel, -50, at)
            / Dot11(type=0, subtype=12, addr1=BROADCAST, addr2=bssid, addr3=bssid,
                    SC=(index % 4096) << 4)
            / Dot11Deauth(reason=7)
        )  # fmt: skip
        packet.time = at
        packets.append(packet)
    return packets


def _radiotap(channel: int, rssi_dbm: int, at: float) -> Any:
    frequency = 2407 + 5 * channel if channel <= 13 else 5000 + 5 * channel
    band = "2GHz+CCK" if channel <= 13 else "5GHz+OFDM"
    return RadioTap(
        present="TSFT+Channel+dBm_AntSignal",
        mac_timestamp=int(at * 1_000_000) % 2**64,
        ChannelFrequency=frequency,
        ChannelFlags=band,
        dBm_AntSignal=rssi_dbm,
    )


def _interleave(*streams: list[Any]) -> list[Any]:
    return sorted((packet for stream in streams for packet in stream), key=lambda p: p.time)


# --- APs used across scenarios ----------------------------------------------

HOME = SimulatedAP("00:11:22:aa:00:01", "HomeNet", skew_ppm=-7.5)
TWIN_VENDOR = SimulatedAP(
    "02:de:ad:be:ef:01", "HomeNet", channel=11, rssi_dbm=-38, skew_ppm=21.0,
    tsf_offset_us=1_000_000, vendor_oui=b"\xaa\xbb\xcc", rates=b"\x8c\x12\x98\x24\xb0\x48\x60\x6c",
)  # fmt: skip
CORP = [
    SimulatedAP(f"00:11:22:cc:00:0{n}", "CorpNet", channel=ch, rssi_dbm=rssi, skew_ppm=skew)
    for n, ch, rssi, skew in ((1, 1, -48, 3.0), (2, 6, -55, -4.0), (3, 11, -61, 9.5))
]


def _scenarios() -> list[dict[str, Any]]:
    """Each entry: name, packets, optional enrollment capture name, expectations."""

    half = HOME.beacon_interval_tu * TU_S / 2
    same_bssid_twin = replace(
        TWIN_VENDOR, bssid=HOME.bssid, channel=HOME.channel, tsf_offset_us=1_000_000
    )
    # Same BSSID and IEs, TSF within 2 ms of the original, but on another channel.
    channel_clone = replace(HOME, channel=1, rssi_dbm=-60, tsf_offset_us=HOME.tsf_offset_us + 2_000)
    corp_outlier = replace(TWIN_VENDOR, ssid="CorpNet", bssid="02:de:ad:be:ef:02")

    return [
        dict(
            name="clean_single_ap",
            description="One stable AP. Negative control.",
            packets=HOME.beacons(start=START, count=80),
            enrollment="home",
            expected_classification="clean",
        ),
        dict(
            name="clean_enterprise_same_ssid",
            description="Three uniform APs share one SSID (enterprise). Negative control "
            "for the environment detector.",
            packets=_interleave(*(ap.beacons(start=START, count=60) for ap in CORP)),
            enrollment="corp",
            expected_classification="clean",
        ),
        dict(
            name="ap_restart",
            description="A trusted AP reboots: TSF and sequence numbers restart once. "
            "Must not look like a twin; a sequence restart alone is weak evidence.",
            packets=HOME.beacons(start=START, count=60)
            + replace(HOME, tsf_offset_us=0).beacons(start=START + 10, count=60),
            enrollment="home",
            expected_classification="info",
            target_bssid=HOME.bssid,
            expected_signals=["sequence_backward_jump"],
        ),
        dict(
            name="ssid_clone_new_bssid",
            description="A second AP with its own BSSID and other hardware advertises the "
            "trusted SSID. No deauthentication.",
            packets=_interleave(
                HOME.beacons(start=START, count=80), TWIN_VENDOR.beacons(start=START + 1, count=80)
            ),
            enrollment="home",
            expected_classification="suspicious",
            target_bssid=TWIN_VENDOR.bssid,
            expected_modules=["identity_verification"],
            expected_signals=["unknown_bssid_for_trusted_ssid"],
        ),
        dict(
            name="classic_evil_twin",
            description="SSID clone on its own BSSID while broadcast deauthentication frames "
            "forged with the real AP's BSSID push its clients away.",
            packets=_interleave(
                HOME.beacons(start=START, count=80),
                TWIN_VENDOR.beacons(start=START + 1, count=80),
                deauth_flood(HOME.bssid, start=START + 3, count=150),
            ),
            enrollment="home",
            expected_classification="evil_twin",
            target_bssid=TWIN_VENDOR.bssid,
            expected_modules=["identity_verification", "deauth_storm"],
            expected_signals=["unknown_bssid_for_trusted_ssid", "broadcast_flood"],
        ),
        dict(
            name="bssid_clone_same_channel",
            description="A second device copies the BSSID and beacons on the same channel "
            "with its own clock.",
            packets=_interleave(
                HOME.beacons(start=START, count=60),
                same_bssid_twin.beacons(start=START + half, count=60, first_sequence=2000),
            ),
            expected_classification="suspicious",
            target_bssid=HOME.bssid,
            expected_modules=["identity_verification"],
            expected_signals=["duplicate_bssid_clock_split", "duplicate_bssid_ie_split"],
        ),
        dict(
            name="bssid_clone_other_channel",
            description="A full copy (BSSID, IEs, near-identical TSF) beacons on another "
            "channel at the same time.",
            packets=_interleave(
                HOME.beacons(start=START, count=60),
                channel_clone.beacons(start=START + half, count=60),
            ),
            expected_classification="suspicious",
            target_bssid=HOME.bssid,
            expected_modules=["identity_verification"],
            expected_signals=["duplicate_bssid_channel_conflict"],
        ),
        dict(
            name="bssid_clone_with_deauth",
            description="BSSID copy on the same channel plus a deauthentication storm.",
            packets=_interleave(
                HOME.beacons(start=START, count=60),
                same_bssid_twin.beacons(start=START + half, count=60, first_sequence=2000),
                deauth_flood(HOME.bssid, start=START + 2, count=150),
            ),
            expected_classification="evil_twin",
            target_bssid=HOME.bssid,
            expected_modules=["identity_verification", "deauth_storm"],
            expected_signals=["duplicate_bssid_clock_split", "broadcast_flood"],
        ),
        dict(
            name="enterprise_outlier",
            description="A fourth AP joins an enterprise SSID with different hardware. "
            "No trusted profiles: found by peer comparison alone.",
            packets=_interleave(
                *(ap.beacons(start=START, count=60) for ap in CORP),
                corp_outlier.beacons(start=START + 1, count=60),
            ),
            expected_classification="suspicious",
            target_bssid=corp_outlier.bssid,
            expected_modules=["environment_anomaly"],
            expected_signals=["same_ssid_ie_fingerprint_outlier", "same_ssid_vendor_oui_outlier"],
        ),
        dict(
            name="deauth_storm_only",
            description="Broadcast deauthentication flood, no impersonating AP.",
            packets=_interleave(
                HOME.beacons(start=START, count=60),
                deauth_flood(HOME.bssid, start=START + 2, count=150),
            ),
            expected_classification="suspicious",
            target_bssid=HOME.bssid,
            expected_modules=["deauth_storm"],
            expected_signals=["management_frame_rate_high", "broadcast_flood"],
        ),
    ]


def _enrollment_captures() -> dict[str, list[Any]]:
    """Known-good captures recorded before the scenarios, used for enrollment."""
    return {
        "home": HOME.beacons(start=START - 600, count=80),
        "corp": _interleave(*(ap.beacons(start=START - 600, count=80) for ap in CORP)),
    }


def write_synthetic_fixtures(output_dir: Path | str) -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    for name, packets in _enrollment_captures().items():
        wrpcap(str(output / f"enroll_{name}.pcap"), packets)
    scenarios = []
    for spec in _scenarios():
        packets = spec.pop("packets")
        enrollment = spec.pop("enrollment", None)
        scenario = Scenario(
            pcap=Path(f"{spec['name']}.pcap"),
            enrollment_pcap=Path(f"enroll_{enrollment}.pcap") if enrollment else None,
            **spec,
        )
        wrpcap(str(output / scenario.pcap), packets)
        scenarios.append(scenario)
    manifest = Manifest(
        source="synthetic Scapy frames generated by `wiguard fixtures generate`",
        limitations="Validates detector logic, not radio-frequency realism.",
        scenarios=scenarios,
    )
    path = output / "manifest.json"
    path.write_text(manifest.model_dump_json(indent=2, exclude_none=True) + "\n", encoding="utf-8")
    return path
