#!/usr/bin/env python3
"""How channel hopping changes what the sensor hears, and when it alerts.

A ten-minute synthetic scenario (S5): a trusted AP on channel 6, an SSID clone
on channel 11 from t = 60 s, and broadcast deauthentication frames forged with
the trusted AP's BSSID on channel 6 at 50 frames/s for t = 120-180 s.

The capture is filtered by a hop schedule: a frame is kept only if it was sent
while the sensor was tuned to its channel and past the settle time. The result
is replayed exactly like a live run (one evaluation every 5 s), and the alert
times are read back from the state database.

Simplifications: no frame loss and no reception from adjacent channels; the
time ``iw`` needs to retune is not counted. The numbers are therefore lower
bounds on what a real sensor achieves, not measurements.

    uv run python experiments/hopping_simulation.py
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from scapy.utils import wrpcap

from wiguard.analysis import analyze_pcap
from wiguard.config import CHANNELS_2GHZ, CHANNELS_5GHZ, WiGuardConfig
from wiguard.detection import TrustedProfileStore, enroll
from wiguard.evaluation.synthetic import HOME, START, TWIN_VENDOR, deauth_flood
from wiguard.runtime import StateWriter, replay_pcap

DURATION_S = 600.0
TWIN_START_S = 60.0
STORM_START_S, STORM_FRAMES = 120.0, 3000  # 60 s at 50 frames/s
BEACON_S = HOME.beacon_interval_tu * 1024e-6

SCHEDULES: dict[str, tuple[int, ...] | None] = {
    "no hopping (every frame)": None,
    "3 channels (1, 6, 11)": (1, 6, 11),
    f"{len(CHANNELS_2GHZ + CHANNELS_5GHZ)} channels (default)": CHANNELS_2GHZ + CHANNELS_5GHZ,
}


def heard(
    packets: list[Any],
    channel: int,
    schedule: tuple[int, ...] | None,
    *,
    settle: float,
    dwell: float,
) -> list[Any]:
    """The packets sent on ``channel`` while the hopping sensor listened there."""
    if schedule is None:
        return packets
    slot = settle + dwell
    kept = []
    for packet in packets:
        elapsed = float(packet.time) - START
        index = int(elapsed // slot)
        if schedule[index % len(schedule)] == channel and elapsed - index * slot >= settle:
            kept.append(packet)
    return kept


def main() -> None:
    config = WiGuardConfig()
    settle, dwell = config.capture.channel_settle_seconds, config.capture.dwell_seconds
    twin_beacons = int((DURATION_S - TWIN_START_S) / BEACON_S)
    streams = [
        (HOME.channel, HOME.beacons(start=START, count=int(DURATION_S / BEACON_S))),
        (TWIN_VENDOR.channel, TWIN_VENDOR.beacons(start=START + TWIN_START_S, count=twin_beacons)),
        (HOME.channel, deauth_flood(HOME.bssid, start=START + STORM_START_S, count=STORM_FRAMES)),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        # Enrollment from a known-good capture on the AP's own channel (no hopping).
        wrpcap(str(work / "enroll.pcap"), HOME.beacons(start=START - 600, count=600))
        baseline = analyze_pcap(work / "enroll.pcap", config, trusted_profiles=[])
        profiles_path = work / "profiles.json"
        TrustedProfileStore(profiles_path).save(
            enroll(baseline.access_points, min_frames=50, enrolled_at=baseline.evaluated_at)
        )
        config = config.with_overrides({"detection.identity.trusted_profiles_path": profiles_path})

        print(
            f"Twin from {TWIN_START_S:g} s, deauth storm from {STORM_START_S:g} s; "
            f"hop slot = {settle} s settle + {dwell} s dwell."
        )
        for name, schedule in SCHEDULES.items():
            kept = [
                heard(packets, ch, schedule, settle=settle, dwell=dwell) for ch, packets in streams
            ]
            pcap = work / "run.pcap"
            wrpcap(str(pcap), sorted((p for s in kept for p in s), key=lambda p: p.time))
            database = work / f"{len(schedule or ())}.db"
            with StateWriter.open(database) as store:
                replay_pcap(pcap, config, store)
            home, twin, storm = (len(packets) for packets in kept)
            print(
                f"\n{name}: heard {home} home beacons, {twin} twin beacons, {storm} deauth frames"
            )
            with sqlite3.connect(database) as db:
                rows = db.execute(
                    "SELECT observed_at, kind, bssid, message FROM timeline"
                    " WHERE kind LIKE 'alert_%' ORDER BY id"
                ).fetchall()
            for observed_at, kind, bssid, message in rows:
                print(f"  {observed_at - START:7.1f} s  {kind:16} {bssid}  {message}")


if __name__ == "__main__":
    main()
