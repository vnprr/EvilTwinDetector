"""Small builders for frames and events used across the tests."""

from __future__ import annotations

from pathlib import Path

from wiguard.detection import DetectionEvent, Module, Severity, Signal
from wiguard.features import BeaconFrame, DisruptionFrame, IEFingerprint

FIXTURES = Path(__file__).parent / "pcap_fixtures" / "synthetic"
MANIFEST = FIXTURES / "manifest.json"
START = 1_767_225_600.0


def ie(name: str = "a", *, vendor: str = "00:11:22", ids: tuple[int, ...] = (0, 1, 3, 48, 221)):
    return IEFingerprint(
        ie_ids=ids, key_ie_ids=(1, 48, 221), vendor_ouis=(vendor,), hash=f"ie-{name}"
    )


def beacon(
    index: int = 0,
    *,
    bssid: str = "00:11:22:33:44:55",
    ssid: str = "HomeNet",
    at: float | None = None,
    tsf_offset_us: float = 1_000_000_000.0,
    skew_ppm: float = 0.0,
    channel: int | None = 6,
    rssi_dbm: int | None = -45,
    sequence_number: int | None = None,
    fingerprint: IEFingerprint | None = None,
    kind: str = "beacon",
    interval_tu: int = 100,
) -> BeaconFrame:
    """A beacon ``index`` intervals after START, with a TSF from a clock of ``skew_ppm``."""

    timestamp = START + index * interval_tu * 1024e-6 if at is None else at
    elapsed_us = (timestamp - START) * 1_000_000.0
    return BeaconFrame(
        timestamp=timestamp,
        kind=kind,  # type: ignore[arg-type]
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        rssi_dbm=rssi_dbm,
        ap_tsf_us=int(tsf_offset_us + elapsed_us * (1 + skew_ppm / 1e6)),
        sequence_number=index % 4096 if sequence_number is None else sequence_number,
        beacon_interval_tu=interval_tu,
        ie=fingerprint or ie(),
    )


def deauth(
    at: float, *, bssid: str = "00:11:22:33:44:55", destination: str = "ff:ff:ff:ff:ff:ff"
) -> DisruptionFrame:
    return DisruptionFrame(
        timestamp=at,
        kind="deauthentication",
        bssid=bssid,
        source=bssid,
        destination=destination,
        channel=6,
        reason=7,
    )


def event(
    module: Module,
    severity: Severity = Severity.HIGH,
    *,
    bssid: str = "aa:aa:aa:aa:aa:aa",
    ssid: str = "Net",
    name: str = "signal",
    context: dict[str, object] | None = None,
) -> DetectionEvent:
    return DetectionEvent(
        module=module,
        bssid=bssid,
        ssid=ssid,
        signals=(Signal(name=name, severity=severity, message=name),),
        last_seen=START,
        context=context or {},
    )
