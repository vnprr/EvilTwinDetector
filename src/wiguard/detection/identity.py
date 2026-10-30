"""Identity verification: compare what is on the air with the trusted profiles.

* A trusted BSSID whose fingerprint or clock changed is probably a copy that
  reuses the real AP's MAC address.
* An unknown BSSID advertising a trusted SSID is a second AP impersonating the
  network name — the classic Evil Twin setup.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from wiguard.features import APSummary

from .events import DetectionEvent, Module, Severity, Signal
from .profiles import TrustedProfile


class IdentityVerifier:
    def __init__(
        self,
        profiles: Iterable[TrustedProfile] = (),
        *,
        min_frames: int = 10,
        clock_skew_delta_ppm: float = 5.0,
        rssi_shift_db: float = 12.0,
    ) -> None:
        self.profiles = {profile.bssid: profile for profile in profiles}
        self.trusted_ssids = {profile.ssid for profile in self.profiles.values() if profile.ssid}
        self.min_frames = min_frames
        self.clock_skew_delta_ppm = clock_skew_delta_ppm
        self.rssi_shift_db = rssi_shift_db

    def evaluate(self, summaries: Sequence[APSummary]) -> list[DetectionEvent]:
        events = []
        for ap in summaries:
            if ap.frames < self.min_frames:
                continue
            profile = self.profiles.get(ap.bssid)
            if profile is not None:
                signals = self._drift(profile, ap)
            elif ap.ssid in self.trusted_ssids:
                signals = [self._unknown_bssid(ap)]
            else:
                continue
            if signals:
                events.append(
                    DetectionEvent(
                        module=Module.IDENTITY,
                        bssid=ap.bssid,
                        ssid=ap.ssid,
                        signals=tuple(signals),
                        last_seen=ap.last_seen,
                        context={"detector": "trusted_profile"},
                    )
                )
        return events

    def _unknown_bssid(self, ap: APSummary) -> Signal:
        trusted = sorted(bssid for bssid, p in self.profiles.items() if p.ssid == ap.ssid)
        return Signal(
            "unknown_bssid_for_trusted_ssid",
            Severity.HIGH,
            "A BSSID that is not enrolled advertises a trusted network name",
            {"trusted_bssids": trusted, "channels": list(ap.channels)},
        )

    def _drift(self, profile: TrustedProfile, ap: APSummary) -> list[Signal]:
        checks = (
            self._fingerprint_changed(profile, ap),
            self._clock_changed(profile, ap),
            self._rssi_shifted(profile, ap),
            self._sequence_jumped(profile, ap),
        )
        return [signal for signal in checks if signal is not None]

    def _fingerprint_changed(self, profile: TrustedProfile, ap: APSummary) -> Signal | None:
        current = ap.dominant_ie_fingerprint
        if not profile.ie_fingerprint or not current or current == profile.ie_fingerprint:
            return None
        return Signal(
            "ie_fingerprint_changed",
            Severity.HIGH,
            "IE fingerprint differs from the trusted profile",
            {"trusted": profile.ie_fingerprint, "current": current},
        )

    def _clock_changed(self, profile: TrustedProfile, ap: APSummary) -> Signal | None:
        if profile.clock_skew_ppm is None or ap.clock_skew_ppm is None:
            return None
        delta = ap.clock_skew_ppm - profile.clock_skew_ppm
        if abs(delta) < self.clock_skew_delta_ppm:
            return None
        return Signal(
            "clock_skew_changed",
            Severity.HIGH,
            "Clock skew differs from the trusted profile",
            {
                "trusted_ppm": round(profile.clock_skew_ppm, 3),
                "current_ppm": round(ap.clock_skew_ppm, 3),
                "delta_ppm": round(delta, 3),
                "threshold_ppm": self.clock_skew_delta_ppm,
            },
        )

    def _rssi_shifted(self, profile: TrustedProfile, ap: APSummary) -> Signal | None:
        if profile.avg_rssi_dbm is None or ap.avg_rssi_dbm is None:
            return None
        delta = ap.avg_rssi_dbm - profile.avg_rssi_dbm
        # Tolerate at least four standard deviations of the enrolled RSSI.
        tolerance = max(self.rssi_shift_db, 4.0 * (profile.rssi_stddev or 0.0))
        if abs(delta) < tolerance:
            return None
        return Signal(
            "rssi_shifted",
            Severity.MEDIUM,
            "Signal strength moved far from the trusted profile",
            {
                "trusted_dbm": profile.avg_rssi_dbm,
                "current_dbm": ap.avg_rssi_dbm,
                "delta_db": round(delta, 2),
                "threshold_db": round(tolerance, 2),
            },
        )

    def _sequence_jumped(self, profile: TrustedProfile, ap: APSummary) -> Signal | None:
        jumps = ap.sequence.backward_jumps
        if jumps <= profile.sequence_backward_jumps:
            return None
        return Signal(
            "sequence_backward_jump",
            Severity.MEDIUM,
            "Sequence numbers jumped backwards (restart or second transmitter)",
            {"trusted": profile.sequence_backward_jumps, "current": jumps},
        )
