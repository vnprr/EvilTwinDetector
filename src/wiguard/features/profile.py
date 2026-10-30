"""Per-AP aggregation: everything WiGuard knows about one BSSID."""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Iterator
from dataclasses import dataclass
from statistics import mean, pstdev

from .clock import ClockSkewEstimator, LinearFit
from .frames import BeaconFrame
from .sequence import SequenceAnalyzer, SequenceStats
from .timing import BeaconTimingAnalyzer, BeaconTimingStats


@dataclass(frozen=True, slots=True)
class APSummary:
    """Immutable snapshot of one AP profile, consumed by the detectors."""

    bssid: str
    ssid: str
    channels: tuple[int, ...]
    first_seen: float
    last_seen: float
    frames: int
    last_rssi_dbm: int | None
    avg_rssi_dbm: float | None
    rssi_stddev: float | None
    dominant_ie_fingerprint: str | None
    ie_fingerprints: tuple[str, ...]
    ie_ids: tuple[int, ...]
    key_ie_ids: tuple[int, ...]
    vendor_ouis: tuple[str, ...]
    clock: LinearFit | None
    timing: BeaconTimingStats
    sequence: SequenceStats

    @property
    def clock_skew_ppm(self) -> float | None:
        return self.clock.skew_ppm if self.clock is not None else None

    def to_dict(self) -> dict[str, object]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channels": list(self.channels),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "frames": self.frames,
            "last_rssi_dbm": self.last_rssi_dbm,
            "avg_rssi_dbm": self.avg_rssi_dbm,
            "rssi_stddev": self.rssi_stddev,
            "dominant_ie_fingerprint": self.dominant_ie_fingerprint,
            "ie_fingerprints": list(self.ie_fingerprints),
            "ie_ids": list(self.ie_ids),
            "key_ie_ids": list(self.key_ie_ids),
            "vendor_ouis": list(self.vendor_ouis),
            "clock_skew_ppm": _round(self.clock_skew_ppm, 3),
            "clock": self.clock.to_dict() if self.clock is not None else None,
            "timing": self.timing.to_dict(),
            "sequence": self.sequence.to_dict(),
        }


class APProfile:
    """Rolling statistics for one BSSID, updated frame by frame.

    IE and timing statistics use beacons only: probe responses are sent on
    demand (not on the beacon schedule) and often carry a different IE set.
    """

    def __init__(self, bssid: str, *, window_size: int, clock_min_samples: int) -> None:
        self.bssid = bssid
        self.frames = 0
        self.first_seen: float | None = None
        self.last_seen: float | None = None
        self.last_rssi_dbm: int | None = None
        self._ssids: Counter[str] = Counter()
        self._channels: set[int] = set()
        self._rssi: deque[int] = deque(maxlen=window_size)
        self._ie_hashes: Counter[str] = Counter()
        self._ie_ids: set[int] = set()
        self._key_ie_ids: set[int] = set()
        self._vendor_ouis: set[str] = set()
        self._clock = ClockSkewEstimator(min_samples=clock_min_samples, window_size=window_size)
        self._timing = BeaconTimingAnalyzer(window_size=window_size)
        self._sequence = SequenceAnalyzer()

    def add(self, frame: BeaconFrame) -> None:
        self.frames += 1
        if self.first_seen is None:
            self.first_seen = frame.timestamp
        self.last_seen = frame.timestamp
        self._ssids[frame.ssid] += 1
        if frame.channel is not None:
            self._channels.add(frame.channel)
        if frame.rssi_dbm is not None:
            self.last_rssi_dbm = frame.rssi_dbm
            self._rssi.append(frame.rssi_dbm)
        if frame.sequence_number is not None:
            self._sequence.add(frame.sequence_number)
        if frame.ap_tsf_us is not None:
            self._clock.add(frame.timestamp, frame.ap_tsf_us)
        if frame.kind == "beacon":
            self._ie_hashes[frame.ie.hash] += 1
            self._ie_ids.update(frame.ie.ie_ids)
            self._key_ie_ids.update(frame.ie.key_ie_ids)
            self._vendor_ouis.update(frame.ie.vendor_ouis)
            if frame.ap_tsf_us is not None:
                self._timing.add(frame.ap_tsf_us, frame.beacon_interval_tu)

    def summary(self) -> APSummary:
        rssi = self._rssi
        return APSummary(
            bssid=self.bssid,
            ssid=self.ssid,
            channels=tuple(sorted(self._channels)),
            first_seen=self.first_seen or 0.0,
            last_seen=self.last_seen or 0.0,
            frames=self.frames,
            last_rssi_dbm=self.last_rssi_dbm,
            avg_rssi_dbm=_round(mean(rssi), 1) if rssi else None,
            rssi_stddev=_round(pstdev(rssi), 2) if len(rssi) > 1 else None,
            dominant_ie_fingerprint=(
                self._ie_hashes.most_common(1)[0][0] if self._ie_hashes else None
            ),
            ie_fingerprints=tuple(sorted(self._ie_hashes)),
            ie_ids=tuple(sorted(self._ie_ids)),
            key_ie_ids=tuple(sorted(self._key_ie_ids)),
            vendor_ouis=tuple(sorted(self._vendor_ouis)),
            clock=self._clock.estimate(),
            timing=self._timing.stats(),
            sequence=self._sequence.stats(),
        )

    @property
    def ssid(self) -> str:
        """Most frequently advertised non-hidden SSID ("" if only hidden)."""
        named = [(count, ssid) for ssid, count in self._ssids.items() if ssid]
        return max(named)[1] if named else ""


class APTracker:
    """All AP profiles seen so far, keyed by BSSID."""

    def __init__(self, *, window_size: int = 300, clock_min_samples: int = 50) -> None:
        self.window_size = window_size
        self.clock_min_samples = clock_min_samples
        self._profiles: dict[str, APProfile] = {}

    def add(self, frame: BeaconFrame) -> APProfile:
        profile = self._profiles.get(frame.bssid)
        if profile is None:
            profile = APProfile(
                frame.bssid,
                window_size=self.window_size,
                clock_min_samples=self.clock_min_samples,
            )
            self._profiles[frame.bssid] = profile
        profile.add(frame)
        return profile

    def summaries(self) -> list[APSummary]:
        return sorted(
            (profile.summary() for profile in self._profiles.values()),
            key=lambda summary: (summary.ssid, summary.bssid),
        )

    def ssid_of(self, bssid: str) -> str | None:
        profile = self._profiles.get(bssid)
        return profile.ssid if profile is not None else None

    def __iter__(self) -> Iterator[APProfile]:
        return iter(self._profiles.values())

    def __len__(self) -> int:
        return len(self._profiles)


def _round(value: float | None, digits: int) -> float | None:
    return None if value is None else round(value, digits)
