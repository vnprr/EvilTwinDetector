"""Information Element (IE) fingerprinting.

A beacon carries a list of Information Elements: supported rates, RSN
(security), HT/VHT capabilities, vendor extensions and so on. Their order and
content depend on the AP's hardware, firmware and configuration, so together
they form a fingerprint that is cheap to observe and hard to copy exactly.

Elements whose content changes from beacon to beacon (TIM, BSS load, channel
switch, quiet) are excluded, otherwise every frame would get a new fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

VENDOR_SPECIFIC_ID = 221

# Elements whose content legitimately changes between beacons of one AP.
DYNAMIC_IE_IDS = frozenset({5, 11, 37, 40})
# Elements whose full content (not only presence) enters the fingerprint:
# rates, HT caps, RSN, extended rates, extended caps, VHT caps, vendor-specific.
KEY_IE_IDS = frozenset({1, 45, 48, 50, 127, 191, VENDOR_SPECIFIC_ID})


@dataclass(frozen=True, slots=True)
class InformationElement:
    id: int
    body: bytes

    @property
    def vendor_oui(self) -> str | None:
        """Vendor OUI (first three bytes) of a vendor-specific element."""
        if self.id != VENDOR_SPECIFIC_ID or len(self.body) < 3:
            return None
        return self.body[:3].hex(":")


@dataclass(frozen=True, slots=True)
class IEFingerprint:
    """Deterministic fingerprint of the stable IEs of one frame."""

    ie_ids: tuple[int, ...]
    """IDs of the stable elements, in wire order."""
    key_ie_ids: tuple[int, ...]
    vendor_ouis: tuple[str, ...]
    hash: str

    def to_dict(self) -> dict[str, object]:
        return {
            "ie_ids": list(self.ie_ids),
            "key_ie_ids": list(self.key_ie_ids),
            "vendor_ouis": list(self.vendor_ouis),
            "hash": self.hash,
        }


def build_ie_fingerprint(elements: tuple[InformationElement, ...]) -> IEFingerprint:
    stable = [element for element in elements if element.id not in DYNAMIC_IE_IDS]
    key = [element for element in stable if element.id in KEY_IE_IDS]
    canonical = {
        "ie_ids": [element.id for element in stable],
        "key_elements": sorted([element.id, element.body.hex()] for element in key),
    }
    digest = hashlib.sha256(
        json.dumps(canonical, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return IEFingerprint(
        ie_ids=tuple(element.id for element in stable),
        key_ie_ids=tuple(sorted({element.id for element in key})),
        vendor_ouis=tuple(sorted({oui for element in key if (oui := element.vendor_oui)})),
        hash=digest,
    )
