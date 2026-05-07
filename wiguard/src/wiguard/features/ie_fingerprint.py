"""Information Element fingerprinting for 802.11 management frames."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any

from scapy.layers.dot11 import Dot11Elt


DYNAMIC_IE_IDS = frozenset({5, 11, 37, 40})
KEY_IE_IDS = frozenset({1, 45, 48, 50, 127, 191, 221})


@dataclass(frozen=True)
class InformationElement:
    id: int
    length: int
    info_hex: str
    oui: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class IEFingerprint:
    """Deterministic fingerprint of stable beacon/probe response IEs."""

    sequence_signature: tuple[int, ...]
    stable_sequence_signature: tuple[int, ...]
    key_elements: tuple[InformationElement, ...]
    vendor_ouis: tuple[str, ...]
    hash: str

    def to_dict(self) -> dict[str, object]:
        return {
            "sequence_signature": list(self.sequence_signature),
            "stable_sequence_signature": list(self.stable_sequence_signature),
            "key_elements": [element.to_dict() for element in self.key_elements],
            "vendor_ouis": list(self.vendor_ouis),
            "hash": self.hash,
        }


def extract_information_elements(packet: Any) -> tuple[InformationElement, ...]:
    """Extract Dot11 Information Elements in wire order."""

    elements: list[InformationElement] = []
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        element_id = getattr(elt, "ID", None)
        if not isinstance(element_id, int):
            break
        raw_info = bytes(getattr(elt, "info", b""))
        oui = _vendor_oui(raw_info) if element_id == 221 else None
        elements.append(
            InformationElement(
                id=element_id,
                length=len(raw_info),
                info_hex=raw_info.hex(),
                oui=oui,
            )
        )
        elt = elt.payload.getlayer(Dot11Elt)
    return tuple(elements)


def build_ie_fingerprint(packet: Any) -> IEFingerprint:
    elements = extract_information_elements(packet)
    sequence = tuple(element.id for element in elements)
    stable_sequence = tuple(element.id for element in elements if element.id not in DYNAMIC_IE_IDS)
    key_elements = tuple(
        element
        for element in elements
        if element.id in KEY_IE_IDS and element.id not in DYNAMIC_IE_IDS
    )
    vendor_ouis = tuple(
        sorted({element.oui for element in key_elements if element.oui is not None})
    )
    canonical_payload = _canonical_payload(stable_sequence, key_elements)
    digest = hashlib.sha256(canonical_payload).hexdigest()
    return IEFingerprint(
        sequence_signature=sequence,
        stable_sequence_signature=stable_sequence,
        key_elements=key_elements,
        vendor_ouis=vendor_ouis,
        hash=digest,
    )


def _canonical_payload(
    stable_sequence: tuple[int, ...],
    key_elements: tuple[InformationElement, ...],
) -> bytes:
    grouped: dict[int, list[dict[str, object]]] = defaultdict(list)
    for element in key_elements:
        grouped[element.id].append(
            {
                "length": element.length,
                "info_hex": element.info_hex,
                "oui": element.oui,
            }
        )
    payload = {
        "stable_sequence": list(stable_sequence),
        "key_elements": {str(key): value for key, value in sorted(grouped.items())},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _vendor_oui(raw_info: bytes) -> str | None:
    if len(raw_info) < 3:
        return None
    return ":".join(f"{byte:02x}" for byte in raw_info[:3])
