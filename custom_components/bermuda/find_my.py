"""
Local Find My address resolution from FindMy.py accessory exports.

Protocol reference: https://github.com/malmeloo/FindMy.py (accessory.py and
util/crypto.py). Only local key derivation is needed; no Apple login or network
requests are made. Keys must never be attached to BermudaDevice objects.
"""

# ruff: noqa: TRY301

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TypedDict
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

P224_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
ROLLOVER = timedelta(minutes=15)
MAX_INDEX = 1_000_000


class AccessoryRecord(TypedDict):
    """Validated subset of a FindMy.py export, stored only in entry options."""

    type: str
    master_key: str
    skn: str
    sks: str
    paired_at: str
    name: str
    model: str
    identifier: str
    alignment_date: str
    alignment_index: int


def parse_accessory(raw: str) -> AccessoryRecord:
    """Validate an export without putting secrets in validation errors."""
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("type") != "accessory":
            raise ValueError
        for key, length in (("master_key", 28), ("skn", 32), ("sks", 32)):
            if not isinstance(data[key], str) or len(bytes.fromhex(data[key])) != length:
                raise ValueError
        if not 0 < int(data["master_key"], 16) < P224_ORDER:
            raise ValueError
        identifier = str(UUID(data["identifier"]))
        paired = datetime.fromisoformat(data["paired_at"])
        aligned = datetime.fromisoformat(data.get("alignment_date") or data["paired_at"])
        index = data.get("alignment_index")
        if index is not None and data.get("alignment_date") is None:
            raise ValueError
        if index is None:
            if data.get("alignment_date") is not None:
                raise ValueError
            index = 0
        if type(index) is not int or not 0 <= index <= MAX_INDEX:
            raise ValueError
        if paired.tzinfo is None or aligned.tzinfo is None or aligned < paired:
            raise ValueError
        if aligned > datetime.now(UTC) + ROLLOVER:
            raise ValueError
        for key in ("name", "model"):
            if data.get(key) is not None and not isinstance(data[key], str):
                raise ValueError
        return AccessoryRecord(
            type="accessory",
            master_key=data["master_key"].lower(),
            skn=data["skn"].lower(),
            sks=data["sks"].lower(),
            paired_at=paired.isoformat(),
            name=data.get("name") or "Find My tag",
            model=data.get("model") or "Find My accessory",
            identifier=identifier,
            alignment_date=aligned.isoformat(),
            alignment_index=index,
        )
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        message = "Invalid Find My accessory export"
        raise ValueError(message) from None


def accessory_address(record: AccessoryRecord) -> str:
    """Stable identity independent of both secret keys and Bluetooth addresses."""
    return f"findmy:{record['identifier']}"


def _kdf(secret: bytes, info: bytes, length: int) -> bytes:
    """Apply the Find My X9.63 SHA-256 key derivation."""
    return X963KDF(algorithm=hashes.SHA256(), length=length, sharedinfo=info).derive(secret)


@dataclass(repr=False)
class _KeyChain:
    master: int
    secret: bytes
    index: int = 0

    def public_key(self, index: int) -> bytes:
        """Advance a chain in order; historical secrets are not retained."""
        if index < self.index:
            message = "Find My key chain cannot move backwards"
            raise ValueError(message)
        while self.index < index:
            self.secret = _kdf(self.secret, b"update", 32)
            self.index += 1
        material = _kdf(self.secret, b"diversify", 72)
        multiplier = int.from_bytes(material[:36], "big") % (P224_ORDER - 1) + 1
        offset = int.from_bytes(material[36:], "big") % (P224_ORDER - 1) + 1
        private = (multiplier * self.master + offset) % P224_ORDER
        return ec.derive_private_key(private, ec.SECP224R1()).public_key().public_numbers().x.to_bytes(28, "big")


@dataclass(frozen=True)
class FindMyMatch:
    """Public identity for a generated advertising key."""

    address: str
    public_key: bytes = field(repr=False)


class FindMyResolver:
    """
    Generate candidate addresses on an executor, then publish a lookup snapshot.

    A tag's clock can pause. Keep every candidate since the imported alignment,
    not just keys close to wall-clock time. Two extra slots cover rollover edges.
    Primary and both possible secondary keys follow FindMy.py's keys_at rules.
    """

    def __init__(self, records: list[AccessoryRecord]) -> None:
        self._records = records
        self._chains = [
            (
                _KeyChain(int(record["master_key"], 16), bytes.fromhex(record["skn"])),
                _KeyChain(int(record["master_key"], 16), bytes.fromhex(record["sks"])),
            )
            for record in records
        ]
        self._next_indices = [
            [max(0, record["alignment_index"] - 2), max(0, record["alignment_index"] - 2) // 96 + 1]
            for record in records
        ]
        self._matches: dict[str, FindMyMatch] = {}

    def refresh(self, now: datetime) -> dict[str, FindMyMatch]:
        """Incrementally derive keys; call serially, outside the event loop."""
        for record, chains, next_indices in zip(self._records, self._chains, self._next_indices, strict=True):
            aligned = datetime.fromisoformat(record["alignment_date"])
            upper = min(MAX_INDEX, record["alignment_index"] + max(0, (now - aligned) // ROLLOVER) + 2)
            for chain_number, end in enumerate((upper, upper // 96 + 2)):
                for index in range(next_indices[chain_number], end + 1):
                    public = chains[chain_number].public_key(index)
                    mac = bytes([public[0] | 0xC0]) + public[1:6]
                    self._matches[mac.hex(":")] = FindMyMatch(accessory_address(record), public)
                next_indices[chain_number] = max(next_indices[chain_number], end + 1)
        return self._matches.copy()


def match_advertisement(
    matches: dict[str, FindMyMatch], address: str, manufacturer_data: dict[int, bytes]
) -> str | None:
    """Match Find My advertisements, verifying the full key when available."""
    match = matches.get(address.lower())
    payload = manufacturer_data.get(0x004C, b"")
    if match is None or len(payload) < 4 or payload[0] != 0x12:
        return None
    if payload[1] == 0x19 and len(payload) == 27:
        if payload[3:25] != match.public_key[6:] or payload[25] != match.public_key[0] >> 6:
            return None
    elif payload[1] != 0x02 or len(payload) != 4:
        return None
    return match.address
