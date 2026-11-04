"""Find My resolution using synthetic keys and independent FindMy.py vectors."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from custom_components.bermuda.bermuda_device import BermudaDevice
from custom_components.bermuda.const import ADDR_TYPE_FIND_MY, CONF_DEVICES
from custom_components.bermuda.coordinator import BermudaDataUpdateCoordinator
from custom_components.bermuda.find_my import (
    FindMyResolver,
    _KeyChain,
    accessory_address,
    match_advertisement,
    parse_accessory,
)


def synthetic_export():
    """Public test material; never use an owner's actual export in fixtures."""
    return {
        "type": "accessory",
        "master_key": bytes(range(1, 29)).hex(),
        "skn": bytes(range(32)).hex(),
        "sks": bytes(range(32, 64)).hex(),
        "paired_at": "2024-01-01T00:00:00+00:00",
        "name": "Test tag",
        "model": "Test accessory",
        "identifier": "00000000-0000-4000-8000-000000000001",
        "alignment_date": datetime.now(UTC).isoformat(),
        "alignment_index": 96,
    }


# Generated independently with FindMy.py 0.10.2, using the synthetic keys above.
@pytest.mark.parametrize(
    ("secret", "index", "expected"),
    [
        ("skn", 0, "a65cc0bfc9b5fc26208249eb966d85635a3c94b7f1b60c7431d41a8a"),
        ("skn", 1, "58d0dd8ea4869cc3681641950337c5b8b796f7ecfc61cd5e87c4717c"),
        ("skn", 95, "00459f7924a776819547025cf95ec8a353ba749ce8dda9335ae3f792"),
        ("skn", 96, "2ad4285aadfe2a7a4ec0338f0d0b34dcb21b55ddb013fe7ecdd2c330"),
        ("skn", 56388, "c5896b7efa6283cc9f519546da658b8a0cf6abf8ce341d0e4f43bdc3"),
        ("sks", 588, "3f1b9a73d6f01aad1341570ced161f58bc9704c4f1f87d13c35f66c0"),
        ("sks", 589, "46133d6732c1f7eb63940c24355d36a2b0390c511f1208c1df74b274"),
    ],
)
def test_key_vectors(secret, index, expected):
    export = synthetic_export()
    chain = _KeyChain(int(export["master_key"], 16), bytes.fromhex(export[secret]))
    assert chain.public_key(index).hex() == expected


@pytest.mark.parametrize(
    "changes",
    [
        {"type": "keypair"},
        {"master_key": "00"},
        {"master_key": "00" * 28},
        {"skn": "not hex"},
        {"sks": None},
        {"identifier": "invalid"},
        {"alignment_index": True},
        {"alignment_index": -1},
        {"alignment_index": 1000001},
        {"alignment_index": "96"},
        {"alignment_index": None},
        {"alignment_date": None},
        {"paired_at": "2024-01-01"},
        {"alignment_date": "2023-01-01T00:00:00Z"},
        {"alignment_date": "2999-01-01T00:00:00Z"},
        {"name": {}},
    ],
)
def test_reject_invalid_exports(changes):
    with pytest.raises(ValueError, match="^Invalid Find My accessory export$"):
        parse_accessory(json.dumps(synthetic_export() | changes))


@pytest.mark.parametrize("raw", ["{", "null", "[]", '"file.json"', "{}"])
def test_invalid_json(raw):
    with pytest.raises(ValueError, match="Invalid Find My accessory export"):
        parse_accessory(raw)


def test_optional_alignment():
    data = synthetic_export()
    del data["alignment_date"], data["alignment_index"]
    record = parse_accessory(json.dumps(data))
    assert record["alignment_index"] == 0
    assert record["alignment_date"] == record["paired_at"]


def test_rotation_secondary_keys_and_paused_clock():
    data = synthetic_export()
    data["alignment_index"] = 56388
    record = parse_accessory(json.dumps(data))
    now = datetime.fromisoformat(record["alignment_date"])
    resolver = FindMyResolver([record])
    initial = resolver.refresh(now)
    later = resolver.refresh(now + timedelta(days=2))
    assert "fb:11:b8:69:20:64" not in initial
    for mac in ("c5:89:6b:7e:fa:62", "fb:11:b8:69:20:64", "ff:1b:9a:73:d6:f0", "c6:13:3d:67:32:c1"):
        assert later[mac].address == accessory_address(record)
    assert resolver.refresh(now + timedelta(days=2)) == later
    # NTP going backwards must not rewind the secret chain or lose matches.
    assert resolver.refresh(now) == later


def test_advertisement_validation():
    record = parse_accessory(json.dumps(synthetic_export()))
    matches = FindMyResolver([record]).refresh(datetime.fromisoformat(record["alignment_date"]))
    mac = "ea:d4:28:5a:ad:fe"
    public = matches[mac].public_key
    payload = b"\x12\x19\x00" + public[6:] + bytes([public[0] >> 6, 0])
    assert match_advertisement(matches, mac.upper(), {76: payload}) == accessory_address(record)
    assert match_advertisement(matches, mac, {76: b"\x12\x02\x00\x00"}) == accessory_address(record)
    for invalid in (b"", payload[:-1], payload + b"\x00", b"\x02\x15\x00\x00", payload[:3] + b"\x00" * 24):
        assert match_advertisement(matches, mac, {76: invalid}) is None
    assert match_advertisement(matches, mac, {77: payload}) is None
    assert match_advertisement(matches, "ff:ff:ff:ff:ff:ff", {76: payload}) is None


def test_rotating_sources_share_one_device():
    record = parse_accessory(json.dumps(synthetic_export()))
    address = accessory_address(record)
    coordinator = MagicMock()
    coordinator.options = {CONF_DEVICES: [address.upper()]}
    coordinator.hass_version_min_2025_4 = True
    meta = BermudaDevice(address, coordinator)
    assert meta.address_type == ADDR_TYPE_FIND_MY
    coordinator.metadevices = {address: meta}
    coordinator._find_my_matches = FindMyResolver([record]).refresh(datetime.fromisoformat(record["alignment_date"]))
    sources = [BermudaDevice(mac, coordinator) for mac in ("c0:45:9f:79:24:a7", "ea:d4:28:5a:ad:fe")]
    for source in sources:
        BermudaDataUpdateCoordinator._register_find_my_source(coordinator, source, {76: b"\x12\x02\x00\x00"})
    BermudaDataUpdateCoordinator._register_find_my_source(coordinator, sources[0], {76: b"\x12\x02\x00\x00"})
    assert meta.metadevice_sources == [sources[1].address, sources[0].address]
    assert len(coordinator.metadevices) == 1
    # The existing aggregation path must retain readings from both addresses.
    for i, source in enumerate(sources):
        source.adverts[(source.address, "scanner")] = SimpleNamespace(rssi=-60 - i)
    coordinator._get_device.side_effect = lambda mac: next(s for s in sources if s.address == mac)
    BermudaDataUpdateCoordinator.update_metadevices(coordinator)
    assert len(meta.adverts) == 2
    assert {advert.rssi for advert in meta.adverts.values()} == {-60, -61}
    meta.adverts.clear()
    assert "master_key" not in json.dumps(meta.to_dict(), default=str)
