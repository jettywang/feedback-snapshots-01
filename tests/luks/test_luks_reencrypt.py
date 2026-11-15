from __future__ import annotations

import gzip
import io
import json
import re
from typing import TYPE_CHECKING, Any, Callable

import pytest

from dissect.fve.luks.luks import LUKS, find_luks_headers
from tests._util import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

BASE_IMAGE = "_data/luks2/aes-ecb-pbkdf2.bin.gz"
PASSPHRASE = "password"


def _load_base_image() -> bytes:
    with gzip.open(absolute_path(BASE_IMAGE), "rb") as fh:
        return fh.read()


def _json_area_offsets(data: bytes) -> Iterator[tuple[int, int]]:
    """Yield (offset, size) of every JSON metadata area in a LUKS2 image."""
    first_offset, second_offset, _ = find_luks_headers(io.BytesIO(data))
    for header_offset in (first_offset, second_offset):
        if header_offset is None:
            continue
        hdr_size = int.from_bytes(data[header_offset + 8 : header_offset + 16], "big")
        yield header_offset + 4096, hdr_size - 4096


def _make_variant(mutate: Callable[[dict[str, Any]], None]) -> io.BytesIO:
    """Return a copy of the base image with only reencryption related metadata changed."""
    data = bytearray(_load_base_image())
    for json_offset, json_size in _json_area_offsets(data):
        metadata = json.loads(bytes(data[json_offset : json_offset + json_size]).rstrip(b"\x00"))
        mutate(metadata)
        patched = json.dumps(metadata).encode()
        assert len(patched) <= json_size
        data[json_offset : json_offset + json_size] = patched.ljust(json_size, b"\x00")
    return io.BytesIO(bytes(data))


def _reencrypt_keyslot(**overrides: Any) -> dict[str, Any]:
    keyslot = {
        "type": "reencrypt",
        "key_size": 32,
        "area": {
            "type": "datashift-checksum",
            "offset": "163840",
            "size": "131072",
            "encryption": "aes-ecb",
            "key_size": 32,
            "hash": "sha256",
            "sector_size": 512,
            "shift_size": 4096,
        },
        "mode": "reencrypt",
        "direction": "forward",
    }
    keyslot.update(overrides)
    return keyslot


def _mutate_in_progress(metadata: dict[str, Any]) -> None:
    """Ongoing reencryption: reencrypt keyslot, transitional segment and flags."""
    metadata["keyslots"]["1"] = _reencrypt_keyslot()
    metadata["segments"]["1"] = {
        "type": "crypt",
        "offset": "1048576",
        "size": "dynamic",
        "iv_tweak": "0",
        "encryption": "aes-ecb",
        "sector_size": 512,
        "flags": ["in-reencryption"],
    }
    metadata["digests"]["0"]["segments"] = ["0", "1"]


def _mutate_incomplete_recovery(metadata: dict[str, Any]) -> None:
    """Interrupted reencryption with incomplete recovery information."""
    keyslot = _reencrypt_keyslot()
    del keyslot["mode"]
    del keyslot["direction"]
    metadata["keyslots"]["1"] = keyslot


def _mutate_unknown_mode_direction(metadata: dict[str, Any]) -> None:
    """Reencrypt keyslot with an unrecognized mode and direction."""
    metadata["keyslots"]["1"] = _reencrypt_keyslot(mode="sideways", direction="upward")


def _mutate_leftover_flags(metadata: dict[str, Any]) -> None:
    """Interrupted reencryption: only transitional segment flags remain."""
    metadata["segments"]["0"]["flags"] = ["in-reencryption"]


def _get_volume_key() -> bytes:
    luks_obj = LUKS(io.BytesIO(_load_base_image()))
    luks_obj.unlock_with_passphrase(PASSPHRASE)
    return luks_obj._active_volume_key


def _verify_crypto_stream(luks_obj: LUKS) -> None:
    stream = luks_obj.open()
    for i in range(4):
        assert stream.read(512) == bytes([i] * 512)


def test_luks2_reencrypt_control() -> None:
    """Control: the unmodified layout is stable and readable through both entry points."""
    volume_key = _get_volume_key()

    luks_obj = LUKS(io.BytesIO(_load_base_image()))
    assert luks_obj.reencryption_status() is None
    luks_obj.unlock_with_passphrase(PASSPHRASE)
    assert luks_obj.reencryption_status() is None
    _verify_crypto_stream(luks_obj)

    luks_obj = LUKS(io.BytesIO(_load_base_image()))
    luks_obj.unlock(volume_key, 0)
    assert luks_obj.reencryption_status() is None
    _verify_crypto_stream(luks_obj)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        pytest.param(
            _mutate_in_progress,
            r"segment 1 has reencryption flags: in-reencryption; reencrypt keyslot 1 present \(reencrypt, forward\)",
            id="in-progress",
        ),
        pytest.param(
            _mutate_incomplete_recovery,
            r"reencrypt keyslot 1 has incomplete recovery information",
            id="incomplete-recovery",
        ),
        pytest.param(
            _mutate_unknown_mode_direction,
            r"reencrypt keyslot 1 has unknown mode or direction: sideways/upward",
            id="unknown-mode-direction",
        ),
        pytest.param(
            _mutate_leftover_flags,
            r"segment 0 has reencryption flags: in-reencryption",
            id="leftover-flags",
        ),
    ],
)
def test_luks2_reencrypt_rejected(mutate: Callable[[dict[str, Any]], None], match: str) -> None:
    """Transitional layouts: unlocking still works, but opening is explicitly refused."""
    volume_key = _get_volume_key()

    # Passphrase entry point: verification succeeds, readability is checked separately.
    luks_obj = LUKS(_make_variant(mutate))
    luks_obj.unlock_with_passphrase(PASSPHRASE)
    assert luks_obj.unlocked
    status = luks_obj.reencryption_status()
    assert status is not None
    assert re.search(match, status)
    with pytest.raises(ValueError, match=f"Refusing to open volume with unfinished reencryption: {match}"):
        luks_obj.open()

    # Direct volume key entry point: same admission check applies.
    luks_obj = LUKS(_make_variant(mutate))
    luks_obj.unlock(volume_key, 0)
    assert luks_obj.unlocked
    with pytest.raises(ValueError, match=f"Refusing to open volume with unfinished reencryption: {match}"):
        luks_obj.open()
