from __future__ import annotations

import struct
import zlib
from collections.abc import Callable
from io import BytesIO

import pytest
from dissect.util.stream import MappingStream

from dissect.fve.crypto import create_cipher
from dissect.fve.exception import InvalidHeaderError
from dissect.fve.veracrypt.c_veracrypt import (
    HEADER_CRC32_RANGE,
    KEY_AREA_CRC32_RANGE,
    c_veracrypt,
)
from dissect.fve.veracrypt.veracrypt import VeraCrypt, is_veracrypt_volume
from tests._util import absolute_path


@pytest.mark.parametrize(
    ("mode", "type", "value", "valid"),
    [
        pytest.param(
            "aes256-sha512",
            "unlock_with_passphrase",
            "password",
            True,
            id="aes256-sha512-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_passphrase",
            "invalid-password",
            False,
            id="aes256-sha512-passphrase-invalid",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_passphrase",
            "password",
            True,
            id="aes256-sha256-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_header_key",
            bytes.fromhex(
                "5c20ecc54e499c16306781f9b300df9688ecc9221d4d9cc62af91466eed82646b3f26c3d4c647438b2b6da10ad256f29de8dca90aee8224e69621c39df3d81a7"
            ),
            True,
            id="aes256-sha512-header-key",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_header_key",
            bytes.fromhex(
                "964a320efd767801d19ab7585a1f3c000f491799979f4515b1f3b6860f244b6cd4c0482d0f6c8605f129f7ca74f06e18a624ed043d474a6c0d2452d0a5181022"
            ),
            True,
            id="aes256-sha256-header-key",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_header_key",
            b"\x00" * 64,
            False,
            id="aes256-sha256-header-key-invalid",
        ),
    ],
)
def test_veracrypt_file_container(mode: str, type: str, value: str | bytes, valid: bool) -> None:
    """Test if we can decrypt a VeraCrypt 1.26.24 (amd64, Windows) file-based container."""
    file = absolute_path(f"_data/veracrypt/{mode}.hc")
    assert is_veracrypt_volume(file.open("rb"))

    vc = VeraCrypt(file.open("rb"))
    assert not vc.unlocked
    assert not vc.is_system

    if not valid:
        with pytest.raises(ValueError, match=r"^Unable to decrypt using provided (passphrase|header keys)$"):
            getattr(vc, type)(value)
        return

    getattr(vc, type)(value)
    assert vc.unlocked
    assert vc.header
    assert vc.header.magic == b"VERA"

    stream = vc.open()
    assert b"FAT12" in stream.read(512)


@pytest.mark.parametrize(
    ("mode", "type", "value"),
    [
        pytest.param(
            "aes256-sha512",
            "unlock_with_passphrase",
            "password",
            id="aes256-sha512-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_header_key",
            bytes.fromhex(
                "9b390d357149246a1ef0766d9b327dbb422631211f6ef37f722238d4a2b5fcaf9361c57d774c386baf806c4cb5097ee455997363a65c3eb684e8bc9ad3ee11e6"
            ),
            id="aes256-sha512-header-key",
        ),
    ],
)
def test_veracrypt_system_partition(mode: str, type: str, value: str) -> None:
    """Test if we can decrypt a VeraCrypt 1.26.24 (64-bit, Windows) system partition."""
    # Mock Disk and Volume and prepare stream with correct offsets.
    file = absolute_path(f"_data/veracrypt/{mode}.system")

    stream = MappingStream(size=31744 + 512 + 64)
    stream.add(offset=0, size=31744, fh=BytesIO(b"\x01" * 31744))
    stream.add(offset=0x7C00, size=512 + 64, fh=BytesIO(file.read_bytes() + (64 * b"\x01")))

    vc = VeraCrypt(stream, is_system=True)  # type: ignore
    getattr(vc, type)(value)

    assert vc.is_system
    assert vc.unlocked
    assert vc.header
    assert vc.header.magic == b"VERA"
    assert vc.cipher == "aes-xts-256-plain64"
    assert vc.version == 5
    assert vc.client_version == 267
    assert vc.size == 0xFC4600000  # 63 GB


HEADER_KEY = bytes.fromhex(
    "5c20ecc54e499c16306781f9b300df9688ecc9221d4d9cc62af91466eed82646"
    "b3f26c3d4c647438b2b6da10ad256f29de8dca90aee8224e69621c39df3d81a7"
)


def _decrypt_header_plaintext() -> bytes:
    raw = absolute_path("_data/veracrypt/aes256-sha512.hc").read_bytes()
    return create_cipher("aes-xts-256-plain64", HEADER_KEY).decrypt(raw[64 : 64 + 512], 0)


def _build_container(mutate: Callable[[bytearray], None]) -> BytesIO:
    """Build an in-memory copy of the reference container with a mutated (re-encrypted) header."""
    raw = bytearray(absolute_path("_data/veracrypt/aes256-sha512.hc").read_bytes())
    cipher = create_cipher("aes-xts-256-plain64", HEADER_KEY)
    plaintext = bytearray(cipher.decrypt(bytes(raw[64 : 64 + 512]), 0))
    mutate(plaintext)
    raw[64 : 64 + 512] = cipher.encrypt(bytes(plaintext), 0)
    return BytesIO(bytes(raw))


def _fix_crc32s(plaintext: bytearray) -> None:
    """Recompute both CRC32s so the mutated header stays internally authenticated."""
    plaintext[8:12] = zlib.crc32(plaintext[KEY_AREA_CRC32_RANGE]).to_bytes(4, "big")
    plaintext[188:192] = zlib.crc32(plaintext[HEADER_CRC32_RANGE]).to_bytes(4, "big")


def _corrupt_key_area_crc32(plaintext: bytearray) -> None:
    plaintext[8] ^= 0xFF  # magic stays intact, key area CRC32 no longer matches


def _corrupt_header_crc32(plaintext: bytearray) -> None:
    plaintext[188] ^= 0xFF  # magic stays intact, header CRC32 no longer matches


def _unknown_version(plaintext: bytearray) -> None:
    struct.pack_into(">H", plaintext, 4, 0xFFFF)
    _fix_crc32s(plaintext)


def _invalid_sector_size(plaintext: bytearray) -> None:
    struct.pack_into(">I", plaintext, 64, 513)  # not a power of two
    _fix_crc32s(plaintext)


def _misaligned_scope(plaintext: bytearray) -> None:
    struct.pack_into(">Q", plaintext, 44, 0x20001)  # mk_scope_offset not sector aligned
    _fix_crc32s(plaintext)


def _volume_size_exceeds_scope(plaintext: bytearray) -> None:
    struct.pack_into(">Q", plaintext, 36, 0x3C0001)  # volume_size > mk_scope_size
    _fix_crc32s(plaintext)


def _oversized_scope(plaintext: bytearray) -> None:
    struct.pack_into(">Q", plaintext, 52, 0x400000)  # mk_scope_offset + mk_scope_size > stream size
    _fix_crc32s(plaintext)


def test_veracrypt_header_crc32_coverage() -> None:
    """Independently recompute both header CRC32s and confirm their exact coverage."""
    plaintext = _decrypt_header_plaintext()
    header = c_veracrypt.VolumeHeader(plaintext)

    # crc32 (absolute bytes 72-75) authenticates the key area: absolute bytes 256-511.
    assert KEY_AREA_CRC32_RANGE == slice(192, 448)
    assert int.from_bytes(header.crc32, "big") == zlib.crc32(plaintext[KEY_AREA_CRC32_RANGE])

    # crc32_decrypted (absolute bytes 252-255) authenticates the header fields: absolute bytes 64-251.
    assert HEADER_CRC32_RANGE == slice(0, 188)
    assert int.from_bytes(header.crc32_decrypted, "big") == zlib.crc32(plaintext[HEADER_CRC32_RANGE])

    # Both CRC32s only cover the 512-byte header; not a single volume data sector is authenticated.
    assert header.mk_scope_offset >= 64 + 512


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        pytest.param(_corrupt_key_area_crc32, r"key area CRC32 mismatch", id="key-area-crc32"),
        pytest.param(_corrupt_header_crc32, r"header CRC32 mismatch", id="header-crc32"),
        pytest.param(_unknown_version, r"Unsupported VeraCrypt header version", id="unknown-version"),
        pytest.param(_invalid_sector_size, r"Invalid VeraCrypt sector size", id="invalid-sector-size"),
        pytest.param(_misaligned_scope, r"master key scope is not sector aligned", id="misaligned-scope"),
        pytest.param(
            _volume_size_exceeds_scope, r"volume size exceeds the master key scope", id="volume-size-exceeds-scope"
        ),
    ],
)
def test_veracrypt_tampered_header_rejected(mutate: Callable[[bytearray], None], match: str) -> None:
    """Test that a tampered header is rejected without leaving an openable volume behind."""
    fh = _build_container(mutate)
    before = fh.getvalue()

    vc = VeraCrypt(fh)
    with pytest.raises(InvalidHeaderError, match=match):
        vc.unlock_with_header_key(HEADER_KEY)

    assert not vc.unlocked
    assert vc.header is None
    with pytest.raises(ValueError, match="Volume is locked"):
        vc.open()

    # The failed unlock must not "repair" and write back a corrected header.
    assert fh.getvalue() == before


def test_veracrypt_tampered_header_rejected_with_passphrase() -> None:
    """Test that a tampered header is also rejected through the passphrase entry point."""
    vc = VeraCrypt(_build_container(_corrupt_key_area_crc32))
    with pytest.raises(InvalidHeaderError, match=r"key area CRC32 mismatch"):
        vc.unlock_with_passphrase("password")
    assert not vc.unlocked


def test_veracrypt_data_area_out_of_bounds() -> None:
    """Test that a CRC-valid header declaring a data area beyond the stream is refused at open()."""
    vc = VeraCrypt(_build_container(_oversized_scope))
    vc.unlock_with_header_key(HEADER_KEY)
    assert vc.unlocked

    with pytest.raises(InvalidHeaderError, match=r"exceeds the stream size"):
        vc.open()
