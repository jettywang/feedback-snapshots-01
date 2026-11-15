from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from dissect.fve.crypto import create_cipher
from dissect.fve.luks.c_luks import c_luks

HEADER_SIZE = 0x4000
JSON_SIZE = HEADER_SIZE - 4096
VOLUME_KEY = bytes(range(32))
PASSPHRASE = b"synthetic-passphrase"
KDF_ITERATIONS = 1000
DIGEST_SALT = b"\x42" * 32

SEGMENT_A_OFFSET = 0x10000
SEGMENT_B_OFFSET = 0x14000
SEGMENT_SIZE = 0x1000

PLAINTEXT_A = bytes((i * 7) & 0xFF for i in range(SEGMENT_SIZE))
PLAINTEXT_B = bytes((0xFF - (i * 11)) & 0xFF for i in range(SEGMENT_SIZE))


def _keyslot_area_offset(keyslot_id: int) -> int:
    return 0x8000 + keyslot_id * 0x1000


def _keyslot(keyslot_id: int, volume_key: bytes = VOLUME_KEY) -> dict[str, str | int | dict]:
    return {
        "type": "luks2",
        "key_size": len(volume_key),
        "af": {"type": "luks1", "stripes": 1, "hash": "sha256"},
        "area": {
            "type": "raw",
            "offset": str(_keyslot_area_offset(keyslot_id)),
            "size": str(len(volume_key)),
            "encryption": "aes-ecb",
            "key_size": len(volume_key),
        },
        "kdf": {
            "type": "pbkdf2",
            "hash": "sha256",
            "iterations": KDF_ITERATIONS,
            "salt": base64.b64encode(bytes([keyslot_id + 1]) * 32).decode(),
        },
    }


def _segment(offset: int, iv_tweak: int, encryption: str, sector_size: int) -> dict[str, str | int]:
    return {
        "type": "crypt",
        "offset": str(offset),
        "size": str(SEGMENT_SIZE),
        "iv_tweak": str(iv_tweak),
        "encryption": encryption,
        "sector_size": sector_size,
    }


def _digest(key_slots: list[int], segments: list[int], volume_key: bytes = VOLUME_KEY) -> dict[str, Any]:
    return {
        "type": "pbkdf2",
        "keyslots": [str(keyslot_id) for keyslot_id in key_slots],
        "segments": [str(segment_id) for segment_id in segments],
        "hash": "sha256",
        "iterations": KDF_ITERATIONS,
        "salt": base64.b64encode(DIGEST_SALT).decode(),
        "digest": base64.b64encode(hashlib.pbkdf2_hmac("sha256", volume_key, DIGEST_SALT, KDF_ITERATIONS, 32)).decode(),
    }


def build_image(
    *,
    segments: dict[int, dict[str, Any]] | None = None,
    keyslots: dict[int, dict[str, Any]] | None = None,
    digests: dict[int, dict[str, Any]] | None = None,
    plaintexts: dict[int, bytes] | None = None,
    segment_keys: dict[int, bytes] | None = None,
    keyslot_volume_keys: dict[int, bytes] | None = None,
    image_size: int = 0x20000,
    second_header: bool = True,
) -> bytes:
    """Build a synthetic LUKS2 image with PBKDF2 keyslots and real encrypted segment data."""
    if segments is None:
        segments = {
            0: _segment(SEGMENT_A_OFFSET, 5, "aes-cbc-plain", 512),
            1: _segment(SEGMENT_B_OFFSET, 1031, "aes-cbc-plain", 512),
        }
    if keyslots is None:
        keyslots = {0: _keyslot(0)}
    if digests is None:
        digests = {0: _digest([0], list(segments))}
    if plaintexts is None:
        plaintexts = {
            segment_id: bytes((segment_id * 64 + i) & 0xFF for i in range(SEGMENT_SIZE)) for segment_id in segments
        }
    if segment_keys is None:
        segment_keys = {}
    if keyslot_volume_keys is None:
        keyslot_volume_keys = {}

    buf = bytearray(image_size)

    for keyslot_id, keyslot in keyslots.items():
        entry = json.loads(json.dumps(keyslot))
        kdf = entry["kdf"]
        if kdf["type"] != "pbkdf2":
            # Only PBKDF2 keyslots can be synthesized without the optional Argon2 implementation.
            continue

        keyslot_key = hashlib.pbkdf2_hmac(
            kdf["hash"],
            PASSPHRASE,
            base64.b64decode(kdf["salt"]),
            kdf["iterations"],
            entry["key_size"],
        )
        keyslot_volume_key = keyslot_volume_keys.get(keyslot_id, VOLUME_KEY)
        area = create_cipher("aes-ecb", keyslot_key, entry["key_size"] * 8).encrypt(keyslot_volume_key)
        area_offset = int(entry["area"]["offset"])
        buf[area_offset : area_offset + len(area)] = area

    for segment_id, plaintext in plaintexts.items():
        segment = segments[segment_id]
        cipher = create_cipher(
            segment["encryption"],
            segment_keys.get(segment_id, VOLUME_KEY),
            sector_size=int(segment["sector_size"]),
        )
        ciphertext = cipher.encrypt(plaintext, int(segment["iv_tweak"]))
        offset = int(segment["offset"])
        buf[offset : offset + len(ciphertext)] = ciphertext

    metadata = {
        "keyslots": {str(key): value for key, value in keyslots.items()},
        "tokens": {},
        "segments": {str(key): value for key, value in segments.items()},
        "digests": {str(key): value for key, value in digests.items()},
        "config": {"json_size": str(JSON_SIZE), "keyslots_size": "0"},
    }
    json_area = json.dumps(metadata).encode().ljust(JSON_SIZE, b"\x00")

    buf[0:4096] = _header(0, b"LUKS\xba\xbe")
    buf[4096 : 4096 + JSON_SIZE] = json_area

    if second_header:
        buf[HEADER_SIZE : HEADER_SIZE + 4096] = _header(HEADER_SIZE, b"SKUL\xba\xbe")
        buf[HEADER_SIZE + 4096 : HEADER_SIZE + 4096 + JSON_SIZE] = json_area

    return bytes(buf)


def _header(offset: int, magic: bytes) -> bytes:
    return bytes(
        c_luks.luks2_hdr_disk(
            magic=magic,
            version=2,
            hdr_size=HEADER_SIZE,
            seqid=1,
            label=b"",
            checksum_alg=b"sha256",
            salt=b"\x00" * 64,
            uuid=b"12345678-1234-1234-1234-123456789abc\x00",
            subsystem=b"",
            hdr_offset=offset,
        )
    )


def segment_pair() -> tuple[dict[int, dict[str, str | int]], dict[int, bytes]]:
    """Return a two-segment layout with different IV starting points and sector sizes."""
    segments = {
        0: _segment(SEGMENT_A_OFFSET, 5, "aes-cbc-plain", 512),
        1: _segment(SEGMENT_B_OFFSET, 1031, "aes-xts-plain64", 4096),
    }
    plaintexts = {0: PLAINTEXT_A, 1: PLAINTEXT_B}
    return segments, plaintexts
