from __future__ import annotations

import base64
import hashlib
import io
import json

import pytest

from dissect.fve.crypto import create_cipher
from dissect.fve.luks.luks import LUKS
from dissect.fve.luks.metadata import Digest, Keyslot, SegmentIntegrity

HDR_SIZE = 0x4000
JSON_SIZE = HDR_SIZE - 4096
KEYSLOT_OFFSET = HDR_SIZE * 2
KEYSLOT_SIZE = 0x8000
DATA_OFFSET = 0x10000

VOLUME_KEY = bytes(range(32))
PASSPHRASE_SALT = b"S" * 32
KEYSLOT_SALT = b"K" * 32
DIGEST_ITERATIONS = 10
KDF_ITERATIONS = 10

UUID = "12345678-1234-1234-1234-123456789abc"


def _header(magic: bytes, offset: int) -> bytes:
    buf = bytearray(4096)
    buf[0:6] = magic
    buf[6:8] = (2).to_bytes(2, "big")
    buf[8:16] = HDR_SIZE.to_bytes(8, "big")
    buf[16:24] = (1).to_bytes(8, "big")
    buf[24:72] = b"segment-test".ljust(48, b"\x00")
    buf[72:104] = b"sha256".ljust(32, b"\x00")
    buf[168:208] = UUID.encode().ljust(40, b"\x00")
    buf[256:264] = offset.to_bytes(8, "big")
    return bytes(buf)


def _digest(key: bytes, keyslots: list[str] | None = None, segments: list[str] | None = None) -> dict:
    return {
        "type": "pbkdf2",
        "keyslots": keyslots if keyslots is not None else ["0"],
        "segments": segments if segments is not None else ["0", "1"],
        "hash": "sha256",
        "iterations": DIGEST_ITERATIONS,
        "salt": base64.b64encode(PASSPHRASE_SALT).decode(),
        "digest": base64.b64encode(hashlib.pbkdf2_hmac("sha256", key, PASSPHRASE_SALT, DIGEST_ITERATIONS, 32)).decode(),
    }


def _keyslot(key_size: int = 32) -> dict:
    return {
        "type": "luks2",
        "key_size": key_size,
        "area": {
            "type": "raw",
            "offset": str(KEYSLOT_OFFSET),
            "size": str(KEYSLOT_SIZE),
            "encryption": "aes-ecb",
            "key_size": key_size,
        },
        "kdf": {
            "type": "pbkdf2",
            "salt": base64.b64encode(KEYSLOT_SALT).decode(),
            "hash": "sha256",
            "iterations": KDF_ITERATIONS,
        },
        "af": {"type": "luks1", "stripes": 1, "hash": "sha256"},
    }


def _segment(offset: int, size: int | str, iv_tweak: int, sector_size: int = 512, **kwargs) -> dict:
    result = {
        "type": "crypt",
        "offset": str(offset),
        "size": str(size),
        "iv_tweak": str(iv_tweak),
        "encryption": "aes-cbc-plain64",
        "sector_size": sector_size,
    }
    result.update(kwargs)
    return result


def _encrypt(data: bytes, iv_tweak: int, cipher: str = "aes-cbc-plain64", sector_size: int = 512) -> bytes:
    cipher_obj = create_cipher(cipher, VOLUME_KEY, 256, sector_size, 512)
    result = bytearray(len(data))
    for offset in range(0, len(data), sector_size):
        block = data[offset : offset + sector_size]
        result[offset : offset + len(block)] = cipher_obj.encrypt(block, iv_tweak + offset // 512)
    return bytes(result)


def _build(
    segments: dict[str, dict],
    plaintext: dict[str, bytes],
    *,
    digests: dict[str, dict] | None = None,
    keyslots: dict[str, dict] | None = None,
    total_size: int | None = None,
    gap: bytes | None = None,
) -> io.BytesIO:
    metadata = {
        "config": {"json_size": str(JSON_SIZE), "keyslots_size": str(KEYSLOT_SIZE)},
        "keyslots": keyslots or {"0": _keyslot()},
        "digests": digests or {"0": _digest(VOLUME_KEY)},
        "segments": segments,
        "tokens": {},
    }

    size = total_size or DATA_OFFSET + 0x6000
    buf = bytearray(size) if gap is None else bytearray(gap * size)
    for segment_id, segment in segments.items():
        if segment["type"] != "crypt":
            continue
        length = segment["size"]
        if isinstance(length, str) and length.isdigit():
            length = int(length)
        if not isinstance(length, int) or isinstance(length, bool):
            continue
        if segment_id not in plaintext:
            continue
        offset = int(segment["offset"])
        encrypted = _encrypt(
            plaintext[segment_id][:length],
            int(segment["iv_tweak"]),
            segment["encryption"],
            segment["sector_size"],
        )
        buf[offset : offset + length] = encrypted

    json_area = json.dumps(metadata, separators=(",", ":")).encode().ljust(JSON_SIZE, b"\x00")
    buf[0:4096] = _header(b"LUKS\xba\xbe", 0)
    buf[4096:HDR_SIZE] = json_area
    buf[HDR_SIZE : HDR_SIZE + 4096] = _header(b"SKUL\xba\xbe", HDR_SIZE)
    buf[HDR_SIZE + 4096 : HDR_SIZE * 2] = json_area

    return io.BytesIO(bytes(buf))


def _two_segment_image() -> tuple[io.BytesIO, dict[str, bytes]]:
    # Logical order is segment 0 then 1, physical order is deliberately reversed.
    # Different IV starts prove each segment is decrypted with its own IV.
    plaintext = {
        "0": bytes([0x11]) * 1536,
        "1": bytes([0x22]) * 1536,
    }
    segments = {
        "0": _segment(DATA_OFFSET + 0x2000, 1536, 0),
        "1": _segment(DATA_OFFSET, 1536, 1000),
    }
    return _build(segments, plaintext), plaintext


def _unlocked(fh: io.BytesIO) -> LUKS:
    volume = LUKS(fh)
    volume.unlock(VOLUME_KEY, 0)
    return volume


def test_open_segments_sequential_and_random_reads() -> None:
    fh, plaintext = _two_segment_image()
    volume = _unlocked(fh)
    stream = volume.open_segments()

    expected = plaintext["0"] + plaintext["1"]
    assert stream.size == len(expected)
    assert stream.read() == expected

    # The logical view must not leak the physical gap between the two segments.
    stream.seek(0)
    assert b"\x00" * 32 not in stream.read()

    # Cross the segment boundary at every possible alignment, including unaligned offsets.
    for offset in range(len(plaintext["0"]) - 8, len(plaintext["0"]) + 8):
        for length in (1, 3, 17, 511, 512, 513, 1024):
            stream.seek(offset)
            assert stream.read(length) == expected[offset : offset + length], (offset, length)

    # Random-shaped reads entirely inside each segment.
    for offset, length in ((0, 1), (5, 500), (511, 2), (1000, 600), (1535, 1), (1536, 1), (2000, 700), (3000, 72)):
        stream.seek(offset)
        assert stream.read(length) == expected[offset : offset + length], (offset, length)


def test_open_segments_keeps_per_segment_parameters() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    stream = volume.open_segments()

    assert [(segment.id, segment.offset, segment.size, segment.iv_tweak) for segment in stream.segments] == [
        (0, DATA_OFFSET + 0x2000, 1536, 0),
        (1, DATA_OFFSET, 1536, 1000),
    ]
    assert stream.segment_for_offset(0).id == 0
    assert stream.segment_for_offset(1535).id == 0
    assert stream.segment_for_offset(1536).id == 1
    assert stream.segment_for_offset(3071).id == 1
    assert stream.segment_for_offset(3072) is None


def test_open_segments_handles_larger_sector_size() -> None:
    plaintext = {"0": bytes([0x33]) * 4096, "1": bytes([0x44]) * 4096}
    segments = {
        "0": _segment(DATA_OFFSET, 4096, 7, sector_size=4096),
        "1": _segment(DATA_OFFSET + 0x2000, 4096, 100000, sector_size=4096),
    }
    volume = _unlocked(_build(segments, plaintext))
    stream = volume.open_segments()

    expected = plaintext["0"] + plaintext["1"]
    assert stream.read() == expected

    # Sub-sector and cross-boundary reads still use each segment's own sector size and IV.
    for offset, length in ((1, 10), (4090, 12), (4096, 4096), (5000, 500)):
        stream.seek(offset)
        assert stream.read(length) == expected[offset : offset + length], (offset, length)


def test_open_segments_single_segment_matches_open() -> None:
    plaintext = {"0": bytes([0x55]) * 1536}
    segments = {"0": _segment(DATA_OFFSET, 1536, 42)}
    digests = {"0": _digest(VOLUME_KEY, segments=["0"])}
    volume = _unlocked(_build(segments, plaintext, digests=digests))

    assert volume.open().read() == plaintext["0"]
    assert volume.open_segments().read() == plaintext["0"]
    assert len(volume.find_segments(0)) == 1


def test_open_segments_read_only_and_bounded() -> None:
    fh, plaintext = _two_segment_image()
    stream = _unlocked(fh).open_segments()

    with pytest.raises(io.UnsupportedOperation):
        stream.write(b"x")
    with pytest.raises(io.UnsupportedOperation):
        stream.truncate()

    stream.seek(stream.size)
    assert stream.read() == b""
    stream.seek(stream.size + 100)
    assert stream.read(10) == b""


def test_open_segments_rejects_overlapping_segments() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.segments[1].offset = volume.metadata.segments[0].offset + 1024

    with pytest.raises(ValueError, match="overlap"):
        volume.open_segments()


def test_open_segments_rejects_missing_digest_binding() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.digests[0].segments = [0]

    with pytest.raises(ValueError, match="does not bind all volume segments"):
        volume.open_segments()


def test_open_segments_rejects_digest_without_segments() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.digests[0].segments = []

    with pytest.raises(ValueError, match="no segment binding"):
        volume.open_segments()


def test_open_segments_rejects_missing_digest() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.digests.clear()

    with pytest.raises(ValueError, match="No digest binding"):
        volume.open_segments()


def test_open_segments_rejects_segment_referenced_by_another_digest() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.digests[1] = Digest.from_dict(_digest(b"\x00" * 32, keyslots=["1"], segments=["1"]))
    volume.metadata.keyslots[1] = Keyslot.from_dict(_keyslot())

    with pytest.raises(ValueError, match="multiple digests"):
        volume.open_segments()


def test_open_segments_rejects_different_key_evidence_for_segment() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)

    # A second keyslot and digest use a different volume key but claim segment 1.
    other_key_digest = _digest(b"\xff" * 32, keyslots=["1"], segments=["1"])
    volume.metadata.digests[1] = Digest.from_dict(other_key_digest)
    volume.metadata.keyslots[1] = Keyslot.from_dict(_keyslot())

    with pytest.raises(ValueError, match="multiple digests"):
        volume.open_segments()


def test_open_segments_rejects_dynamic_segment_swallowing_another_segment() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)

    # Segment 1 is physically first; a dynamic size would extend over segment 0.
    volume.metadata.segments[1].size = "dynamic"

    with pytest.raises(ValueError, match="overlap"):
        volume.open_segments()


def test_open_segments_accepts_trailing_dynamic_segment() -> None:
    plaintext = {"0": bytes([0x21]) * 1536, "1": bytes([0x22]) * 1024}
    segments = {
        "0": _segment(DATA_OFFSET, 1536, 0),
        "1": _segment(DATA_OFFSET + 0x2000, 1024, 90),
    }
    volume = _unlocked(_build(segments, plaintext, total_size=DATA_OFFSET + 0x2000 + 1024))
    volume.metadata.segments[1].size = "dynamic"

    stream = volume.open_segments()
    assert stream.size == 1536 + 1024
    assert stream.read() == plaintext["0"] + plaintext["1"]


def test_open_segments_rejects_segment_beyond_backing_size() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.segments[1].offset = fh.getbuffer().nbytes - 512

    with pytest.raises(ValueError, match="extends beyond the backing volume"):
        volume.open_segments()


def test_open_segments_rejects_indeterminate_segment_size() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.segments[1].size = "unbounded"

    with pytest.raises(ValueError, match="indeterminate"):
        volume.open_segments()


def test_open_segments_rejects_unsupported_segment_metadata() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.segments[1].flags = ["in-reencryption"]

    with pytest.raises(NotImplementedError, match="unsupported flags"):
        volume.open_segments()

    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.segments[1].type = "integrity"

    with pytest.raises(NotImplementedError, match="Unsupported segment type"):
        volume.open_segments()


def test_open_segments_allows_non_aligned_physical_offset() -> None:
    plaintext = {"0": bytes([0x31]) * 512, "1": bytes([0x32]) * 512}
    segments = {
        "0": _segment(DATA_OFFSET + 3, 512, 0),
        "1": _segment(DATA_OFFSET + 0x1000 + 5, 512, 77),
    }
    volume = _unlocked(_build(segments, plaintext))
    assert volume.open_segments().read() == plaintext["0"] + plaintext["1"]


def test_open_segments_rejects_locked_volume() -> None:
    fh, _ = _two_segment_image()
    with pytest.raises(ValueError, match="locked"):
        LUKS(fh).open_segments()


def test_open_segments_ignores_physical_gap() -> None:
    plaintext = {"0": bytes([0x66]) * 1536, "1": bytes([0x77]) * 1536}
    segments = {
        "0": _segment(DATA_OFFSET, 1536, 0),
        "1": _segment(DATA_OFFSET + 0x4000, 1536, 77),
    }
    fh = _build(segments, plaintext, gap=b"\xaa")
    stream = _unlocked(fh).open_segments()

    data = stream.read()
    assert data == plaintext["0"] + plaintext["1"]
    assert b"\xaa" not in data
    assert b"\x00" not in data


def test_open_uses_segmented_view_for_multiple_segments() -> None:
    fh, plaintext = _two_segment_image()
    volume = _unlocked(fh)

    assert volume.open().read() == plaintext["0"] + plaintext["1"]
    with pytest.raises(NotImplementedError, match="more than one segment"):
        volume.find_segment(0)


def test_open_segments_real_fixture_reencrypted_into_two_ciphers() -> None:
    import gzip
    from pathlib import Path

    fixture = Path(__file__).parent.parent / "_data" / "luks2" / "aes-ecb-pbkdf2.bin.gz"
    with gzip.open(fixture, "rb") as fh:
        raw = bytearray(fh.read())

    volume = LUKS(io.BytesIO(bytes(raw)))
    volume.unlock_with_passphrase("password")
    volume_key = volume._active_volume_key

    data_offset = volume.metadata.segments[0].offset
    plaintext = volume.open().read()
    split = 1024

    def encrypt(data: bytes, iv_tweak: int, cipher: str) -> bytes:
        cipher_obj = create_cipher(cipher, volume_key, len(volume_key) * 8, 512, 512)
        result = bytearray(len(data))
        for offset in range(0, len(data), 512):
            block = data[offset : offset + 512]
            result[offset : offset + len(block)] = cipher_obj.encrypt(block, iv_tweak + offset // 512)
        return bytes(result)

    first = encrypt(plaintext[:split], 0, "aes-cbc-plain64")
    second = encrypt(plaintext[split:], 12345, "aes-cbc-plain")
    raw[data_offset : data_offset + split] = first
    raw[data_offset + split : data_offset + len(plaintext)] = second

    volume = LUKS(io.BytesIO(bytes(raw)))
    volume.unlock_with_passphrase("password")
    volume.metadata.segments[0].size = split
    volume.metadata.segments[0].encryption = "aes-cbc-plain64"
    volume.metadata.segments[1] = type(volume.metadata.segments[0]).from_dict(
        {
            "type": "crypt",
            "offset": str(data_offset + split),
            "size": str(len(plaintext) - split),
            "iv_tweak": "12345",
            "encryption": "aes-cbc-plain",
            "sector_size": 512,
        }
    )
    volume.metadata.digests[0].segments = [0, 1]

    stream = volume.open_segments()
    assert stream.read() == plaintext
    stream.seek(split - 10)
    assert stream.read(20) == plaintext[split - 10 : split + 10]


def test_open_refuses_unsupported_multi_segment_layout() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.segments[1].integrity = SegmentIntegrity.from_dict(
        {"type": "aead", "journal_encryption": "none", "journal_integrity": "none"}
    )

    with pytest.raises(NotImplementedError, match="integrity"):
        volume.open()
    with pytest.raises(NotImplementedError, match="integrity"):
        volume.open_segments()


def test_open_segments_rejects_digest_with_mixed_keyslot_key_sizes() -> None:
    fh, _ = _two_segment_image()
    volume = _unlocked(fh)
    volume.metadata.keyslots[1] = Keyslot.from_dict(_keyslot(key_size=64))
    volume.metadata.digests[0].keyslots = [0, 1]

    with pytest.raises(ValueError, match="different key sizes"):
        volume.open_segments()
