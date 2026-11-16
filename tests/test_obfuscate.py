"""Contract tests for the read-only file view of :class:`ObfuscatedBeacon`.

All expectations come from short, independently crafted reference vectors
(hand-computed XOR bytes, the well-known RC4 "Key"/"Plaintext" vector, the
RFC 4648 Base64 vectors and hand-assembled LZNT1 chunks) instead of
round-tripping data through the implementation under test.
"""

import binascii
import io
import struct

import pytest

from dissect.cobaltstrike.obfuscate import ObfuscatedBeacon, ObfuscationType

# --- Reference vectors (input bytes are literals, expectations are fixed plaintext) ---

# XOR: plaintext b"CS4.11-XOR!" with repeating key b"K3y!" (hand-computed).
XOR_KEY = b"K3y!"
XOR_PLAINTEXT = b"CS4.11-XOR!"
XOR_OBFUSCATED = bytes.fromhex("08604d0f7a025479046158")
XOR_TAIL = b"\xfeTAIL-XOR!\xff"

# RC4: well-known reference vector, key "Key" / plaintext "Plaintext".
RC4_KEY = b"Key"
RC4_PLAINTEXT = b"Plaintext"
RC4_OBFUSCATED = bytes.fromhex("bbf316e8d940af0ad3")
RC4_TAIL = b"\xfeTAIL-RC4!\xff"

# BASE64: RFC 4648 test vector "Man" -> "TWFu" (encoded size != original size).
B64_PLAINTEXT = b"Man"
B64_OBFUSCATED = b"TWFu"
B64_TAIL = b"\xfeTAIL-B64!\xff"

# LZNT1: hand-assembled uncompressed chunk, header 0x3000 | (len - 1), then raw
# bytes, then a 0x0000 terminator chunk (encoded size != original size).
LZNT1_PLAINTEXT = b"HELLO-LZNT1!"
LZNT1_OBFUSCATED = bytes.fromhex("0b3048454c4c4f2d4c5a4e5431210000")
LZNT1_TAIL = b"\xfeTAIL-LZNT1!\xff"

# LZNT1: hand-assembled compressed chunk (0xB000 header) with flag byte 0x00,
# i.e. 8 literal symbols, then a 0x0000 terminator chunk.
LZNT1C_PLAINTEXT = b"ABCDEFGH"
LZNT1C_OBFUSCATED = bytes.fromhex("08b00041424344454647480000")
LZNT1C_TAIL = b"\xfeTAIL-LZNT1C!\xff"


def build_stage(
    obfuscation_type: int,
    key: bytes,
    payload: bytes,
    original_size: int,
    key_size: int | None = None,
    payload_size: int | None = None,
    tail: bytes = b"",
) -> bytes:
    """Build a StageObfuscateSettings blob followed by key, payload and shell tail."""
    key_size = len(key) if key_size is None else key_size
    payload_size = len(payload) if payload_size is None else payload_size
    header = struct.pack("<IIII", obfuscation_type, key_size, original_size, payload_size)
    return header + key + payload + tail


def make_view(blob: bytes, offset: int = 0) -> ObfuscatedBeacon:
    return ObfuscatedBeacon(io.BytesIO(blob), offset=offset)


VECTORS = [
    pytest.param(
        ObfuscationType.OBFUSCATION_XOR,
        XOR_KEY,
        XOR_OBFUSCATED,
        XOR_PLAINTEXT,
        XOR_TAIL,
        id="xor",
    ),
    pytest.param(
        ObfuscationType.OBFUSCATION_RC4,
        RC4_KEY,
        RC4_OBFUSCATED,
        RC4_PLAINTEXT,
        RC4_TAIL,
        id="rc4",
    ),
    pytest.param(
        ObfuscationType.OBFUSCATION_BASE64,
        b"",
        B64_OBFUSCATED,
        B64_PLAINTEXT,
        B64_TAIL,
        id="base64",
    ),
    pytest.param(
        ObfuscationType.OBFUSCATION_LZNT1,
        b"",
        LZNT1_OBFUSCATED,
        LZNT1_PLAINTEXT,
        LZNT1_TAIL,
        id="lznt1-uncompressed-chunk",
    ),
    pytest.param(
        ObfuscationType.OBFUSCATION_LZNT1,
        b"",
        LZNT1C_OBFUSCATED,
        LZNT1C_PLAINTEXT,
        LZNT1C_TAIL,
        id="lznt1-compressed-chunk",
    ),
]


@pytest.mark.parametrize(("obfuscation_type", "key", "payload", "plaintext", "tail"), VECTORS)
def test_read_matches_declared_payload_boundary(obfuscation_type, key, payload, plaintext, tail):
    """The view deobfuscates exactly payload_size bytes; the shell tail stays out."""
    blob = build_stage(obfuscation_type, key, payload, original_size=len(plaintext), tail=tail)
    obf = make_view(blob)

    assert obf.settings.payload_size == len(payload)
    assert obf.read() == plaintext
    assert len(obf.deobfuscated_payload) == obf.settings.original_size
    # The shell tail is trailing data past the declared payload boundary.
    assert obf.leftover == tail
    assert tail not in obf.deobfuscated_payload


@pytest.mark.parametrize(("obfuscation_type", "key", "payload", "plaintext", "tail"), VECTORS)
def test_interleaved_seek_and_short_reads(obfuscation_type, key, payload, plaintext, tail):
    """Interleaved seeks, short reads and reads past EOF never change the content."""
    blob = build_stage(obfuscation_type, key, payload, original_size=len(plaintext), tail=tail)
    obf = make_view(blob)

    # Short reads reassemble into the reference plaintext.
    chunks = []
    while chunk := obf.read(2):
        chunks.append(chunk)
    assert b"".join(chunks) == plaintext
    # At EOF further reads stay empty.
    assert obf.read(1) == b""

    # Seeking around and re-reading yields the same bytes.
    assert obf.seek(1) == 1
    assert obf.read(3) == plaintext[1:4]
    assert obf.seek(-2, io.SEEK_END) == len(plaintext) - 2
    assert obf.read() == plaintext[-2:]
    assert obf.seek(1, io.SEEK_CUR) == len(plaintext) + 1
    assert obf.read(1) == b""

    # Full re-read after seeking back is identical and free of shell tail bytes.
    obf.seek(0)
    assert obf.read() == plaintext
    assert tail not in plaintext


@pytest.mark.parametrize(("obfuscation_type", "key", "payload", "plaintext", "tail"), VECTORS)
def test_view_is_bounded_at_nonzero_offset(obfuscation_type, key, payload, plaintext, tail):
    """A prefix before the settings struct does not disturb the payload boundary."""
    prefix = b"\x90" * 7
    blob = prefix + build_stage(obfuscation_type, key, payload, original_size=len(plaintext), tail=tail)
    obf = make_view(blob, offset=len(prefix))

    assert obf.read() == plaintext
    assert obf.leftover == tail


def test_original_size_differs_from_encoded_size():
    """Base64 and LZNT1 declare an original size different from the encoded size."""
    for obfuscation_type, payload, plaintext in (
        (ObfuscationType.OBFUSCATION_BASE64, B64_OBFUSCATED, B64_PLAINTEXT),
        (ObfuscationType.OBFUSCATION_LZNT1, LZNT1_OBFUSCATED, LZNT1_PLAINTEXT),
    ):
        blob = build_stage(obfuscation_type, b"", payload, original_size=len(plaintext))
        obf = make_view(blob)

        assert obf.settings.original_size != obf.settings.payload_size
        assert obf.read() == plaintext
        assert len(obf.deobfuscated_payload) == obf.settings.original_size


def test_truncated_key_material_is_not_full_recovery():
    """A file ending inside the declared key material cannot yield the full config."""
    declared_key_size = 16
    declared_original_size = 32
    partial_key = b"\x01\x02\x03\x04\x05"
    blob = build_stage(
        ObfuscationType.OBFUSCATION_XOR,
        partial_key,
        payload=b"",
        original_size=declared_original_size,
        key_size=declared_key_size,
        payload_size=declared_original_size,
    )
    obf = make_view(blob)

    # The key material is truncated and no payload bytes remain.
    assert len(obf.key) < obf.settings.key_size
    assert obf.read() == b""
    # The view must not be mistaken for a fully recovered config.
    assert len(obf.deobfuscated_payload) != obf.settings.original_size


def test_truncated_payload_is_not_full_recovery():
    """A payload shorter than declared only yields a partial deobfuscation."""
    declared_payload_size = 16
    partial_payload = XOR_OBFUSCATED[:6]
    blob = build_stage(
        ObfuscationType.OBFUSCATION_XOR,
        XOR_KEY,
        partial_payload,
        original_size=declared_payload_size,
        payload_size=declared_payload_size,
    )
    obf = make_view(blob)

    recovered = obf.read()
    assert recovered == XOR_PLAINTEXT[:6]
    assert len(recovered) < obf.settings.original_size


def test_truncated_lznt1_payload_is_not_full_recovery():
    """A cut-off LZNT1 stream decompresses to less than the declared original size."""
    blob = build_stage(
        ObfuscationType.OBFUSCATION_LZNT1,
        b"",
        LZNT1_OBFUSCATED[:5],
        original_size=len(LZNT1_PLAINTEXT),
        payload_size=len(LZNT1_OBFUSCATED),
    )
    obf = make_view(blob)

    recovered = obf.read()
    assert recovered == LZNT1_PLAINTEXT[:3]
    assert len(recovered) < obf.settings.original_size


def test_decoded_length_contradicts_declared_original_size():
    """The view exposes the actual decoded length, not the declared original size."""
    blob = build_stage(
        ObfuscationType.OBFUSCATION_BASE64,
        b"",
        B64_OBFUSCATED,
        original_size=64,  # contradicts the 3 bytes that "TWFu" decodes to
    )
    obf = make_view(blob)

    recovered = obf.read()
    assert recovered == B64_PLAINTEXT
    assert len(recovered) != obf.settings.original_size


def test_undecodable_base64_raises_instead_of_partial_view():
    """Undecodable input fails loudly instead of posing as a recovered config."""
    blob = build_stage(
        ObfuscationType.OBFUSCATION_BASE64,
        b"",
        b"abc",  # invalid padding, cannot be decoded
        original_size=16,
    )
    with pytest.raises(binascii.Error):
        make_view(blob)


def test_unknown_obfuscation_type_raises():
    blob = build_stage(99, b"", b"payload", original_size=7)
    with pytest.raises(ValueError, match="Unknown obfuscation type"):
        make_view(blob)
