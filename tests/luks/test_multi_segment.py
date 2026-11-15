from __future__ import annotations

import io

import pytest

from dissect.fve.crypto.dmcrypt import CryptStream, MultiSegmentStream
from dissect.fve.exception import UnsupportedLayoutError
from dissect.fve.luks import LUKS
from tests.luks._synthetic import (
    PLAINTEXT_A,
    PLAINTEXT_B,
    SEGMENT_A_OFFSET,
    SEGMENT_B_OFFSET,
    SEGMENT_SIZE,
    VOLUME_KEY,
    build_image,
    segment_pair,
)


def _open(data: bytes) -> LUKS:
    luks = LUKS(io.BytesIO(data))
    luks.unlock(VOLUME_KEY, 0)
    return luks


def _segment(offset: int, iv_tweak: int, encryption: str = "aes-cbc-plain", sector_size: int = 512) -> dict:
    return {
        "type": "crypt",
        "offset": str(offset),
        "size": str(SEGMENT_SIZE),
        "iv_tweak": str(iv_tweak),
        "encryption": encryption,
        "sector_size": sector_size,
    }


def test_multi_segment_sequential_read() -> None:
    segments, plaintexts = segment_pair()
    stream = _open(build_image(segments=segments, plaintexts=plaintexts)).open()

    assert isinstance(stream, MultiSegmentStream)
    assert stream.size == 2 * SEGMENT_SIZE
    assert stream.read(SEGMENT_SIZE) == PLAINTEXT_A
    assert stream.read(SEGMENT_SIZE) == PLAINTEXT_B
    assert stream.read(SEGMENT_SIZE) == b""


def test_multi_segment_cross_boundary_random_reads() -> None:
    segments, plaintexts = segment_pair()
    expected = PLAINTEXT_A + PLAINTEXT_B
    stream = _open(build_image(segments=segments, plaintexts=plaintexts)).open()

    # Every start offset around the boundary, with lengths that end before, exactly on and after the boundary.
    for offset in (0, 1, 511, 512, 513, SEGMENT_SIZE - 1, SEGMENT_SIZE, SEGMENT_SIZE + 1, 2 * SEGMENT_SIZE - 1):
        for length in (1, 511, 512, 513, SEGMENT_SIZE):
            stream.seek(offset)
            assert stream.read(length) == expected[offset : offset + length], (offset, length)

    # A single read spanning both segments.
    stream.seek(0)
    assert stream.read() == expected


def test_multi_segment_read_does_not_spill_into_unsupported_area() -> None:
    segments, plaintexts = segment_pair()
    stream = _open(build_image(segments=segments, plaintexts=plaintexts)).open()

    stream.seek(SEGMENT_SIZE - 16)
    data = stream.read(32)
    assert data == PLAINTEXT_A[-16:] + PLAINTEXT_B[:16]

    stream.seek(2 * SEGMENT_SIZE)
    assert stream.read(64) == b""
    assert stream.peek(64) == b""


def test_multi_segment_preserves_individual_iv_offsets() -> None:
    # Both segments contain the same plaintext, but are encrypted with different IV starting points and sector sizes.
    # A stream that reuses the first segment's parameters would produce different plaintext for the second segment.
    plaintext = PLAINTEXT_A
    segments = {
        0: _segment(SEGMENT_A_OFFSET, 5),
        1: _segment(SEGMENT_B_OFFSET, 12345, "aes-cbc-plain", 4096),
    }
    stream = _open(build_image(segments=segments, plaintexts={0: plaintext, 1: plaintext})).open()

    assert stream.read(SEGMENT_SIZE) == plaintext
    assert stream.read(SEGMENT_SIZE) == plaintext


def test_single_segment_api_unchanged() -> None:
    segments = {0: _segment(SEGMENT_A_OFFSET, 5)}
    stream = _open(build_image(segments=segments, plaintexts={0: PLAINTEXT_A})).open()

    assert isinstance(stream, CryptStream)
    assert stream.read() == PLAINTEXT_A


def test_multi_segment_overlap_rejected() -> None:
    segments = {
        0: _segment(SEGMENT_B_OFFSET - 512, 5),
        1: _segment(SEGMENT_B_OFFSET, 5),
    }
    luks = _open(build_image(segments=segments, digests={0: _digest([0], [0, 1])}))

    with pytest.raises(UnsupportedLayoutError, match="overlap"):
        luks.open()


def test_multi_segment_missing_digest_binding_rejected() -> None:
    segments = {
        0: _segment(SEGMENT_A_OFFSET, 5),
        1: _segment(SEGMENT_B_OFFSET, 5),
    }
    luks = _open(build_image(segments=segments, digests={0: _digest([0], [0])}))

    with pytest.raises(UnsupportedLayoutError, match="has no digest binding"):
        luks.open()


def test_multi_segment_different_keys_rejected() -> None:
    segments = {
        0: _segment(SEGMENT_A_OFFSET, 5),
        1: _segment(SEGMENT_B_OFFSET, 5),
    }
    other_volume_key = bytes(range(32, 64))
    digests = {
        0: _digest([0], [0], VOLUME_KEY),
        1: _digest([1], [1], other_volume_key),
    }
    luks = _open(build_image(segments=segments, digests=digests, keyslots={0: _keyslot(0)}))

    # The second segment's only binding is a digest that the active key does not verify.
    with pytest.raises(UnsupportedLayoutError, match="not verified with the active volume key"):
        luks.open()


def test_multi_segment_dynamic_size_rejected() -> None:
    first = _segment(SEGMENT_A_OFFSET, 5)
    second = _segment(SEGMENT_B_OFFSET, 5)
    second["size"] = "dynamic"
    segments = {0: first, 1: second}
    luks = _open(build_image(segments=segments, digests={0: _digest([0], [0, 1])}))

    with pytest.raises(UnsupportedLayoutError, match="dynamic size"):
        luks.open()


def test_multi_segment_keyslot_overlap_rejected() -> None:
    # Place a segment over the keyslot area.
    segments = {
        0: _segment(0x8000, 5),
        1: _segment(SEGMENT_B_OFFSET, 5),
    }
    luks = _open(build_image(segments=segments, digests={0: _digest([0], [0, 1])}))

    with pytest.raises(UnsupportedLayoutError, match="keyslot"):
        luks.open()


def test_multi_segment_unknown_segment_rejected() -> None:
    segments = {
        0: _segment(SEGMENT_A_OFFSET, 5),
        1: _segment(SEGMENT_B_OFFSET, 5),
    }
    # Digest references a segment that does not exist in the metadata.
    digests = {0: _digest([0], [0, 1, 2])}
    luks = _open(build_image(segments=segments, digests=digests))

    with pytest.raises(UnsupportedLayoutError, match="not present in the metadata"):
        luks.open()


def test_multi_segment_unverified_digest_rejected() -> None:
    segments = {
        0: _segment(SEGMENT_A_OFFSET, 5),
        1: _segment(SEGMENT_B_OFFSET, 5),
    }
    other_volume_key = bytes(range(32, 64))
    digests = {
        0: _digest([0], [0, 1], VOLUME_KEY),
        1: _digest([0], [1], other_volume_key),
    }
    luks = _open(build_image(segments=segments, digests=digests))

    with pytest.raises(UnsupportedLayoutError, match="not verified with the active volume key"):
        luks.open()


def test_multi_segment_keyslot_alternate_layout_rejected() -> None:
    segments = {
        0: _segment(SEGMENT_A_OFFSET, 5),
        1: _segment(SEGMENT_B_OFFSET, 5),
    }
    other_volume_key = bytes(range(32, 64))
    digests = {
        0: _digest([0], [0, 1], VOLUME_KEY),
        1: _digest([0], [0], other_volume_key),
    }
    luks = _open(build_image(segments=segments, digests=digests))

    # The same keyslot is bound to an alternate, unverified layout, so the layout is ambiguous.
    with pytest.raises(UnsupportedLayoutError, match="also bound to digest"):
        luks.open()


def test_multi_segment_conflicting_verified_digests_rejected() -> None:
    segments = {
        0: _segment(SEGMENT_A_OFFSET, 5),
        1: _segment(SEGMENT_B_OFFSET, 5),
    }
    digests = {
        0: _digest([0], [0], VOLUME_KEY),
        1: _digest([0], [1], VOLUME_KEY),
    }
    luks = _open(build_image(segments=segments, digests=digests))

    with pytest.raises(UnsupportedLayoutError, match="conflicting segment layouts"):
        luks.open()


def test_multi_segment_logical_order_follows_segment_ids() -> None:
    # Segment 0 lives at the higher physical offset, but logical order is defined by segment ID.
    segments = {
        0: _segment(SEGMENT_B_OFFSET, 5),
        1: _segment(SEGMENT_A_OFFSET, 77),
    }
    plaintexts = {0: PLAINTEXT_A, 1: PLAINTEXT_B}
    stream = _open(build_image(segments=segments, plaintexts=plaintexts)).open()

    assert stream.read(SEGMENT_SIZE) == PLAINTEXT_A
    assert stream.read(SEGMENT_SIZE) == PLAINTEXT_B


def test_open_multi_explicit_on_single_segment() -> None:
    segments = {0: _segment(SEGMENT_A_OFFSET, 5)}
    luks = _open(build_image(segments=segments, plaintexts={0: PLAINTEXT_A}))

    assert isinstance(luks.open(), CryptStream)

    stream = luks.open_multi()
    assert isinstance(stream, MultiSegmentStream)
    assert stream.read() == PLAINTEXT_A


def test_multi_segment_requires_unlock() -> None:
    luks = LUKS(io.BytesIO(build_image()))

    with pytest.raises(ValueError, match="locked"):
        luks.open()

    with pytest.raises(ValueError, match="locked"):
        luks.open_multi()


def _digest(keyslots: list[int], segments: list[int], volume_key: bytes = VOLUME_KEY) -> dict:
    from tests.luks._synthetic import _digest as build_digest

    return build_digest(keyslots, segments, volume_key)


def _keyslot(keyslot_id: int) -> dict:
    from tests.luks._synthetic import _keyslot as build_keyslot

    return build_keyslot(keyslot_id)
