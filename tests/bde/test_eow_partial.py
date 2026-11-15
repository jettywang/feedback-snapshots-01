from __future__ import annotations

import gzip
import hashlib
import io
import struct
from binascii import crc32
from contextlib import contextmanager
from typing import TYPE_CHECKING

import pytest

from dissect.fve.bde import bde
from dissect.fve.bde.c_bde import CIPHER_MAP, EOW_BM_SIGNATURE, EOW_BR_SIGNATURE
from dissect.fve.crypto import create_cipher
from dissect.fve.exception import UnknownStateError
from tests._util import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import BinaryIO

    from dissect.fve.bde.c_bde import FVE_KEY_TYPE
    from dissect.fve.crypto.base import Cipher

IMAGE_PATH = "_data/bde/eow_partial.bin.gz"
IMAGE_SHA256 = "a6324af56d6f1a269c1cf08dce0edce33e234cd1c10ff51aad77f9bfb9034a3e"
IMAGE_DATA_SHA256 = "09c9ae5e9ae6e5c2a42f6eeb98bb2f126b6552789cd91ee28d87597f642475c7"
IMAGE_SIZE = 361004032
PASSPHRASE = "password12!@"

SECTOR_SIZE = 512
CHUNK_SIZE = 0x800000
CHUNKS_PER_BITMAP = 33

# The second bitmap of the image starts at this offset and describes a region of 33 chunks.
BITMAP2_OFFSET = 0x15640000
REGION2_OFFSET = 0x2202000
REGION2_SIZE = 0x101EE000

# Independent expected states for the real bitmap. The bitmap bytes are 00 00 f0 ff ff ff ff ff with a bitmap size
# of 33 bits, so chunks 0-19 are plain text and chunks 20-32 are encrypted. This list is asserted against the raw
# record in test_eow_real_bitmap_states_match_independent_list, the tests below never derive it from _iter_run_state.
REGION2_STATES = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
]  # fmt: skip

# Independent expected byte segments for region 2. Plain text is read from the image as-is, encrypted chunks must be
# decrypted with the FVEK. Chunk 20 starts at 0xc202000, chunk 32 is the last (partial) chunk of the region. These
# segments are an independent list, not generated from the stream under test.
REGION2_SEGMENTS = [
    (False, REGION2_OFFSET, 20 * CHUNK_SIZE),
    (True, REGION2_OFFSET + 20 * CHUNK_SIZE, REGION2_SIZE - 20 * CHUNK_SIZE),
]
REGION3_SEGMENTS = [(True, 0x123F0000, 0x10000000)]


class Overlay(io.RawIOBase):
    """Read-only view over an image with a number of patched ranges."""

    def __init__(self, fh: BinaryIO, size: int, patches: list[tuple[int, bytes]]):
        self.fh = fh
        self._size = size
        self._pos = 0
        self._patches = sorted(patches)

    @property
    def size(self) -> int:
        return self._size

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            pass
        elif whence == io.SEEK_CUR:
            pos += self._pos
        elif whence == io.SEEK_END:
            pos += self._size
        else:
            raise ValueError(f"Invalid whence value: {whence}")

        self._pos = max(0, pos)
        return self._pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self._size - self._pos

        n = min(n, self._size - self._pos)
        start = self._pos

        self.fh.seek(start)
        result = bytearray(self.fh.read(n))

        for patch_offset, patch in self._patches:
            begin = max(start, patch_offset)
            end = min(start + n, patch_offset + len(patch))
            if begin < end:
                result[begin - start : end - start] = patch[begin - patch_offset : end - patch_offset]

        self._pos += len(result)
        return bytes(result)


def _read_raw(offset: int, length: int) -> bytes:
    with gzip.GzipFile(absolute_path(IMAGE_PATH), "rb") as fh:
        fh.seek(offset)
        return fh.read(length)


def _cipher(key: bytes, key_type: FVE_KEY_TYPE) -> Cipher:
    return create_cipher(CIPHER_MAP[key_type], key, sector_size=SECTOR_SIZE, iv_sector_size=SECTOR_SIZE)


def _expected_bytes(cipher: Cipher, segments: list[tuple[bool, int, int]], offset: int, length: int) -> bytes:
    """Build expected plain text from an independent list of (encrypted, offset, length) segments."""
    aligned_offset = offset - (offset % SECTOR_SIZE)
    aligned_end = offset + length
    if aligned_end % SECTOR_SIZE:
        aligned_end += SECTOR_SIZE - (aligned_end % SECTOR_SIZE)

    result = bytearray()
    for encrypted, segment_offset, segment_length in segments:
        begin = max(aligned_offset, segment_offset)
        end = min(aligned_end, segment_offset + segment_length)
        if begin >= end:
            continue

        data = _read_raw(begin, end - begin)
        if encrypted:
            data = cipher.decrypt(data, begin // SECTOR_SIZE)

        result += data

    start = offset - aligned_offset
    return bytes(result[start : start + length])


def _pack_bits(bits: list[int]) -> bytes:
    result = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit:
            result[index // 8] |= 1 << (index % 8)
    return bytes(result)


def _bitmap_block(
    region_offset: int,
    region_size: int,
    states: list[int],
    *,
    bitmap_size: int | None = None,
    record_data: bytes | None = None,
) -> bytes:
    """Build a complete EOW bitmap block with two records, the second one being active."""
    bitmap_size = len(states) if bitmap_size is None else bitmap_size
    data = _pack_bits(states) if record_data is None else record_data

    record_offsets = (512, 1024)
    record_size = 512
    block = bytearray(record_offsets[-1] + record_size)

    struct.pack_into(
        "<10sHIIQQQIIII",
        block,
        0,
        EOW_BM_SIGNATURE,
        60,
        len(block),
        2,
        region_offset,
        region_size,
        0x15641000,
        *record_offsets,
        record_size,
        0,
    )
    struct.pack_into("<I", block, 56, crc32(bytes(block[:60]) + bytes(block[60 : record_offsets[0]])))

    for record_index, sequence_number in enumerate((1, 2)):
        offset = record_offsets[record_index]
        record = bytearray(record_size)
        record_data_for_sequence = bytes(bitmap_size) if sequence_number == 1 else data
        record_length = 36 + len(record_data_for_sequence)

        struct.pack_into(
            "<10sHIIQII",
            record,
            0,
            EOW_BR_SIGNATURE,
            36,
            record_length,
            bitmap_size,
            sequence_number,
            2,
            0,
        )
        record[36:record_length] = record_data_for_sequence
        struct.pack_into("<I", record, 32, crc32(bytes(record[:36]) + record_data_for_sequence))

        block[offset : offset + record_size] = record

    return bytes(block)


def _paused_information_patch(offset: int, size: int) -> tuple[bytes, bytes]:
    """Patch the information header to the paused state and return the header and validation patches."""
    buf = bytearray(_read_raw(offset, size))
    buf[12:14] = struct.pack("<H", 3)  # FVE_STATE.PAUSED
    buf[14:16] = struct.pack("<H", 1)  # FVE_STATE.DECRYPTED

    # The integrity datum is encrypted with the VMK we don't have here, so only the CRC32 is updated.
    crc = crc32(bytes(buf)) & 0xFFFFFFFF
    return bytes(buf), struct.pack("<I", crc)


@contextmanager
def _open_overlay(patches: list[tuple[int, bytes]], key: tuple[bytes, FVE_KEY_TYPE]) -> Iterator[bde.BDE]:
    raw = gzip.GzipFile(absolute_path(IMAGE_PATH), "rb")
    try:
        bde_obj = bde.BDE(Overlay(raw, IMAGE_SIZE, patches))
        bde_obj.unlock_with_fvek(key[0])
        yield bde_obj
    finally:
        raw.close()


@pytest.fixture(scope="module")
def eow_bde() -> Iterator[bde.BDE]:
    with gzip.GzipFile(absolute_path(IMAGE_PATH), "rb") as fh:
        bde_obj = bde.BDE(fh)
        bde_obj.unlock_with_passphrase(PASSPHRASE)
        yield bde_obj


@pytest.fixture(scope="module")
def eow_key(eow_bde: bde.BDE) -> tuple[bytes, FVE_KEY_TYPE]:
    return eow_bde._fvek, eow_bde._fvek_type


@pytest.fixture(scope="module")
def eow_cipher(eow_key: tuple[bytes, FVE_KEY_TYPE]) -> Cipher:
    return _cipher(*eow_key)


def _image_digest() -> str:
    digest = hashlib.sha256()
    with gzip.GzipFile(absolute_path(IMAGE_PATH), "rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def test_eow_image_hash_unchanged() -> None:
    # The synthetic cases are all read-only overlays: the fixture and the image it contains must never change.
    assert hashlib.sha256(absolute_path(IMAGE_PATH).read_bytes()).hexdigest() == IMAGE_SHA256
    assert _image_digest() == IMAGE_DATA_SHA256


def test_eow_real_bitmap_states_match_independent_list() -> None:
    # Decode the raw active record bitmap ourselves to document the independent state list used below.
    raw = _read_raw(BITMAP2_OFFSET + 1024 + 36, (CHUNKS_PER_BITMAP + 7) // 8)
    assert [(raw[index // 8] >> (index % 8)) & 1 for index in range(CHUNKS_PER_BITMAP)] == REGION2_STATES


@pytest.mark.parametrize(
    ("offset", "length", "expected"),
    [
        # Start at the last plain text chunk and cross into the first encrypted chunk.
        (
            0xBA02000,
            3 * CHUNK_SIZE,
            [
                (bde.BitlockerStream.RUN_PLAIN, 380944, 16384),
                (bde.BitlockerStream.RUN_ENCRYPTED, 397328, 32768),
            ],
        ),
        # Start in the middle of the last plain text chunk and cross the chunk boundary.
        (
            0xBA0E800,
            16584 * SECTOR_SIZE,
            [
                (bde.BitlockerStream.RUN_PLAIN, 381044, 16284),
                (bde.BitlockerStream.RUN_ENCRYPTED, 397328, 300),
            ],
        ),
        # Exactly the first encrypted chunk.
        (0xC202000, 2 * CHUNK_SIZE, [(bde.BitlockerStream.RUN_ENCRYPTED, 397328, 32768)]),
        # 24 sectors before the chunk boundary, crossing into the encrypted chunk.
        (
            0xC1FF000,
            0x4000,
            [
                (bde.BitlockerStream.RUN_PLAIN, 397304, 24),
                (bde.BitlockerStream.RUN_ENCRYPTED, 397328, 8),
            ],
        ),
        # Last valid bitmap bit (chunk 32) is encrypted.
        (0x12202000, CHUNK_SIZE, [(bde.BitlockerStream.RUN_ENCRYPTED, 593936, 16384)]),
        # Last sector of region 2 and the first two sectors of region 3 are all encrypted and must not be split
        # by the bitmap region boundary.
        (0x123EFE00, 3 * SECTOR_SIZE, [(bde.BitlockerStream.RUN_ENCRYPTED, 597887, 3)]),
    ],
    ids=["chunk19_to_21", "mid_chunk19_crossing", "chunk20", "cross_chunk20", "last_bit", "region2_to_3"],
)
def test_eow_real_bitmap_chunk_boundaries(
    eow_bde: bde.BDE, offset: int, length: int, expected: list[tuple[int, int, int]]
) -> None:
    stream = eow_bde.open()
    assert list(stream._iter_runs(offset, length)) == expected


def test_eow_real_bitmap_head_and_tail(eow_bde: bde.BDE) -> None:
    stream = eow_bde.open()

    # One sector of the reserved bitmap 1 region, followed by the first plain text sector of region 2.
    assert list(stream._iter_runs(REGION2_OFFSET - SECTOR_SIZE, 2 * SECTOR_SIZE)) == [
        (bde.BitlockerStream.RUN_SPARSE, 69647, 1),
        (bde.BitlockerStream.RUN_PLAIN, 69648, 1),
    ]

    # The final sector described by bitmap 2 is encrypted.
    assert list(stream._iter_runs(REGION2_OFFSET + REGION2_SIZE - SECTOR_SIZE, SECTOR_SIZE)) == [
        (bde.BitlockerStream.RUN_ENCRYPTED, 597887, 1)
    ]

    # The final one-sector gap in region 3, just before the reserved conversion log area, is encrypted.
    last_sector = (0x1553A000 // SECTOR_SIZE) - 1
    assert list(stream._iter_runs(last_sector * SECTOR_SIZE, SECTOR_SIZE)) == [
        (bde.BitlockerStream.RUN_ENCRYPTED, last_sector, 1)
    ]


def test_eow_real_reserved_adjacency(eow_bde: bde.BDE) -> None:
    stream = eow_bde.open()

    # 8 plain text sectors from plain text chunk 12, followed by the reserved information region at 0x93f0000.
    assert list(stream._iter_runs(0x93EF000, 0x4000)) == [
        (bde.BitlockerStream.RUN_PLAIN, 302968, 8),
        (bde.BitlockerStream.RUN_SPARSE, 302976, 24),
    ]

    # 8 encrypted sectors from plain text chunk 20's region, followed by the reserved information region at 0x105f0000.
    assert list(stream._iter_runs(0x105EF000, 0x4000)) == [
        (bde.BitlockerStream.RUN_ENCRYPTED, 536440, 8),
        (bde.BitlockerStream.RUN_SPARSE, 536448, 24),
    ]

    # Reading up to and across the reserved boundary coalesces the identical plain text sectors before it.
    assert list(stream._iter_runs(0x93EF000 - SECTOR_SIZE, 2 * SECTOR_SIZE)) == [
        (bde.BitlockerStream.RUN_PLAIN, 302967, 2),
    ]


def test_eow_real_bitmap_bytes(eow_bde: bde.BDE, eow_cipher: Cipher) -> None:
    stream = eow_bde.open()

    # One sector before and one sector after the first encrypted chunk boundary.
    cases = [
        (0xC202000 - SECTOR_SIZE, SECTOR_SIZE, REGION2_SEGMENTS),
        (0xC202000, SECTOR_SIZE, REGION2_SEGMENTS),
        (0xC202000 - 300, 600, REGION2_SEGMENTS),
        (0xC202000 + 123, 1000, REGION2_SEGMENTS),
        (0x123F0000, 1024, REGION3_SEGMENTS),
    ]

    for offset, length, segments in cases:
        assert stream.readoffset(offset, length) == _expected_bytes(eow_cipher, segments, offset, length)


def test_eow_interleaved_seek_read(eow_bde: bde.BDE, eow_cipher: Cipher) -> None:
    stream = eow_bde.open()

    reads = [
        (0xBA02000, 512),
        (0xC202000, 2048),
        (0xBA02000, 512),
        (0xBA02000 + CHUNK_SIZE - 256, 512),
        (0xC202000, 512),
        (0xBA02000 + CHUNK_SIZE - 256, 512),
        (0xC202000 + 4096, 700),
        (0xC202000 + 4096, 700),
        (0xBA0E800, 16584 * SECTOR_SIZE),
        (0x123F0000, 4096),
        (0xC202000, 2048),
    ]

    expected = {
        (offset, length): _expected_bytes(eow_cipher, REGION2_SEGMENTS + REGION3_SEGMENTS, offset, length)
        for offset, length in reads
    }
    seen = {}

    for offset, length in reads:
        stream.seek(offset)
        actual = stream.read(length)

        # Every read must produce the same plain text as the independent expected bytes.
        assert actual == expected[(offset, length)]

        # Re-reading a previously read range must produce identical bytes.
        if (offset, length) in seen:
            assert actual == seen[(offset, length)]
        seen[(offset, length)] = actual

    # Explicitly seek backwards and re-read a mix of plain text and encrypted ranges.
    for offset, length in [(0xC202000, 2048), (0xBA02000, 512), (0x123F0000, 4096), (0xC202000, 2048)]:
        stream.seek(offset)
        assert stream.read(length) == expected[(offset, length)]


def test_eow_synthetic_short_bitmap(eow_key: tuple[bytes, FVE_KEY_TYPE], eow_cipher: Cipher) -> None:
    states = [1, 0, 1]
    block = _bitmap_block(REGION2_OFFSET, len(states) * CHUNK_SIZE, states)

    with _open_overlay([(BITMAP2_OFFSET, block)], eow_key) as bde_obj:
        stream = bde_obj.open()

        assert list(stream._iter_runs(REGION2_OFFSET, len(states) * CHUNK_SIZE)) == [
            (bde.BitlockerStream.RUN_ENCRYPTED, 69648, 16384),
            (bde.BitlockerStream.RUN_PLAIN, 86032, 16384),
            (bde.BitlockerStream.RUN_ENCRYPTED, 102416, 16384),
        ]

        # The bitmap boundary: a read crossing from chunk 0 into chunk 1 must change state at the chunk boundary.
        assert list(stream._iter_runs(REGION2_OFFSET + CHUNK_SIZE - SECTOR_SIZE, 2 * SECTOR_SIZE)) == [
            (bde.BitlockerStream.RUN_ENCRYPTED, 86031, 1),
            (bde.BitlockerStream.RUN_PLAIN, 86032, 1),
        ]

        # Each chunk start and the last sector of each chunk must use that chunk's own bit.
        for chunk, state in enumerate(states):
            run_type = bde.BitlockerStream.RUN_ENCRYPTED if state else bde.BitlockerStream.RUN_PLAIN
            chunk_offset = REGION2_OFFSET + chunk * CHUNK_SIZE
            first_sector = chunk_offset // SECTOR_SIZE
            last_sector = first_sector + (CHUNK_SIZE // SECTOR_SIZE) - 1

            assert list(stream._iter_runs(chunk_offset, SECTOR_SIZE)) == [(run_type, first_sector, 1)]
            assert list(stream._iter_runs(last_sector * SECTOR_SIZE, SECTOR_SIZE)) == [(run_type, last_sector, 1)]

        segments = [
            (bool(states[0]), REGION2_OFFSET, CHUNK_SIZE),
            (bool(states[1]), REGION2_OFFSET + CHUNK_SIZE, CHUNK_SIZE),
            (bool(states[2]), REGION2_OFFSET + 2 * CHUNK_SIZE, CHUNK_SIZE),
        ]
        for chunk in range(len(states)):
            offset = REGION2_OFFSET + chunk * CHUNK_SIZE
            assert stream.readoffset(offset, 512) == _expected_bytes(eow_cipher, segments, offset, 512)

        # The synthetic region ends after three chunks; anything after it has no bitmap and is an unknown state.
        with pytest.raises(UnknownStateError):
            list(stream._iter_runs(REGION2_OFFSET + len(states) * CHUNK_SIZE, SECTOR_SIZE))

        with pytest.raises(UnknownStateError):
            stream.readoffset(REGION2_OFFSET + len(states) * CHUNK_SIZE, SECTOR_SIZE)


def test_eow_single_bit_flip_only_affects_range(eow_key: tuple[bytes, FVE_KEY_TYPE], eow_cipher: Cipher) -> None:
    states = [1, 0, 1]
    mutated = [0, 0, 1]
    base_block = _bitmap_block(REGION2_OFFSET, len(states) * CHUNK_SIZE, states)
    mutated_block = _bitmap_block(REGION2_OFFSET, len(states) * CHUNK_SIZE, mutated)

    segments = [
        (True, REGION2_OFFSET, CHUNK_SIZE),
        (False, REGION2_OFFSET + CHUNK_SIZE, CHUNK_SIZE),
        (True, REGION2_OFFSET + 2 * CHUNK_SIZE, CHUNK_SIZE),
    ]

    with (
        _open_overlay([(BITMAP2_OFFSET, base_block)], eow_key) as base_bde,
        _open_overlay([(BITMAP2_OFFSET, mutated_block)], eow_key) as mutated_bde,
    ):
        base_stream = base_bde.open()
        mutated_stream = mutated_bde.open()

        for chunk in range(len(states)):
            offset = REGION2_OFFSET + chunk * CHUNK_SIZE
            expected = _expected_bytes(eow_cipher, segments, offset, 512)

            assert base_stream.readoffset(offset, 512) == expected
            actual = mutated_stream.readoffset(offset, 512)

            if chunk == 0:
                # Flipping only the first bit changes exactly the first chunk.
                assert actual != expected
                assert actual == _read_raw(offset, 512)
            else:
                assert actual == expected


def test_eow_shifted_bitmap_index_fails(eow_key: tuple[bytes, FVE_KEY_TYPE]) -> None:
    states = [1, 0, 1]
    # Deliberately move the bitmap to the next chunk. The original range is now not covered by any bitmap.
    shifted = _bitmap_block(REGION2_OFFSET + CHUNK_SIZE, len(states) * CHUNK_SIZE, states)

    with _open_overlay([(BITMAP2_OFFSET, shifted)], eow_key) as bde_obj:
        stream = bde_obj.open()

        with pytest.raises(UnknownStateError):
            list(stream._iter_runs(REGION2_OFFSET, SECTOR_SIZE))

        with pytest.raises(UnknownStateError):
            stream.readoffset(REGION2_OFFSET, SECTOR_SIZE)

        # The first sector of the shifted bitmap region is now described by bit 0.
        assert list(stream._iter_runs(REGION2_OFFSET + CHUNK_SIZE, SECTOR_SIZE)) == [
            (bde.BitlockerStream.RUN_ENCRYPTED, 86032, 1)
        ]


def test_eow_truncated_bitmap(eow_key: tuple[bytes, FVE_KEY_TYPE]) -> None:
    # The record claims 16 bits, but only one byte of bitmap data is present. Chunks 0-7 are validly described as
    # plain text, chunk 8 and beyond have no data at all and must raise instead of becoming zero-filled plain text.
    block = _bitmap_block(REGION2_OFFSET, 16 * CHUNK_SIZE, [], bitmap_size=16, record_data=b"\x00")

    with _open_overlay([(BITMAP2_OFFSET, block)], eow_key) as bde_obj:
        stream = bde_obj.open()

        assert list(stream._iter_runs(REGION2_OFFSET, 8 * CHUNK_SIZE)) == [
            (bde.BitlockerStream.RUN_PLAIN, 69648, 8 * 16384)
        ]

        # A valid zero bit is real plain text and reads the image bytes (all zeroes in this image).
        assert stream.readoffset(REGION2_OFFSET + 7 * CHUNK_SIZE, SECTOR_SIZE) == b"\x00" * SECTOR_SIZE

        # A missing bit is not the same as a zero bit: it must raise, not silently return zeroes.
        with pytest.raises(UnknownStateError):
            list(stream._iter_runs(REGION2_OFFSET + 8 * CHUNK_SIZE, SECTOR_SIZE))

        with pytest.raises(UnknownStateError):
            stream.readoffset(REGION2_OFFSET + 8 * CHUNK_SIZE, SECTOR_SIZE)


def test_eow_truncated_bitmap_no_zero_padding(eow_key: tuple[bytes, FVE_KEY_TYPE]) -> None:
    # A bitmap that is not present at all must not be interpreted as an all-zero (plain text) bitmap.
    block = _bitmap_block(REGION2_OFFSET, CHUNK_SIZE, [], bitmap_size=1, record_data=b"")

    with _open_overlay([(BITMAP2_OFFSET, block)], eow_key) as bde_obj:
        stream = bde_obj.open()

        with pytest.raises(UnknownStateError):
            list(stream._iter_runs(REGION2_OFFSET, SECTOR_SIZE))

        with pytest.raises(UnknownStateError):
            stream.readoffset(REGION2_OFFSET, SECTOR_SIZE)


def test_eow_paused_state(eow_bde: bde.BDE, eow_key: tuple[bytes, FVE_KEY_TYPE], eow_cipher: Cipher) -> None:
    information_patch, validation_patch = _paused_information_patch(
        eow_bde.information.offset, eow_bde.information.size
    )
    states = [0, 1, 0]
    block = _bitmap_block(REGION2_OFFSET, len(states) * CHUNK_SIZE, states)

    patches = [
        (eow_bde.information.offset, information_patch),
        (eow_bde.information.offset + eow_bde.information.size + 4, validation_patch),
        (BITMAP2_OFFSET, block),
    ]

    with _open_overlay(patches, eow_key) as bde_obj:
        assert bde_obj.paused
        assert bde_obj.switching
        assert bde_obj.encrypted

        stream = bde_obj.open()
        assert stream.encrypted

        assert list(stream._iter_runs(REGION2_OFFSET, len(states) * CHUNK_SIZE)) == [
            (bde.BitlockerStream.RUN_PLAIN, 69648, 16384),
            (bde.BitlockerStream.RUN_ENCRYPTED, 86032, 16384),
            (bde.BitlockerStream.RUN_PLAIN, 102416, 16384),
        ]

        segments = [
            (False, REGION2_OFFSET, CHUNK_SIZE),
            (True, REGION2_OFFSET + CHUNK_SIZE, CHUNK_SIZE),
            (False, REGION2_OFFSET + 2 * CHUNK_SIZE, CHUNK_SIZE),
        ]
        for chunk in range(len(states)):
            offset = REGION2_OFFSET + chunk * CHUNK_SIZE
            assert stream.readoffset(offset, 512) == _expected_bytes(eow_cipher, segments, offset, 512)


def test_eow_partial_bitmap_region(eow_key: tuple[bytes, FVE_KEY_TYPE]) -> None:
    # Region ends one sector before the end of the second chunk, so the last sector has no bitmap coverage.
    region_size = 2 * CHUNK_SIZE - SECTOR_SIZE
    block = _bitmap_block(REGION2_OFFSET, region_size, [0, 1])

    with _open_overlay([(BITMAP2_OFFSET, block)], eow_key) as bde_obj:
        stream = bde_obj.open()

        # A whole number of chunks fits in the region, except for the final sector.
        assert list(stream._iter_runs(REGION2_OFFSET + CHUNK_SIZE, CHUNK_SIZE - SECTOR_SIZE)) == [
            (bde.BitlockerStream.RUN_ENCRYPTED, 86032, 16383)
        ]

        with pytest.raises(UnknownStateError):
            list(stream._iter_runs(REGION2_OFFSET + region_size - SECTOR_SIZE, 2 * SECTOR_SIZE))
