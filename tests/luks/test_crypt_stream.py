"""Geometry regression tests for the LUKS/dm-crypt decrypting stream.

These tests do not perform a sequential encrypt/decrypt round trip starting at the volume header.
Instead they build small synthetic encrypted images with a non-zero data offset, an explicit
``iv_tweak`` and an image-declared logical sector size, then verify that :class:`CryptStream`
keeps three concepts strictly separated:

- the physical file offset (``segment.offset`` plus the logical read offset),
- the logical read offset inside the decrypted volume,
- the 512-byte sector number used for IV generation (``iv_tweak`` plus the logical offset
  expressed in 512-byte units, never the host disk block size or the logical sector index).

The on-disk images are produced with the same dm-crypt cipher primitives that
:class:`CryptStream` consumes, but the expected IV sector numbers are asserted independently
through a recording cipher. Two deliberately wrong stream implementations are included to prove
the tests can distinguish a physical file offset from a logical sector number.
"""

from __future__ import annotations

from io import BytesIO
from typing import BinaryIO

import pytest

from dissect.fve.crypto import create_cipher
from dissect.fve.crypto.dmcrypt import CryptStream

# A non-zero data offset that is a multiple of 512 (the dm-crypt IV sector size) but deliberately
# not a multiple of 4096, so it cannot be mistaken for a host block size boundary.
DATA_OFFSET = 24 * 512
# A non-zero IV tweak, kept different from DATA_OFFSET // 512 so tweak and offset bugs diverge.
IV_TWEAK = 4096
HEADER_FILL = 0xAA

XTS_KEY = bytes(range(32)) * 2
CBC_KEY = bytes(range(32))

CIPHER_PARAMS = [
    pytest.param("aes-xts-plain64", XTS_KEY, id="xts-plain64"),
    pytest.param("aes-cbc-essiv:sha256", CBC_KEY, id="cbc-essiv"),
]
SECTOR_SIZES = [512, 4096]


def make_plaintext(length: int) -> bytes:
    """Deterministic, non-repeating plaintext so every slice is recognisable."""
    return bytes((index * 29 + 17) & 0xFF for index in range(length))


def build_image(
    cipher_spec: str,
    key: bytes,
    sector_size: int,
    sector_count: int,
    plaintext: bytes,
    iv_tweak: int = IV_TWEAK,
    data_offset: int = DATA_OFFSET,
) -> BytesIO:
    """Encrypt ``plaintext`` sector by sector using the dm-crypt IV sector convention.

    IV sectors are always numbered in 512-byte units, even when the logical sector size is 4096:
    a 4096-byte sector therefore starts at IV sector ``iv_tweak + logical_offset // 512`` and
    consumes eight IV sector numbers internally.
    """
    cipher = create_cipher(cipher_spec, key, sector_size=sector_size)
    payload = bytearray()
    for index in range(sector_count):
        sector_plaintext = plaintext[index * sector_size : (index + 1) * sector_size]
        iv_sector = iv_tweak + (index * sector_size) // 512
        payload += cipher.encrypt(sector_plaintext, iv_sector)

    return BytesIO(bytes([HEADER_FILL]) * data_offset + bytes(payload))


def open_stream(
    image: BinaryIO,
    cipher_spec: str,
    key: bytes,
    sector_size: int,
    payload_size: int,
    *,
    iv_tweak: int = IV_TWEAK,
    data_offset: int = DATA_OFFSET,
) -> CryptStream:
    return CryptStream(
        image,
        cipher_spec,
        key,
        offset=data_offset,
        size=payload_size,
        iv_tweak=iv_tweak,
        sector_size=sector_size,
    )


def sector_count_for(sector_size: int) -> int:
    """Enough logical sectors for every seeked window below, at either sector size."""
    return 32 if sector_size == 512 else 8


@pytest.mark.parametrize(("cipher_spec", "key"), CIPHER_PARAMS)
@pytest.mark.parametrize("sector_size", SECTOR_SIZES)
def test_non_zero_data_offset_and_iv_sector_numbering(
    cipher_spec: str, key: bytes, sector_size: int
) -> None:
    sector_count = sector_count_for(sector_size)
    plaintext = make_plaintext(sector_size * sector_count)
    image = build_image(cipher_spec, key, sector_size, sector_count, plaintext)
    stream = open_stream(image, cipher_spec, key, sector_size, len(plaintext))

    # The stream spans only the payload region; the physical header is never exposed.
    assert stream.size == len(plaintext)
    assert stream.readoffset(0, len(plaintext)) == plaintext

    # Explicit boundary check: payload byte zero lives at physical DATA_OFFSET, proving the
    # logical read offset is not confused with the physical file offset.
    assert image.getvalue()[DATA_OFFSET : DATA_OFFSET + 16] != plaintext[:16]
    assert image.getvalue()[:16] == bytes([HEADER_FILL]) * 16

    # Independent dm-crypt reference: re-derive the IV sector number for a seeked 4096-byte
    # window and confirm the stream used (iv_tweak + logical 512-byte sector), nothing else.
    seek_offset = 8192
    window = sector_size if sector_size == 4096 else 4096
    expected_iv_sector = IV_TWEAK + seek_offset // 512
    reference = create_cipher(cipher_spec, key, sector_size=sector_size)
    expected_window = reference.decrypt(
        image.getvalue()[DATA_OFFSET + seek_offset : DATA_OFFSET + seek_offset + window],
        expected_iv_sector,
    )
    assert stream.readoffset(seek_offset, window) == expected_window == plaintext[
        seek_offset : seek_offset + window
    ]


@pytest.mark.parametrize(("cipher_spec", "key"), CIPHER_PARAMS)
@pytest.mark.parametrize("sector_size", SECTOR_SIZES)
def test_unaligned_small_reads_and_cross_sector_seeks(
    cipher_spec: str, key: bytes, sector_size: int
) -> None:
    sector_count = sector_count_for(sector_size)
    plaintext = make_plaintext(sector_size * sector_count)
    image = build_image(cipher_spec, key, sector_size, sector_count, plaintext)
    stream = open_stream(image, cipher_spec, key, sector_size, len(plaintext))

    # Reads that are neither sector aligned nor a sector multiple must still return known bytes.
    first_offset = 37
    first_length = 123
    assert stream.readoffset(first_offset, first_length) == plaintext[first_offset : first_offset + first_length]

    # Seek across several logical sectors and read another unaligned window spanning a boundary.
    second_offset = sector_size * 3 + 129
    second_length = sector_size + 77
    assert stream.readoffset(second_offset, second_length) == plaintext[
        second_offset : second_offset + second_length
    ]

    # A seek far past the first AlignedStream buffer window, where logical/IV sector indexing
    # bugs are no longer masked by the stream starting at offset zero.
    third_offset = 8192 + 11
    third_length = 2048
    assert stream.readoffset(third_offset, third_length) == plaintext[
        third_offset : third_offset + third_length
    ]


@pytest.mark.parametrize(("cipher_spec", "key"), CIPHER_PARAMS)
@pytest.mark.parametrize("sector_size", SECTOR_SIZES)
def test_same_range_different_slicing(cipher_spec: str, key: bytes, sector_size: int) -> None:
    sector_count = sector_count_for(sector_size)
    plaintext = make_plaintext(sector_size * sector_count)
    # A deliberately small, unaligned range that crosses a logical sector boundary.
    range_start = sector_size - 41
    range_end = sector_size + 137

    def fresh_stream() -> CryptStream:
        return open_stream(
            build_image(cipher_spec, key, sector_size, sector_count, plaintext),
            cipher_spec,
            key,
            sector_size,
            len(plaintext),
        )

    single = fresh_stream().readoffset(range_start, range_end - range_start)

    # Split the exact same range into three differently sized, unaligned slices.
    first_cut = range_start + 17
    second_cut = range_start + 97
    sliced = b"".join(
        [
            fresh_stream().readoffset(range_start, first_cut - range_start),
            fresh_stream().readoffset(first_cut, second_cut - first_cut),
            fresh_stream().readoffset(second_cut, range_end - second_cut),
        ]
    )

    # Byte-by-byte reads exercise the alignment buffer on every single byte.
    bytewise = b"".join(
        fresh_stream().readoffset(index, 1) for index in range(range_start, range_end)
    )

    assert single == sliced == bytewise == plaintext[range_start:range_end]


@pytest.mark.parametrize(("cipher_spec", "key"), CIPHER_PARAMS)
@pytest.mark.parametrize("sector_size", SECTOR_SIZES)
def test_iv_tweak_must_match_segment(cipher_spec: str, key: bytes, sector_size: int) -> None:
    sector_count = sector_count_for(sector_size)
    plaintext = make_plaintext(sector_size * sector_count)
    image = build_image(cipher_spec, key, sector_size, sector_count, plaintext)

    correct = open_stream(BytesIO(image.getvalue()), cipher_spec, key, sector_size, len(plaintext))
    assert correct.readoffset(0, len(plaintext)) == plaintext

    # The image was encrypted with IV_TWEAK; a stream ignoring it must not produce the plaintext.
    without_tweak = open_stream(
        BytesIO(image.getvalue()), cipher_spec, key, sector_size, len(plaintext), iv_tweak=0
    )
    assert without_tweak.readoffset(0, len(plaintext)) != plaintext

    # A different tweak is equally wrong, proving the tweak is actually applied to every IV.
    shifted_tweak = open_stream(
        BytesIO(image.getvalue()), cipher_spec, key, sector_size, len(plaintext), iv_tweak=IV_TWEAK + 1
    )
    assert shifted_tweak.readoffset(0, len(plaintext)) != plaintext


class PhysicalFileOffsetStream(CryptStream):
    """Wrong implementation: numbers IV sectors from the physical file position.

    This folds the data offset into the IV sector number instead of only using the logical
    read offset relative to the payload.
    """

    def _read(self, offset: int, length: int) -> bytes:
        self.fh.seek(self.offset + offset)
        buffer = bytearray(self.fh.read(length))
        wrong_sector = ((self.offset + offset) // 512) + self.iv_tweak
        self.cipher.decrypt(buffer, wrong_sector, buffer)
        return bytes(buffer)


class LogicalSectorIndexStream(CryptStream):
    """Wrong implementation: numbers IV sectors by logical sector index.

    This divides the logical offset by the image-declared sector size instead of the fixed
    512-byte dm-crypt IV sector size, i.e. it treats a 4096-byte sector as IV sector 1 rather
    than as IV sector 8. It can only diverge for a 4096-byte sector size.
    """

    def _read(self, offset: int, length: int) -> bytes:
        self.fh.seek(self.offset + offset)
        buffer = bytearray(self.fh.read(length))
        wrong_sector = (offset // self.sector_size) + self.iv_tweak
        self.cipher.decrypt(buffer, wrong_sector, buffer)
        return bytes(buffer)


WRONG_STREAM_PARAMS = [
    pytest.param(PhysicalFileOffsetStream, True, id="physical-file-offset"),
    pytest.param(LogicalSectorIndexStream, False, id="logical-sector-index"),
]


@pytest.mark.parametrize(("cipher_spec", "key"), CIPHER_PARAMS)
@pytest.mark.parametrize("sector_size", SECTOR_SIZES)
@pytest.mark.parametrize(("wrong_stream", "applies_to_512"), WRONG_STREAM_PARAMS)
def test_wrong_iv_sector_numbering_is_rejected(
    cipher_spec: str,
    key: bytes,
    sector_size: int,
    wrong_stream: type[CryptStream],
    applies_to_512: bool,
) -> None:
    if sector_size == 512 and not applies_to_512:
        pytest.skip("Logical sector index and 512-byte IV numbering coincide for a 512-byte sector")

    sector_count = sector_count_for(sector_size)
    plaintext = make_plaintext(sector_size * sector_count)
    image = build_image(cipher_spec, key, sector_size, sector_count, plaintext)

    # Seek past the first alignment buffer window so a mis-indexed IV cannot be hidden by a
    # read that happens to start at logical offset zero.
    seek_offset = 8192
    read_length = 512

    good = open_stream(BytesIO(image.getvalue()), cipher_spec, key, sector_size, len(plaintext))
    assert good.readoffset(seek_offset, read_length) == plaintext[seek_offset : seek_offset + read_length]

    bad = wrong_stream(
        BytesIO(image.getvalue()),
        cipher_spec,
        key,
        offset=DATA_OFFSET,
        size=len(plaintext),
        iv_tweak=IV_TWEAK,
        sector_size=sector_size,
    )
    bad_plaintext = bad.readoffset(seek_offset, read_length)
    assert bad_plaintext != plaintext[seek_offset : seek_offset + read_length], (
        f"{wrong_stream.__name__} incorrectly produced the known plaintext: it must use "
        "iv_tweak + logical_offset // 512 as the IV sector number"
    )


class RecordingCryptStream(CryptStream):
    """CryptStream variant that records every IV sector number handed to the cipher."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.iv_sectors: list[int] = []

    def _read(self, offset: int, length: int) -> bytes:
        self.fh.seek(self.offset + offset)
        buffer = bytearray(self.fh.read(length))
        iv_sector = (offset // 512) + self.iv_tweak
        self.iv_sectors.append(iv_sector)
        self.cipher.decrypt(buffer, iv_sector, buffer)
        return bytes(buffer)


@pytest.mark.parametrize(("cipher_spec", "key"), CIPHER_PARAMS)
def test_iv_sector_uses_512_byte_units_for_4096_sector(cipher_spec: str, key: bytes) -> None:
    sector_size = 4096
    sector_count = 8
    plaintext = make_plaintext(sector_size * sector_count)
    image = build_image(cipher_spec, key, sector_size, sector_count, plaintext)
    stream = RecordingCryptStream(
        image,
        cipher_spec,
        key,
        offset=DATA_OFFSET,
        size=len(plaintext),
        iv_tweak=IV_TWEAK,
        sector_size=sector_size,
    )

    # Read a 4096-byte logical sector from an AlignedStream buffer boundary (8192) so it is
    # served by a single _read call. Its IV sector must be the tweak plus eight 512-byte units,
    # not the tweak plus one logical sector index.
    seek_offset = 8192
    decrypted = stream.readoffset(seek_offset, sector_size)
    assert stream.iv_sectors == [IV_TWEAK + seek_offset // 512]
    assert IV_TWEAK + 1 not in stream.iv_sectors
    assert decrypted == plaintext[seek_offset : seek_offset + sector_size]
