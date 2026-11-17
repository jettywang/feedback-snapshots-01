"""Vector regression tests for encrypted file reads on APFS one-key volumes.

The expected plaintext and the AES-XTS tweak computation in this module come
from a self-contained reference implementation (see :func:`xts_reference`),
not from :class:`~dissect.apfs.stream.FileStream` itself. The ciphertext
vectors are pinned by their SHA-256 digests in :data:`CIPHERTEXT_SHA256`.
"""

from __future__ import annotations

import hashlib
import random
from typing import TYPE_CHECKING

import pytest
from Crypto.Cipher import AES

from dissect.apfs.exception import Error
from dissect.apfs.stream import FileStream
from dissect.fve.crypto import create_cipher

if TYPE_CHECKING:
    from collections.abc import Callable

BLOCK_SIZE = 4096
SECTOR_SIZE = 512
SECTORS_PER_BLOCK = BLOCK_SIZE // SECTOR_SIZE

# Fixed volume encryption key (VEK) for all vectors in this module.
VEK = bytes(range(32))

OID = 0x1234

# Extent table: (logical_addr, phys_block_num, length, crypto_id).
# Two logically contiguous extents that are physically discontiguous (100 -> 250)
# and carry different crypto_ids (0x20 -> 0x40).
EXTENTS = (
    (0 * BLOCK_SIZE, 100, 2 * BLOCK_SIZE, 0x20),
    (2 * BLOCK_SIZE, 250, 2 * BLOCK_SIZE, 0x40),
)

# The file tail (500 bytes) does not fill a whole block.
FILE_SIZE = 3 * BLOCK_SIZE + 500

# SHA-256 digests of the four on-disk ciphertext blocks (physical blocks 100,
# 101, 250 and 251), pinning the reference vectors.
CIPHERTEXT_SHA256 = (
    "040259d77b280f4ae567ededf06b2a29ef78548eb3292d87ec8787e78793c7fc",
    "6bf2e5ed7bc6e9a76dc353bad2cc87c2c158088b0f800e931eacc95d349b4941",
    "1be813455c0d41c0a5b46ddc5e46cc3e11d384ea77fc283815cddcddb2982902",
    "a42bb3e792bb9c0dbaf0e17441ec1baf8cdaae7d6a3a691d4ddaca54a3f6cf8b",
)


def xts_reference(key: bytes, data: bytes, sector: int, *, encrypt: bool) -> bytes:
    """Self-contained AES-XTS reference (IEEE 1619, plain64 IV, 512-byte sectors)."""
    data_cipher = AES.new(key[:16], AES.MODE_ECB)
    tweak_cipher = AES.new(key[16:], AES.MODE_ECB)

    out = bytearray()
    for sector_offset in range(0, len(data), SECTOR_SIZE):
        tweak_int = int.from_bytes(
            tweak_cipher.encrypt((sector + sector_offset // SECTOR_SIZE).to_bytes(16, "little")), "little"
        )
        for block_offset in range(0, SECTOR_SIZE, 16):
            tweak = tweak_int.to_bytes(16, "little")
            chunk = data[sector_offset + block_offset : sector_offset + block_offset + 16]
            masked = bytes(a ^ b for a, b in zip(chunk, tweak))
            crypted = (data_cipher.encrypt if encrypt else data_cipher.decrypt)(masked)
            out += bytes(a ^ b for a, b in zip(crypted, tweak))

            tweak_int <<= 1
            if tweak_int & (1 << 128):
                tweak_int ^= (1 << 128) | 0x87

    return bytes(out)


def plaintext_block(index: int) -> bytes:
    """Deterministic plaintext for file block ``index``."""
    return random.Random(f"apfs-filestream-vector-{index}").randbytes(BLOCK_SIZE)


PLAINTEXT = b"".join(plaintext_block(i) for i in range(4))[:FILE_SIZE]


def correct_sector(logical: int, phys: int, block_in_extent: int, crypto_id: int) -> int:
    """The tweak sector FileStream is expected to use: crypto_id in block units, scaled to sectors."""
    return (crypto_id + block_in_extent) * SECTORS_PER_BLOCK


def physical_block_sector(logical: int, phys: int, block_in_extent: int, crypto_id: int) -> int:
    """Wrong: tweak derived from the physical block number."""
    return (phys + block_in_extent) * SECTORS_PER_BLOCK


def logical_offset_sector(logical: int, phys: int, block_in_extent: int, crypto_id: int) -> int:
    """Wrong: tweak derived from the logical file offset."""
    return (logical + block_in_extent * BLOCK_SIZE) // SECTOR_SIZE


def block_unit_sector(logical: int, phys: int, block_in_extent: int, crypto_id: int) -> int:
    """Wrong: crypto_id used as a sector number without block-to-sector conversion."""
    return crypto_id + block_in_extent


def build_blocks(sector_fn: Callable[[int, int, int, int], int]) -> dict[int, bytes]:
    """Build the on-disk ciphertext blocks, encrypting each plaintext block with ``sector_fn``."""
    blocks = {}
    for logical, phys, length, crypto_id in EXTENTS:
        for block_in_extent in range(length // BLOCK_SIZE):
            file_block = logical // BLOCK_SIZE + block_in_extent
            sector = sector_fn(logical, phys, block_in_extent, crypto_id)
            blocks[phys + block_in_extent] = xts_reference(VEK, plaintext_block(file_block), sector, encrypt=True)
    return blocks


class SyntheticContainer:
    """Minimal stand-in for :class:`~dissect.apfs.apfs.APFS`."""

    block_size = BLOCK_SIZE
    sectors_per_block = SECTORS_PER_BLOCK

    def __init__(self, blocks: dict[int, bytes]) -> None:
        self._blocks = blocks

    def _read_block(self, address: int, count: int = 1) -> bytes:
        return b"".join(self._blocks[address + i] for i in range(count))


class SyntheticVolume:
    """Minimal stand-in for an encrypted one-key :class:`~dissect.apfs.objects.fs.FS`."""

    def __init__(self, container: SyntheticContainer, cipher: object | None) -> None:
        self.container = container
        self._cipher = cipher
        self.is_sealed = False
        self.is_encrypted = True
        self.is_onekey = True

    def cursor(self) -> None:
        return None


def open_stream(volume: SyntheticVolume, size: int = FILE_SIZE) -> FileStream:
    """Create a FileStream over ``volume`` backed by the synthetic extent table."""
    stream = FileStream(volume, OID, size)

    def _lookup(offset: int) -> tuple[int, int, int, int]:
        for logical, phys, length, crypto_id in EXTENTS:
            if logical <= offset < logical + length:
                return logical, phys, length, crypto_id
        raise Error(f"Could not find file extent for {OID} at offset {offset}")

    stream._lookup = _lookup
    return stream


class RecordingCipher:
    """Cipher wrapper that records every (sector, length) decrypt call."""

    def __init__(self, cipher: object) -> None:
        self._cipher = cipher
        self.calls: list[tuple[int, int]] = []

    def decrypt(self, data: bytes, sector: int) -> bytes:
        self.calls.append((sector, len(data)))
        return self._cipher.decrypt(data, sector)


@pytest.fixture
def volume() -> SyntheticVolume:
    return SyntheticVolume(SyntheticContainer(build_blocks(correct_sector)), create_cipher("aes-xts-128", VEK))


def test_vectors_are_pinned() -> None:
    """The reference vectors must stay bit-exact; this guards the reference itself."""
    blocks = build_blocks(correct_sector)
    digests = tuple(hashlib.sha256(blocks[phys]).hexdigest() for phys in (100, 101, 250, 251))
    assert digests == CIPHERTEXT_SHA256


def test_tweak_uses_crypto_id_not_block_numbers(volume: SyntheticVolume) -> None:
    """Every decrypt call must use sector (crypto_id + block_in_extent) * sectors_per_block."""
    cipher = RecordingCipher(volume._cipher)
    volume._cipher = cipher

    stream = open_stream(volume)
    for _ in range(4):
        stream.read(BLOCK_SIZE)

    expected = [
        (correct_sector(logical, phys, b, cid), BLOCK_SIZE) for logical, phys, _, cid in EXTENTS for b in (0, 1)
    ]
    assert cipher.calls == expected

    # The pinned sectors must not coincide with any of the wrong formulas,
    # otherwise the vectors could not distinguish them.
    for logical, phys, _, cid in EXTENTS:
        for b in (0, 1):
            sector = correct_sector(logical, phys, b, cid)
            assert sector != physical_block_sector(logical, phys, b, cid)
            assert sector != logical_offset_sector(logical, phys, b, cid)
            assert sector != block_unit_sector(logical, phys, b, cid)


def test_short_read_within_block(volume: SyntheticVolume) -> None:
    stream = open_stream(volume)
    stream.seek(123)
    assert stream.read(1000) == PLAINTEXT[123:1123]


def test_cross_extent_boundary_slice(volume: SyntheticVolume) -> None:
    stream = open_stream(volume)
    stream.seek(2 * BLOCK_SIZE - 777)
    assert stream.read(2 * 777) == PLAINTEXT[2 * BLOCK_SIZE - 777 : 2 * BLOCK_SIZE + 777]


def test_partial_block_tail(volume: SyntheticVolume) -> None:
    stream = open_stream(volume)
    stream.seek(3 * BLOCK_SIZE)
    assert stream.read() == PLAINTEXT[3 * BLOCK_SIZE :]
    assert len(PLAINTEXT[3 * BLOCK_SIZE :]) == 500


def test_full_sequential_read(volume: SyntheticVolume) -> None:
    assert open_stream(volume).read() == PLAINTEXT


def test_sequential_and_random_reads_are_identical(volume: SyntheticVolume) -> None:
    stream = open_stream(volume)
    sequential = stream.read()

    rng = random.Random(20261118)
    for _ in range(200):
        offset = rng.randrange(FILE_SIZE)
        length = rng.randrange(1, FILE_SIZE - offset + 1)
        stream.seek(offset)
        assert stream.read(length) == sequential[offset : offset + length]


@pytest.mark.parametrize(
    "sector_fn",
    [physical_block_sector, logical_offset_sector, block_unit_sector],
    ids=["physical-block-number", "logical-file-offset", "missing-sector-conversion"],
)
def test_wrong_tweak_counterexample(sector_fn: Callable[[int, int, int, int], int]) -> None:
    """Vectors must reject tweaks derived from anything but crypto_id in sector units."""
    blocks = build_blocks(correct_sector)

    # Reference level: decrypting the real vectors with the wrong tweak yields garbage.
    for logical, phys, length, crypto_id in EXTENTS:
        for block_in_extent in range(length // BLOCK_SIZE):
            wrong = xts_reference(
                VEK, blocks[phys + block_in_extent], sector_fn(logical, phys, block_in_extent, crypto_id), encrypt=False
            )
            assert wrong != plaintext_block(logical // BLOCK_SIZE + block_in_extent)

    # Implementation level: data encrypted with the wrong tweak source is not
    # transparently readable as plaintext by FileStream.
    volume = SyntheticVolume(SyntheticContainer(build_blocks(sector_fn)), create_cipher("aes-xts-128", VEK))
    assert open_stream(volume).read() != PLAINTEXT


def test_locked_volume_raises_and_leaks_nothing() -> None:
    volume = SyntheticVolume(SyntheticContainer(build_blocks(correct_sector)), None)
    stream = open_stream(volume)

    with pytest.raises(Error, match="unlock it first"):
        stream.read()

    stream.seek(0)
    with pytest.raises(Error, match="unlock it first"):
        stream.read(1)

    # After unlocking, the very same stream must produce the plaintext.
    volume._cipher = create_cipher("aes-xts-128", VEK)
    stream.seek(0)
    assert stream.read() == PLAINTEXT
