"""Forensic selection tests for the two VBK snapshot metadata slots.

A VBK file carries two snapshot slots. Forensic readers must not simply trust the slot whose
``SnapshotDescriptor.Version`` is numerically highest: a slot write can be interrupted halfway
through, leaving a higher-versioned but corrupt slot on disk. The active slot has to be the
actually committed metadata, which means:

- its ``SnapshotSlotHeader.ContainsSnapshot`` flag must be set, and
- its CRC must validate against the CRC algorithm selected by ``StorageHeader.SnapshotSlotFormat``
  (CRC32C when ``SnapshotSlotFormat > 5``, plain CRC32 otherwise).

The synthetic VBK files below are assembled from raw bytes. Every expected CRC in this module is
computed directly over the bytes covered by the on-disk format, so ``SnapshotSlot.verify`` is never
used to derive an expected value; it is only the behavior under test inside the ``VBK`` entry point.
"""

from __future__ import annotations

import struct
from io import BytesIO
from zlib import crc32

import pytest

from dissect.archive.vbk.c_vbk import PAGE_SIZE, c_vbk
from dissect.archive.vbk.vbk import VBK, VBKError
from dissect.util.hash.crc32c import crc32c

SLOT_HEADER_SIZE = len(c_vbk.SnapshotSlotHeader)
DESCRIPTOR_SIZE = len(c_vbk.SnapshotDescriptor)
GRAIN_SIZE = len(c_vbk.BanksGrain)
BANK_DESCRIPTOR_SIZE = len(c_vbk.BankDescriptor)

MAX_BANKS = 1
VALID_MAX_BANKS = 0xF8
VALID_MAX_BANKS_V6 = 0x7F00

OLD_VERSION = 1
NEW_VERSION = 2
OLD_ROOT_PAGE = 0x111111
NEW_ROOT_PAGE = 0x222222


def expected_slot_crc(data: bytes, slot_offset: int, slot_format: int) -> int:
    """Compute a slot CRC the way the on-disk format prescribes, over the real covered bytes.

    Mirrors the coverage and algorithm selection of ``SnapshotSlot.verify`` but reads directly from
    the raw file image instead of calling that method: remainder of the slot header, the full
    snapshot descriptor, the banks grain and the whole bank descriptor array.
    """
    algorithm = crc32c if slot_format > 5 else crc32
    covered_length = 4 + DESCRIPTOR_SIZE + GRAIN_SIZE + MAX_BANKS * BANK_DESCRIPTOR_SIZE
    return algorithm(data[slot_offset + 4 : slot_offset + 4 + covered_length])


def slot_image_size(contains_snapshot: bool, slot_format: int) -> int:
    """Compute the page-aligned on-disk size of a slot, matching ``SnapshotSlot.size``."""
    valid_max_banks = VALID_MAX_BANKS if slot_format == 0 else VALID_MAX_BANKS_V6
    bank_entries = MAX_BANKS if contains_snapshot else valid_max_banks
    size = SLOT_HEADER_SIZE + DESCRIPTOR_SIZE + bank_entries * BANK_DESCRIPTOR_SIZE
    return (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def build_vbk(
    slot_format: int,
    slot1: tuple[str, int, int],
    slot2: tuple[str, int, int],
) -> tuple[bytes, int, int]:
    """Build a synthetic VBK image with two described snapshot slots.

    Each slot spec is ``(state, version, root_page)`` where ``state`` is one of:

    - ``"empty"``: ``ContainsSnapshot`` is not set;
    - ``"valid"``: fully written metadata with a CRC computed over its covered bytes;
    - ``"torn"``: like ``"valid"`` but with a byte inside the CRC coverage flipped afterwards,
      modeling a half-written slot that still advertises the higher version;
    - ``"wrong_crc"``: carrying a CRC produced with the other CRC algorithm than the one
      ``SnapshotSlotFormat`` requires.
    """
    s1_contains = slot1[0] != "empty"
    s2_contains = slot2[0] != "empty"
    s1_size = slot_image_size(s1_contains, slot_format)
    s2_size = slot_image_size(s2_contains, slot_format)

    slot1_offset = PAGE_SIZE
    slot2_offset = slot1_offset + s1_size
    bank_start = slot2_offset + s2_size

    # Every populated slot gets a bank: a (zeroed) bank header page plus one data page.
    bank_geometry = (
        (bank_start, 2 * PAGE_SIZE),
        (bank_start + 2 * PAGE_SIZE, 2 * PAGE_SIZE),
    )
    image = bytearray(bank_start + 4 * PAGE_SIZE)

    storage_header = c_vbk.StorageHeader(
        FormatVersion=9,
        Initialized=1,
        SnapshotSlotFormat=slot_format,
        StandardBlockSize=0x10000,
    ).dumps()
    image[: len(storage_header)] = storage_header

    def write_slot(offset: int, spec: tuple[str, int, int], bank: tuple[int, int]) -> None:
        state, version, root_page = spec
        if state == "empty":
            struct.pack_into("<II", image, offset, 0, 0)
            return

        struct.pack_into("<II", image, offset, 0, 1)  # CRC placeholder + ContainsSnapshot
        descriptor = c_vbk.SnapshotDescriptor(
            Version=version,
            StorageEOF=len(image),
            BanksCount=1,
            DirectoryRoot=c_vbk.DirectoryRootRecord(RootPage=root_page, Count=0),
            BlocksStore=c_vbk.BlocksStoreHeader(RootPage=0, Count=0),
            CryptoStore=c_vbk.CryptoStoreRecord(RootPage=-1),
        ).dumps()
        grain = c_vbk.BanksGrain(MaxBanks=MAX_BANKS, StoredBanks=1).dumps()
        bank_descriptor = c_vbk.BankDescriptor(CRC=0, Offset=bank[0], Size=bank[1]).dumps()

        body = descriptor + grain + bank_descriptor
        image[offset + SLOT_HEADER_SIZE : offset + SLOT_HEADER_SIZE + len(body)] = body

        if state == "wrong_crc":
            wrong_algorithm = crc32 if slot_format > 5 else crc32c
            covered_length = 4 + DESCRIPTOR_SIZE + GRAIN_SIZE + BANK_DESCRIPTOR_SIZE
            stored_crc = wrong_algorithm(image[offset + 4 : offset + 4 + covered_length])
        else:
            stored_crc = expected_slot_crc(bytes(image), offset, slot_format)
        struct.pack_into("<I", image, offset, stored_crc)

        if state == "torn":
            # Flip a byte in the first bank descriptor, which is part of the CRC coverage but does
            # not affect parsing of the descriptor or grain.
            torn_offset = offset + SLOT_HEADER_SIZE + DESCRIPTOR_SIZE + GRAIN_SIZE
            image[torn_offset] ^= 0xFF

    write_slot(slot1_offset, slot1, bank_geometry[0])
    write_slot(slot2_offset, slot2, bank_geometry[1])

    # Each bank data page is a one-page meta blob whose NextPage pointer terminates the chain.
    for bank_offset, _ in bank_geometry:
        struct.pack_into("<q", image, bank_offset + PAGE_SIZE, -1)

    return bytes(image), slot1_offset, slot2_offset


def open_vbk(image: bytes, verify: bool) -> VBK:
    return VBK(BytesIO(image), verify=verify)


@pytest.mark.parametrize("slot_format", [0, 5, 6], ids=["crc32", "crc32-boundary-format5", "crc32c"])
def test_torn_higher_version_slot_is_rejected_for_valid_old_slot(slot_format: int) -> None:
    """A half-written new slot must not win over a committed lower-version slot."""
    image, slot1_offset, slot2_offset = build_vbk(
        slot_format,
        ("valid", OLD_VERSION, OLD_ROOT_PAGE),
        ("torn", NEW_VERSION, NEW_ROOT_PAGE),
    )

    assert expected_slot_crc(image, slot1_offset, slot_format) == struct.unpack_from("<I", image, slot1_offset)[0]
    assert expected_slot_crc(image, slot2_offset, slot_format) != struct.unpack_from("<I", image, slot2_offset)[0]

    vbk = open_vbk(image, verify=True)

    assert vbk.active_slot.offset == slot1_offset
    assert vbk.active_slot.descriptor.Version == OLD_VERSION
    assert vbk.root.root == OLD_ROOT_PAGE


@pytest.mark.parametrize("slot_format", [0, 5, 6], ids=["crc32", "crc32-boundary-format5", "crc32c"])
def test_no_active_slot_when_both_slots_are_invalid(slot_format: int) -> None:
    """With no slot carrying a valid CRC there is no metadata that can be confirmed committed."""
    image, _, slot2_offset = build_vbk(
        slot_format,
        ("torn", OLD_VERSION, OLD_ROOT_PAGE),
        ("torn", NEW_VERSION, NEW_ROOT_PAGE),
    )

    with pytest.raises(VBKError, match="No active VBK metadata slot found"):
        open_vbk(image, verify=True)

    # The raw bytes of the higher-versioned slot are still present, they are just not trustworthy.
    stored_crc = struct.unpack_from("<I", image, slot2_offset)[0]
    assert expected_slot_crc(image, slot2_offset, slot_format) != stored_crc


@pytest.mark.parametrize("slot_format", [0, 5, 6], ids=["crc32", "crc32-boundary-format5", "crc32c"])
def test_verify_false_trusts_unverified_metadata(slot_format: int) -> None:
    """verify=False gives up the CRC integrity guarantee and falls back to raw version ordering.

    Without verification the torn higher-version slot is treated as active, so the root directory is
    sourced from bytes that were never confirmed committed.
    """
    image, _, slot2_offset = build_vbk(
        slot_format,
        ("valid", OLD_VERSION, OLD_ROOT_PAGE),
        ("torn", NEW_VERSION, NEW_ROOT_PAGE),
    )

    vbk = open_vbk(image, verify=False)

    assert vbk.active_slot.offset == slot2_offset
    assert vbk.root.root == NEW_ROOT_PAGE


def test_contains_snapshot_gate_ignores_unpopulated_higher_version_slot() -> None:
    """A slot without ContainsSnapshot cannot be selected even if its bytes look versioned."""
    image, slot1_offset, slot2_offset = build_vbk(
        0,
        ("valid", OLD_VERSION, OLD_ROOT_PAGE),
        ("empty", NEW_VERSION, NEW_ROOT_PAGE),
    )

    assert struct.unpack_from("<I", image, slot2_offset + 4)[0] == 0

    vbk = open_vbk(image, verify=True)

    assert vbk.active_slot.offset == slot1_offset
    assert vbk.root.root == OLD_ROOT_PAGE

    # When no slot is populated at all, neither ContainsSnapshot nor CRC can save the reader.
    empty_image, _, _ = build_vbk(0, ("empty", OLD_VERSION, OLD_ROOT_PAGE), ("empty", NEW_VERSION, NEW_ROOT_PAGE))
    with pytest.raises(VBKError, match="No active VBK metadata slot found"):
        open_vbk(empty_image, verify=False)


@pytest.mark.parametrize("slot_format", [0, 5, 6], ids=["crc32", "crc32-boundary-format5", "crc32c"])
def test_crc_computed_with_wrong_algorithm_does_not_validate(slot_format: int) -> None:
    """A valid CRC32 stored in a CRC32C slot (and vice versa) must be treated as corrupt."""
    image, slot1_offset, slot2_offset = build_vbk(
        slot_format,
        ("valid", OLD_VERSION, OLD_ROOT_PAGE),
        ("wrong_crc", NEW_VERSION, NEW_ROOT_PAGE),
    )

    stored_crc = struct.unpack_from("<I", image, slot2_offset)[0]
    assert expected_slot_crc(image, slot2_offset, slot_format) != stored_crc

    vbk = open_vbk(image, verify=True)

    assert vbk.active_slot.offset == slot1_offset
    assert vbk.root.root == OLD_ROOT_PAGE


@pytest.mark.parametrize("slot_format", [0, 5, 6], ids=["crc32", "crc32-boundary-format5", "crc32c"])
def test_highest_version_wins_when_both_slots_are_committed(slot_format: int) -> None:
    """Baseline: version ordering only decides between slots that both pass all criteria."""
    image, _, slot2_offset = build_vbk(
        slot_format,
        ("valid", OLD_VERSION, OLD_ROOT_PAGE),
        ("valid", NEW_VERSION, NEW_ROOT_PAGE),
    )

    vbk = open_vbk(image, verify=True)

    assert vbk.active_slot.offset == slot2_offset
    assert vbk.active_slot.descriptor.Version == NEW_VERSION
    assert vbk.root.root == NEW_ROOT_PAGE
