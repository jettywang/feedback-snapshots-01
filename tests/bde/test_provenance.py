from __future__ import annotations

import struct
from typing import BinaryIO

import pytest

from dissect.fve.bde import SourceType, bde
from dissect.fve.bde.information import Information


def _unlock_vista(bde_obj: bde.BDE) -> None:
    bde_obj.unlock_with_recovery_password("517506-503998-044583-576191-587004-635965-501270-087802")


def _unlock_aes_128(bde_obj: bde.BDE) -> None:
    bde_obj.unlock_with_passphrase("password12!@")


def test_provenance_vista_boot_sector(bde_vista: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_vista)
    _unlock_vista(bde_obj)
    stream = bde_obj.open()

    data, segments = stream.read_with_provenance(0, 0x2000)

    # Plaintext must be identical to the regular decryption interface
    stream.seek(0)
    assert data == stream.read(0x2000)

    assert [segment.source for segment in segments] == [SourceType.VISTA_COMPAT, SourceType.ORIGINAL]

    boot = segments[0]
    assert boot.offset == 0
    assert boot.size == 0x200
    assert boot.physical_offset == 0

    # The original on-disk bytes are retained separately from the logical plaintext
    bde_obj.fh.seek(0)
    on_disk = bde_obj.fh.read(0x200)
    assert boot.raw == on_disk
    assert boot.data != boot.raw

    # The compatibility interpretation is explicitly identifiable
    assert boot.raw[0x03:0x0B] == b"-FVE-FS-"
    assert boot.data[0x03:0x0B] == b"NTFS    "

    assert len(boot.patches) == 2
    oem_patch, mft2_patch = boot.patches

    assert oem_patch.offset == 0x03
    assert oem_patch.field == "OEM ID"
    assert oem_patch.original == b"-FVE-FS-"
    assert oem_patch.patched == b"NTFS    "

    assert mft2_patch.offset == 0x38
    assert mft2_patch.field == "MFT2 start LCN"
    assert mft2_patch.original == on_disk[0x38:0x40]
    assert mft2_patch.patched == struct.pack("<Q", bde_obj.information.header.Mft2StartLcn)

    # The remainder of the Vista header is plaintext at its original location
    plain = segments[1]
    assert plain.offset == 0x200
    assert plain.physical_offset == 0x200
    assert plain.patches == []
    assert plain.data == plain.raw


def test_provenance_virtualized_boot_sector(bde_aes_128: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_aes_128)
    _unlock_aes_128(bde_obj)
    stream = bde_obj.open()

    assert stream.relocation_valid

    data, segments = stream.read_with_provenance(0, 0x2000)

    stream.seek(0)
    assert data == stream.read(0x2000)

    assert len(segments) == 1
    boot = segments[0]
    assert boot.source == SourceType.RELOCATED
    assert boot.offset == 0
    assert boot.size == 0x2000
    assert boot.patches == []

    # The boot sector is relocated to the virtualized block, not at its logical location
    assert boot.physical_offset == bde_obj.information.virtualized_block_offset == 0x2200000

    # Reading the source back from the reported physical location yields ciphertext
    bde_obj.fh.seek(boot.physical_offset)
    assert bde_obj.fh.read(0x2000) == boot.raw
    assert boot.raw != boot.data
    assert boot.raw[0x03:0x0B] != b"NTFS    "
    assert boot.data[0x03:0x0B] == b"NTFS    "

    # The logical plaintext is the decryption of the relocated ciphertext
    assert stream.cipher.decrypt(boot.raw, boot.physical_offset // stream.sector_size) == boot.data


def test_provenance_spanning_regions(bde_aes_128: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_aes_128)
    _unlock_aes_128(bde_obj)
    stream = bde_obj.open()

    # Crosses the virtualized region boundary at 0x2000 with a misaligned start
    data, segments = stream.read_with_provenance(0x1800, 0x1000)

    stream.seek(0x1800)
    assert data == stream.read(0x1000)

    assert [(segment.source, segment.offset, segment.size) for segment in segments] == [
        (SourceType.RELOCATED, 0x1800, 0x800),
        (SourceType.DECRYPTED, 0x2000, 0x800),
    ]
    assert segments[0].physical_offset == 0x2200000 + 0x1800
    assert segments[1].physical_offset == 0x2000

    # Crosses a normal encrypted region, the reserved regions and back
    offset = 0x21F0000 - 0x200
    length = 0x200 + 0x12000 + 0x200
    data, segments = stream.read_with_provenance(offset, length)

    stream.seek(offset)
    assert data == stream.read(length)

    assert [(segment.source, segment.offset, segment.size) for segment in segments] == [
        (SourceType.DECRYPTED, offset, 0x200),
        (SourceType.RESERVED, 0x21F0000, 0x12000),
        (SourceType.DECRYPTED, 0x2202000, 0x200),
    ]

    reserved = segments[1]
    assert reserved.physical_offset is None
    assert reserved.raw is None
    assert reserved.data == b"\x00" * reserved.size


def test_provenance_decrypted_volume(bde_decrypted: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_decrypted)
    stream = bde_obj.open()

    # The first sectors are still relocated to the virtualized block, but stored in plaintext
    data, segments = stream.read_with_provenance(0, 0x400)

    stream.seek(0)
    assert data == stream.read(0x400)

    assert len(segments) == 1
    assert segments[0].source == SourceType.RELOCATED
    assert segments[0].physical_offset == bde_obj.information.virtualized_block_offset
    assert segments[0].data == segments[0].raw

    # Beyond the virtualized region everything is plaintext at its original location
    data, segments = stream.read_with_provenance(0x2000, 0x400)

    stream.seek(0x2000)
    assert data == stream.read(0x400)

    assert len(segments) == 1
    assert segments[0].source == SourceType.ORIGINAL
    assert segments[0].physical_offset == 0x2000
    assert segments[0].data == segments[0].raw


@pytest.mark.parametrize("corrupt_offset", [0, 0x123])
def test_provenance_corrupt_relocation(
    bde_aes_128: BinaryIO, monkeypatch: pytest.MonkeyPatch, corrupt_offset: int
) -> None:
    bde_obj = bde.BDE(bde_aes_128)
    _unlock_aes_128(bde_obj)

    # Adjacent metadata carries a plausible relocation offset, it must not be borrowed
    virtualization_info = bde_obj.information.dataset.find_virtualization_info()
    assert virtualization_info is not None
    assert virtualization_info.virtualized_block_offset == 0x2200000

    monkeypatch.setattr(Information, "virtualized_block_offset", property(lambda self: corrupt_offset))
    stream = bde_obj.open()

    assert not stream.relocation_valid
    assert stream.relocation_problems()

    segments = stream.provenance(0, 0x2000)
    assert len(segments) == 1
    assert segments[0].source == SourceType.CORRUPT

    # No valid boot sector is produced by borrowing the adjacent metadata
    assert segments[0].physical_offset != virtualization_info.virtualized_block_offset

    # Sectors beyond the virtualized range are unaffected
    segments = stream.provenance(0x2000, 0x200)
    assert segments[0].source == SourceType.DECRYPTED
