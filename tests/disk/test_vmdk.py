from __future__ import annotations

import gzip
import struct
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dissect.hypervisor.disk.c_vmdk import SECTOR_SIZE, VMDK_MAGIC, c_vmdk
from dissect.hypervisor.disk.vmdk import VMDK, DiskDescriptor, ExtentDescriptor, open_parent
from tests._util import absolute_path


def descriptor(tmp_path: Path, extents: list[str], name: str = "disk.vmdk") -> Path:
    path = tmp_path / name
    path.write_text(
        "\n".join(
            [
                "# Disk DescriptorFile",
                "version=1",
                "CID=fffffffe",
                "parentCID=ffffffff",
                "",
                "# Extent Description",
                *extents,
                "",
                "#DDB",
                'ddb.virtualHWVersion = "4"',
                "",
            ]
        )
    )
    return path


def test_vmdk_sesparse() -> None:
    with gzip.open(absolute_path("_data/disk/vmdk/sesparse.vmdk.gz"), "rb") as fh:
        vmdk = VMDK(fh)

        disk = vmdk.disks[0]

        assert disk.is_sesparse
        assert disk._grain_directory_size == 0x20000
        assert disk._grain_table_size == 0x1000
        assert disk._grain_entry_type == c_vmdk.uint64
        assert disk._grain_directory[0] == 0x1000000000000000

        header = disk.header
        assert header.magic == c_vmdk.SESPARSE_CONST_HEADER_MAGIC
        assert header.version == 0x200000001

        assert vmdk.read(0x1000000) == b"a" * 0x1000000


@pytest.mark.parametrize(
    ("extent_description", "expected_extents"),
    [
        (
            'RW 123456789 SPARSE "disk.vmdk"',
            [
                ExtentDescriptor(
                    raw='RW 123456789 SPARSE "disk.vmdk"',
                    access_mode="RW",
                    sectors=123456789,
                    type="SPARSE",
                    filename='"disk.vmdk"',
                    start_sector=None,
                    partition_uuid=None,
                    device_identifier=None,
                ),
            ],
        ),
        (
            'RW 123456789 FLAT "disk-flat.vmdk" 0',
            [
                ExtentDescriptor(
                    raw='RW 123456789 FLAT "disk-flat.vmdk" 0',
                    access_mode="RW",
                    sectors=123456789,
                    type="FLAT",
                    filename='"disk-flat.vmdk"',
                    start_sector=0,
                    partition_uuid=None,
                    device_identifier=None,
                )
            ],
        ),
        (
            "RDONLY 0 ZERO",
            [
                ExtentDescriptor(
                    raw="RDONLY 0 ZERO",
                    access_mode="RDONLY",
                    sectors=0,
                    type="ZERO",
                ),
            ],
        ),
        (
            'NOACCESS 123456789 SPARSE "disk-sparse.vmdk" 123 partition-uuid device-id',
            [
                ExtentDescriptor(
                    raw='NOACCESS 123456789 SPARSE "disk-sparse.vmdk" 123 partition-uuid device-id',
                    access_mode="NOACCESS",
                    sectors=123456789,
                    type="SPARSE",
                    filename='"disk-sparse.vmdk"',
                    start_sector=123,
                    partition_uuid="partition-uuid",
                    device_identifier="device-id",
                ),
            ],
        ),
        ("RW 1234567890", []),
        ('RDONLY "file.vmdk"', []),
        ("NOACCESS", []),
        (
            'RW 1234567890 SPARSE "disk with spaces.vmdk"',
            [
                ExtentDescriptor(
                    raw='RW 1234567890 SPARSE "disk with spaces.vmdk"',
                    access_mode="RW",
                    sectors=1234567890,
                    type="SPARSE",
                    filename='"disk with spaces.vmdk"',
                    start_sector=None,
                    partition_uuid=None,
                    device_identifier=None,
                )
            ],
        ),
        (
            'RW 1234567890 SPARSE "disk with spaces.vmdk" 123',
            [
                ExtentDescriptor(
                    raw='RW 1234567890 SPARSE "disk with spaces.vmdk" 123',
                    access_mode="RW",
                    sectors=1234567890,
                    type="SPARSE",
                    filename='"disk with spaces.vmdk"',
                    start_sector=123,
                    partition_uuid=None,
                    device_identifier=None,
                )
            ],
        ),
        (
            'RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid',
            [
                ExtentDescriptor(
                    raw='RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid',
                    access_mode="RW",
                    sectors=1234567890,
                    type="SPARSE",
                    filename='"disk with spaces.vmdk"',
                    start_sector=123,
                    partition_uuid="part-uuid",
                    device_identifier=None,
                )
            ],
        ),
        (
            'RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid device-id',
            [
                ExtentDescriptor(
                    raw='RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid device-id',
                    access_mode="RW",
                    sectors=1234567890,
                    type="SPARSE",
                    filename='"disk with spaces.vmdk"',
                    start_sector=123,
                    partition_uuid="part-uuid",
                    device_identifier="device-id",
                )
            ],
        ),
        (
            r'RW 16777216 SPARSE "this is an example "\' diskëäô:)\\\'`\foo.vmdk" 123',
            [
                ExtentDescriptor(
                    raw=r'RW 16777216 SPARSE "this is an example "\' diskëäô:)\\\'`\foo.vmdk" 123',
                    access_mode="RW",
                    sectors=16777216,
                    type="SPARSE",
                    filename=r'"this is an example "\' diskëäô:)\\\'`\foo.vmdk"',
                    start_sector=123,
                    partition_uuid=None,
                    device_identifier=None,
                )
            ],
        ),
        (
            r'RW 13371337 SPARSE "🦊 🦊 🦊.vmdk"',
            [
                ExtentDescriptor(
                    raw=r'RW 13371337 SPARSE "🦊 🦊 🦊.vmdk"',
                    access_mode="RW",
                    sectors=13371337,
                    type="SPARSE",
                    filename='"🦊 🦊 🦊.vmdk"',
                )
            ],
        ),
    ],
    ids=(
        "sparse",
        "flat",
        "zero",
        "sparse-ids",
        "bad-1",
        "bad-2",
        "bad-3",
        "spaces-four-parts",
        "spaces-five-parts",
        "spaces-six-parts",
        "spaces-seven-parts",
        "specials-five-parts",
        "emoji-four-parts",
    ),
)
def test_vmdk_extent_description(extent_description: str, expected_extents: list[ExtentDescriptor]) -> None:
    """Test if we correctly parse VMDK sparse and flat extent descriptions.

    Resources:
        - https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#22-extent-descriptions
    """
    descriptor = DiskDescriptor.parse(extent_description)
    assert descriptor.extents == expected_extents


def test_open_parent_all_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test open_parent handles absolute and relative filename_hint paths."""

    # Mock Path.exists to simulate file existence
    def mock_exists(path: Path) -> bool:
        return str(path) in {
            "/a/b/c/d.vmdk",  # Case: absolute path
            "base/relative/hint.vmdk",  # Case: full relative path
            "base/hint.vmdk",  # Case: basename in same dir
            "../sibling/hint.vmdk",  # Case: fallback to sibling
        }

    with monkeypatch.context() as m:
        m.setattr("pathlib.Path.exists", mock_exists)

        # Mock VMDK to avoid real file I/O
        mock_vmdk = MagicMock()
        m.setattr("dissect.hypervisor.disk.vmdk.VMDK", lambda path: mock_vmdk)
        mock_vmdk.path = "mocked-path"

        # Case: Absolute path — should use /a/b/c/d.vmdk directly
        vmdk = open_parent(Path("base"), "/a/b/c/d.vmdk")
        assert str(vmdk.path) == "mocked-path"

        # Case: Full relative path — try base/relative/hint.vmdk
        vmdk = open_parent(Path("base"), "relative/hint.vmdk")
        assert str(vmdk.path) == "mocked-path"

        # Case: Basename only — fall back to base/hint.vmdk
        vmdk = open_parent(Path("base"), "hint.vmdk")
        assert str(vmdk.path) == "mocked-path"

        # Case: Fallback to sibling — try ../sibling/hint.vmdk
        vmdk = open_parent(Path("base"), "sibling/hint.vmdk")
        assert str(vmdk.path) == "mocked-path"


def test_vmdk_flat_start_sector(tmp_path: Path) -> None:
    """A FLAT extent only exposes its declared sector range in the backing file."""
    # Prefix, valid range and tail all have distinct contents so any leak is visible
    (tmp_path / "flat.vmdk").write_bytes(b"P" * 4 * SECTOR_SIZE + b"V" * 8 * SECTOR_SIZE + b"T" * 4 * SECTOR_SIZE)

    vmdk = VMDK(descriptor(tmp_path, ['RW 8 FLAT "flat.vmdk" 4']))

    assert vmdk.size == 8 * SECTOR_SIZE
    assert vmdk.read() == b"V" * 8 * SECTOR_SIZE

    # Reads before the valid range, on both sides of the boundary and after it
    assert vmdk.readoffset(0, SECTOR_SIZE) == b"V" * SECTOR_SIZE
    assert vmdk.readoffset(7 * SECTOR_SIZE + 100, SECTOR_SIZE) == b"V" * (SECTOR_SIZE - 100)
    assert vmdk.readoffset(vmdk.size, 1024) == b""
    assert vmdk.readoffset(vmdk.size - 100, 200) == b"V" * 100


def test_vmdk_flat_unaligned_reads(tmp_path: Path) -> None:
    """Unaligned reads on and around extent boundaries return only declared bytes."""
    (tmp_path / "flat.vmdk").write_bytes(bytes(range(256)) * 36)

    # Every byte in the backing file differs from the next, so offset errors show up immediately
    vmdk = VMDK(descriptor(tmp_path, ['RW 8 FLAT "flat.vmdk" 4']))
    expected = bytes(range(256)) * 36
    expected = expected[4 * SECTOR_SIZE : 12 * SECTOR_SIZE]

    for offset in (0, 1, 511, 512, 513, 1000, 4095, 4096, 4097, 5000, vmdk.size - 1, vmdk.size):
        length = 1 if offset >= vmdk.size else 700
        assert vmdk.readoffset(offset, length) == expected[offset : offset + length], hex(offset)


def test_vmdk_multiple_extents(tmp_path: Path) -> None:
    """Multiple extents with different backing offsets are joined at the correct logical positions."""
    (tmp_path / "a.vmdk").write_bytes(b"P" * 3 * SECTOR_SIZE + b"A" * 4 * SECTOR_SIZE + b"Q" * 3 * SECTOR_SIZE)
    (tmp_path / "b.vmdk").write_bytes(b"R" * 2 * SECTOR_SIZE + b"B" * 5 * SECTOR_SIZE + b"S" * 2 * SECTOR_SIZE)

    vmdk = VMDK(
        descriptor(
            tmp_path,
            [
                'RW 4 FLAT "a.vmdk" 3',
                "RW 2 ZERO",
                'RW 5 FLAT "b.vmdk" 2',
            ],
        )
    )

    assert vmdk.size == 11 * SECTOR_SIZE
    assert vmdk.read() == b"A" * 4 * SECTOR_SIZE + b"\x00" * 2 * SECTOR_SIZE + b"B" * 5 * SECTOR_SIZE

    # Read across every extent boundary, both aligned and unaligned
    assert vmdk.readoffset(3 * SECTOR_SIZE + 100, 200) == b"A" * 200
    assert vmdk.readoffset(4 * SECTOR_SIZE - 100, 200) == b"A" * 100 + b"\x00" * 100
    assert vmdk.readoffset(6 * SECTOR_SIZE - 100, 200) == b"\x00" * 100 + b"B" * 100
    assert vmdk.readoffset(7 * SECTOR_SIZE - 100, 200) == b"B" * 200

    # Unaligned read spanning the two FLAT extents and the ZERO extent in between
    data = vmdk.readoffset(2 * SECTOR_SIZE + 123, 6 * SECTOR_SIZE)
    assert data == b"A" * (2 * SECTOR_SIZE - 123) + b"\x00" * 2 * SECTOR_SIZE + b"B" * (2 * SECTOR_SIZE + 123)


def test_vmdk_extent_shorter_than_declared(tmp_path: Path) -> None:
    """A backing file shorter than its declared extent must not borrow bytes from a neighbouring extent."""
    (tmp_path / "short.vmdk").write_bytes(b"V" * 3 * SECTOR_SIZE)
    (tmp_path / "next.vmdk").write_bytes(b"W" * 5 * SECTOR_SIZE)

    vmdk = VMDK(
        descriptor(
            tmp_path,
            [
                'RW 8 FLAT "short.vmdk" 0',
                'RW 5 FLAT "next.vmdk" 0',
            ],
        )
    )

    assert vmdk.size == 13 * SECTOR_SIZE
    assert vmdk.read() == b"V" * 3 * SECTOR_SIZE + b"\x00" * 5 * SECTOR_SIZE + b"W" * 5 * SECTOR_SIZE

    # The short extent's missing tail must not expose bytes from the next extent
    assert vmdk.readoffset(2 * SECTOR_SIZE, 2 * SECTOR_SIZE) == b"V" * SECTOR_SIZE + b"\x00" * SECTOR_SIZE


def test_vmdk_flat_start_beyond_file(tmp_path: Path) -> None:
    """A start sector beyond the backing material reads as zeroes, not as bytes from elsewhere."""
    (tmp_path / "flat.vmdk").write_bytes(b"P" * 4 * SECTOR_SIZE)

    vmdk = VMDK(descriptor(tmp_path, ['RW 4 FLAT "flat.vmdk" 10']))

    assert vmdk.read() == b"\x00" * 4 * SECTOR_SIZE


def test_vmdk_zero_extent(tmp_path: Path) -> None:
    """A ZERO extent occupies its declared range and always reads as zeroes."""
    vmdk = VMDK(descriptor(tmp_path, ["RW 6 ZERO"], "zero.vmdk"))

    assert vmdk.size == 6 * SECTOR_SIZE
    assert vmdk.read() == b"\x00" * 6 * SECTOR_SIZE
    assert vmdk.readoffset(SECTOR_SIZE - 10, 20) == b"\x00" * 20


def sparse_extent(tmp_path: Path, capacity: int, allocated: bytes | None) -> Path:
    """Create a minimal sparse extent with optional allocated grains at logical sectors 0 and 12."""
    grain_size = 4
    grain_table_sectors = 1
    # Sector layout: 0 header, 1 descriptor, 2 grain directory, 3 grain table, 4 unused, 5+ grain data
    grain_data_sector = 5
    header = c_vmdk.VMDKSparseExtentHeader()
    header.magic = VMDK_MAGIC
    header.version = 1
    header.flags = 0
    header.capacity = capacity
    header.grain_size = grain_size
    header.descriptor_offset = 1
    header.descriptor_size = 1
    header.num_grain_table_entries = 512
    header.primary_grain_directory_offset = 2
    header.secondary_grain_directory_offset = 0
    header.overhead = 4
    header.is_dirty = 0
    header.compress_algorithm = 0

    buf = bytearray(header.dumps())
    buf += b"\x00" * SECTOR_SIZE
    buf += struct.pack("<I", 3) + b"\x00" * (SECTOR_SIZE - 4)

    grain_table = bytearray(grain_table_sectors * SECTOR_SIZE)
    if allocated:
        struct.pack_into("<I", grain_table, 0, grain_data_sector)
    # An allocated grain that is only reachable if the sparse header capacity is ignored
    struct.pack_into("<I", grain_table, 3 * 4, grain_data_sector + grain_size)
    buf += grain_table
    buf += b"\x00" * SECTOR_SIZE
    buf += allocated or b""
    buf += b"X" * grain_size * SECTOR_SIZE

    path = tmp_path / "sparse.vmdk"
    path.write_bytes(bytes(buf))
    return path


def test_vmdk_sparse_declared_length(tmp_path: Path) -> None:
    """A sparse extent must not expose grains outside its descriptor-declared range."""
    sparse_extent(tmp_path, capacity=8, allocated=b"S" * 4 * SECTOR_SIZE)

    exact = VMDK(descriptor(tmp_path, ['RW 8 SPARSE "sparse.vmdk"'], "exact.vmdk"))
    assert exact.size == 8 * SECTOR_SIZE
    assert exact.read() == b"S" * 4 * SECTOR_SIZE + b"\x00" * 4 * SECTOR_SIZE

    # Declaring more sectors than the sparse header covers must read as zeroes, not as more material
    longer = VMDK(descriptor(tmp_path, ['RW 12 SPARSE "sparse.vmdk"'], "longer.vmdk"))
    assert longer.size == 12 * SECTOR_SIZE
    assert longer.read() == b"S" * 4 * SECTOR_SIZE + b"\x00" * 8 * SECTOR_SIZE

    # Grains beyond the header capacity must not become readable just because the descriptor is longer
    beyond = VMDK(descriptor(tmp_path, ['RW 16 SPARSE "sparse.vmdk"'], "beyond.vmdk"))
    assert beyond.size == 16 * SECTOR_SIZE
    assert beyond.read() == b"S" * 4 * SECTOR_SIZE + b"\x00" * 12 * SECTOR_SIZE

    # Declaring less sectors truncates the virtual disk at the descriptor boundary
    shorter = VMDK(descriptor(tmp_path, ['RW 4 SPARSE "sparse.vmdk"'], "shorter.vmdk"))
    assert shorter.size == 4 * SECTOR_SIZE
    assert shorter.read() == b"S" * 4 * SECTOR_SIZE
    assert shorter.readoffset(shorter.size - 100, 200) == b"S" * 100


def test_vmdk_sparse_shorter_than_declared(tmp_path: Path) -> None:
    """A sparse extent declaring more sectors than the header capacity never falls through to adjacent content."""
    (tmp_path / "next.vmdk").write_bytes(b"N" * 4 * SECTOR_SIZE)
    sparse_extent(tmp_path, capacity=4, allocated=None)

    vmdk = VMDK(
        descriptor(
            tmp_path,
            [
                'RW 8 SPARSE "sparse.vmdk"',
                'RW 4 FLAT "next.vmdk" 0',
            ],
        )
    )

    assert vmdk.size == 12 * SECTOR_SIZE
    assert vmdk.read() == b"\x00" * 8 * SECTOR_SIZE + b"N" * 4 * SECTOR_SIZE


def test_vmdk_zero_length_extent(tmp_path: Path) -> None:
    """A zero-length extent occupies no space and must not expose its backing file."""
    (tmp_path / "empty.vmdk").write_bytes(b"E" * 4 * SECTOR_SIZE)
    (tmp_path / "data.vmdk").write_bytes(b"D" * 2 * SECTOR_SIZE)

    vmdk = VMDK(
        descriptor(
            tmp_path,
            [
                'RW 0 FLAT "empty.vmdk" 0',
                'RW 2 FLAT "data.vmdk" 0',
                "RW 0 ZERO",
            ],
        )
    )

    assert vmdk.size == 2 * SECTOR_SIZE
    assert vmdk.read() == b"D" * 2 * SECTOR_SIZE
    assert vmdk.readoffset(SECTOR_SIZE, SECTOR_SIZE) == b"D" * SECTOR_SIZE


def test_vmdk_parse_start_sector(tmp_path: Path) -> None:
    """The descriptor start sector is parsed as an integer and zero is preserved."""
    parsed = DiskDescriptor.parse('RW 8 FLAT "flat.vmdk" 0')
    assert parsed.extents[0].start_sector == 0

    parsed = DiskDescriptor.parse('RW 8 FLAT "flat.vmdk" 123')
    assert parsed.extents[0].start_sector == 123
