from __future__ import annotations

import gzip
import io
from uuid import UUID

import pytest

from dissect.hypervisor.disk.vhdx import VHDX, _iter_partial_runs, c_vhdx
from dissect.hypervisor.exceptions import InvalidSignature, InvalidVirtualDisk
from tests._util import absolute_path

ALIGNMENT = 64 * 1024
MB = 1024 * 1024

BAT_GUID = UUID("2dc27766-f623-4200-9d64-115e9bfd4a08")
METADATA_REGION_GUID = UUID("8b7ca206-4790-4b9a-b8fe-575f050f886e")
FILE_PARAMETERS_GUID = UUID("caa16737-fa36-4d43-b3b6-33f0aa44e76b")
VIRTUAL_DISK_SIZE_GUID = UUID("2fa54224-cd1b-4876-b211-5dbed83bf4b8")
LOGICAL_SECTOR_SIZE_GUID = UUID("8141bf1d-a96f-4709-ba47-f233a8faab5f")
PHYSICAL_SECTOR_SIZE_GUID = UUID("cda348c7-445d-4471-9cc9-e9885251c556")
VIRTUAL_DISK_ID_GUID = UUID("beca12ab-b2e6-4523-93ef-c309e000c746")
PARENT_LOCATOR_GUID = UUID("a8d35f2d-b30b-454d-abf7-d3d84834ab0c")
VHDX_PARENT_LOCATOR_GUID = UUID("b04aefb7-d19e-4a81-b789-25b8e9445913")

UNKNOWN_OPTIONAL_GUID = UUID("11111111-2222-3333-4444-555555555555")
UNKNOWN_REQUIRED_GUID = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


def test_vhdx_fixed() -> None:
    with gzip.open(absolute_path("_data/disk/vhdx/fixed.vhdx.gz"), "rb") as fh:
        v = VHDX(fh)

        assert v.size == 0xA00000
        assert v.block_size == 0x200000
        assert v.has_parent == 0
        assert v.sector_size == 0x200
        assert v.bat.chunk_ratio == 0x800
        assert v.id == UUID("4a49d245-db0a-4634-9818-9f93db5ba6c1")

        assert v.read(512) == bytes.fromhex(
            "33c08ed0bc007c8ec08ed8be007cbf0006b90002fcf3a450681c06cbfbb90400"
            "bdbe07807e00007c0b0f850e0183c510e2f1cd1888560055c6461105c6461000"
            "b441bbaa55cd135d720f81fb55aa7509f7c101007403fe46106660807e100074"
            "2666680000000066ff760868000068007c680100681000b4428a56008bf4cd13"
            "9f83c4109eeb14b80102bb007c8a56008a76018a4e028a6e03cd136661731cfe"
            "4e11750c807e00800f848a00b280eb845532e48a5600cd135deb9e813efe7d55"
            "aa756eff7600e88d007517fab0d1e664e88300b0dfe660e87c00b0ffe664e875"
            "00fbb800bbcd1a6623c0753b6681fb54435041753281f90201722c666807bb00"
            "006668000200006668080000006653665366556668000000006668007c000066"
            "6168000007cd1a5a32f6ea007c0000cd18a0b707eb08a0b607eb03a0b50732e4"
            "0500078bf0ac3c007409bb0700b40ecd10ebf2f4ebfd2bc9e464eb002402e0f8"
            "2402c3496e76616c696420706172746974696f6e207461626c65004572726f72"
            "206c6f6164696e67206f7065726174696e672073797374656d004d697373696e"
            "67206f7065726174696e672073797374656d000000637b9a8a3dad8c00000002"
            "030007e525008000000000380000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000055aa"
        )

        v.seek(0x200000)
        assert v.read(512) == b"\xff" * 512

        for block in range(v.bat._pb_count):
            block_entry = v.bat.pb(block)
            assert block_entry.state == c_vhdx.PAYLOAD_BLOCK_FULLY_PRESENT


def test_vhdx_dynamic() -> None:
    with gzip.open(absolute_path("_data/disk/vhdx/dynamic.vhdx.gz"), "rb") as fh:
        v = VHDX(fh)

        assert v.size == 0xA00000
        assert v.block_size == 0x2000000
        assert v.has_parent == 0
        assert v.sector_size == 0x200
        assert v.bat.chunk_ratio == 0x80
        assert v.id == UUID("788015f0-5e93-4bd2-a5de-b0cd8459db11")

        assert v.read(512) == bytes.fromhex(
            "33c08ed0bc007c8ec08ed8be007cbf0006b90002fcf3a450681c06cbfbb90400"
            "bdbe07807e00007c0b0f850e0183c510e2f1cd1888560055c6461105c6461000"
            "b441bbaa55cd135d720f81fb55aa7509f7c101007403fe46106660807e100074"
            "2666680000000066ff760868000068007c680100681000b4428a56008bf4cd13"
            "9f83c4109eeb14b80102bb007c8a56008a76018a4e028a6e03cd136661731cfe"
            "4e11750c807e00800f848a00b280eb845532e48a5600cd135deb9e813efe7d55"
            "aa756eff7600e88d007517fab0d1e664e88300b0dfe660e87c00b0ffe664e875"
            "00fbb800bbcd1a6623c0753b6681fb54435041753281f90201722c666807bb00"
            "006668000200006668080000006653665366556668000000006668007c000066"
            "6168000007cd1a5a32f6ea007c0000cd18a0b707eb08a0b607eb03a0b50732e4"
            "0500078bf0ac3c007409bb0700b40ecd10ebf2f4ebfd2bc9e464eb002402e0f8"
            "2402c3496e76616c696420706172746974696f6e207461626c65004572726f72"
            "206c6f6164696e67206f7065726174696e672073797374656d004d697373696e"
            "67206f7065726174696e672073797374656d000000637b9af93dad8c00000002"
            "030007e525008000000000380000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000055aa"
        )

        v.seek(0x200000)
        assert v.read(512) == b"\xff" * 512


def test_vhdx_differencing() -> None:
    with (
        pytest.raises(IOError, match="Failed to open parent disk with locator"),
        gzip.open(absolute_path("_data/disk/vhdx/differencing.avhdx.gz"), "rb") as fh,
    ):
        VHDX(fh)


@pytest.mark.parametrize(
    ("test_input", "expected"),
    [
        ((b"\xff", 0, 8), [(1, 8)]),
        ((b"\xff", 4, 4), [(1, 4)]),
        ((b"\x00", 0, 8), [(0, 8)]),
        ((b"\x00", 4, 4), [(0, 4)]),
        ((b"\xff\x00", 0, 8), [(1, 8)]),
        ((b"\xff\x00", 4, 8), [(1, 4), (0, 4)]),
        ((b"\x00\x00", 0, 12), [(0, 12)]),
        ((b"\x00\xff", 4, 8), [(0, 4), (1, 4)]),
        ((b"\xf0\xf0", 0, 16), [(0, 4), (1, 4), (0, 4), (1, 4)]),
        ((b"\x0f\x0f", 0, 16), [(1, 4), (0, 4), (1, 4), (0, 4)]),
        ((b"\x00", 0, 6), [(0, 6)]),
        ((b"\x00", 1, 6), [(0, 6)]),
    ],
)
def test_vhdx_partial_runs(test_input: tuple[bytes, int, int], expected: list[tuple[int, int]]) -> None:
    assert list(_iter_partial_runs(*test_input)) == expected


def _region_entry(guid: UUID, offset: int, length: int, required: int = 1) -> bytes:
    return c_vhdx.region_table_entry(guid=guid.bytes_le, file_offset=offset, length=length, required=required).dumps()


def _metadata_entry(guid: UUID, offset: int, length: int, user: int = 0, vds: int = 1, req: int = 1) -> bytes:
    return c_vhdx.metadata_table_entry(
        item_id=guid.bytes_le,
        offset=offset,
        length=length,
        is_user=user,
        is_virtual_disk=vds,
        is_required=req,
        reserved2=0,
    ).dumps()


def _build_synthetic_vhdx(
    extra_metadata: list[tuple[UUID, int, bytes, dict]] | None = None,
    extra_metadata_entries: bytes = b"",
    region_entries: list[bytes] | None = None,
    mutate: object | None = None,
    has_parent: int = 0,
    include_parent_locator: bool = False,
    locator_length: int = 512,
    locator_key_offset: int = 64,
    locator_key_length: int = 22,
    file_size: int = 4 * MB,
    mutate_second_region_table: object | None = None,
) -> io.BytesIO:
    """Build a small, in-memory VHDX with controllable region and metadata corruption."""
    buf = bytearray(file_size)
    buf[0:8] = b"vhdxfile"

    buf[ALIGNMENT : ALIGNMENT + c_vhdx.header.size] = c_vhdx.header(signature=b"head", sequence_number=1).dumps()
    buf[2 * ALIGNMENT : 2 * ALIGNMENT + c_vhdx.header.size] = c_vhdx.header(
        signature=b"head", sequence_number=2
    ).dumps()

    entries = region_entries
    if entries is None:
        entries = [
            _region_entry(BAT_GUID, 3 * MB, MB),
            _region_entry(METADATA_REGION_GUID, 2 * MB, MB),
        ]
    region_table = c_vhdx.region_table_header(
        signature=b"regi", checksum=0, entry_count=len(entries), reserved=b"\x00" * 4
    ).dumps() + b"".join(entries)
    buf[3 * ALIGNMENT : 3 * ALIGNMENT + len(region_table)] = region_table

    if mutate_second_region_table is not None:
        second_entries = mutate_second_region_table()
        second_table = c_vhdx.region_table_header(
            signature=b"regi", checksum=0, entry_count=len(second_entries), reserved=b"\x00" * 4
        ).dumps() + b"".join(second_entries)
        buf[4 * ALIGNMENT : 4 * ALIGNMENT + len(second_table)] = second_table
    else:
        buf[4 * ALIGNMENT : 4 * ALIGNMENT + len(region_table)] = region_table

    metadata_offset = 2 * MB
    base_items: list[tuple[UUID, int, bytes, int]] = [
        (
            FILE_PARAMETERS_GUID,
            0x10000,
            c_vhdx.file_parameters(
                block_size=0x200000, leave_block_allocated=0, has_parent=has_parent, reserved=0
            ).dumps(),
            0,
        ),
        (VIRTUAL_DISK_SIZE_GUID, 0x10008, (10 * MB).to_bytes(8, "little"), 1),
        (LOGICAL_SECTOR_SIZE_GUID, 0x10010, (512).to_bytes(4, "little"), 1),
        (PHYSICAL_SECTOR_SIZE_GUID, 0x10014, (4096).to_bytes(4, "little"), 1),
        (VIRTUAL_DISK_ID_GUID, 0x10018, b"\x11" * 16, 1),
    ]

    metadata_entries = b""
    for guid, item_offset, payload, is_virtual_disk in base_items:
        buf[metadata_offset + item_offset : metadata_offset + item_offset + len(payload)] = payload
        metadata_entries += _metadata_entry(guid, item_offset, len(payload), vds=is_virtual_disk)

    for guid, item_offset, payload, flags in extra_metadata or []:
        buf[metadata_offset + item_offset : metadata_offset + item_offset + len(payload)] = payload
        metadata_entries += _metadata_entry(guid, item_offset, len(payload), **flags)

    if include_parent_locator:
        locator_offset = 0x30000
        locator_header = c_vhdx.parent_locator_header(
            locator_type=VHDX_PARENT_LOCATOR_GUID.bytes_le, reserved=0, key_value_count=1
        ).dumps()
        locator_entry = c_vhdx.parent_locator_entry(
            key_offset=locator_key_offset,
            value_offset=128,
            key_length=locator_key_length,
            value_length=40,
        ).dumps()
        buf[metadata_offset + locator_offset : metadata_offset + locator_offset + len(locator_header)] = locator_header
        buf[metadata_offset + locator_offset + 20 : metadata_offset + locator_offset + 20 + len(locator_entry)] = (
            locator_entry
        )
        key = "relative_path".encode("utf-16-le")
        value = "child.avhdx".encode("utf-16-le")
        buf[
            metadata_offset + locator_offset + locator_key_offset : metadata_offset
            + locator_offset
            + locator_key_offset
            + len(key)
        ] = key
        buf[metadata_offset + locator_offset + 128 : metadata_offset + locator_offset + 128 + len(value)] = value
        metadata_entries += _metadata_entry(PARENT_LOCATOR_GUID, locator_offset, locator_length, vds=0)

    metadata_entries += extra_metadata_entries
    metadata_header = c_vhdx.metadata_table_header(
        signature=b"metadata",
        reserved=b"\x00" * 2,
        entry_count=len(metadata_entries) // c_vhdx.metadata_table_entry.size,
        reserved2=b"\x00" * 20,
    ).dumps()
    buf[metadata_offset : metadata_offset + len(metadata_header)] = metadata_header
    buf[metadata_offset + 32 : metadata_offset + 32 + len(metadata_entries)] = metadata_entries

    if mutate is not None:
        mutate(buf)

    return io.BytesIO(bytes(buf))


def test_vhdx_synthetic_valid() -> None:
    vhdx = VHDX(_build_synthetic_vhdx())

    assert vhdx.size == 10 * MB
    assert vhdx.block_size == 0x200000
    assert vhdx.has_parent == 0
    assert vhdx.sector_size == 512
    assert vhdx.read(512) == b"\x00" * 512


def test_vhdx_synthetic_unknown_optional_metadata_is_kept() -> None:
    payload = b"future-optional-item"
    vhdx = VHDX(
        _build_synthetic_vhdx(
            extra_metadata=[
                (UNKNOWN_OPTIONAL_GUID, 0x20000, payload, {"vds": 1, "req": 0}),
            ]
        )
    )

    assert UNKNOWN_OPTIONAL_GUID in vhdx.metadata.unknown_entries
    unknown_entry = vhdx.metadata.unknown_entries[UNKNOWN_OPTIONAL_GUID]
    assert unknown_entry.length == len(payload)
    assert vhdx.metadata.get(UNKNOWN_OPTIONAL_GUID, required=False) is None


def test_vhdx_synthetic_unknown_required_metadata_rejected() -> None:
    with pytest.raises(InvalidVirtualDisk, match="Required metadata item is not understood"):
        VHDX(
            _build_synthetic_vhdx(
                extra_metadata=[
                    (UNKNOWN_REQUIRED_GUID, 0x20000, b"x", {"vds": 1, "req": 1}),
                ]
            )
        )


@pytest.mark.parametrize(
    ("guid", "offset", "payload", "flags"),
    [
        (VIRTUAL_DISK_SIZE_GUID, 0x20000, (20 * MB).to_bytes(8, "little"), {"vds": 1, "req": 1}),
        (LOGICAL_SECTOR_SIZE_GUID, 0x20000, (4096).to_bytes(4, "little"), {"vds": 1, "req": 1}),
    ],
)
def test_vhdx_synthetic_duplicate_required_metadata_rejected(
    guid: UUID, offset: int, payload: bytes, flags: dict
) -> None:
    with pytest.raises(InvalidVirtualDisk, match="Duplicate metadata table entry"):
        VHDX(_build_synthetic_vhdx(extra_metadata=[(guid, offset, payload, flags)]))


def test_vhdx_synthetic_out_of_bounds_metadata_item_rejected() -> None:
    # Offset plus length extends past the 1 MiB metadata region.
    rogue_entry = _metadata_entry(UNKNOWN_OPTIONAL_GUID, 0xFFFF8, 16, req=0)
    with pytest.raises(InvalidVirtualDisk, match="falls outside the metadata region"):
        VHDX(_build_synthetic_vhdx(extra_metadata_entries=rogue_entry))


def test_vhdx_synthetic_wrong_known_item_length_rejected() -> None:
    def corrupt_first_entry_length(buf: bytearray) -> None:
        # The first metadata entry (file parameters) starts right after the 32-byte table header,
        # its length field is at byte 20 of the entry.
        entry_offset = 2 * MB + c_vhdx.metadata_table_header.size
        buf[entry_offset + 20 : entry_offset + 24] = (99).to_bytes(4, "little")

    with pytest.raises(InvalidVirtualDisk, match="has length 0x63, expected 0x8"):
        VHDX(_build_synthetic_vhdx(mutate=corrupt_first_entry_length))


def test_vhdx_synthetic_metadata_entry_count_rejected() -> None:
    def set_invalid_count(buf: bytearray) -> None:
        buf[2 * MB : 2 * MB + c_vhdx.metadata_table_header.size] = c_vhdx.metadata_table_header(
            signature=b"metadata", reserved=b"\x00" * 2, entry_count=1025, reserved2=b"\x00" * 20
        ).dumps()

    with pytest.raises(InvalidVirtualDisk, match="Invalid metadata table entry count: 1025"):
        VHDX(_build_synthetic_vhdx(mutate=set_invalid_count))


def test_vhdx_synthetic_duplicate_region_guid_rejected() -> None:
    entries = [
        _region_entry(BAT_GUID, 3 * MB, MB),
        _region_entry(METADATA_REGION_GUID, 2 * MB, MB),
        _region_entry(BAT_GUID, 1 * MB, MB, required=0),
    ]
    with pytest.raises(InvalidVirtualDisk, match="Duplicate region table entry"):
        VHDX(_build_synthetic_vhdx(region_entries=entries))


def test_vhdx_synthetic_region_past_end_of_file_rejected() -> None:
    entries = [
        _region_entry(BAT_GUID, 3 * MB, MB),
        _region_entry(METADATA_REGION_GUID, 5 * MB, MB),
    ]
    with pytest.raises(InvalidVirtualDisk, match="extends past the end of the file"):
        VHDX(_build_synthetic_vhdx(region_entries=entries))


def test_vhdx_synthetic_overlapping_regions_rejected() -> None:
    entries = [
        _region_entry(BAT_GUID, 3 * MB, MB),
        _region_entry(METADATA_REGION_GUID, 2 * MB, MB),
        _region_entry(UUID(int=999), 2 * MB, MB, required=0),
    ]
    with pytest.raises(InvalidVirtualDisk, match="overlaps region"):
        VHDX(_build_synthetic_vhdx(region_entries=entries))


def test_vhdx_synthetic_unknown_required_region_rejected() -> None:
    entries = [
        _region_entry(BAT_GUID, 3 * MB, MB),
        _region_entry(METADATA_REGION_GUID, 2 * MB, MB),
        _region_entry(UUID(int=1234), 1 * MB, MB, required=1),
    ]
    with pytest.raises(InvalidVirtualDisk, match="Required region is not understood"):
        VHDX(_build_synthetic_vhdx(region_entries=entries))


def test_vhdx_synthetic_unknown_optional_region_accepted() -> None:
    entries = [
        _region_entry(BAT_GUID, 3 * MB, MB),
        _region_entry(METADATA_REGION_GUID, 2 * MB, MB),
        _region_entry(UUID(int=1234), 1 * MB, MB, required=0),
    ]
    vhdx = VHDX(_build_synthetic_vhdx(region_entries=entries))
    assert vhdx.region_table.get(UUID(int=1234), required=False) is not None


def test_vhdx_synthetic_diverging_region_tables_rejected() -> None:
    def second_table() -> list[bytes]:
        return [
            _region_entry(BAT_GUID, 3 * MB, MB, required=0),
            _region_entry(METADATA_REGION_GUID, 2 * MB, MB),
        ]

    with pytest.raises(InvalidVirtualDisk, match="described differently by the two region tables"):
        VHDX(_build_synthetic_vhdx(mutate_second_region_table=second_table))


def test_vhdx_synthetic_invalid_logical_sector_size_rejected() -> None:
    def set_bad_sector_size(buf: bytearray) -> None:
        buf[2 * MB + 0x10010 : 2 * MB + 0x10014] = (1024).to_bytes(4, "little")

    with pytest.raises(InvalidVirtualDisk, match="Invalid logical sector size: 1024"):
        VHDX(_build_synthetic_vhdx(mutate=set_bad_sector_size))


def test_vhdx_synthetic_unaligned_disk_size_rejected() -> None:
    def set_bad_disk_size(buf: bytearray) -> None:
        buf[2 * MB + 0x10008 : 2 * MB + 0x10010] = (10 * MB + 1).to_bytes(8, "little")

    with pytest.raises(InvalidVirtualDisk, match="Invalid virtual disk size"):
        VHDX(_build_synthetic_vhdx(mutate=set_bad_disk_size))


def test_vhdx_synthetic_parent_locator_out_of_bounds_rejected() -> None:
    with pytest.raises(InvalidVirtualDisk, match="falls outside the parent locator metadata item"):
        VHDX(
            _build_synthetic_vhdx(
                has_parent=1,
                include_parent_locator=True,
                locator_key_offset=600,
            )
        )


def test_vhdx_synthetic_parent_locator_odd_key_length_rejected() -> None:
    with pytest.raises(InvalidVirtualDisk, match="Parent locator key has an invalid length"):
        VHDX(
            _build_synthetic_vhdx(
                has_parent=1,
                include_parent_locator=True,
                locator_key_length=7,
            )
        )


def test_vhdx_synthetic_parent_locator_item_too_small_rejected() -> None:
    with pytest.raises(InvalidVirtualDisk, match="exceed the metadata item"):
        VHDX(
            _build_synthetic_vhdx(
                has_parent=1,
                include_parent_locator=True,
                locator_length=24,
            )
        )


def test_vhdx_synthetic_valid_parent_locator_parses() -> None:
    # A valid locator must parse fully; only the missing parent file may fail afterwards.
    vhdx_file = _build_synthetic_vhdx(has_parent=1, include_parent_locator=True)
    vhdx_file.name = str(absolute_path("_data/disk/vhdx/nonexistent.avhdx"))
    with pytest.raises(IOError, match="Failed to open parent disk with locator"):
        VHDX(vhdx_file)


def test_vhdx_synthetic_parent_without_locator_rejected() -> None:
    with pytest.raises(InvalidVirtualDisk, match="missing the parent locator metadata item"):
        VHDX(_build_synthetic_vhdx(has_parent=1))


def test_vhdx_synthetic_locator_without_parent_rejected() -> None:
    with pytest.raises(InvalidVirtualDisk, match="present but the disk has no parent"):
        VHDX(_build_synthetic_vhdx(has_parent=0, include_parent_locator=True))


def test_vhdx_synthetic_bad_signature_rejected() -> None:
    def corrupt_signature(buf: bytearray) -> None:
        buf[0:8] = b"notvhdx!"

    with pytest.raises(InvalidSignature, match="Invalid file identifier signature"):
        VHDX(_build_synthetic_vhdx(mutate=corrupt_signature))
