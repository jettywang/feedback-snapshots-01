from __future__ import annotations

import io

import pytest

from dissect.archive.wim.exception import (
    DuplicatePartError,
    IncompleteResourceError,
    InvalidWIMSetError,
)
from dissect.archive.wim.wim import WIM
from tests._tools.wim._synth import basic_resources, build_set

GUID = bytes.fromhex("00112233445566778899aabbccddeeff")
OTHER_GUID = bytes.fromhex("ffeeddccbbaa99887766554433221100")

FILE_HASH = bytes.fromhex("0aaa8266648364d68b67be77c53f708a77fda84c")
DIR_FILE_HASH = bytes.fromhex("1fc83a896287fe48f6d42d8d04f88f6dc90c0c45")
ADS_HASH = bytes.fromhex("8e2dbd4ff0c5e125b445ded476f5bb9637e115a6")


def _owners(metadata_part: int = 1, file_part: int = 1, dir_file_part: int = 2, ads_part: int = 2) -> dict[bytes, int]:
    resources = basic_resources()
    metadata = next(resource.hash for resource in resources.values() if resource.is_metadata)
    owners = {hash: 1 for hash in resources}
    owners[metadata] = metadata_part
    owners[FILE_HASH] = file_part
    owners[DIR_FILE_HASH] = dir_file_part
    owners[ADS_HASH] = ads_part
    return owners


def _two_parts(guid: bytes = GUID, **owners: int) -> list[bytes]:
    return build_set(guid, _owners(**owners))


def _wim(parts: list[bytes]) -> WIM:
    return WIM([io.BytesIO(part) for part in parts])


def test_cross_part_directory_and_content() -> None:
    parts = _two_parts()
    wim = _wim([parts[1], parts[0]])

    assert wim.guid == GUID
    assert wim.total_parts == 2
    assert wim.missing_parts == []
    assert [part.number for part in wim.parts] == [1, 2]

    image = next(wim.images())
    assert sorted(image.root.listdir()) == ["ads.txt", "dir", "file.txt", "link.txt"]
    assert image.get("file.txt").open().read() == basic_resources()[FILE_HASH].data
    assert image.get("dir/another.txt").open().read() == basic_resources()[DIR_FILE_HASH].data

    metadata = next(resource for resource in wim.resources.values() if resource.is_metadata)
    assert metadata.part_number == 1
    assert wim.resources[FILE_HASH].part_number == 1
    assert wim.resources[DIR_FILE_HASH].part_number == 2
    assert wim.verify() == []


def test_argument_order_does_not_matter() -> None:
    parts = _two_parts()
    first = _wim(parts)
    second = _wim(list(reversed(parts)))

    assert first.guid == second.guid
    assert first.total_parts == second.total_parts
    assert {hash: resource.part_number for hash, resource in first.resources.items()} == {
        hash: resource.part_number for hash, resource in second.resources.items()
    }
    assert next(first.images()).get("dir/another.txt").open().read() == next(second.images()).get(
        "dir/another.txt"
    ).open().read()


def test_mixed_set_same_numbered_part_is_rejected() -> None:
    ours = _two_parts(GUID)
    other = _two_parts(OTHER_GUID)

    with pytest.raises(InvalidWIMSetError, match=OTHER_GUID.hex()[:8]):
        _wim([ours[0], other[1]])

    with pytest.raises(InvalidWIMSetError, match=GUID.hex()[:8]):
        _wim([other[1], ours[0]])


def test_duplicate_part_number_is_rejected() -> None:
    parts = _two_parts()
    with pytest.raises(DuplicatePartError, match="part 1"):
        _wim([parts[0], parts[0]])


def test_missing_part_lists_metadata_but_content_fails() -> None:
    parts = _two_parts()
    wim = _wim([parts[0]])

    assert wim.missing_parts == [2]
    image = next(wim.images())
    assert sorted(image.root.listdir()) == ["ads.txt", "dir", "file.txt", "link.txt"]

    assert image.get("file.txt").open().read() == basic_resources()[FILE_HASH].data
    with pytest.raises(IncompleteResourceError, match="missing part 2"):
        image.get("dir/another.txt").size()
    with pytest.raises(IncompleteResourceError, match="missing part 2"):
        image.get("dir/another.txt").open()

    incomplete = wim.verify()
    assert (DIR_FILE_HASH, 2) in incomplete
    assert (FILE_HASH, 1) not in incomplete


def test_truncated_part_is_incomplete_not_zero_filled() -> None:
    parts = _two_parts()
    # Keep the header, table and metadata readable, but cut the data region of part 2.
    resources = basic_resources()
    data_end = len(parts[1])
    truncated = parts[1][: data_end - len(resources[DIR_FILE_HASH].data)]
    wim = _wim([parts[0], truncated])

    image = next(wim.images())
    assert sorted(image.root.listdir()) == ["ads.txt", "dir", "file.txt", "link.txt"]
    with pytest.raises(IncompleteResourceError, match="part ends at"):
        image.get("dir/another.txt").size()
    with pytest.raises(IncompleteResourceError, match="part ends at"):
        image.get("dir/another.txt").open()


def test_out_of_range_part_numbers_are_rejected() -> None:
    parts = _two_parts()
    header = bytearray(parts[0])
    # PartNumber lives at offset 8 + 4 + 4 + 4 + 16 = 40 in the packed header.
    header[40:42] = (3).to_bytes(2, "little")
    with pytest.raises(InvalidWIMSetError, match="exceeds TotalParts"):
        _wim([bytes(header), parts[1]])


def test_single_resource_split_over_parts() -> None:
    parts = _two_parts()
    # Rewrite both copies of the table so one file resource is a spanned resource with
    # one extent in each part. The fixture's file.txt data is split at its midpoint.
    from dissect.archive.wim.c_wim import RESHDR_FLAG, c_wim

    resources = basic_resources()
    content = resources[FILE_HASH].data
    midpoint = len(content) // 2
    first, second = content[:midpoint], content[midpoint:]

    rebuilt = []
    for part_number, data in enumerate(parts, start=1):
        buf = bytearray(data)
        header = c_wim.WIMHEADER_V1_PACKED(buf)
        table_offset = int(header.OffsetTable.Offset)
        table_size = int.from_bytes(header.OffsetTable.Size, "little")
        offset = table_offset
        for _ in range(table_size // len(c_wim._RESHDR_DISK)):
            record = c_wim._RESHDR_DISK(buf[offset : offset + len(c_wim._RESHDR_DISK)])
            if bytes(record.Hash) == FILE_HASH:
                chunk = first if part_number == 1 else second
                data_offset = (len(buf) + 7) & -8
                buf.extend(b"\x00" * (data_offset - len(buf)))
                record.Base.Size = len(chunk).to_bytes(7, "little")
                record.Base.Flags = RESHDR_FLAG(int(record.Base.Flags) | int(RESHDR_FLAG.SPANNED))
                record.Base.Offset = data_offset
                record.Base.OriginalSize = len(chunk)
                record.PartNumber = part_number
                buf[offset : offset + len(c_wim._RESHDR_DISK)] = record.dumps()
                buf.extend(chunk)
                break
            offset += len(c_wim._RESHDR_DISK)
        rebuilt.append(bytes(buf))

    wim = _wim(rebuilt)
    resource = wim.resources[FILE_HASH]
    assert resource.part_numbers == [1, 2]
    assert resource.open().read() == content


def test_resource_cannot_borrow_from_other_set() -> None:
    ours = _two_parts(GUID)
    other = _two_parts(OTHER_GUID)

    # Our set's table says DIR_FILE_HASH lives in part 2. Supplying our part 1 and
    # another set's part 2 must fail while reading identities, before any resource is
    # resolved -- there is no way to borrow that same-numbered part.
    with pytest.raises(InvalidWIMSetError, match="belongs to WIM set"):
        _wim([ours[0], other[1]])

    # Supplying parts from both sets under swapped argument order gives the same verdict.
    with pytest.raises(InvalidWIMSetError, match="expected"):
        _wim([other[1], ours[0]])


def test_missing_metadata_part_cannot_list_images_silently() -> None:
    parts = _two_parts()
    wim = _wim([parts[1]])

    assert wim.missing_parts == [1]
    with pytest.raises(IncompleteResourceError, match="missing part 1"):
        next(wim.images())


def test_verify_reports_declared_part_not_argument_position() -> None:
    parts = _two_parts()
    # Deliberately pass parts in reverse; the reported part must still be part 2,
    # because that is what the resource table declares.
    wim = _wim([parts[1], parts[0]])
    assert wim.verify() == []

    # Simulate the same set with part 2 removed: only part 1 is available.
    partial = _wim([parts[0]])
    incomplete = partial.verify()
    assert (DIR_FILE_HASH, 2) in incomplete
    assert (FILE_HASH, 1) not in incomplete


def test_forwarded_table_copy_offsets_are_not_authoritative() -> None:
    from dissect.archive.wim.c_wim import c_wim

    parts = _two_parts()
    # Part 2 forwards the table for a resource that lives in part 1. Give that copy a
    # bogus offset: it describes part 1 from part 2, so part 1's own copy must win.
    buf = bytearray(parts[1])
    header = c_wim.WIMHEADER_V1_PACKED(buf)
    offset = int(header.OffsetTable.Offset)
    for _ in range(int.from_bytes(header.OffsetTable.Size, "little") // len(c_wim._RESHDR_DISK)):
        record = c_wim._RESHDR_DISK(buf[offset : offset + len(c_wim._RESHDR_DISK)])
        if bytes(record.Hash) == FILE_HASH:
            record.Base.Offset = 1
            buf[offset : offset + len(c_wim._RESHDR_DISK)] = record.dumps()
            break
        offset += len(c_wim._RESHDR_DISK)

    wim = _wim([bytes(buf), parts[0]])
    assert wim.resources[FILE_HASH].part_number == 1
    assert wim.resources[FILE_HASH].open().read() == basic_resources()[FILE_HASH].data


def test_three_parts_missing_middle_reports_exact_parts() -> None:
    parts = build_set(GUID, _owners(metadata_part=1, file_part=1, dir_file_part=3, ads_part=3), total_parts=3)
    wim = _wim([parts[2], parts[0]])

    assert wim.total_parts == 3
    assert wim.missing_parts == [2]
    assert [part.number for part in wim.parts] == [1, 3]

    image = next(wim.images())
    assert image.get("file.txt").open().read() == basic_resources()[FILE_HASH].data
    assert image.get("dir/another.txt").open().read() == basic_resources()[DIR_FILE_HASH].data
    assert wim.verify() == []


def test_verify_lists_all_incomplete_resources_and_their_parts() -> None:
    parts = _two_parts()
    wim = _wim([parts[0]])
    incomplete = dict(wim.verify())

    assert incomplete[DIR_FILE_HASH] == 2
    assert incomplete[ADS_HASH] == 2
    assert FILE_HASH not in incomplete
    metadata = next(resource for resource in wim.resources.values() if resource.is_metadata)
    assert metadata.hash not in incomplete


def test_verify_detects_short_data_region_in_available_part() -> None:
    parts = _two_parts()
    truncated = parts[1][: len(parts[1]) - len(basic_resources()[DIR_FILE_HASH].data)]
    wim = _wim([parts[0], truncated])

    incomplete = dict(wim.verify())
    assert incomplete[DIR_FILE_HASH] == 2


def test_separate_part_arguments_and_iterable_are_equivalent() -> None:
    parts = _two_parts()
    from_iterable = WIM([io.BytesIO(parts[1]), io.BytesIO(parts[0])])
    from_arguments = WIM(io.BytesIO(parts[1]), io.BytesIO(parts[0]))

    assert from_arguments.guid == from_iterable.guid
    assert [part.number for part in from_arguments.parts] == [1, 2]
    assert from_arguments.resources[DIR_FILE_HASH].part_number == 2


def test_declared_total_parts_survives_missing_parts() -> None:
    parts = build_set(GUID, _owners(), total_parts=3)
    # Provide parts 2 and 3 only. Part 2 still carries TotalParts=3 in its header,
    # which must describe the set as a whole rather than the highest part present.
    wim = _wim([parts[2], parts[1]])

    assert wim.total_parts == 3
    assert wim.missing_parts == [1]
    assert [part.number for part in wim.parts] == [2, 3]


def test_spanned_resource_with_missing_contributing_part_fails() -> None:
    from dissect.archive.wim.c_wim import RESHDR_FLAG, c_wim

    parts = _two_parts()
    # Mark file.txt spanned in every copy of the table while keeping its bytes in
    # part 1. Without part 2, the set is incomplete for that resource.
    rebuilt = []
    for data in parts:
        buf = bytearray(data)
        header = c_wim.WIMHEADER_V1_PACKED(buf)
        offset = int(header.OffsetTable.Offset)
        for _ in range(int.from_bytes(header.OffsetTable.Size, "little") // len(c_wim._RESHDR_DISK)):
            record = c_wim._RESHDR_DISK(buf[offset : offset + len(c_wim._RESHDR_DISK)])
            if bytes(record.Hash) == FILE_HASH:
                record.Base.Flags = RESHDR_FLAG(int(record.Base.Flags) | int(RESHDR_FLAG.SPANNED))
                buf[offset : offset + len(c_wim._RESHDR_DISK)] = record.dumps()
                break
            offset += len(c_wim._RESHDR_DISK)
        rebuilt.append(bytes(buf))

    wim = _wim([rebuilt[0]])
    with pytest.raises(IncompleteResourceError, match="spans parts"):
        wim.resources[FILE_HASH].open()
