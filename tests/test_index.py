from __future__ import annotations

import io
import struct
from functools import lru_cache
from typing import BinaryIO
from unittest.mock import Mock

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, COLLATION, INDEX_ENTRY_END, INDEX_ENTRY_NODE, c_ntfs
from dissect.ntfs.index import Index, IndexEntry, IndexRoot, Match, MftReferenceCheck, _cmp_filename, _cmp_ulong
from dissect.ntfs.ntfs import NTFS


def mock_filename_entry(filename: str) -> IndexEntry:
    attribute = c_ntfs._FILE_NAME(
        FileNameLength=len(filename),
        FileName=filename,
    ).dumps()
    header = c_ntfs._INDEX_ENTRY(
        Length=len(c_ntfs._INDEX_ENTRY) + len(attribute),
        KeyLength=len(attribute),
    )
    data = header.dumps() + attribute

    mock_root = Mock(attribute_type=ATTRIBUTE_TYPE_CODE.FILE_NAME)
    mock_index = Mock(root=mock_root)
    return IndexEntry(mock_index, io.BytesIO(data), 0)


def mock_ulong_entry(value: int) -> IndexEntry:
    header = c_ntfs._INDEX_ENTRY(
        Length=len(c_ntfs._INDEX_ENTRY) + 4,
        KeyLength=4,
    )
    data = header.dumps() + struct.pack("<I", value)

    mock_root = Mock(attribute_type=ATTRIBUTE_TYPE_CODE.UNUSED)
    mock_index = Mock(root=mock_root)
    return IndexEntry(mock_index, io.BytesIO(data), 0)


def test_cmp_filename() -> None:
    entry = mock_filename_entry("bbbb")

    assert _cmp_filename(entry, "CCCC") == Match.Greater
    assert _cmp_filename(entry, "BBBB") == Match.Equal
    assert _cmp_filename(entry, "BBBA") == Match.Less
    assert _cmp_filename(entry, "BBBBA") == Match.Greater
    assert _cmp_filename(entry, "BBBBB") == Match.Greater

    entry = mock_filename_entry("C_20127.NLS")
    assert _cmp_filename(entry, "CONFIG") == Match.Less


def test_cmp_ulong() -> None:
    entry = mock_ulong_entry(100)

    assert _cmp_ulong(entry, 99) == Match.Less
    assert _cmp_ulong(entry, 100) == Match.Equal
    assert _cmp_ulong(entry, 101) == Match.Greater


def test_index_lookup(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)

    root = fs.mft.get("Large Directory")
    assert len(root.listdir()) == 2048

    for i in range(2048):
        entry = root.get(f"Directory {i}")
        assert entry.filename == f"Directory {i}"


def make_file_reference(segment: int, sequence: int) -> bytes:
    return c_ntfs.FILE_REFERENCE(
        SegmentNumberLowPart=segment & 0xFFFFFFFF,
        SegmentNumberHighPart=(segment >> 32) & 0xFFFF,
        SequenceNumber=sequence,
    ).dumps()


def make_index_entry(
    segment: int,
    sequence: int,
    filename: str,
    node_vcn: int | None = None,
    key_length: int | None = None,
) -> bytes:
    key = c_ntfs._FILE_NAME(FileNameLength=len(filename), FileName=filename).dumps()
    key_length = len(key) if key_length is None else key_length
    key = key.ljust(key_length, b"\x00")

    tail = struct.pack("<Q", node_vcn) if node_vcn is not None else b""
    length = len(c_ntfs._INDEX_ENTRY) + len(key) + len(tail)
    pad = -length % 8
    length += pad

    flags = INDEX_ENTRY_NODE if node_vcn is not None else 0
    header = make_file_reference(segment, sequence) + struct.pack("<HHHH", length, key_length, flags, 0)
    return header + key + b"\x00" * pad + tail


def make_end_entry() -> bytes:
    return make_file_reference(0, 0) + struct.pack("<HHHH", len(c_ntfs._INDEX_ENTRY), 0, INDEX_ENTRY_END, 0)


def make_index_root(entries: bytes, slack: bytes = b"") -> bytes:
    header = c_ntfs._INDEX_ROOT(
        AttributeType=ATTRIBUTE_TYPE_CODE.FILE_NAME,
        CollationRule=COLLATION.FILE_NAME,
        BytesPerIndexBuffer=0x1000,
        ClustersPerIndexBuffer=1,
        IndexHeader=c_ntfs._INDEX_HEADER(
            FirstEntryOffset=0x10,
            TotalSizeOfEntries=0x10 + len(entries),
            AllocatedSize=0x10 + len(entries) + len(slack),
            Flags=1,
        ),
    )
    return header.dumps() + entries + slack


def make_indx_buffer(entries: bytes, slack: bytes = b"", vcn: int = 0, size: int = 0x1000) -> bytes:
    buf = bytearray(size)
    struct.pack_into("<4sHHQQ", buf, 0, b"INDX", 0x28, 9, 0, vcn)
    struct.pack_into(
        "<IIIB3s",
        buf,
        0x18,
        0x30,  # FirstEntryOffset, relative to the _INDEX_HEADER
        0x30 + len(entries),  # TotalSizeOfEntries
        0x30 + len(entries) + len(slack),  # AllocatedSize
        0,
        b"\x00" * 3,
    )
    start = 0x18 + 0x30
    buf[start : start + len(entries)] = entries
    buf[start + len(entries) : start + len(entries) + len(slack)] = slack

    # Apply a valid update sequence array so apply_fixup() accepts the buffer
    usa = bytearray(b"\xaa\xbb")
    for i in range(size // 0x200):
        sector_end = (i + 1) * 0x200 - 2
        usa += buf[sector_end : sector_end + 2]
        buf[sector_end : sector_end + 2] = b"\xaa\xbb"
    buf[0x28 : 0x28 + len(usa)] = usa
    return bytes(buf)


def test_residual_entries() -> None:
    # One active entry in the index buffer at VCN 1
    active_entry = make_index_entry(50, 1, "active_file.txt")

    # Two residual candidates: deleted_alpha.txt in the index root slack with a matching MFT
    # record, deleted_beta.txt in the index buffer slack with a stale sequence number
    deleted_alpha = make_index_entry(100, 3, "deleted_alpha.txt")
    deleted_beta = make_index_entry(200, 5, "deleted_beta.txt")

    # Counter-example: bytes that merely look like a $FILE_NAME, but with a forged KeyLength
    # that is inconsistent with the FileNameLength inside the key
    ghost_key = c_ntfs._FILE_NAME(FileNameLength=len("ghost.txt"), FileName="ghost.txt").dumps()
    ghost = make_index_entry(300, 1, "ghost.txt", key_length=len(ghost_key) + 8)

    # Two root node entries pointing at the same (shared) child node
    root_entries = (
        make_index_entry(40, 1, "node_separator_a", node_vcn=1)
        + make_index_entry(41, 1, "node_separator_b", node_vcn=1)
        + make_end_entry()
    )
    root_data = make_index_root(root_entries, slack=deleted_alpha + b"\x00" * 16)

    buffer_entries = active_entry + make_end_entry()
    buffer_data = make_indx_buffer(buffer_entries, slack=deleted_beta + ghost + b"\x00" * 16, vcn=1)

    mft_records = {
        100: Mock(header=Mock(SequenceNumber=3)),
        200: Mock(header=Mock(SequenceNumber=7)),
    }
    mft = Mock()
    mft.get.side_effect = lambda ref: mft_records[ref]

    index = Index.__new__(Index)
    index.record = Mock(ntfs=Mock(mft=mft))
    index.name = "$I30"
    index.root = IndexRoot(index, io.BytesIO(root_data))
    index._index_stream = io.BytesIO(b"\x00" * 0x1000 + buffer_data)
    index._vcn_size_shift = 12
    index.index_buffer = lru_cache(128)(index.index_buffer)

    # Normal enumeration only returns active entries; the residual candidates and the
    # counter-example must not be mixed in
    active_names = sorted(entry.attribute.file_name for entry in index.entries())
    assert active_names == ["active_file.txt", "node_separator_a", "node_separator_b"]

    # The shared child node is scanned only once, so each candidate is recovered exactly once
    residuals = list(index.residual_entries())
    by_name = {candidate.filename: candidate for candidate in residuals}
    assert sorted(by_name) == ["deleted_alpha.txt", "deleted_beta.txt"]

    # The bytes in the index root slack fully support the name recovery and the MFT
    # cross-check confirms the file reference
    alpha = by_name["deleted_alpha.txt"]
    assert alpha.vcn is None
    assert root_data[alpha.offset : alpha.offset + alpha.length] == alpha.raw
    assert alpha.segment_number == 100
    assert alpha.sequence_number == 3
    assert alpha.mft_check is MftReferenceCheck.MATCH
    assert alpha.mft_record is mft_records[100]

    # The bytes in the index buffer slack support the name recovery, but the referenced MFT
    # record was reused (sequence 7 != 5), so the relation cannot be confirmed
    beta = by_name["deleted_beta.txt"]
    assert beta.vcn == 1
    assert buffer_data[beta.offset - 0x1000 : beta.offset - 0x1000 + beta.length] == beta.raw
    assert beta.segment_number == 200
    assert beta.sequence_number == 5
    assert beta.mft_check is MftReferenceCheck.STALE_SEQUENCE
    assert beta.mft_record is mft_records[200]
