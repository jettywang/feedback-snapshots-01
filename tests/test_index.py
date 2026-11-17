from __future__ import annotations

import io
import random
import struct
from typing import BinaryIO
from unittest.mock import Mock
from uuid import UUID

import pytest
from dissect.util.sid import read_sid, write_sid

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, COLLATION, INDEX_ENTRY_END, INDEX_ENTRY_NODE, c_ntfs
from dissect.ntfs.index import (
    Index,
    IndexEntry,
    Match,
    _cmp_filename,
    _cmp_security_hash,
    _cmp_sid,
    _cmp_ulong,
    _cmp_ulongs,
)
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

    # ULONGs are unsigned: values with the high bit set sort above 0x7FFFFFFF
    high = raw_entry(struct.pack("<I", 0x80000000))
    assert _cmp_ulong(high, 0x7FFFFFFF) == Match.Less
    assert _cmp_ulong(high, 0x80000000) == Match.Equal
    assert _cmp_ulong(high, 0xFFFFFFFF) == Match.Greater


def raw_entry(key: bytes = b"", data: bytes = b"", node_vcn: int | None = None, end: bool = False) -> IndexEntry:
    """Build an index entry without touching a real index or volume."""
    data_offset = len(c_ntfs._INDEX_ENTRY) + len(key)

    if end:
        flags = INDEX_ENTRY_END | (INDEX_ENTRY_NODE if node_vcn is not None else 0)
        body = struct.pack("<Q", node_vcn) if node_vcn is not None else b""
        data_offset = 0
    else:
        flags = INDEX_ENTRY_NODE if node_vcn is not None else 0
        body = key + data + (struct.pack("<Q", node_vcn) if node_vcn is not None else b"")

    header = struct.pack(
        "<HHIHHHH",
        data_offset,
        len(data),
        0,
        len(c_ntfs._INDEX_ENTRY) + len(body),
        len(key),
        flags,
        0,
    )
    return IndexEntry(None, io.BytesIO(header + body), 0)


class FakeIndexRoot:
    def __init__(self, collation_rule: COLLATION, entries: list[IndexEntry]):
        self.collation_rule = collation_rule
        self.attribute_type = ATTRIBUTE_TYPE_CODE.UNUSED
        self._entries = entries

    def entries(self) -> list[IndexEntry]:
        return list(self._entries)


class FakeIndexBuffer:
    def __init__(self, entries: list[IndexEntry]):
        self._entries = entries

    def entries(self) -> list[IndexEntry]:
        return list(self._entries)


class FakeIndex(Index):
    """A small in-memory B-tree for exercising index traversal and lookups."""

    def __init__(self, collation_rule: COLLATION, root: list[IndexEntry], buffers: dict[int, list[IndexEntry]]):
        self.root = FakeIndexRoot(collation_rule, root)
        self._buffers = {vcn: FakeIndexBuffer(entries) for vcn, entries in buffers.items()}
        self._index_stream = True

    def index_buffer(self, vcn: int) -> FakeIndexBuffer:
        return self._buffers[vcn]


def multi_level_index(
    collation_rule: COLLATION, leaves: list[list[IndexEntry]], separator_keys: list[bytes]
) -> tuple[FakeIndex, list[IndexEntry]]:
    """Build a three-level index from four leaves and three separator keys.

    ``separator_keys`` is ordered as ``(lower, root, upper)``. The tree shape matches
    how NTFS stores separator keys on every level::

        root:       [root separator -> internal left] [end -> internal right]
        internal left:  [lower separator -> leaf 1]   [end -> leaf 2]
        internal right: [upper separator -> leaf 3]   [end -> leaf 4]

    Separator keys are standalone entries and are not repeated in the leaves.
    """
    lower, root_separator, upper = separator_keys
    separators = [
        raw_entry(root_separator, node_vcn=1),
        raw_entry(lower, node_vcn=11),
        raw_entry(upper, node_vcn=21),
    ]
    index = FakeIndex(
        collation_rule,
        [separators[0], raw_entry(end=True, node_vcn=2)],
        {
            1: [separators[1], raw_entry(end=True, node_vcn=12)],
            2: [separators[2], raw_entry(end=True, node_vcn=22)],
            11: [*leaves[0], raw_entry(end=True)],
            12: [*leaves[1], raw_entry(end=True)],
            21: [*leaves[2], raw_entry(end=True)],
            22: [*leaves[3], raw_entry(end=True)],
        },
    )
    ordered = [
        *leaves[0],
        separators[1],
        *leaves[1],
        separators[0],
        *leaves[2],
        separators[2],
        *leaves[3],
    ]
    return index, ordered


def ulong_key(*values: int) -> bytes:
    return struct.pack(f"<{len(values)}I", *values)


def test_cmp_ulongs() -> None:
    entry = raw_entry(ulong_key(0x7FFFFFFF, 0xFFFFFFFF))

    assert _cmp_ulongs(entry, (0x7FFFFFFF, 0xFFFFFFFF)) == Match.Equal
    assert _cmp_ulongs(entry, (0x7FFFFFFF, 0xFFFFFFFE)) == Match.Less
    assert _cmp_ulongs(entry, (0x80000000, 0x00000000)) == Match.Greater
    assert _cmp_ulongs(entry, ulong_key(0x7FFFFFFF, 0xFFFFFFFF)) == Match.Equal

    uuid = UUID("00112233-4455-6677-8899-aabbccddeeff")
    uuid_entry = raw_entry(uuid.bytes_le)
    assert _cmp_ulongs(uuid_entry, uuid) == Match.Equal
    assert _cmp_ulongs(uuid_entry, uuid.bytes_le) == Match.Equal

    with pytest.raises(ValueError, match="Invalid entry key length"):
        _cmp_ulongs(raw_entry(b"\x01\x02\x03"), (1,))
    with pytest.raises(ValueError, match="Invalid search value length"):
        _cmp_ulongs(entry, b"\x01\x02\x03")
    with pytest.raises(ValueError, match="Invalid search value length"):
        _cmp_ulongs(entry, (0x7FFFFFFF,))
    with pytest.raises(ValueError, match="Invalid search value length"):
        _cmp_ulongs(entry, (0x7FFFFFFF, 0xFFFFFFFF, 0x00000000))
    with pytest.raises(TypeError, match="Unsupported search value"):
        _cmp_ulongs(entry, "not-an-integer-key")


def test_cmp_sid() -> None:
    entry = raw_entry(write_sid("S-1-5-32-544"))

    assert _cmp_sid(entry, "S-1-5-32-544") == Match.Equal
    assert _cmp_sid(entry, write_sid("S-1-5-32-544")) == Match.Equal
    assert _cmp_sid(entry, "S-1-5-32-545") == Match.Greater
    assert _cmp_sid(entry, "S-1-5-32-543") == Match.Less

    # Sub authorities are unsigned, so 0x80000000 sorts after 0x7FFFFFFF
    high = raw_entry(write_sid("S-1-5-32-2147483648"))
    assert _cmp_sid(high, "S-1-5-32-2147483647") == Match.Less
    assert _cmp_sid(high, "S-1-5-32-4294967295") == Match.Greater

    # Compare by the structure, not by the textual representation
    with pytest.raises(ValueError, match="Invalid entry key length"):
        _cmp_sid(raw_entry(write_sid("S-1-5-32-544")[:-1]), "S-1-5-32-544")
    with pytest.raises(ValueError, match="Invalid search value length"):
        _cmp_sid(entry, write_sid("S-1-5-32-544") + b"\x00")
    with pytest.raises(ValueError, match="Invalid search value"):
        _cmp_sid(entry, "not-a-sid")


def test_cmp_security_hash() -> None:
    entry = raw_entry(struct.pack("<II", 0xDEADBEEF, 0x80000000))

    assert _cmp_security_hash(entry, (0xDEADBEEF, 0x80000000)) == Match.Equal
    assert _cmp_security_hash(entry, struct.pack("<II", 0xDEADBEEF, 0x80000000)) == Match.Equal
    # Same hash, different security ID: this is a different key
    assert _cmp_security_hash(entry, (0xDEADBEEF, 0x80000001)) == Match.Greater
    assert _cmp_security_hash(entry, (0xDEADBEEF, 0x7FFFFFFF)) == Match.Less
    assert _cmp_security_hash(entry, (0xDEADBEEE, 0xFFFFFFFF)) == Match.Less
    assert _cmp_security_hash(entry, (0xDEADBEF0, 0x00000000)) == Match.Greater

    with pytest.raises(ValueError, match="Invalid entry key length"):
        _cmp_security_hash(raw_entry(struct.pack("<III", 1, 2, 3)), (1, 2))
    with pytest.raises(ValueError, match="Invalid search value length"):
        _cmp_security_hash(entry, struct.pack("<II", 1, 2) + b"\x00")
    with pytest.raises(ValueError, match="Invalid search value"):
        _cmp_security_hash(entry, (0xDEADBEEF, 0x100000000))
    with pytest.raises(TypeError, match="Unsupported search value"):
        _cmp_security_hash(entry, "not-a-hash-key")


def test_ulongs_multi_level_lookup() -> None:
    keys = [
        (0x00000001, 0x00000000),
        (0x00000001, 0xFFFFFFFF),
        (0x7FFFFFFF, 0x00000000),  # separator 1
        (0x7FFFFFFF, 0x00000001),
        (0x7FFFFFFF, 0xFFFFFFFF),
        (0x80000000, 0x00000000),  # separator 0
        (0x80000000, 0x00000001),
        (0x80000000, 0xFFFFFFFF),
        (0xFFFFFFFF, 0x00000000),  # separator 2
        (0xFFFFFFFF, 0x00000001),
        (0xFFFFFFFF, 0xFFFFFFFF),
    ]
    separator_keys = [ulong_key(*keys[i]) for i in (2, 5, 8)]
    leaves = [
        [raw_entry(ulong_key(*keys[0])), raw_entry(ulong_key(*keys[1]))],
        [raw_entry(ulong_key(*keys[3])), raw_entry(ulong_key(*keys[4]))],
        [raw_entry(ulong_key(*keys[6])), raw_entry(ulong_key(*keys[7]))],
        [raw_entry(ulong_key(*keys[9])), raw_entry(ulong_key(*keys[10]))],
    ]
    index, ordered = multi_level_index(COLLATION.NTOFS_ULONGS, leaves, separator_keys)

    # Sequential traversal is ordered by the comparator, not by physical layout
    assert [entry.key for entry in index.entries()] == [entry.key for entry in ordered]
    assert [entry.key for entry in index.entries()] == [ulong_key(*key) for key in keys]

    # Every key, including the separator keys, is found independently of query order
    random.seed(0)
    for order in (keys, list(reversed(keys)), random.sample(keys, len(keys))):
        assert [index.search(value).key for value in order] == [ulong_key(*value) for value in order]

    missing = [
        (0x00000000, 0x00000000),
        (0x00000001, 0x00000001),
        (0x7FFFFFFF, 0x80000000),
        (0x80000000, 0x80000000),
        (0xFFFFFFFF, 0x00000002),
    ]
    for value in missing:
        with pytest.raises(KeyError):
            index.search(value)

    # A value with a different number of integers is not a valid key for this index
    with pytest.raises(ValueError, match="Invalid search value length"):
        index.search((0xFFFFFFFF, 0xFFFFFFFF, 0x00000000))

    # Interleave misses with hits: a failed lookup must not move the cursor
    for hit, miss in zip(keys, missing, strict=False):
        with pytest.raises(KeyError):
            index.search(miss)
        assert index.search(hit).key == ulong_key(*hit)


def test_security_hash_multi_level_lookup() -> None:
    keys = [
        (0xDEADBEEF, 0x00000001),
        (0xDEADBEEF, 0x00000002),  # separator 1
        (0xDEADBEEF, 0x00000003),
        (0xDEADBEEF, 0x80000000),  # separator 0
        (0xDEADBEEF, 0xFFFFFFFF),
        (0xFFFFFFFF, 0x00000000),  # separator 2
        (0xFFFFFFFF, 0x00000001),
        (0xFFFFFFFF, 0x80000000),
    ]
    separator_keys = [struct.pack("<II", *keys[i]) for i in (1, 3, 5)]
    leaves = [
        [raw_entry(struct.pack("<II", *keys[0]))],
        [raw_entry(struct.pack("<II", *keys[2]))],
        [raw_entry(struct.pack("<II", *keys[4]))],
        [raw_entry(struct.pack("<II", *keys[6])), raw_entry(struct.pack("<II", *keys[7]))],
    ]
    index, ordered = multi_level_index(COLLATION.NTOFS_SECURITY_HASH, leaves, separator_keys)

    assert [entry.key for entry in index.entries()] == [entry.key for entry in ordered]
    assert [entry.key for entry in index.entries()] == [struct.pack("<II", *key) for key in keys]

    # Same hash, different security ID is a different full key
    for key in keys:
        assert index.search(key).key == struct.pack("<II", *key)
        assert index.search(struct.pack("<II", *key)).key == struct.pack("<II", *key)

    same_hash = [(0xDEADBEEF, 0x00000000), (0xDEADBEEF, 0x00000004), (0xFFFFFFFF, 0x00000002)]
    for key in same_hash:
        with pytest.raises(KeyError):
            index.search(key)

    # A same-hash miss must not disturb the following lookup
    for hit, miss in zip(keys, same_hash, strict=False):
        with pytest.raises(KeyError):
            index.search(miss)
        assert index.search(hit).key == struct.pack("<II", *hit)


def test_sid_multi_level_lookup() -> None:
    sids = [
        "S-1-5-18",
        "S-1-5-19",
        "S-1-5-20",  # separator lower
        "S-1-5-32-544",
        "S-1-5-32-545",  # separator root
        "S-1-5-32-2147483647",
        "S-1-5-32-2147483648",  # separator upper
        "S-1-5-32-4294967295",
    ]
    separator_keys = [write_sid(sids[i]) for i in (2, 4, 6)]
    leaves = [
        [raw_entry(write_sid(sids[0])), raw_entry(write_sid(sids[1]))],
        [raw_entry(write_sid(sids[3]))],
        [raw_entry(write_sid(sids[5]))],
        [raw_entry(write_sid(sids[7]))],
    ]
    index, ordered = multi_level_index(COLLATION.NTOFS_SID, leaves, separator_keys)

    # Sub authorities are compared as unsigned values; a high-bit SID sorts last
    assert [entry.key for entry in index.entries()] == [entry.key for entry in ordered]
    assert [entry.key for entry in index.entries()] == [write_sid(sid) for sid in sids]

    for sid in sids:
        assert index.search(sid).key == write_sid(sid)

    # A miss between neighbouring SIDs does not affect a following lookup
    for hit, miss in zip(sids, ("S-1-5-32-546", "S-1-5-32-2147483646", "S-1-5-21-544"), strict=False):
        with pytest.raises(KeyError):
            index.search(miss)
        assert index.search(hit).key == write_sid(hit)


def test_custom_comparator() -> None:
    """A caller-supplied comparator must still work and take precedence over the rule."""
    keys = [b"\x01", b"\x02", b"\x03"]
    index = FakeIndex(
        COLLATION.NTOFS_ULONG,  # Would reject a one-byte key if the built-in comparator was used
        [raw_entry(end=True, node_vcn=1)],
        {
            1: [*(raw_entry(key) for key in keys), raw_entry(end=True)],
        },
    )

    def byte_cmp(entry: IndexEntry, value: int) -> Match:
        if value < entry.key[0]:
            return Match.Less
        if value > entry.key[0]:
            return Match.Greater
        return Match.Equal

    # The custom comparator receives the value untouched and controls the search
    assert index.search(2, cmp=byte_cmp).key == b"\x02"
    assert index.search(1, cmp=byte_cmp).key == b"\x01"

    with pytest.raises(KeyError):
        index.search(4, cmp=byte_cmp)

    # Without a custom comparator the one-byte keys are rejected as invalid for ULONG
    with pytest.raises(ValueError, match="Invalid key length"):
        index.search(2)


def test_security_indexes(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)
    secure = fs.mft.get("$Secure")

    # $SII: security ID (ULONG)
    sii = secure.index("$SII")
    sii_entries = list(sii.entries())
    assert len(sii_entries) == 12
    for entry in sii_entries:
        security_id = int.from_bytes(entry.key, "little")
        assert sii.search(security_id).key == entry.key

    with pytest.raises(KeyError):
        sii.search(0xDEADBEEF)

    # $SDH: hash + security ID; the same hash with another security ID is not a hit
    sdh = secure.index("$SDH")
    sdh_entries = list(sdh.entries())
    assert len(sdh_entries) == 12
    for entry in sdh_entries:
        hash_id, security_id = struct.unpack("<II", entry.key)
        assert sdh.search((hash_id, security_id)).key == entry.key

        with pytest.raises(KeyError):
            sdh.search((hash_id, security_id + 1))

    # $ObjId:$O: compound integer key (the object ID GUID, as little-endian ULONGs)
    objid = fs.mft.get("$Extend/$ObjId").index("$O")
    for entry in objid.entries():
        assert objid.search(UUID(bytes_le=entry.key)).key == entry.key
        assert objid.search(struct.unpack("<4I", entry.key)).key == entry.key

    # $Quota:$O: SID key
    quota = fs.mft.get("$Extend/$Quota").index("$O")
    for entry in quota.entries():
        assert quota.search(read_sid(entry.key)).key == entry.key


def test_index_lookup(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)

    root = fs.mft.get("Large Directory")
    assert len(root.listdir()) == 2048

    for i in range(2048):
        entry = root.get(f"Directory {i}")
        assert entry.filename == f"Directory {i}"

    index = root.index("$I30")
    entries = list(index.entries())
    assert [entry.attribute.file_name for entry in entries] == sorted(
        (entry.attribute.file_name for entry in entries), key=str.upper
    )
