from __future__ import annotations

import struct
from typing import BinaryIO
from uuid import UUID

from dissect.ntfs.attr import Attribute
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, COLLATION, INDEX_ENTRY_END, c_ntfs
from dissect.ntfs.mft import MftRecord
from dissect.ntfs.ntfs import NTFS
from dissect.ntfs.objectid import (
    Guid,
    ObjectIdIndexEntry,
    ObjectIdReport,
    ObjectIdStatus,
)

INDEX_RECORD = 25


def _align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _resident_attribute(attr_type: ATTRIBUTE_TYPE_CODE, data: bytes, name: str = "") -> bytes:
    name_raw = name.encode("utf-16-le")
    name_offset = 24 if name else 0
    value_offset = _align(24 + len(name_raw))
    record_length = _align(value_offset + len(data))

    header = c_ntfs._ATTRIBUTE_RECORD_HEADER(
        TypeCode=attr_type,
        RecordLength=record_length,
        FormCode=0,
        NameLength=len(name),
        NameOffset=name_offset,
        Flags=0,
        Instance=0,
    )
    header.Form.Resident.ValueLength = len(data)
    header.Form.Resident.ValueOffset = value_offset

    result = bytearray(record_length)
    result[:24] = header.dumps()[:24]
    if name_raw:
        result[24 : 24 + len(name_raw)] = name_raw
    result[value_offset : value_offset + len(data)] = data
    return bytes(result)


def _mft_record(sequence: int, attributes: list[bytes]) -> bytes:
    data = bytearray(1024)
    data[:4] = b"FILE"

    struct.pack_into("<H", data, 4, 0x30)
    struct.pack_into("<H", data, 6, 3)
    struct.pack_into("<H", data, 16, sequence)
    struct.pack_into("<H", data, 18, 1)
    struct.pack_into("<H", data, 20, 0x38)
    struct.pack_into("<H", data, 22, 0)
    struct.pack_into("<I", data, 28, len(data))

    attributes_raw = b"".join(attributes) + b"\xff\xff\xff\xff"
    data[0x38 : 0x38 + len(attributes_raw)] = attributes_raw
    struct.pack_into("<I", data, 24, 0x38 + len(attributes_raw))

    data[0x30:0x32] = b"\xaa\xaa"
    data[0x32:0x34] = b"\x01\x02"
    data[0x34:0x36] = b"\x03\x04"
    data[510:512] = b"\xaa\xaa"
    data[1022:1024] = b"\xaa\xaa"
    return bytes(data)


def _index_entry(key: bytes, data: bytes) -> bytes:
    length = 16 + len(key) + len(data)
    result = bytearray(length)
    struct.pack_into("<HHI", result, 0, 32, len(data), 0)
    struct.pack_into("<HHHH", result, 8, length, len(key), 0, 0)
    result[16 : 16 + len(key)] = key
    result[16 + len(key) :] = data
    return bytes(result)


def _end_entry() -> bytes:
    result = bytearray(16)
    struct.pack_into("<HHHH", result, 8, 16, 0, INDEX_ENTRY_END, 0)
    return bytes(result)


def _index_root(entries: bytes) -> bytes:
    header = c_ntfs._INDEX_HEADER(
        FirstEntryOffset=0x10,
        TotalSizeOfEntries=len(entries),
        AllocatedSize=len(entries),
        Flags=0,
    )
    root = c_ntfs._INDEX_ROOT(
        AttributeType=ATTRIBUTE_TYPE_CODE.UNUSED,
        CollationRule=COLLATION.NTOFS_ULONGS,
        BytesPerIndexBuffer=4096,
        ClustersPerIndexBuffer=1,
        IndexHeader=header,
    )
    return root.dumps() + entries


def _guid(byte: int) -> Guid:
    return Guid(bytes([byte]) * 16)


def _object_id_attribute(
    object_id: Guid,
    birth_volume_id: Guid | None = None,
    birth_object_id: Guid | None = None,
    domain_id: Guid | None = None,
) -> bytes:
    raw = (
        object_id.raw
        + (birth_volume_id.raw if birth_volume_id else bytes(16))
        + (birth_object_id.raw if birth_object_id else bytes(16))
        + (domain_id.raw if domain_id else bytes(16))
    )
    return _resident_attribute(ATTRIBUTE_TYPE_CODE.OBJECT_ID, raw)


def _index_data(
    segment: int,
    sequence: int,
    birth_volume_id: Guid | None = None,
    birth_object_id: Guid | None = None,
    domain_id: Guid | None = None,
) -> bytes:
    return (
        struct.pack("<IHH", segment, 0, sequence)
        + (birth_volume_id.raw if birth_volume_id else bytes(16))
        + (birth_object_id.raw if birth_object_id else bytes(16))
        + (domain_id.raw if domain_id else bytes(16))
    )


def _record(
    segment: int,
    sequence: int,
    object_id_attribute: bytes | None,
    *,
    index_entries: list[tuple[Guid, bytes]] | None = None,
) -> MftRecord:
    attributes = [object_id_attribute] if object_id_attribute else []
    if index_entries is not None:
        entries = b"".join(_index_entry(key.raw, data) for key, data in index_entries) + _end_entry()
        attributes.append(_resident_attribute(ATTRIBUTE_TYPE_CODE.INDEX_ROOT, _index_root(entries), name="$O"))

    record = MftRecord.from_bytes(_mft_record(sequence, attributes))
    record.segment = segment
    return record


def _index(entries: list[tuple[Guid, bytes]]) -> dict[bytes, ObjectIdIndexEntry]:
    parsed = {}
    for offset, (key, data) in enumerate(entries):
        entry = ObjectIdIndexEntry(
            key_raw=key.raw,
            data_raw=data,
            index_offset=32 + offset * 88,
            index_record_segment=INDEX_RECORD,
        )
        parsed[key.raw] = entry
    return parsed


# One file whose attribute and index entry agree, and one whose attribute and index entry carry
# different current object IDs.
CURRENT_A = _guid(0x11)
CURRENT_B = _guid(0x22)
BIRTH_VOLUME = _guid(0x33)
BIRTH_OBJECT = _guid(0x44)
DOMAIN = _guid(0x55)

FILE_A = _record(
    41,
    1,
    _object_id_attribute(CURRENT_A, BIRTH_VOLUME, BIRTH_OBJECT, DOMAIN),
)
FILE_B = _record(
    42,
    1,
    _object_id_attribute(CURRENT_B, BIRTH_VOLUME, BIRTH_OBJECT, DOMAIN),
)
INDEX_ENTRIES = _index(
    [
        (CURRENT_A, _index_data(41, 1, BIRTH_VOLUME, BIRTH_OBJECT, DOMAIN)),
        # A stale entry: its key is CURRENT_B, but it points at a different record generation.
        (CURRENT_B, _index_data(41, 99, BIRTH_VOLUME, BIRTH_OBJECT, DOMAIN)),
    ]
)


def test_object_id_attribute_preserves_raw_and_display() -> None:
    attribute = Attribute.from_bytes(_object_id_attribute(CURRENT_A, BIRTH_VOLUME, BIRTH_OBJECT, DOMAIN))

    assert attribute.type == ATTRIBUTE_TYPE_CODE.OBJECT_ID
    assert attribute.resident
    assert attribute.object_id_raw == CURRENT_A.raw
    assert attribute.birth_volume_id_raw == BIRTH_VOLUME.raw
    assert attribute.birth_object_id_raw == BIRTH_OBJECT.raw
    assert attribute.domain_id_raw == DOMAIN.raw

    assert attribute.object_id == UUID(bytes_le=CURRENT_A.raw)
    assert attribute.object_id_display == CURRENT_A.display
    assert attribute.birth_volume_id == UUID(bytes_le=BIRTH_VOLUME.raw)
    assert attribute.birth_volume_id_display == BIRTH_VOLUME.display
    assert attribute.birth_object_id == UUID(bytes_le=BIRTH_OBJECT.raw)
    assert attribute.birth_object_id_display == BIRTH_OBJECT.display
    assert attribute.domain_id == UUID(bytes_le=DOMAIN.raw)
    assert attribute.domain_id_display == DOMAIN.display

    # Raw bytes stay in on-disk (little endian GUID) order, display uses the canonical form.
    assert attribute.object_id_raw[0] == 0x11
    assert str(UUID(bytes_le=attribute.object_id_raw)) == attribute.object_id_display

    assert attribute.data()[:16] == CURRENT_A.raw


def test_object_id_attribute_missing_birth_fields() -> None:
    attribute = Attribute.from_bytes(_object_id_attribute(CURRENT_A))

    assert attribute.object_id == UUID(bytes_le=CURRENT_A.raw)
    assert attribute.object_id_display == CURRENT_A.display
    assert attribute.birth_volume_id is None
    assert attribute.birth_volume_id_display is None
    assert attribute.birth_object_id is None
    assert attribute.domain_id is None
    assert attribute.raw[:16] == CURRENT_A.raw
    assert attribute.raw[16:] == bytes(48)


def test_object_id_report_consistent() -> None:
    report = ObjectIdReport.from_record(
        FILE_A,
        entries=[INDEX_ENTRIES[CURRENT_A.raw]],
        current_volume_id=BIRTH_VOLUME,
    )

    assert report.status == ObjectIdStatus.CONSISTENT
    assert report.is_consistent
    assert report.current_identity_status == ObjectIdStatus.CONSISTENT
    assert report.birth_identity_status == ObjectIdStatus.CONSISTENT
    assert report.cross_volume_move is False
    assert not report.proven_cross_volume_move
    assert report.reasons == ()

    assert report.current_object_id == CURRENT_A
    assert report.birth_volume_id == BIRTH_VOLUME
    assert report.birth_object_id == BIRTH_OBJECT
    assert report.domain_id == DOMAIN

    # Every conclusion traces to the concrete attribute and index entry.
    assert report.attribute is not None
    assert report.attribute.source == "attribute"
    assert report.attribute.record_segment == 41
    assert report.attribute.record_sequence == 1
    assert report.attribute.raw == attribute_raw(report)
    assert report.attribute.object_id == CURRENT_A

    assert report.index_entry is not None
    assert report.index_entry.source == "index_entry"
    assert report.index_entry.record_segment == 41
    assert report.index_entry.record_sequence == 1
    assert report.index_entry.index_record_segment == INDEX_RECORD
    assert report.index_entry.index_offset == 32
    assert report.index_entry.birth_volume_id == BIRTH_VOLUME

    assert "MFT record 41#1" in report.attribute.describe()
    assert "MFT record 25" in report.index_entry.describe()


def attribute_raw(report: ObjectIdReport) -> bytes:
    return report.attribute.raw if report.attribute else b""


def test_object_id_report_conflicting_record_generation() -> None:
    report = ObjectIdReport.from_record(
        FILE_B,
        entries=[INDEX_ENTRIES[CURRENT_B.raw]],
        current_volume_id=BIRTH_VOLUME,
    )

    assert report.status == ObjectIdStatus.CONFLICT
    assert report.is_conflict
    assert report.current_identity_status == ObjectIdStatus.CONFLICT
    assert report.cross_volume_move is None
    assert not report.proven_cross_volume_move
    assert "file_reference_sequence_mismatch" in report.reasons

    # The index entry in the fixture points at segment 41 generation 99, not FILE_B (42#1).
    assert report.index_entry is not None
    assert report.index_entry.record_segment == 41
    assert report.index_entry.record_sequence == 99
    assert report.record_segment == 42
    assert report.record_sequence == 1


def test_object_id_report_stale_index_entry_is_insufficient() -> None:
    # This index entry has no resolvable file record, so only one side of the identity relationship exists.
    stale = ObjectIdIndexEntry(
        key_raw=CURRENT_B.raw,
        data_raw=_index_data(41, 99, BIRTH_VOLUME, BIRTH_OBJECT, DOMAIN),
        index_offset=120,
        index_record_segment=INDEX_RECORD,
    )

    report = ObjectIdReport.from_index_entry(stale, current_volume_id=BIRTH_VOLUME)

    assert report.status == ObjectIdStatus.INSUFFICIENT
    assert report.is_insufficient
    assert report.cross_volume_move is None
    assert not report.proven_cross_volume_move
    assert report.reasons == ("missing_file_record",)
    assert report.attribute is None
    assert len(report.index_entries) == 1
    assert report.index_entries[0].index_offset == 120
    assert report.index_entries[0].object_id == CURRENT_B


def test_object_id_report_missing_birth_information_is_not_a_proven_move() -> None:
    record = _record(41, 1, _object_id_attribute(CURRENT_A))
    entry = ObjectIdIndexEntry(
        key_raw=CURRENT_A.raw,
        data_raw=_index_data(41, 1),
        index_offset=32,
        index_record_segment=INDEX_RECORD,
    )

    report = ObjectIdReport.from_record(record, entries=[entry], current_volume_id=BIRTH_VOLUME)

    # The current identity agrees, but without birth fields there is no proof of any cross-volume move.
    assert report.status == ObjectIdStatus.INSUFFICIENT
    assert report.current_identity_status == ObjectIdStatus.CONSISTENT
    assert report.birth_identity_status == ObjectIdStatus.INSUFFICIENT
    assert report.cross_volume_move is None
    assert not report.proven_cross_volume_move
    assert "missing_birth_volume_id" in report.reasons
    assert "missing_birth_object_id" in report.reasons


def test_object_id_report_missing_attribute_is_insufficient() -> None:
    report = ObjectIdReport.from_record(_record(41, 1, None), entries=[], current_volume_id=BIRTH_VOLUME)

    assert report.status == ObjectIdStatus.INSUFFICIENT
    assert report.attribute is None
    assert report.reasons == ("missing_object_id_attribute",)


def test_object_id_report_missing_index_is_insufficient() -> None:
    report = ObjectIdReport.from_record(FILE_A, entries=[])

    assert report.status == ObjectIdStatus.INSUFFICIENT
    assert report.index_entries == ()
    assert "missing_index_entry" in report.reasons


def test_object_id_report_birth_mismatch_conflicts() -> None:
    record = _record(41, 1, _object_id_attribute(CURRENT_A, BIRTH_VOLUME, BIRTH_OBJECT, DOMAIN))
    entry = ObjectIdIndexEntry(
        key_raw=CURRENT_A.raw,
        data_raw=_index_data(41, 1, BIRTH_VOLUME, BIRTH_OBJECT, _guid(0x66)),
        index_offset=32,
        index_record_segment=INDEX_RECORD,
    )

    report = ObjectIdReport.from_record(record, entries=[entry], current_volume_id=BIRTH_VOLUME)

    assert report.status == ObjectIdStatus.CONFLICT
    assert report.current_identity_status == ObjectIdStatus.CONSISTENT
    assert report.birth_identity_status == ObjectIdStatus.CONFLICT
    assert report.cross_volume_move is None
    assert "domain_id_mismatch" in report.reasons


def test_object_id_report_cross_volume_move_only_when_all_sides_agree() -> None:
    other_volume = _guid(0x77)
    record = _record(41, 1, _object_id_attribute(CURRENT_A, other_volume, BIRTH_OBJECT, DOMAIN))
    entry = ObjectIdIndexEntry(
        key_raw=CURRENT_A.raw,
        data_raw=_index_data(41, 1, other_volume, BIRTH_OBJECT, DOMAIN),
        index_offset=32,
        index_record_segment=INDEX_RECORD,
    )

    report = ObjectIdReport.from_record(record, entries=[entry], current_volume_id=BIRTH_VOLUME)

    assert report.status == ObjectIdStatus.CONSISTENT
    assert report.cross_volume_move is True
    assert report.proven_cross_volume_move

    # Same materials, but without a current volume ID, the move cannot be proven.
    report = ObjectIdReport.from_record(record, entries=[entry])

    assert report.status == ObjectIdStatus.CONSISTENT
    assert report.cross_volume_move is None
    assert not report.proven_cross_volume_move
    assert "current_volume_id_unavailable" in report.reasons


def test_object_id_index_parses_entries_and_reports_against_real_volume(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)

    index = fs.objid
    assert index is not None
    assert index.volume_id is None

    entries = list(index)
    assert entries
    assert all(entry.index_record_segment == 25 for entry in entries)
    assert {entry.file_reference_segment for entry in entries} >= {41, 42, 43}

    report = index.report_path("File.txt")
    assert report.status == ObjectIdStatus.INSUFFICIENT
    assert report.current_identity_status == ObjectIdStatus.CONSISTENT
    assert report.birth_identity_status == ObjectIdStatus.INSUFFICIENT
    assert report.cross_volume_move is None
    assert report.record_segment == 41
    assert report.record_sequence == 1
    assert report.attribute is not None
    assert report.index_entry is not None
    assert report.index_entry.record_segment == 41
    assert report.index_entry.record_sequence == 1

    # The attribute in this sample is only 16 bytes, while the index entry carries a birth object ID
    # but no birth volume or domain. This asymmetric, incomplete material must stay insufficient.
    assert report.birth_volume_id is None
    assert report.domain_id is None
    assert report.attribute.birth_volume_id is None
    assert report.index_entry.birth_object_id == report.current_object_id
    assert report.to_dict()["status"] == "insufficient"
    assert "missing_birth_volume_id" in report.reasons
    assert "missing_birth_object_id" in report.reasons


def test_object_id_index_from_ntfs_without_mft() -> None:
    fs = NTFS()
    assert fs.objid is None


def test_object_id_report_same_id_on_two_files_conflicts() -> None:
    # Two files that both carry CURRENT_A, each with an index entry pointing at a different record.
    shared_a = ObjectIdIndexEntry(
        key_raw=CURRENT_A.raw,
        data_raw=_index_data(41, 1, BIRTH_VOLUME, BIRTH_OBJECT, DOMAIN),
        index_offset=32,
        index_record_segment=INDEX_RECORD,
    )
    shared_b = ObjectIdIndexEntry(
        key_raw=CURRENT_A.raw,
        data_raw=_index_data(42, 1, BIRTH_VOLUME, BIRTH_OBJECT, DOMAIN),
        index_offset=120,
        index_record_segment=INDEX_RECORD,
    )

    report = ObjectIdReport.from_record(
        FILE_A,
        entries=[shared_a, shared_b],
        current_volume_id=BIRTH_VOLUME,
    )

    assert report.status == ObjectIdStatus.CONFLICT
    assert report.current_identity_status == ObjectIdStatus.CONFLICT
    assert "duplicate_index_entries" in report.reasons
    assert report.cross_volume_move is None
    assert not report.proven_cross_volume_move
    assert len(report.index_entries) == 2
    assert {entry.record_segment for entry in report.index_entries} == {41, 42}
