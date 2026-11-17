from __future__ import annotations

import io
import struct

from dissect.hypervisor.descriptor.c_hyperv import (
    KeyDataFlag,
    KeyDataType,
)
from dissect.hypervisor.descriptor.hyperv import (
    HyperVFile,
    HyperVKeyEvidence,
    KeyEntryRef,
    KeyEvidenceError,
    UnparseableValue,
)
from tests.descriptor._hyperv_builder import KEY_TABLE_OFFSET, HyperVStorageBuilder


def _open(data: bytes) -> HyperVFile:
    return HyperVFile(io.BytesIO(data))


def _record_by_key(view: HyperVFile, name: str) -> HyperVKeyEvidence:
    matches = view.evidence_view().find_by_name(name)
    assert matches, f"no evidence record named {name!r}"
    return matches[0]


def _healthy_file() -> tuple[HyperVStorageBuilder, bytes]:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    builder.entry("count", KeyDataType.Int, -7, parent_table_idx=1, parent_offset=root.entry_offset)
    builder.entry("unsigned", KeyDataType.UInt, 42, parent_table_idx=1, parent_offset=root.entry_offset)
    builder.entry("ratio", KeyDataType.Double, 2.5, parent_table_idx=1, parent_offset=root.entry_offset)
    builder.entry("enabled", KeyDataType.Bool, True, parent_table_idx=1, parent_offset=root.entry_offset)
    builder.entry("label", KeyDataType.String, "hello", parent_table_idx=1, parent_offset=root.entry_offset)
    builder.entry("blob", KeyDataType.Array, b"\x01\x02", parent_table_idx=1, parent_offset=root.entry_offset)
    builder.entry(
        "external",
        KeyDataType.String,
        "w" * 1100,
        parent_table_idx=1,
        parent_offset=root.entry_offset,
        file_pointer=True,
    )
    builder.free_entry()
    return builder, builder.build()


def test_evidence_view_reports_type_location_parent_and_ranges() -> None:
    _builder, data = _healthy_file()
    hf = _open(data)
    view = hf.evidence_view()

    assert view.table_errors == []
    assert all(not record.has_errors for record in view.records)

    root = _record_by_key(hf, "root")
    assert root.type == KeyDataType.Node
    assert root.parent is None
    assert root.value is None
    assert root.entry_range.offset == KEY_TABLE_OFFSET + root.ref.entry_offset
    assert not root.value_range.external

    label = _record_by_key(hf, "label")
    assert label.type == KeyDataType.String
    assert label.value == "hello"
    assert label.parent == root.ref
    assert not label.value_range.external
    assert label.key_range.length == len("label")
    assert label.raw[-(10):] == "hello".encode("utf-16-le")

    external = _record_by_key(hf, "external")
    assert external.is_file_object_pointer
    assert external.value_range.external
    assert external.value == "w" * 1100
    assert external.value_range.length == 2200


def test_typed_evidence_values_match_original_bytes() -> None:
    _builder, data = _healthy_file()
    hf = _open(data)

    cases = {
        "count": (KeyDataType.Int, -7, 8),
        "unsigned": (KeyDataType.UInt, 42, 8),
        "ratio": (KeyDataType.Double, 2.5, 8),
        "enabled": (KeyDataType.Bool, True, 4),
        "label": (KeyDataType.String, "hello", 10),
        "blob": (KeyDataType.Array, b"\x01\x02", 2),
    }
    for name, (entry_type, expected, length) in cases.items():
        record = _record_by_key(hf, name)
        assert record.type == entry_type
        assert record.value == expected
        assert record.value_range.length == length
        # The typed result must be traceable back to the exact original bytes.
        assert hf.fh.seek(record.value_range.offset) == record.value_range.offset
        assert hf.fh.read(length) == record.raw[-(length):]


def test_duplicate_names_keep_independent_identities() -> None:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    first = builder.entry("dup", KeyDataType.Int, 1, parent_table_idx=1, parent_offset=root.entry_offset)
    second = builder.entry("dup", KeyDataType.Int, 2, parent_table_idx=1, parent_offset=root.entry_offset)
    builder.free_entry()
    hf = _open(builder.build())

    siblings = hf.evidence_view().find_by_name("dup")
    assert len(siblings) == 2
    assert {record.ref.entry_offset for record in siblings} == {
        first.entry_offset,
        second.entry_offset,
    }
    assert [record.value for record in siblings] == [1, 2]

    # Convenience tree keeps the historical overwrite semantics.
    assert hf.as_dict()["root"]["dup"] == 2
    # Evidence children surface both siblings.
    root_ref = KeyEntryRef(1, KEY_TABLE_OFFSET, root.entry_offset)
    assert len(hf.evidence_view().children(root_ref)) == 2


def test_bad_entry_does_not_overwrite_valid_sibling_or_neighbour() -> None:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    good = builder.entry("dup", KeyDataType.Int, 11, parent_table_idx=1, parent_offset=root.entry_offset)
    neighbour = builder.entry(
        "neighbour", KeyDataType.String, "safe", parent_table_idx=1, parent_offset=root.entry_offset
    )
    bad = builder.entry("dup", KeyDataType.Int, 0, parent_table_idx=1, parent_offset=root.entry_offset)
    # Corrupt the last live entry so it claims far more bytes than the table contains.
    builder.patch_table(1, bad, 2, struct.pack("<I", bad.size + 0x400))

    hf = _open(builder.build())
    view = hf.evidence_view()
    bad_record = view.get(KeyEntryRef(1, KEY_TABLE_OFFSET, bad.entry_offset))

    assert KeyEvidenceError.TRUNCATED_ENTRY in bad_record.issue_codes()
    # The valid sibling survives in the convenience tree.
    assert hf.as_dict()["root"]["dup"] == 11
    # The adjacent entry's value is not swallowed into the corrupt entry's result.
    neighbour_record = view.get(KeyEntryRef(1, KEY_TABLE_OFFSET, neighbour.entry_offset))
    assert neighbour_record.value == "safe"
    assert neighbour_record.issue_codes() == []
    # The good entry itself stays clean.
    good_record = view.get(KeyEntryRef(1, KEY_TABLE_OFFSET, good.entry_offset))
    assert good_record.issue_codes() == []
    assert good_record.value == 11


def test_type_length_contradiction_is_reported() -> None:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    entry = builder.entry("num", KeyDataType.Int, 9, parent_table_idx=1, parent_offset=root.entry_offset)
    # Shrink the declared entry size below the 21-byte header to create a hard size contradiction.
    builder.patch_table(1, entry, 2, struct.pack("<I", 8))
    builder.free_entry()

    hf = _open(builder.build())
    record = hf.evidence_view().get(KeyEntryRef(1, KEY_TABLE_OFFSET, entry.entry_offset))
    assert KeyEvidenceError.INVALID_ENTRY_SIZE in record.issue_codes()
    assert "num" not in hf.as_dict()["root"]


def test_unknown_type_is_reported_and_retained() -> None:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    entry = builder.entry("weird", KeyDataType.Int, 1, parent_table_idx=1, parent_offset=root.entry_offset)
    entry.raw[0] = 42
    builder.free_entry()

    hf = _open(builder.build())
    record = hf.evidence_view().get(KeyEntryRef(1, KEY_TABLE_OFFSET, entry.entry_offset))
    assert record.type is None
    assert KeyEvidenceError.UNKNOWN_TYPE in record.issue_codes()
    assert isinstance(record.value, UnparseableValue)
    assert record.raw  # original bytes remain available
    assert "weird" not in hf.as_dict()["root"]


def test_out_of_bounds_file_pointer_is_reported_with_bounded_read() -> None:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    entry = builder.entry(
        "far",
        KeyDataType.String,
        "payload",
        parent_table_idx=1,
        parent_offset=root.entry_offset,
        file_pointer=True,
    )
    # Point the pointer past the end of the file.
    pointer_field = entry.size - 12
    struct.pack_into("<IQ", entry.raw, pointer_field, 7, 0x999999)
    builder.free_entry()

    hf = _open(builder.build())
    record = hf.evidence_view().get(KeyEntryRef(1, KEY_TABLE_OFFSET, entry.entry_offset))
    assert KeyEvidenceError.POINTER_OUT_OF_BOUNDS in record.issue_codes()
    assert isinstance(record.value, UnparseableValue)
    # The bounded read returns no neighbouring bytes instead of walking the file.
    assert record.value_range.read(hf.fh, hf._file_size) == b""
    assert "far" not in hf.as_dict()["root"]


def test_unknown_file_object_pointer_is_reported() -> None:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    entry = builder.entry(
        "dangling",
        KeyDataType.String,
        "payload",
        parent_table_idx=1,
        parent_offset=root.entry_offset,
        file_pointer=True,
    )
    pointer_field = entry.size - 12
    struct.pack_into("<IQ", entry.raw, pointer_field, 7, 0x5000)
    builder.free_entry()

    hf = _open(builder.build())
    record = hf.evidence_view().get(KeyEntryRef(1, KEY_TABLE_OFFSET, entry.entry_offset))
    assert KeyEvidenceError.UNKNOWN_FILE_OBJECT in record.issue_codes()
    assert isinstance(record.value, UnparseableValue)


def test_parent_cycle_is_reported_and_excludes_ring_from_convenience_tree() -> None:
    builder = HyperVStorageBuilder()
    node_a = builder.entry("a", KeyDataType.Node)
    node_b = builder.entry("b", KeyDataType.Node, parent_table_idx=1, parent_offset=node_a.entry_offset)
    # Rewire node_a to point at node_b, forming a -> b -> a.
    struct.pack_into("<H", node_a.raw, 6, 1)
    struct.pack_into("<I", node_a.raw, 8, node_b.entry_offset)
    builder.entry("child", KeyDataType.Int, 3, parent_table_idx=1, parent_offset=node_b.entry_offset)
    builder.free_entry()

    hf = _open(builder.build())
    view = hf.evidence_view()
    for name in ("a", "b", "child"):
        record = view.find_by_name(name)[0]
        assert KeyEvidenceError.PARENT_CYCLE in record.issue_codes()
        assert record.linked is False

    assert hf.as_dict() == {}


def test_missing_parent_table_and_entry_are_reported() -> None:
    builder = HyperVStorageBuilder()
    builder.entry("root", KeyDataType.Node)
    builder.entry("ghost_table", KeyDataType.Int, 1, parent_table_idx=9, parent_offset=0x10)
    builder.entry(
        "ghost_entry",
        KeyDataType.Int,
        2,
        parent_table_idx=1,
        parent_offset=0x777,
    )
    builder.free_entry()

    hf = _open(builder.build())
    view = hf.evidence_view()
    assert KeyEvidenceError.MISSING_PARENT_TABLE in view.find_by_name("ghost_table")[0].issue_codes()
    assert KeyEvidenceError.MISSING_PARENT_ENTRY in view.find_by_name("ghost_entry")[0].issue_codes()
    # The sound root and its valid subtree stay available.
    assert list(hf.as_dict().keys()) == ["root"]


def test_incomplete_entry_is_reported_without_losing_neighbours() -> None:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    builder.entry("before", KeyDataType.Int, 5, parent_table_idx=1, parent_offset=root.entry_offset)
    truncated = builder.entry("cut", KeyDataType.String, "partial", parent_table_idx=1, parent_offset=root.entry_offset)
    builder.patch_table(1, truncated, 2, struct.pack("<I", truncated.size + 0x400))
    hf = _open(builder.build())
    view = hf.evidence_view()
    truncated_record = view.find_by_name("cut")[0]
    assert KeyEvidenceError.TRUNCATED_ENTRY in truncated_record.issue_codes()
    # The earlier neighbour remains a clean, fully readable record.
    assert view.find_by_name("before")[0].value == 5
    assert view.find_by_name("before")[0].issue_codes() == []
    assert "cut" not in hf.as_dict()["root"]
    assert hf.as_dict()["root"]["before"] == 5


def test_short_key_table_documents_inline_external_and_sibling_evidence() -> None:
    builder, data = _healthy_file()
    hf = _open(data)
    view = hf.evidence_view()

    inline = [record for record in view.records if record.value_range and not record.value_range.external]
    external = [record for record in view.records if record.value_range and record.value_range.external]
    assert inline
    assert external
    assert all(record.ref.table_index == 1 for record in view.records)
    assert len(view.roots()) == 1

    # Every record carries physical identity plus complete location metadata.
    for record in view.records:
        assert isinstance(record.ref, KeyEntryRef)
        assert record.entry_range.length == record.declared_size
        assert record.flags == (KeyDataFlag.FileObjectPointer if record.is_file_object_pointer else 0)


def test_bad_table_signature_is_reported_without_losing_entries() -> None:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    builder.entry("n", KeyDataType.Int, 1, parent_table_idx=1, parent_offset=root.entry_offset)
    builder.free_entry()
    data = bytearray(builder.build())
    struct.pack_into("<H", data, KEY_TABLE_OFFSET, 0xFFFF)

    hf = _open(bytes(data))
    view = hf.evidence_view()
    assert KeyEvidenceError.BAD_TABLE_SIGNATURE in [issue.error for issue in view.table_errors]
    # The entries are still exposed as evidence even though the table header is corrupt.
    assert {record.name for record in view.records if record.type != KeyDataType.Free} == {"root", "n"}


def test_truncated_table_is_reported_at_table_level() -> None:
    builder = HyperVStorageBuilder()
    root = builder.entry("root", KeyDataType.Node)
    builder.entry("n", KeyDataType.Int, 1, parent_table_idx=1, parent_offset=root.entry_offset)
    builder.free_entry()

    hf = _open(builder.build()[: KEY_TABLE_OFFSET + 0x40])
    view = hf.evidence_view()
    codes = [issue.error for issue in view.table_errors]
    assert KeyEvidenceError.TRUNCATED_TABLE in codes
    assert KeyEvidenceError.TRUNCATED_ENTRY_HEADER in codes


def test_convenience_interface_compatibility_is_unchanged_for_sound_files() -> None:
    builder, data = _healthy_file()
    hf = _open(data)

    assert set(hf.keys()) == {"root"}
    assert hf["root"].type == KeyDataType.Node
    assert hf.as_dict() == {
        "root": {
            "count": -7,
            "unsigned": 42,
            "ratio": 2.5,
            "enabled": True,
            "label": "hello",
            "blob": b"\x01\x02",
            "external": "w" * 1100,
        }
    }
    # Evidence remains available independently of the convenience projection.
    assert len(hf.evidence_view()) == 9
    assert hf.evidence_view().errors() == []
