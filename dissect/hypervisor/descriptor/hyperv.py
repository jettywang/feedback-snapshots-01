# References:
# - VmDataStore.dll
from __future__ import annotations

import enum
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream

from dissect.hypervisor.descriptor.c_hyperv import (
    KeyDataFlag,
    KeyDataType,
    ObjectEntryType,
    c_hyperv,
)
from dissect.hypervisor.exceptions import InvalidSignature

if TYPE_CHECKING:
    from collections.abc import ItemsView, Iterator, KeysView, ValuesView

ENTRY_HEADER_SIZE = len(c_hyperv.HyperVStorageKeyTableEntryHeader)
KEY_DATA_TYPE_VALUES = set(KeyDataType._value2member_map_)


class KeyEvidenceError(enum.Enum):
    """Ways in which a key table entry or its surrounding structure can be malformed.

    Every error is reported on an evidence record instead of being raised, so a single corrupt
    entry never aborts parsing of its neighbours.
    """

    BAD_TABLE_SIGNATURE = "key table has an invalid signature"
    TRUNCATED_TABLE = "key table extends past its declared object size"
    TRUNCATED_ENTRY_HEADER = "entry header is incomplete"
    TRUNCATED_ENTRY = "entry body is smaller than its declared size"
    INVALID_ENTRY_SIZE = "entry has a size smaller than its header"
    UNKNOWN_TYPE = "entry type is not a known KeyDataType"
    TYPE_LENGTH_MISMATCH = "declared entry size does not match the type and value length"
    VALUE_OUT_OF_BOUNDS = "value data reaches past the key table"
    POINTER_OUT_OF_BOUNDS = "file object pointer points outside the file"
    UNKNOWN_FILE_OBJECT = "file object pointer does not reference a known file object"
    MISSING_PARENT_TABLE = "parent table index does not exist"
    MISSING_PARENT_ENTRY = "parent offset does not point to an entry in the parent table"
    PARENT_CYCLE = "parent chain contains a cycle"


class UnparseableValue:
    """Sentinel for an evidence value that can not be decoded without reading out of bounds.

    The original bytes remain available through :class:`HyperVKeyEvidence` so an investigator can
    inspect the partial data manually instead of silently getting a wrong value.
    """

    def __repr__(self) -> str:
        return "<unparseable value: inspect the evidence raw bytes and errors>"


UNPARSEABLE_VALUE = UnparseableValue()


@dataclass(frozen=True, slots=True)
class KeyDataRange:
    """A byte range inside the Hyper-V file.

    A negative ``length`` or a range that extends past the end of the file means the data could
    not be fully read; the ``raw`` property then only returns the bytes that are actually present.
    """

    offset: int
    length: int
    external: bool = False

    def __str__(self) -> str:
        location = "external" if self.external else "inline"
        return f"{location} 0x{self.offset:x}..0x{self.offset + max(self.length, 0):x} ({self.length} bytes)"

    def read(self, fh: BinaryIO, file_size: int) -> bytes:
        if self.offset < 0 or self.length < 0 or self.offset >= file_size:
            return b""
        fh.seek(self.offset)
        return fh.read(min(self.length, file_size - self.offset))

    @property
    def is_complete(self) -> bool:
        return self.offset >= 0 and self.length >= 0


@dataclass(frozen=True, slots=True)
class KeyEvidenceIssue:
    """A single structural problem recorded while building the evidence view."""

    error: KeyEvidenceError
    message: str


@dataclass(frozen=True, slots=True)
class KeyEntryRef:
    """Stable identifier of a key table entry based on its physical location."""

    table_index: int
    table_offset: int
    entry_offset: int

    def __str__(self) -> str:
        return f"table {self.table_index} @ 0x{self.table_offset:x}, entry @ 0x{self.entry_offset:x}"


@dataclass(slots=True)
class HyperVKeyEvidence:
    """Raw key evidence for a single key table entry.

    Unlike the convenience mapping on :class:`HyperVFile`, every entry keeps its own identity even
    when multiple entries share the same key name, and malformed entries are reported alongside the
    bytes that were actually read instead of being silently dropped.
    """

    ref: KeyEntryRef
    name: str
    type: KeyDataType | None
    flags: int
    declared_size: int
    parent: KeyEntryRef | None
    key_range: KeyDataRange | None
    value_range: KeyDataRange | None
    entry_range: KeyDataRange
    value: object
    raw: bytes
    errors: list[KeyEvidenceIssue] = field(default_factory=list)
    linked: bool = True

    @property
    def is_file_object_pointer(self) -> bool:
        """Return whether the value lives in an external file object."""
        return bool(self.flags & KeyDataFlag.FileObjectPointer)

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    def issue_codes(self) -> list[KeyEvidenceError]:
        return [issue.error for issue in self.errors]


@dataclass(slots=True)
class HyperVEvidenceView:
    """Investigator-facing view of the raw key evidence in a Hyper-V storage file.

    ``records`` preserves every parseable entry across all active key tables, including entries with
    duplicate names and entries with structural errors. ``table_errors`` holds problems that could
    not be attributed to a specific entry. The convenience mapping on :class:`HyperVFile` is a
    filtered projection of this view.
    """

    records: list[HyperVKeyEvidence]
    table_errors: list[KeyEvidenceIssue] = field(default_factory=list)
    by_ref: dict[KeyEntryRef, HyperVKeyEvidence] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.by_ref = {record.ref: record for record in self.records}

    def __iter__(self) -> Iterator[HyperVKeyEvidence]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def get(self, ref: KeyEntryRef) -> HyperVKeyEvidence | None:
        return self.by_ref.get(ref)

    def find_by_name(self, name: str) -> list[HyperVKeyEvidence]:
        """Return every record carrying ``name``, keeping duplicate-name identities separate."""
        return [record for record in self.records if record.name == name]

    def errors(self) -> list[KeyEvidenceIssue]:
        """Return all issues, both entry-level and table-level, in discovery order."""
        issues = list(self.table_errors)
        for record in self.records:
            issues.extend(record.errors)
        return issues

    def roots(self) -> list[HyperVKeyEvidence]:
        """Return the root entries, including duplicate root names as separate records."""
        return [
            record
            for record in self.records
            if record.linked and record.parent is None and record.type != KeyDataType.Free
        ]

    def children(self, ref: KeyEntryRef) -> list[HyperVKeyEvidence]:
        """Return the linked children of ``ref``, preserving duplicate-name siblings."""
        return [
            record
            for record in self.records
            if record.linked and record.parent == ref and record.type != KeyDataType.Free
        ]


class HyperVFile:
    """HyperVFile implementation.

    I think, technically, the underlying container is called ``HyperVStorage``, and the ``HyperVFile`` adds
    some features on top of that. We just call it ``HyperVFile`` for convenience.

    A ``HyperVFile`` has 2 headers, one at ``0x0000`` and one at ``0x1000``. The active header is determined
    by a sequence number.

    A replay log is located at an offset specified in the header. This replay log functions as a journal
    for changes made to the file. A file is dirty if it contains outstanding entries in the replay log,
    and replaying the specified log entries is necessary. This is not currently implemented.

    An object table seems to be located at ``0x2000``, but it's unclear if this is always the case. The offset
    might be related to the header size, log size or data alignment. This will need some more research.
    This table contains entries that describe the various "objects" contained within this file. The available
    types are listed in the ``ObjectEntryType`` enum.

    ``HyperVFile``'s have a version number, and it looks like there are some slight differences between
    different versions. The key tables are at least stored in a different manner, because there's code
    to handle loading them differently, and also to update them to the new format if an old version is
    encountered. However, I haven't seen any files with older versions yet, so we guard this implementation
    to only version ``0x0400`` at this time.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.fh.seek(c_hyperv.FIRST_HEADER_OFFSET)
        header1 = c_hyperv.HyperVStorageHeader(self.fh)
        self.fh.seek(c_hyperv.SECOND_HEADER_OFFSET)
        header2 = c_hyperv.HyperVStorageHeader(self.fh)

        self.header = header1 if header1.sequence_number > header2.sequence_number else header2
        self.headers = [header1, header2]

        if self.header.signature != c_hyperv.SIGNATURE_STORAGE_HEADER:
            raise InvalidSignature(f"Invalid header signature: 0x{self.header.signature:x}")

        if self.header.version != 0x400:
            # Need test files to know how the keys are stored.
            raise NotImplementedError(f"Unsupported version: 0x{self.header.version:x}")

        self.replay_logs = [HyperVStorageReplayLog(self, self.header.replay_log_offset)]
        self.object_tables = [HyperVStorageObjectTable(self, c_hyperv.OBJECT_TABLE_OFFSET)]
        self.key_tables: dict[int, list[HyperVStorageKeyTable]] = {}
        self.file_objects: dict[int, HyperVStorageFileObject] = {}

        for object_table in self.object_tables:
            for entry in object_table.entries:
                if entry.allocated == 0:
                    continue

                if entry.type == ObjectEntryType.ObjectTable:
                    # Haven't seen a file yet with additional object tables, but I assume this is how it'd work
                    new_object_table = HyperVStorageObjectTable(self, entry.offset)
                    self.object_tables.append(new_object_table)

                if entry.type == ObjectEntryType.KeyTable:
                    key_table = HyperVStorageKeyTable(self, entry.offset, entry.size)
                    if key_table.index not in self.key_tables:
                        self.key_tables[key_table.index] = []
                    # Haven't seen a file yet with multiple tables of the same index, but different
                    # sequence number, but I assume this is how it'd work.
                    self.key_tables[key_table.index].append(key_table)
                    self.key_tables[key_table.index].sort(key=lambda table: table.sequence_number, reverse=True)

                if entry.type == ObjectEntryType.File:
                    self.file_objects[entry.offset] = HyperVStorageFileObject(self, entry.offset, entry.size)

                if entry.type == ObjectEntryType.ReplayLog:
                    # Haven't seen a file yet with additional replay logs, but I assume this is how it'd work
                    replay_log = HyperVStorageReplayLog(self, entry.offset)
                    self.replay_logs.append(replay_log)

        # The evidence view is the single source of truth. It never raises on corrupt entries:
        # every structural problem is recorded on the affected record instead.
        self.evidence = self._build_evidence()

        # The convenience mapping projects only sound, linked entries onto nodes. Malformed entries
        # never replace a valid entry of the same name.
        self.root = self._build_convenience_tree()

    def _build_evidence(self) -> HyperVEvidenceView:
        self.fh.seek(0, 2)
        self._file_size = self.fh.tell()

        records: list[HyperVKeyEvidence] = []
        table_errors: list[KeyEvidenceIssue] = []

        for tables in self.key_tables.values():
            active_table = tables[0]
            table_ref_records, table_issues = self._evidence_for_table(active_table, self._file_size)
            records.extend(table_ref_records)
            table_errors.extend(table_issues)

        self._resolve_evidence_parents(records)
        self._detect_parent_cycles(records)

        view = HyperVEvidenceView(records=records, table_errors=table_errors)
        self._decode_evidence_values(view, self._file_size)
        return view

    def _evidence_for_table(
        self, table: HyperVStorageKeyTable, file_size: int
    ) -> tuple[list[HyperVKeyEvidence], list[KeyEvidenceIssue]]:
        records: list[HyperVKeyEvidence] = []
        issues: list[KeyEvidenceIssue] = []

        if table.invalid_signature:
            issues.append(
                KeyEvidenceIssue(
                    KeyEvidenceError.BAD_TABLE_SIGNATURE,
                    f"key table index {table.index} at 0x{table.offset:x} has an invalid signature",
                )
            )

        if table.truncated:
            issues.append(
                KeyEvidenceIssue(
                    KeyEvidenceError.TRUNCATED_TABLE,
                    f"key table index {table.index} at 0x{table.offset:x} ends at "
                    f"0x{table.offset + table.size:x} but the file is 0x{file_size:x} bytes",
                )
            )

        scan_issues_by_offset: dict[int, list[KeyEvidenceIssue]] = {}
        for entry, entry_issues in table.scan_entries():
            issues.extend(entry_issues)
            if entry is None:
                # A header could not even be read; the scanner already reported where it stopped.
                continue
            scan_issues_by_offset[entry.offset] = entry_issues
            records.append(self._evidence_for_entry(entry))

        for record in records:
            if record.ref.table_offset == table.offset:
                record.errors.extend(scan_issues_by_offset.get(record.ref.entry_offset, []))

        return records, issues

    def _evidence_for_entry(self, entry: HyperVStorageKeyTableEntry) -> HyperVKeyEvidence:
        header = entry.header
        ref = KeyEntryRef(entry.table.index, entry.table.offset, entry.offset)

        entry_end = min(entry.offset + entry.size, len(entry.table.raw))
        entry_range = KeyDataRange(
            offset=entry.table.offset + entry.offset,
            length=entry.size,
        )
        raw = entry.table.raw[entry.offset : entry_end].tobytes()

        raw_type = header.type & 0xFF
        flags = (header.type & 0xFF00) >> 8
        entry_type = KeyDataType(raw_type) if raw_type in KEY_DATA_TYPE_VALUES else None
        entry_errors: list[KeyEvidenceIssue] = []
        if entry_type is None:
            entry_errors.append(
                KeyEvidenceIssue(
                    KeyEvidenceError.UNKNOWN_TYPE,
                    f"entry at 0x{entry.offset:x} has unknown data type {raw_type}",
                )
            )

        key_range = None
        name = ""
        if header.data_offset >= 1:
            key_start = entry.offset + ENTRY_HEADER_SIZE
            key_end = key_start + header.data_offset - 1
            key_range = KeyDataRange(entry.table.offset + key_start, max(header.data_offset - 1, 0))
            key_bytes = entry.table.raw[key_start : min(key_end, len(entry.table.raw))].tobytes()
            name = _decode_key_name(key_bytes)

        parent_ref = None
        if header.parent_table_idx:
            parent_table = self.key_tables.get(header.parent_table_idx)
            if parent_table:
                parent_table = parent_table[0]
                parent_ref = KeyEntryRef(parent_table.index, parent_table.offset, header.parent_offset)
            else:
                parent_ref = KeyEntryRef(header.parent_table_idx, -1, header.parent_offset)

        value_range, value_errors = self._evidence_value_range(entry, entry_type, flags)
        entry_errors.extend(value_errors)
        entry_errors.extend(_fixed_type_size_errors(entry, entry_type))

        return HyperVKeyEvidence(
            ref=ref,
            name=name,
            type=entry_type,
            flags=flags,
            declared_size=entry.size,
            parent=parent_ref,
            key_range=key_range,
            value_range=value_range,
            entry_range=entry_range,
            value=UNPARSEABLE_VALUE,
            raw=raw,
            errors=entry_errors,
        )

    def _evidence_value_range(
        self, entry: HyperVStorageKeyTableEntry, entry_type: KeyDataType | None, flags: int
    ) -> tuple[KeyDataRange | None, list[KeyEvidenceIssue]]:
        errors: list[KeyEvidenceIssue] = []
        header = entry.header
        table_raw = entry.table.raw

        if entry_type == KeyDataType.Free or entry_type is None:
            return None, errors

        if flags & KeyDataFlag.FileObjectPointer:
            pointer_offset = entry.offset + ENTRY_HEADER_SIZE + header.data_offset
            if pointer_offset + 12 > len(table_raw):
                errors.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.VALUE_OUT_OF_BOUNDS,
                        f"file object pointer of entry at 0x{entry.offset:x} reaches past the key table",
                    )
                )
                return KeyDataRange(-1, -1, external=True), errors

            pointer_size, pointer_file_offset = struct.unpack("<IQ", table_raw[pointer_offset : pointer_offset + 12])
            data_range = KeyDataRange(pointer_file_offset, pointer_size, external=True)

            if pointer_file_offset + pointer_size > self._file_size:
                errors.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.POINTER_OUT_OF_BOUNDS,
                        f"file object pointer 0x{pointer_file_offset:x}+0x{pointer_size:x} "
                        f"reaches past the end of the file (0x{self._file_size:x})",
                    )
                )
            if pointer_file_offset not in self.file_objects:
                errors.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.UNKNOWN_FILE_OBJECT,
                        f"file object pointer references no file object at 0x{pointer_file_offset:x}",
                    )
                )
            return data_range, errors

        value_offset = entry.offset + ENTRY_HEADER_SIZE + header.data_offset
        value_length = _inline_value_length(entry, entry_type)
        if value_length < 0:
            errors.append(
                KeyEvidenceIssue(
                    KeyEvidenceError.TYPE_LENGTH_MISMATCH,
                    f"entry at 0x{entry.offset:x} of type {entry_type.name} has no room for its length prefix",
                )
            )
            return KeyDataRange(entry.table.offset + value_offset, value_length), errors

        # Strings and arrays store a uint32 content-length prefix immediately before the payload.
        if entry_type in (KeyDataType.String, KeyDataType.Array):
            value_offset += 4

        if value_offset < 0 or value_offset + value_length > len(table_raw):
            errors.append(
                KeyEvidenceIssue(
                    KeyEvidenceError.VALUE_OUT_OF_BOUNDS,
                    f"value of entry at 0x{entry.offset:x} reaches past the key table "
                    f"(needs 0x{value_offset + value_length:x}, table is 0x{len(table_raw):x})",
                )
            )
        return KeyDataRange(entry.table.offset + value_offset, value_length), errors

    def _resolve_evidence_parents(self, records: list[HyperVKeyEvidence]) -> None:
        by_ref = {record.ref: record for record in records}
        for record in records:
            if record.parent is None or record.type == KeyDataType.Free:
                continue

            parent_ref = record.parent
            if parent_ref.table_offset == -1:
                record.errors.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.MISSING_PARENT_TABLE,
                        f"entry {record.name!r} references missing parent table {parent_ref.table_index}",
                    )
                )
                record.linked = False
                continue

            parent = by_ref.get(parent_ref)
            if parent is None:
                record.errors.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.MISSING_PARENT_ENTRY,
                        f"entry {record.name!r} references missing parent {parent_ref}",
                    )
                )
                record.linked = False
                continue

            if parent.type != KeyDataType.Node:
                parent_type = parent.type.name if parent.type is not None else "unknown"
                record.errors.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.TYPE_LENGTH_MISMATCH,
                        f"entry {record.name!r} has a parent of type {parent_type} instead of Node",
                    )
                )
                record.linked = False

    def _detect_parent_cycles(self, records: list[HyperVKeyEvidence]) -> None:
        by_ref = {record.ref: record for record in records}
        for record in records:
            if record.type == KeyDataType.Free:
                continue

            seen: set[KeyEntryRef] = set()
            current = record
            while current is not None and current.parent is not None:
                if current.ref in seen:
                    record.errors.append(
                        KeyEvidenceIssue(
                            KeyEvidenceError.PARENT_CYCLE,
                            f"parent chain of entry {record.name!r} loops back through {current.ref}",
                        )
                    )
                    record.linked = False
                    break
                seen.add(current.ref)
                current = by_ref.get(current.parent)

    def _decode_evidence_values(self, view: HyperVEvidenceView, file_size: int) -> None:
        for record in view.records:
            if record.type in (None, KeyDataType.Free) or record.value_range is None:
                continue
            if record.type == KeyDataType.Node:
                record.value = None
                continue

            data = record.value_range.read(self.fh, file_size)
            if (
                record.value_range.length > len(data)
                or KeyEvidenceError.VALUE_OUT_OF_BOUNDS in record.issue_codes()
                or KeyEvidenceError.POINTER_OUT_OF_BOUNDS in record.issue_codes()
                or KeyEvidenceError.UNKNOWN_FILE_OBJECT in record.issue_codes()
            ):
                record.value = UNPARSEABLE_VALUE
                continue

            try:
                record.value = _decode_typed_value(record.type, data)
            except (struct.error, UnicodeDecodeError, ValueError):
                record.errors.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.TYPE_LENGTH_MISMATCH,
                        f"value bytes of entry {record.name!r} do not decode as {record.type.name}",
                    )
                )
                record.value = UNPARSEABLE_VALUE

    def _build_convenience_tree(self) -> dict[str, HyperVStorageKeyTableEntry]:
        sound_refs = {
            record.ref
            for record in self.evidence.records
            if record.linked and not record.has_errors and record.type != KeyDataType.Free
        }

        root: dict[str, HyperVStorageKeyTableEntry] = {}
        for key_tables in self.key_tables.values():
            active_table = key_tables[0]
            for entry in active_table.entries:
                ref = KeyEntryRef(active_table.index, active_table.offset, entry.offset)
                if ref not in sound_refs:
                    # A malformed entry never replaces an already linked valid entry.
                    continue

                parent = entry.parent
                if parent is None:
                    root[entry.key] = entry
                    continue

                parent_ref = KeyEntryRef(parent.table.index, parent.table.offset, parent.offset)
                if parent_ref not in sound_refs:
                    continue
                # Sound duplicate names keep the historical overwrite semantics; the evidence view
                # retains every sibling separately.
                parent.children[entry.key] = entry

        return root

    def __getitem__(self, key: str) -> HyperVStorageKeyTableEntry:
        return self.root[key]

    def keys(self) -> KeysView[str]:
        return self.root.keys()

    def items(self) -> ItemsView[str, HyperVStorageKeyTableEntry]:
        return self.root.items()

    def values(self) -> ValuesView[HyperVStorageKeyTableEntry]:
        return self.root.values()

    def evidence_view(self) -> HyperVEvidenceView:
        """Return the raw key evidence for the complete file.

        Unlike :meth:`as_dict` and the mapping-style helpers, this view keeps every entry with its
        physical identity, reports structural errors explicitly, and exposes the original byte ranges
        of both inline and external file object data.
        """
        return self.evidence

    def as_dict(self) -> dict:
        """Return a nested dictionary of the sound portion of the key tree.

        This is the convenience interface and intentionally hides evidence details:

        - Only entries without structural errors that resolve to a node are included.
        - Valid entries sharing a key name keep the historical overwrite semantics, so the last valid
          entry wins; a malformed entry can never overwrite a valid entry with the same name.
        - Use :meth:`evidence_view` to inspect every duplicate-name sibling, error records and raw bytes.
        """
        obj = {}

        for key, entry in self.root.items():
            obj[key] = entry.as_dict()

        return obj

    @property
    def version(self) -> int:
        return self.header.version

    def _align(self, offset: int) -> int:
        remainder = offset % self.header.alignment
        if remainder == 0:
            return offset
        return offset + self.header.alignment - remainder


class HyperVStorageReplayLog:
    """The replay log tracks changes in the file.

    Old changes are actually still resident in the log, but not counted in the ``num_entries`` field.
    """

    def __init__(self, hyperv_file: HyperVFile, offset: int):
        self.file = hyperv_file
        self.offset = offset

        self.file.fh.seek(offset)
        self.header = c_hyperv.HyperVStorageReplayLog(self.file.fh)

        if self.header.signature != c_hyperv.SIGNATURE_REPLAY_LOG_HEADER:
            raise InvalidSignature(f"Invalid replay log signature: 0x{self.header.signature:x}")

        self.entries = c_hyperv.HyperVStorageReplayLogEntry[self.header.num_entries](self.file.fh)


class HyperVStorageObjectTable:
    """The object table tracks all "objects".

    Objects are specific blocks in the file that have been designated a specific type.
    For example, the object table can list one or more key tables.
    """

    def __init__(self, hyperv_file: HyperVFile, offset: int):
        self.file = hyperv_file
        self.offset = offset

        self.file.fh.seek(offset)
        self.header = c_hyperv.HyperVStorageObjectTable(self.file.fh)

        if self.header.signature != c_hyperv.SIGNATURE_OBJECT_TABLE_HEADER:
            raise InvalidSignature(f"Invalid object table signature: 0x{self.header.signature:x}")

        self.entries = c_hyperv.HyperVStorageObjectTableEntry[self.header.num_entries](self.file.fh)


class HyperVStorageKeyTable:
    """The key table stores key value pairs and their relation to parent keys.

    A table has a specific table index and one or more key entries.
    """

    def __init__(self, hyperv_file: HyperVFile, offset: int, size: int):
        self.file = hyperv_file
        self.offset = offset
        self.size = size

        fh = self.file.fh
        fh.seek(offset)
        self.raw = memoryview(fh.read(size))

        # Only a short read from the file itself is truncation; zero padding inside a fully present
        # aligned object is a normal part of the layout.
        self.truncated = len(self.raw) < size
        self.invalid_signature = False
        table_header_size = len(c_hyperv.HyperVStorageKeyTable)
        if len(self.raw) < table_header_size:
            # Can't parse a header; record an empty placeholder so the evidence view can still report
            # the truncated table instead of failing the whole file.
            self.header = c_hyperv.HyperVStorageKeyTable(b"\x00" * table_header_size)
            self.truncated = True
        else:
            self.header = c_hyperv.HyperVStorageKeyTable(self.raw)

        if self.header.signature != c_hyperv.SIGNATURE_KEY_TABLE_HEADER:
            self.invalid_signature = True
        self.entries: list[HyperVStorageKeyTableEntry] = []
        self._lookup: dict[int, HyperVStorageKeyTableEntry] = {}
        self.scan_errors: list[KeyEvidenceIssue] = []

        for entry, issues in self.scan_entries():
            self.scan_errors.extend(issues)
            if entry is not None:
                self.entries.append(entry)
                self._lookup[entry.offset] = entry

    def scan_entries(self) -> list[tuple[HyperVStorageKeyTableEntry | None, list[KeyEvidenceIssue]]]:
        """Walk the entry region without raising on corrupt or truncated data.

        Each result pairs an entry (``None`` when even the header is unreadable) with the structural
        issues encountered at that position. Entries before a corrupt entry are returned on their own,
        so a bad declaration can never absorb a neighbouring value into its result.
        """
        results: list[tuple[HyperVStorageKeyTableEntry | None, list[KeyEvidenceIssue]]] = []
        entry_offset = len(c_hyperv.HyperVStorageKeyTable)

        while entry_offset < len(self.raw):
            issues: list[KeyEvidenceIssue] = []

            if entry_offset + ENTRY_HEADER_SIZE > len(self.raw):
                issues.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.TRUNCATED_ENTRY_HEADER,
                        f"entry header at 0x{entry_offset:x} in table {self.index} is incomplete",
                    )
                )
                results.append((None, issues))
                break

            entry = HyperVStorageKeyTableEntry(self, entry_offset)
            if entry.size == 0:
                # Zero-sized markers and zero padding terminate the populated region.
                break

            if entry.size < ENTRY_HEADER_SIZE:
                issues.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.INVALID_ENTRY_SIZE,
                        f"entry at 0x{entry_offset:x} declares size {entry.size}, "
                        f"smaller than the {ENTRY_HEADER_SIZE}-byte header",
                    )
                )
                results.append((entry, issues))
                break

            if entry_offset + entry.size > len(self.raw):
                issues.append(
                    KeyEvidenceIssue(
                        KeyEvidenceError.TRUNCATED_ENTRY,
                        f"entry at 0x{entry_offset:x} declares size {entry.size} but only "
                        f"{len(self.raw) - entry_offset} bytes remain in table {self.index}",
                    )
                )
                results.append((entry, issues))
                # Entries are laid out contiguously, so after an overlong declaration no following
                # offset can be trusted. The corrupt entry is still returned on its own.
                break

            results.append((entry, issues))
            entry_offset += entry.size

        return results

    @property
    def index(self) -> int:
        """Return the table index."""
        return self.header.index

    @property
    def sequence_number(self) -> int:
        """Return the table sequence number."""
        return self.header.sequence_number


class HyperVStorageKeyTableEntry:
    """Entry in a key table.

    The first 16 bytes are a combined flag and type field. The high 8 bits are flags, the low 8 bits are type.

    Only one flag is currently known, which we've called ``FileObjectPointer``. It's the lowest bit of the flag bits.
    If this flag is set, it means the value of this entry is located in a file object. File objects pointers are
    12 bytes and consist of a ``uint32`` size and a ``uint64`` offset value. The offset is the absolute offset into the
    file. This method is similar to how parent keys are referenced.

    Values are stored in a file object if their size >= ``0x800``. As only strings and "arrays" are of variable size,
    these are the only data types that can be stored in file objects.

    Data type summary:

    - ``KeyDataType.Free``:
        - Allocated but free.

    - ``KeyDataType.Unknown``:
        - Unknown entry type. Anything greater than 9 and exactly 2 is unknown.

    - ``KeyDataType.Int``:
        - Signed 64 bit integer.

    - ``KeyDataType.UInt``:
        - Unsigned 64 bit integer.

    - ``KeyDataType.Double``:
        - 64 bit double.

    - ``KeyDataType.String``:
        - UTF-16-LE encoded string

    - ``KeyDataType.Array``:
        - Bytes?

    - ``KeyDataType.Bool``:
        - Boolean encoded as 32 bit integer.

    - ``KeyDataType.Node``:
        - Tree nodes. Value size is coded as 8, but actual size is 12.
        - First 8 bytes are unknown, but latter 4 bytes is the insertion sequence number.
    """

    def __init__(self, table: HyperVStorageKeyTable, offset: int):
        self.table = table
        self.offset = offset
        self.header = c_hyperv.HyperVStorageKeyTableEntryHeader(table.raw[offset:])
        self.children: dict[str, HyperVStorageKeyTableEntry] = {}

    def __getitem__(self, key: str) -> HyperVStorageKeyTableEntry:
        return self.children[key]

    def __repr__(self) -> str:
        return f"<HyperVStorageKeyTableEntry type={self.type} size={self.size} offset=0x{self.offset:x}>"

    @property
    def parent(self) -> HyperVStorageKeyTableEntry | None:
        """Return the entry parent, if there is any.

        Requires that all key tables are loaded. Returns ``None`` when the referenced parent table or
        entry does not exist; the evidence view records the structural error in that case.
        """
        if not self.header.parent_table_idx:
            return None

        parent_tables = self.table.file.key_tables.get(self.header.parent_table_idx)
        if not parent_tables:
            return None
        return parent_tables[0]._lookup.get(self.header.parent_offset)

    @property
    def flags(self) -> int:
        """Return the entry flags."""
        return (self.header.type & 0xFF00) >> 8

    @property
    def type(self) -> KeyDataType | None:
        """Return the entry type, or ``None`` when the type byte is unknown.

        Returning ``None`` instead of raising keeps malformed entries available through the evidence
        view; :attr:`HyperVKeyEvidence.errors` carries the corresponding :class:`KeyEvidenceError`.
        """
        raw_type = self.header.type & 0xFF
        if raw_type not in KEY_DATA_TYPE_VALUES:
            return None
        return KeyDataType(raw_type)

    @property
    def size(self) -> int:
        """Return the entry size."""
        return self.header.size

    @property
    def is_file_object_pointer(self) -> bool:
        """Return whether the value is a file object pointer."""
        return bool(KeyDataFlag(self.flags) & KeyDataFlag.FileObjectPointer)

    @property
    def file_object_pointer(self) -> tuple[int, int]:
        """Return the file object pointer information."""
        if not self.is_file_object_pointer:
            raise TypeError(f"KeyTableEntry is not a file object pointer: {self}")

        data = self.raw[self.header.data_offset :]
        size, offset = struct.unpack("<IQ", data[:12])
        # We swap the values since that is a bit more logical
        return offset, size

    @property
    def raw(self) -> memoryview:
        """Returns the raw data for this entry, clamped to the enclosing key table."""
        data_offset = self.offset + ENTRY_HEADER_SIZE
        end = min(self.offset + self.size, len(self.table.raw))
        return self.table.raw[data_offset:end]

    @property
    def data(self) -> memoryview:
        """Returns the data portion for this entry.

        Convenience accessor for sound entries only. Entries with out-of-bounds data are excluded from
        the convenience tree; use :meth:`HyperVFile.evidence_view` for bounded access to those bytes.
        """
        if self.is_file_object_pointer:
            _, size = self.file_object_pointer
            file_object = self.get_file_object()
            # This memoryview has no purpose, only do it so the return value type is consistent
            return memoryview(file_object.read(size))

        return self.raw[self.header.data_offset :]

    @property
    def key(self) -> str:
        """Returns the key name for this entry."""
        # Subtract 1 for the terminating null byte
        return _decode_key_name(self.raw.tobytes()[: self.header.data_offset - 1])

    @property
    def value(self) -> int | float | bool | bytes | str:
        """Return a Python native value for this entry.

        Only valid for sound entries reachable through the convenience mapping. Malformed entries are
        excluded there and should be consumed through :meth:`HyperVFile.evidence_view` instead.
        """
        data = self.data

        if self.type == KeyDataType.Int:
            return struct.unpack("<q", data[:8])[0]

        if self.type == KeyDataType.UInt:
            return struct.unpack("<Q", data[:8])[0]

        if self.type == KeyDataType.Double:
            return struct.unpack("<d", data[:8])[0]

        if self.type in (KeyDataType.String, KeyDataType.Array):
            if not self.is_file_object_pointer:
                data_len = struct.unpack("<I", data[:4])[0]
                data = data[4 : 4 + data_len]

            data = data.tobytes()
            if self.type == KeyDataType.String:
                return data.decode("utf-16-le")
            return data

        if self.type == KeyDataType.Bool:
            return struct.unpack("<I", data[:4])[0] != 0

        raise TypeError(f"Unknown data type: {self.type}")

    @property
    def data_size(self) -> int:
        """Return the total amount of data bytes, including the key name.

        Reference:
            - ``HyperVStorageKeyTableEntry::GetDataSizeInBytes``
        """
        if self.type == KeyDataType.Node:
            return self.header.data_offset + 12
        return self.header.data_offset + self.value_size

    @property
    def value_size(self) -> int:
        """Return the amount of bytes a value occupies.

        Reference:
            - ``HyperVStorageKeyTableEntry::GetValueSizeInBytes``
        """
        if self.type == KeyDataType.Free:
            return self.header.size - len(c_hyperv.HyperVStorageKeyTableEntryHeader)

        if self.is_file_object_pointer:
            return 12

        if self.type == KeyDataType.Node:
            # The code returns 8 here, but it's actually 12?
            # First 8 bytes is an unknown value, but the latter 4 bytes are an insertion sequence number
            return 8

        if self.type in (KeyDataType.String, KeyDataType.Array):
            return struct.unpack("<I", self.raw[self.header.data_offset : self.header.data_offset + 4])[0]

        if self.type in (KeyDataType.Int, KeyDataType.UInt):
            return 8

        if self.type == KeyDataType.Double:
            return 8

        if self.type == KeyDataType.Bool:
            return 4

        if self.type is None:
            raise TypeError(f"Unknown data type: {self.header.type & 0xFF}")

        raise TypeError(f"Unknown data type: {self.type}")

    def keys(self) -> KeysView[int]:
        return self.children.keys()

    def items(self) -> ItemsView[int, HyperVStorageKeyTableEntry]:
        return self.children.items()

    def values(self) -> ValuesView[HyperVStorageKeyTableEntry]:
        return self.children.values()

    def as_dict(self) -> dict:
        if self.type != KeyDataType.Node:
            raise TypeError(f"KeyTableEntry can't be dumped as dictionary: {self.type}")

        obj = {}
        for key, child in self.children.items():
            value = child.as_dict() if child.type == KeyDataType.Node else child.value

            obj[key] = value

        return obj

    def get_file_object(self) -> HyperVStorageFileObject:
        if not self.is_file_object_pointer:
            raise TypeError(f"Entry is not a file object pointer: {self}")

        offset, size = self.file_object_pointer
        file_object = self.table.file.file_objects.get(offset)
        if not file_object:
            raise ValueError(f"Unknown file object: 0x{offset:x} (0x{size:x})")

        return file_object


class HyperVStorageFileObject:
    """File object from the object table.

    File objects are referenced by their absolute offset in the file. The object table also stores
    a size, but this size will always be aligned with the data alignment of the Hyper-V file.
    The actual size of the data stored is located in the data portion of the ``HyperVStorageKeyTableEntry``
    that references that file object.
    """

    def __init__(self, hyperv_file: HyperVFile, offset: int, size: int):
        self.file = hyperv_file
        self.offset = offset
        self.size = size

    def read(self, n: int = -1) -> bytes:
        if n is not None and n < -1:
            raise ValueError("invalid number of bytes to read")

        read_length = self.size if n == -1 else min(n, self.size)

        self.file.fh.seek(self.offset)
        return self.file.fh.read(read_length)

    def open(self, size: int | None = None) -> BinaryIO:
        return RangeStream(self.file.fh, self.offset, size or self.size)


def _decode_key_name(key_bytes: bytes) -> str:
    try:
        return key_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return key_bytes.decode("utf-8", errors="replace")


def _inline_value_length(entry: HyperVStorageKeyTableEntry, entry_type: KeyDataType | None) -> int:
    """Return the inline value payload length in bytes, or ``-1`` when a length prefix can't be read."""
    header = entry.header
    prefix_offset = entry.offset + ENTRY_HEADER_SIZE + header.data_offset

    if entry_type == KeyDataType.Node:
        return 12
    if entry_type in (KeyDataType.Int, KeyDataType.UInt, KeyDataType.Double):
        return 8
    if entry_type == KeyDataType.Bool:
        return 4
    if entry_type in (KeyDataType.String, KeyDataType.Array):
        if prefix_offset + 4 > len(entry.table.raw):
            return -1
        return struct.unpack("<I", entry.table.raw[prefix_offset : prefix_offset + 4])[0]
    return -1


def _fixed_type_size_errors(
    entry: HyperVStorageKeyTableEntry, entry_type: KeyDataType | None
) -> list[KeyEvidenceIssue]:
    """Flag entries whose declared size can't contain their type, key and value.

    On-disk entries may carry trailing reserved or padding bytes, so a larger declared size is legal;
    only a size smaller than the required minimum is a type/length contradiction.
    """
    if entry_type in (None, KeyDataType.Free):
        return []

    header = entry.header
    if header.data_offset < 1:
        return [
            KeyEvidenceIssue(
                KeyEvidenceError.TYPE_LENGTH_MISMATCH,
                f"entry at 0x{entry.offset:x} has no room for its key name",
            )
        ]

    expected_value_size = _expected_value_size(entry, entry_type)
    if expected_value_size < 0:
        return []

    minimum_size = ENTRY_HEADER_SIZE + header.data_offset + expected_value_size
    if minimum_size > entry.size:
        return [
            KeyEvidenceIssue(
                KeyEvidenceError.TYPE_LENGTH_MISMATCH,
                f"entry at 0x{entry.offset:x} of type {entry_type.name} declares size {entry.size} "
                f"but needs at least {minimum_size} bytes for its type, key and value",
            )
        ]
    return []


def _expected_value_size(entry: HyperVStorageKeyTableEntry, entry_type: KeyDataType) -> int:
    """Return the on-disk bytes occupied by the value, including any inline length prefix."""
    if entry.is_file_object_pointer:
        return 12
    payload_length = _inline_value_length(entry, entry_type)
    if payload_length < 0:
        return -1
    if entry_type in (KeyDataType.String, KeyDataType.Array):
        return 4 + payload_length
    return payload_length


def _decode_typed_value(entry_type: KeyDataType, data: bytes) -> int | float | bool | bytes | str:
    if entry_type in (KeyDataType.Int, KeyDataType.UInt):
        return struct.unpack("<q" if entry_type == KeyDataType.Int else "<Q", data[:8])[0]
    if entry_type == KeyDataType.Double:
        return struct.unpack("<d", data[:8])[0]
    if entry_type == KeyDataType.Bool:
        return struct.unpack("<I", data[:4])[0] != 0
    if entry_type == KeyDataType.String:
        # Evidence ranges already exclude the 4-byte length prefix. An empty payload is a valid
        # empty string and must not raise on the UTF-16 decode.
        return data.decode("utf-16-le") if data else ""
    if entry_type == KeyDataType.Array:
        return data
    raise TypeError(f"Unsupported value type: {entry_type}")
