from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, FILE_NUMBER_VOLUME
from dissect.ntfs.exceptions import (
    Error,
    FileNotFoundError,
    MftNotAvailableError,
    NotADirectoryError,
    VolumeNotAvailableError,
)
from dissect.ntfs.index import Index

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.ntfs.attr import ObjectId as ObjectIdAttribute
    from dissect.ntfs.index import IndexEntry
    from dissect.ntfs.mft import MftRecord
    from dissect.ntfs.ntfs import NTFS


class ObjectIdStatus(str, Enum):
    """Outcome of comparing one ``$OBJECT_ID`` attribute with the ``$ObjId:$O`` index."""

    CONSISTENT = "consistent"
    CONFLICT = "conflict"
    INSUFFICIENT = "insufficient"

    # Aliases so callers can use the terminology that fits their report.
    MATCH = "consistent"
    MISMATCH = "conflict"
    INSUFFICIENT_EVIDENCE = "insufficient"


@dataclass(frozen=True)
class Guid:
    """A GUID that keeps both the raw on-disk bytes and the usual display form."""

    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) != 16:
            raise ValueError(f"GUID must be 16 bytes, got {len(self.raw)}")
        object.__setattr__(self, "raw", bytes(self.raw))

    @classmethod
    def from_value(cls, value: Guid | UUID | str | bytes | bytearray | memoryview) -> Guid:
        """Normalize a UUID, string, or raw byte value to a :class:`Guid`."""
        if isinstance(value, cls):
            return value
        if isinstance(value, UUID):
            return cls(value.bytes_le)
        if isinstance(value, str):
            return cls(UUID(value).bytes_le)
        if isinstance(value, bytes | bytearray | memoryview):
            value = bytes(value)
            if len(value) == 16:
                return cls(value)
            raise ValueError(f"GUID must be 16 bytes, got {len(value)}")
        raise TypeError(f"Invalid GUID value: {value!r}")

    @classmethod
    def from_optional(cls, value: bytes | None) -> Guid | None:
        """Return ``None`` for empty or truncated GUID fields, otherwise a :class:`Guid`."""
        if not value or len(value) != 16 or not any(value):
            return None
        return cls(value)

    @property
    def uuid(self) -> UUID:
        """Return the parsed UUID."""
        return UUID(bytes_le=self.raw)

    @property
    def display(self) -> str:
        """Return the canonical GUID string."""
        return str(self.uuid)

    @property
    def hex(self) -> str:
        """Return the raw on-disk bytes as hexadecimal."""
        return self.raw.hex()

    def __str__(self) -> str:
        return self.display

    def __repr__(self) -> str:
        return f"Guid(raw={self.hex!r}, display={self.display!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Guid):
            return self.raw == other.raw
        if isinstance(other, UUID):
            return self.uuid == other
        if isinstance(other, str):
            return self.display.lower() == other.lower()
        if isinstance(other, bytes | bytearray | memoryview):
            return self.raw == bytes(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.raw)

    def to_dict(self) -> dict[str, str]:
        """Return the raw and display forms for serialization."""
        return {"raw": self.hex, "display": self.display}


@dataclass(frozen=True)
class ObjectIdEvidence:
    """A concrete attribute or index entry that a report conclusion is based on."""

    source: str
    record_segment: int | None
    record_sequence: int | None
    raw: bytes
    object_id: Guid | None
    birth_volume_id: Guid | None = None
    birth_object_id: Guid | None = None
    domain_id: Guid | None = None
    key_raw: bytes = b""
    index_record_segment: int | None = None
    index_offset: int | None = None
    index_vcn: int | None = None
    attribute_type: str | None = None
    attribute_name: str | None = None

    @classmethod
    def from_attribute(cls, attr: ObjectIdAttribute) -> ObjectIdEvidence:
        """Create evidence from a parsed ``$OBJECT_ID`` attribute."""
        record = attr.record
        return cls(
            source="attribute",
            record_segment=record.segment if record else None,
            record_sequence=record.header.SequenceNumber if record and record.header else None,
            raw=attr.raw,
            object_id=Guid.from_optional(attr.object_id_raw),
            birth_volume_id=Guid.from_optional(attr.birth_volume_id_raw),
            birth_object_id=Guid.from_optional(attr.birth_object_id_raw),
            domain_id=Guid.from_optional(attr.domain_id_raw),
            attribute_type="OBJECT_ID",
            attribute_name=attr.header.name,
        )

    @classmethod
    def from_index_entry(cls, entry: ObjectIdIndexEntry) -> ObjectIdEvidence:
        """Create evidence from a parsed ``$ObjId:$O`` index entry."""
        return cls(
            source="index_entry",
            record_segment=entry.file_reference_segment,
            record_sequence=entry.file_reference_sequence,
            raw=entry.data_raw,
            object_id=entry.object_id,
            birth_volume_id=entry.birth_volume_id,
            birth_object_id=entry.birth_object_id,
            domain_id=entry.domain_id,
            key_raw=entry.key_raw,
            index_record_segment=entry.index_record_segment,
            index_offset=entry.index_offset,
            index_vcn=entry.index_vcn,
            attribute_type="OBJECT_ID",
        )

    def describe(self) -> str:
        """Return a human readable trace of this evidence."""
        if self.source == "attribute":
            return f"$OBJECT_ID attribute in MFT record {self.record_segment}#{self.record_sequence}"

        location = f"offset {self.index_offset}" if self.index_offset is not None else "unknown offset"
        if self.index_vcn is not None:
            location += f", VCN {self.index_vcn}"
        return (
            f"$ObjId:$O index entry at {location} in MFT record {self.index_record_segment}, "
            f"file reference {self.record_segment}#{self.record_sequence}"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable representation of this evidence."""
        return {
            "source": self.source,
            "description": self.describe(),
            "record_segment": self.record_segment,
            "record_sequence": self.record_sequence,
            "raw": self.raw.hex(),
            "key_raw": self.key_raw.hex(),
            "object_id": self.object_id.to_dict() if self.object_id else None,
            "birth_volume_id": self.birth_volume_id.to_dict() if self.birth_volume_id else None,
            "birth_object_id": self.birth_object_id.to_dict() if self.birth_object_id else None,
            "domain_id": self.domain_id.to_dict() if self.domain_id else None,
            "index_record_segment": self.index_record_segment,
            "index_offset": self.index_offset,
            "index_vcn": self.index_vcn,
            "attribute_type": self.attribute_type,
            "attribute_name": self.attribute_name,
        }


@dataclass(frozen=True)
class ObjectIdIndexEntry:
    """A parsed entry from the volume-level ``$ObjId:$O`` index."""

    key_raw: bytes
    data_raw: bytes
    index_offset: int
    index_vcn: int | None = None
    index_record_segment: int | None = None

    @classmethod
    def from_index_entry(cls, entry: IndexEntry, index_record: MftRecord) -> ObjectIdIndexEntry:
        """Parse an :class:`~dissect.ntfs.index.IndexEntry` into an object ID index entry."""
        return cls(
            key_raw=entry.key,
            data_raw=entry.data,
            index_offset=entry.offset,
            index_vcn=getattr(entry, "vcn", None),
            index_record_segment=index_record.segment,
        )

    @property
    def object_id(self) -> Guid | None:
        """Return the current object ID stored in the index key."""
        return Guid.from_optional(self.key_raw) if len(self.key_raw) == 16 else None

    @property
    def file_reference_segment(self) -> int | None:
        """Return the segment number of the referenced MFT record."""
        if len(self.data_raw) < 8:
            return None
        low, high, _ = struct.unpack_from("<IHH", self.data_raw)
        return low | (high << 32)

    @property
    def file_reference_sequence(self) -> int | None:
        """Return the sequence number (record generation) of the referenced MFT record."""
        if len(self.data_raw) < 8:
            return None
        return struct.unpack_from("<H", self.data_raw, 6)[0]

    @property
    def has_birth_information(self) -> bool:
        """Return whether the index data carries the full birth and domain fields."""
        return len(self.data_raw) >= 56

    @property
    def birth_volume_id(self) -> Guid | None:
        """Return the birth volume GUID from the index data, if present."""
        return Guid.from_optional(self.data_raw[8:24]) if self.has_birth_information else None

    @property
    def birth_object_id(self) -> Guid | None:
        """Return the birth object GUID from the index data, if present."""
        return Guid.from_optional(self.data_raw[24:40]) if self.has_birth_information else None

    @property
    def domain_id(self) -> Guid | None:
        """Return the domain GUID from the index data, if present."""
        return Guid.from_optional(self.data_raw[40:56]) if self.has_birth_information else None

    @property
    def evidence(self) -> ObjectIdEvidence:
        """Return this entry as traceable evidence."""
        return ObjectIdEvidence.from_index_entry(self)

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable representation of this entry."""
        return self.evidence.to_dict()


@dataclass(frozen=True)
class ObjectIdReport:
    """Read-only comparison of a file ``$OBJECT_ID`` attribute and the volume ``$ObjId`` index."""

    status: ObjectIdStatus
    record_segment: int | None
    record_sequence: int | None
    current_object_id: Guid | None
    birth_volume_id: Guid | None = None
    birth_object_id: Guid | None = None
    domain_id: Guid | None = None
    attribute: ObjectIdEvidence | None = None
    index_entries: tuple[ObjectIdEvidence, ...] = ()
    reasons: tuple[str, ...] = ()
    current_identity_status: ObjectIdStatus = ObjectIdStatus.INSUFFICIENT
    birth_identity_status: ObjectIdStatus = ObjectIdStatus.INSUFFICIENT
    cross_volume_move: bool | None = None
    current_volume_id: Guid | None = None

    @property
    def index_entry(self) -> ObjectIdEvidence | None:
        """Return the single matching index entry, if there is exactly one."""
        return self.index_entries[0] if len(self.index_entries) == 1 else None

    @property
    def evidence(self) -> tuple[ObjectIdEvidence, ...]:
        """Return all evidence that contributes to this report."""
        return ((self.attribute,) if self.attribute else ()) + self.index_entries

    @property
    def is_consistent(self) -> bool:
        """Return whether the attribute and index are consistent."""
        return self.status == ObjectIdStatus.CONSISTENT

    @property
    def is_conflict(self) -> bool:
        """Return whether the attribute and index conflict."""
        return self.status == ObjectIdStatus.CONFLICT

    @property
    def is_insufficient(self) -> bool:
        """Return whether there is not enough evidence for a conclusion."""
        return self.status == ObjectIdStatus.INSUFFICIENT

    @property
    def identity_status(self) -> ObjectIdStatus:
        """Return the status of the current object identity."""
        return self.current_identity_status

    @property
    def proven_cross_volume_move(self) -> bool:
        """Return whether the report proves a cross-volume move."""
        return self.cross_volume_move is True

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable representation of the report."""
        return {
            "status": self.status.value,
            "current_identity_status": self.current_identity_status.value,
            "birth_identity_status": self.birth_identity_status.value,
            "record_segment": self.record_segment,
            "record_sequence": self.record_sequence,
            "current_object_id": self.current_object_id.to_dict() if self.current_object_id else None,
            "birth_volume_id": self.birth_volume_id.to_dict() if self.birth_volume_id else None,
            "birth_object_id": self.birth_object_id.to_dict() if self.birth_object_id else None,
            "domain_id": self.domain_id.to_dict() if self.domain_id else None,
            "current_volume_id": self.current_volume_id.to_dict() if self.current_volume_id else None,
            "cross_volume_move": self.cross_volume_move,
            "reasons": list(self.reasons),
            "attribute": self.attribute.to_dict() if self.attribute else None,
            "index_entries": [entry.to_dict() for entry in self.index_entries],
        }

    @classmethod
    def from_record(
        cls,
        record: MftRecord,
        index: ObjectIdIndex | None = None,
        *,
        entries: Iterable[ObjectIdIndexEntry] | None = None,
        current_volume_id: Guid | UUID | str | bytes | None = None,
        record_segment: int | None = None,
        record_sequence: int | None = None,
    ) -> ObjectIdReport:
        """Build a report for a single MFT record.

        Args:
            record: The file record to inspect.
            index: Optional volume-level ``$ObjId:$O`` index. If omitted, ``entries`` can be supplied directly.
            entries: Optional pre-selected index entries, useful when the index cannot be opened through an MFT.
            current_volume_id: Optional GUID of the volume the record resides on, used to prove cross-volume moves.
            record_segment: Optional override for the record's segment number.
            record_sequence: Optional override for the record's sequence number.

        Returns:
            A read-only :class:`ObjectIdReport`.
        """
        record_segment = record_segment if record_segment is not None else record.segment
        record_sequence = (
            record_sequence
            if record_sequence is not None
            else (record.header.SequenceNumber if record.header else None)
        )
        current_volume = Guid.from_value(current_volume_id) if current_volume_id is not None else None

        attrs = list(record.attributes[ATTRIBUTE_TYPE_CODE.OBJECT_ID])
        if not attrs:
            return cls(
                status=ObjectIdStatus.INSUFFICIENT,
                record_segment=record_segment,
                record_sequence=record_sequence,
                current_object_id=None,
                index_entries=tuple(entry.evidence for entry in entries or ()),
                reasons=("missing_object_id_attribute",),
                current_volume_id=current_volume,
            )

        attribute_evidence = ObjectIdEvidence.from_attribute(attrs[0])
        current_object_id = attribute_evidence.object_id
        reasons: list[str] = []

        if len(attrs) > 1:
            reasons.append("multiple_object_id_attributes")

        if current_object_id is None:
            return cls(
                status=ObjectIdStatus.INSUFFICIENT,
                record_segment=record_segment,
                record_sequence=record_sequence,
                current_object_id=None,
                attribute=attribute_evidence,
                reasons=(*reasons, "missing_current_object_id"),
                current_volume_id=current_volume,
            )

        if entries is not None:
            index_entries = list(entries)
            index_available = True
        elif index is not None:
            index_entries = index.lookup(current_object_id)
            index_available = True
        else:
            index_entries = []
            index_available = False

        index_evidence = tuple(entry.evidence for entry in index_entries)

        if not index_entries:
            reason = "missing_index_entry" if index_available else "missing_objid_index"
            return cls(
                status=ObjectIdStatus.INSUFFICIENT,
                record_segment=record_segment,
                record_sequence=record_sequence,
                current_object_id=current_object_id,
                birth_volume_id=attribute_evidence.birth_volume_id,
                birth_object_id=attribute_evidence.birth_object_id,
                domain_id=attribute_evidence.domain_id,
                attribute=attribute_evidence,
                index_entries=(),
                reasons=(*reasons, reason),
                current_volume_id=current_volume,
            )

        entry = index_entries[0]
        current_reasons: list[str] = []

        if len(index_entries) > 1:
            current_reasons.append("duplicate_index_entries")

        if entry.object_id != current_object_id:
            current_reasons.append("index_object_id_mismatch")

        if record_segment is None or entry.file_reference_segment is None:
            current_reasons.append("unverifiable_file_reference")
        elif entry.file_reference_segment != record_segment:
            current_reasons.append("file_reference_segment_mismatch")

        if record_sequence is None or entry.file_reference_sequence is None:
            current_reasons.append("unverifiable_record_generation")
        elif entry.file_reference_sequence != record_sequence:
            current_reasons.append("file_reference_sequence_mismatch")

        current_identity_status = ObjectIdStatus.CONFLICT if current_reasons else ObjectIdStatus.CONSISTENT

        birth_reasons: list[str] = []
        birth_comparable = True

        birth_comparable &= _compare_birth_field(
            attribute_evidence.birth_volume_id,
            entry.birth_volume_id,
            "birth_volume_id",
            birth_reasons,
            required=True,
        )
        birth_comparable &= _compare_birth_field(
            attribute_evidence.birth_object_id,
            entry.birth_object_id,
            "birth_object_id",
            birth_reasons,
            required=True,
        )
        # The domain ID is optional on non-domain-joined volumes. Compare it if both sides carry one,
        # but don't reject an otherwise complete birth identity just because it is absent.
        _compare_birth_field(
            attribute_evidence.domain_id,
            entry.domain_id,
            "domain_id",
            birth_reasons,
            required=False,
        )

        if any(reason.endswith("_mismatch") for reason in birth_reasons):
            birth_identity_status = ObjectIdStatus.CONFLICT
        elif birth_comparable:
            birth_identity_status = ObjectIdStatus.CONSISTENT
        else:
            birth_identity_status = ObjectIdStatus.INSUFFICIENT

        reasons.extend(current_reasons)
        reasons.extend(birth_reasons)

        if current_identity_status == ObjectIdStatus.CONFLICT or birth_identity_status == ObjectIdStatus.CONFLICT:
            status = ObjectIdStatus.CONFLICT
        elif (
            current_identity_status == ObjectIdStatus.INSUFFICIENT
            or birth_identity_status == ObjectIdStatus.INSUFFICIENT
        ):
            status = ObjectIdStatus.INSUFFICIENT
        else:
            status = ObjectIdStatus.CONSISTENT

        cross_volume_move = None
        if status == ObjectIdStatus.CONSISTENT:
            if current_volume is None:
                reasons.append("current_volume_id_unavailable")
            elif attribute_evidence.birth_volume_id == current_volume:
                cross_volume_move = False
            else:
                cross_volume_move = True

        return cls(
            status=status,
            record_segment=record_segment,
            record_sequence=record_sequence,
            current_object_id=current_object_id,
            birth_volume_id=attribute_evidence.birth_volume_id,
            birth_object_id=attribute_evidence.birth_object_id,
            domain_id=attribute_evidence.domain_id,
            attribute=attribute_evidence,
            index_entries=index_evidence,
            reasons=tuple(reasons),
            current_identity_status=current_identity_status,
            birth_identity_status=birth_identity_status,
            cross_volume_move=cross_volume_move,
            current_volume_id=current_volume,
        )

    @classmethod
    def from_index_entry(
        cls,
        entry: ObjectIdIndexEntry,
        *,
        record: MftRecord | None = None,
        current_volume_id: Guid | UUID | str | bytes | None = None,
    ) -> ObjectIdReport:
        """Build a report starting from a single index entry.

        This is useful for stale or orphaned index entries whose target record is no longer the file
        described by the entry. If ``record`` is omitted, the report is insufficient.
        """
        if not isinstance(entry, ObjectIdIndexEntry):
            raise TypeError(f"Invalid object ID index entry: {entry!r}")

        current_volume = Guid.from_value(current_volume_id) if current_volume_id is not None else None

        if entry.object_id is None:
            return cls(
                status=ObjectIdStatus.INSUFFICIENT,
                record_segment=None,
                record_sequence=None,
                current_object_id=None,
                birth_volume_id=entry.birth_volume_id,
                birth_object_id=entry.birth_object_id,
                domain_id=entry.domain_id,
                index_entries=(entry.evidence,),
                reasons=("missing_index_object_id",),
                current_volume_id=current_volume,
            )

        if record is None:
            return cls(
                status=ObjectIdStatus.INSUFFICIENT,
                record_segment=None,
                record_sequence=None,
                current_object_id=entry.object_id,
                birth_volume_id=entry.birth_volume_id,
                birth_object_id=entry.birth_object_id,
                domain_id=entry.domain_id,
                index_entries=(entry.evidence,),
                reasons=("missing_file_record",),
                current_volume_id=current_volume,
            )

        return cls.from_record(
            record,
            entries=(entry,),
            current_volume_id=current_volume_id,
        )


class ObjectIdIndex:
    """Read-only wrapper around the volume-level ``$ObjId:$O`` index.

    Args:
        record: The MFT record of the ``$ObjId`` file, or an already opened :class:`~dissect.ntfs.index.Index`.
        name: The index name to open. Defaults to ``$O``.
    """

    def __init__(self, record: MftRecord | Index, name: str = "$O"):
        if isinstance(record, Index):
            self.index = record
            self.record = record.record
        else:
            self.record = record
            self.index = record.index(name)

        self._entries: tuple[ObjectIdIndexEntry, ...] | None = None

    @classmethod
    def from_ntfs(cls, ntfs: NTFS) -> ObjectIdIndex | None:
        """Return the volume's ``$ObjId`` index, or ``None`` if it is not available."""
        if not ntfs or not ntfs.mft:
            return None

        try:
            return cls(ntfs.mft.get("$Extend\\$ObjId"))
        except (Error, FileNotFoundError, MftNotAvailableError, NotADirectoryError, VolumeNotAvailableError):
            return None

    @property
    def volume_id(self) -> Guid | None:
        """Return the volume's own object ID if one can be read from ``$Volume``."""
        return _volume_id(self.record)

    def entries(self) -> Iterator[ObjectIdIndexEntry]:
        """Yield all parsable entries from the index."""
        if self._entries is None:
            self._entries = tuple(
                ObjectIdIndexEntry.from_index_entry(entry, self.record)
                for entry in self.index.entries()
                if not entry.is_end
            )

        yield from self._entries

    def lookup(self, object_id: Guid | UUID | str | bytes) -> list[ObjectIdIndexEntry]:
        """Return all index entries whose key matches ``object_id``."""
        if isinstance(object_id, UUID | str | bytes | bytearray | memoryview):
            object_id = Guid.from_value(object_id)
        elif not isinstance(object_id, Guid):
            raise TypeError(f"Invalid object ID: {object_id!r}")

        return [entry for entry in self.entries() if entry.key_raw == object_id.raw]

    def report(
        self,
        record: MftRecord,
        *,
        current_volume_id: Guid | UUID | str | bytes | None = None,
    ) -> ObjectIdReport:
        """Build a report for ``record`` using this index."""
        if current_volume_id is None:
            current_volume_id = self.volume_id
        return ObjectIdReport.from_record(record, index=self, current_volume_id=current_volume_id)

    def report_path(
        self,
        path: str,
        *,
        current_volume_id: Guid | UUID | str | bytes | None = None,
    ) -> ObjectIdReport:
        """Resolve ``path`` through the MFT and build a report for it."""
        ntfs = self.record.ntfs
        if not ntfs or not ntfs.mft:
            raise MftNotAvailableError

        return self.report(ntfs.mft.get(path), current_volume_id=current_volume_id)

    def report_entry(
        self,
        entry: ObjectIdIndexEntry,
        *,
        current_volume_id: Guid | UUID | str | bytes | None = None,
    ) -> ObjectIdReport:
        """Build a report for a single index entry, resolving its target record if possible."""
        if current_volume_id is None:
            current_volume_id = self.volume_id

        record = None
        segment = entry.file_reference_segment
        ntfs = self.record.ntfs
        if segment is not None and ntfs and ntfs.mft:
            try:
                record = ntfs.mft.get(segment)
            except (Error, EOFError):
                record = None

        return ObjectIdReport.from_index_entry(entry, record=record, current_volume_id=current_volume_id)

    def reports(self) -> Iterator[ObjectIdReport]:
        """Yield a report for every entry in the index."""
        for entry in self.entries():
            yield self.report_entry(entry)

    def __iter__(self) -> Iterator[ObjectIdIndexEntry]:
        return self.entries()


def _compare_birth_field(
    attribute_value: Guid | None,
    index_value: Guid | None,
    name: str,
    reasons: list[str],
    *,
    required: bool,
) -> bool:
    if attribute_value is None or index_value is None:
        if required or attribute_value != index_value:
            reasons.append(f"missing_{name}")
        return False

    if attribute_value != index_value:
        reasons.append(f"{name}_mismatch")
        return False

    return True


def _volume_id(record: MftRecord) -> Guid | None:
    ntfs = record.ntfs if record else None
    if not ntfs or not ntfs.mft:
        return None

    try:
        volume = ntfs.mft.get(FILE_NUMBER_VOLUME)
        attrs = volume.attributes[ATTRIBUTE_TYPE_CODE.OBJECT_ID]
        if not attrs:
            return None
        return Guid.from_optional(attrs[0].object_id_raw)
    except (Error, FileNotFoundError, MftNotAvailableError, VolumeNotAvailableError):
        return None
