from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, c_ntfs

if TYPE_CHECKING:
    from dissect.ntfs.mft import MftRecord

# Size of the fixed part of a FILE_FULL_EA_INFORMATION structure
EA_ENTRY_HEADER_SIZE = 8


class EaStatus(enum.Enum):
    """Overall consistency status of an extended attribute view."""

    CONSISTENT = "consistent"
    INCONSISTENT = "inconsistent"


@dataclass
class EaSource:
    """Provenance of a single extended attribute entry or summary.

    Args:
        segment: The MFT segment number of the record the data was read from.
        attribute_offset: The offset of the attribute within the MFT record.
        resident: Whether the attribute content is resident.
        entry_offset: The offset of the entry within the ``$EA`` attribute data.
    """

    segment: int | None = None
    attribute_offset: int | None = None
    resident: bool = True
    entry_offset: int = 0


@dataclass
class EaEntry:
    """A single parsed ``$EA`` entry.

    The raw name and value are kept as bytes so duplicate names and non-text
    values are preserved as evidence instead of being collapsed into a dict.

    Args:
        name: The raw (undecoded) entry name, without the null terminator.
        flags: The raw entry flags (e.g. ``EA_FLAG.NEED_EA``).
        value: The raw binary entry value.
        source: The provenance of this entry.
        next_entry_offset: The raw ``NextEntryOffset`` of this entry.
        truncated: Whether the entry was cut off by the end of the attribute data.
        issues: Entry specific inconsistencies encountered while parsing.
    """

    name: bytes
    flags: int
    value: bytes
    source: EaSource
    next_entry_offset: int
    truncated: bool = False
    issues: list[str] = field(default_factory=list)

    @property
    def name_text(self) -> str:
        """Return the entry name decoded as ASCII, replacing undecodable bytes."""
        return self.name.decode("ascii", errors="replace")

    @property
    def need_ea(self) -> bool:
        """Return whether this entry has the ``NEED_EA`` flag set."""
        return bool(self.flags & c_ntfs.EA_FLAG.NEED_EA)


@dataclass
class EaInformation:
    """A parsed ``$EA_INFORMATION`` summary.

    Args:
        ea_length: The packed size of the extended attributes.
        need_ea_count: The number of entries with the ``NEED_EA`` flag set.
        ea_query_length: The buffer size required to query the extended attributes.
        source: The provenance of this summary.
    """

    ea_length: int
    need_ea_count: int
    ea_query_length: int
    source: EaSource


@dataclass
class EaView:
    """Investigation view over the extended attributes of an MFT record.

    Links every parsed ``$EA`` entry back to the ``$EA_INFORMATION`` summary and
    reports per-entry provenance and an overall consistency status. Entries are
    kept as an ordered list, so duplicate names are preserved.

    Args:
        entries: All parsed ``$EA`` entries, in on-disk order.
        information: The parsed ``$EA_INFORMATION`` summary, if present.
        issues: All inconsistencies encountered while building this view.
    """

    entries: list[EaEntry]
    information: EaInformation | None
    issues: list[str]

    @property
    def status(self) -> EaStatus:
        """Return the overall consistency status of this view."""
        entry_issues = any(entry.issues for entry in self.entries)
        return EaStatus.INCONSISTENT if self.issues or entry_issues else EaStatus.CONSISTENT

    @property
    def consistent(self) -> bool:
        """Return whether this view is fully consistent."""
        return self.status is EaStatus.CONSISTENT

    @property
    def names(self) -> list[bytes]:
        """Return all raw entry names, preserving duplicates."""
        return [entry.name for entry in self.entries]

    def by_name(self) -> dict[bytes, list[EaEntry]]:
        """Return all entries grouped by raw name, preserving duplicates."""
        result: dict[bytes, list[EaEntry]] = {}
        for entry in self.entries:
            result.setdefault(entry.name, []).append(entry)
        return result


def _align4(value: int) -> int:
    return (value + 3) & ~3


def parse_ea_entries(data: bytes, source: EaSource | None = None) -> tuple[list[EaEntry], list[str], int | None]:
    """Defensively parse a chain of ``FILE_FULL_EA_INFORMATION`` entries from ``$EA`` data.

    The ``NextEntryOffset`` chain is validated: an entry may never link outside the
    attribute data, overlap its predecessor, or form a loop. When an entry is
    truncated, the remaining bytes are not interpreted as further entries, so
    trailing data can never masquerade as a complete attribute.

    Args:
        data: The raw ``$EA`` attribute data.
        source: Optional provenance to stamp on every parsed entry.

    Returns:
        A tuple of the parsed entries, a list of issues and the packed length of the
        entry chain. The packed length is ``None`` if the chain terminated abnormally.
    """
    entries = []
    issues = []
    packed_length = None

    source = source or EaSource()
    offset = 0
    seen = set()

    while offset < len(data):
        if offset in seen:
            issues.append(f"Loop detected in $EA entry chain at offset {offset}")
            break
        seen.add(offset)

        if len(data) - offset < EA_ENTRY_HEADER_SIZE:
            issues.append(f"Trailing {len(data) - offset} byte(s) at offset {offset} too small for an $EA entry header")
            break

        next_entry_offset = int.from_bytes(data[offset : offset + 4], "little")
        flags = data[offset + 4]
        name_length = data[offset + 5]
        value_length = int.from_bytes(data[offset + 6 : offset + 8], "little")

        entry_source = replace(source, entry_offset=offset)
        name_start = offset + EA_ENTRY_HEADER_SIZE
        name_end = name_start + name_length
        # The on-disk name is null terminated, the value follows the terminator
        value_start = name_end + 1
        value_end = value_start + value_length

        if name_end > len(data):
            issues.append(f"Truncated $EA entry name at offset {offset}")
            entries.append(EaEntry(data[name_start:], flags, b"", entry_source, next_entry_offset, truncated=True))
            break

        if value_end > len(data):
            issues.append(f"Truncated $EA entry value at offset {offset}")
            entries.append(
                EaEntry(
                    data[name_start:name_end],
                    flags,
                    data[value_start:] if value_start <= len(data) else b"",
                    entry_source,
                    next_entry_offset,
                    truncated=True,
                )
            )
            break

        entries.append(EaEntry(data[name_start:name_end], flags, data[value_start:value_end], entry_source, next_entry_offset))

        if next_entry_offset == 0:
            packed_length = _align4(value_end)
            break

        next_offset = offset + next_entry_offset
        if next_offset <= offset:
            issues.append(f"$EA entry at offset {offset} links backwards to offset {next_offset}")
            break
        if next_offset < value_end:
            issues.append(f"$EA entry at offset {offset} links into itself at offset {next_offset}")
            break
        if next_offset > len(data):
            issues.append(f"$EA entry at offset {offset} links outside the attribute data to offset {next_offset}")
            break

        offset = next_offset
    else:
        if entries:
            issues.append("$EA entry chain reached the end of the attribute data without a terminating entry")

    return entries, issues, packed_length


def ea_view(record: MftRecord) -> EaView:
    """Build an :class:`EaView` for the given MFT record.

    Reads the ``$EA`` attribute(s) (resident or non-resident) and the
    ``$EA_INFORMATION`` summary of the record and cross-checks them. Summary
    count mismatches are reported, never silently corrected.

    Args:
        record: The MFT record to build the view for.
    """
    entries: list[EaEntry] = []
    issues: list[str] = []
    information = None
    packed_length = 0

    info_attrs = record.attributes[ATTRIBUTE_TYPE_CODE.EA_INFORMATION]
    for index, attr in enumerate(info_attrs):
        if index > 0:
            issues.append(f"Additional $EA_INFORMATION attribute at offset {attr.header.offset}")
            continue
        if attr.attribute is None:
            issues.append(f"$EA_INFORMATION attribute at offset {attr.header.offset} could not be read")
            continue
        information = EaInformation(
            attr.attribute.ea_length,
            attr.attribute.need_ea_count,
            attr.attribute.ea_query_length,
            EaSource(record.segment, attr.header.offset, attr.header.resident),
        )

    ea_attrs = record.attributes[ATTRIBUTE_TYPE_CODE.EA]
    for attr in ea_attrs:
        source = EaSource(record.segment, attr.header.offset, attr.header.resident)
        if attr.attribute is None:
            issues.append(f"$EA attribute at offset {attr.header.offset} could not be read")
            continue

        attr_entries, attr_issues, attr_packed_length = parse_ea_entries(attr.attribute.data, source)
        entries.extend(attr_entries)
        issues.extend(attr_issues)
        if attr_packed_length is not None:
            packed_length += attr_packed_length

    if information is None and entries:
        issues.append("Parsed $EA entries but the record has no readable $EA_INFORMATION attribute")

    if information is not None:
        if not entries and information.ea_length:
            issues.append(
                f"$EA_INFORMATION reports {information.ea_length} byte(s) of packed data but no $EA entries were parsed"
            )
        if entries:
            need_ea = sum(entry.need_ea for entry in entries)
            if need_ea != information.need_ea_count:
                issues.append(
                    f"$EA_INFORMATION NeedEaCount ({information.need_ea_count}) does not match "
                    f"the {need_ea} parsed NEED_EA entrie(s)"
                )
            if all(not entry.truncated for entry in entries) and packed_length != information.ea_length:
                issues.append(
                    f"$EA_INFORMATION EaLength ({information.ea_length}) does not match "
                    f"the packed length of the parsed entries ({packed_length})"
                )

    return EaView(entries, information, issues)
