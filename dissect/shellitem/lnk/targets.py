"""Unified target evidence collection for LNK files.

A (malicious) shortcut can advertise different targets in its display name,
LinkInfo, IDList and environment variable data blocks. This module collects a
candidate target from every source that carries one, records the provenance of
each candidate (source, encoding, dependencies, raw byte range) and reports
whether the sources agree, conflict, or cannot be compared.

Command line arguments and icon locations are *not* program targets; they are
collected for visibility but never mixed into the program path comparison.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from dissect.shellitem.lnk.lnk import Lnk, LnkTargetIdList

RUNTIME_CAVEAT = (
    "Static comparison of file bytes only: Windows resolves the executed target at runtime "
    "(LinkInfo, IDList, environment variable expansion, known-folder aliasing, link tracking), "
    "so these bytes alone cannot guarantee which target is ultimately executed."
)

ENVIRONMENT_VARIABLE_PATTERN = re.compile(r"%([^%]+)%")

#: Shell item class type indicators this module can extract a path component from.
SHELL_ITEM_ROOT = 0x1F  # Root folder / known folder (GUID)
SHELL_ITEM_DRIVE = 0x2F  # Drive letter


class CandidateStatus(Enum):
    """Whether a candidate's value could be fully recovered from its source."""

    OK = "ok"
    TRUNCATED = "truncated"
    UNSUPPORTED = "unsupported"


class Relation(Enum):
    """How the comparable target candidates relate to each other."""

    CONSISTENT = "consistent"
    CONFLICT = "conflict"
    INCOMPARABLE = "incomparable"


@dataclass
class TargetCandidate:
    """A single target candidate recovered from one source within a LNK file.

    Args:
        source: Identifier of the structure the candidate was recovered from.
        role: Role of the value: ``display``, ``program``, ``relative``, ``arguments``
            or ``icon``. Only ``display`` and ``program`` candidates take part in
            target comparison.
        value: The recovered target value, or None if it could not be recovered.
        encoding: Encoding of the recovered value (e.g. ``utf-16-le``, ``system-ansi``).
        depends_on: Runtime dependencies of this candidate, e.g. ``env:SystemRoot``,
            ``link-file-location``, ``drive:C:`` or ``known-folder:{guid}``.
        offset: Offset of the source structure within the parsed stream.
        size: Size of the source structure within the parsed stream.
        raw: Raw bytes of the source (kept for truncated or unsupported sources).
        status: Whether the value could be fully recovered.
        note: Optional human readable note.
    """

    source: str
    role: str
    value: str | None
    encoding: str | None
    depends_on: list[str] = field(default_factory=list)
    offset: int | None = None
    size: int | None = None
    raw: bytes | None = None
    status: CandidateStatus = CandidateStatus.OK
    note: str | None = None

    @property
    def comparable(self) -> bool:
        """Whether this candidate may take part in the target comparison."""
        return self.role in ("display", "program") and self.status is CandidateStatus.OK and bool(self.value)


@dataclass
class TargetReport:
    """The unified target evidence set of a LNK file.

    Args:
        candidates: All collected target candidates, including non-target roles.
        relation: How the comparable candidates relate (consistent/conflict/incomparable).
        conflicts: Tuples of (source_a, source_b, value_a, value_b) that disagree.
        incomparable: Candidates that should take part in comparison but could not
            be recovered (truncated or unsupported). Their raw bytes are preserved;
            no other source is used as a substitute to claim full agreement.
        notes: Human readable notes, including the runtime resolution caveat.
    """

    candidates: list[TargetCandidate]
    relation: Relation
    conflicts: list[tuple[str, str, str, str]] = field(default_factory=list)
    incomparable: list[TargetCandidate] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def compared(self) -> list[TargetCandidate]:
        return [candidate for candidate in self.candidates if candidate.comparable]

    @property
    def complete(self) -> bool:
        """Whether every display/program source could be compared."""
        return not self.incomparable

    def verdict(self) -> str:
        """One-line verdict that never claims full agreement when sources are missing."""
        if self.relation is Relation.CONFLICT:
            return f"CONFLICT: {len(self.conflicts)} source pair(s) advertise different targets"
        if self.relation is Relation.CONSISTENT:
            if self.incomparable:
                return (
                    f"PARTIALLY CONSISTENT: {len(self.compared)} comparable source(s) agree, "
                    f"but {len(self.incomparable)} source(s) could not be compared"
                )
            return f"CONSISTENT: all {len(self.compared)} target source(s) agree"
        return "INCOMPARABLE: fewer than two comparable target sources"

    def summary(self) -> str:
        """Human readable multi-line report of the target evidence set."""
        lines = [f"Target verdict\t\t\t: {self.verdict()}"]
        for candidate in self.candidates:
            depends = f" depends_on={','.join(candidate.depends_on)}" if candidate.depends_on else ""
            raw_range = ""
            if candidate.offset is not None:
                if candidate.size:
                    raw_range = f" raw={candidate.offset:#x}+{candidate.size:#x}"
                else:
                    raw_range = f" raw={candidate.offset:#x}"
            value = candidate.value if candidate.value is not None else f"<{candidate.status.value}>"
            lines.append(
                f"  [{candidate.status.value}] {candidate.source} "
                f"({candidate.role}, {candidate.encoding}){raw_range}: {value}{depends}"
            )
            if candidate.note:
                lines.append(f"       note: {candidate.note}")
        for source_a, source_b, value_a, value_b in self.conflicts:
            lines.append(f"  conflict: {source_a}={value_a!r} != {source_b}={value_b!r}")
        for note in self.notes:
            lines.append(f"  {note}")
        return "\n".join(lines)


def _decode_ansi(raw: bytes) -> str:
    return raw.decode("cp1252", errors="backslashreplace")


def _normalize(value: str) -> str:
    """Normalize a target value for comparison (case and separator insensitive)."""
    return value.strip().replace("/", "\\").rstrip("\\").casefold()


def _file_entry_name(data: bytes) -> tuple[str | None, str | None]:
    """Extract the name of a file entry shell item (class types 0x30-0x3f).

    Prefers the long (unicode) name from a 0xBEEF0004 extension block and falls
    back to the short (ANSI) name. Returns (name, encoding) or (None, None).
    """
    signature_offset = data.find(b"\x04\x00\xef\xbe")
    if signature_offset >= 4:
        extension = data[signature_offset - 4 :]
        version = int.from_bytes(extension[2:4], "little")
        # The long name offset differs per extension version; try known offsets
        # in order of likelihood for the observed version.
        offsets = (0x2A, 0x16, 0x10) if version >= 0x0007 else (0x10, 0x16, 0x2A)
        for offset in offsets:
            if len(extension) <= offset:
                continue
            try:
                name = extension[offset:].decode("utf-16-le").split("\x00")[0]
            except UnicodeDecodeError:
                continue
            if name and name.isprintable():
                return name, "utf-16-le"

    short_name = data[12:].split(b"\x00")[0]
    if short_name:
        return _decode_ansi(short_name), "system-ansi"
    return None, None


def _idlist_candidate(
    source: str,
    target_idlist: LnkTargetIdList,
    offset: int | None,
    size: int | None,
) -> TargetCandidate:
    """Build a target candidate from a (Vista or regular) TARGET_IDLIST structure.

    Unsupported shell item types are preserved raw and reported as unsupported;
    the path is never substituted with a value from another source.
    """
    if target_idlist.truncated or target_idlist.idlist is None:
        return TargetCandidate(
            source=source,
            role="program",
            value=None,
            encoding=None,
            offset=offset,
            size=size,
            raw=target_idlist.raw,
            status=CandidateStatus.TRUNCATED,
            note="IDList is truncated or malformed; raw bytes preserved",
        )

    components = []
    depends_on = []
    unsupported = []
    for item in target_idlist.idlist.itemid_list:
        data = bytes(item.data)
        if not data:
            continue
        class_type = data[0]
        if class_type == SHELL_ITEM_ROOT:
            # A root item only anchors the IDList in the shell namespace (e.g. a
            # known folder); it is not part of the target path itself.
            guid = UUID(bytes_le=data[2:18]) if len(data) >= 18 else None
            if guid:
                depends_on.append(f"known-folder:{guid}")
            else:
                depends_on.append("known-folder:<unparseable>")
        elif class_type == SHELL_ITEM_DRIVE:
            drive = _decode_ansi(data[1:].split(b"\x00")[0]).rstrip("\\")
            components.append(drive)
            depends_on.append(f"drive:{drive}")
        elif class_type & 0x70 == 0x30:
            name, _encoding = _file_entry_name(data)
            if name is None:
                unsupported.append(item)
                break
            components.append(name)
        else:
            unsupported.append(item)
            break

    if unsupported:
        raw = b"".join(bytes(item.dumps()) for item in unsupported)
        types = ", ".join(f"{bytes(item.data)[0]:#x}" for item in unsupported if item.data)
        return TargetCandidate(
            source=source,
            role="program",
            value=None,
            encoding=None,
            depends_on=depends_on,
            offset=offset,
            size=size,
            raw=raw,
            status=CandidateStatus.UNSUPPORTED,
            note=f"Unsupported shell item type(s) {types} preserved raw; not substituted from another source",
        )

    value = "\\".join(component for component in components if component)
    return TargetCandidate(
        source=source,
        role="program",
        value=value or None,
        encoding="shell-item (mixed)",
        depends_on=depends_on,
        offset=offset,
        size=size,
        raw=target_idlist.raw,
    )


def _string_data_candidates(lnk: Lnk) -> list[TargetCandidate]:
    candidates = []
    string_data = lnk.stringdata
    if not string_data.string_data:
        return candidates

    encoding = "utf-16-le" if lnk.flag("is_unicode") else "system-ansi"
    roles = (
        ("name_string", "display", []),
        ("relative_path", "relative", ["link-file-location"]),
        ("command_line_arguments", "arguments", []),
        ("icon_location", "icon", []),
    )
    for name, role, depends_on in roles:
        if name not in string_data.string_data:
            continue
        entry = string_data.string_data[name]
        value = entry.string if isinstance(entry.string, str) else _decode_ansi(entry.string)
        offset, size = string_data.offsets.get(name, (None, None))
        status = CandidateStatus.TRUNCATED if name in string_data.truncated else CandidateStatus.OK
        note = None
        if status is CandidateStatus.TRUNCATED:
            note = "String data is truncated; value is partial"
        elif role == "relative":
            note = "Relative to the link file location; excluded from target comparison"
        elif role in ("arguments", "icon"):
            note = "Not a program target; excluded from target comparison"
        candidates.append(
            TargetCandidate(
                source=f"string_data.{name}",
                role=role,
                value=value,
                encoding=encoding,
                depends_on=depends_on,
                offset=offset,
                size=size,
                status=status,
                note=note,
            )
        )
    return candidates


def _link_info_candidates(lnk: Lnk) -> list[TargetCandidate]:
    candidates = []
    link_info = lnk.linkinfo
    if link_info.link_info is None:
        return candidates

    offset, size = link_info.raw_offset, link_info.raw_size
    common_path_suffix = _decode_ansi(link_info.common_path_suffix) if link_info.common_path_suffix else ""

    if link_info.flag("volumeid_and_local_basepath") and link_info.local_base_path is not None:
        local_base_path = _decode_ansi(link_info.local_base_path)
        depends_on = []
        if match := re.match(r"^([A-Za-z]:)", local_base_path):
            depends_on.append(f"drive:{match.group(1).upper()}")
        candidates.append(
            TargetCandidate(
                source="link_info.local_base_path+common_path_suffix",
                role="program",
                value=local_base_path + common_path_suffix,
                encoding="system-ansi",
                depends_on=depends_on,
                offset=offset,
                size=size,
            )
        )

    if link_info.flag("common_network_relative_link_and_pathsuffix"):
        relative_link = link_info.common_network_relative_link
        if relative_link and relative_link.net_name:
            net_name = _decode_ansi(relative_link.net_name)
            candidates.append(
                TargetCandidate(
                    source="link_info.net_name+common_path_suffix",
                    role="program",
                    value=net_name.rstrip("\\") + ("\\" + common_path_suffix if common_path_suffix else ""),
                    encoding="system-ansi",
                    depends_on=["network-share"],
                    offset=offset,
                    size=size,
                )
            )
    return candidates


def _extra_data_candidates(lnk: Lnk) -> list[TargetCandidate]:
    candidates = []
    extra_data = lnk.extradata

    for block_name, info in extra_data.truncated_blocks.items():
        role = "icon" if block_name == "ICON_ENVIRONMENT_PROPS" else "program"
        candidates.append(
            TargetCandidate(
                source=f"extra_data.{block_name}",
                role=role,
                value=None,
                encoding=None,
                offset=info["offset"],
                size=info["declared_size"],
                raw=info["raw"],
                status=CandidateStatus.TRUNCATED,
                note=(
                    f"Block declares {info['declared_size']} bytes but only {len(info['raw'])} "
                    "are present; raw bytes preserved"
                ),
            )
        )

    if "ENVIRONMENT_PROPS" in extra_data.extradata:
        props = extra_data.extradata["ENVIRONMENT_PROPS"]
        offset, size = extra_data.offsets.get("ENVIRONMENT_PROPS", (None, None))
        value = props.target_unicode
        ansi_value = _decode_ansi(props.target_ansi).rstrip("\x00")
        note = None
        if ansi_value and ansi_value != value:
            note = f"ANSI variant differs: {ansi_value!r}"
        candidates.append(
            TargetCandidate(
                source="extra_data.ENVIRONMENT_PROPS",
                role="program",
                value=value,
                encoding="utf-16-le",
                depends_on=[f"env:{name}" for name in ENVIRONMENT_VARIABLE_PATTERN.findall(value)],
                offset=offset,
                size=size,
                note=note,
            )
        )

    if "ICON_ENVIRONMENT_PROPS" in extra_data.extradata:
        props = extra_data.extradata["ICON_ENVIRONMENT_PROPS"]
        offset, size = extra_data.offsets.get("ICON_ENVIRONMENT_PROPS", (None, None))
        candidates.append(
            TargetCandidate(
                source="extra_data.ICON_ENVIRONMENT_PROPS",
                role="icon",
                value=props.target_unicode,
                encoding="utf-16-le",
                depends_on=[f"env:{name}" for name in ENVIRONMENT_VARIABLE_PATTERN.findall(props.target_unicode)],
                offset=offset,
                size=size,
                note="Not a program target; excluded from target comparison",
            )
        )

    if "VISTA_AND_ABOVE_IDLIST_PROPS" in extra_data.extradata:
        vista_idlist = extra_data.extradata["VISTA_AND_ABOVE_IDLIST_PROPS"]
        offset, size = extra_data.offsets.get("VISTA_AND_ABOVE_IDLIST_PROPS", (None, None))
        candidates.append(
            _idlist_candidate("extra_data.VISTA_AND_ABOVE_IDLIST_PROPS", vista_idlist, offset, size)
        )

    # Present the extra data candidates in file order.
    candidates.sort(key=lambda candidate: candidate.offset if candidate.offset is not None else -1)
    return candidates


def collect_targets(lnk: Lnk) -> TargetReport:
    """Collect the unified target evidence set of a parsed LNK file.

    Args:
        lnk: A parsed Lnk object.

    Returns:
        A TargetReport with one candidate per target source, the relation
        between the comparable candidates, and notes on sources that could
        not be compared.
    """
    candidates: list[TargetCandidate] = []

    if lnk.flag("has_link_target_idlist"):
        target_idlist = lnk.target_idlist
        offset = target_idlist.raw_offset
        size = 2 + target_idlist.size if target_idlist.size is not None else None
        candidates.append(_idlist_candidate("target_idlist", target_idlist, offset, size))

    candidates.extend(_link_info_candidates(lnk))
    candidates.extend(_string_data_candidates(lnk))
    candidates.extend(_extra_data_candidates(lnk))

    compared = [candidate for candidate in candidates if candidate.comparable]
    incomparable = [
        candidate
        for candidate in candidates
        if candidate.role in ("display", "program") and not candidate.comparable
    ]

    groups: dict[str, list[TargetCandidate]] = {}
    for candidate in compared:
        groups.setdefault(_normalize(candidate.value), []).append(candidate)

    conflicts = []
    group_values = list(groups.values())
    for index, group in enumerate(group_values):
        for other in group_values[index + 1 :]:
            conflicts.append((group[0].source, other[0].source, group[0].value, other[0].value))

    if len(compared) < 2:
        relation = Relation.INCOMPARABLE
    elif len(groups) == 1:
        relation = Relation.CONSISTENT
    else:
        relation = Relation.CONFLICT

    notes = []
    for candidate in incomparable:
        notes.append(
            f"{candidate.source} could not be compared ({candidate.status.value}); "
            "its raw bytes are preserved and no other source was used as a substitute"
        )
    notes.append(RUNTIME_CAVEAT)

    return TargetReport(
        candidates=candidates,
        relation=relation,
        conflicts=conflicts,
        incomparable=incomparable,
        notes=notes,
    )
