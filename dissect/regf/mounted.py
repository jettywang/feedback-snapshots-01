"""Read-only correlation of ``SYSTEM\\MountedDevices`` values.

MountedDevices maps symbolic names (drive letters and volume names) to data
that may describe a disk or a reference to another name.  This module keeps
the original value bytes and cell offsets, recognizes two conservative binary
volume identity forms, and resolves exact textual references between registry
value names.

The recognized binary forms are:

* ``MBR``: exactly 12 bytes, a little-endian 32-bit disk signature followed by
  a little-endian 64-bit partition offset.
* ``GPT``: exactly 24 bytes, the ASCII marker ``DMIO:ID:`` followed by a
  little-endian 16-byte GPT partition GUID.

Anything else is retained as unknown evidence.  The binary form is decided
from the bytes in the value's own data cell; the identity is never assembled
from the cell offset or from another value.
"""

from __future__ import annotations

import re
import struct
import uuid
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, ClassVar, Literal, TypeAlias, cast

from dissect.regf.c_regf import REG_BINARY, c_regf
from dissect.regf.exceptions import RegistryKeyNotFoundError
from dissect.regf.regf import KeyValue, RegistryHive

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.regf.regf import KeyNode

__all__ = [
    "AliasConflict",
    "GptVolumeIdentity",
    "IdentityRecord",
    "MbrVolumeIdentity",
    "MountedDeviceValue",
    "MountedDevicesAnalysis",
    "MountedDevicesCorrelation",
    "ReferenceHop",
    "TextDeviceIdentity",
    "VolumeIdentity",
    "analyze_mounted_devices",
    "correlate_mounted_devices",
]

_DRIVE_RE = re.compile(r"^\\(?:\?\?|dosdevices)\\([a-z]):$", re.IGNORECASE)
_VOLUME_RE = re.compile(
    r"^\\(?:\?\?|dosdevices)\\volume\{([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}$",
    re.IGNORECASE,
)
_TEXT_RE = re.compile(r"^\\(?:\?\?|dosdevices|device)\\[^\x00]*$", re.IGNORECASE)

MBR_SIZE = 12
GPT_PREFIX = b"DMIO:ID:"
GPT_SIZE = 8 + 16

MBR_BASIS = "12-byte MBR disk signature + 8-byte little-endian partition offset"
GPT_BASIS = "24-byte DMIO:ID: marker + little-endian GPT partition GUID"
TEXT_BASIS = "textual device reference"
UNKNOWN_BASIS = "unrecognized binary layout; original bytes retained"


@dataclass(frozen=True)
class MbrVolumeIdentity:
    """An MBR volume identity: disk signature plus partition offset."""

    disk_signature: int
    partition_offset: int
    kind: ClassVar[Literal["mbr"]] = "mbr"

    @property
    def canonical(self) -> str:
        """Return a stable identity string for cross-snapshot comparison."""
        return f"mbr:{self.disk_signature:08x}:{self.partition_offset:016x}"

    def to_dict(self) -> dict[str, int | str]:
        return {
            "kind": self.kind,
            "canonical": self.canonical,
            "disk_signature": self.disk_signature,
            "partition_offset": self.partition_offset,
        }


@dataclass(frozen=True)
class GptVolumeIdentity:
    """A GPT volume identity: the partition GUID from ``DMIO:ID:`` data."""

    partition_guid: uuid.UUID
    kind: ClassVar[Literal["gpt"]] = "gpt"

    @property
    def canonical(self) -> str:
        """Return a stable identity string for cross-snapshot comparison."""
        return f"gpt:{self.partition_guid}"

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "canonical": self.canonical,
            "partition_guid": str(self.partition_guid),
        }


@dataclass(frozen=True)
class TextDeviceIdentity:
    """An exact textual device path, not a confirmed binary volume identity."""

    device_path: str
    kind: ClassVar[Literal["text"]] = "text"

    @property
    def canonical(self) -> str:
        """Return a case-insensitive, exact-path identity string."""
        return f"text:{self.device_path.casefold()}"

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "canonical": self.canonical,
            "device_path": self.device_path,
        }


VolumeIdentity: TypeAlias = MbrVolumeIdentity | GptVolumeIdentity | TextDeviceIdentity


@dataclass(frozen=True)
class ReferenceHop:
    """One registry value visited while following a textual device reference."""

    name: str
    value_cell_offset: int | None = None
    raw_hex: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "value_cell_offset": self.value_cell_offset,
            "raw_hex": self.raw_hex,
        }


@dataclass(frozen=True)
class MountedDeviceValue:
    """One MountedDevices value with its evidence and resolved identity."""

    name: str
    alias: Literal["drive-letter", "volume-name", "other"]
    alias_key: str
    raw: bytes
    value_type: int
    value_cell_offset: int
    data_cell_offset: int | None
    kind: Literal["mbr", "gpt", "text", "unknown", "reference", "ambiguous"]
    status: Literal[
        "binary-identity",
        "text-identity",
        "reference",
        "unresolved",
        "cycle",
        "ambiguous",
        "unknown",
    ]
    identity: VolumeIdentity | None
    parse_basis: str
    snapshot: str | None = None
    reference: str | None = None
    chain: tuple[ReferenceHop, ...] = ()
    detail: str | None = None

    @property
    def raw_hex(self) -> str:
        """Hexadecimal form of the original value data."""
        return self.raw.hex()

    @property
    def confirmed(self) -> bool:
        """Whether this value resolves to a recognized binary identity."""
        return self.identity is not None and self.identity.kind in ("mbr", "gpt")

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "name": self.name,
            "alias": self.alias,
            "alias_key": self.alias_key,
            "value_type": self.value_type,
            "value_cell_offset": self.value_cell_offset,
            "data_cell_offset": self.data_cell_offset,
            "raw_hex": self.raw_hex,
            "raw_length": len(self.raw),
            "kind": self.kind,
            "status": self.status,
            "parse_basis": self.parse_basis,
            "confirmed": self.confirmed,
        }
        if self.snapshot is not None:
            result["snapshot"] = self.snapshot
        if self.identity is not None:
            result["identity"] = self.identity.to_dict()
        if self.reference is not None:
            result["reference"] = self.reference
        if self.chain:
            result["chain"] = [hop.to_dict() for hop in self.chain]
        if self.detail is not None:
            result["detail"] = self.detail
        return result


@dataclass(frozen=True)
class IdentityRecord:
    """All aliases that resolve to the same identity in one or more snapshots."""

    identity: VolumeIdentity
    aliases: tuple[MountedDeviceValue, ...]

    @property
    def snapshots(self) -> tuple[str, ...]:
        """Snapshots in which this identity was observed."""
        names = {alias.snapshot for alias in self.aliases if alias.snapshot is not None}
        return tuple(sorted(names))

    @property
    def alias_names(self) -> tuple[str, ...]:
        """Original registry value names that resolve to this identity."""
        return tuple(alias.name for alias in self.aliases)

    @property
    def confirmed(self) -> bool:
        """Whether the identity is a recognized binary form."""
        return self.identity.kind in ("mbr", "gpt")

    def to_dict(self) -> dict[str, object]:
        return {
            "identity": self.identity.to_dict(),
            "confirmed": self.confirmed,
            "snapshots": list(self.snapshots),
            "aliases": [alias.to_dict() for alias in self.aliases],
        }


@dataclass(frozen=True)
class AliasConflict:
    """One alias name observed with more than one identity."""

    alias_key: str
    identity_keys: tuple[str, ...]
    values: tuple[MountedDeviceValue, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "alias_key": self.alias_key,
            "identity_keys": list(self.identity_keys),
            "reason": self.reason,
            "values": [value.to_dict() for value in self.values],
        }


@dataclass(frozen=True)
class MountedDevicesAnalysis:
    """Read-only analysis result for one hive snapshot's MountedDevices key."""

    snapshot: str | None
    key_path: str
    values: tuple[MountedDeviceValue, ...] = ()
    identities: tuple[IdentityRecord, ...] = ()
    conflicts: tuple[AliasConflict, ...] = ()
    problems: tuple[str, ...] = ()

    @property
    def records(self) -> tuple[IdentityRecord, ...]:
        """Alias for :attr:`identities`, the evidence records for this snapshot."""
        return self.identities

    @property
    def unresolved(self) -> tuple[MountedDeviceValue, ...]:
        """Values without a confirmed identity, including references and unknown data."""
        return tuple(value for value in self.values if not value.confirmed)

    def to_dict(self) -> dict[str, object]:
        return {
            "snapshot": self.snapshot,
            "key_path": self.key_path,
            "values": [value.to_dict() for value in self.values],
            "identities": [record.to_dict() for record in self.identities],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "problems": list(self.problems),
        }


@dataclass(frozen=True)
class MountedDevicesCorrelation:
    """Identity records combined across snapshots, with alias reuse conflicts."""

    records: tuple[IdentityRecord, ...]
    conflicts: tuple[AliasConflict, ...]
    snapshots: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "records": [record.to_dict() for record in self.records],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "snapshots": list(self.snapshots),
        }


def analyze_mounted_devices(source: RegistryHive | KeyNode, *, snapshot: str | None = None) -> MountedDevicesAnalysis:
    """Analyze MountedDevices without modifying the hive.

    Args:
        source: A :class:`RegistryHive` or its MountedDevices ``KeyNode``.
        snapshot: Optional label used to keep evidence from different hives apart.

    Returns:
        A :class:`MountedDevicesAnalysis` with original bytes, cell offsets,
        resolved identities, and any unresolved, cyclic, or conflicting values.
    """
    if isinstance(source, RegistryHive):
        try:
            key = source.open("MountedDevices")
        except RegistryKeyNotFoundError:
            return MountedDevicesAnalysis(
                snapshot=snapshot,
                key_path="MountedDevices",
                problems=("MountedDevices key not found in hive",),
            )
        key_path = key.path or "MountedDevices"
    else:
        key = source
        key_path = key.path or key.name or "MountedDevices"

    rows, problems = _read_values(key)
    values = _resolve_rows(rows, snapshot=snapshot)
    records = _build_identity_records(values)
    conflicts = _find_conflicts(values)
    return MountedDevicesAnalysis(
        snapshot=snapshot,
        key_path=key_path,
        values=values,
        identities=records,
        conflicts=conflicts,
        problems=problems,
    )


def correlate_mounted_devices(*analyses: MountedDevicesAnalysis) -> MountedDevicesCorrelation:
    """Combine identity evidence from multiple snapshots without merging aliases.

    Identities are combined by their canonical binary or exact textual value.
    A drive letter or volume name that points to different identities in
    different snapshots is reported as a conflict; the conflicting aliases are
    not collapsed into one identity record.

    Args:
        *analyses: Results from :func:`analyze_mounted_devices`.

    Returns:
        A :class:`MountedDevicesCorrelation` suitable for later disk evidence
        comparison.
    """
    grouped: dict[str, list[MountedDeviceValue]] = {}
    grouped_identities: dict[str, VolumeIdentity] = {}
    for analysis in analyses:
        for value in analysis.values:
            if value.identity is None:
                continue
            grouped.setdefault(value.identity.canonical, []).append(value)
            grouped_identities.setdefault(value.identity.canonical, value.identity)

    records = tuple(
        IdentityRecord(
            identity=grouped_identities[canonical],
            aliases=tuple(sorted(aliases, key=lambda alias: (alias.snapshot or "", alias.value_cell_offset))),
        )
        for canonical, aliases in sorted(grouped.items())
    )
    snapshots = tuple(sorted({analysis.snapshot for analysis in analyses if analysis.snapshot is not None}))
    return MountedDevicesCorrelation(
        records=records,
        conflicts=_find_conflicts(tuple(value for analysis in analyses for value in analysis.values)),
        snapshots=snapshots,
    )


def _read_values(key: KeyNode) -> tuple[list[_Row], tuple[str, ...]]:
    rows: list[_Row] = []
    problems: list[str] = []

    count = key.cell.ValueList.Count
    if not count:
        return rows, tuple(problems)

    try:
        value_data = key.hive.cell_data(key.cell.ValueList.List)
    except Exception as exc:
        return rows, (f"unable to read value list at 0x{key.cell.ValueList.List:x}: {exc}",)

    count = min(count, len(value_data) // 4)
    for offset in c_regf.int32[count](value_data):
        if offset <= 2:
            continue

        try:
            data = key.hive.cell_data(offset)
        except Exception as exc:
            problems.append(f"unable to read value cell at 0x{offset:x}: {exc}")
            continue

        if data[:2] != KeyValue.__signature__:
            problems.append(f"invalid value cell signature {data[:2]!r} at 0x{offset:x}")
            continue

        try:
            value = KeyValue(key.hive, data)
            raw = value.data
        except Exception as exc:
            problems.append(f"unable to parse value cell at 0x{offset:x}: {exc}")
            continue

        rows.append(_Row(value=value, raw=raw, value_cell_offset=offset))

    return rows, tuple(problems)


@dataclass(frozen=True)
class _Row:
    value: KeyValue
    raw: bytes
    value_cell_offset: int

    @property
    def name(self) -> str:
        return self.value.name

    @property
    def alias_key(self) -> str:
        return _alias_key(self.name)


def _resolve_rows(rows: list[_Row], *, snapshot: str | None) -> tuple[MountedDeviceValue, ...]:
    by_key: dict[str, list[_Row]] = {}
    for row in rows:
        by_key.setdefault(row.alias_key, []).append(row)

    parsed: dict[int, MountedDeviceValue] = {}
    row_index = {id(row): index for index, row in enumerate(rows)}
    for index, row in enumerate(rows):
        parsed[index] = _parse_row(row, snapshot=snapshot)

    for index in range(len(rows)):
        parsed[index] = _resolve_reference(parsed[index], by_key, parsed, row_index)

    return tuple(parsed[index] for index in range(len(rows)))


def _parse_row(row: _Row, *, snapshot: str | None) -> MountedDeviceValue:
    alias, alias_key = _alias(row.name)
    reference = _decode_text_reference(row.raw, row.value.type) if row.value.type == REG_BINARY else None
    identity, kind, status, parse_basis = _parse_identity(row.raw, row.value.type)

    if reference is not None and identity is not None:
        return _make_value(
            row,
            snapshot=snapshot,
            alias=alias,
            alias_key=alias_key,
            kind="ambiguous",
            status="ambiguous",
            identity=None,
            parse_basis=(
                f"both interpretations are structurally valid: {parse_basis}; "
                f"and text reference to {reference!r}; neither confirmed"
            ),
            reference=reference,
            detail="binary and textual interpretations conflict; original bytes retained",
        )

    if reference is not None:
        return _make_value(
            row,
            snapshot=snapshot,
            alias=alias,
            alias_key=alias_key,
            kind="reference",
            status="reference",
            identity=None,
            parse_basis=f"text reference to {reference!r}; target resolution pending",
            reference=reference,
        )

    return _make_value(
        row,
        snapshot=snapshot,
        alias=alias,
        alias_key=alias_key,
        kind=kind,
        status=status,
        identity=identity,
        parse_basis=parse_basis,
    )


def _resolve_reference(
    value: MountedDeviceValue,
    by_key: dict[str, list[_Row]],
    parsed: dict[int, MountedDeviceValue],
    row_index: dict[int, int],
) -> MountedDeviceValue:
    if value.reference is None or value.kind == "ambiguous":
        return value

    current = value.reference
    chain: list[ReferenceHop] = []
    visited: set[str] = {value.alias_key}
    resolved = value

    while True:
        target_key = _alias_key(current)
        if target_key in visited:
            hop = _hop_for(current, by_key, row_index, parsed)
            resolved = _replace_value(
                value,
                kind="reference",
                status="cycle",
                identity=None,
                reference=value.reference,
                chain=(*chain, hop),
                detail=f"reference cycle at {current!r}",
            )
            break

        visited.add(target_key)
        matches = by_key.get(target_key, [])
        if len(matches) > 1:
            hops = [parsed[row_index[id(match)]] for match in matches]
            resolved = _replace_value(
                value,
                kind="reference",
                status="ambiguous",
                identity=None,
                reference=value.reference,
                chain=(*chain, *(ReferenceHop(t.name, t.value_cell_offset, t.raw_hex) for t in hops)),
                detail="target name is duplicated in MountedDevices",
            )
            break

        if not matches:
            hop = ReferenceHop(current)
            if _is_registry_alias(target_key):
                resolved = _replace_value(
                    value,
                    kind="reference",
                    status="unresolved",
                    identity=None,
                    reference=value.reference,
                    chain=(*chain, hop),
                    detail=f"target registry value {current!r} is missing",
                )
            else:
                resolved = _replace_value(
                    value,
                    kind="text",
                    status="text-identity",
                    identity=TextDeviceIdentity(current),
                    reference=value.reference,
                    chain=(*chain, hop),
                    parse_basis=f"{TEXT_BASIS}: exact device path {current!r}",
                )
            break

        target = parsed[row_index[id(matches[0])]]
        hop = ReferenceHop(target.name, target.value_cell_offset, target.raw_hex)
        if target.kind == "ambiguous":
            resolved = _replace_value(
                value,
                kind="ambiguous",
                status="ambiguous",
                identity=None,
                reference=value.reference,
                chain=(*chain, hop),
                detail=f"target registry value {target.name!r} is itself ambiguous",
            )
            break

        chain.append(hop)
        if target.reference is not None:
            current = target.reference
            continue

        if target.identity is not None:
            resolved = _replace_value(
                value,
                kind=target.kind,
                status="reference",
                identity=target.identity,
                reference=value.reference,
                chain=tuple(chain),
                parse_basis=(
                    f"text reference to registry value {target.name!r}; "
                    f"identity taken from that value ({target.parse_basis})"
                ),
            )
        else:
            resolved = _replace_value(
                value,
                kind="unknown",
                status="unresolved",
                identity=None,
                reference=value.reference,
                chain=tuple(chain),
                detail=f"target registry value {target.name!r} has unknown data",
            )
        break

    return resolved


def _hop_for(
    name: str,
    by_key: dict[str, list[_Row]],
    row_index: dict[int, int],
    parsed: dict[int, MountedDeviceValue],
) -> ReferenceHop:
    matches = by_key.get(_alias_key(name), [])
    if len(matches) == 1:
        target = parsed[row_index[id(matches[0])]]
        return ReferenceHop(target.name, target.value_cell_offset, target.raw_hex)
    return ReferenceHop(name)


def _make_value(
    row: _Row,
    *,
    snapshot: str | None,
    alias: Literal["drive-letter", "volume-name", "other"],
    alias_key: str,
    kind: Literal["mbr", "gpt", "text", "unknown", "reference", "ambiguous"],
    status: Literal[
        "binary-identity",
        "text-identity",
        "reference",
        "unresolved",
        "cycle",
        "ambiguous",
        "unknown",
    ],
    identity: VolumeIdentity | None,
    parse_basis: str,
    reference: str | None = None,
    chain: tuple[ReferenceHop, ...] = (),
    detail: str | None = None,
) -> MountedDeviceValue:
    return MountedDeviceValue(
        name=row.name,
        alias=alias,
        alias_key=alias_key,
        raw=row.raw,
        value_type=int(row.value.type),
        value_cell_offset=row.value_cell_offset,
        data_cell_offset=_data_cell_offset(row),
        kind=kind,
        status=status,
        identity=identity,
        parse_basis=parse_basis,
        snapshot=snapshot,
        reference=reference,
        chain=chain,
        detail=detail,
    )


def _replace_value(value: MountedDeviceValue, **changes: object) -> MountedDeviceValue:
    return replace(value, **cast("dict[str, Any]", changes))


def _parse_identity(
    raw: bytes,
    value_type: int,
) -> tuple[
    VolumeIdentity | None,
    Literal["mbr", "gpt", "text", "unknown"],
    Literal["binary-identity", "text-identity", "unknown"],
    str,
]:
    if value_type != REG_BINARY:
        return (
            None,
            "unknown",
            "unknown",
            f"value type {value_type} is not REG_BINARY; original bytes retained without a binary identity",
        )

    if len(raw) == MBR_SIZE:
        disk_signature, partition_offset = struct.unpack("<IQ", raw)
        if disk_signature:
            return (
                MbrVolumeIdentity(disk_signature, partition_offset),
                "mbr",
                "binary-identity",
                f"{MBR_BASIS}; disk signature 0x{disk_signature:08x}, partition offset 0x{partition_offset:x}",
            )
        return (
            None,
            "unknown",
            "unknown",
            "12-byte layout with a zero disk signature is not a valid MBR identity; original bytes retained",
        )

    if len(raw) == GPT_SIZE and raw.startswith(GPT_PREFIX):
        partition_guid = uuid.UUID(bytes_le=raw[len(GPT_PREFIX) :])
        if partition_guid.int:
            return (
                GptVolumeIdentity(partition_guid),
                "gpt",
                "binary-identity",
                f"{GPT_BASIS}; partition GUID {partition_guid}",
            )
        return (
            None,
            "unknown",
            "unknown",
            f"{GPT_PREFIX!r} marker with a nil GUID is not a valid partition identity; original bytes retained",
        )

    return (
        None,
        "unknown",
        "unknown",
        f"{UNKNOWN_BASIS} ({len(raw)} bytes)",
    )


def _decode_text_reference(raw: bytes, value_type: int) -> str | None:
    if value_type != REG_BINARY or len(raw) < 4 or raw[0] != 0x5C:
        return None

    candidates: list[str] = []
    if raw[1] == 0x00:
        if len(raw) % 2 != 0:
            return None
        candidates.append("utf-16-le")
    else:
        candidates.append("latin1")

    for encoding in candidates:
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue

        text = text.rstrip("\x00")
        if not text.isprintable():
            continue
        if _TEXT_RE.match(text):
            return text

    return None


def _alias(name: str) -> tuple[Literal["drive-letter", "volume-name", "other"], str]:
    key = _alias_key(name)
    if key.startswith("drive:"):
        return "drive-letter", key
    if key.startswith("volume:"):
        return "volume-name", key
    return "other", key


def _alias_key(name: str) -> str:
    text = name.rstrip("\x00")
    if match := _DRIVE_RE.match(text):
        return f"drive:{match.group(1).upper()}"

    if match := _VOLUME_RE.match(text):
        return f"volume:{match.group(1).lower()}"

    return f"name:{text.casefold()}"


def _is_registry_alias(alias_key: str) -> bool:
    return alias_key.startswith(("drive:", "volume:"))


def _data_cell_offset(row: _Row) -> int | None:
    length = row.value.cell.DataLength
    if length & 0x80000000 or row.value.is_big_value:
        return None
    return int(row.value.cell.Data)


def _build_identity_records(values: tuple[MountedDeviceValue, ...]) -> tuple[IdentityRecord, ...]:
    grouped: dict[str, list[MountedDeviceValue]] = {}
    identities: dict[str, VolumeIdentity] = {}
    for value in values:
        if value.identity is None:
            continue
        grouped.setdefault(value.identity.canonical, []).append(value)
        identities.setdefault(value.identity.canonical, value.identity)

    return tuple(
        IdentityRecord(identity=identities[canonical], aliases=tuple(aliases))
        for canonical, aliases in sorted(grouped.items())
    )


def _find_conflicts(values: Iterable[MountedDeviceValue]) -> tuple[AliasConflict, ...]:
    by_alias: dict[str, list[MountedDeviceValue]] = {}
    for value in values:
        if value.identity is None:
            continue
        by_alias.setdefault(value.alias_key, []).append(value)

    conflicts: list[AliasConflict] = []
    for alias_key, aliases in by_alias.items():
        identity_keys = tuple(sorted({alias.identity.canonical for alias in aliases if alias.identity is not None}))
        if len(identity_keys) > 1:
            conflicts.append(
                AliasConflict(
                    alias_key=alias_key,
                    identity_keys=identity_keys,
                    values=tuple(aliases),
                    reason="one alias points to different identities; aliases must not be merged",
                )
            )

    return tuple(conflicts)
