"""Read-only forensic comparison of two 7z archives.

This module compares two archives without extracting member data to disk.  Every
member that can be read is decompressed in memory straight into a SHA-256
calculator; the plaintext is discarded as soon as it has been hashed.  The
result separates three questions that are easy to confuse when the same
document arrives twice in different wrappers:

* did the member *content* really change,
* did only the archive packaging change (compression method, timestamps,
  attributes, solid layout, and so on), or
* could the content not be verified at all.

The entry point is :func:`compare_archives`; the result is an
:class:`ArchiveComparison` whose ``members`` are :class:`MemberDiff` objects.
"""

from __future__ import annotations

import enum
import hashlib
import os
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from py7zr.compressor import get_methods_names
from py7zr.exceptions import PasswordRequired, UnsupportedCompressionMethodError
from py7zr.helpers import get_sanitized_output_path
from py7zr.io import Py7zIO, WriterFactory
from py7zr.py7zr import SevenZipFile

__all__ = [
    "ArchiveComparison",
    "ArchiveSnapshot",
    "MemberCategory",
    "MemberDiff",
    "MemberSnapshot",
    "MemberVerdict",
    "compare_archives",
]

COMPARISON_FORMAT = "py7zr-archive-comparison-v1"

# The order is used for the ``changes`` tuple and for rendered reports, so that
# two runs over the same pair of archives produce byte-identical output.
_CHANGE_ORDER = (
    "member_type",
    "sha256",
    "size",
    "crc32",
    "creationtime",
    "lastwritetime",
    "lastaccesstime",
    "attributes",
    "posix_mode",
    "methods",
    "compressed_size",
    "solid",
)


class MemberVerdict(enum.Enum):
    """The outcome of comparing one member (name and occurrence) across sides."""

    IDENTICAL = "identical"
    PACKAGING_CHANGED = "packaging_changed"
    CONTENT_CHANGED = "content_changed"
    ADDED = "added"
    REMOVED = "removed"
    UNVERIFIABLE = "unverifiable"

    @property
    def is_content_change(self) -> bool:
        """True for verdicts that represent a confirmed change of member set/content."""
        return self in (MemberVerdict.CONTENT_CHANGED, MemberVerdict.ADDED, MemberVerdict.REMOVED)


class MemberCategory(enum.Enum):
    """The three-way grouping required from a forensic comparison."""

    CONTENT_CHANGED = "content_changed"
    PACKAGING_ONLY = "packaging_only"
    UNVERIFIABLE = "unverifiable"
    IDENTICAL = "identical"


@dataclass(frozen=True)
class MemberSnapshot:
    """Metadata and content digest for one member on one side.

    ``sha256`` is ``None`` when the member's content could not be read or hashed;
    in that case ``error`` explains why.  Directories and sockets carry no
    content digest by definition.
    """

    name: str
    occurrence: int
    kind: str
    size: int | None
    compressed: int | None
    crc32: int | None
    creationtime: int | None
    lastwritetime: int | None
    lastaccesstime: int | None
    attributes: int | None
    posix_mode: int | None
    methods: tuple[str, ...]
    solid: bool | None
    sha256: str | None
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "occurrence": self.occurrence,
            "kind": self.kind,
            "size": self.size,
            "compressed": self.compressed,
            "crc32": self.crc32,
            "creationtime": self.creationtime,
            "lastwritetime": self.lastwritetime,
            "lastaccesstime": self.lastaccesstime,
            "attributes": self.attributes,
            "posix_mode": self.posix_mode,
            "methods": list(self.methods),
            "solid": self.solid,
            "sha256": self.sha256,
            "error": self.error,
        }


@dataclass(frozen=True)
class MemberDiff:
    """Comparison of one member (identified by name *and* occurrence)."""

    name: str
    occurrence: int
    verdict: MemberVerdict
    left: MemberSnapshot | None
    right: MemberSnapshot | None
    changes: tuple[str, ...] = ()
    evidence: str | None = None
    notes: tuple[str, ...] = ()

    @property
    def category(self) -> MemberCategory:
        if self.verdict.is_content_change:
            return MemberCategory.CONTENT_CHANGED
        if self.verdict is MemberVerdict.PACKAGING_CHANGED:
            return MemberCategory.PACKAGING_ONLY
        if self.verdict is MemberVerdict.UNVERIFIABLE:
            return MemberCategory.UNVERIFIABLE
        return MemberCategory.IDENTICAL

    @property
    def display_name(self) -> str:
        """Name with an occurrence suffix when the archive stores duplicates."""
        if self.occurrence == 0:
            return self.name
        return f"{self.name}#{self.occurrence + 1}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "occurrence": self.occurrence,
            "verdict": self.verdict.value,
            "category": self.category.value,
            "changes": list(self.changes),
            "evidence": self.evidence,
            "notes": list(self.notes),
            "left": self.left.to_dict() if self.left is not None else None,
            "right": self.right.to_dict() if self.right is not None else None,
        }


@dataclass(frozen=True)
class ArchiveSnapshot:
    """Observable wrapper metadata for one archive."""

    path: str
    exists: bool
    size: int | None
    header_size: int | None
    methods: tuple[str, ...]
    solid: bool | None
    blocks: int | None
    member_count: int | None
    encrypted: bool | None
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "size": self.size,
            "header_size": self.header_size,
            "methods": list(self.methods),
            "solid": self.solid,
            "blocks": self.blocks,
            "member_count": self.member_count,
            "encrypted": self.encrypted,
            "error": self.error,
        }


@dataclass
class ArchiveComparison:
    """Result of :func:`compare_archives`.

    ``members`` covers the union of member names on both sides, in left archive
    order followed by members that exist only on the right.  Duplicate names
    are matched by occurrence so that each entry is traceable to one specific
    member, not merely to a name that appears more than once.
    """

    left: ArchiveSnapshot
    right: ArchiveSnapshot
    members: tuple[MemberDiff, ...]
    archive_changes: tuple[str, ...] = ()
    format: str = COMPARISON_FORMAT

    @property
    def content_changes(self) -> tuple[MemberDiff, ...]:
        """Members whose content or presence was confirmed to change."""
        return tuple(m for m in self.members if m.category is MemberCategory.CONTENT_CHANGED)

    @property
    def packaging_changes(self) -> tuple[MemberDiff, ...]:
        """Members whose content is verified equal but whose wrapper metadata differs."""
        return tuple(m for m in self.members if m.category is MemberCategory.PACKAGING_ONLY)

    @property
    def unverifiable(self) -> tuple[MemberDiff, ...]:
        """Members whose content could not be verified on at least one side."""
        return tuple(m for m in self.members if m.category is MemberCategory.UNVERIFIABLE)

    @property
    def identical(self) -> tuple[MemberDiff, ...]:
        """Members that are byte-for-byte and metadata identical on both sides."""
        return tuple(m for m in self.members if m.category is MemberCategory.IDENTICAL)

    @property
    def has_content_changes(self) -> bool:
        return bool(self.content_changes)

    @property
    def has_unverifiable(self) -> bool:
        return bool(self.unverifiable)

    @property
    def only_packaging_changes(self) -> bool:
        """True when every member was verified and none changed content."""
        return not self.has_content_changes and not self.has_unverifiable

    @property
    def has_archive_errors(self) -> bool:
        return self.left.error is not None or self.right.error is not None

    def summary(self) -> dict[str, int]:
        return {
            "members": len(self.members),
            "content_changed": len(self.content_changes),
            "packaging_changed": len(self.packaging_changes),
            "unverifiable": len(self.unverifiable),
            "identical": len(self.identical),
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable evidence record (digests, no plaintext)."""
        return {
            "format": self.format,
            "read_only": True,
            "digest_algorithm": "sha256",
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
            "archive_changes": list(self.archive_changes),
            "summary": self.summary(),
            "members": [m.to_dict() for m in self.members],
        }

    def format_text(self, *, show_identical: bool = False) -> str:
        """Render the comparison as a human-readable report."""
        lines: list[str] = []
        lines.append("Archive comparison (read-only; member data is hashed in memory, never written out)")
        lines.append(f"  left : {_describe_archive(self.left)}")
        lines.append(f"  right: {_describe_archive(self.right)}")
        if self.left.error is not None:
            lines.append(f"  left error : {self.left.error}")
        if self.right.error is not None:
            lines.append(f"  right error: {self.right.error}")
        if self.archive_changes:
            lines.append(f"  wrapper changes: {', '.join(self.archive_changes)}")
        lines.append("")

        groups = (
            ("Content changed", self.content_changes),
            ("Packaging only", self.packaging_changes),
            ("Unverifiable", self.unverifiable),
        )
        for title, members in groups:
            lines.append(f"{title} ({len(members)})")
            if not members:
                lines.append("  (none)")
            for member in members:
                lines.append(f"  {_format_member(member)}")
            lines.append("")
        if show_identical:
            lines.append(f"Identical ({len(self.identical)})")
            for member in self.identical:
                lines.append(f"  {member.display_name}")
            lines.append("")

        summary = self.summary()
        lines.append(
            "Summary: {content_changed} content changed, {packaging_changed} packaging only, "
            "{unverifiable} unverifiable, {identical} identical".format(**summary)
        )
        return "\n".join(lines)


def compare_archives(
    left: str | os.PathLike[str],
    right: str | os.PathLike[str],
    *,
    password: str | None = None,
) -> ArchiveComparison:
    """Compare two 7z archives without extracting anything to a file.

    Both archives are opened read-only.  Every member that can be decompressed
    is streamed through a SHA-256 calculator and the plaintext is discarded;
    no temporary or output files are created.  A member's content is considered
    verified only when both sides produced a complete digest.  If a side cannot
    be read -- encrypted without a password, unsupported method, corrupt stream,
    or an unreadable archive file -- the member is reported as ``unverifiable``
    rather than guessed at.

    :param left: Path to the baseline archive.
    :param right: Path to the received archive.
    :param password: Optional password applied to both archives.  Without it,
        encrypted members are reported as unverifiable.
    :return: An :class:`ArchiveComparison`.
    """
    left_snapshot, left_members = _inspect_archive(left, password)
    right_snapshot, right_members = _inspect_archive(right, password)

    keys: list[tuple[str, int]] = list(left_members)
    keys.extend(key for key in right_members if key not in left_members)

    members: list[MemberDiff] = []
    left_failed = left_snapshot.error is not None
    right_failed = right_snapshot.error is not None
    for key in keys:
        left_member = left_members.get(key)
        right_member = right_members.get(key)
        members.append(_compare_member(left_member, right_member, left_failed=left_failed, right_failed=right_failed))

    archive_changes = _compare_wrappers(left_snapshot, right_snapshot)
    return ArchiveComparison(
        left=left_snapshot,
        right=right_snapshot,
        members=tuple(members),
        archive_changes=archive_changes,
    )


# ---------------------------------------------------------------------------
# Internal: reading one side


@dataclass
class _Record:
    name: str
    occurrence: int
    kind: str
    size: int | None
    compressed: int | None
    crc32: int | None
    creationtime: int | None
    lastwritetime: int | None
    lastaccesstime: int | None
    attributes: int | None
    posix_mode: int | None
    methods: tuple[str, ...]
    solid: bool | None
    error: str | None = None

    @property
    def key(self) -> tuple[str, int]:
        return (self.name, self.occurrence)


class _DigestIO(Py7zIO):
    """Discard member plaintext after updating a SHA-256 and CRC-32."""

    __slots__ = ("filename", "_size", "_sha256", "_crc32", "complete")

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self._size = 0
        self._sha256 = hashlib.sha256()
        self._crc32 = 0
        self.complete = False

    def write(self, s: bytes | bytearray) -> int:
        self._size += len(s)
        self._sha256.update(s)
        self._crc32 = zlib.crc32(s, self._crc32)
        return len(s)

    def read(self, size: int | None = None) -> bytes:
        return b""

    def seek(self, offset: int, whence: int = 0) -> int:
        return 0

    def flush(self) -> None:
        return None

    def size(self) -> int:
        return self._size

    def close(self) -> None:
        self.complete = True

    @property
    def sha256(self) -> str:
        return self._sha256.hexdigest()

    @property
    def crc32(self) -> int:
        return self._crc32 & 0xFFFFFFFF


class _DigestFactory(WriterFactory):
    def __init__(self) -> None:
        self.products: dict[str, _DigestIO] = {}

    def create(self, filename: str) -> Py7zIO:
        product = _DigestIO(filename)
        self.products[filename] = product
        return product

    def digest(self, filename: str) -> _DigestIO | None:
        product = self.products.get(filename)
        if product is not None and product.complete:
            return product
        return None


def _describe_exception(exc: BaseException) -> str:
    if isinstance(exc, PasswordRequired):
        return "PasswordRequired: encrypted content needs a password"
    if isinstance(exc, UnsupportedCompressionMethodError):
        return "UnsupportedCompressionMethodError: unsupported compression method"
    message = str(exc).strip()
    if isinstance(exc, OSError) and len(message) > 200:
        message = message[:197] + "..."
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):  # pragma: no-cover
        return None


def _member_kind(member: Any) -> str:
    if member.is_directory:
        return "directory"
    if member.is_symlink:
        return "symlink"
    if member.is_socket:
        return "socket"
    if member.is_file:
        return "file"
    return "special"


def _member_methods(member: Any) -> tuple[str, ...]:
    folder = getattr(member, "folder", None)
    if folder is None or not getattr(folder, "coders", None):
        return ()
    try:
        return tuple(get_methods_names([folder.coders]))
    except Exception:  # pragma: no-cover - unknown coder ids
        return ()


def _make_records(files: Iterable[Any]) -> list[_Record]:
    records: list[_Record] = []
    counts: dict[str, int] = {}
    for member in files:
        name = member.filename
        occurrence = counts.get(name, 0)
        counts[name] = occurrence + 1
        properties = member.file_properties()
        folder = getattr(member, "folder", None)
        records.append(
            _Record(
                name=name,
                occurrence=occurrence,
                kind=_member_kind(member),
                size=_as_int(member.uncompressed),
                compressed=_as_int(member.compressed),
                crc32=_as_int(member.crc32),
                creationtime=_as_int(properties.get("creationtime")),
                lastwritetime=_as_int(properties.get("lastwritetime")),
                lastaccesstime=_as_int(properties.get("lastaccesstime")),
                attributes=_as_int(properties.get("attributes")),
                posix_mode=_as_int(member.posix_mode),
                methods=_member_methods(member),
                solid=bool(getattr(folder, "solid", False)) if folder is not None else None,
            )
        )
    return records


def _expected_output_key(record: _Record) -> str | None:
    """Mirror :meth:`SevenZipFile._extract`'s output naming and sanitisation."""
    outname = record.name if record.occurrence == 0 else f"{record.name}_{record.occurrence - 1}"
    try:
        return get_sanitized_output_path(outname, None).as_posix()
    except Exception as exc:
        record.error = _describe_exception(exc)
        return None


def _collect_digests(archive: SevenZipFile, records: list[_Record]) -> dict[tuple[str, int], _DigestIO]:
    expected: dict[tuple[str, int], str] = {}
    for record in records:
        if record.kind in ("directory", "socket"):
            continue
        key = _expected_output_key(record)
        if key is not None:
            expected[record.key] = key

    factory = _DigestFactory()
    full_pass_error: str | None = None
    if expected:
        try:
            archive.extractall(factory=factory)
        except Exception as exc:
            full_pass_error = _describe_exception(exc)

    results: dict[tuple[str, int], _DigestIO] = {}
    missing: list[_Record] = []
    for record in records:
        if record.kind in ("directory", "socket"):
            continue
        key = expected.get(record.key)
        product = factory.digest(key) if key is not None else None
        if product is not None:
            results[record.key] = product
        else:
            missing.append(record)

    if missing:
        _retry_missing(archive, missing, expected, results, full_pass_error)
    return results


def _retry_missing(
    archive: SevenZipFile,
    missing: list[_Record],
    expected: dict[tuple[str, int], str],
    results: dict[tuple[str, int], _DigestIO],
    full_pass_error: str | None,
) -> None:
    """Re-read individual names after a whole-archive pass failed part way.

    Members that failed together in one solid block can then be reported one by
    one, and a bad member no longer hides the verdict for its neighbours.
    """
    # A member may share its name with one that the first pass did read, so retry
    # every missing record rather than skipping names already seen.
    by_name: dict[str, list[_Record]] = {}
    name_order: list[str] = []
    for record in missing:
        if record.error is not None:
            continue
        if record.name not in by_name:
            by_name[record.name] = []
            name_order.append(record.name)
        by_name[record.name].append(record)

    attempted = False
    for name in name_order:
        try:
            archive.reset()
        except Exception as exc:  # pragma: no-cover - defensive
            for record in by_name[name]:
                record.error = _describe_exception(exc)
            continue
        factory = _DigestFactory()
        retry_error: str | None = None
        attempted = True
        try:
            archive.extract(targets=[name], factory=factory)
        except Exception as exc:
            retry_error = _describe_exception(exc)
        for record in by_name[name]:
            key = expected.get(record.key)
            product = factory.digest(key) if key is not None else None
            if product is not None:
                results[record.key] = product
                record.error = None
            elif record.error is None:
                record.error = retry_error or full_pass_error or "content digest unavailable"

    if not attempted:
        for record in missing:
            if record.key not in results and record.error is None:
                record.error = full_pass_error or "content digest unavailable"


def _snapshot_from_record(record: _Record, product: _DigestIO | None) -> MemberSnapshot:
    digest = product.sha256 if product is not None and product.complete else None
    error = record.error
    if digest is None and error is None and record.kind not in ("directory", "socket"):
        error = "content digest unavailable"
    return MemberSnapshot(
        name=record.name,
        occurrence=record.occurrence,
        kind=record.kind,
        size=record.size,
        compressed=record.compressed,
        crc32=product.crc32 if product is not None and product.complete else record.crc32,
        creationtime=record.creationtime,
        lastwritetime=record.lastwritetime,
        lastaccesstime=record.lastaccesstime,
        attributes=record.attributes,
        posix_mode=record.posix_mode,
        methods=record.methods,
        solid=record.solid,
        sha256=digest,
        error=error,
    )


def _inspect_archive(
    path: str | os.PathLike[str], password: str | None
) -> tuple[ArchiveSnapshot, dict[tuple[str, int], MemberSnapshot]]:
    path_str = os.fspath(path)
    exists = os.path.exists(path_str)
    try:
        physical_size: int | None = os.stat(path_str).st_size
    except OSError:
        physical_size = None

    error: str | None = None
    try:
        archive = SevenZipFile(path_str, "r", password=password)
    except Exception as exc:
        error = _describe_exception(exc)
        snapshot = ArchiveSnapshot(
            path=path_str,
            exists=exists,
            size=physical_size,
            header_size=None,
            methods=(),
            solid=None,
            blocks=None,
            member_count=None,
            encrypted=None,
            error=error,
        )
        return snapshot, {}

    try:
        try:
            header = getattr(archive, "header", None)
            files = list(getattr(archive, "files", []) or [])
            try:
                methods = tuple(archive._get_method_names())
            except Exception:
                methods = ()
            try:
                solid = bool(archive._is_solid())
            except Exception:  # pragma: no-cover - defensive
                solid = None
            if header is not None and getattr(header, "main_streams", None) is not None:
                blocks = len(header.main_streams.unpackinfo.folders)
                header_size = header.size
            else:
                blocks = 0
                header_size = getattr(header, "size", None)
            records = _make_records(files)
            products = _collect_digests(archive, records)
            members = {record.key: _snapshot_from_record(record, products.get(record.key)) for record in records}
        except Exception as exc:
            # Metadata that cannot even be enumerated is reported as a failure of
            # this side; comparison still proceeds from whatever the other side has.
            error = _describe_exception(exc)
            snapshot = ArchiveSnapshot(
                path=path_str,
                exists=exists,
                size=physical_size,
                header_size=None,
                methods=(),
                solid=None,
                blocks=None,
                member_count=None,
                encrypted=None,
                error=error,
            )
            return snapshot, {}
        snapshot = ArchiveSnapshot(
            path=path_str,
            exists=exists,
            size=physical_size,
            header_size=header_size,
            methods=methods,
            solid=solid,
            blocks=blocks,
            member_count=len(records),
            encrypted=bool(getattr(archive, "password_protected", False)),
            error=None,
        )
        return snapshot, members
    finally:
        archive.close()
        # archive.close() deletes the attribute workspace; nothing else is touched.


# ---------------------------------------------------------------------------
# Internal: comparing two sides


def _metadata_changes(left: MemberSnapshot, right: MemberSnapshot) -> tuple[str, ...]:
    changes: list[str] = []

    def add(name: str) -> None:
        if name not in changes:
            changes.append(name)

    for name in ("creationtime", "lastwritetime", "lastaccesstime", "attributes", "posix_mode"):
        left_value = getattr(left, name)
        right_value = getattr(right, name)
        if left_value is not None and right_value is not None and left_value != right_value:
            add(name)
    if left.methods != right.methods:
        add("methods")
    if left.solid is not None and right.solid is not None and left.solid != right.solid:
        add("solid")
    if left.compressed is not None and right.compressed is not None and left.compressed != right.compressed:
        add("compressed_size")
    if left.crc32 is not None and right.crc32 is not None and left.crc32 != right.crc32:
        add("crc32")
    return _sorted_changes(changes)


def _sorted_changes(changes: Iterable[str]) -> tuple[str, ...]:
    unique = set(changes)
    return tuple(sorted(unique, key=lambda name: _CHANGE_ORDER.index(name) if name in _CHANGE_ORDER else len(_CHANGE_ORDER)))


def _unverifiable_notes(left: MemberSnapshot | None, right: MemberSnapshot | None) -> tuple[str, ...]:
    notes: list[str] = []
    for side_name, member in (("left", left), ("right", right)):
        if member is None:
            notes.append(f"{side_name}: member absent")
        elif member.kind == "socket":
            notes.append(f"{side_name}: socket member has no content to verify")
        elif member.sha256 is None:
            reason = member.error or "content digest unavailable"
            notes.append(f"{side_name}: {reason}")
    return tuple(dict.fromkeys(notes))


def _compare_member(
    left: MemberSnapshot | None,
    right: MemberSnapshot | None,
    *,
    left_failed: bool = False,
    right_failed: bool = False,
) -> MemberDiff:
    name = left.name if left is not None else right.name  # type: ignore[union-attr]
    occurrence = left.occurrence if left is not None else right.occurrence  # type: ignore[union-attr]

    if left is None and right is not None:
        if right.sha256 is None and right.kind in ("file", "symlink"):
            return MemberDiff(
                name,
                occurrence,
                MemberVerdict.UNVERIFIABLE,
                None,
                right,
                notes=_unverifiable_notes(None, right),
            )
        if right_failed:
            return MemberDiff(
                name,
                occurrence,
                MemberVerdict.UNVERIFIABLE,
                None,
                right,
                notes=("right: archive could not be read, so absence on the left proves nothing",),
            )
        return MemberDiff(name, occurrence, MemberVerdict.ADDED, None, right)
    if right is None and left is not None:
        if left.sha256 is None and left.kind in ("file", "symlink"):
            return MemberDiff(
                name,
                occurrence,
                MemberVerdict.UNVERIFIABLE,
                left,
                None,
                notes=_unverifiable_notes(left, None),
            )
        if right_failed:
            return MemberDiff(
                name,
                occurrence,
                MemberVerdict.UNVERIFIABLE,
                left,
                None,
                notes=("right: archive could not be read, so absence on the right proves nothing",),
            )
        return MemberDiff(name, occurrence, MemberVerdict.REMOVED, left, None)
    assert left is not None and right is not None

    if left.kind != right.kind:
        return MemberDiff(
            name,
            occurrence,
            MemberVerdict.CONTENT_CHANGED,
            left,
            right,
            changes=("member_type",),
            evidence="member_type",
            notes=(f"member type {left.kind} -> {right.kind}",),
        )

    if left.kind in ("directory", "socket"):
        metadata = _metadata_changes(left, right)
        if left.kind == "socket":
            return MemberDiff(
                name,
                occurrence,
                MemberVerdict.UNVERIFIABLE,
                left,
                right,
                changes=metadata,
                notes=("socket member has no content to verify",),
            )
        if metadata:
            return MemberDiff(name, occurrence, MemberVerdict.PACKAGING_CHANGED, left, right, changes=metadata)
        return MemberDiff(name, occurrence, MemberVerdict.IDENTICAL, left, right)

    # Rows below are regular files and symlinks (symlink target bytes are content).
    if left.sha256 is not None and right.sha256 is not None:
        if left.sha256 != right.sha256:
            changes = ["sha256"]
            if left.size is not None and right.size is not None and left.size != right.size:
                changes.append("size")
            if left.kind == "symlink":
                notes: tuple[str, ...] = ("symlink target changed",)
            else:
                notes = ()
            return MemberDiff(
                name,
                occurrence,
                MemberVerdict.CONTENT_CHANGED,
                left,
                right,
                changes=_sorted_changes(changes),
                evidence="sha256",
                notes=notes,
            )
        metadata = _metadata_changes(left, right)
        if metadata:
            return MemberDiff(name, occurrence, MemberVerdict.PACKAGING_CHANGED, left, right, changes=metadata)
        return MemberDiff(name, occurrence, MemberVerdict.IDENTICAL, left, right)

    # Content could not be hashed on at least one side.  Only an exact size or a
    # stored CRC difference can still prove a content change; anything else is
    # explicitly unverifiable rather than assumed equal.
    if left.size is not None and right.size is not None and left.size != right.size:
        return MemberDiff(
            name,
            occurrence,
            MemberVerdict.CONTENT_CHANGED,
            left,
            right,
            changes=("size",),
            evidence="size",
            notes=("content digest unavailable; size in the header differs",),
        )
    if left.crc32 is not None and right.crc32 is not None and left.crc32 != right.crc32:
        return MemberDiff(
            name,
            occurrence,
            MemberVerdict.CONTENT_CHANGED,
            left,
            right,
            changes=("crc32",),
            evidence="crc32",
            notes=("content digest unavailable; stored CRC32 differs",),
        )
    return MemberDiff(
        name,
        occurrence,
        MemberVerdict.UNVERIFIABLE,
        left,
        right,
        changes=_metadata_changes(left, right),
        notes=_unverifiable_notes(left, right),
    )


def _compare_wrappers(left: ArchiveSnapshot, right: ArchiveSnapshot) -> tuple[str, ...]:
    if left.error is not None or right.error is not None:
        return ()
    changes: list[str] = []
    if left.methods != right.methods:
        changes.append("methods")
    for name in ("solid", "blocks", "member_count", "size", "header_size", "encrypted"):
        left_value = getattr(left, name)
        right_value = getattr(right, name)
        if left_value is not None and right_value is not None and left_value != right_value:
            changes.append(name)
    return tuple(changes)


# ---------------------------------------------------------------------------
# Internal: text rendering


def _describe_archive(snapshot: ArchiveSnapshot) -> str:
    if snapshot.error is not None:
        return f"{snapshot.path} (unreadable)"
    methods = ", ".join(snapshot.methods) if snapshot.methods else "no compressed stream"
    solid = "solid" if snapshot.solid else "not solid"
    return f"{snapshot.path} ({methods}; {solid}; {snapshot.member_count} members)"


def _format_member(member: MemberDiff) -> str:
    parts = [f"[{member.verdict.value}] {member.display_name}"]
    if member.left is not None and member.right is not None:
        if member.left.sha256 is not None and member.right.sha256 is not None:
            if member.left.sha256 == member.right.sha256:
                parts.append(f"sha256 {member.left.sha256}")
            else:
                parts.append(f"sha256 {member.left.sha256} -> {member.right.sha256}")
        if member.left.size is not None and member.right.size is not None and member.left.size != member.right.size:
            parts.append(f"size {member.left.size} -> {member.right.size}")
    elif member.left is not None:
        parts.append("only in left")
    elif member.right is not None:
        parts.append("only in right")
    if member.changes:
        parts.append(f"changes: {', '.join(member.changes)}")
    if member.notes:
        parts.append("; ".join(member.notes))
    if member.left is not None and member.right is not None:
        for side_name, side in (("left", member.left), ("right", member.right)):
            if side.error is not None and not any(side.error in note for note in member.notes):
                parts.append(f"{side_name}: {side.error}")
    return "  ".join(parts)
