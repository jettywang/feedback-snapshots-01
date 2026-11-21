"""Destination collision preflight and approved migration plans.

An archive records member names as opaque strings, but the file system that
receives them decides which strings denote the same file.  A case-insensitive
share folds ``Report.txt`` and ``report.txt`` together; a normalizing file
system also folds canonically equivalent Unicode spellings.  Extracting to such
a destination can silently overwrite one member with another, or with a file
that already exists there.

The objects here make that decision inspectable before anything is written.  A
:class:`DestinationProfile` describes the destination semantics, so a Windows or
macOS destination can be rehearsed on any host.
:meth:`py7zr.SevenZipFile.preflight_destination` returns a
:class:`PreflightReport` naming every colliding member; its
:class:`MigrationPlan` can be approved with a chosen policy and then passed to
:meth:`py7zr.SevenZipFile.extract` or
:meth:`py7zr.SevenZipFile.extractall`.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import posixpath
import sys
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from py7zr.exceptions import DestinationConflictError

CONFLICT_POLICIES = ("reject", "skip", "rename", "overwrite")


def _check_policy(policy: str) -> str:
    if policy not in CONFLICT_POLICIES:
        raise ValueError(f"policy must be one of {', '.join(CONFLICT_POLICIES)}; got {policy!r}")
    return policy


@dataclass(frozen=True)
class DestinationProfile:
    """Describe the file-name semantics of the destination file system.

    The profile is purely declarative: building one never touches the file
    system, so any platform can be rehearsed on any host.

    :param case_sensitive: ``False`` models a case-insensitive destination such
        as the default Windows or macOS volume.
    :param unicode_normalization: ``"NFC"``, ``"NFD"``, ``"NFKC"`` or
        ``"NFKD"`` when the destination folds canonically equivalent Unicode
        spellings, or ``None`` to compare code points as they are.
    :param strip_trailing_dots_and_spaces: ``True`` models Windows, which
        ignores trailing dots and spaces in a path component.
    :param name: A label included in reports; it has no effect on matching.
    """

    case_sensitive: bool = True
    unicode_normalization: str | None = None
    strip_trailing_dots_and_spaces: bool = False
    name: str = "custom"

    def __post_init__(self) -> None:
        if self.unicode_normalization is not None and self.unicode_normalization not in (
            "NFC",
            "NFD",
            "NFKC",
            "NFKD",
        ):
            raise ValueError(
                "unicode_normalization must be NFC, NFD, NFKC, NFKD or None; "
                f"got {self.unicode_normalization!r}"
            )

    @classmethod
    def for_platform(cls, platform: str) -> DestinationProfile:
        """Return the usual destination semantics for a platform name.

        Accepted names are ``"windows"`` (also ``"win32"``), ``"macos"``
        (also ``"darwin"``), ``"linux"`` and ``"posix"``.  The macOS preset
        describes the default case-insensitive, normalization-insensitive
        volume; a case-sensitive macOS volume is
        ``DestinationProfile(case_sensitive=True, unicode_normalization="NFD")``.
        """
        key = platform.lower()
        if key in ("windows", "win32", "nt"):
            # NTFS folds case and ignores trailing dots/spaces, but it does
            # not normalize Unicode: those spellings can coexist.
            return cls(
                case_sensitive=False,
                unicode_normalization=None,
                strip_trailing_dots_and_spaces=True,
                name="windows",
            )
        if key in ("macos", "mac", "darwin", "osx"):
            return cls(
                case_sensitive=False,
                unicode_normalization="NFD",
                strip_trailing_dots_and_spaces=False,
                name="macos",
            )
        if key in ("linux", "posix", "unix"):
            return cls(case_sensitive=True, unicode_normalization=None, name="linux")
        raise ValueError(f"unknown destination platform {platform!r}")

    @classmethod
    def native(cls) -> DestinationProfile:
        """Return the profile for the host platform."""
        if sys.platform.startswith("win"):
            return cls.for_platform("windows")
        if sys.platform == "darwin":
            return cls.for_platform("macos")
        return cls.for_platform("linux")

    @property
    def description(self) -> str:
        parts = ["case-sensitive" if self.case_sensitive else "case-insensitive"]
        if self.unicode_normalization is not None:
            parts.append(f"unicode={self.unicode_normalization}")
        if self.strip_trailing_dots_and_spaces:
            parts.append("trailing dots/spaces folded")
        return f"{self.name} ({', '.join(parts)})"


@dataclass(frozen=True)
class DestinationEntry:
    """A path that is already present at the destination.

    Existing entries are simulated: the destination is never read during a
    preflight.  This lets an operator describe a shared drive as it is today.
    """

    path: str
    is_directory: bool = False


@dataclass(frozen=True)
class DestinationMember:
    """One archive member as seen by a destination preflight."""

    index: int
    name: str
    is_directory: bool = False


@dataclass(frozen=True)
class ConflictMember:
    """A participant in a destination collision.

    *index* is the member's position in archive order (the same value as
    ``ArchiveFile.id``), so a report locates it even when two members share a
    name.  *target* is its path after destination spelling is applied.
    """

    index: int
    name: str
    is_directory: bool
    target: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "is_directory": self.is_directory,
            "target": self.target,
        }


@dataclass(frozen=True)
class DestinationConflict:
    """Two members, or a member and an existing entry, that land together.

    ``kind`` is one of ``"case"``, ``"unicode"``, ``"trailing"``,
    ``"duplicate"``, ``"directory"``, ``"existing"`` or ``"type"``.  A
    two-member conflict has both archive members in :attr:`members`; an
    existing-entry conflict has the archive member in :attr:`members` and the
    destination entry in :attr:`existing`.
    """

    kind: str
    key: str
    members: tuple[ConflictMember, ...]
    message: str
    existing: DestinationEntry | None = None

    @property
    def names(self) -> tuple[str, ...]:
        """Member names taking part in the conflict, in archive order."""
        return tuple(member.name for member in self.members)

    @property
    def indices(self) -> tuple[int, ...]:
        """Member indices taking part in the conflict, in archive order."""
        return tuple(member.index for member in self.members)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "kind": self.kind,
            "key": self.key,
            "members": [member.to_dict() for member in self.members],
            "message": self.message,
        }
        if self.existing is not None:
            result["existing"] = {
                "path": self.existing.path,
                "is_directory": self.existing.is_directory,
            }
        return result

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class PlannedMember:
    """The decision for one archive member in a :class:`MigrationPlan`."""

    index: int
    member: str
    output_name: str | None
    action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "member": self.member,
            "output_name": self.output_name,
            "action": self.action,
        }


@dataclass(frozen=True)
class MigrationPlan:
    """A concrete mapping from archive members to destination paths.

    A plan is built by :meth:`py7zr.SevenZipFile.preflight_destination` or
    :meth:`py7zr.SevenZipFile.plan_extraction`.  Extraction refuses a plan that
    is not approved or still has unresolved conflicts, and does so before the
    destination directory or a :class:`py7zr.WriterFactory` is touched.

    ``action`` is ``"extract"``, ``"overwrite"`` or ``"skip"``.  ``"overwrite"``
    means an archive member intentionally replaces the earlier member or the
    simulated existing entry at that path.
    """

    profile: DestinationProfile
    policy: str
    entries: tuple[PlannedMember, ...]
    conflicts: tuple[DestinationConflict, ...]
    unresolved: tuple[DestinationConflict, ...]
    archive_fingerprint: tuple[tuple[int, str, bool], ...]
    approved: bool = False

    @property
    def ok(self) -> bool:
        """``True`` when the plan is approved and has no unresolved conflicts."""
        return self.approved and not self.unresolved

    @property
    def conflict_count(self) -> int:
        return len(self.conflicts)

    def entry_for(self, member_index: int) -> PlannedMember | None:
        """Return the planned decision for a member index, or ``None``."""
        for entry in self.entries:
            if entry.index == member_index:
                return entry
        return None

    def effective_name(self, member_index: int) -> str | None:
        """Return the destination path planned for a member index.

        ``None`` means the member is skipped.
        """
        entry = self.entry_for(member_index)
        return None if entry is None else entry.output_name

    def approve(self) -> MigrationPlan:
        """Return an approved copy of this plan.

        :raises DestinationConflictError: If any conflict is unresolved.  Use
            another policy (for example ``"rename"`` or ``"skip"``) via
            :meth:`PreflightReport.approve` to resolve collisions explicitly.
        """
        if self.unresolved:
            raise DestinationConflictError(
                self.unresolved,
                "cannot approve a migration plan with unresolved conflicts; "
                "choose a policy such as 'rename' or 'skip'",
            )
        return dataclasses.replace(self, approved=True)

    def require_usable(self, archive_fingerprint: tuple[tuple[int, str, bool], ...]) -> None:
        """Validate this plan for extraction without touching the destination.

        :raises ValueError: If the plan was built for a different archive.
        :raises DestinationConflictError: If the plan is not approved or has
            unresolved conflicts.
        """
        if self.archive_fingerprint != archive_fingerprint:
            raise ValueError("migration plan was built for a different archive or archive version")
        if self.unresolved:
            raise DestinationConflictError(self.unresolved, "migration plan has unresolved destination conflicts")
        if not self.approved:
            raise DestinationConflictError(
                self.conflicts,
                "migration plan has not been approved; call PreflightReport.approve() first",
            )

    def summary(self) -> str:
        """Return a human-readable plan description."""
        status = "approved" if self.approved else "not approved"
        lines = [f"Migration plan ({self.profile.description}, policy={self.policy}, {status})"]
        for entry in self.entries:
            if entry.action == "skip":
                lines.append(f"- skip member {entry.index} {entry.member!r}")
            else:
                lines.append(f"- {entry.action} member {entry.index} {entry.member!r} -> {entry.output_name!r}")
        for conflict in self.unresolved:
            lines.append(f"! unresolved: {conflict}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.description,
            "policy": self.policy,
            "approved": self.approved,
            "entries": [entry.to_dict() for entry in self.entries],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "unresolved": [conflict.to_dict() for conflict in self.unresolved],
        }


@dataclass(frozen=True)
class PreflightReport:
    """The result of inspecting an archive against a destination profile.

    Building the report never writes.  :attr:`conflicts` locates every
    collision; :attr:`plan` holds the concrete decisions for the requested
    policy.  Call :meth:`approve` to obtain an approved plan, then pass it to
    extraction.
    """

    profile: DestinationProfile
    members: tuple[DestinationMember, ...]
    existing: tuple[DestinationEntry, ...]
    conflicts: tuple[DestinationConflict, ...]
    plan: MigrationPlan

    @property
    def ok(self) -> bool:
        """``True`` when no collision was found."""
        return not self.conflicts

    @property
    def conflict_count(self) -> int:
        return len(self.conflicts)

    def plan_for(self, policy: str) -> MigrationPlan:
        """Build a fresh plan for *policy* from the same inspection."""
        return _build_plan(self.profile, self.members, self.existing, _check_policy(policy))

    def approve(self, policy: str | None = None) -> MigrationPlan:
        """Return an approved plan, optionally under a different policy.

        With the default ``"reject"`` policy any collision remains unresolved.
        ``"rename"`` gives later members unique names, ``"skip"`` keeps the
        first member, and ``"overwrite"`` lets archive order decide.
        """
        return self.plan_for(policy or self.plan.policy).approve()

    def summary(self) -> str:
        """Return a human-readable report naming every conflicting member."""
        lines = [f"Destination preflight: {self.profile.description}"]
        if not self.conflicts:
            lines.append("No destination collisions.")
            return "\n".join(lines)
        lines.append(f"{len(self.conflicts)} destination collision(s):")
        for conflict in self.conflicts:
            lines.append(f"- {conflict.kind}: {conflict.message}")
        lines.append("")
        lines.append(self.plan.summary())
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.description,
            "ok": self.ok,
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "plan": self.plan.to_dict(),
        }


def _coerce_profile(destination: DestinationProfile | str | None) -> DestinationProfile:
    if destination is None:
        return DestinationProfile.native()
    if isinstance(destination, DestinationProfile):
        return destination
    if isinstance(destination, str):
        return DestinationProfile.for_platform(destination)
    raise TypeError("destination must be a DestinationProfile, a platform name, or None")


def _coerce_existing_entries(
    existing: Iterable[str | os.PathLike[str] | DestinationEntry]
    | Mapping[str | os.PathLike[str], bool]
    | None,
) -> tuple[DestinationEntry, ...]:
    """Normalize the ``existing`` argument into a tuple of entries."""
    if existing is None:
        return ()
    entries: list[DestinationEntry] = []
    if isinstance(existing, Mapping):
        for path, is_directory in existing.items():
            entries.append(DestinationEntry(os.fspath(path), bool(is_directory)))
        return tuple(entries)
    if isinstance(existing, (str, os.PathLike, DestinationEntry)):
        raise TypeError("existing must be an iterable of paths or DestinationEntry objects, not a single path")
    for item in existing:
        if isinstance(item, DestinationEntry):
            entries.append(item)
            continue
        path = os.fspath(item)
        if not isinstance(path, str):
            raise TypeError("existing paths must be strings or path-like objects")
        is_directory = path.endswith("/") or path.endswith(os.sep)
        if is_directory:
            path = path.rstrip("/" + os.sep)
        entries.append(DestinationEntry(path, is_directory))
    return tuple(entries)


def _split_parts(path: str) -> tuple[str, ...]:
    """Split an archive or destination path into meaningful components."""
    parts = pathlib.PurePosixPath(path).parts
    return tuple(part for part in parts if part not in ("", "."))


def _display_parts(profile: DestinationProfile, parts: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for part in parts:
        if profile.unicode_normalization is not None:
            part = unicodedata.normalize(profile.unicode_normalization, part)
        if profile.strip_trailing_dots_and_spaces:
            stripped = part.rstrip(" .")
            if stripped:
                part = stripped
        result.append(part)
    return tuple(result)


def _key_parts(profile: DestinationProfile, parts: tuple[str, ...]) -> tuple[str, ...]:
    display = _display_parts(profile, parts)
    if profile.case_sensitive:
        return display
    return tuple(part.casefold() for part in display)


def _key(profile: DestinationProfile, parts: tuple[str, ...]) -> str:
    return "/".join(_key_parts(profile, parts))


def _join_parts(parts: tuple[str, ...]) -> str:
    return "/".join(parts)


def _strip_trailing(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(part.rstrip(" .") for part in parts)


def _member_label(member: ConflictMember) -> str:
    kind = "directory" if member.is_directory else "member"
    return f"{kind} {member.index} {member.name!r}"


def _existing_label(entry: DestinationEntry) -> str:
    kind = "directory" if entry.is_directory else "file"
    return f"existing {kind} {entry.path!r}"


@dataclass
class _ScanMember:
    descriptor: DestinationMember
    parts: tuple[str, ...]
    target_parts: tuple[str, ...]

    @property
    def index(self) -> int:
        return self.descriptor.index

    @property
    def name(self) -> str:
        return self.descriptor.name

    @property
    def is_directory(self) -> bool:
        return self.descriptor.is_directory

    @property
    def target(self) -> str:
        return _join_parts(self.target_parts)

    def conflict_member(self) -> ConflictMember:
        return ConflictMember(self.index, self.name, self.is_directory, self.target)


class _Analysis:
    def __init__(self) -> None:
        self.conflicts: list[DestinationConflict] = []
        self.dir_first: dict[str, tuple[str, ...]] = {}
        self.dir_owner: dict[str, _ScanMember] = {}
        self.full_first: dict[str, _ScanMember] = {}
        self.existing_by_key: dict[str, DestinationEntry] = {}
        self.keys: set[str] = set()
        self.reported_directory_keys: set[str] = set()


def _append_conflict(analysis: _Analysis, seen: set[tuple], conflict: DestinationConflict) -> None:
    existing_key = None if conflict.existing is None else conflict.existing.path
    identity = (conflict.kind, conflict.key, conflict.indices, existing_key)
    if identity in seen:
        return
    seen.add(identity)
    analysis.conflicts.append(conflict)


def _analyze(
    profile: DestinationProfile,
    members: tuple[DestinationMember, ...],
    existing: tuple[DestinationEntry, ...],
) -> _Analysis:
    analysis = _Analysis()
    seen: set[tuple] = set()

    for entry in existing:
        parts = _split_parts(entry.path)
        if not parts:
            continue
        target_parts = _display_parts(profile, parts)
        analysis.existing_by_key[_key(profile, parts)] = entry
        limit = len(parts) if entry.is_directory else len(parts) - 1
        for i in range(1, limit + 1):
            prefix_key = _key(profile, parts[:i])
            analysis.keys.add(prefix_key)
            analysis.dir_first.setdefault(prefix_key, target_parts[:i])

    for descriptor in members:
        parts = _split_parts(descriptor.name)
        if not parts:
            continue
        target_parts = _display_parts(profile, parts)
        scan = _ScanMember(descriptor, parts, target_parts)
        full_key = _key(profile, parts)
        parent_count = len(parts) if descriptor.is_directory else len(parts) - 1

        for i in range(1, parent_count + 1):
            prefix_key = _key(profile, parts[:i])
            owner = analysis.full_first.get(prefix_key)
            if owner is not None and not owner.is_directory:
                owner_member = owner.conflict_member()
                scan_member = scan.conflict_member()
                _append_conflict(
                    analysis,
                    seen,
                    DestinationConflict(
                        "type",
                        prefix_key,
                        (owner_member, scan_member),
                        f"{_member_label(owner_member)} is a file but {_member_label(scan_member)} "
                        f"needs that path as a directory",
                    ),
                )
            existing_entry = analysis.existing_by_key.get(prefix_key)
            if existing_entry is not None and not existing_entry.is_directory:
                scan_member = scan.conflict_member()
                _append_conflict(
                    analysis,
                    seen,
                    DestinationConflict(
                        "type",
                        prefix_key,
                        (scan_member,),
                        f"{_existing_label(existing_entry)} blocks the directory needed by "
                        f"{_member_label(scan_member)}",
                        existing=existing_entry,
                    ),
                )

        existing_entry = analysis.existing_by_key.get(full_key)
        if existing_entry is not None and existing_entry.is_directory and descriptor.is_directory:
            # Merging into an existing destination directory is the normal
            # case for a migration and does not overwrite a file.
            existing_entry = None

        owner = analysis.full_first.get(full_key)
        if owner is not None:
            owner_member = owner.conflict_member()
            scan_member = scan.conflict_member()
            if owner.is_directory != descriptor.is_directory:
                kind = "type"
                message = (
                    f"{_member_label(owner_member)} and {_member_label(scan_member)} "
                    f"land on the same path {full_key!r} but have different types"
                )
            elif owner.is_directory:
                kind = "directory"
                message = (
                    f"{_member_label(owner_member)} and {_member_label(scan_member)} "
                    f"spell the same destination directory {full_key!r} differently"
                )
                analysis.reported_directory_keys.add(full_key)
            else:
                if owner.parts == parts:
                    kind = "duplicate"
                elif tuple(part.casefold() for part in owner.parts) == tuple(part.casefold() for part in parts):
                    kind = "case"
                elif _strip_trailing(owner.parts) == _strip_trailing(parts):
                    kind = "trailing"
                else:
                    kind = "unicode"
                message = (
                    f"{_member_label(owner_member)} and {_member_label(scan_member)} "
                    f"both land on destination path {full_key!r}"
                )
            _append_conflict(
                analysis,
                seen,
                DestinationConflict(kind, full_key, (owner_member, scan_member), message),
            )
        else:
            if existing_entry is not None:
                scan_member = scan.conflict_member()
                if existing_entry.is_directory == descriptor.is_directory:
                    message = (
                        f"{_member_label(scan_member)} lands on {_existing_label(existing_entry)} "
                        f"at destination path {full_key!r}"
                    )
                    _append_conflict(
                        analysis,
                        seen,
                        DestinationConflict("existing", full_key, (scan_member,), message, existing=existing_entry),
                    )
                else:
                    message = (
                        f"{_member_label(scan_member)} lands on {_existing_label(existing_entry)} "
                        f"at destination path {full_key!r}, and the types differ"
                    )
                    _append_conflict(
                        analysis,
                        seen,
                        DestinationConflict("type", full_key, (scan_member,), message, existing=existing_entry),
                    )

        analysis.full_first.setdefault(full_key, scan)
        analysis.keys.add(full_key)

        for i in range(1, parent_count + 1):
            prefix_key = _key(profile, parts[:i])
            first_spelling = analysis.dir_first.get(prefix_key)
            if first_spelling is None:
                analysis.dir_first[prefix_key] = target_parts[:i]
                analysis.dir_owner[prefix_key] = scan
                continue
            analysis.keys.add(prefix_key)
            if (
                first_spelling != target_parts[:i]
                and prefix_key not in analysis.reported_directory_keys
                and prefix_key in analysis.dir_owner
            ):
                owner_scan = analysis.dir_owner[prefix_key]
                owner_member = owner_scan.conflict_member()
                scan_member = scan.conflict_member()
                _append_conflict(
                    analysis,
                    seen,
                    DestinationConflict(
                        "directory",
                        prefix_key,
                        (owner_member, scan_member),
                        f"{_member_label(owner_member)} and {_member_label(scan_member)} "
                        f"need directory {prefix_key!r} spelled "
                        f"{_join_parts(first_spelling)!r} and {_join_parts(target_parts[:i])!r}",
                    ),
                )
                analysis.reported_directory_keys.add(prefix_key)

    return analysis


def _unresolved(analysis: _Analysis, policy: str) -> list[DestinationConflict]:
    if policy == "reject":
        return list(analysis.conflicts)
    unresolved: list[DestinationConflict] = []
    for conflict in analysis.conflicts:
        if conflict.kind == "directory":
            # Directory spellings are merged onto the first spelling under
            # every non-reject policy; no member is dropped.
            continue
        later = max(conflict.members, key=lambda member: member.index)
        if conflict.existing is not None:
            entry = conflict.existing
            existing_parts = _split_parts(entry.path)
            member_parts = _split_parts(later.name)
            exact = len(existing_parts) == len(member_parts)
            if policy == "skip":
                continue
            if policy == "overwrite":
                # Overwriting the contents of a file at the same path is
                # supported.  A directory cannot be replaced by a file or a
                # file by a directory without removing an existing entry, so
                # that stays unresolved.
                if exact and entry.is_directory == later.is_directory:
                    continue
                unresolved.append(conflict)
                continue
            if policy == "rename":
                # Renaming is a leaf operation.  An exact path (same or
                # different type) can be moved aside; a file blocking a parent
                # directory cannot.
                if exact:
                    continue
                unresolved.append(conflict)
                continue
        else:
            first = min(conflict.members, key=lambda member: member.index)
            second = max(conflict.members, key=lambda member: member.index)
            if policy == "skip":
                continue
            if conflict.kind == "type":
                # A type collision cannot be fixed by overwriting.  A later
                # file can be renamed away from an earlier directory, but a
                # later member that needs an earlier file as a directory
                # cannot.
                if policy == "rename" and first.is_directory and not second.is_directory:
                    continue
                unresolved.append(conflict)
                continue
            if policy in ("overwrite", "rename"):
                continue
    return unresolved


def _conflict_action(conflict: DestinationConflict, policy: str) -> tuple[int, str] | None:
    if policy == "reject" or conflict.kind == "directory":
        return None
    later = max(conflict.members, key=lambda member: member.index)
    if conflict.existing is not None:
        if policy in ("skip", "overwrite"):
            return later.index, policy
        if policy == "rename":
            return later.index, "rename"
        return None
    if policy in ("skip", "overwrite"):
        return later.index, policy
    if policy == "rename":
        return later.index, "rename"
    return None


def _canonical_parents(
    profile: DestinationProfile,
    parts: tuple[str, ...],
    dir_first: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    parents: tuple[str, ...] = ()
    for i in range(1, len(parts)):
        canonical = dir_first.get(_key(profile, parts[:i]))
        if canonical is not None:
            parents = canonical
    return parents


def _unique_target(
    profile: DestinationProfile,
    parent_parts: tuple[str, ...],
    filename: str,
    used_keys: set[str],
    is_directory: bool,
) -> str:
    if is_directory:
        stem, suffix = filename, ""
    else:
        stem, suffix = posixpath.splitext(filename)
    counter = 1
    while True:
        candidate = f"{stem}~{counter}{suffix}"
        candidate_parts = (*parent_parts, candidate)
        candidate_key = _key(profile, candidate_parts)
        if candidate_key not in used_keys:
            used_keys.add(candidate_key)
            return _join_parts(candidate_parts)
        counter += 1


def _build_plan(
    profile: DestinationProfile,
    members: tuple[DestinationMember, ...],
    existing: tuple[DestinationEntry, ...],
    policy: str,
) -> MigrationPlan:
    analysis = _analyze(profile, members, existing)
    unresolved = _unresolved(analysis, policy)
    unresolved_ids = {id(conflict) for conflict in unresolved}

    actions: dict[int, str] = {}
    for conflict in analysis.conflicts:
        if id(conflict) in unresolved_ids:
            continue
        action = _conflict_action(conflict, policy)
        if action is None:
            continue
        index, requested = action
        current = actions.get(index)
        if current is None or requested == "skip":
            actions[index] = requested

    used_keys = set(analysis.keys)
    entries: list[PlannedMember] = []
    for descriptor in members:
        parts = _split_parts(descriptor.name)
        if not parts:
            entries.append(PlannedMember(descriptor.index, descriptor.name, None, "skip"))
            continue
        target_parts = _display_parts(profile, parts)
        full_key = _key(profile, parts)
        parents = _canonical_parents(profile, parts, analysis.dir_first)
        action = actions.get(descriptor.index, "extract")
        if action == "skip":
            entries.append(PlannedMember(descriptor.index, descriptor.name, None, "skip"))
            continue
        if action == "rename":
            output = _unique_target(profile, parents, target_parts[-1], used_keys, descriptor.is_directory)
            entries.append(PlannedMember(descriptor.index, descriptor.name, output, "extract"))
            continue
        final_part = target_parts[-1]
        if descriptor.is_directory:
            canonical_dir = analysis.dir_first.get(full_key)
            if canonical_dir is not None:
                final_part = canonical_dir[-1]
        output = _join_parts((*parents, final_part))
        if action == "overwrite" and analysis.full_first.get(full_key) is not None:
            entries.append(PlannedMember(descriptor.index, descriptor.name, output, "overwrite"))
        else:
            entries.append(PlannedMember(descriptor.index, descriptor.name, output, "extract"))

    fingerprint = tuple((member.index, member.name, member.is_directory) for member in members)
    return MigrationPlan(
        profile=profile,
        policy=policy,
        entries=tuple(entries),
        conflicts=tuple(analysis.conflicts),
        unresolved=tuple(unresolved),
        archive_fingerprint=fingerprint,
        approved=not analysis.conflicts,
    )


def preflight(
    members: Iterable[DestinationMember],
    *,
    destination: DestinationProfile | str | None = None,
    existing: Iterable[str | os.PathLike[str] | DestinationEntry]
    | Mapping[str | os.PathLike[str], bool]
    | None = None,
    policy: str = "reject",
) -> PreflightReport:
    """Inspect members against a destination without writing anything.

    This is the library-level entry point used by
    :meth:`py7zr.SevenZipFile.preflight_destination`; it is useful for callers
    that hold member metadata without an open archive.

    :param members: The archive members to inspect, in archive order.
    :param destination: A :class:`DestinationProfile`, a platform name, or
        ``None`` for the host platform.
    :param existing: Paths already present at the destination.  A string ending
        in a separator is treated as a directory; use :class:`DestinationEntry`
        to state the type explicitly.  A mapping of path to ``is_directory`` is
        also accepted.
    :param policy: ``"reject"``, ``"skip"``, ``"rename"`` or ``"overwrite"``.
    :return: A :class:`PreflightReport`.
    """
    selected_profile = _coerce_profile(destination)
    selected_policy = _check_policy(policy)
    member_tuple = tuple(members)
    existing_tuple = _coerce_existing_entries(existing)
    plan = _build_plan(selected_profile, member_tuple, existing_tuple, selected_policy)
    return PreflightReport(
        profile=selected_profile,
        members=member_tuple,
        existing=existing_tuple,
        conflicts=plan.conflicts,
        plan=plan,
    )
