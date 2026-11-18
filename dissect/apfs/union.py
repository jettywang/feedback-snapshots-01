from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Sequence
from uuid import UUID

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import (
    FirmlinkConflictError,
    FirmlinkTargetError,
    UnionFileNotFoundError,
    UnionNotADirectoryError,
    UnionPathTraversalError,
    UnionSymlinkLoopError,
    UnionSymlinkTargetError,
    UnionVolumeUnavailableError,
    VolumeGroupError,
    VolumeGroupIdentityError,
    VolumeGroupMismatchError,
    VolumeGroupRoleError,
    VolumeGroupSelectionError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.apfs.objects.fs import FS, INode

PathLike = str | bytes | Sequence[str]

_DATA_MOUNT_PREFIX = "/System/Volumes/Data"
_DATA_MOUNT_PARTS = ("System", "Volumes", "Data")
_MAX_SYMLINKS = 40


@dataclass(frozen=True, slots=True)
class FirmlinkMapping:
    """A single System-to-Data firmlink mapping supplied by the caller.

    Args:
        source: Path in the System volume union namespace, for example ``/Library``.
        target: Path on the Data volume. Both relative paths (``Library``), absolute
            paths (``/Library``) and paths using the macOS data mount prefix
            (``/System/Volumes/Data/Library``) are accepted.
        source_volume_uuid: Optional expected UUID of the System volume.
        target_volume_uuid: Optional expected UUID of the Data volume.
        evidence: Optional free-form origin of this mapping material.
    """

    source: str
    target: str
    source_volume_uuid: UUID | None = None
    target_volume_uuid: UUID | None = None
    evidence: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _canonical_source(self.source))
        object.__setattr__(self, "target", _canonical_target(self.target))
        object.__setattr__(self, "source_volume_uuid", _as_uuid(self.source_volume_uuid))
        object.__setattr__(self, "target_volume_uuid", _as_uuid(self.target_volume_uuid))

    @property
    def source_parts(self) -> tuple[str, ...]:
        """The normalized source path components."""
        return _parts_from_absolute(self.source)

    @property
    def target_parts(self) -> tuple[str, ...]:
        """The normalized Data volume target path components."""
        return _target_parts(self.target)

    @property
    def data_path(self) -> str:
        """The normalized path on the Data volume."""
        return _path_from_parts(self.target_parts)

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable representation of this mapping."""
        return {
            "source": self.source,
            "target": self.target,
            "data_path": self.data_path,
            "source_volume_uuid": str(self.source_volume_uuid) if self.source_volume_uuid else None,
            "target_volume_uuid": str(self.target_volume_uuid) if self.target_volume_uuid else None,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class UnionHop:
    """A single step in a union path resolution."""

    kind: str
    union_path: str
    volume_uuid: UUID | None
    volume_role: str | None
    volume_path: str | None
    evidence: str
    mapping: dict[str, Any] | None = None
    symlink_target: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable representation of this hop."""
        return {
            "kind": self.kind,
            "union_path": self.union_path,
            "volume_uuid": str(self.volume_uuid) if self.volume_uuid else None,
            "volume_role": self.volume_role,
            "volume_path": self.volume_path,
            "evidence": self.evidence,
            "mapping": self.mapping,
            "symlink_target": self.symlink_target,
        }


@dataclass(frozen=True, slots=True)
class UnionCandidate:
    """One possible backing entry for a union path."""

    union_path: str
    volume_uuid: UUID | None
    volume_role: str | None
    volume_name: str | None
    volume_path: str
    exists: bool
    selected: bool
    is_firmlink_source: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable representation of this candidate."""
        return {
            "union_path": self.union_path,
            "volume_uuid": str(self.volume_uuid) if self.volume_uuid else None,
            "volume_role": self.volume_role,
            "volume_name": self.volume_name,
            "volume_path": self.volume_path,
            "exists": self.exists,
            "selected": self.selected,
            "is_firmlink_source": self.is_firmlink_source,
            "evidence": self.evidence,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class UnionScope:
    """The part of a user-visible namespace that a union view can actually back."""

    complete: bool
    group_id: UUID | None
    system_uuid: UUID | None
    data_uuid: UUID | None
    system_role: str | None
    data_role: str | None
    mapping_sources: tuple[str, ...]
    visible: tuple[str, ...]
    unavailable: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable representation of this scope."""
        return {
            "complete": self.complete,
            "group_id": str(self.group_id) if self.group_id else None,
            "system_uuid": str(self.system_uuid) if self.system_uuid else None,
            "data_uuid": str(self.data_uuid) if self.data_uuid else None,
            "system_role": self.system_role,
            "data_role": self.data_role,
            "mapping_sources": self.mapping_sources,
            "visible": self.visible,
            "unavailable": self.unavailable,
            "reason": self.reason,
        }


class UnionNode:
    """A node in the explicit union view, carrying the volume it really came from.

    A node is never detached from its backing volume. ``volume_uuid``,
    ``volume_role`` and ``volume_path`` always describe the actual inode that was
    read, while ``union_path`` is the path the user sees. ``trace`` records every
    volume switch, firmlink mapping and symbolic link expansion used to reach it.
    """

    def __init__(
        self,
        view: VolumeGroupView,
        inode: INode | None,
        *,
        volume: FS | None,
        volume_parts: tuple[str, ...],
        union_parts: tuple[str, ...],
        trace: Sequence[UnionHop],
        alternatives: Sequence[UnionCandidate] = (),
        available: bool = True,
        error: VolumeGroupError | None = None,
    ):
        self.view = view
        self.inode = inode
        self.volume = volume
        self.volume_parts = volume_parts
        self.union_parts = union_parts
        self.trace = _dedupe_trace(trace)
        self.alternatives = tuple(alternatives)
        self.available = available
        self.error = error

    def __repr__(self) -> str:
        volume = self.volume_uuid or "unavailable"
        return f"<UnionNode union_path={self.union_path!r} volume={volume} volume_path={self.volume_path!r}>"

    @property
    def union_path(self) -> str:
        """The path as visible in the union namespace."""
        return _path_from_parts(self.union_parts)

    @property
    def volume_path(self) -> str | None:
        """The path inside the backing volume."""
        if not self.available:
            return None
        return _path_from_parts(self.volume_parts)

    @property
    def volume_uuid(self) -> UUID | None:
        """The UUID of the volume that actually backs this node."""
        return _volume_uuid(self.volume) if self.volume is not None else None

    @property
    def volume_role(self) -> str | None:
        """The role of the volume that actually backs this node."""
        return _role_name(self.volume) if self.volume is not None else None

    @property
    def volume_name(self) -> str | None:
        """The name of the volume that actually backs this node."""
        return getattr(self.volume, "name", None) if self.volume is not None else None

    @property
    def name(self) -> str | None:
        """The basename of the union path."""
        return self.union_parts[-1] if self.union_parts else "/"

    @property
    def oid(self) -> int | None:
        """The inode object ID, if available."""
        return getattr(self.inode, "oid", None) if self.inode is not None else None

    @property
    def sibling_id(self) -> int | None:
        """The inode sibling ID, if available."""
        return getattr(self.inode, "sibling_id", None) if self.inode is not None else None

    def _require_available(self) -> INode:
        if not self.available or self.inode is None:
            if isinstance(self.error, VolumeGroupError):
                raise self.error
            raise UnionVolumeUnavailableError(
                f"Union path is not available: {self.union_path}",
                scope=self.view.scope,
                details={"path": self.union_path, "trace": [hop.as_dict() for hop in self.trace]},
            )
        return self.inode

    def is_dir(self) -> bool:
        """Return whether the backing inode is a directory."""
        return self._require_available().is_dir()

    def is_file(self) -> bool:
        """Return whether the backing inode is a regular file."""
        return self._require_available().is_file()

    def is_symlink(self) -> bool:
        """Return whether the backing inode is a symbolic link."""
        return self._require_available().is_symlink()

    def is_firmlink(self) -> bool:
        """Return whether the backing inode is marked as a firmlink."""
        inode = self._require_available()
        checker = getattr(inode, "is_firmlink", None)
        return bool(checker()) if callable(checker) else False

    @property
    def size(self) -> int:
        """The size of the backing inode."""
        return self._require_available().size

    @property
    def mode(self) -> int:
        """The mode of the backing inode."""
        return self._require_available().mode

    def readlink(self) -> str:
        """Read the symbolic link target of the backing inode."""
        return self._require_available().readlink()

    def open(self) -> Any:
        """Open a stream for the backing inode."""
        return self._require_available().open()

    def get(self, name: str) -> UnionNode:
        """Look up a child by name in the union namespace."""
        return self.view.lookup((*self.union_parts, name))

    def listdir(self) -> dict[str, UnionNode]:
        """List the union directory entries of this node."""
        return self.view.listdir(self.union_path)

    def evidence(self) -> dict[str, Any]:
        """Return the complete jump evidence for this node."""
        result: dict[str, Any] = {
            "union_path": self.union_path,
            "available": self.available,
            "volume": None,
            "volume_path": self.volume_path,
            "inode": {"oid": self.oid, "sibling_id": self.sibling_id},
            "trace": [hop.as_dict() for hop in self.trace],
            "alternatives": [candidate.as_dict() for candidate in self.alternatives],
            "error": None,
        }
        if self.volume is not None:
            result["volume"] = {
                "uuid": str(self.volume_uuid) if self.volume_uuid else None,
                "role": self.volume_role,
                "name": self.volume_name,
                "path": self.volume_path,
            }
        if self.error is not None:
            result["error"] = {
                "type": type(self.error).__name__,
                "message": str(self.error),
                "details": self.error.details,
            }
        return result


class VolumeGroupView:
    """An explicit union view over an APFS System/Data volume group.

    The caller supplies both volumes and the firmlink mapping material; this view
    never discovers host mount points and never changes the existing single-volume
    :class:`~dissect.apfs.objects.fs.FS` API. All lookups stay within the supplied
    APFS volumes.

    Args:
        system: The System volume (role ``SYSTEM``), or ``None`` for a partial view.
        data: The Data volume (role ``DATA``), or ``None`` for a partial view.
        firmlinks: Mapping material as :class:`FirmlinkMapping` objects, text lines
            in ``source<TAB>target`` (or ``source -> target``) form, or an iterable
            of either.
        group_id: Optional expected volume group UUID.
        allow_missing: Allow constructing a partial view from a single volume.
    """

    def __init__(
        self,
        system: FS | None,
        data: FS | None = None,
        firmlinks: Iterable[FirmlinkMapping | str] | str | bytes | None = (),
        *,
        group_id: UUID | str | None = None,
        allow_missing: bool = True,
    ):
        if system is None and data is None:
            raise VolumeGroupIdentityError("At least one volume is required for a union view")

        self.system = system
        self.data = data
        expected_group_id = _as_uuid(group_id)

        self._system_role = _role_name(system) if system is not None else None
        self._data_role = _role_name(data) if data is not None else None

        if system is not None and _role_value(system) != int(c_apfs.APFS_VOL_ROLE.SYSTEM):
            raise VolumeGroupRoleError(
                f"Expected a SYSTEM volume, got {self._system_role}",
                scope=None,
                details={"volume_uuid": _uuid_string(system), "role": self._system_role},
            )
        if data is not None and _role_value(data) != int(c_apfs.APFS_VOL_ROLE.DATA):
            raise VolumeGroupRoleError(
                f"Expected a DATA volume, got {self._data_role}",
                scope=None,
                details={"volume_uuid": _uuid_string(data), "role": self._data_role},
            )

        if system is not None and data is not None:
            system_uuid = _volume_uuid(system)
            data_uuid = _volume_uuid(data)
            if (system_uuid is not None and system_uuid == data_uuid) or system is data:
                raise VolumeGroupIdentityError(
                    "System and Data volumes must be distinct",
                    scope=None,
                    details={"volume_uuid": _uuid_string(system)},
                )

        if system is not None and data is not None:
            system_uuid = _volume_uuid(system)
            data_uuid = _volume_uuid(data)
            if system_uuid is not None and system_uuid == data_uuid:
                raise VolumeGroupIdentityError(
                    "System and Data volumes must be distinct",
                    scope=None,
                    details={"volume_uuid": str(system_uuid)},
                )

            system_group = _volume_group_id(system)
            data_group = _volume_group_id(data)
            if system_group is None or data_group is None:
                raise VolumeGroupIdentityError(
                    "Both volumes must carry a volume group identifier",
                    scope=None,
                    details={
                        "system_uuid": _uuid_string(system),
                        "data_uuid": _uuid_string(data),
                        "system_group_id": str(system_group) if system_group else None,
                        "data_group_id": str(data_group) if data_group else None,
                    },
                )
            if system_group != data_group:
                raise VolumeGroupMismatchError(
                    "System and Data volumes belong to different volume groups",
                    scope=None,
                    details={
                        "system_uuid": _uuid_string(system),
                        "data_uuid": _uuid_string(data),
                        "system_group_id": str(system_group),
                        "data_group_id": str(data_group),
                    },
                )
            if expected_group_id is not None and expected_group_id != system_group:
                raise VolumeGroupMismatchError(
                    "Volume group does not match the expected group identifier",
                    scope=None,
                    details={
                        "expected_group_id": str(expected_group_id),
                        "actual_group_id": str(system_group),
                    },
                )
            group_id_value: UUID | None = system_group
        else:
            present = system if system is not None else data
            actual_group = _volume_group_id(present) if present is not None else None
            if expected_group_id is not None:
                if actual_group is not None and actual_group != expected_group_id:
                    raise VolumeGroupMismatchError(
                        "Volume does not match the expected group identifier",
                        scope=None,
                        details={
                            "expected_group_id": str(expected_group_id),
                            "actual_group_id": str(actual_group),
                            "volume_uuid": _uuid_string(present),
                        },
                    )
                group_id_value = expected_group_id
            elif actual_group is not None:
                group_id_value = actual_group
            elif not allow_missing:
                raise VolumeGroupIdentityError(
                    "Volume group identity could not be established",
                    scope=None,
                    details={"volume_uuid": _uuid_string(present)},
                )
            else:
                group_id_value = None

        self.group_id = group_id_value
        self.mappings = tuple(_parse_material(firmlinks))
        self._mappings: dict[tuple[str, ...], FirmlinkMapping] = {}
        self._mapping_evidence: dict[tuple[str, ...], dict[str, Any]] = {}
        self._scope: UnionScope | None = None

        self._validate_mappings()

        self._scope = self._build_scope()

    def __repr__(self) -> str:
        return (
            f"<VolumeGroupView group_id={self.group_id} "
            f"system={_uuid_string(self.system)} data={_uuid_string(self.data)} "
            f"mappings={len(self.mappings)} complete={self.complete}>"
        )

    @classmethod
    def from_candidates(
        cls,
        candidates: Iterable[FS],
        firmlinks: Iterable[FirmlinkMapping | str] | str | bytes | None = (),
        *,
        group_id: UUID | str | None = None,
        allow_missing: bool = True,
    ) -> VolumeGroupView:
        """Build a view by selecting one System and one Data volume from candidates.

        Candidates from other roles or other volume groups are reported separately
        in the selection error instead of being silently mixed into one view.
        """
        expected_group_id = _as_uuid(group_id)
        records: list[dict[str, Any]] = []
        systems: dict[UUID | None, list[FS]] = {}
        datas: dict[UUID | None, list[FS]] = {}
        seen: set[UUID | None] = set()

        for volume in candidates:
            volume_uuid = _volume_uuid(volume)
            if volume_uuid is not None:
                if volume_uuid in seen:
                    continue
                seen.add(volume_uuid)

            role = _role_value(volume)
            group = _volume_group_id(volume)
            record = {
                "volume_uuid": _uuid_string(volume),
                "role": _role_name(volume),
                "group_id": str(group) if group else None,
            }
            records.append(record)

            if expected_group_id is not None and group is not None and group != expected_group_id:
                continue
            if role == int(c_apfs.APFS_VOL_ROLE.SYSTEM):
                systems.setdefault(group, []).append(volume)
            elif role == int(c_apfs.APFS_VOL_ROLE.DATA):
                datas.setdefault(group, []).append(volume)

        groups = sorted(set(systems) | set(datas), key=lambda item: str(item))
        usable = [
            group
            for group in groups
            if group is not None and len(systems.get(group, ())) == 1 and len(datas.get(group, ())) == 1
        ]
        if len(usable) == 1:
            group = usable[0]
            return cls(
                systems[group][0],
                datas[group][0],
                firmlinks,
                group_id=expected_group_id or group,
                allow_missing=allow_missing,
            )

        if allow_missing and len(usable) == 0:
            partial = [
                group
                for group in groups
                if group is not None and len(systems.get(group, ())) + len(datas.get(group, ())) == 1
            ]
            if len(partial) == 1:
                group = partial[0]
                system = systems[group][0] if systems.get(group) else None
                data = datas[group][0] if datas.get(group) else None
                return cls(system, data, firmlinks, group_id=expected_group_id or group, allow_missing=True)

        raise VolumeGroupSelectionError(
            "Could not select exactly one System/Data volume pair",
            scope=None,
            details={
                "candidates": records,
                "groups": {
                    str(group): {"system": len(systems.get(group, ())), "data": len(datas.get(group, ()))}
                    for group in groups
                },
            },
        )

    @classmethod
    def from_container(
        cls,
        container: Any,
        firmlinks: Iterable[FirmlinkMapping | str] | str | bytes | None = (),
        *,
        group_id: UUID | str | None = None,
        allow_missing: bool = True,
    ) -> VolumeGroupView:
        """Build a view from an :class:`~dissect.apfs.apfs.APFS` container."""
        return cls.from_candidates(
            container.volumes,
            firmlinks,
            group_id=group_id,
            allow_missing=allow_missing,
        )

    @property
    def scope(self) -> UnionScope:
        """The visible and unavailable parts of this union view."""
        if self._scope is None:
            self._scope = self._build_scope()
        return self._scope

    @property
    def complete(self) -> bool:
        """Whether both volumes of the group were supplied."""
        return self.system is not None and self.data is not None

    def coverage(self) -> dict[str, Any]:
        """Return the view coverage as a serialisable dictionary."""
        return self._scope.as_dict()

    def validate_mappings(self) -> list[dict[str, Any]]:
        """Validate all mappings against the supplied volumes.

        Returns one evidence record per mapping. Missing targets are reported in
        the record rather than turned into a successful lookup.
        """
        result = []
        for mapping in self.mappings:
            record = mapping.as_dict()
            record["source_evidence"] = self._source_evidence(mapping)
            record["target_evidence"] = self._target_evidence(mapping)
            source_exists = record["source_evidence"].get("exists")
            target_exists = record["target_evidence"].get("exists")
            if self.system is None:
                record["status"] = "system-unavailable"
            elif source_exists is False:
                record["status"] = "missing-source"
            elif record["source_evidence"].get("is_dir") is False:
                record["status"] = "source-not-directory"
            elif record["source_evidence"].get("marker_mismatch"):
                record["status"] = "marker-mismatch"
            elif self.data is None:
                record["status"] = "data-unavailable"
            elif target_exists is False:
                record["status"] = "missing-target"
            elif record["target_evidence"].get("is_dir") is False:
                record["status"] = "target-not-directory"
            else:
                record["status"] = "ok"
            result.append(record)
        return result

    def lookup(self, path: PathLike, *, follow_symlinks: bool = True) -> UnionNode:
        """Resolve a path in the union namespace.

        The result always records the backing volume and the complete jump trace.
        Symbolic links are followed inside the union namespace only; they can never
        escape to the host file system.
        """
        parts = _normalize_path(path)
        trace: list[UnionHop] = []
        root = "system"
        prefix: tuple[str, ...] = ()
        if self.system is not None:
            trace.append(self._root_hop(self.system, "system-root"))
        elif self.data is not None:
            trace.append(self._root_hop(self.data, "data-root"))

        data_prefix = _DATA_MOUNT_PARTS
        if parts[: len(data_prefix)] == data_prefix:
            if self.data is None:
                raise UnionVolumeUnavailableError(
                    f"Data volume is required for path: {_path_from_parts(parts)}",
                    scope=self._scope,
                    details={
                        "path": _path_from_parts(parts),
                        "reason": "explicit Data mount prefix requires the Data volume",
                    },
                )
            root = "data"
            prefix = data_prefix
            parts = parts[len(data_prefix) :]
            trace.append(
                UnionHop(
                    kind="data-mount",
                    union_path=_path_from_parts(data_prefix),
                    volume_uuid=_volume_uuid(self.data),
                    volume_role=self._data_role,
                    volume_path="/",
                    evidence="explicit /System/Volumes/Data prefix; path resolved on the Data volume",
                )
            )

        return self._resolve(parts, trace, follow_symlinks=follow_symlinks, root=root, prefix=prefix)

    def get(self, path: PathLike, node: UnionNode | None = None) -> UnionNode:
        """Alias for :meth:`lookup`."""
        return self.lookup(path)

    def stat(self, path: PathLike, *, follow_symlinks: bool = True) -> UnionNode:
        """Return the union node for a path."""
        return self.lookup(path, follow_symlinks=follow_symlinks)

    def lstat(self, path: PathLike) -> UnionNode:
        """Return the union node without following a final symbolic link."""
        return self.lookup(path, follow_symlinks=False)

    def exists(self, path: PathLike, *, follow_symlinks: bool = True) -> bool:
        """Return whether a path is visible in the union namespace."""
        try:
            self.lookup(path, follow_symlinks=follow_symlinks)
        except (VolumeGroupError, FileNotFoundError, NotADirectoryError):
            return False
        return True

    def visible_roots(self) -> list[dict[str, Any]]:
        """Describe which top-level namespaces this view can actually back.

        This is the explicit scope report used when one of the two volumes is
        missing: unmapped System paths remain visible, mapped sources are only
        visible if their Data target is available, and Data-only mappings are
        visible through their declared source paths.
        """
        result = []
        if self.system is not None:
            result.append(
                {
                    "union_path": "/",
                    "volume_uuid": str(_volume_uuid(self.system)),
                    "volume_role": self._system_role,
                    "available": True,
                    "kind": "system-root",
                }
            )
        for mapping in self.mappings:
            record = {
                "union_path": mapping.source,
                "data_path": mapping.data_path,
                "available": self.data is not None and self._target_evidence(mapping).get("exists") is True,
                "kind": "firmlink",
                "volume_uuid": str(_volume_uuid(self.data)) if self.data is not None else None,
                "volume_role": self._data_role,
                "source_evidence": self._source_evidence(mapping),
                "target_evidence": self._target_evidence(mapping),
            }
            result.append(record)
        return result

    def open(self, path: PathLike) -> Any:
        """Open a file in the union namespace."""
        return self.lookup(path).open()

    def readlink(self, path: PathLike) -> str:
        """Read a symbolic link without following it."""
        return self.lstat(path).readlink()

    def listdir(self, path: PathLike = "/") -> dict[str, UnionNode]:
        """List a union directory.

        Entries backed by a missing volume are returned as unavailable nodes with
        their evidence, so a partial view can describe its scope without pretending
        to be complete.
        """
        parts = _normalize_path(path)
        if not parts and self.system is None:
            return self._synthetic_mapping_roots()

        node = self.lookup(parts)
        if not node.is_dir():
            raise UnionNotADirectoryError(
                f"Not a directory: {node.union_path}",
                scope=self._scope,
                details={"path": node.union_path, "node": node.evidence()},
            )

        result: dict[str, UnionNode] = {}
        for name in node.inode.listdir():
            child_parts = (*node.union_parts, name)
            try:
                child = self.lookup(child_parts, follow_symlinks=False)
            except VolumeGroupError as exc:
                self._augment(exc, child_parts, node.trace)
                result[name] = UnionNode(
                    self,
                    None,
                    volume=None,
                    volume_parts=child_parts,
                    union_parts=child_parts,
                    trace=exc.details.get("trace_hops", node.trace),
                    alternatives=(),
                    available=False,
                    error=exc,
                )
            else:
                result[name] = child
        return result

    def _synthetic_mapping_roots(self) -> dict[str, UnionNode]:
        result: dict[str, UnionNode] = {}
        for mapping in self.mappings:
            name = mapping.source_parts[0]
            if name in result:
                continue
            try:
                result[name] = self.lookup((name,), follow_symlinks=False)
            except VolumeGroupError as exc:
                self._augment(exc, (name,), ())
                result[name] = UnionNode(
                    self,
                    None,
                    volume=None,
                    volume_parts=(name,),
                    union_parts=(name,),
                    trace=exc.details.get("trace_hops", ()),
                    available=False,
                    error=exc,
                )
        return result

    def candidates(self, path: PathLike, *, follow_symlinks: bool = False) -> tuple[UnionCandidate, ...]:
        """Return every plausible backing entry for a union path.

        This is where same-name conflicts are made explicit: a mapped union path
        can exist both as the System-side firmlink source and as the Data-side
        target. The default lookup selects the mapping target but never hides the
        alternative.
        """
        parts = _normalize_path(path)
        if parts[: len(_DATA_MOUNT_PARTS)] == _DATA_MOUNT_PARTS:
            data_parts = parts[len(_DATA_MOUNT_PARTS) :]
            return (
                self._candidate_for_volume(
                    self.data,
                    data_parts,
                    parts,
                    is_firmlink_source=False,
                    evidence={"reason": "explicit /System/Volumes/Data prefix"},
                    selected=True,
                ),
            )

        if self.system is None:
            mapping = self._mapping_for(parts)
            if mapping is not None:
                return (
                    self._candidate_for_volume(
                        self.data,
                        mapping.target_parts + parts[len(mapping.source_parts) :],
                        parts,
                        is_firmlink_source=False,
                        evidence={"mapping": mapping.as_dict()},
                        selected=True,
                    ),
                )
            return (
                self._candidate_for_volume(
                    None, parts, parts, is_firmlink_source=False, evidence={"reason": "system volume not supplied"}
                ),
            )

        mapping = self._mapping_for(parts)
        result: list[UnionCandidate] = []

        if mapping is not None:
            remainder = parts[len(mapping.source_parts) :]
            system_parts = mapping.source_parts + remainder
            result.append(
                self._candidate_for_volume(
                    self.system,
                    system_parts,
                    parts,
                    is_firmlink_source=True,
                    evidence=self._source_evidence(mapping),
                )
            )
            result.append(
                self._candidate_for_volume(
                    self.data,
                    mapping.target_parts + remainder,
                    parts,
                    is_firmlink_source=False,
                    evidence={"mapping": mapping.as_dict()},
                    selected=True,
                )
            )
        else:
            result.append(self._candidate_for_volume(self.system, parts, parts, is_firmlink_source=False))
        return tuple(result)

    def evidence(self, path: PathLike) -> dict[str, Any]:
        """Return the full resolution evidence for a path."""
        parts = _normalize_path(path)
        try:
            node = self.lookup(parts)
        except VolumeGroupError as exc:
            return {
                "path": _path_from_parts(parts),
                "scope": self._scope.as_dict(),
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "details": exc.details,
                },
                "candidates": [candidate.as_dict() for candidate in self.candidates(parts)],
            }
        return {
            "path": node.union_path,
            "scope": self._scope.as_dict(),
            "node": node.evidence(),
            "candidates": [candidate.as_dict() for candidate in self.candidates(parts)],
        }

    def _build_scope(self) -> UnionScope:
        mapping_sources = tuple(mapping.source for mapping in self.mappings)
        backed: list[str] = []
        missing: list[str] = []
        for mapping in self.mappings:
            target = self._target_evidence(mapping)
            if target.get("available") is True and target.get("exists") is True:
                source = self._source_evidence(mapping)
                if source.get("exists") is not False and source.get("marker_mismatch") is not True:
                    backed.append(mapping.source)
                    continue
            missing.append(mapping.source)

        if self.system is not None:
            visible: tuple[str, ...] = ("/",)
            unavailable = tuple(missing)
            if self.data is None:
                reason = "Data volume is missing; only unmapped System paths are fully visible."
            elif missing:
                reason = "Both volumes are present, but some mapped targets are missing or unbacked."
            else:
                reason = "System and Data volumes are both present; mapped paths resolve on Data."
        else:
            visible = tuple(backed)
            unavailable = ("/", *missing)
            reason = "System volume is missing; only declared mapping targets with existing Data inodes are visible."

        return UnionScope(
            complete=self.complete,
            group_id=self.group_id,
            system_uuid=_volume_uuid(self.system) if self.system is not None else None,
            data_uuid=_volume_uuid(self.data) if self.data is not None else None,
            system_role=self._system_role,
            data_role=self._data_role,
            mapping_sources=mapping_sources,
            visible=visible,
            unavailable=unavailable,
            reason=reason,
        )

    def _validate_mappings(self) -> None:
        for mapping in self.mappings:
            source_parts = mapping.source_parts
            if not source_parts:
                raise FirmlinkConflictError(
                    "A firmlink source can not be the union root",
                    scope=None,
                    details={"mapping": mapping.as_dict()},
                )
            if source_parts in self._mappings:
                existing = self._mappings[source_parts]
                if existing.target_parts != mapping.target_parts:
                    raise FirmlinkConflictError(
                        f"Conflicting mappings for {mapping.source}",
                        scope=None,
                        details={"existing": existing.as_dict(), "conflicting": mapping.as_dict()},
                    )
                continue

            for other_parts, other in self._mappings.items():
                if _is_prefix(other_parts, source_parts) or _is_prefix(source_parts, other_parts):
                    raise FirmlinkConflictError(
                        "Overlapping firmlink sources make the union namespace ambiguous",
                        scope=None,
                        details={"existing": other.as_dict(), "conflicting": mapping.as_dict()},
                    )

            if mapping.source_volume_uuid is not None and self.system is not None:
                system_uuid = _volume_uuid(self.system)
                if system_uuid is not None and mapping.source_volume_uuid != system_uuid:
                    raise FirmlinkConflictError(
                        "Firmlink source volume does not match the supplied System volume",
                        scope=None,
                        details={"mapping": mapping.as_dict(), "system_uuid": str(system_uuid)},
                    )

            if mapping.target_volume_uuid is not None:
                data_uuid = _volume_uuid(self.data) if self.data is not None else None
                if data_uuid is not None and mapping.target_volume_uuid != data_uuid:
                    raise FirmlinkConflictError(
                        "Firmlink target volume does not match the supplied Data volume",
                        scope=None,
                        details={"mapping": mapping.as_dict(), "data_uuid": str(data_uuid)},
                    )

            self._mappings[source_parts] = mapping

    def _mapping_for(self, parts: tuple[str, ...]) -> FirmlinkMapping | None:
        for index in range(len(parts), 0, -1):
            mapping = self._mappings.get(parts[:index])
            if mapping is not None:
                return mapping
        return None

    def _source_evidence(self, mapping: FirmlinkMapping) -> dict[str, Any]:
        key = mapping.source_parts
        if key in self._mapping_evidence:
            return self._mapping_evidence[key]

        record: dict[str, Any] = {
            "exists": None,
            "is_dir": None,
            "is_symlink": None,
            "firmlink_flag": None,
            "xattr_target": None,
            "marker_mismatch": False,
            "reason": None,
        }
        if self.system is None:
            record["reason"] = "system volume not supplied"
            self._mapping_evidence[key] = record
            return record

        inode = self._try_walk(self.system, mapping.source_parts)
        if inode is None:
            record["exists"] = False
            record["reason"] = "source does not exist on the System volume"
            self._mapping_evidence[key] = record
            return record

        record["exists"] = True
        record["oid"] = getattr(inode, "oid", None)
        record["is_dir"] = inode.is_dir()
        record["is_symlink"] = inode.is_symlink()
        checker = getattr(inode, "is_firmlink", None)
        if callable(checker):
            record["firmlink_flag"] = bool(checker())

        xattr_target = getattr(inode, "firmlink_target", None)
        if xattr_target:
            record["xattr_target"] = xattr_target
            try:
                xattr_parts = _target_parts(xattr_target)
            except (FirmlinkConflictError, ValueError) as exc:
                record["marker_mismatch"] = True
                record["marker_error"] = str(exc)
            else:
                record["marker_mismatch"] = xattr_parts != mapping.target_parts

        self._mapping_evidence[key] = record
        return record

    def _target_evidence(self, mapping: FirmlinkMapping) -> dict[str, Any]:
        if self.data is None:
            return {"available": False, "reason": "data volume not supplied", "exists": None}
        inode = self._try_walk(self.data, mapping.target_parts)
        if inode is None:
            return {"available": True, "exists": False}
        return {
            "available": True,
            "exists": True,
            "is_dir": inode.is_dir(),
            "oid": getattr(inode, "oid", None),
        }

    def _root_hop(self, volume: FS, kind: str) -> UnionHop:
        return UnionHop(
            kind=kind,
            union_path="/",
            volume_uuid=_volume_uuid(volume),
            volume_role=_role_name(volume),
            volume_path="/",
            evidence="volume root",
        )

    def _resolve(
        self,
        parts: tuple[str, ...],
        trace: list[UnionHop],
        *,
        follow_symlinks: bool,
        root: str = "system",
        prefix: tuple[str, ...] = (),
    ) -> UnionNode:
        queue: deque[str] = deque(parts)
        resolved: list[str] = []
        symlinks = 0
        seen: set[tuple[UUID | None, str | None, str]] = set()
        last_node: UnionNode | None = None

        while queue:
            component = queue.popleft()
            if component in ("", "."):
                continue
            if component == "..":
                if not resolved:
                    raise UnionPathTraversalError(
                        "Path escapes the union root",
                        scope=self._scope,
                        details={"trace": [hop.as_dict() for hop in trace]},
                    )
                resolved.pop()
                continue

            current_parts = (*resolved, component)
            union_parts = prefix + current_parts
            node = self._resolve_direct(current_parts, trace, root=root, display_parts=union_parts)
            trace = list(node.trace)
            last_node = node

            if node.is_symlink() and (queue or follow_symlinks):
                target = node.readlink()
                if not target:
                    raise UnionSymlinkTargetError(
                        f"Empty symbolic link target at {node.union_path}",
                        scope=self._scope,
                        details={"path": node.union_path, "node": node.evidence()},
                    )

                key = (node.volume_uuid, node.volume_path, node.union_path)
                if key in seen:
                    raise UnionSymlinkLoopError(
                        f"Symbolic link loop at {node.union_path}",
                        scope=self._scope,
                        details={"path": node.union_path, "target": target, "trace": [hop.as_dict() for hop in trace]},
                    )
                seen.add(key)
                symlinks += 1
                if symlinks > _MAX_SYMLINKS:
                    raise UnionSymlinkLoopError(
                        "Too many symbolic links while resolving union path",
                        scope=self._scope,
                        details={"path": node.union_path, "target": target},
                    )

                if target.startswith("/"):
                    base: tuple[str, ...] = ()
                else:
                    base = tuple(resolved)
                try:
                    target_parts = _link_target_parts(target, base=base)
                except UnionPathTraversalError:
                    raise
                except Exception as exc:
                    raise UnionSymlinkTargetError(
                        f"Unusable symbolic link target at {node.union_path}: {exc}",
                        scope=self._scope,
                        details={"path": node.union_path, "target": target},
                    ) from exc

                trace.append(
                    UnionHop(
                        kind="symlink",
                        union_path=node.union_path,
                        volume_uuid=node.volume_uuid,
                        volume_role=node.volume_role,
                        volume_path=node.volume_path,
                        evidence="symbolic link followed inside the union namespace",
                        symlink_target=target,
                    )
                )

                next_root = (
                    root
                    if not target.startswith("/")
                    else ("data" if target_parts[: len(_DATA_MOUNT_PARTS)] == _DATA_MOUNT_PARTS else "system")
                )
                next_prefix = prefix if not target.startswith("/") else ()
                if target.startswith("/") and target_parts[: len(_DATA_MOUNT_PARTS)] == _DATA_MOUNT_PARTS:
                    if self.data is None:
                        raise UnionVolumeUnavailableError(
                            f"Symbolic link target requires the Data volume: {target}",
                            scope=self._scope,
                            details={"path": node.union_path, "target": target},
                        )
                    next_root = "data"
                    next_prefix = _DATA_MOUNT_PARTS
                    target_parts = target_parts[len(_DATA_MOUNT_PARTS) :]
                    trace.append(
                        UnionHop(
                            kind="data-mount",
                            union_path=_DATA_MOUNT_PREFIX,
                            volume_uuid=_volume_uuid(self.data),
                            volume_role=self._data_role,
                            volume_path="/",
                            evidence="symbolic link target uses the explicit Data mount prefix",
                            symlink_target=target,
                        )
                    )

                queue = deque(target_parts + tuple(queue))
                resolved = []
                root = next_root
                prefix = next_prefix
                continue

            resolved.append(component)

        if not resolved:
            return self._resolve_direct((), trace, root=root, display_parts=prefix)
        return self._resolve_direct(
            tuple(resolved),
            trace,
            previous=last_node,
            root=root,
            display_parts=prefix + tuple(resolved),
        )

    def _resolve_direct(
        self,
        parts: tuple[str, ...],
        trace: list[UnionHop],
        *,
        previous: UnionNode | None = None,
        root: str = "system",
        display_parts: tuple[str, ...] | None = None,
    ) -> UnionNode:
        union_parts = parts if display_parts is None else display_parts
        if previous is not None and previous.union_parts == union_parts:
            return previous

        if root == "data":
            return self._resolve_data(parts, trace, display_parts=union_parts)

        mapping = self._mapping_for(parts)
        if mapping is not None:
            source_evidence = self._source_evidence(mapping)
            source_parts = mapping.source_parts
            if self.system is not None:
                if not source_evidence.get("exists", True):
                    raise FirmlinkTargetError(
                        f"Firmlink source does not exist: {mapping.source}",
                        scope=self._scope,
                        details={
                            "path": _path_from_parts(parts),
                            "mapping": mapping.as_dict(),
                            "source_evidence": source_evidence,
                            "trace_hops": tuple(trace),
                        },
                    )
                if source_evidence.get("is_dir") is False:
                    raise FirmlinkTargetError(
                        f"Firmlink source is not a directory: {mapping.source}",
                        scope=self._scope,
                        details={
                            "path": _path_from_parts(parts),
                            "mapping": mapping.as_dict(),
                            "source_evidence": source_evidence,
                        },
                    )
                if source_evidence.get("marker_mismatch"):
                    raise FirmlinkConflictError(
                        f"Firmlink marker for {mapping.source} disagrees with the supplied mapping",
                        scope=self._scope,
                        details={
                            "path": _path_from_parts(parts),
                            "mapping": mapping.as_dict(),
                            "source_evidence": source_evidence,
                        },
                    )

            if self.data is None:
                raise UnionVolumeUnavailableError(
                    f"Data volume is required for mapped path: {_path_from_parts(parts)}",
                    scope=self._scope,
                    details={
                        "path": _path_from_parts(parts),
                        "mapping": mapping.as_dict(),
                        "source_evidence": source_evidence,
                        "trace_hops": tuple(trace),
                    },
                )

            remainder = parts[len(source_parts) :]
            data_parts = mapping.target_parts + remainder
            try:
                inode = self._walk(self.data, data_parts, mapping=mapping)
            except UnionFileNotFoundError as exc:
                raise FirmlinkTargetError(
                    f"Firmlink target does not exist: {_path_from_parts(data_parts)}",
                    scope=self._scope,
                    details={
                        "path": _path_from_parts(parts),
                        "mapping": mapping.as_dict(),
                        "data_path": _path_from_parts(data_parts),
                        "source_evidence": source_evidence,
                        "trace_hops": tuple(trace),
                    },
                ) from exc
            except UnionVolumeErrorTypes as exc:
                self._augment(exc, parts, trace, mapping=mapping)
                raise

            if remainder and not inode.is_dir() and len(remainder) > 1:
                raise UnionNotADirectoryError(
                    f"Not a directory: {_path_from_parts(parts)}",
                    scope=self._scope,
                    details={"path": _path_from_parts(parts), "mapping": mapping.as_dict()},
                )

            if parts == source_parts:
                trace.append(
                    UnionHop(
                        kind="firmlink-source",
                        union_path=mapping.source,
                        volume_uuid=_volume_uuid(self.system) if self.system is not None else None,
                        volume_role=self._system_role,
                        volume_path=mapping.source,
                        evidence="System-side firmlink source",
                        mapping=mapping.as_dict(),
                    )
                )
                trace.append(
                    UnionHop(
                        kind="firmlink",
                        union_path=_path_from_parts(union_parts),
                        volume_uuid=_volume_uuid(self.data),
                        volume_role=self._data_role,
                        volume_path=_path_from_parts(data_parts),
                        evidence="caller-supplied mapping; path switched from System to Data",
                        mapping=mapping.as_dict(),
                    )
                )
            else:
                trace.append(
                    UnionHop(
                        kind="data-path",
                        union_path=_path_from_parts(union_parts),
                        volume_uuid=_volume_uuid(self.data),
                        volume_role=self._data_role,
                        volume_path=_path_from_parts(data_parts),
                        evidence="resolved on the Data volume under the mapped target",
                        mapping=mapping.as_dict(),
                    )
                )

            alternatives = self._mapping_alternatives(mapping, union_parts)
            return UnionNode(
                self,
                inode,
                volume=self.data,
                volume_parts=data_parts,
                union_parts=union_parts,
                trace=trace,
                alternatives=alternatives,
            )

        if self.system is not None:
            try:
                inode = self._walk(self.system, parts)
            except UnionVolumeErrorTypes as exc:
                self._augment(exc, parts, trace)
                raise
            trace.append(
                UnionHop(
                    kind="system",
                    union_path=_path_from_parts(union_parts),
                    volume_uuid=_volume_uuid(self.system),
                    volume_role=self._system_role,
                    volume_path=_path_from_parts(parts),
                    evidence="path stayed on the System volume",
                )
            )
            return UnionNode(
                self,
                inode,
                volume=self.system,
                volume_parts=parts,
                union_parts=union_parts,
                trace=trace,
            )

        raise UnionFileNotFoundError(
            f"Path not found in the union view: {_path_from_parts(parts)}",
            scope=self._scope,
            details={
                "path": _path_from_parts(parts),
                "mappings": [mapping.as_dict() for mapping in self.mappings],
                "trace_hops": tuple(trace),
            },
        )

    def _resolve_data(
        self,
        parts: tuple[str, ...],
        trace: list[UnionHop],
        *,
        display_parts: tuple[str, ...] | None = None,
    ) -> UnionNode:
        union_parts = parts if display_parts is None else display_parts
        if self.data is None:
            raise UnionVolumeUnavailableError(
                f"Data volume is required for path: {_path_from_parts(parts)}",
                scope=self._scope,
                details={"path": _path_from_parts(parts), "trace_hops": tuple(trace)},
            )
        try:
            inode = self._walk(self.data, parts)
        except UnionFileNotFoundError as exc:
            raise FirmlinkTargetError(
                f"Data volume path does not exist: {_path_from_parts(parts)}",
                scope=self._scope,
                details={
                    "path": _path_from_parts(parts),
                    "volume_uuid": _uuid_string(self.data),
                    "trace_hops": tuple(trace),
                },
            ) from exc

        trace.append(
            UnionHop(
                kind="data",
                union_path=_path_from_parts(union_parts),
                volume_uuid=_volume_uuid(self.data),
                volume_role=self._data_role,
                volume_path=_path_from_parts(parts),
                evidence="path resolved directly on the Data volume",
            )
        )
        candidate = self._candidate_for_volume(self.data, parts, union_parts, is_firmlink_source=False, selected=True)
        return UnionNode(
            self,
            inode,
            volume=self.data,
            volume_parts=parts,
            union_parts=union_parts,
            trace=trace,
            alternatives=(candidate,),
        )

    def _walk(self, volume: FS, parts: tuple[str, ...], *, mapping: FirmlinkMapping | None = None) -> INode:
        inode = volume.root
        for index, component in enumerate(parts):
            if not inode.is_dir():
                raise UnionNotADirectoryError(
                    f"Not a directory: {_path_from_parts(parts[:index])}",
                    scope=self._scope,
                    details={
                        "path": _path_from_parts(parts[:index]),
                        "mapping": mapping.as_dict() if mapping else None,
                    },
                )
            try:
                entry = inode.get(component)
            except (FileNotFoundError, KeyError) as exc:
                raise UnionFileNotFoundError(
                    f"Path not found: {_path_from_parts(parts[: index + 1])}",
                    scope=self._scope,
                    details={
                        "path": _path_from_parts(parts[: index + 1]),
                        "volume_uuid": _uuid_string(volume),
                        "mapping": mapping.as_dict() if mapping else None,
                    },
                ) from exc
            inode = _entry_inode(entry)
        return inode

    def _try_walk(self, volume: FS | None, parts: tuple[str, ...]) -> INode | None:
        if volume is None:
            return None
        try:
            return self._walk(volume, parts)
        except (VolumeGroupError, FileNotFoundError, NotADirectoryError):
            return None

    def _candidate_for_volume(
        self,
        volume: FS | None,
        volume_parts: tuple[str, ...],
        union_parts: tuple[str, ...],
        *,
        is_firmlink_source: bool,
        evidence: dict[str, Any] | None = None,
        selected: bool = False,
    ) -> UnionCandidate:
        inode: INode | None = None
        error = None
        if volume is None:
            error = "volume not supplied"
        else:
            try:
                inode = self._walk(volume, volume_parts)
            except (VolumeGroupError, FileNotFoundError, NotADirectoryError) as exc:
                error = f"{type(exc).__name__}: {exc}"

        candidate_evidence = dict(evidence or {})
        if inode is not None:
            candidate_evidence["oid"] = getattr(inode, "oid", None)
            candidate_evidence["is_dir"] = inode.is_dir()
            candidate_evidence["is_symlink"] = inode.is_symlink()

        return UnionCandidate(
            union_path=_path_from_parts(union_parts),
            volume_uuid=_volume_uuid(volume) if volume is not None else None,
            volume_role=_role_name(volume) if volume is not None else None,
            volume_name=getattr(volume, "name", None) if volume is not None else None,
            volume_path=_path_from_parts(volume_parts),
            exists=inode is not None,
            selected=selected,
            is_firmlink_source=is_firmlink_source,
            evidence=candidate_evidence,
            error=error,
        )

    def _mapping_alternatives(self, mapping: FirmlinkMapping, parts: tuple[str, ...]) -> tuple[UnionCandidate, ...]:
        remainder = parts[len(mapping.source_parts) :]
        system_parts = mapping.source_parts + remainder
        system_candidate = self._candidate_for_volume(
            self.system,
            system_parts,
            parts,
            is_firmlink_source=True,
            evidence=self._source_evidence(mapping),
        )
        data_candidate = self._candidate_for_volume(
            self.data,
            mapping.target_parts + remainder,
            parts,
            is_firmlink_source=False,
            evidence={"mapping": mapping.as_dict()},
            selected=True,
        )
        return (system_candidate, data_candidate)

    def _augment(
        self,
        exc: VolumeGroupError,
        parts: tuple[str, ...],
        trace: Sequence[UnionHop],
        *,
        mapping: FirmlinkMapping | None = None,
    ) -> None:
        if exc.scope is None:
            exc.scope = self._scope
        exc.details.setdefault("path", _path_from_parts(parts))
        exc.details.setdefault("trace_hops", tuple(trace))
        if mapping is not None:
            exc.details.setdefault("mapping", mapping.as_dict())


def parse_firmlinks(material: str | bytes | Iterable[FirmlinkMapping | str] | None) -> list[FirmlinkMapping]:
    """Parse firmlink mapping material.

    Accepts text lines in ``/usr/share/firmlinks`` style (``source<TAB>target``),
    ``source -> target`` lines, a mapping of source to target, existing mappings,
    or an iterable of either.
    """
    if material is None:
        return []
    if isinstance(material, bytes):
        material = material.decode()
    if isinstance(material, str):
        return _parse_firmlink_text(material)
    if isinstance(material, FirmlinkMapping):
        return [material]
    if isinstance(material, Mapping):
        return parse_firmlinks_item(material)

    result: list[FirmlinkMapping] = []
    for item in material:
        if isinstance(item, FirmlinkMapping):
            result.append(item)
        elif isinstance(item, bytes):
            result.extend(_parse_firmlink_text(item.decode()))
        elif isinstance(item, str):
            result.extend(_parse_firmlink_text(item))
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            source, target = item
            result.append(FirmlinkMapping(str(source), str(target)))
        elif isinstance(item, Mapping):
            result.extend(parse_firmlinks_item(item))
        else:
            raise FirmlinkConflictError(
                "Unsupported firmlink mapping material",
                details={"type": type(item).__name__},
            )
    return result


def parse_firmlinks_item(material: Mapping) -> list[FirmlinkMapping]:
    """Parse a single mapping-like object."""
    result: list[FirmlinkMapping] = []
    for source, target in material.items():
        targets = target if isinstance(target, (list, tuple)) else (target,)
        result.extend(FirmlinkMapping(str(source), str(item)) for item in targets)
    return result


def _parse_material(material: str | bytes | Iterable[FirmlinkMapping | str] | None) -> list[FirmlinkMapping]:
    return parse_firmlinks(material)


def _parse_firmlink_text(text: str) -> list[FirmlinkMapping]:
    result = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "->" in line:
            parts = line.split("->", 1)
        elif "\t" in line:
            parts = line.split("\t", 1)
        elif "=" in line:
            parts = line.split("=", 1)
        else:
            parts = line.split(None, 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            raise FirmlinkConflictError(
                f"Invalid firmlink mapping on line {line_number}",
                details={"line": raw_line},
            )
        try:
            result.append(FirmlinkMapping(parts[0].strip(), parts[1].strip()))
        except (FirmlinkConflictError, ValueError) as exc:
            raise FirmlinkConflictError(
                f"Invalid firmlink mapping on line {line_number}: {exc}",
                details={"line": raw_line},
            ) from exc
    return result


def _canonical_source(value: str) -> str:
    if not isinstance(value, str):
        raise FirmlinkConflictError("Firmlink source must be a string", details={"source": repr(value)})
    if "\x00" in value:
        raise FirmlinkConflictError("Firmlink source contains a NUL byte", details={"source": value})
    if not value.startswith("/"):
        raise FirmlinkConflictError(
            "Firmlink source must be an absolute union path",
            details={"source": value},
        )
    parts = _parts_from_absolute(value)
    return _path_from_parts(parts)


def _canonical_target(value: str) -> str:
    if not isinstance(value, str):
        raise FirmlinkConflictError("Firmlink target must be a string", details={"target": repr(value)})
    if "\x00" in value:
        raise FirmlinkConflictError("Firmlink target contains a NUL byte", details={"target": value})
    target = value.strip()
    if not target:
        raise FirmlinkConflictError("Firmlink target can not be empty")
    _target_parts(target)
    return target


def _target_parts(value: str) -> tuple[str, ...]:
    target = value.strip()
    if target == _DATA_MOUNT_PREFIX or target == _DATA_MOUNT_PREFIX.lstrip("/"):
        return ()
    if target.startswith(_DATA_MOUNT_PREFIX + "/"):
        target = target[len(_DATA_MOUNT_PREFIX) + 1 :]
    elif target.startswith(_DATA_MOUNT_PREFIX.lstrip("/") + "/"):
        target = target[len(_DATA_MOUNT_PREFIX.lstrip("/")) + 1 :]
    elif target.startswith("/"):
        target = target[1:]

    parts = []
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not parts:
                raise FirmlinkConflictError(
                    "Firmlink target escapes the Data volume root",
                    details={"target": value},
                )
            parts.pop()
            continue
        parts.append(component)
    return tuple(parts)


def _normalize_path(path: PathLike) -> tuple[str, ...]:
    if isinstance(path, bytes):
        path = path.decode()
    if not isinstance(path, str):
        path = "/".join(str(part) for part in path)
    if "\x00" in path:
        raise UnionFileNotFoundError("Path contains a NUL byte", details={"path": path})

    parts: list[str] = []
    for component in path.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not parts:
                raise UnionPathTraversalError("Path escapes the union root", details={"path": path})
            parts.pop()
            continue
        parts.append(component)
    return tuple(parts)


def _parts_from_absolute(path: str) -> tuple[str, ...]:
    parts: list[str] = []
    for component in path.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not parts:
                raise FirmlinkConflictError(
                    "Firmlink source escapes the union root",
                    details={"source": path},
                )
            parts.pop()
            continue
        parts.append(component)
    return tuple(parts)


def _link_target_parts(target: str, *, base: tuple[str, ...]) -> tuple[str, ...]:
    if not target or "\x00" in target:
        raise UnionSymlinkTargetError("Invalid symbolic link target", details={"target": target})
    if target.startswith("/"):
        return _normalize_path(target)

    parts = list(base)
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not parts:
                raise UnionPathTraversalError(
                    "Symbolic link target escapes the union root",
                    details={"target": target, "base": _path_from_parts(base)},
                )
            parts.pop()
            continue
        parts.append(component)
    return tuple(parts)


def _path_from_parts(parts: Sequence[str]) -> str:
    if not parts:
        return "/"
    return "/" + "/".join(parts)


def _is_prefix(prefix: tuple[str, ...], value: tuple[str, ...]) -> bool:
    return len(prefix) <= len(value) and value[: len(prefix)] == prefix


def _dedupe_trace(trace: Sequence[UnionHop]) -> tuple[UnionHop, ...]:
    result: list[UnionHop] = []
    for hop in trace:
        if result:
            previous = result[-1]
            if (
                previous.kind == hop.kind
                and previous.union_path == hop.union_path
                and previous.volume_uuid == hop.volume_uuid
                and previous.volume_path == hop.volume_path
            ):
                continue
        result.append(hop)
    return tuple(result)


def _entry_inode(entry: Any) -> INode:
    inode = getattr(entry, "inode", None)
    return inode if inode is not None else entry


def _volume_uuid(volume: FS | None) -> UUID | None:
    if volume is None:
        return None
    uuid = getattr(volume, "uuid", None)
    if isinstance(uuid, UUID):
        return uuid
    if uuid is not None:
        try:
            return UUID(str(uuid))
        except ValueError:
            return None
    return None


def _uuid_string(volume: FS | None) -> str | None:
    uuid = _volume_uuid(volume)
    return str(uuid) if uuid is not None else None


def _volume_group_id(volume: FS | None) -> UUID | None:
    if volume is None:
        return None
    group_id = getattr(volume, "volume_group_id", None)
    if isinstance(group_id, UUID):
        return group_id
    if group_id is None:
        return None
    try:
        return UUID(str(group_id))
    except ValueError:
        return None


def _role_value(volume: FS | None) -> int | None:
    if volume is None:
        return None
    role = getattr(volume, "role", None)
    if role is None:
        return None
    try:
        return int(role)
    except (TypeError, ValueError):
        return None


def _role_name(volume: FS | None) -> str | None:
    if volume is None:
        return None
    role = getattr(volume, "role", None)
    if role is None:
        return None
    return getattr(role, "name", str(role))


def _as_uuid(value: UUID | str | None) -> UUID | None:
    if value is None or isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except ValueError as exc:
        raise VolumeGroupIdentityError(
            "Invalid volume group identifier",
            details={"group_id": str(value)},
        ) from exc


UnionVolumeErrorTypes = (UnionFileNotFoundError, UnionNotADirectoryError, UnionVolumeUnavailableError)


__all__ = [
    "FirmlinkMapping",
    "UnionCandidate",
    "UnionHop",
    "UnionNode",
    "UnionScope",
    "VolumeGroupView",
    "parse_firmlinks",
]
