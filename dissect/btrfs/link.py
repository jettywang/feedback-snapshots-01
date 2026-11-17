from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.util.hash import crc32c

from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.exceptions import (
    DanglingLinkError,
    Error,
    FileNotFoundError,
    LinkBudgetExceeded,
    LinkLoopError,
    LinkNotADirectoryError,
    LinkResolutionError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.btrfs.btrfs import Btrfs, INode, Subvolume


DEFAULT_MAX_HOPS = 40


class LinkStatus(str, Enum):
    """Overall result of resolving a path or symlink."""

    RESOLVED = "resolved"
    NOT_FOUND = "not_found"
    DANGLING = "dangling"
    LOOP = "loop"
    BUDGET_EXHAUSTED = "budget_exhausted"
    NOT_A_DIRECTORY = "not_a_directory"
    ERROR = "error"

    @property
    def ok(self) -> bool:
        return self is LinkStatus.RESOLVED


class LinkHopStatus(str, Enum):
    """Result of one explicit symlink expansion."""

    FOLLOWED = "followed"
    DANGLING = "dangling"
    LOOP = "loop"
    BUDGET_EXHAUSTED = "budget_exhausted"
    NOT_A_DIRECTORY = "not_a_directory"
    ERROR = "error"

    @property
    def ok(self) -> bool:
        return self is LinkHopStatus.FOLLOWED


_STATUS_TO_HOP = {
    LinkStatus.DANGLING: LinkHopStatus.DANGLING,
    LinkStatus.LOOP: LinkHopStatus.LOOP,
    LinkStatus.BUDGET_EXHAUSTED: LinkHopStatus.BUDGET_EXHAUSTED,
    LinkStatus.NOT_A_DIRECTORY: LinkHopStatus.NOT_A_DIRECTORY,
    LinkStatus.ERROR: LinkHopStatus.ERROR,
}


@dataclass(frozen=True, order=True)
class RootIdentity:
    """Identity of one Btrfs root, such as a subvolume or snapshot.

    Inode numbers are only unique inside a root. The filesystem UUID, root
    object ID, root UUID and root tree address together identify the root.
    """

    fsid: UUID
    objectid: int
    uuid: UUID
    bytenr: int

    @classmethod
    def from_subvolume(cls, subvolume: Subvolume) -> RootIdentity:
        root_item = subvolume.tree.root_item
        return cls(
            fsid=subvolume.btrfs.uuid,
            objectid=subvolume.objectid,
            uuid=UUID(bytes=root_item.uuid),
            bytenr=root_item.bytenr,
        )


@dataclass(frozen=True, order=True)
class InodeIdentity:
    """Identity of an inode, qualified by the root that contains it."""

    root: RootIdentity
    inum: int

    @classmethod
    def from_inode(cls, node: INode) -> InodeIdentity:
        return cls(root=RootIdentity.from_subvolume(node.subvolume), inum=node.inum)

    @property
    def fsid(self) -> UUID:
        return self.root.fsid

    @property
    def root_objectid(self) -> int:
        return self.root.objectid

    @property
    def root_uuid(self) -> UUID:
        return self.root.uuid

    @property
    def root_bytenr(self) -> int:
        return self.root.bytenr

    @property
    def inode(self) -> int:
        return self.inum

    def __str__(self) -> str:
        return f"{self.fsid}:{self.root.objectid}:{self.inum}"


@dataclass
class LinkHop:
    """Evidence for one symlink expansion.

    ``base`` is the directory from which the target was interpreted. For an
    absolute target this is the caller selected evidence root. ``result`` is
    the object the jump arrived at when the whole target path resolved.
    """

    index: int
    link: InodeIdentity
    target: str
    base: InodeIdentity
    absolute: bool
    status: LinkHopStatus
    result: InodeIdentity | None = None
    error: str | None = None
    link_path: str = ""
    base_path: str = ""

    @property
    def ok(self) -> bool:
        return self.status is LinkHopStatus.FOLLOWED

    @property
    def inode(self) -> int:
        return self.link.inum

    @property
    def inum(self) -> int:
        return self.link.inum

    @property
    def root(self) -> RootIdentity:
        return self.link.root

    @property
    def resolved(self) -> InodeIdentity | None:
        return self.result


@dataclass
class LinkResolution:
    """Result of an explicit, bounded Btrfs link resolution.

    A successful result has ``status == LinkStatus.RESOLVED`` and ``final``
    set to the resulting object. A failed result keeps every hop that was
    attempted in ``steps`` and exposes the failure through ``error`` and
    ``status``.
    """

    path: str
    evidence_root: INode
    status: LinkStatus
    steps: list[LinkHop] = field(default_factory=list)
    max_hops: int = DEFAULT_MAX_HOPS
    source: INode | None = None
    final: INode | None = None
    last: INode | None = None
    error: LinkResolutionError | None = None
    resolved_path: str = ""

    @property
    def ok(self) -> bool:
        return self.status is LinkStatus.RESOLVED

    @property
    def resolved(self) -> bool:
        return self.ok

    @property
    def success(self) -> bool:
        return self.ok

    @property
    def hops(self) -> int:
        """Number of symlink expansions that were performed."""
        return sum(1 for step in self.steps if step.status is LinkHopStatus.FOLLOWED)

    @property
    def attempted_hops(self) -> int:
        return len(self.steps)

    @property
    def chain(self) -> list[LinkHop]:
        return self.steps

    @property
    def evidence(self) -> list[LinkHop]:
        return self.steps

    @property
    def final_identity(self) -> InodeIdentity | None:
        return InodeIdentity.from_inode(self.final) if self.final is not None else None

    @property
    def error_message(self) -> str | None:
        return str(self.error) if self.error is not None else None

    def __bool__(self) -> bool:
        return self.ok

    def __iter__(self) -> Iterator[LinkHop]:
        return iter(self.steps)

    def __len__(self) -> int:
        return len(self.steps)

    def raise_for_status(self) -> LinkResolution:
        """Raise the recorded failure, if any."""
        if self.error is not None:
            self.error.result = self
            raise self.error
        return self


class _ResolutionFailure(Exception):
    def __init__(
        self,
        status: LinkStatus,
        error: LinkResolutionError,
        last: INode | None,
        stopped_at: INode | None = None,
    ):
        super().__init__(str(error))
        self.status = status
        self.error = error
        self.last = last
        # The symlink object an enclosing jump reached before the failure
        # happened further down the chain. Enclosing hops can record it as
        # their completed result even though the overall resolution failed.
        self.stopped_at = stopped_at


class _Result:
    def __init__(self, inode: INode, path: str):
        self.inode = inode
        self.path = path


class _Resolver:
    def __init__(self, btrfs: Btrfs, evidence_root: INode, max_hops: int, follow_final: bool):
        self.btrfs = btrfs
        self.evidence_root = evidence_root
        self.evidence_root_identity = InodeIdentity.from_inode(evidence_root)
        self.evidence_root_path = _display_path(evidence_root)
        self.max_hops = max_hops
        self.follow_final = follow_final
        self.steps: list[LinkHop] = []
        self.performed = 0

    def resolve(
        self,
        path: str,
        start: INode | None = None,
        start_path: str = "",
        source: INode | None = None,
    ) -> LinkResolution:
        absolute = path.startswith("/")
        if absolute:
            # Absolute paths always begin at the caller selected evidence
            # root, regardless of any starting inode supplied by the caller.
            current = self.evidence_root
            stack: list[str] = []
        else:
            current = start if start is not None else self.evidence_root
            stack = _relative_parts(start_path)

        try:
            result = self._walk(
                path,
                current,
                stack,
                active=(),
                follow_final=self.follow_final,
                missing=LinkStatus.NOT_FOUND,
                boundary=self.evidence_root_identity if absolute else None,
            )
            status = LinkStatus.RESOLVED
            error = None
            final = result.inode
            last = final
            resolved_path = result.path
        except _ResolutionFailure as failure:
            status = failure.status
            error = failure.error
            final = None
            last = failure.last
            resolved_path = ""
        except Error as exc:
            status = LinkStatus.ERROR
            error = LinkResolutionError(str(exc))
            final = None
            last = current
            resolved_path = ""

        return self._finish(path, source, status, final, last, error, resolved_path)

    def follow_inode(self, node: INode) -> LinkResolution:
        """Follow one symlink inode, interpreting a relative target from its directory."""
        path = _display_path(node)
        if not node.is_symlink():
            return self._finish(path, node, LinkStatus.RESOLVED, node, node, None, path)

        containing = node.parent or _recover_parent(node)
        if containing is None:
            error = DanglingLinkError(f"Symlink {node!r} has no containing directory")
            return self._finish(path, node, LinkStatus.DANGLING, None, node, error, "")

        name = _last_component(path) or repr(node)
        stack = _relative_parts(_display_path(containing))

        try:
            result = self._expand(node, name, containing, stack, active=())
            status = LinkStatus.RESOLVED
            error = None
            final = result.inode
            last = final
            resolved_path = result.path
        except _ResolutionFailure as failure:
            status = failure.status
            error = failure.error
            final = None
            last = failure.last
            resolved_path = ""
        except Error as exc:
            status = LinkStatus.ERROR
            error = LinkResolutionError(str(exc))
            final = None
            last = node
            resolved_path = ""

        return self._finish(path, node, status, final, last, error, resolved_path)

    def _finish(
        self,
        path: str,
        source: INode | None,
        status: LinkStatus,
        final: INode | None,
        last: INode | None,
        error: LinkResolutionError | None,
        resolved_path: str,
    ) -> LinkResolution:
        result = LinkResolution(
            path=path,
            evidence_root=self.evidence_root,
            status=status,
            steps=self.steps,
            max_hops=self.max_hops,
            source=source,
            final=final,
            last=last,
            error=error,
            resolved_path=resolved_path,
        )
        if error is not None:
            error.result = result
        return result

    def _walk(
        self,
        path: str,
        current: INode,
        stack: list[str],
        active: tuple[InodeIdentity, ...],
        follow_final: bool,
        missing: LinkStatus,
        boundary: InodeIdentity | None = None,
    ) -> _Result:
        """Walk path components without ever consulting a host path.

        ``boundary`` is set for an absolute path or absolute symlink target:
        that path starts at the evidence root and ``..`` cannot leave it.
        """
        pending = _parts(path)

        while pending:
            component = pending.pop(0)

            if component in ("", "."):
                continue

            if component == "..":
                current, stack = self._up(current, stack, boundary)
                continue

            if not current.is_dir():
                raise _ResolutionFailure(
                    LinkStatus.NOT_A_DIRECTORY,
                    LinkNotADirectoryError(f"{current!r} is not a directory while resolving component {component!r}"),
                    current,
                )

            try:
                child = _lookup(current, component)
            except FileNotFoundError as exc:
                raise _ResolutionFailure(missing, _missing_error(missing, str(exc)), current) from exc
            except Error as exc:
                raise _ResolutionFailure(LinkStatus.ERROR, LinkResolutionError(str(exc)), current) from exc

            is_final = not pending
            if child.is_symlink() and (not is_final or follow_final):
                try:
                    expanded = self._expand(child, component, current, stack, active)
                except _ResolutionFailure as failure:
                    # A final symlink object was found, so the enclosing jump
                    # did reach it even though following it failed. A failure
                    # in a non-final component means the target path itself
                    # was not completed, so no enclosing jump may claim it.
                    failure.stopped_at = child if is_final else None
                    failure.last = failure.last or child
                    raise
                current = expanded.inode
                stack = _relative_parts(expanded.path)
                continue

            current = child
            stack.append(component)

        return _Result(current, "/".join(stack))

    def _expand(
        self,
        link: INode,
        name: str,
        containing: INode,
        stack: list[str],
        active: tuple[InodeIdentity, ...],
    ) -> _Result:
        """Expand one symlink, recording the hop and returning its target object."""
        identity = InodeIdentity.from_inode(link)
        link_path = "/".join([*stack, name])
        target = link.link
        absolute = target.startswith("/")
        base = self.evidence_root if absolute else containing

        hop = LinkHop(
            index=len(self.steps),
            link=identity,
            target=target,
            base=InodeIdentity.from_inode(base),
            absolute=absolute,
            status=LinkHopStatus.FOLLOWED,
            link_path=link_path,
            base_path=self.evidence_root_path if absolute else "/".join(stack),
        )
        self.steps.append(hop)

        if identity in active:
            hop.status = LinkHopStatus.LOOP
            hop.error = f"Symlink loop detected at {identity} ({link_path})"
            raise _ResolutionFailure(LinkStatus.LOOP, LinkLoopError(hop.error), link)

        if self.performed >= self.max_hops:
            hop.status = LinkHopStatus.BUDGET_EXHAUSTED
            hop.error = f"Link hop budget of {self.max_hops} exhausted at {identity} ({link_path})"
            raise _ResolutionFailure(LinkStatus.BUDGET_EXHAUSTED, LinkBudgetExceeded(hop.error), link)

        if target == "":
            hop.status = LinkHopStatus.DANGLING
            hop.error = f"Empty symlink target at {identity} ({link_path})"
            raise _ResolutionFailure(LinkStatus.DANGLING, DanglingLinkError(hop.error), link)

        self.performed += 1
        base_stack = [] if absolute else list(stack)

        try:
            result = self._walk(
                target,
                base,
                base_stack,
                active=(*active, identity),
                follow_final=True,
                missing=LinkStatus.DANGLING,
                boundary=self.evidence_root_identity if absolute else None,
            )
        except _ResolutionFailure as failure:
            # This jump's target path reached the next link object. The jump
            # itself is completed evidence; the failure belongs to the deeper
            # hop that expands that object. The repeat detection has already
            # marked the offending hop as LOOP.
            if failure.stopped_at is not None:
                hop.result = InodeIdentity.from_inode(failure.stopped_at)
                hop.status = LinkHopStatus.FOLLOWED
            else:
                hop.status = _STATUS_TO_HOP.get(failure.status, LinkHopStatus.ERROR)
                hop.error = str(failure.error)
            raise

        hop.result = InodeIdentity.from_inode(result.inode)
        return result

    def _up(self, current: INode, stack: list[str], boundary: InodeIdentity | None) -> tuple[INode, list[str]]:
        # An absolute path or absolute symlink target starts at the evidence
        # root, and that root is a namespace boundary: its parent is never
        # consulted. Relative paths keep their real Btrfs parent context,
        # including the directory in which a subvolume is mounted.
        if boundary is not None and InodeIdentity.from_inode(current) == boundary:
            return current, stack

        parent = self._parent_of(current)
        if parent is None:
            # A subvolume root with no observable parent has no directory to
            # return to; ".." stays at that root instead of touching a host
            # path or inventing a parent.
            return current, stack

        return parent, stack[:-1] if stack else stack

    def _parent_of(self, node: INode) -> INode | None:
        if node.parent is not None:
            return node.parent

        if node.inum == node.subvolume.tree.root_item.root_dirid:
            # A separately opened subvolume root has no parent object chained
            # to it. Recover the directory in which the subvolume is mounted
            # from the root backref, entirely inside Btrfs metadata.
            try:
                item, data = self.btrfs._root_tree.find(
                    objectid=node.subvolume.objectid,
                    type=c_btrfs.BTRFS_ROOT_BACKREF_KEY,
                )
            except KeyError:
                return None

            root_ref = c_btrfs.btrfs_root_ref(data)
            parent_subvolume = self.btrfs.open_subvolume(item.key.offset)
            return parent_subvolume.inode(root_ref.dirid, c_btrfs.BTRFS_FT_DIR)

        return _recover_parent(node)


def resolve_link(
    fs: Btrfs | INode | Subvolume,
    path: str | None = None,
    *,
    root: Subvolume | INode | str | int | None = None,
    node: INode | None = None,
    max_hops: int = DEFAULT_MAX_HOPS,
    follow_final: bool = True,
    strict: bool = False,
) -> LinkResolution:
    """Resolve a path or symlink explicitly inside the Btrfs namespace.

    Relative symlink targets are interpreted from the directory that contains
    the link. Absolute targets are interpreted from ``root``, the evidence
    root selected by the caller. ``root`` is also a namespace boundary, so
    ``..`` can never leave it and no host path is ever consulted.

    Args:
        fs: A filesystem, subvolume or inode to resolve in.
        path: The path to resolve. If ``fs`` is an :class:`INode` and this is
            ``None``, the inode is followed when it is a symlink.
        root: Optional evidence root: a subvolume, directory inode, path or
            subvolume object ID.
        node: Optional inode used as the starting directory for a relative path.
        max_hops: Caller supplied maximum number of symlink expansions.
        follow_final: Whether a symlink in the final path component is followed.
        strict: Raise the recorded error on failure instead of returning it.
    """
    _validate_max_hops(max_hops)

    from dissect.btrfs.btrfs import Btrfs, INode, Subvolume

    if isinstance(fs, Btrfs):
        btrfs = fs
        if isinstance(path, int):
            path = fs.default_subvolume.inode(path)
    elif isinstance(fs, Subvolume):
        btrfs = fs.btrfs
        root = fs if root is None else root
        if isinstance(path, int):
            path = fs.inode(path)
    elif isinstance(fs, INode):
        btrfs = fs.btrfs
        root = fs.subvolume if root is None else root
        if path is None:
            resolver = _Resolver(btrfs, _coerce_root(btrfs, root), max_hops, follow_final)
            result = resolver.follow_inode(fs)
            if strict:
                result.raise_for_status()
            return result
    else:
        raise TypeError(f"Unsupported filesystem object: {type(fs)!r}")

    if isinstance(path, INode):
        resolver = _Resolver(btrfs, _coerce_root(btrfs, root), max_hops, follow_final)
        result = resolver.follow_inode(path)
        if strict:
            result.raise_for_status()
        return result

    if path is None:
        path = ""
    if not isinstance(path, str):
        raise TypeError("path must be a string")

    evidence_root = _coerce_root(btrfs, root)
    resolver = _Resolver(btrfs, evidence_root, max_hops, follow_final)
    start = node if node is not None else evidence_root
    start_path = _display_path(start) if node is not None else ""

    result = resolver.resolve(path, start=start, start_path=start_path, source=node)
    if strict:
        result.raise_for_status()
    return result


def resolve_symlink(fs: Btrfs | INode | Subvolume, path: str | None = None, **kwargs: Any) -> LinkResolution:
    """Alias for :func:`resolve_link`."""
    return resolve_link(fs, path, **kwargs)


# Short aliases and historical spellings for callers that import the module
# directly or expect link-oriented names.
resolve = resolve_link
LinkStep = LinkHop
LinkEvidence = LinkHop
ResolvedLink = LinkResolution
SymlinkLoopError = LinkLoopError
HopBudgetExceeded = LinkBudgetExceeded


def _coerce_root(
    btrfs: Btrfs,
    root: Subvolume | INode | str | int | None,
    default: INode | None = None,
) -> INode:
    from dissect.btrfs.btrfs import INode, Subvolume

    if root is None:
        return default if default is not None else btrfs.root

    if isinstance(root, Subvolume):
        return root.root
    if isinstance(root, INode):
        return root
    if isinstance(root, int):
        return btrfs.open_subvolume(root).root
    if isinstance(root, str):
        node = btrfs.get(root)
        if not node.is_dir():
            raise LinkNotADirectoryError(f"Evidence root {root!r} is not a directory")
        return node

    raise TypeError(f"Unsupported evidence root: {type(root)!r}")


def _lookup(directory: INode, name: str) -> INode:
    """Look up one name in a directory without following a symlink."""
    name_bytes = name.encode(errors="surrogateescape")
    name_hash = (crc32c.update(1, name_bytes) ^ 0xFFFFFFFF) & 0xFFFFFFFF

    for _, data in directory.subvolume.tree.cursor().iter(directory.inum, c_btrfs.BTRFS_DIR_ITEM_KEY, name_hash):
        try:
            for dir_item in _iter_dir_items(data):
                if dir_item.name == name_bytes:
                    return _dir_item_target(directory, dir_item)
        except EOFError as exc:
            raise Error(
                f"Corrupt dir_item in directory inode {directory.inum} " f"of subvolume {directory.subvolume.objectid}"
            ) from exc

    raise FileNotFoundError(
        f"File not found: {name!r} in directory inode {directory.inum} " f"of subvolume {directory.subvolume.objectid}"
    )


def _dir_item_target(directory: INode, dir_item: c_btrfs.btrfs_dir_item) -> INode:
    location = dir_item.location

    if location.type == c_btrfs.BTRFS_ROOT_ITEM_KEY:
        # Bind the subvolume root to the directory in which it was found, so
        # that ".." from that root returns to that directory and never to a
        # separately opened copy or to the host.
        return directory.btrfs.open_subvolume(location.objectid, directory).root
    if location.type == c_btrfs.BTRFS_INODE_ITEM_KEY:
        return directory.subvolume.inode(location.objectid, dir_item.type, directory)

    raise NotImplementedError(f"Unknown dir_item type: {location.type}")


def _iter_dir_items(data: memoryview) -> Iterable[c_btrfs.btrfs_dir_item]:
    """Iterate all ``btrfs_dir_item`` records packed in one tree item."""
    offset = 0
    while offset < len(data):
        dir_item = c_btrfs.btrfs_dir_item(data[offset:])
        yield dir_item
        offset += len(dir_item)


def _missing_error(status: LinkStatus, message: str) -> LinkResolutionError:
    return DanglingLinkError(message) if status is LinkStatus.DANGLING else LinkResolutionError(message)


def _parts(path: str) -> list[str]:
    return path.split("/")


def _relative_parts(path: str) -> list[str]:
    return [part for part in path.split("/") if part and part != "."]


def _last_component(path: str) -> str:
    parts = _relative_parts(path)
    return parts[-1] if parts else ""


def _display_path(node: INode) -> str:
    try:
        return node.full_path
    except Exception:
        try:
            return node.path
        except Exception:
            return repr(node)


def _recover_parent(node: INode) -> INode | None:
    """Best effort parent recovery for an inode not obtained through traversal."""
    try:
        for parent in node.parents:
            if InodeIdentity.from_inode(parent) != InodeIdentity.from_inode(node):
                return parent
    except Exception:
        return None
    return None


def _validate_max_hops(max_hops: int) -> None:
    if not isinstance(max_hops, int) or isinstance(max_hops, bool) or max_hops < 0:
        raise ValueError("max_hops must be a non-negative integer")
