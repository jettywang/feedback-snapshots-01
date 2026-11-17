"""Reconcile XFS directory references with the link counts declared by inodes.

XFS stores no back reference from an inode to the directory entries that name it. Auditing a link count
therefore requires walking the namespace from a chosen directory and collecting every entry that points at
the inode. This module does that walk and returns a reviewable relationship graph rather than a single
verdict.

Objects are identified by **inode position and generation** (:class:`InodeKey`). A directory entry only
records an inode number, so an inode number that was reused after deletion would otherwise inherit the
relations of its previous occupant. Edges are attached to a key, never to a bare inode number. Callers that
already know which generation they are investigating can pass ``expected_generations``; entries that now hit
a different generation are reported as :attr:`EdgeStatus.GENERATION_MISMATCH` and are excluded from the new
object's count.

Every directory entry becomes its own edge, so hard links are preserved individually: two names for one inode
are two edges and both count towards the observed link total.

Directories are counted with the XFS rules, not like regular files. A directory declares one link for its own
``.`` entry, one for the name it has in its parent, and one ``..`` entry in each immediate child directory.
A regular file only declares one link per name that points at it. A ``.`` or ``..`` entry that points at a
non-directory is reported as an anomaly and is not folded into that object's observed count.

Coverage is part of the conclusion. When a directory cannot be fully enumerated (corrupt data fork, invalid
block, unsupported format), a duplicate name makes its contents ambiguous, its ``..`` entry disagrees with
the name edge that reached it, or the walk was deliberately bounded (a non-root start or ``max_depth``), the
number of observed references is only a **lower bound**. Such a node gets :attr:`LinkVerdict.LOWER_BOUND` and
a shortfall against ``nlink`` is never presented as evidence that the link count was tampered with. A lower
bound that already exceeds ``nlink`` is still :attr:`LinkVerdict.SURPLUS`: incomplete coverage can hide
references, but it cannot explain away the references that were observed.
"""

from __future__ import annotations

import enum
import stat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.xfs.c_xfs import FILETYPES
from dissect.xfs.exceptions import Error
from dissect.xfs.xfs import DirectoryEntry, INode

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from dissect.xfs.xfs import XFS


class EdgeKind(str, enum.Enum):
    """The role a directory entry plays in link accounting."""

    NAME = "name"
    """A normal file name. Every hard link is a separate ``NAME`` edge."""

    DOT = "dot"
    """The ``.`` entry of a directory."""

    DOTDOT = "dotdot"
    """The ``..`` entry of a directory."""


class EdgeStatus(str, enum.Enum):
    """Whether an entry could be tied to the object currently stored at its inode number."""

    RESOLVED = "resolved"
    """The target inode was read and its identity agrees with the entry."""

    FREE_INODE = "free_inode"
    """The target inode slot is free (``di_mode == 0``); the entry is a stale or dangling reference."""

    UNREADABLE = "unreadable"
    """The target inode could not be parsed."""

    OUT_OF_RANGE = "out_of_range"
    """The recorded inode number is outside the filesystem."""

    TYPE_MISMATCH = "type_mismatch"
    """The entry's recorded file type disagrees with the inode now at that number."""

    GENERATION_MISMATCH = "generation_mismatch"
    """The inode now at that number has a different generation than the caller expected."""


class LinkVerdict(str, enum.Enum):
    """Comparison between the observed references and the declared link count."""

    CONSISTENT = "consistent"
    """Coverage is complete and the observed references equal ``nlink``."""

    SHORTFALL = "shortfall"
    """Coverage is complete but fewer references were observed than ``nlink`` declares."""

    SURPLUS = "surplus"
    """More references were observed than ``nlink`` declares. The observed count is a sound lower bound."""

    LOWER_BOUND = "lower_bound"
    """Coverage is incomplete and the observed count does not exceed ``nlink``; nothing further is implied."""


COUNTED_STATUSES = frozenset({EdgeStatus.RESOLVED})

PARSE_FAILURES = (Error, EOFError, ValueError)


@dataclass(frozen=True, order=True)
class InodeKey:
    """Identity of an inode: its absolute position and generation.

    Two observations with the same inode number but a different generation are distinct objects. Edges are
    attached to a key, never to the bare inode number.
    """

    inum: int
    generation: int

    def __str__(self) -> str:
        return f"{self.inum}:{self.generation}"


@dataclass(frozen=True)
class ReferenceEdge:
    """A single directory entry observed while walking the namespace.

    Attributes:
        parent: Identity of the directory that contains the entry.
        name: The entry name (``.`` and ``..`` included).
        kind: Whether this is a normal name or a ``.``/``..`` entry.
        inum: The absolute inode number recorded in the entry.
        target: Identity of the inode actually found at ``inum``, when it could be read.
        status: Whether the entry could be tied to ``target``.
        filetype: Raw ftype byte from the entry, or ``None`` if the entry has none.
        mode: ``stat`` mode of the target when it could be read.
        block: Directory data block holding the entry, or ``None`` for shortform directories.
        offset: Offset of the entry inside its block, or ``None`` for shortform directories.
        index: Ordinal of the entry within the directory or block.
    """

    parent: InodeKey
    name: str
    kind: EdgeKind
    inum: int
    target: InodeKey | None
    status: EdgeStatus
    filetype: int | None = None
    mode: int | None = None
    block: int | None = None
    offset: int | None = None
    index: int | None = None

    @property
    def counted(self) -> bool:
        """Return whether this edge contributes to the target's observed link count."""
        return self.status in COUNTED_STATUSES

    @property
    def target_mode(self) -> int | None:
        """Return the target inode's file type bits, if known."""
        return None if self.mode is None else stat.S_IFMT(self.mode)

    @property
    def may_be_directory(self) -> bool:
        """Return whether this entry could refer to a directory that was not entered.

        Used to decide whether an excluded entry hides part of the namespace. The recorded ftype is used
        when the inode itself cannot be read, because a corrupt but directory-typed entry may still have
        children an examiner would expect to see.
        """
        if self.target_mode is not None:
            return self.target_mode == stat.S_IFDIR
        if self.filetype is not None:
            return FILETYPES.get(self.filetype) == stat.S_IFDIR
        return True


@dataclass
class DirectoryScan:
    """The outcome of enumerating one directory.

    Attributes:
        key: Identity of the directory.
        path: Path at which the directory was first reached from the selected root.
        depth: Distance from the selected root.
        complete: Whether enumeration finished without an error or ambiguity.
        error: Description of the problems that make this scan incomplete, if any.
        entry_count: Number of entries yielded before completion or failure.
        duplicate_names: Names that occurred more than once in this directory.
        dot_target: Identity named by the ``.`` entry, if the entry was seen and readable.
        dotdot_target: Identity named by the ``..`` entry, if the entry was seen and readable.
        parent_name_edges: Directories that contain a name edge for this directory.
        child_directories: Directories reached from this directory by name.
    """

    key: InodeKey
    path: str
    depth: int
    complete: bool = True
    error: str | None = None
    entry_count: int = 0
    duplicate_names: list[str] = field(default_factory=list)
    dot_target: InodeKey | None = None
    dotdot_target: InodeKey | None = None
    parent_name_edges: list[InodeKey] = field(default_factory=list)
    child_directories: list[InodeKey] = field(default_factory=list)


@dataclass
class LinkNode:
    """Link accounting for one object in the relationship graph.

    Attributes:
        key: Identity of the object.
        inode: The parsed inode.
        filetype: File type bits of the inode.
        declared_nlink: Link count stored in the inode.
        observed_names: ``NAME`` edges attributed to this object.
        observed_dot: ``.`` edges attributed to this object.
        observed_dotdot: ``..`` edges attributed to this object.
        observed: References used for the comparison, using the directory or file counting rule.
        excluded: Entries that named this inode number but could not be tied to this object.
        depth: Distance from the selected root, or ``None`` if the object was not reached by a name.
        path: Path at which the object was first reached from the selected root, if any.
        scanned: Whether this object's directory entries were enumerated.
        lower_bound: Whether ``observed`` is a lower bound of the true reference count.
        verdict: Comparison between ``observed`` and ``declared_nlink``.
        reasons: Human-readable evidence supporting ``verdict``.
    """

    key: InodeKey
    inode: INode
    filetype: int
    declared_nlink: int
    observed_names: int = 0
    observed_dot: int = 0
    observed_dotdot: int = 0
    observed: int = 0
    excluded: int = 0
    depth: int | None = None
    path: str | None = None
    scanned: bool = False
    lower_bound: bool = True
    verdict: LinkVerdict = LinkVerdict.LOWER_BOUND
    reasons: list[str] = field(default_factory=list)

    @property
    def is_directory(self) -> bool:
        """Return whether the object is a directory."""
        return self.filetype == stat.S_IFDIR

    @property
    def surplus(self) -> int:
        """Return how many more references were observed than declared (negative for a shortfall)."""
        return self.observed - self.declared_nlink


@dataclass
class LinkAudit:
    """Result of a directory reference reconciliation walk."""

    xfs: XFS
    root: InodeKey
    nodes: dict[InodeKey, LinkNode]
    edges: list[ReferenceEdge]
    directories: dict[InodeKey, DirectoryScan]
    coverage_complete: bool
    coverage_reasons: list[str]
    is_filesystem_root: bool

    def __repr__(self) -> str:
        return (
            f"<LinkAudit root={self.root} nodes={len(self.nodes)} edges={len(self.edges)} "
            f"complete={self.coverage_complete}>"
        )

    def node(self, target: int | InodeKey | INode) -> LinkNode:
        """Return the node for an inode number, key or inode object.

        Raises:
            KeyError: If the object is not part of this audit or the number is ambiguous.
        """
        if isinstance(target, INode):
            key = InodeKey(target.inum, target.generation)
        elif isinstance(target, InodeKey):
            key = target
        else:
            matches = [key for key in self.nodes if key.inum == target]
            if len(matches) != 1:
                raise KeyError(f"inode number {target} does not identify exactly one audited object")
            key = matches[0]
        return self.nodes[key]

    def edges_to(self, target: int | InodeKey) -> list[ReferenceEdge]:
        """Return every recorded entry that names the given inode number or key."""
        if isinstance(target, InodeKey):
            return [edge for edge in self.edges if edge.target == target]
        return [edge for edge in self.edges if edge.inum == target]

    @property
    def identity_map(self) -> dict[int, int]:
        """Return the generation observed for every audited inode number."""
        return {key.inum: key.generation for key in self.nodes}

    def problems(self) -> list[LinkNode]:
        """Return the nodes that are not consistent or that are only lower bounds."""
        return [node for node in self.nodes.values() if node.verdict is not LinkVerdict.CONSISTENT]

    def summary(self) -> dict[str, int]:
        """Count the nodes per verdict."""
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            counts[node.verdict.value] = counts.get(node.verdict.value, 0) + 1
        return counts

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation of the whole graph."""

        def key_dict(key: InodeKey | None) -> dict[str, int] | None:
            return None if key is None else {"inum": key.inum, "generation": key.generation}

        return {
            "root": key_dict(self.root),
            "is_filesystem_root": self.is_filesystem_root,
            "coverage_complete": self.coverage_complete,
            "coverage_reasons": list(self.coverage_reasons),
            "nodes": [
                {
                    "inum": node.key.inum,
                    "generation": node.key.generation,
                    "filetype": node.filetype,
                    "directory": node.is_directory,
                    "declared_nlink": node.declared_nlink,
                    "observed": node.observed,
                    "observed_names": node.observed_names,
                    "observed_dot": node.observed_dot,
                    "observed_dotdot": node.observed_dotdot,
                    "excluded": node.excluded,
                    "path": node.path,
                    "depth": node.depth,
                    "scanned": node.scanned,
                    "lower_bound": node.lower_bound,
                    "verdict": node.verdict.value,
                    "reasons": list(node.reasons),
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "parent": key_dict(edge.parent),
                    "name": edge.name,
                    "kind": edge.kind.value,
                    "inum": edge.inum,
                    "target": key_dict(edge.target),
                    "status": edge.status.value,
                    "counted": edge.counted,
                    "filetype": edge.filetype,
                    "mode": edge.mode,
                    "block": edge.block,
                    "offset": edge.offset,
                    "index": edge.index,
                }
                for edge in self.edges
            ],
            "directories": [
                {
                    "inum": scan.key.inum,
                    "generation": scan.key.generation,
                    "path": scan.path,
                    "depth": scan.depth,
                    "complete": scan.complete,
                    "error": scan.error,
                    "entries": scan.entry_count,
                    "duplicate_names": list(scan.duplicate_names),
                    "dot_target": key_dict(scan.dot_target),
                    "dotdot_target": key_dict(scan.dotdot_target),
                    "parent_name_edges": [key_dict(parent) for parent in scan.parent_name_edges],
                    "child_directories": [key_dict(child) for child in scan.child_directories],
                }
                for scan in self.directories.values()
            ],
        }

    def describe(self) -> Iterator[str]:
        """Yield a human-readable line per node and per questionable entry.

        The lines are explicit about coverage, so a report can quote them without turning a lower bound into
        a tampering conclusion.
        """
        for node in sorted(self.nodes.values(), key=lambda node: (node.key.inum, node.key.generation)):
            label = node.path if node.path is not None else f"<{node.key}>"
            if node.is_directory:
                indicators = f"dot={node.observed_dot} name={node.observed_names} dotdot={node.observed_dotdot}"
            else:
                indicators = f"names={node.observed_names}"
            if node.excluded:
                indicators += f" excluded={node.excluded}"
            yield (
                f"{label} ({node.key}) type={node.filetype:#o} declared={node.declared_nlink} "
                f"observed={node.observed} [{indicators}] lower_bound={node.lower_bound} "
                f"verdict={node.verdict.value}"
            )
            for reason in node.reasons:
                yield f"  - {reason}"

        for edge in self.edges:
            if edge.status is EdgeStatus.RESOLVED:
                continue
            yield (
                f"entry {edge.parent}:{edge.name} -> inode {edge.inum} status={edge.status.value} "
                f"(block={edge.block}, offset={edge.offset}, index={edge.index})"
            )


def reconcile_links(
    xfs: XFS,
    root: INode | int | str | None = None,
    *,
    expected_generations: Mapping[int, int] | None = None,
    max_depth: int | None = None,
) -> LinkAudit:
    """Walk directory references from ``root`` and compare them with each inode's ``nlink``.

    Args:
        xfs: The filesystem to inspect. It is only read, never modified.
        root: The directory to start from: an :class:`INode`, an absolute inode number, a path, or ``None``
            for the filesystem root.
        expected_generations: Optional mapping of inode number to the generation observed earlier. Directory
            entries do not record a generation; supplying this mapping lets the walk refuse to attach an old
            name to an inode number that has since been reused.
        max_depth: Optional recursion limit. Directories at this depth are not entered, so the resulting
            counts become lower bounds.

    Returns:
        A :class:`LinkAudit` with the nodes, edges and per-node verdicts.

    Raises:
        Error: If the root inode cannot be parsed.
        FileNotFoundError: If ``root`` is a path that does not exist.
    """
    root_inode = _coerce_root(xfs, root)
    return _Walker(xfs, dict(expected_generations or {}), max_depth).run(root_inode)


def _coerce_root(xfs: XFS, root: INode | int | str | None) -> INode:
    if root is None:
        return xfs.root
    if isinstance(root, INode):
        return root
    if isinstance(root, str):
        return xfs.get(root)
    return xfs.get_inode(root)


@dataclass
class _Target:
    """A parsed target inode, cached per inode number."""

    key: InodeKey
    mode: int
    inode: INode


class _Walker:
    def __init__(self, xfs: XFS, expected: dict[int, int], max_depth: int | None) -> None:
        self.xfs = xfs
        self.expected = expected
        self.max_depth = max_depth

        self.states: dict[InodeKey, _NodeState] = {}
        self.edges: list[ReferenceEdge] = []
        self.directories: dict[InodeKey, DirectoryScan] = {}
        self.coverage_reasons: list[str] = []
        self.is_filesystem_root = False
        self.truncated = False
        self.hidden_subtrees = 0

        self._targets: dict[int, tuple[_Target | None, EdgeStatus]] = {}
        self._counts: dict[InodeKey, list[int]] = {}
        self._queue: list[tuple[INode, InodeKey, int, str]] = []
        self._scheduled: set[InodeKey] = set()

    def run(self, root_inode: INode) -> LinkAudit:
        root_key = InodeKey(root_inode.inum, root_inode.generation)
        self.is_filesystem_root = root_inode.inum == self.xfs.sb.sb_rootino
        if not self.is_filesystem_root:
            self.coverage_reasons.append(
                "the selected root is not the filesystem root, so references from outside the subtree are unknown"
            )

        self._state(root_key, root_inode, depth=0, path="/")
        self._schedule(root_inode, root_key, 0, "/")

        while self._queue:
            inode, key, depth, path = self._queue.pop(0)
            self._scan_directory(inode, key, depth, path)

        self._check_directories()

        if self.truncated:
            self.coverage_reasons.append(f"the walk stopped at max_depth={self.max_depth}")
        for scan in self.directories.values():
            if not scan.complete and scan.error is not None:
                self.coverage_reasons.append(f"directory {scan.path} ({scan.key}): {scan.error}")
        if self.hidden_subtrees:
            self.coverage_reasons.append(
                f"{self.hidden_subtrees} excluded entry/entries could refer to directories that were not enumerated"
            )

        coverage_complete = (
            self.is_filesystem_root
            and not self._incomplete_directories()
            and not self.truncated
            and not self.hidden_subtrees
        )
        nodes = self._finalize(coverage_complete)

        return LinkAudit(
            xfs=self.xfs,
            root=root_key,
            nodes=nodes,
            edges=self.edges,
            directories=self.directories,
            coverage_complete=coverage_complete,
            coverage_reasons=self.coverage_reasons,
            is_filesystem_root=self.is_filesystem_root,
        )

    def _state(self, key: InodeKey, inode: INode, depth: int | None = None, path: str | None = None) -> _NodeState:
        state = self.states.get(key)
        if state is None:
            state = _NodeState(key, inode, inode.filetype, inode.nlink)
            self.states[key] = state
        if depth is not None and (state.depth is None or depth < state.depth):
            state.depth = depth
            state.path = path
        return state

    def _schedule(self, inode: INode, key: InodeKey, depth: int, path: str) -> None:
        if key in self._scheduled:
            return
        self._scheduled.add(key)
        self._queue.append((inode, key, depth, path))

    def _inspect(self, inum: int) -> tuple[_Target | None, EdgeStatus]:
        """Return the parsed target and the failure status, caching per inode number."""
        if inum in self._targets:
            return self._targets[inum]

        result: tuple[_Target | None, EdgeStatus]
        try:
            inode = self.xfs.get_inode(inum)
        except Error:
            result = (None, EdgeStatus.OUT_OF_RANGE)
        else:
            try:
                raw = inode.inode
            except PARSE_FAILURES:
                result = (None, EdgeStatus.UNREADABLE)
            else:
                result = (_Target(InodeKey(inum, raw.di_gen), raw.di_mode, inode), EdgeStatus.RESOLVED)
        self._targets[inum] = result
        return result

    def _scan_directory(self, inode: INode, key: InodeKey, depth: int, path: str) -> None:
        state = self._state(key, inode, depth, path)
        state.scanned = True

        entries: list[DirectoryEntry] = []
        error: str | None = None
        iterator = inode.iter_entries()
        try:
            while True:
                entries.append(next(iterator))
        except StopIteration:
            pass
        except PARSE_FAILURES as exc:
            error = str(exc)

        scan = DirectoryScan(
            key=key,
            path=path,
            depth=depth,
            complete=error is None,
            error=error,
            entry_count=len(entries),
        )
        self.directories[key] = scan

        seen_names: dict[str, int] = {}
        for entry in entries:
            if entry.name in seen_names:
                seen_names[entry.name] += 1
                if seen_names[entry.name] == 2:
                    scan.duplicate_names.append(entry.name)
            else:
                seen_names[entry.name] = 1

            edge = self._make_edge(key, entry, depth, path)
            self.edges.append(edge)

            if edge.kind is EdgeKind.DOT and edge.target is not None:
                scan.dot_target = edge.target
            elif edge.kind is EdgeKind.DOTDOT and edge.target is not None:
                scan.dotdot_target = edge.target

            self._account(edge)

            if edge.kind is EdgeKind.DOT and edge.counted and edge.target != key:
                scan.error = _append_issue(
                    scan.error, f"the . entry points at inode {edge.inum}, not at the directory itself"
                )
            if edge.kind is EdgeKind.DOTDOT and edge.counted and edge.target_mode != stat.S_IFDIR:
                scan.error = _append_issue(
                    scan.error, f"the .. entry points at inode {edge.inum}, which is not a directory"
                )

            if edge.kind is EdgeKind.NAME and edge.counted and edge.target_mode == stat.S_IFDIR:
                scan.child_directories.append(edge.target)
                if self.max_depth is not None and depth >= self.max_depth:
                    self.truncated = True
                    continue
                target = self._targets[edge.inum][0]
                assert target is not None
                child_path = _join(path, edge.name)
                child = self._state(edge.target, target.inode, depth + 1, child_path)
                self._schedule(child.inode, edge.target, depth + 1, child_path)

        if scan.duplicate_names:
            scan.complete = False
            scan.error = _append_issue(
                scan.error, f"duplicate name(s) make entry ownership ambiguous: {', '.join(scan.duplicate_names)}"
            )
        elif scan.error is not None:
            scan.complete = False

    def _account(self, edge: ReferenceEdge) -> None:
        if edge.counted and edge.target is not None:
            counts = self._counts.setdefault(edge.target, [0, 0, 0])
            if edge.kind is EdgeKind.NAME:
                counts[0] += 1
            elif edge.kind is EdgeKind.DOT:
                counts[1] += 1
            else:
                counts[2] += 1
            return

        if edge.may_be_directory:
            # An entry that is not tied to a readable inode could still be a directory whose contents were
            # therefore never enumerated. Keep that uncertainty visible.
            self.hidden_subtrees += 1
        if edge.target is not None:
            state = self.states.get(edge.target)
            if state is not None:
                state.uncertain = True

    def _make_edge(self, parent: InodeKey, entry: DirectoryEntry, depth: int, path: str) -> ReferenceEdge:
        kind = _kind(entry.name)
        target, failure = self._inspect(entry.inum)
        if target is None:
            return ReferenceEdge(
                parent=parent,
                name=entry.name,
                kind=kind,
                inum=entry.inum,
                target=None,
                status=failure,
                filetype=entry.filetype,
                block=entry.block,
                offset=entry.offset,
                index=entry.index,
            )

        if target.mode == 0:
            # A free inode slot holds no object; the entry is stale but must stay visible as evidence. It is
            # deliberately not attached to any node: there is no current object to account links for.
            return ReferenceEdge(
                parent=parent,
                name=entry.name,
                kind=kind,
                inum=entry.inum,
                target=None,
                status=EdgeStatus.FREE_INODE,
                filetype=entry.filetype,
                mode=target.mode,
                block=entry.block,
                offset=entry.offset,
                index=entry.index,
            )

        status = EdgeStatus.RESOLVED
        expected_generation = self.expected.get(entry.inum)
        if expected_generation is not None and expected_generation != target.key.generation:
            status = EdgeStatus.GENERATION_MISMATCH
        elif entry.filetype is not None:
            declared_type = FILETYPES.get(entry.filetype)
            if declared_type is not None and declared_type != stat.S_IFMT(target.mode):
                status = EdgeStatus.TYPE_MISMATCH

        child_depth = depth + 1
        child_path = _join(path, entry.name)
        if status is EdgeStatus.RESOLVED:
            # Only a name that actually reaches this object may contribute a path; a stale or
            # generation-mismatched entry must not make a new object look reachable under an old name.
            self._state(target.key, target.inode, depth=child_depth, path=child_path)

        return self._edge(parent, entry, kind, target.key, status, target.mode)

    def _edge(
        self,
        parent: InodeKey,
        entry: DirectoryEntry,
        kind: EdgeKind,
        key: InodeKey,
        status: EdgeStatus,
        mode: int,
    ) -> ReferenceEdge:
        return ReferenceEdge(
            parent=parent,
            name=entry.name,
            kind=kind,
            inum=entry.inum,
            target=key,
            status=status,
            filetype=entry.filetype,
            mode=mode,
            block=entry.block,
            offset=entry.offset,
            index=entry.index,
        )

    def _check_directories(self) -> None:
        for key, scan in self.directories.items():
            name_edges = [
                edge for edge in self.edges if edge.target == key and edge.kind is EdgeKind.NAME and edge.counted
            ]
            parents = {edge.parent for edge in name_edges}
            scan.parent_name_edges = sorted(parents)
            if len(name_edges) > 1:
                # Two names for one directory are two hard links to a directory, which XFS does not create.
                # Either the name edges or the inode are inconsistent, so the subtree is not fully trustworthy.
                scan.complete = False
                joined = ", ".join(f"{edge.parent}:{edge.name}" for edge in name_edges)
                scan.error = _append_issue(scan.error, f"directory has multiple name edges: {joined}")
            if scan.dotdot_target is not None and parents and scan.dotdot_target not in parents:
                scan.complete = False
                joined = ", ".join(str(parent) for parent in sorted(parents))
                scan.error = _append_issue(
                    scan.error,
                    f"the .. entry points at {scan.dotdot_target} while the name edge comes from {joined}",
                )
            if scan.dot_target is not None and scan.dot_target != key:
                scan.complete = False
                scan.error = _append_issue(scan.error, "the . entry points at a different inode")
            if scan.error is not None:
                scan.complete = False

    def _incomplete_directories(self) -> bool:
        return any(not scan.complete for scan in self.directories.values())

    def _finalize(self, coverage_complete: bool) -> dict[InodeKey, LinkNode]:
        nodes: dict[InodeKey, LinkNode] = {}
        for key, state in self.states.items():
            counts = self._counts.get(key, [0, 0, 0])
            observed_names, observed_dot, observed_dotdot = counts
            observed = (
                observed_names + observed_dot + observed_dotdot if state.filetype == stat.S_IFDIR else observed_names
            )
            excluded = sum(1 for edge in self.edges if edge.target == key and not edge.counted)
            scan = self.directories.get(key)
            complete = coverage_complete and not state.uncertain and (scan is None or scan.complete)

            node = LinkNode(
                key=key,
                inode=state.inode,
                filetype=state.filetype,
                declared_nlink=state.declared_nlink,
                observed_names=observed_names,
                observed_dot=observed_dot,
                observed_dotdot=observed_dotdot,
                observed=observed,
                excluded=excluded,
                depth=state.depth,
                path=state.path,
                scanned=state.scanned,
                lower_bound=not complete,
            )

            if observed > state.declared_nlink:
                node.verdict = LinkVerdict.SURPLUS
            elif not complete:
                node.verdict = LinkVerdict.LOWER_BOUND
            elif observed == state.declared_nlink:
                node.verdict = LinkVerdict.CONSISTENT
            else:
                node.verdict = LinkVerdict.SHORTFALL

            node.reasons = self._reasons(node)
            nodes[key] = node
        return nodes

    def _reasons(self, node: LinkNode) -> list[str]:
        reasons = [
            f"inode {node.key} declares nlink={node.declared_nlink} and "
            f"{node.observed} reference(s) were attributed to this object"
        ]
        if node.is_directory:
            reasons.append(
                "directory accounting uses . + parent name + one .. per child directory "
                f"(dot={node.observed_dot}, name={node.observed_names}, dotdot={node.observed_dotdot})"
            )
        else:
            reasons.append("only NAME entries count towards this non-directory object")

        if node.excluded:
            reasons.append(
                f"{node.excluded} entry/entries name inode {node.key.inum} but were not tied to this generation"
            )

        if node.verdict is LinkVerdict.LOWER_BOUND:
            reasons.append(
                "coverage is incomplete, so the observed count is a lower bound and no shortfall is implied"
            )
        elif node.verdict is LinkVerdict.SHORTFALL:
            reasons.append("coverage is complete but fewer references were observed than declared")
        elif node.verdict is LinkVerdict.SURPLUS:
            reasons.append("observed references already exceed the declared link count")
            if node.lower_bound:
                reasons.append("the observed count is still a lower bound, so the surplus can only grow")
        else:
            reasons.append("observed references match the declared link count")
        return reasons


class _NodeState:
    __slots__ = ("key", "inode", "filetype", "declared_nlink", "depth", "path", "scanned", "uncertain")

    def __init__(self, key: InodeKey, inode: INode, filetype: int, declared_nlink: int) -> None:
        self.key = key
        self.inode = inode
        self.filetype = filetype
        self.declared_nlink = declared_nlink
        self.depth: int | None = None
        self.path: str | None = None
        self.scanned = False
        self.uncertain = False


def _kind(name: str) -> EdgeKind:
    if name == ".":
        return EdgeKind.DOT
    if name == "..":
        return EdgeKind.DOTDOT
    return EdgeKind.NAME


def _append_issue(current: str | None, issue: str) -> str:
    return issue if current is None else f"{current}; {issue}"


def _join(path: str, name: str) -> str:
    return f"/{name}" if path == "/" else f"{path}/{name}"
