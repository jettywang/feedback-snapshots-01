"""Restricted forensic replay of (incremental) btrfs send command sequences.

This module implements a *restricted* inference interface on top of
:mod:`dissect.btrfs`: the caller explicitly supplies a read-only baseline
subvolume and an already-parsed sequence of send commands. Replaying the
sequence produces a purely in-memory *virtual* file state in which every
byte range carries provenance information (baseline extent, inline write,
hole or unknown).

Nothing is ever written to the host filesystem or to the baseline volume.

Identity model
--------------
An incremental send stream is only admissible against a baseline whose
identity (subvolume UUID *and* transaction id) exactly matches the clone
source declared in the stream header. Two baselines with byte-identical
content but different identities therefore yield different admission
results.

Unknown handling
----------------
Commands the caller could not parse (:class:`Unparsed`) conservatively
turn the affected scope unknown instead of silently claiming a complete
reconstruction: a file-scoped failure poisons that file, a stream-scoped
failure poisons the whole virtual filesystem.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.btrfs.exceptions import (
    BaselineMismatchError,
    SendStreamError,
    UnknownRegionError,
)

if TYPE_CHECKING:
    from typing import BinaryIO
    from uuid import UUID

    from dissect.btrfs.btrfs import Subvolume

__all__ = [
    "Baseline",
    "BaselineIdentity",
    "Clone",
    "Mkdir",
    "Mkfile",
    "Rename",
    "Rmdir",
    "Segment",
    "SendReplay",
    "Snapshot",
    "SourceKind",
    "Subvol",
    "Truncate",
    "Unlink",
    "Unparsed",
    "VirtualFS",
    "VirtualFile",
    "Write",
]


# --- Identity and baseline ---------------------------------------------------


@dataclass(frozen=True)
class BaselineIdentity:
    """Identity of a baseline subvolume: its UUID and transaction id."""

    uuid: UUID
    ctransid: int


class Baseline:
    """Read-only view of a caller-supplied baseline subvolume.

    The identity is derived from the subvolume root item, never from
    caller-supplied metadata, so it cannot be spoofed by the send stream.

    Args:
        subvolume: The subvolume to use as clone source. Opened read-only;
            only ``read`` operations are ever issued against it.
    """

    def __init__(self, subvolume: Subvolume):
        self.subvolume = subvolume
        root_item = subvolume.tree.root_item
        self.identity = BaselineIdentity(uuid=subvolume.uuid, ctransid=root_item.ctransid)
        self._streams: dict[str, BinaryIO] = {}

    def read(self, path: str, offset: int, size: int) -> bytes:
        """Read ``size`` bytes at ``offset`` from the baseline file at ``path``."""
        if path not in self._streams:
            self._streams[path] = self.subvolume.get(path).open()
        fh = self._streams[path]
        fh.seek(offset)
        return fh.read(size)

    def size(self, path: str) -> int:
        """Return the size of the baseline file at ``path``."""
        return self.subvolume.get(path).size


# --- Parsed send commands ----------------------------------------------------


@dataclass
class Subvol:
    """Start of a full (non-incremental) send stream."""

    path: str
    uuid: UUID
    ctransid: int


@dataclass
class Snapshot:
    """Start of an incremental send stream, declaring its clone source."""

    path: str
    uuid: UUID
    ctransid: int
    clone_uuid: UUID
    clone_ctransid: int


@dataclass
class Mkdir:
    path: str


@dataclass
class Mkfile:
    path: str


@dataclass
class Write:
    path: str
    offset: int
    data: bytes


@dataclass
class Clone:
    """Clone (reflink) a range from a clone source into a received file.

    ``clone_uuid``/``clone_ctransid`` identify the source subvolume;
    ``clone_path`` is resolved relative to that subvolume's root.
    """

    path: str
    offset: int
    length: int
    clone_uuid: UUID
    clone_ctransid: int
    clone_path: str
    clone_offset: int


@dataclass
class Rename:
    from_path: str
    to_path: str


@dataclass
class Truncate:
    path: str
    size: int


@dataclass
class Unlink:
    path: str


@dataclass
class Rmdir:
    path: str


@dataclass
class Unparsed:
    """A command the caller's parser could not decode.

    ``path`` is the affected file if it could be determined, otherwise
    ``None`` and the entire virtual filesystem is considered affected.
    """

    reason: str
    path: str | None = None


# --- Provenance --------------------------------------------------------------


class SourceKind(enum.Enum):
    BASELINE = "baseline"
    WRITE = "write"
    HOLE = "hole"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Source:
    """Provenance of a byte range."""

    kind: SourceKind
    path: str | None = None
    offset: int = 0
    data: bytes | None = None
    command_index: int | None = None
    reason: str | None = None

    def shift(self, count: int) -> Source:
        """Return the source as seen ``count`` bytes further into it."""
        if self.kind == SourceKind.BASELINE:
            return Source(SourceKind.BASELINE, path=self.path, offset=self.offset + count)
        if self.kind == SourceKind.WRITE:
            return Source(SourceKind.WRITE, data=self.data[count:], command_index=self.command_index)
        return self


@dataclass(frozen=True)
class Segment:
    """A contiguous byte range of a virtual file and its provenance."""

    start: int
    length: int
    source: Source

    @property
    def end(self) -> int:
        return self.start + self.length


def _merge(segments: list[Segment]) -> list[Segment]:
    """Sort segments and merge adjacent ones with identical sources."""
    merged = []
    for segment in sorted(segments, key=lambda seg: seg.start):
        if segment.length == 0:
            continue
        if merged and merged[-1].end == segment.start and merged[-1].source == segment.source:
            previous = merged[-1]
            merged[-1] = Segment(previous.start, previous.length + segment.length, previous.source)
        else:
            merged.append(segment)
    return merged


class VirtualFile:
    """In-memory reconstruction of a single received file."""

    def __init__(self, baseline: Baseline | None = None):
        self._baseline = baseline
        self.segments: list[Segment] = []
        self.size = 0

    @property
    def unknown(self) -> bool:
        return any(segment.source.kind == SourceKind.UNKNOWN for segment in self.segments)

    def provenance(self) -> list[Segment]:
        """Return the provenance map of the file."""
        return list(self.segments)

    def read(self, offset: int = 0, size: int | None = None) -> bytes:
        """Read known bytes from the virtual file.

        Raises:
            UnknownRegionError: If the requested range intersects an
                unknown region.
        """
        size = self.size - offset if size is None else min(size, self.size - offset)
        if offset < 0 or size <= 0:
            return b""

        result = []
        end = offset + size
        for segment in self.segments:
            if segment.end <= offset:
                continue
            if segment.start >= end:
                break

            start = max(segment.start, offset)
            count = min(segment.end, end) - start
            delta = start - segment.start
            source = segment.source

            if source.kind == SourceKind.UNKNOWN:
                raise UnknownRegionError(
                    f"Range [{start:#x}, {start + count:#x}) is unknown: {source.reason}"
                )
            if source.kind == SourceKind.HOLE:
                result.append(b"\x00" * count)
            elif source.kind == SourceKind.WRITE:
                result.append(source.data[delta : delta + count])
            elif source.kind == SourceKind.BASELINE:
                if self._baseline is None:
                    raise SendStreamError("No baseline available to resolve a baseline range")
                result.append(self._baseline.read(source.path, source.offset + delta, count))

        return b"".join(result)

    # -- mutation (virtual only, never touches the host) --

    def _splice(self, offset: int, length: int, new: list[Segment]) -> None:
        end = offset + length
        result = []
        for segment in self.segments:
            if segment.end <= offset or segment.start >= end:
                result.append(segment)
                continue
            if segment.start < offset:
                result.append(Segment(segment.start, offset - segment.start, segment.source))
            if segment.end > end:
                result.append(Segment(end, segment.end - end, segment.source.shift(end - segment.start)))
        result.extend(new)
        self.segments = _merge(result)
        self.size = max((segment.end for segment in self.segments), default=0)

    def _pad_to(self, offset: int) -> None:
        if offset > self.size:
            self.segments = _merge([*self.segments, Segment(self.size, offset - self.size, Source(SourceKind.HOLE))])
            self.size = offset

    def write(self, offset: int, data: bytes, command_index: int) -> None:
        self._pad_to(offset)
        source = Source(SourceKind.WRITE, data=bytes(data), command_index=command_index)
        self._splice(offset, len(data), [Segment(offset, len(data), source)])

    def clone_from(self, source_segments: list[Segment], offset: int) -> None:
        """Splice externally built segments in at ``offset``."""
        length = sum(segment.length for segment in source_segments)
        self._pad_to(offset)
        self._splice(offset, length, [Segment(offset + seg.start, seg.length, seg.source) for seg in source_segments])

    def extract(self, offset: int, length: int) -> list[Segment]:
        """Return segments covering ``[offset, offset + length)``, relative to 0.

        Ranges beyond the current file size are returned as holes.
        """
        result = []
        position = offset
        end = offset + length
        for segment in self.segments:
            if segment.end <= position or segment.start >= end:
                continue
            start = max(segment.start, position)
            if start > position:
                result.append(Segment(position - offset, start - position, Source(SourceKind.HOLE)))
            count = min(segment.end, end) - start
            result.append(Segment(start - offset, count, segment.source.shift(start - segment.start)))
            position = start + count
        if position < end:
            result.append(Segment(position - offset, end - position, Source(SourceKind.HOLE)))
        return result

    def truncate(self, size: int) -> None:
        if size < self.size:
            self._splice(size, self.size - size, [])
        else:
            self._pad_to(size)
        self.size = size

    def mark_unknown(self, reason: str, command_index: int) -> None:
        """Poison the whole file: content is no longer reconstructable."""
        source = Source(SourceKind.UNKNOWN, command_index=command_index, reason=reason)
        self.segments = [Segment(0, self.size, source)] if self.size else []


# --- Replay engine -----------------------------------------------------------


@dataclass
class VirtualFS:
    """Result of replaying a send command sequence."""

    identity: BaselineIdentity
    root: str
    baseline: Baseline | None
    files: dict[str, VirtualFile] = field(default_factory=dict)
    dirs: set[str] = field(default_factory=set)
    degraded: bool = False
    warnings: list[str] = field(default_factory=list)

    def get(self, path: str) -> VirtualFile:
        return self.files[path]

    def read(self, path: str, offset: int = 0, size: int | None = None) -> bytes:
        return self.files[path].read(offset, size)


class SendReplay:
    """Replay parsed send command sequences against read-only baselines.

    Args:
        baselines: The baseline subvolumes the caller explicitly admits as
            clone sources, keyed by their on-disk identity.
    """

    def __init__(self, baselines: list[Baseline]):
        self.baselines = {baseline.identity: baseline for baseline in baselines}

    def admit(self, command: Subvol | Snapshot) -> Baseline | None:
        """Check stream-header identity against the admitted baselines.

        Returns the matched baseline, or ``None`` for a full send.

        Raises:
            BaselineMismatchError: If the declared clone source identity
                does not exactly match any admitted baseline.
        """
        if isinstance(command, Subvol):
            return None

        identity = BaselineIdentity(command.clone_uuid, command.clone_ctransid)
        baseline = self.baselines.get(identity)
        if baseline is None:
            raise BaselineMismatchError(
                f"Send stream declares clone source {identity}, "
                f"which matches none of the admitted baselines: {sorted(self.baselines)}"
            )
        return baseline

    def replay(self, commands: list) -> VirtualFS:
        """Replay a parsed command sequence into a virtual filesystem."""
        if not commands or not isinstance(commands[0], (Subvol, Snapshot)):
            raise SendStreamError("Command sequence must start with a Subvol or Snapshot command")

        header = commands[0]
        baseline = self.admit(header)
        vfs = VirtualFS(
            identity=BaselineIdentity(header.uuid, header.ctransid),
            root=_normpath(header.path),
            baseline=baseline,
        )

        for index, command in enumerate(commands[1:], start=1):
            self._apply(vfs, command, index)

        return vfs

    def _apply(self, vfs: VirtualFS, command, index: int) -> None:
        if isinstance(command, Mkdir):
            vfs.dirs.add(self._relpath(vfs, command.path))
        elif isinstance(command, Mkfile):
            vfs.files[self._relpath(vfs, command.path)] = VirtualFile(vfs.baseline)
        elif isinstance(command, Write):
            self._file(vfs, command.path).write(command.offset, command.data, index)
        elif isinstance(command, Clone):
            self._clone(vfs, command, index)
        elif isinstance(command, Rename):
            self._rename(vfs, command)
        elif isinstance(command, Truncate):
            self._file(vfs, command.path).truncate(command.size)
        elif isinstance(command, Unlink):
            vfs.files.pop(self._relpath(vfs, command.path), None)
        elif isinstance(command, Rmdir):
            vfs.dirs.discard(self._relpath(vfs, command.path))
        elif isinstance(command, Unparsed):
            self._poison(vfs, command, index)
        else:
            raise SendStreamError(f"Unsupported command: {command!r}")

    def _relpath(self, vfs: VirtualFS, path: str) -> str:
        path = _normpath(path)
        if path == vfs.root:
            return ""
        if vfs.root and path.startswith(vfs.root + "/"):
            return path[len(vfs.root) + 1 :]
        return path

    def _file(self, vfs: VirtualFS, path: str) -> VirtualFile:
        path = self._relpath(vfs, path)
        if path not in vfs.files:
            vfs.files[path] = VirtualFile(vfs.baseline)
        return vfs.files[path]

    def _clone(self, vfs: VirtualFS, command: Clone, index: int) -> None:
        target = self._file(vfs, command.path)
        identity = BaselineIdentity(command.clone_uuid, command.clone_ctransid)

        if vfs.baseline is not None and identity == vfs.baseline.identity:
            # Clone from the admitted baseline subvolume
            path = _normpath(command.clone_path)
            available = max(0, vfs.baseline.size(path) - command.clone_offset)
            length = min(command.length, available)
            segments = [Segment(0, length, Source(SourceKind.BASELINE, path=path, offset=command.clone_offset))]
            if length < command.length:
                segments.append(Segment(length, command.length - length, Source(SourceKind.HOLE)))
            target.clone_from(segments, command.offset)
        elif identity == vfs.identity:
            # Clone from within the received subvolume itself
            source_path = self._relpath(vfs, command.clone_path)
            if source_path not in vfs.files:
                self._unknown_range(vfs, target, command, index, f"Self-clone from unknown file: {source_path}")
                return
            target.clone_from(vfs.files[source_path].extract(command.clone_offset, command.length), command.offset)
        else:
            self._unknown_range(
                vfs, target, command, index, f"Clone source identity {identity} was not admitted"
            )

    def _unknown_range(self, vfs: VirtualFS, target: VirtualFile, command: Clone, index: int, reason: str) -> None:
        vfs.warnings.append(f"command #{index}: {reason}")
        vfs.degraded = True
        source = Source(SourceKind.UNKNOWN, command_index=index, reason=reason)
        target.clone_from([Segment(0, command.length, source)], command.offset)

    def _rename(self, vfs: VirtualFS, command: Rename) -> None:
        from_path = self._relpath(vfs, command.from_path)
        to_path = self._relpath(vfs, command.to_path)

        if from_path in vfs.files:
            vfs.files[to_path] = vfs.files.pop(from_path)
        if from_path in vfs.dirs:
            vfs.dirs.discard(from_path)
            vfs.dirs.add(to_path)

        # Move any children along when renaming a directory
        prefix = from_path + "/"
        for path in [path for path in vfs.files if path.startswith(prefix)]:
            vfs.files[to_path + path[len(from_path) :]] = vfs.files.pop(path)
        for path in [path for path in vfs.dirs if path.startswith(prefix)]:
            vfs.dirs.discard(path)
            vfs.dirs.add(to_path + path[len(from_path) :])

    def _poison(self, vfs: VirtualFS, command: Unparsed, index: int) -> None:
        reason = f"Unparsed command #{index}: {command.reason}"
        vfs.warnings.append(reason)
        vfs.degraded = True

        if command.path is not None:
            self._file(vfs, command.path).mark_unknown(reason, index)
        else:
            for file in vfs.files.values():
                file.mark_unknown(reason, index)


def _normpath(path: str) -> str:
    return "/".join(part for part in path.split("/") if part not in ("", "."))
