from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from dissect.etl.headers.event import ExtType

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.etl.headers.headers import Header


class FrameStatus(str, Enum):
    """How a single raw stack frame address was resolved against supplied evidence.

    Members:
        ASSOCIATED: Exactly one caller-supplied module load interval covers the frame.
        CONFLICT: More than one caller-supplied module load interval covers the frame.
        UNKNOWN: No caller-supplied module load interval covers the frame.
    """

    ASSOCIATED = "associated"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ModuleEvidence:
    """A caller-supplied, sourced module load interval for one process.

    The evidence is scoped to a single process incarnation (identified by ``pid``
    together with its lifetime bounds) and to a time interval. Nothing in this
    class is derived from the local machine or downloaded symbols; the ``source``
    string is required so every match stays traceable to the evidence the caller
    used.

    Args:
        pid: The process id the module was loaded in.
        base_address: The load base address of the module.
        end_address: The exclusive end address of the mapped module.
        module_name: A caller-chosen name for the module.
        source: Where this load interval came from. Required for provenance.
        loaded_at: Inclusive start of the load interval, or ``None`` if unknown.
        unloaded_at: Exclusive end of the load interval, or ``None`` if still loaded.
        process_start: Inclusive start of the process lifetime, or ``None`` if unknown.
        process_end: Exclusive end of the process lifetime, or ``None`` if unknown.
        evidence_id: Optional caller-assigned identifier for compact references.
    """

    pid: int
    base_address: int
    end_address: int
    module_name: str
    source: str
    loaded_at: datetime | None = None
    unloaded_at: datetime | None = None
    process_start: datetime | None = None
    process_end: datetime | None = None
    evidence_id: str | None = None

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("ModuleEvidence requires a non-empty source")
        if self.base_address < 0:
            raise ValueError("base_address must be non-negative")
        if self.end_address <= self.base_address:
            raise ValueError("end_address must be greater than base_address")
        if self.loaded_at is not None and self.unloaded_at is not None and self.unloaded_at < self.loaded_at:
            raise ValueError("unloaded_at cannot be before loaded_at")
        if self.process_start is not None and self.process_end is not None and self.process_end < self.process_start:
            raise ValueError("process_end cannot be before process_start")

    def covers_process(self, timestamp: datetime) -> bool:
        """Return whether the process lifetime covers ``timestamp``."""
        if self.process_start is not None and timestamp < self.process_start:
            return False
        if self.process_end is not None and timestamp >= self.process_end:
            return False
        return True

    def covers_address(self, address: int) -> bool:
        """Return whether ``address`` falls inside the mapped module interval."""
        return self.base_address <= address < self.end_address

    def covers_time(self, timestamp: datetime) -> bool:
        """Return whether the module was mapped at ``timestamp``."""
        if self.loaded_at is not None and timestamp < self.loaded_at:
            return False
        if self.unloaded_at is not None and timestamp >= self.unloaded_at:
            return False
        return True

    def relative_offset(self, address: int) -> int:
        """Return the offset of ``address`` relative to the module base."""
        return address - self.base_address


@dataclass(frozen=True)
class StackOrigin:
    """Where a stack trace extension was observed inside the trace."""

    event_index: int
    extension_index: int
    pid: int | None
    timestamp: datetime | None


@dataclass(frozen=True)
class RawStackEvidence:
    """The verbatim contents of a StackTrace32/StackTrace64 header extension.

    Raw addresses and the original pointer width are preserved. No resolution,
    symbol download or local module mapping happens at this stage.
    """

    match_id: int
    addresses: tuple[int, ...]
    pointer_width: int
    origin: StackOrigin
    ext_type: ExtType

    @property
    def is_64bit(self) -> bool:
        """Whether the addresses were captured as 64-bit pointers."""
        return self.pointer_width == 8


@dataclass(frozen=True)
class ModuleMatch:
    """A candidate module for a frame, with the offset and its provenance."""

    module_name: str
    base_address: int
    relative_offset: int
    evidence: ModuleEvidence


@dataclass(frozen=True)
class FrameResolution:
    """The resolution of one frame, retaining the original stack position."""

    frame_index: int
    address: int
    pointer_width: int
    status: FrameStatus
    candidates: tuple[ModuleMatch, ...] = ()

    @property
    def match(self) -> ModuleMatch | None:
        """The single candidate when the frame was associated, otherwise ``None``."""
        return self.candidates[0] if self.status == FrameStatus.ASSOCIATED else None


@dataclass(frozen=True)
class StackResolution:
    """The resolution of an entire stack trace extension, frame order preserved."""

    match_id: int
    pointer_width: int
    origin: StackOrigin
    frames: tuple[FrameResolution, ...]

    @property
    def statuses(self) -> tuple[FrameStatus, ...]:
        """The per-frame statuses in original stack order."""
        return tuple(frame.status for frame in self.frames)


class OfflineStackResolver:
    """Resolves raw stack addresses against caller-supplied module load evidence.

    Resolution is strictly offline and scoped:

    * Only ``ModuleEvidence`` records supplied to this instance are used. Symbols
      are never downloaded and the local machine's module layout is never consulted.
    * A module only matches a frame when it belongs to the same pid, the process
      lifetime covers the event timestamp, the module was still loaded at that
      timestamp and the address falls inside its mapped interval.
    * All lookups are per-instance keyed by pid. There is deliberately no global
      address cache, so pid reuse, ASLR collisions across processes and unloaded or
      unknown addresses can never bleed into each other.
    """

    def __init__(self, module_evidence: Iterable[ModuleEvidence] = ()):
        self._evidence: dict[int, tuple[ModuleEvidence, ...]] = {}
        for evidence in module_evidence:
            self.add_evidence(evidence)

    def add_evidence(self, evidence: ModuleEvidence) -> None:
        """Add one caller-supplied module load interval."""
        existing = self._evidence.get(evidence.pid, ())
        self._evidence[evidence.pid] = (*existing, evidence)

    def evidence_for_pid(self, pid: int) -> tuple[ModuleEvidence, ...]:
        """Return the module evidence supplied for ``pid``."""
        return self._evidence.get(pid, ())

    def resolve_frame(
        self, pid: int | None, timestamp: datetime | None, address: int
    ) -> tuple[FrameStatus, tuple[ModuleMatch, ...]]:
        """Resolve one address for a process at a point in time.

        Returns the status and every candidate that covers the frame. A single
        candidate means associated, multiple means conflict and none means unknown.
        """
        if pid is None or timestamp is None:
            return FrameStatus.UNKNOWN, ()

        candidates = []
        for evidence in self.evidence_for_pid(pid):
            if (
                evidence.covers_process(timestamp)
                and evidence.covers_time(timestamp)
                and evidence.covers_address(address)
            ):
                candidates.append(
                    ModuleMatch(
                        module_name=evidence.module_name,
                        base_address=evidence.base_address,
                        relative_offset=evidence.relative_offset(address),
                        evidence=evidence,
                    )
                )

        if not candidates:
            return FrameStatus.UNKNOWN, ()
        if len(candidates) > 1:
            return FrameStatus.CONFLICT, tuple(candidates)
        return FrameStatus.ASSOCIATED, (candidates[0],)

    def resolve_stack(self, stack: RawStackEvidence, pid: int | None, timestamp: datetime | None) -> StackResolution:
        """Resolve every frame of a raw stack trace, preserving frame order."""
        frames = []
        for frame_index, address in enumerate(stack.addresses):
            status, candidates = self.resolve_frame(pid, timestamp, address)
            frames.append(
                FrameResolution(
                    frame_index=frame_index,
                    address=address,
                    pointer_width=stack.pointer_width,
                    status=status,
                    candidates=candidates,
                )
            )
        return StackResolution(
            match_id=stack.match_id,
            pointer_width=stack.pointer_width,
            origin=stack.origin,
            frames=tuple(frames),
        )


_STACK_EXT_TYPES = {
    ExtType.STACK_TRACE32: 4,
    ExtType.STACK_TRACE64: 8,
}


def extract_stack_evidence(
    header: Header,
    event_index: int = 0,
    resolver: OfflineStackResolver | None = None,
) -> tuple[list[RawStackEvidence], list[StackResolution]]:
    """Extract StackTrace extensions from an event header and optionally resolve them.

    The raw evidence always preserves the match id, the original addresses, their
    32/64-bit width and the extension position. When ``resolver`` is provided the
    stacks are additionally resolved using only its caller-supplied module
    evidence; otherwise no resolution is attempted.

    Args:
        header: A parsed event header carrying header extensions.
        event_index: Caller-assigned position of the event inside the trace.
        resolver: Optional offline resolver with caller-supplied module evidence.

    Returns:
        A tuple of raw stack evidence and, when a resolver is given, its resolutions.
    """
    raw_stacks: list[RawStackEvidence] = []
    resolutions: list[StackResolution] = []

    pid = getattr(header, "process_id", None)
    timestamp = getattr(header, "timestamp", None)

    for extension_index, extension in enumerate(header.header_extensions):
        pointer_width = _STACK_EXT_TYPES.get(extension.ext_type)
        if pointer_width is None:
            continue

        data: dict[str, Any] = extension.data
        origin = StackOrigin(
            event_index=event_index,
            extension_index=extension_index,
            pid=pid,
            timestamp=timestamp,
        )
        raw_stack = RawStackEvidence(
            match_id=data["MatchId"],
            addresses=tuple(data["Address"]),
            pointer_width=pointer_width,
            origin=origin,
            ext_type=extension.ext_type,
        )
        raw_stacks.append(raw_stack)

        if resolver is not None:
            resolutions.append(resolver.resolve_stack(raw_stack, pid, timestamp))

    return raw_stacks, resolutions
