"""Evidence-based process lineage reconstruction from ETW process events.

This module turns the already parsed kernel process events produced by
:class:`dissect.etl.etl.ETL` into a process genealogy that can be defended in a
security investigation.  The design follows a few hard rules:

* A process identity is a *lifecycle*, not a PID.  The kernel ``UniqueProcessKey``
  (an ``EPROCESSOR`` pointer) is the stable identity when present.  When it is not
  (older ``Process_V0``/``Process_V1`` events) a PID can only identify a process
  for the time interval in which it is known to be alive.
* PIDs are reused.  Two events that share a PID (or an image file name) are never
  merged into the same instance automatically.
* Every output relation points back at the concrete events that support it.
* When the evidence does not justify a parent/child edge, the relation is emitted
  as *unresolved* with a reason rather than as a confident edge.  Start times are
  never invented from the position of an event in the file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from dissect.etl.utils import ProcessGuid

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence
    from datetime import datetime

    from dissect.etl.etl import ETL, EventRecord

# Kernel process opcodes (the low byte of the hook id, also the manifest "value").
OPCODE_START = 1
OPCODE_END = 2
OPCODE_DCSTART = 3
OPCODE_DCEND = 4
OPCODE_TERMINATE = 11
OPCODE_DEFUNCT = 39

# Opcodes that mark the birth of a process instance.
BIRTH_OPCODES = frozenset({OPCODE_START, OPCODE_DCSTART})
# Opcodes that mark the end of a process instance.
DEATH_OPCODES = frozenset({OPCODE_END, OPCODE_DCEND, OPCODE_TERMINATE, OPCODE_DEFUNCT})
# Birth events delivered by the kernel rundown (process already alive at log start).
RUNDOWN_BIRTH_OPCODES = frozenset({OPCODE_DCSTART})
RUNDOWN_DEATH_OPCODES = frozenset({OPCODE_DCEND})

# Payload fields that identify a process / its parent, when available per version.
_PID_FIELDS = ("ProcessId",)
_PARENT_FIELDS = ("ParentId",)
_KEY_FIELDS = ("UniqueProcessKey",)
_IMAGE_FIELDS = ("ImageFileName",)


class ProcessEventType(Enum):
    """The lifecycle meaning of a kernel process event."""

    START = "Start"
    END = "End"
    DCSTART = "DCStart"
    DCEND = "DCEnd"
    TERMINATE = "Terminate"
    DEFUNCT = "Defunct"
    UNKNOWN = "Unknown"


_EVENT_TYPE_BY_OPCODE = {
    OPCODE_START: ProcessEventType.START,
    OPCODE_END: ProcessEventType.END,
    OPCODE_DCSTART: ProcessEventType.DCSTART,
    OPCODE_DCEND: ProcessEventType.DCEND,
    OPCODE_TERMINATE: ProcessEventType.TERMINATE,
    OPCODE_DEFUNCT: ProcessEventType.DEFUNCT,
}


class IdentityBasis(Enum):
    """How the identity of a reconstructed instance was established."""

    UNIQUE_KEY = "unique_process_key"
    PID_INTERVAL = "pid_interval"


class RelationConfidence(Enum):
    """Whether a parent relation is proven by the evidence or only tentative."""

    CONFIRMED = "confirmed"
    UNRESOLVED = "unresolved"


class UnresolvedReason(Enum):
    """Why a parent/child relation could not be turned into a confirmed edge."""

    PARENT_NO_EVENTS = "parent_process_has_no_events_in_trace"
    PARENT_NOT_ALIVE = "no_parent_instance_alive_at_child_birth"
    PARENT_AMBIGUOUS = "multiple_parent_instances_match"
    SELF_PARENT = "process_references_itself_as_parent"
    MISSING_PARENT_FIELD = "event_has_no_parent_identifier"


@dataclass(frozen=True, slots=True)
class EventLocation:
    """Where an event was found inside the ETL file.

    The combination of buffer index and byte offset uniquely locates the raw
    record, so any conclusion can be traced back to its physical position.
    """

    buffer_index: int
    record_offset: int
    sequence: int

    def __str__(self) -> str:
        return f"buffer={self.buffer_index} offset=0x{self.record_offset:x} seq={self.sequence}"


@dataclass(frozen=True, slots=True)
class ProcessObservation:
    """A single kernel process event, preserving its location and raw fields."""

    location: EventLocation
    event_type: ProcessEventType
    opcode: int
    version: int | None
    symbol: str | None
    timestamp: datetime
    process_id: int | None
    parent_id: int | None
    unique_process_key: int | None
    image_file_name: str | None
    is_rundown: bool
    raw_fields: dict[str, Any]

    @property
    def has_unique_key(self) -> bool:
        return self.unique_process_key is not None

    @property
    def is_birth(self) -> bool:
        return self.opcode in BIRTH_OPCODES

    @property
    def is_death(self) -> bool:
        return self.opcode in DEATH_OPCODES


@dataclass(slots=True)
class ProcessInstance:
    """One concrete execution of a program: an identity with a lifecycle.

    The same PID appearing in two instances means the PID was reused; the two
    instances are never collapsed.
    """

    instance_id: str
    identity_basis: IdentityBasis
    process_id: int
    unique_process_key: int | None
    observations: list[ProcessObservation] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)

    @property
    def image_file_name(self) -> str | None:
        for obs in self.observations:
            if obs.image_file_name:
                return obs.image_file_name
        return None

    @property
    def birth(self) -> ProcessObservation | None:
        return self.observations[0] if self.observations else None

    @property
    def death(self) -> ProcessObservation | None:
        for obs in reversed(self.observations):
            if obs.is_death:
                return obs
        return None

    @property
    def pre_existing(self) -> bool:
        """True when the instance was already running before the trace started.

        Only a rundown birth (``DCStart``) supports that conclusion.  A missing
        start event is *not* reinterpreted as pre-existence.
        """
        return self.birth is not None and self.birth.event_type == ProcessEventType.DCSTART

    @property
    def has_end_event(self) -> bool:
        return self.death is not None

    def is_alive_at(self, moment: datetime) -> bool:
        """Return whether this instance is the live holder of its identity at ``moment``.

        The interval is closed by observed events only.  An instance observed
        through a birth and without an end event is treated as still alive after
        its last observation; an instance whose only evidence is a death event is
        treated as alive up to that death.
        """
        first = self.observations[0].timestamp
        last = self.observations[-1].timestamp
        if moment < first:
            return False
        death = self.death
        if death is not None and moment > death.timestamp:
            return False
        if moment > last and death is None:
            # No end event: the process is not known to have terminated.
            return True
        return first <= moment <= last


@dataclass(frozen=True, slots=True)
class ProcessRelation:
    """A parent/child relationship and the exact evidence behind it."""

    child: ProcessInstance
    confidence: RelationConfidence
    parent: ProcessInstance | None
    claimed_parent_id: int | None
    reason: UnresolvedReason | None
    evidence: EventLocation

    @property
    def is_confirmed(self) -> bool:
        return self.confidence == RelationConfidence.CONFIRMED


@dataclass(slots=True)
class ProcessLineage:
    """The reconstructed set of process instances and their relationships."""

    instances: list[ProcessInstance]
    relations: list[ProcessRelation]
    observations: list[ProcessObservation]

    def confirmed_relations(self) -> list[ProcessRelation]:
        return [relation for relation in self.relations if relation.is_confirmed]

    def unresolved_relations(self) -> list[ProcessRelation]:
        return [relation for relation in self.relations if not relation.is_confirmed]

    def instances_for_pid(self, process_id: int) -> list[ProcessInstance]:
        return [instance for instance in self.instances if instance.process_id == process_id]

    def render_text(self) -> str:
        """Render a human readable, evidence-annotated report."""
        lines: list[str] = []
        lines.append("Process instances")
        lines.append("-----------------")
        for instance in self.instances:
            lines.append(_format_instance(instance))
        lines.append("")
        lines.append("Confirmed parent/child edges")
        lines.append("----------------------------")
        confirmed = self.confirmed_relations()
        if not confirmed:
            lines.append("(none)")
        for relation in confirmed:
            lines.append(_format_confirmed_relation(relation))
        lines.append("")
        lines.append("Unresolved parent relationships (not presented as edges)")
        lines.append("---------------------------------------------------------")
        unresolved = self.unresolved_relations()
        if not unresolved:
            lines.append("(none)")
        for relation in unresolved:
            lines.append(_format_unresolved_relation(relation))
        return "\n".join(lines)


def build_process_lineage(etl: ETL) -> ProcessLineage:
    """Reconstruct process lineage from the process events inside an ETL file.

    Args:
        etl: An opened :class:`~dissect.etl.etl.ETL` file.

    Returns:
        A :class:`ProcessLineage` holding lifecycle instances and relations whose
        confidence reflects the available evidence.
    """
    observations = list(iter_process_observations(etl))
    instances = _build_instances(observations)
    relations = _build_relations(instances)
    return ProcessLineage(instances=instances, relations=relations, observations=observations)


def iter_process_observations(etl: ETL) -> Iterator[ProcessObservation]:
    """Yield a :class:`ProcessObservation` for every kernel process event.

    Non-process events and events whose payload cannot be parsed are skipped.
    Each yielded observation retains its physical :class:`EventLocation` and the
    original payload fields.
    """
    sequence = 0
    for buffer_index, record_offset, record in _iter_records_with_location(etl):
        location = EventLocation(
            buffer_index=buffer_index,
            record_offset=record_offset,
            sequence=sequence,
        )
        observation = _observation_from_record(record, location)
        if observation is not None:
            yield observation
            sequence += 1


def _iter_records_with_location(etl: ETL) -> Iterator[tuple[int, int, EventRecord]]:
    for buffer_index, buffer in enumerate(etl.buffers()):
        offset = 0
        for record in buffer:
            yield buffer_index, offset, record
            offset += record.aligned_size


def _observation_from_record(record: EventRecord, location: EventLocation) -> ProcessObservation | None:
    header = record.header
    group = getattr(header, "group", None)
    opcode = getattr(header, "opcode", None)
    if group is None or opcode is None:
        return None
    if header.provider_id != ProcessGuid:
        return None
    if opcode not in _EVENT_TYPE_BY_OPCODE:
        return None

    try:
        event = record.event
        values = _safe_event_values(event)
    except (EOFError, ValueError, KeyError):
        # A truncated or malformed payload cannot support a conclusion; skip it.
        return None

    event_type = _EVENT_TYPE_BY_OPCODE[opcode]
    return ProcessObservation(
        location=location,
        event_type=event_type,
        opcode=opcode,
        version=header.version,
        symbol=event.symbol(),
        timestamp=header.timestamp,
        process_id=_first_int(values, _PID_FIELDS, header),
        parent_id=_first_int(values, _PARENT_FIELDS),
        unique_process_key=_first_int(values, _KEY_FIELDS),
        image_file_name=_decode(_first_value(values, _IMAGE_FIELDS)),
        is_rundown=opcode in RUNDOWN_BIRTH_OPCODES or opcode in RUNDOWN_DEATH_OPCODES,
        raw_fields=dict(values),
    )


def _safe_event_values(event: Any) -> dict[str, Any]:
    try:
        return dict(event.event_values())
    except AttributeError:
        # Older structs expose attributes but no ``_values`` mapping on this
        # cstruct version; fall back to the parsed struct's public attributes.
        struct = event._struct
        if struct is None:
            return {}
        return {name: getattr(struct, name) for name in dir(struct) if not name.startswith("_")}


def _first_int(values: dict[str, Any], names: Sequence[str], header: Any | None = None) -> int | None:
    value = _first_value(values, names)
    if value is None and header is not None:
        value = getattr(header, "process_id", None)
    return _coerce_int(value)


def _first_value(values: dict[str, Any], names: Sequence[str]) -> Any:
    for name in names:
        if name in values:
            return values[name]
    return None


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _decode(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    return str(value)


def _build_instances(observations: Iterable[ProcessObservation]) -> list[ProcessInstance]:
    """Group observations into lifecycle instances.

    Each observation is assigned an identity *token*: the kernel
    ``UniqueProcessKey`` when present, otherwise a PID-scoped token.  Tokens live
    in a single namespace so a keyless PID token can never collide with a key
    token.  A fresh birth event for a token that is open or was already retired
    opens a brand new instance; that is precisely how PID/key reuse is kept apart
    instead of merging two unrelated executions.
    """
    instances: list[ProcessInstance] = []
    open_instances: dict[tuple[str, int], ProcessInstance] = {}
    retired_tokens: set[tuple[str, int]] = set()
    # PIDs that already backed an instance, so a new instance reusing a PID is
    # flagged even when it carries a different UniqueProcessKey (the normal case).
    pids_seen: set[int] = set()
    counters: dict[str, int] = {}

    def next_index(prefix: str) -> int:
        counters[prefix] = counters.get(prefix, 0) + 1
        return counters[prefix]

    for obs in observations:
        if obs.process_id is None:
            # Terminate-style events always carry a PID in practice; ignore if not.
            continue

        if obs.has_unique_key:
            token: tuple[str, int] = ("key", obs.unique_process_key)
            identity_basis = IdentityBasis.UNIQUE_KEY
            id_prefix = "K"
            id_value = obs.unique_process_key
        else:
            token = ("pid", obs.process_id)
            identity_basis = IdentityBasis.PID_INTERVAL
            id_prefix = "P"
            id_value = obs.process_id

        instance = open_instances.get(token)

        if obs.is_birth:
            token_reused = instance is not None or token in retired_tokens
            if token_reused:
                # A second birth for the same identity means reuse of that identity.
                open_instances.pop(token, None)
                retired_tokens.add(token)
            instance = _new_instance(instances, id_prefix, id_value, identity_basis, obs, next_index(id_prefix))
            if token_reused or obs.process_id in pids_seen:
                # Same identity token reborn, or the PID was already used by an
                # earlier instance: the PID has been recycled.
                instance.anomalies.append("identity_reused_new_instance_opened")
            pids_seen.add(obs.process_id)
            open_instances[token] = instance
            continue

        if instance is None:
            # End/terminate without any birth evidence: create a partial instance so
            # the event is never silently dropped.  No start time is fabricated.
            instance = _new_instance(instances, id_prefix, id_value, identity_basis, obs, next_index(id_prefix))
            instance.anomalies.append("observed_without_birth_event")
            pids_seen.add(obs.process_id)
            open_instances[token] = instance

        instance.observations.append(obs)

        if obs.is_death:
            open_instances.pop(token, None)
            retired_tokens.add(token)

    return instances


def _new_instance(
    instances: list[ProcessInstance],
    prefix: str,
    identity_value: int,
    basis: IdentityBasis,
    first_observation: ProcessObservation,
    index: int,
) -> ProcessInstance:
    instance = ProcessInstance(
        instance_id=f"{prefix}{index:04d}",
        identity_basis=basis,
        process_id=first_observation.process_id or 0,
        unique_process_key=first_observation.unique_process_key,
        observations=[first_observation],
    )
    instances.append(instance)
    return instance


def _build_relations(instances: Sequence[ProcessInstance]) -> list[ProcessRelation]:
    """Establish parent/child relations from the birth event of each instance."""
    relations: list[ProcessRelation] = []
    for child in instances:
        birth = child.birth
        if birth is None or birth.parent_id is None:
            relations.append(
                ProcessRelation(
                    child=child,
                    confidence=RelationConfidence.UNRESOLVED,
                    parent=None,
                    claimed_parent_id=None,
                    reason=UnresolvedReason.MISSING_PARENT_FIELD,
                    evidence=child.observations[0].location,
                )
            )
            continue

        parent, reason = _resolve_parent(child, birth.parent_id, instances)
        if parent is not None:
            relations.append(
                ProcessRelation(
                    child=child,
                    confidence=RelationConfidence.CONFIRMED,
                    parent=parent,
                    claimed_parent_id=birth.parent_id,
                    reason=None,
                    evidence=birth.location,
                )
            )
        else:
            relations.append(
                ProcessRelation(
                    child=child,
                    confidence=RelationConfidence.UNRESOLVED,
                    parent=None,
                    claimed_parent_id=birth.parent_id,
                    reason=reason,
                    evidence=birth.location,
                )
            )
    return relations


def _resolve_parent(
    child: ProcessInstance, parent_id: int, instances: Sequence[ProcessInstance]
) -> tuple[ProcessInstance | None, UnresolvedReason | None]:
    if parent_id == child.process_id:
        return None, UnresolvedReason.SELF_PARENT

    candidates = [instance for instance in instances if instance.process_id == parent_id and instance is not child]
    if not candidates:
        return None, UnresolvedReason.PARENT_NO_EVENTS

    birth = child.birth
    alive = [instance for instance in candidates if birth is not None and instance.is_alive_at(birth.timestamp)]
    if len(alive) == 1:
        return alive[0], None
    if len(alive) > 1:
        return None, UnresolvedReason.PARENT_AMBIGUOUS
    return None, UnresolvedReason.PARENT_NOT_ALIVE


def _format_instance(instance: ProcessInstance) -> str:
    birth = instance.birth
    death = instance.death
    image = instance.image_file_name or "<unknown image>"
    key = hex(instance.unique_process_key) if instance.unique_process_key is not None else "-"
    state = (
        "pre-existing (rundown)"
        if instance.pre_existing
        else ("no end event" if not instance.has_end_event else "complete lifecycle")
    )
    birth_text = (
        f"{birth.event_type.value}@{birth.timestamp.isoformat()} [{birth.location}]"
        if birth is not None
        else "no birth event"
    )
    death_text = (
        f"{death.event_type.value}@{death.timestamp.isoformat()} [{death.location}]" if death is not None else "none"
    )
    line = (
        f"{instance.instance_id} pid={instance.process_id} key={key} image={image!r} "
        f"basis={instance.identity_basis.value} state={state}"
    )
    details = [line, f"    birth: {birth_text}", f"    death: {death_text}"]
    for anomaly in instance.anomalies:
        details.append(f"    anomaly: {anomaly}")
    return "\n".join(details)


def _format_confirmed_relation(relation: ProcessRelation) -> str:
    parent = relation.parent
    child = relation.child
    assert parent is not None
    return (
        f"{parent.instance_id} (pid={parent.process_id} {parent.image_file_name or '?'}) -> "
        f"{child.instance_id} (pid={child.process_id} {child.image_file_name or '?'}) "
        f"claimed_parent_pid={relation.claimed_parent_id} evidence=[{relation.evidence}]"
    )


def _format_unresolved_relation(relation: ProcessRelation) -> str:
    child = relation.child
    reason = relation.reason.value if relation.reason is not None else "unknown"
    return (
        f"{child.instance_id} (pid={child.process_id} {child.image_file_name or '?'}) "
        f"claimed_parent_pid={relation.claimed_parent_id} -> UNRESOLVED ({reason}) "
        f"evidence=[{relation.evidence}]"
    )
