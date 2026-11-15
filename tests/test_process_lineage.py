from __future__ import annotations

import io
from datetime import timedelta

import pytest

import dissect.etl.etl as etl_module
from dissect.etl import c_etl as real_c_etl
from dissect.etl.etl import ETL
from dissect.etl.lineage import (
    IdentityBasis,
    ProcessEventType,
    RelationConfidence,
    UnresolvedReason,
    build_process_lineage,
    iter_process_observations,
)

from ._etl_factory import DCEND, DCSTART, END, START, RawProcessEvent, build_etl


@pytest.fixture(autouse=True)
def _restore_c_etl() -> object:
    # Other test modules monkeypatch the shared ``etl.c_etl`` global with mocks.
    # Restore the real parser so these tests are independent of execution order.
    etl_module.c_etl = real_c_etl.c_etl
    yield
    etl_module.c_etl = real_c_etl.c_etl


def lineage_for(events: list[RawProcessEvent]) -> object:
    return build_process_lineage(ETL(io.BytesIO(build_etl(events))))


def by_image(lineage: object, image: str) -> list[object]:
    return [instance for instance in lineage.instances if instance.image_file_name == image]


def relation_for(lineage: object, instance: object) -> object:
    return next(relation for relation in lineage.relations if relation.child is instance)


def test_normal_parent_child_creation_is_confirmed_with_evidence() -> None:
    events = [
        RawProcessEvent(START, 100, 4, 0xAAAA, "explorer.exe", 100),
        RawProcessEvent(START, 200, 100, 0xBBBB, "notepad.exe", 200),
        RawProcessEvent(END, 200, 100, 0xBBBB, "notepad.exe", 300),
    ]
    lineage = lineage_for(events)

    assert len(lineage.instances) == 2
    parent = by_image(lineage, "explorer.exe")[0]
    child = by_image(lineage, "notepad.exe")[0]

    relation = relation_for(lineage, child)
    assert relation.is_confirmed
    assert relation.parent is parent
    assert relation.claimed_parent_id == 100
    # The edge points at the child's concrete birth event.
    assert relation.evidence == child.birth.location
    assert child.has_end_event is True
    assert child.death.event_type == ProcessEventType.END


def test_pid_recycle_opens_two_distinct_instances() -> None:
    events = [
        RawProcessEvent(START, 500, 100, 0x1111, "svchost.exe", 100),
        RawProcessEvent(START, 600, 500, 0x2222, "cmd.exe", 200),
        RawProcessEvent(END, 600, 500, 0x2222, "cmd.exe", 300),
        # Same PID 600, different UniqueProcessKey -> a new execution.
        RawProcessEvent(START, 600, 500, 0x3333, "cmd.exe", 400),
    ]
    lineage = lineage_for(events)

    cmd_instances = by_image(lineage, "cmd.exe")
    assert len(cmd_instances) == 2
    first, second = cmd_instances
    assert first.unique_process_key == 0x2222
    assert second.unique_process_key == 0x3333
    assert first.instance_id != second.instance_id
    assert "identity_reused_new_instance_opened" in second.anomalies

    # Both children resolve to the still-alive parent, but remain separate edges.
    assert relation_for(lineage, first).parent.process_id == 500
    assert relation_for(lineage, second).parent.process_id == 500
    assert {id(relation.parent) for relation in lineage.confirmed_relations()} == {
        id(by_image(lineage, "svchost.exe")[0])
    }


def test_same_image_and_pid_are_never_merged() -> None:
    events = [
        RawProcessEvent(START, 600, 100, 0x2222, "cmd.exe", 200),
        RawProcessEvent(END, 600, 100, 0x2222, "cmd.exe", 300),
        RawProcessEvent(START, 600, 100, 0x9999, "cmd.exe", 400),
    ]
    lineage = lineage_for(events)
    assert len(by_image(lineage, "cmd.exe")) == 2
    assert len({instance.instance_id for instance in lineage.instances}) == 2


def test_rundown_process_is_marked_pre_existing_without_fabricated_start() -> None:
    events = [
        # Already running when the trace began; no Start event exists for it.
        RawProcessEvent(DCSTART, 500, 400, 0x1111, "services.exe", 100),
        RawProcessEvent(START, 600, 500, 0x2222, "cmd.exe", 200),
    ]
    lineage = lineage_for(events)
    services = by_image(lineage, "services.exe")[0]

    assert services.pre_existing is True
    assert services.birth.event_type == ProcessEventType.DCSTART
    # The birth timestamp is the rundown observation's own timestamp, never invented.
    assert services.birth.timestamp == lineage.observations[0].timestamp

    # A child born after rundown can still confirm against the live rundown process.
    cmd = by_image(lineage, "cmd.exe")[0]
    assert relation_for(lineage, cmd).parent is services


def test_rundown_death_does_not_create_a_second_instance() -> None:
    events = [
        RawProcessEvent(DCSTART, 500, 400, 0x1111, "services.exe", 100),
        RawProcessEvent(DCEND, 500, 400, 0x1111, "services.exe", 500),
    ]
    lineage = lineage_for(events)
    services = by_image(lineage, "services.exe")
    assert len(services) == 1
    instance = services[0]
    assert instance.birth.event_type == ProcessEventType.DCSTART
    assert instance.death.event_type == ProcessEventType.DCEND
    assert len(instance.observations) == 2


def test_missing_end_event_leaves_lifecycle_open() -> None:
    events = [
        RawProcessEvent(START, 100, 4, 0xAAAA, "longrunning.exe", 100),
        RawProcessEvent(START, 200, 100, 0xBBBB, "child.exe", 200),
    ]
    lineage = lineage_for(events)
    parent = by_image(lineage, "longrunning.exe")[0]

    assert parent.has_end_event is False
    assert parent.death is None
    # An instance without an end event is considered alive after its last event.
    assert parent.is_alive_at(parent.birth.timestamp + timedelta(seconds=10)) is True


def test_death_without_birth_is_kept_not_backfilled() -> None:
    events = [
        # Only an end event survived; the start was lost before/within the trace.
        RawProcessEvent(END, 777, 100, 0x7777, "orphan.exe", 900),
    ]
    lineage = lineage_for(events)
    orphan = by_image(lineage, "orphan.exe")[0]

    assert "observed_without_birth_event" in orphan.anomalies
    assert orphan.birth.event_type == ProcessEventType.END
    # No parent relation can be derived because there is no birth claim.
    relation = relation_for(lineage, orphan)
    assert relation.confidence == RelationConfidence.UNRESOLVED


def test_missing_parent_event_is_unresolved_not_a_confirmed_edge() -> None:
    events = [
        RawProcessEvent(START, 700, 999, 0x4444, "evil.exe", 500),
    ]
    lineage = lineage_for(events)
    evil = by_image(lineage, "evil.exe")[0]
    relation = relation_for(lineage, evil)

    assert relation.confidence == RelationConfidence.UNRESOLVED
    assert relation.parent is None
    assert relation.reason == UnresolvedReason.PARENT_NO_EVENTS
    assert relation.claimed_parent_id == 999
    # It must not appear among the confident edges.
    assert lineage.confirmed_relations() == []
    assert lineage.unresolved_relations() == [relation]


def test_dead_parent_is_not_claimed_as_alive() -> None:
    events = [
        RawProcessEvent(START, 100, 4, 0xAAAA, "parent.exe", 100),
        RawProcessEvent(END, 100, 4, 0xAAAA, "parent.exe", 200),
        # Child references PID 100 after it terminated.
        RawProcessEvent(START, 300, 100, 0xCCCC, "late.exe", 300),
    ]
    lineage = lineage_for(events)
    late = by_image(lineage, "late.exe")[0]
    relation = relation_for(lineage, late)

    assert relation.confidence == RelationConfidence.UNRESOLVED
    assert relation.reason == UnresolvedReason.PARENT_NOT_ALIVE


def test_self_parent_is_unresolved() -> None:
    events = [
        RawProcessEvent(START, 800, 800, 0xDDDD, "weird.exe", 100),
    ]
    lineage = lineage_for(events)
    weird = by_image(lineage, "weird.exe")[0]
    relation = relation_for(lineage, weird)
    assert relation.confidence == RelationConfidence.UNRESOLVED
    assert relation.reason == UnresolvedReason.SELF_PARENT


def test_ambiguous_parent_pid_reuse_is_unresolved() -> None:
    events = [
        # Two live instances share parent PID 400 at the same moment (PID reuse
        # without an intervening end event in the captured window).
        RawProcessEvent(START, 400, 4, 0x0001, "parent_a.exe", 100),
        RawProcessEvent(START, 400, 4, 0x0002, "parent_b.exe", 200),
        RawProcessEvent(START, 500, 400, 0x0003, "child.exe", 300),
    ]
    lineage = lineage_for(events)
    child = by_image(lineage, "child.exe")[0]
    relation = relation_for(lineage, child)

    assert relation.confidence == RelationConfidence.UNRESOLVED
    assert relation.reason == UnresolvedReason.PARENT_AMBIGUOUS
    assert relation.parent is None


def test_keyless_v1_events_group_by_pid_interval() -> None:
    events = [
        # V1 payloads have no UniqueProcessKey; identity is PID over an interval.
        RawProcessEvent(START, 600, 100, None, "cmd.exe", 200, version=1),
        RawProcessEvent(END, 600, 100, None, "cmd.exe", 300, version=1),
        RawProcessEvent(START, 600, 100, None, "cmd.exe", 400, version=1),
    ]
    lineage = lineage_for(events)
    cmd_instances = by_image(lineage, "cmd.exe")
    assert len(cmd_instances) == 2
    assert all(instance.identity_basis == IdentityBasis.PID_INTERVAL for instance in cmd_instances)
    assert all(instance.unique_process_key is None for instance in cmd_instances)


def test_every_observation_keeps_location_and_raw_fields() -> None:
    events = [
        RawProcessEvent(START, 600, 100, 0x2222, "cmd.exe", 200),
    ]
    etl = ETL(io.BytesIO(build_etl(events)))
    observations = list(iter_process_observations(etl))

    assert len(observations) == 1
    obs = observations[0]
    assert obs.location.buffer_index == 0
    assert isinstance(obs.location.record_offset, int)
    assert obs.location.sequence == 0
    assert obs.process_id == 600
    assert obs.parent_id == 100
    # Original payload fields are retained verbatim.
    assert obs.raw_fields["UniqueProcessKey"] == 0x2222
    assert obs.raw_fields["ImageFileName"] == b"cmd.exe"
    assert obs.raw_fields["SessionId"] == 1


def test_locations_remain_distinct_across_events() -> None:
    events = [
        RawProcessEvent(START, 100, 4, 0xAAAA, "a.exe", 100),
        RawProcessEvent(START, 200, 100, 0xBBBB, "b.exe", 200),
        RawProcessEvent(START, 300, 200, 0xCCCC, "c.exe", 300),
    ]
    etl = ETL(io.BytesIO(build_etl(events)))
    observations = list(iter_process_observations(etl))
    locations = {(obs.location.buffer_index, obs.location.record_offset) for obs in observations}
    assert len(locations) == 3
    assert [obs.location.sequence for obs in observations] == [0, 1, 2]


def test_render_text_distinguishes_confirmed_and_unresolved() -> None:
    events = [
        RawProcessEvent(START, 100, 4, 0xAAAA, "parent.exe", 100),
        RawProcessEvent(START, 200, 100, 0xBBBB, "child.exe", 200),
        RawProcessEvent(START, 300, 999, 0xCCCC, "ghost.exe", 300),
    ]
    report = lineage_for(events).render_text()
    assert "Confirmed parent/child edges" in report
    assert "parent.exe" in report and "child.exe" in report
    assert "UNRESOLVED (parent_process_has_no_events_in_trace)" in report
    assert "ghost.exe" in report


def test_events_span_multiple_buffers_with_correct_locations() -> None:
    events = [
        RawProcessEvent(START, 100 + index, 100, 0xAAAA + index, f"p{index}.exe", 100 + index * 10)
        for index in range(12)
    ]
    etl = ETL(io.BytesIO(build_etl(events, buffer_size=0x300)))
    observations = list(iter_process_observations(etl))

    assert len(observations) == len(events)
    used_buffers = {obs.location.buffer_index for obs in observations}
    assert len(used_buffers) > 1
    # Offsets reset inside each buffer while the global sequence stays contiguous.
    assert [obs.location.sequence for obs in observations] == list(range(len(events)))
    assert observations[2].location.buffer_index == 1
    assert observations[2].location.record_offset == 0x0


def test_non_process_events_are_ignored() -> None:
    # The logfile header event is present in every file but must not become a process.
    events = [RawProcessEvent(START, 100, 4, 0xAAAA, "solo.exe", 100)]
    lineage = lineage_for(events)
    assert len(lineage.instances) == 1
    assert lineage.instances[0].image_file_name == "solo.exe"


@pytest.mark.parametrize(
    ("opcode", "expected"),
    [
        (START, ProcessEventType.START),
        (END, ProcessEventType.END),
        (DCSTART, ProcessEventType.DCSTART),
        (DCEND, ProcessEventType.DCEND),
    ],
)
def test_event_type_mapping(opcode: int, expected: ProcessEventType) -> None:
    lineage = lineage_for([RawProcessEvent(opcode, 100, 4, 0xAAAA, "x.exe", 100)])
    assert lineage.observations[0].event_type == expected
