from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from dissect.etl.c_etl import c_etl
from dissect.etl.headers.event import EventHeaderExtendedDataItem, ExtType
from dissect.etl.stack_evidence import (
    FrameStatus,
    ModuleEvidence,
    OfflineStackResolver,
    RawStackEvidence,
    StackOrigin,
    extract_stack_evidence,
)

UTC = timezone.utc
T0 = datetime(2026, 11, 16, 10, 0, 0, tzinfo=UTC)


def make_stack_extension(ext_type: ExtType, match_id: int, addresses: list[int]) -> EventHeaderExtendedDataItem:
    struct_type = (
        c_etl.EVENT_HEADER_EXT_TYPE_STACK_TRACE32
        if ext_type == ExtType.STACK_TRACE32
        else c_etl.EVENT_HEADER_EXT_TYPE_STACK_TRACE64
    )
    payload = struct_type(MatchId=match_id, Address=addresses).dumps()
    return EventHeaderExtendedDataItem(
        c_etl.EventHeaderExtendedDataItemHeader(
            Size=len(payload) + 8,
            ExtType=ext_type,
            DataSize=len(payload),
            Data=payload,
        ).dumps()
    )


def make_header(pid: int, timestamp: datetime, extensions: list[EventHeaderExtendedDataItem]) -> SimpleNamespace:
    return SimpleNamespace(process_id=pid, timestamp=timestamp, header_extensions=extensions)


def make_raw(
    match_id: int,
    addresses: tuple[int, ...],
    pointer_width: int,
    pid: int = 100,
    timestamp: datetime = T0,
) -> RawStackEvidence:
    ext_type = ExtType.STACK_TRACE64 if pointer_width == 8 else ExtType.STACK_TRACE32
    return RawStackEvidence(
        match_id=match_id,
        addresses=addresses,
        pointer_width=pointer_width,
        origin=StackOrigin(event_index=0, extension_index=0, pid=pid, timestamp=timestamp),
        ext_type=ext_type,
    )


def module(
    pid: int,
    name: str,
    base: int,
    end: int,
    *,
    source: str,
    loaded_at: datetime | None = None,
    unloaded_at: datetime | None = None,
    process_start: datetime | None = None,
    process_end: datetime | None = None,
    evidence_id: str | None = None,
) -> ModuleEvidence:
    return ModuleEvidence(
        pid=pid,
        base_address=base,
        end_address=end,
        module_name=name,
        source=source,
        loaded_at=loaded_at,
        unloaded_at=unloaded_at,
        process_start=process_start,
        process_end=process_end,
        evidence_id=evidence_id,
    )


def test_raw_evidence_preserves_width_matchid_and_order() -> None:
    ext32 = make_stack_extension(ExtType.STACK_TRACE32, 0x11223344, [0x90001000, 0x90002000])
    header = make_header(424, T0, [ext32])

    raw, resolved = extract_stack_evidence(header, event_index=7)

    assert resolved == []
    assert len(raw) == 1
    stack = raw[0]
    assert stack.pointer_width == 4
    assert stack.is_64bit is False
    assert stack.match_id == 0x11223344
    assert stack.addresses == (0x90001000, 0x90002000)
    assert stack.origin.pid == 424
    assert stack.origin.timestamp == T0
    assert stack.origin.event_index == 7
    assert stack.origin.extension_index == 0


def test_64bit_width_and_verbatim_addresses() -> None:
    high_address = 0xFFFFFFFF00001234
    ext64 = make_stack_extension(ExtType.STACK_TRACE64, 9, [high_address])
    header = make_header(100, T0, [ext64])

    raw, _ = extract_stack_evidence(header)

    assert raw[0].pointer_width == 8
    assert raw[0].is_64bit is True
    assert raw[0].addresses == (high_address,)


def test_same_address_different_modules_across_processes() -> None:
    shared_address = 0x7FF800001234
    resolver = OfflineStackResolver(
        [
            module(100, "alpha.dll", 0x7FF800000000, 0x7FF800010000, source="evidence://process-100/image"),
            module(200, "beta.dll", 0x7FF800000000, 0x7FF800010000, source="evidence://process-200/image"),
        ]
    )

    resolution_100 = resolver.resolve_stack(make_raw(1, (shared_address,), 8, pid=100), 100, T0)
    resolution_200 = resolver.resolve_stack(make_raw(2, (shared_address,), 8, pid=200), 200, T0)

    frame_100 = resolution_100.frames[0]
    frame_200 = resolution_200.frames[0]
    assert frame_100.status == FrameStatus.ASSOCIATED
    assert frame_200.status == FrameStatus.ASSOCIATED
    assert frame_100.match.module_name == "alpha.dll"
    assert frame_200.match.module_name == "beta.dll"
    assert frame_100.match.relative_offset == 0x1234
    assert frame_200.match.relative_offset == 0x1234
    assert frame_100.match.evidence.source == "evidence://process-100/image"
    assert frame_200.match.evidence.source == "evidence://process-200/image"


def test_pid_reuse_does_not_cross_lifetimes() -> None:
    address = 0x500010
    reuse_pid = 300
    old_process = module(
        reuse_pid,
        "old.exe",
        0x500000,
        0x510000,
        source="evidence://pid-300/incarnation-1",
        process_start=T0,
        process_end=T0 + timedelta(seconds=10),
    )
    new_process = module(
        reuse_pid,
        "new.exe",
        0x500000,
        0x510000,
        source="evidence://pid-300/incarnation-2",
        process_start=T0 + timedelta(seconds=20),
    )
    resolver = OfflineStackResolver([old_process, new_process])

    old_event = T0 + timedelta(seconds=5)
    new_event = T0 + timedelta(seconds=25)

    old_frame = resolver.resolve_frame(reuse_pid, old_event, address)
    new_frame = resolver.resolve_frame(reuse_pid, new_event, address)

    assert old_frame[0] == FrameStatus.ASSOCIATED
    assert old_frame[1][0].module_name == "old.exe"
    assert new_frame[0] == FrameStatus.ASSOCIATED
    assert new_frame[1][0].module_name == "new.exe"

    # An event between the two lifetimes has no valid process, even though the
    # address and pid match both stored intervals on their own.
    gap_frame = resolver.resolve_frame(reuse_pid, T0 + timedelta(seconds=15), address)
    assert gap_frame[0] == FrameStatus.UNKNOWN
    assert gap_frame[1] == ()


def test_unloaded_module_is_unknown_after_unload() -> None:
    address = 0x600040
    resolver = OfflineStackResolver(
        [
            module(
                400,
                "plugin.dll",
                0x600000,
                0x610000,
                source="evidence://process-400/image-load",
                loaded_at=T0,
                unloaded_at=T0 + timedelta(seconds=30),
            )
        ]
    )

    while_loaded = resolver.resolve_frame(400, T0 + timedelta(seconds=20), address)
    after_unload = resolver.resolve_frame(400, T0 + timedelta(seconds=31), address)
    at_unload_boundary = resolver.resolve_frame(400, T0 + timedelta(seconds=30), address)

    assert while_loaded[0] == FrameStatus.ASSOCIATED
    assert while_loaded[1][0].module_name == "plugin.dll"
    assert after_unload[0] == FrameStatus.UNKNOWN
    assert at_unload_boundary[0] == FrameStatus.UNKNOWN


def test_unknown_address_and_missing_pid_remain_unknown() -> None:
    resolver = OfflineStackResolver(
        [module(500, "known.dll", 0x700000, 0x710000, source="evidence://process-500/image")]
    )

    outside_range = resolver.resolve_frame(500, T0, 0x999999)
    unknown_pid = resolver.resolve_frame(999, T0, 0x700100)
    no_pid = resolver.resolve_frame(None, T0, 0x700100)
    no_timestamp = resolver.resolve_frame(500, None, 0x700100)

    assert outside_range == (FrameStatus.UNKNOWN, ())
    assert unknown_pid == (FrameStatus.UNKNOWN, ())
    assert no_pid == (FrameStatus.UNKNOWN, ())
    assert no_timestamp == (FrameStatus.UNKNOWN, ())


def test_overlapping_evidence_is_reported_as_conflict() -> None:
    address = 0x800200
    resolver = OfflineStackResolver(
        [
            module(600, "first.dll", 0x800000, 0x810000, source="evidence://process-600/load-a"),
            module(600, "second.dll", 0x800000, 0x810000, source="evidence://process-600/load-b"),
        ]
    )

    status, candidates = resolver.resolve_frame(600, T0, address)

    assert status == FrameStatus.CONFLICT
    assert len(candidates) == 2
    assert {candidate.module_name for candidate in candidates} == {"first.dll", "second.dll"}
    assert all(candidate.relative_offset == 0x200 for candidate in candidates)

    resolution = resolver.resolve_stack(make_raw(3, (address,), 8, pid=600), 600, T0)
    assert resolution.frames[0].status == FrameStatus.CONFLICT
    assert resolution.frames[0].match is None


def test_resolver_instances_are_isolated() -> None:
    address = 0x7FF800001000
    resolver_a = OfflineStackResolver(
        [module(700, "only-in-a.dll", 0x7FF800000000, 0x7FF800010000, source="evidence://a")]
    )
    resolver_b = OfflineStackResolver()

    assert resolver_a.resolve_frame(700, T0, address)[0] == FrameStatus.ASSOCIATED
    assert resolver_b.resolve_frame(700, T0, address)[0] == FrameStatus.UNKNOWN


def test_every_association_is_traceable() -> None:
    addresses = (0x900010, 0x900020)
    evidence = module(
        800,
        "traceable.dll",
        0x900000,
        0x910000,
        source="evidence://process-800/image-id-55",
        evidence_id="IMG-55",
    )
    resolver = OfflineStackResolver([evidence])
    raw = make_raw(77, addresses, 8, pid=800)

    resolution = resolver.resolve_stack(raw, 800, T0)

    assert resolution.match_id == 77
    assert resolution.origin.extension_index == raw.origin.extension_index
    for index, frame in enumerate(resolution.frames):
        assert frame.frame_index == index
        assert frame.address == addresses[index]
        assert frame.status == FrameStatus.ASSOCIATED
        assert frame.match.evidence is evidence
        assert frame.match.evidence.evidence_id == "IMG-55"
        assert frame.match.evidence.source == "evidence://process-800/image-id-55"


def test_extract_and_resolve_end_to_end() -> None:
    shared = 0x100050
    ext_pid1 = make_stack_extension(ExtType.STACK_TRACE32, 1, [shared, 0xDEADBEEF])
    ext_pid2 = make_stack_extension(ExtType.STACK_TRACE64, 2, [shared])
    header_1 = make_header(100, T0, [ext_pid1])
    header_2 = make_header(200, T0, [ext_pid2])

    resolver = OfflineStackResolver(
        [
            module(100, "alpha32.dll", 0x100000, 0x200000, source="evidence://p100"),
            module(200, "beta64.dll", 0x100000, 0x200000, source="evidence://p200"),
        ]
    )

    raw_1, resolution_1 = extract_stack_evidence(header_1, event_index=0, resolver=resolver)
    raw_2, resolution_2 = extract_stack_evidence(header_2, event_index=1, resolver=resolver)

    assert raw_1[0].pointer_width == 4
    assert [frame.status for frame in resolution_1[0].frames] == [
        FrameStatus.ASSOCIATED,
        FrameStatus.UNKNOWN,
    ]
    assert resolution_1[0].frames[0].match.module_name == "alpha32.dll"
    assert resolution_1[0].frames[0].match.relative_offset == 0x50
    assert resolution_1[0].frames[1].address == 0xDEADBEEF

    assert raw_2[0].pointer_width == 8
    assert resolution_2[0].frames[0].status == FrameStatus.ASSOCIATED
    assert resolution_2[0].frames[0].match.module_name == "beta64.dll"


def test_evidence_requires_source_and_valid_ranges() -> None:
    with pytest.raises(ValueError, match="source"):
        ModuleEvidence(pid=1, base_address=0x1000, end_address=0x2000, module_name="x", source="")

    with pytest.raises(ValueError, match="end_address"):
        ModuleEvidence(pid=1, base_address=0x2000, end_address=0x1000, module_name="x", source="ev")

    with pytest.raises(ValueError, match="unloaded_at"):
        ModuleEvidence(
            pid=1,
            base_address=0x1000,
            end_address=0x2000,
            module_name="x",
            source="ev",
            loaded_at=T0,
            unloaded_at=T0 - timedelta(seconds=1),
        )
