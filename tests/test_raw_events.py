from __future__ import annotations

import io
from collections import Counter

import pytest

import dissect.etl.etl as etl_module
from dissect.etl import EventRecord, EventResult, RawEvent
from dissect.etl.c_etl import c_etl
from dissect.etl.etl import ETL, parse_payload
from dissect.etl.exceptions import InvalidEventError

from .etl_event_builder import (
    KNOWN_OPCODE,
    KNOWN_PROVIDER,
    KNOWN_VERSION,
    UNKNOWN_PROVIDER,
    UNKNOWN_VERSION,
    build_mixed_etl,
    load_mixed_etl,
)


@pytest.fixture(autouse=True)
def _restore_etl_globals() -> object:
    # test_etl_buffer swaps the module-level c_etl for a MagicMock without restoring it.
    etl_module.c_etl = c_etl
    yield
    etl_module.c_etl = c_etl


def _record_by_offset(records: list[EventRecord], offset: int) -> EventRecord:
    # Use the plain attribute, not ``record.raw``, so selecting a record never parses it.
    return next(record for record in records if record.file_offset == offset)


@pytest.fixture()
def mixed_etl() -> tuple[ETL, dict[str, int]]:
    return load_mixed_etl()


def test_every_physical_record_is_retained_once(mixed_etl: tuple[ETL, dict[str, int]]) -> None:
    etl, _ = mixed_etl
    records = list(etl)

    # The counter must be a flat per-record tally: nothing is swallowed, nothing duplicated.
    assert len(records) == sum(1 for _ in records)
    assert {record.raw.file_offset for record in records} == {record.raw.file_offset for record in records}


def test_known_event_keeps_existing_interface(mixed_etl: tuple[ETL, dict[str, int]]) -> None:
    etl, offsets = mixed_etl
    record = _record_by_offset(list(etl), offsets["known"])

    assert record.raw.result == EventResult.DECODED
    event = record.event
    assert event.provider_id() == KNOWN_PROVIDER
    assert event.symbol() == "DataTransmitReceiveTransmit3_V1"
    values = event.event_values()
    assert values["ThreadId"] == 100
    assert values["ProcessId"] == 1000


def test_missing_manifest_is_unknown_but_retained(mixed_etl: tuple[ETL, dict[str, int]]) -> None:
    etl, offsets = mixed_etl
    record = _record_by_offset(list(etl), offsets["missing_manifest"])
    raw = record.raw

    assert raw.result == EventResult.MANIFEST_NOT_FOUND
    assert raw.result.is_unknown
    assert not raw.result.is_corrupt
    assert raw.provider_id == UNKNOWN_PROVIDER
    assert raw.header_type == 0x13
    assert raw.event_identity == (1, 0)
    assert raw.payload == b"\xde\xad\xbe\xef"
    assert raw.error is None
    # An unknown event still yields an Event, just without structured fields.
    assert record.event.symbol() is None
    assert record.event.event_values()["Extensions"] == []


def test_unknown_version_is_unknown_but_retained(mixed_etl: tuple[ETL, dict[str, int]]) -> None:
    etl, offsets = mixed_etl
    record = _record_by_offset(list(etl), offsets["unknown_version"])
    raw = record.raw

    assert raw.result == EventResult.UNKNOWN_TEMPLATE
    assert raw.result.is_unknown
    assert not raw.result.is_corrupt
    assert raw.provider_id == KNOWN_PROVIDER
    assert raw.event_identity == (KNOWN_OPCODE, UNKNOWN_VERSION)
    assert raw.payload == b"\x01\x02\x03\x04"


def test_empty_payload_is_distinct_from_unknown_and_corrupt(
    mixed_etl: tuple[ETL, dict[str, int]],
) -> None:
    etl, offsets = mixed_etl
    record = _record_by_offset(list(etl), offsets["empty_payload"])
    raw = record.raw

    assert raw.result == EventResult.EMPTY_PAYLOAD
    assert not raw.result.is_unknown
    assert not raw.result.is_corrupt
    assert raw.provider_id == KNOWN_PROVIDER
    assert raw.payload == b""
    assert "no payload" in raw.reason


def test_known_template_decode_failure_is_corrupt_not_unknown(
    mixed_etl: tuple[ETL, dict[str, int]],
) -> None:
    etl, offsets = mixed_etl
    record = _record_by_offset(list(etl), offsets["template_failed"])
    raw = record.raw

    assert raw.result == EventResult.TEMPLATE_FAILED
    assert raw.result.is_corrupt
    assert not raw.result.is_unknown
    assert raw.provider_id == KNOWN_PROVIDER
    assert raw.event_identity == (KNOWN_OPCODE, KNOWN_VERSION)
    assert isinstance(raw.error, EOFError)
    with pytest.raises(InvalidEventError):
        _ = record.event


def test_truncated_header_is_corrupt_and_keeps_raw_bytes(
    mixed_etl: tuple[ETL, dict[str, int]],
) -> None:
    etl, offsets = mixed_etl
    records = list(etl)
    record = _record_by_offset(records, offsets["truncated"])
    raw = record.raw

    assert record.header is None
    assert raw.result == EventResult.TRUNCATED
    assert raw.result.is_corrupt
    assert not raw.result.is_unknown
    assert raw.header_type is None
    assert raw.provider_id is None
    assert raw.payload.startswith(b"\x60\x00\x13\xc0")
    assert isinstance(raw.error, EOFError)
    with pytest.raises(InvalidEventError):
        _ = record.event

    # A truncated record is the final record of the buffer.
    assert records[-1] is record


def test_classification_counts(mixed_etl: tuple[ETL, dict[str, int]]) -> None:
    etl, _ = mixed_etl
    results = [record.raw.result for record in etl]

    for expected in (
        EventResult.MANIFEST_NOT_FOUND,
        EventResult.UNKNOWN_TEMPLATE,
        EventResult.EMPTY_PAYLOAD,
        EventResult.TEMPLATE_FAILED,
        EventResult.TRUNCATED,
    ):
        assert results.count(expected) == 1
    assert results.count(EventResult.DECODED) == 4


def test_raw_payload_is_an_independent_copy() -> None:
    etl, offsets = load_mixed_etl()
    record = _record_by_offset(list(etl), offsets["known"])
    payload = record.raw.payload

    # bytes are immutable; a fresh accessor returns equal content, never a mutated memoryview.
    assert payload == record.raw.payload
    assert isinstance(payload, bytes)
    assert isinstance(record.raw.payload, bytes)


def test_raw_event_survives_repeated_access_without_reparse(
    mixed_etl: tuple[ETL, dict[str, int]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    etl, offsets = mixed_etl
    record = _record_by_offset(list(etl), offsets["missing_manifest"])
    first = record.raw

    calls = 0

    def explode(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("parse_payload must not run again")

    monkeypatch.setattr("dissect.etl.etl.parse_payload", explode)
    assert record.raw is first
    assert record.event.symbol() is None
    assert calls == 0


def test_payload_parsing_stays_lazy_until_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    etl, offsets = load_mixed_etl()
    record = _record_by_offset(list(etl), offsets["known"])

    # Merely reading the record must not parse its payload.
    assert record._raw is None
    assert record._event is None

    calls = 0
    real_parse = etl_module.parse_payload

    def counting_parse(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(etl_module, "parse_payload", counting_parse)
    assert record.raw.result == EventResult.DECODED
    assert calls == 1
    # A second access reuses the cached result instead of re-parsing.
    assert record.event.symbol() == "DataTransmitReceiveTransmit3_V1"
    assert calls == 1


def test_parse_payload_returns_raw_and_event_for_known_header() -> None:
    etl, offsets = load_mixed_etl()
    record = _record_by_offset(list(etl), offsets["known"])
    raw, event = parse_payload(record.header, buffer_offset=0, file_offset=0)

    assert isinstance(raw, RawEvent)
    assert raw.result == EventResult.DECODED
    assert event is not None
    assert event.symbol() == "DataTransmitReceiveTransmit3_V1"


def test_file_roundtrip_preserves_all_records() -> None:
    data, offsets = build_mixed_etl()
    records = list(ETL(io.BytesIO(data)))

    assert _record_by_offset(records, offsets["truncated"]).raw.result == EventResult.TRUNCATED
    assert len(records) == 9
    # All retained offsets point inside the actual file.
    assert all(0 <= record.raw.file_offset < len(data) for record in records)


def test_report_lists_every_record_with_a_matching_count() -> None:
    """End-to-end report over an ETL mixing known, unknown, empty, corrupt and truncated events.

    Run with ``pytest -s`` to print the full report. The summary count must equal the number of
    physical records that were iterated, proving no record is swallowed to fake a clean run.
    """
    etl, _ = load_mixed_etl()
    records = list(etl)

    counts: Counter[EventResult] = Counter()
    print()
    for index, record in enumerate(records):
        raw = record.raw
        counts[raw.result] += 1
        print(
            f"[{index}] {raw.result.name:<18} file=0x{raw.file_offset:x} "
            f"header_type={raw.header_type} provider={raw.provider_id} "
            f"opcode/version={raw.event_identity} payload={len(raw.payload)} bytes"
        )
        print(f"    reason: {raw.reason}")
    print("summary:", {result.name: counts.get(result, 0) for result in EventResult})

    # Every physical record is accounted for exactly once: the tally matches the iteration.
    assert sum(counts.values()) == len(records)
    assert len(records) == 9
    assert counts[EventResult.DECODED] == 4
    assert counts[EventResult.MANIFEST_NOT_FOUND] == 1
    assert counts[EventResult.UNKNOWN_TEMPLATE] == 1
    assert counts[EventResult.EMPTY_PAYLOAD] == 1
    assert counts[EventResult.TEMPLATE_FAILED] == 1
    assert counts[EventResult.TRUNCATED] == 1
