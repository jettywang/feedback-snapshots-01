"""Seeded semantic regression for CloudEvents binding switches."""

import base64
import json
import random
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Final, cast

import pytest
from cloudevents.core.base import BaseCloudEvent
from cloudevents.core.bindings import http, kafka
from cloudevents.core.formats.json import JSONFormat
from cloudevents.core.v1.event import CloudEvent

SEED: Final[int] = 20261125
CASE_COUNT: Final[int] = 8
EXTENSION_NAME: Final[str] = "genext"
BINARY_DATA_TYPE: Final[str] = "application/octet-stream"
FORMAT: Final[JSONFormat] = JSONFormat()
OMITTED_TIME_MARKER: Final[str] = "<time omitted on wire: aware SDK default>"

HTTP_BINARY: Final[str] = "http-binary"
HTTP_STRUCTURED: Final[str] = "http-structured"
KAFKA_BINARY: Final[str] = "kafka-binary"
KAFKA_STRUCTURED: Final[str] = "kafka-structured"
HTTP_CARRIERS: Final[tuple[str, ...]] = (HTTP_BINARY, HTTP_STRUCTURED)
KAFKA_CARRIERS: Final[tuple[str, ...]] = (KAFKA_BINARY, KAFKA_STRUCTURED)
CARRIERS: Final[tuple[str, ...]] = HTTP_CARRIERS + KAFKA_CARRIERS
ROUTES: Final[tuple[tuple[str, str], ...]] = tuple(
    [(http, kafka) for http in HTTP_CARRIERS for kafka in KAFKA_CARRIERS]
    + [(kafka, http) for kafka in KAFKA_CARRIERS for http in HTTP_CARRIERS]
)
ROUTE_IDS: Final[tuple[str, ...]] = tuple(
    f"{first}_to_{second}" for first, second in ROUTES
)

KNOWN_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {
        "id",
        "source",
        "type",
        "specversion",
        "time",
        "datacontenttype",
        "dataschema",
        "subject",
    }
)


@dataclass(frozen=True)
class GeneratedCase:
    index: int
    seed: int
    event: CloudEvent
    raw_data: bytes
    extension_value: str

    @property
    def case_id(self) -> str:
        return f"case{self.index:02d}"


def generate_case(index: int) -> GeneratedCase:
    """Generate one tiny, valid event from an independent fixed-seed RNG."""
    rng = random.Random(f"{SEED}:{index}")
    offset_minutes = rng.choice((0, 330, -480))
    event_time = datetime(
        2024,
        1 + rng.randrange(12),
        1 + rng.randrange(28),
        rng.randrange(24),
        rng.randrange(60),
        rng.randrange(60),
        tzinfo=timezone(timedelta(minutes=offset_minutes)),
    )
    # FF/FE guarantee the payload is not representable as decoded UTF-8 text.
    raw_data = b"\xff\xfe" + bytes(
        rng.randrange(256) for _ in range(rng.randrange(2, 7))
    )
    extension_value = f"ext-{rng.randrange(16**6):06x}"
    event_id = f"gen-{index:02d}-{rng.randrange(16**6):06x}"

    event = CloudEvent(
        {
            "specversion": "1.0",
            "id": event_id,
            "source": f"urn:test:binding-regression:{index:02d}",
            "type": "com.example.binding.generated",
            "time": event_time,
            "datacontenttype": BINARY_DATA_TYPE,
            EXTENSION_NAME: extension_value,
        },
        raw_data,
    )
    return GeneratedCase(index, SEED, event, raw_data, extension_value)


CASES: Final[tuple[GeneratedCase, ...]] = tuple(
    generate_case(index) for index in range(CASE_COUNT)
)
CASE_IDS: Final[tuple[str, ...]] = tuple(case.case_id for case in CASES)


def _data_snapshot(data: Any) -> dict[str, Any]:
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
        return {"kind": "bytes", "length": len(raw), "hex": raw.hex()}
    if data is None:
        return {"kind": "null"}
    return {"kind": type(data).__name__, "value": data}


def _snapshot(event: BaseCloudEvent) -> dict[str, Any]:
    time_value = event.get_time()
    time_in_utc = (
        time_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if time_value is not None
        else None
    )
    attributes = event.get_attributes()
    return {
        "id": event.get_id(),
        "source": event.get_source(),
        "type": event.get_type(),
        "specversion": event.get_specversion(),
        "time": time_in_utc,
        "datacontenttype": event.get_datacontenttype(),
        "dataschema": event.get_dataschema(),
        "subject": event.get_subject(),
        "extensions": {
            name: attributes[name]
            for name in sorted(attributes)
            if name not in KNOWN_ATTRIBUTES
        },
        "data": _data_snapshot(event.get_data()),
    }


def _minimal_diff(expected: Any, actual: Any) -> Any:
    """Return only mismatching branches; matching fields disappear."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        diff: dict[str, Any] = {}
        for key in sorted(expected.keys() | actual.keys()):
            if key not in expected:
                diff[key] = {"unexpected": actual[key]}
            elif key not in actual:
                diff[key] = {"missing": expected[key]}
            else:
                child_diff = _minimal_diff(expected[key], actual[key])
                if child_diff:
                    diff[key] = child_diff
        return diff

    if expected == actual:
        return {}
    return {"expected": expected, "actual": actual}


def _assert_matches_case(
    case: GeneratedCase,
    actual: BaseCloudEvent,
    *,
    stage: int,
    carrier: str,
    route: str | None = None,
) -> None:
    diff = _minimal_diff(_snapshot(case.event), _snapshot(actual))
    if not diff:
        return

    route_context = f" route={route}" if route is not None else ""
    compact_diff = json.dumps(
        diff, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False
    )
    raise AssertionError(
        "CloudEvents binding mismatch "
        f"stage={stage} carrier={carrier}{route_context} "
        f"seed={case.seed} case={case.case_id}\n{compact_diff}"
    )


def _encode(carrier: str, event: BaseCloudEvent) -> Any:
    if carrier == HTTP_BINARY:
        return http.to_binary(event, FORMAT)
    if carrier == HTTP_STRUCTURED:
        return http.to_structured(event, FORMAT)
    if carrier == KAFKA_BINARY:
        return kafka.to_binary(event, FORMAT)
    if carrier == KAFKA_STRUCTURED:
        return kafka.to_structured(event, FORMAT)
    raise AssertionError(f"unknown carrier: {carrier}")


def _decode(carrier: str, message: Any) -> BaseCloudEvent:
    if carrier == HTTP_BINARY:
        return http.from_binary(message, FORMAT, CloudEvent)
    if carrier == HTTP_STRUCTURED:
        return http.from_structured(message, FORMAT, CloudEvent)
    if carrier == KAFKA_BINARY:
        return kafka.from_binary(message, FORMAT, CloudEvent)
    if carrier == KAFKA_STRUCTURED:
        return kafka.from_structured(message, FORMAT, CloudEvent)
    raise AssertionError(f"unknown carrier: {carrier}")


def _roundtrip(carrier: str, event: BaseCloudEvent) -> BaseCloudEvent:
    return _decode(carrier, _encode(carrier, event))


def _normalized_headers(carrier: str, message: Any) -> dict[str, str]:
    if carrier.startswith("http-"):
        return dict(message.headers)
    return {name: value.decode("utf-8") for name, value in message.headers.items()}


def _payload(carrier: str, message: Any) -> bytes:
    payload = message.body if carrier.startswith("http-") else message.value
    return cast(bytes, payload)


def _prefix(carrier: str) -> str:
    return "ce-" if carrier.startswith("http-") else "ce_"


def _assert_legal_wire_representation(
    case: GeneratedCase, carrier: str, message: Any
) -> None:
    headers = _normalized_headers(carrier, message)
    payload = _payload(carrier, message)
    prefix = _prefix(carrier)
    event = case.event

    if carrier.startswith("kafka-"):
        assert message.key is None

    if carrier.endswith("-binary"):
        assert headers["content-type"] == BINARY_DATA_TYPE
        assert f"{prefix}datacontenttype" not in headers
        assert headers[f"{prefix}id"] == event.get_id()
        assert headers[f"{prefix}source"] == event.get_source()
        assert headers[f"{prefix}type"] == event.get_type()
        assert headers[f"{prefix}specversion"] == event.get_specversion()
        assert headers[f"{prefix}{EXTENSION_NAME}"] == case.extension_value
        assert headers[f"{prefix}time"]
        # Binary mode carries application/octet-stream data without base64.
        assert payload == case.raw_data
        return

    assert headers["content-type"] == FORMAT.get_content_type()
    envelope = json.loads(payload)
    assert envelope["id"] == event.get_id()
    assert envelope["source"] == event.get_source()
    assert envelope["type"] == event.get_type()
    assert envelope["specversion"] == event.get_specversion()
    assert envelope[EXTENSION_NAME] == case.extension_value
    assert envelope["time"]
    # Structured JSON carries bytes as data_base64 and must not also use data.
    assert "data" not in envelope
    assert base64.b64decode(envelope["data_base64"], validate=True) == case.raw_data


def _remove_wire_time(carrier: str, message: Any) -> Any:
    if carrier.endswith("-binary"):
        prefix = _prefix(carrier)
        headers = {
            name: value
            for name, value in message.headers.items()
            if name.lower() != f"{prefix}time"
        }
        return replace(message, headers=headers)

    envelope = json.loads(_payload(carrier, message))
    envelope.pop("time", None)
    without_time = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    if carrier.startswith("http-"):
        return replace(message, body=without_time)
    return replace(message, value=without_time)


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize("carrier", CARRIERS)
def test_seeded_events_keep_semantics_in_each_legal_carrier(
    case: GeneratedCase, carrier: str
) -> None:
    message = _encode(carrier, case.event)
    _assert_legal_wire_representation(case, carrier, message)

    decoded = _decode(carrier, message)
    _assert_matches_case(case, decoded, stage=1, carrier=carrier)


def _run_two_hop_route(
    case: GeneratedCase,
    first_carrier: str,
    second_carrier: str,
    *,
    second_stage: Callable[[BaseCloudEvent], BaseCloudEvent] | None = None,
) -> BaseCloudEvent:
    route = f"{first_carrier}->{second_carrier}"

    after_first = _roundtrip(first_carrier, case.event)
    _assert_matches_case(case, after_first, stage=1, carrier=first_carrier, route=route)

    if second_stage is None:
        after_second = _roundtrip(second_carrier, after_first)
    else:
        after_second = second_stage(after_first)

    _assert_matches_case(
        case, after_second, stage=2, carrier=second_carrier, route=route
    )
    return after_second


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize(("first_carrier", "second_carrier"), ROUTES, ids=ROUTE_IDS)
def test_binding_switch_preserves_identity_time_extension_and_bytes(
    case: GeneratedCase, first_carrier: str, second_carrier: str
) -> None:
    _run_two_hop_route(case, first_carrier, second_carrier)


def _drop_extension(event: BaseCloudEvent, extension_name: str) -> CloudEvent:
    attributes = dict(event.get_attributes())
    attributes.pop(extension_name, None)
    return CloudEvent(attributes, event.get_data())


def test_second_stage_extension_loss_is_located_with_minimal_diff() -> None:
    case = CASES[0]

    def faulty_second_stage(event: BaseCloudEvent) -> BaseCloudEvent:
        kafka_message = kafka.to_binary(event, FORMAT)
        decoded = kafka.from_binary(kafka_message, FORMAT, CloudEvent)
        return _drop_extension(decoded, EXTENSION_NAME)

    with pytest.raises(AssertionError) as exc_info:
        _run_two_hop_route(
            case,
            HTTP_BINARY,
            KAFKA_BINARY,
            second_stage=faulty_second_stage,
        )

    report = str(exc_info.value)
    assert "stage=2" in report
    assert "carrier=kafka-binary" in report
    assert "route=http-binary->kafka-binary" in report
    assert "extensions" in report
    assert EXTENSION_NAME in report
    assert '"missing"' in report


TIME_INSTANT = datetime(2024, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
TIME_CASES: Final[tuple[tuple[str, str], ...]] = (
    (HTTP_BINARY, "2024-03-04T05:06:07Z"),
    (HTTP_BINARY, "2024-03-04T05:06:07+00:00"),
    (HTTP_BINARY, "2024-03-04T05%3A06%3A07Z"),
    (HTTP_BINARY, "2024-03-04T10%3A36%3A07%2B05%3A30"),
    (KAFKA_BINARY, "2024-03-04T05:06:07Z"),
    (KAFKA_BINARY, "2024-03-04T05:06:07+00:00"),
    (KAFKA_BINARY, "2024-03-04T10:36:07+05:30"),
)
TIME_IDS: Final[tuple[str, ...]] = (
    "http-z",
    "http-utc-numeric-offset",
    "http-percent-encoded-colon",
    "http-percent-encoded-offset",
    "kafka-z",
    "kafka-utc-numeric-offset",
    "kafka-non-utc-offset",
)


def _binary_time_event(carrier: str, wire_time: str) -> BaseCloudEvent:
    required = {
        "specversion": "1.0",
        "id": "time-id",
        "source": "/time",
        "type": "com.example.time",
    }
    if carrier == HTTP_BINARY:
        http_headers = {f"ce-{name}": value for name, value in required.items()}
        http_headers["ce-time"] = wire_time
        message: Any = http.HTTPMessage(headers=http_headers, body=b"")
    else:
        kafka_headers: dict[str, bytes] = {
            f"ce_{name}": value.encode("utf-8") for name, value in required.items()
        }
        kafka_headers["ce_time"] = wire_time.encode("utf-8")
        message = kafka.KafkaMessage(headers=kafka_headers, key=None, value=b"")
    return _decode(carrier, message)


@pytest.mark.parametrize(("carrier", "wire_time"), TIME_CASES, ids=TIME_IDS)
def test_compatible_time_spellings_keep_same_instant(
    carrier: str, wire_time: str
) -> None:
    event = _binary_time_event(carrier, wire_time)
    parsed_time = event.get_time()

    assert isinstance(parsed_time, datetime)
    assert parsed_time.utcoffset() is not None
    assert parsed_time.astimezone(timezone.utc) == TIME_INSTANT


@pytest.mark.parametrize("carrier", CARRIERS)
def test_omitted_wire_time_is_accepted_as_optional_form(carrier: str) -> None:
    case = CASES[1]
    message = _remove_wire_time(carrier, _encode(carrier, case.event))
    decoded = _decode(carrier, message)

    parsed_time = decoded.get_time()
    assert isinstance(parsed_time, datetime)
    assert parsed_time.tzinfo is not None
    assert parsed_time.utcoffset() is not None

    expected = _snapshot(case.event)
    actual = _snapshot(decoded)
    expected["time"] = OMITTED_TIME_MARKER
    actual["time"] = OMITTED_TIME_MARKER
    diff = _minimal_diff(expected, actual)
    assert not diff, json.dumps(
        diff, sort_keys=True, separators=(",", ":"), default=str
    )
