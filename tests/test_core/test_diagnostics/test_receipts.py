#  Copyright 2018-Present The CloudEvents Authors
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Diagnostic receipts for failed reception over the HTTP and RabbitMQ bindings.

The scenario mirrors a redelivered CloudEvent arriving twice over different
transports: two local carriers share identical CloudEvent attributes but are
encoded as different JSON bytes.  Synthetic content-decoding and
event-construction failures are interleaved across the transports and content
modes, and a final successful reception proves that earlier diagnostics do not
leak into success results.
"""

import dataclasses
import json
from json import JSONDecodeError
from typing import Any

import pytest

from cloudevents.core.bindings import http, rabbitmq
from cloudevents.core.bindings.http import HTTPMessage
from cloudevents.core.bindings.rabbitmq import RabbitMQMessage
from cloudevents.core.diagnostics import (
    ContentMode,
    DiagnosticReceipt,
    FailureStage,
    ReceptionBinding,
    diagnostic_receipt,
    digest_raw_content,
    get_diagnostic_receipt,
    get_qualified_exception_name,
)
from cloudevents.core.exceptions import (
    CloudEventValidationError,
    MissingRequiredAttributeError,
)
from cloudevents.core.formats.json import JSONFormat
from cloudevents.core.v1.event import CloudEvent

ATTRIBUTES: dict[str, str] = {
    "specversion": "1.0",
    "id": "redelivery-id-77",
    "source": "/orders/123",
    "type": "com.example.order.created",
    "datacontenttype": "application/json",
    "time": "2026-11-25T09:30:00Z",
}
PAYLOAD: dict[str, Any] = {"orderId": 123, "status": "created"}


class DecodingFailureFormat(JSONFormat):
    """Format whose payload/body decoding always fails with a decoding error."""

    def read_data(
        self,
        body: bytes,
        datacontenttype: str | None,
    ) -> dict[str, Any] | str | bytes | None:
        raise UnicodeDecodeError(
            "utf-8", body, 0, min(1, len(body)), "synthetic decoding failure"
        )

    def read(
        self,
        event_factory: Any,
        data: str | bytes,
    ) -> CloudEvent:
        raw = data if isinstance(data, bytes) else data.encode("utf-8")
        raise UnicodeDecodeError(
            "utf-8", raw, 0, min(1, len(raw)), "synthetic decoding failure"
        )


class ConstructionFailureFormat(JSONFormat):
    """Format that decodes fine but fails while constructing the event."""

    def read(
        self,
        event_factory: Any,
        data: str | bytes,
    ) -> CloudEvent:
        return super().read(
            event_factory=failing_event_factory,
            data=data,
        )


def failing_event_factory(
    attributes: dict[str, Any],
    data: dict[str, Any] | str | bytes | None,
) -> CloudEvent:
    """Event factory preserving the construction failure semantics."""
    raise MissingRequiredAttributeError(attribute_name="source")


def build_carriers() -> tuple[bytes, bytes]:
    """
    Build two carriers with identical CloudEvent attributes but different JSON
    bytes (different key ordering and whitespace), both decoding to the same
    structured CloudEvent.
    """
    envelope_a = dict(ATTRIBUTES)
    envelope_a["data"] = PAYLOAD
    carrier_a = (
        b'{\n  "specversion": "1.0",\n  "id": "redelivery-id-77",\n'
        b'  "source": "/orders/123",\n  "type": "com.example.order.created",\n'
        b'  "datacontenttype": "application/json",\n'
        b'  "time": "2026-11-25T09:30:00Z",\n  "data": {\n'
        b'    "orderId": 123,\n    "status": "created"\n  }\n}'
    )
    envelope_b = dict(ATTRIBUTES)
    envelope_b["data"] = PAYLOAD
    carrier_b = (
        b'{"data":{"status":"created","orderId":123},'
        b'"datacontenttype":"application/json","type":"com.example.order.created",'
        b'"source":"/orders/123","id":"redelivery-id-77",'
        b'"time":"2026-11-25T09:30:00Z","specversion":"1.0"}'
    )
    # Sanity check: the hand-built bytes match the declared attributes.
    assert json.loads(carrier_a) == envelope_a
    assert json.loads(carrier_b) == envelope_b
    assert carrier_a != carrier_b
    return carrier_a, carrier_b


def assert_same_event(left: CloudEvent, right: CloudEvent) -> None:
    """Two differently encoded carriers must decode into the same event."""
    assert left.get_attributes() == right.get_attributes()
    assert left.get_data() == right.get_data()


def structured_http(body: bytes) -> HTTPMessage:
    return HTTPMessage(
        headers={"content-type": JSONFormat.CONTENT_TYPE}, body=body
    )


def structured_rabbitmq(body: bytes) -> RabbitMQMessage:
    return RabbitMQMessage(
        headers={}, content_type=JSONFormat.CONTENT_TYPE, body=body
    )


@pytest.fixture
def carriers() -> tuple[bytes, bytes]:
    return build_carriers()


def test_carriers_share_attributes_but_have_distinct_bytes(
    carriers: tuple[bytes, bytes],
) -> None:
    carrier_a, carrier_b = carriers
    event_a = JSONFormat().read(CloudEvent, carrier_a)
    event_b = JSONFormat().read(CloudEvent, carrier_b)
    assert_same_event(event_a, event_b)
    assert carrier_a != carrier_b
    assert digest_raw_content(carrier_a) != digest_raw_content(carrier_b)
    # The digest is recomputable offline from the untouched carrier bytes.
    assert digest_raw_content(carrier_a).startswith("sha256:")


@pytest.mark.parametrize(
    "binding, message_builder, expected_binding",
    [
        (http, structured_http, ReceptionBinding.HTTP),
        (rabbitmq, structured_rabbitmq, ReceptionBinding.RABBITMQ),
    ],
)
def test_structured_decoding_failure_keeps_exception_and_receipt(
    binding: Any,
    message_builder: Any,
    expected_binding: ReceptionBinding,
    carriers: tuple[bytes, bytes],
) -> None:
    carrier = carriers[0]
    message = message_builder(carrier)
    with pytest.raises(UnicodeDecodeError) as exc_info:
        binding.from_structured(message, DecodingFailureFormat())

    exception = exc_info.value
    receipt = get_diagnostic_receipt(exception)
    assert receipt is not None
    assert receipt.binding == expected_binding
    assert receipt.content_mode == ContentMode.STRUCTURED
    assert receipt.failure_stage == FailureStage.CONTENT_DECODING
    assert receipt.raw_content_digest == digest_raw_content(carrier)
    assert receipt.exception_type == get_qualified_exception_name(exception)
    assert receipt.exception_type == "builtins.UnicodeDecodeError"
    # Receipts carry identifiers only, never the raw payload.
    assert carrier.decode("utf-8") not in repr(receipt)
    assert dataclasses.is_dataclass(receipt)


@pytest.mark.parametrize(
    "binding, message_builder, expected_binding",
    [
        (http, structured_http, ReceptionBinding.HTTP),
        (rabbitmq, structured_rabbitmq, ReceptionBinding.RABBITMQ),
    ],
)
def test_structured_construction_failure_keeps_exception_and_receipt(
    binding: Any,
    message_builder: Any,
    expected_binding: ReceptionBinding,
    carriers: tuple[bytes, bytes],
) -> None:
    carrier = carriers[1]
    message = message_builder(carrier)
    with pytest.raises(MissingRequiredAttributeError) as exc_info:
        binding.from_structured(message, ConstructionFailureFormat())

    exception = exc_info.value
    receipt = get_diagnostic_receipt(exception)
    assert receipt is not None
    assert receipt.binding == expected_binding
    assert receipt.content_mode == ContentMode.STRUCTURED
    assert receipt.failure_stage == FailureStage.EVENT_CONSTRUCTION
    assert receipt.raw_content_digest == digest_raw_content(carrier)
    assert (
        receipt.exception_type
        == "cloudevents.core.exceptions.MissingRequiredAttributeError"
    )
    assert exception.attribute_name == "source"


def binary_http(body: bytes) -> HTTPMessage:
    return HTTPMessage(
        headers={
            "ce-specversion": ATTRIBUTES["specversion"],
            "ce-id": ATTRIBUTES["id"],
            "ce-source": ATTRIBUTES["source"],
            "ce-type": ATTRIBUTES["type"],
            "ce-time": ATTRIBUTES["time"],
            "content-type": ATTRIBUTES["datacontenttype"],
        },
        body=body,
    )


def binary_rabbitmq(body: bytes) -> RabbitMQMessage:
    return RabbitMQMessage(
        headers={
            "ce-specversion": ATTRIBUTES["specversion"],
            "ce-id": ATTRIBUTES["id"],
            "ce-source": ATTRIBUTES["source"],
            "ce-type": ATTRIBUTES["type"],
            "ce-time": ATTRIBUTES["time"],
        },
        content_type=ATTRIBUTES["datacontenttype"],
        body=body,
    )


@pytest.mark.parametrize(
    "binding, message_builder, expected_binding",
    [
        (http, binary_http, ReceptionBinding.HTTP),
        (rabbitmq, binary_rabbitmq, ReceptionBinding.RABBITMQ),
    ],
)
def test_binary_decoding_failure_receipt(
    binding: Any,
    message_builder: Any,
    expected_binding: ReceptionBinding,
    carriers: tuple[bytes, bytes],
) -> None:
    carrier = carriers[0]
    message = message_builder(carrier)
    with pytest.raises(UnicodeDecodeError) as exc_info:
        binding.from_binary(message, DecodingFailureFormat(), CloudEvent)

    receipt = get_diagnostic_receipt(exc_info.value)
    assert receipt is not None
    assert receipt.binding == expected_binding
    assert receipt.content_mode == ContentMode.BINARY
    assert receipt.failure_stage == FailureStage.CONTENT_DECODING
    assert receipt.raw_content_digest == digest_raw_content(carrier)


@pytest.mark.parametrize(
    "binding, message_builder, expected_binding",
    [
        (http, binary_http, ReceptionBinding.HTTP),
        (rabbitmq, binary_rabbitmq, ReceptionBinding.RABBITMQ),
    ],
)
def test_binary_construction_failure_receipt(
    binding: Any,
    message_builder: Any,
    expected_binding: ReceptionBinding,
    carriers: tuple[bytes, bytes],
) -> None:
    carrier = carriers[1]
    message = message_builder(carrier)
    with pytest.raises(MissingRequiredAttributeError) as exc_info:
        binding.from_binary(
            message, JSONFormat(), event_factory=failing_event_factory
        )

    receipt = get_diagnostic_receipt(exc_info.value)
    assert receipt is not None
    assert receipt.binding == expected_binding
    assert receipt.content_mode == ContentMode.BINARY
    assert receipt.failure_stage == FailureStage.EVENT_CONSTRUCTION
    assert receipt.raw_content_digest == digest_raw_content(carrier)


def test_interleaved_failures_distinguish_binding_mode_digest_and_stage(
    carriers: tuple[bytes, bytes],
) -> None:
    """
    Drive the two carriers over both transports while interleaving the two
    failure kinds, then compare the collected receipts.
    """
    carrier_a, carrier_b = carriers
    collected: list[DiagnosticReceipt] = []

    cases = [
        # HTTP gets carrier A; decoding fails in binary mode
        (
            http.from_binary,
            binary_http(carrier_a),
            DecodingFailureFormat(),
            CloudEvent,
        ),
        # RabbitMQ gets carrier B; construction fails in binary mode
        (
            rabbitmq.from_binary,
            binary_rabbitmq(carrier_b),
            JSONFormat(),
            failing_event_factory,
        ),
        # HTTP gets carrier B; decoding fails in structured mode
        (
            http.from_structured,
            structured_http(carrier_b),
            DecodingFailureFormat(),
            None,
        ),
        # RabbitMQ gets carrier A; construction fails in structured mode
        (
            rabbitmq.from_structured,
            structured_rabbitmq(carrier_a),
            ConstructionFailureFormat(),
            None,
        ),
    ]

    expected = [
        (
            ReceptionBinding.HTTP,
            ContentMode.BINARY,
            FailureStage.CONTENT_DECODING,
            digest_raw_content(carrier_a),
        ),
        (
            ReceptionBinding.RABBITMQ,
            ContentMode.BINARY,
            FailureStage.EVENT_CONSTRUCTION,
            digest_raw_content(carrier_b),
        ),
        (
            ReceptionBinding.HTTP,
            ContentMode.STRUCTURED,
            FailureStage.CONTENT_DECODING,
            digest_raw_content(carrier_b),
        ),
        (
            ReceptionBinding.RABBITMQ,
            ContentMode.STRUCTURED,
            FailureStage.EVENT_CONSTRUCTION,
            digest_raw_content(carrier_a),
        ),
    ]

    for case, expectation in zip(cases, expected):
        receiver, message, event_format, factory = case
        with pytest.raises(Exception) as exc_info:
            if factory is None:
                receiver(message, event_format)
            else:
                receiver(message, event_format, factory)
        receipt = get_diagnostic_receipt(exc_info.value)
        assert receipt is not None
        assert (
            receipt.binding,
            receipt.content_mode,
            receipt.failure_stage,
            receipt.raw_content_digest,
        ) == expectation
        collected.append(receipt)

    # The same raw bytes produce the same digest across the two bindings ...
    assert collected[0].raw_content_digest == collected[3].raw_content_digest
    assert collected[1].raw_content_digest == collected[2].raw_content_digest
    # ... while the two encodings remain distinguishable.
    assert (
        collected[0].raw_content_digest != collected[1].raw_content_digest
    )
    # Binding and mode stay distinguishable even for identical raw bytes.
    assert collected[0].binding != collected[3].binding
    assert collected[0].content_mode != collected[3].content_mode
    assert collected[1].binding != collected[2].binding
    assert collected[1].content_mode != collected[2].content_mode


def test_exception_taxonomy_is_preserved_for_both_failure_kinds(
    carriers: tuple[bytes, bytes],
) -> None:
    carrier_a, carrier_b = carriers

    with pytest.raises(UnicodeDecodeError):
        http.from_structured(structured_http(carrier_a), DecodingFailureFormat())

    with pytest.raises(MissingRequiredAttributeError) as missing:
        rabbitmq.from_binary(
            binary_rabbitmq(carrier_b),
            JSONFormat(),
            event_factory=failing_event_factory,
        )
    assert isinstance(missing.value, ValueError)
    assert isinstance(missing.value, MissingRequiredAttributeError)

    # A natural structured-mode JSON syntax error keeps its original type.
    malformed = b'{"specversion": "1.0", "broken"'
    with pytest.raises(JSONDecodeError) as json_error:
        rabbitmq.from_structured_event(structured_rabbitmq(malformed))
    receipt = get_diagnostic_receipt(json_error.value)
    assert receipt is not None
    assert receipt.failure_stage == FailureStage.CONTENT_DECODING
    assert receipt.exception_type == "json.decoder.JSONDecodeError"

    # A natural structured-mode validation error keeps its original type.
    invalid_envelope = b'{"specversion": "1.0", "id": "only-id"}'
    with pytest.raises(CloudEventValidationError) as validation_error:
        http.from_structured_event(structured_http(invalid_envelope))
    receipt = get_diagnostic_receipt(validation_error.value)
    assert receipt is not None
    assert receipt.failure_stage == FailureStage.EVENT_CONSTRUCTION
    assert receipt.exception_type == (
        "cloudevents.core.exceptions.CloudEventValidationError"
    )


def test_successful_reception_has_no_residual_diagnostics(
    carriers: tuple[bytes, bytes],
) -> None:
    carrier_a, carrier_b = carriers

    # Produce failures first so any shared state would have a chance to leak.
    with pytest.raises(UnicodeDecodeError):
        http.from_structured(structured_http(carrier_a), DecodingFailureFormat())
    with pytest.raises(MissingRequiredAttributeError):
        rabbitmq.from_binary(
            binary_rabbitmq(carrier_b),
            JSONFormat(),
            event_factory=failing_event_factory,
        )

    # Structured success over both transports.
    http_event = http.from_structured_event(structured_http(carrier_a))
    rabbit_event = rabbitmq.from_structured_event(
        structured_rabbitmq(carrier_b)
    )
    assert_same_event(http_event, rabbit_event)
    assert get_diagnostic_receipt(http_event) is None
    assert get_diagnostic_receipt(rabbit_event) is None

    # Binary success over both transports.
    http_binary_event = http.from_binary_event(binary_http(carrier_a))
    rabbit_binary_event = rabbitmq.from_binary_event(binary_rabbitmq(carrier_b))
    assert_same_event(http_binary_event, rabbit_binary_event)
    assert get_diagnostic_receipt(http_binary_event) is None
    assert get_diagnostic_receipt(rabbit_binary_event) is None

    # Auto-detecting entry points likewise return clean events.
    assert get_diagnostic_receipt(
        http.from_http_event(structured_http(carrier_a))
    ) is None
    assert get_diagnostic_receipt(
        rabbitmq.from_rabbitmq_event(binary_rabbitmq(carrier_b))
    ) is None


def test_auto_detecting_entry_points_attach_receipts(
    carriers: tuple[bytes, bytes],
) -> None:
    carrier_a, carrier_b = carriers

    with pytest.raises(UnicodeDecodeError) as http_error:
        http.from_http(structured_http(carrier_a), DecodingFailureFormat())
    receipt = get_diagnostic_receipt(http_error.value)
    assert receipt is not None
    assert receipt.binding == ReceptionBinding.HTTP
    assert receipt.content_mode == ContentMode.STRUCTURED

    with pytest.raises(MissingRequiredAttributeError) as rabbit_error:
        rabbitmq.from_rabbitmq(
            binary_rabbitmq(carrier_b),
            JSONFormat(),
            event_factory=failing_event_factory,
        )
    receipt = get_diagnostic_receipt(rabbit_error.value)
    assert receipt is not None
    assert receipt.binding == ReceptionBinding.RABBITMQ
    assert receipt.content_mode == ContentMode.BINARY


def test_receipt_is_frozen_and_holds_no_payload(carriers: tuple[bytes, bytes]) -> None:
    carrier_a, _ = carriers
    with pytest.raises(UnicodeDecodeError) as exc_info:
        http.from_structured(structured_http(carrier_a), DecodingFailureFormat())
    receipt = get_diagnostic_receipt(exc_info.value)
    assert receipt is not None
    with pytest.raises(dataclasses.FrozenInstanceError):
        receipt.failure_stage = FailureStage.EVENT_CONSTRUCTION  # type: ignore[misc]
    assert PAYLOAD["status"] not in str(receipt)


def test_existing_receipt_is_not_overwritten() -> None:
    """Nested reception wrappers preserve the innermost receipt."""
    carrier = b'{"specversion": "1.0"}'
    with pytest.raises(UnicodeDecodeError) as exc_info:
        http.from_structured(structured_http(carrier), DecodingFailureFormat())
    first_receipt = get_diagnostic_receipt(exc_info.value)
    assert first_receipt is not None

    # Re-entering a reception wrapper with the same exception-like failure
    # must not replace an already attached receipt.
    with pytest.raises(UnicodeDecodeError) as nested:
        with diagnostic_receipt(
            binding=ReceptionBinding.RABBITMQ,
            content_mode=ContentMode.STRUCTURED,
            raw_content=carrier,
            default_stage=FailureStage.EVENT_CONSTRUCTION,
        ):
            raise exc_info.value
    assert get_diagnostic_receipt(nested.value) is first_receipt
    assert nested.value is exc_info.value
