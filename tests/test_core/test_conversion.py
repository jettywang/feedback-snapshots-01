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

import json
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

import pytest
from cloudevents.core.base import BaseCloudEvent, EventFactory
from cloudevents.core.bindings import amqp
from cloudevents.core.conversion import (
    AMQP_BINARY_BINDING,
    HTTP_BINARY_BINDING,
    BinaryBinding,
    convert_structured,
    convert_structured_to_binary,
)
from cloudevents.core.exceptions import ConversionStage, StrictConversionError
from cloudevents.core.formats.json import JSONFormat
from cloudevents.core.v1.event import CloudEvent

EVENT_TIME = datetime(2026, 1, 2, 3, 4, 5, 123000, tzinfo=timezone.utc)

# A small event carrying a registered Binary extension ("blob"), an unknown
# string extension ("mystery") and a timestamp, so the two exits disagree on
# what they can express.
EVENT_JSON = json.dumps(
    {
        "specversion": "1.0",
        "id": "relay-1",
        "source": "/relay",
        "type": "com.example.relay",
        "time": "2026-01-02T03:04:05.123Z",
        "datacontenttype": "application/json",
        "blob": "aGVsbG8=",
        "mystery": "kept-as-string",
        "data": {"msg": "hi"},
    }
).encode("utf-8")

EXTENSION_TYPES = {"blob": bytes}


class RecordingFormat:
    """Format implementation recording every callback the conversion makes."""

    def __init__(self) -> None:
        self._delegate = JSONFormat()
        self.calls: list[str] = []

    def read(
        self, event_factory: EventFactory | None, data: str | bytes
    ) -> BaseCloudEvent:
        self.calls.append("read")
        return self._delegate.read(event_factory, data)

    def write(self, event: BaseCloudEvent) -> bytes:
        self.calls.append("write")
        return self._delegate.write(event)

    def write_data(
        self,
        data: dict[str, Any] | str | bytes | None,
        datacontenttype: str | None,
    ) -> bytes:
        self.calls.append("write_data")
        return self._delegate.write_data(data, datacontenttype)

    def read_data(
        self, body: bytes, datacontenttype: str | None
    ) -> dict[str, Any] | str | bytes | None:
        self.calls.append("read_data")
        return self._delegate.read_data(body, datacontenttype)

    def get_content_type(self) -> str:
        return self._delegate.get_content_type()


def recording_binding(binding: BinaryBinding, calls: list[str]) -> BinaryBinding:
    """Wrap a binding's message factory so invocations are recorded."""

    def to_binary(event: BaseCloudEvent, event_format: Any) -> Any:
        calls.append(binding.name)
        return binding.to_binary(event, event_format)

    return replace(binding, to_binary=to_binary)


def test_interleaved_exits_share_one_decode_and_diverge() -> None:
    event_format = RecordingFormat()
    factory_calls: list[str] = []
    exits = [
        recording_binding(AMQP_BINARY_BINDING, factory_calls),
        recording_binding(HTTP_BINARY_BINDING, factory_calls),
    ]

    # Same small event, both exits validated in interleaved orderings.
    passes = [
        convert_structured(EVENT_JSON, event_format, order, None, EXTENSION_TYPES)
        for order in (exits, list(reversed(exits)))
    ]

    # The compatible event is decoded once per relay pass, not once per exit.
    assert event_format.calls.count("read") == 2
    # The format's data callbacks feed the shared validation plus each
    # successful message factory.
    assert event_format.calls.count("write_data") == 4
    assert event_format.calls.count("read_data") == 2

    # Only the AMQP exit ever produced a message; the rejected HTTP exit has
    # no partial message to publish.
    assert factory_calls == ["amqp", "amqp"]

    for results in passes:
        by_binding = {result.binding: result for result in results}
        amqp_result = by_binding["amqp"]
        http_result = by_binding["http"]

        assert amqp_result.error is None
        assert isinstance(amqp_result.message, amqp.AMQPMessage)

        assert http_result.message is None
        assert http_result.error is not None
        assert http_result.error.attribute_name == "blob"
        assert http_result.error.stage == ConversionStage.ATTRIBUTE

    # The legal exit round-trips back to the original semantics: timestamp,
    # binary extension and unknown string extension are all preserved.
    amqp_message = {r.binding: r for r in passes[0]}["amqp"].message
    assert isinstance(amqp_message, amqp.AMQPMessage)
    restored = amqp.from_binary(amqp_message, JSONFormat(), CloudEvent)
    assert restored.get_time() == EVENT_TIME
    assert restored.get_extension("blob") == b"hello"
    assert restored.get_extension("mystery") == "kept-as-string"
    assert restored.get_data() == {"msg": "hi"}


def test_single_exit_conversion_returns_message_or_raises() -> None:
    message = convert_structured_to_binary(
        EVENT_JSON, JSONFormat(), AMQP_BINARY_BINDING, None, EXTENSION_TYPES
    )
    assert isinstance(message, amqp.AMQPMessage)

    with pytest.raises(StrictConversionError) as exc_info:
        convert_structured_to_binary(
            EVENT_JSON, JSONFormat(), HTTP_BINARY_BINDING, None, EXTENSION_TYPES
        )
    assert exc_info.value.attribute_name == "blob"
    assert exc_info.value.stage == ConversionStage.ATTRIBUTE


def test_unregistered_extensions_keep_their_json_types() -> None:
    # Without a registry entry "blob" stays a base64 string, which every exit
    # can express, so both conversions succeed.
    results = convert_structured(
        EVENT_JSON,
        JSONFormat(),
        [AMQP_BINARY_BINDING, HTTP_BINARY_BINDING],
    )
    assert all(result.error is None for result in results)
    message = results[0].message
    assert isinstance(message, amqp.AMQPMessage)
    restored = amqp.from_binary(message, JSONFormat(), CloudEvent)
    assert restored.get_extension("blob") == "aGVsbG8="


def test_decode_stage_reports_attribute_from_version_validation() -> None:
    invalid = json.dumps(
        {
            "specversion": "1.0",
            "id": "relay-2",
            "type": "com.example.relay",
        }
    ).encode("utf-8")

    with pytest.raises(StrictConversionError) as exc_info:
        convert_structured(invalid, JSONFormat(), [AMQP_BINARY_BINDING])
    assert exc_info.value.stage == ConversionStage.DECODE
    assert exc_info.value.attribute_name == "source"


def test_decode_stage_reports_uninterpretable_registered_extension() -> None:
    broken = json.dumps(
        {
            "specversion": "1.0",
            "id": "relay-3",
            "source": "/relay",
            "type": "com.example.relay",
            "blob": "!!!not-base64!!!",
        }
    ).encode("utf-8")

    with pytest.raises(StrictConversionError) as exc_info:
        convert_structured(
            broken, JSONFormat(), [AMQP_BINARY_BINDING], None, EXTENSION_TYPES
        )
    assert exc_info.value.stage == ConversionStage.DECODE
    assert exc_info.value.attribute_name == "blob"


def test_data_stage_validates_format_callback_output() -> None:
    class StringBodyFormat(JSONFormat):
        def write_data(self, data: Any, datacontenttype: Any) -> Any:
            return "not-bytes"

    factory_calls: list[str] = []
    binding = recording_binding(AMQP_BINARY_BINDING, factory_calls)

    with pytest.raises(StrictConversionError) as exc_info:
        convert_structured(EVENT_JSON, StringBodyFormat(), [binding])
    assert exc_info.value.stage == ConversionStage.DATA
    assert exc_info.value.attribute_name == "data"
    assert factory_calls == []


def test_v03_input_is_validated_by_its_own_version() -> None:
    v03_event = json.dumps(
        {
            "specversion": "0.3",
            "id": "relay-4",
            "source": "/relay",
            "type": "com.example.relay",
            "time": "2026-01-02T03:04:05.123Z",
            "mystery": "kept-as-string",
        }
    ).encode("utf-8")

    (result,) = convert_structured(v03_event, JSONFormat(), [AMQP_BINARY_BINDING])
    assert result.error is None
    assert isinstance(result.message, amqp.AMQPMessage)

    restored = amqp.from_binary(result.message, JSONFormat())
    assert restored.get_specversion() == "0.3"
    assert restored.get_time() == EVENT_TIME
    assert restored.get_extension("mystery") == "kept-as-string"
