#  Copyright 2018-Present The CloudEvents Authors
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from __future__ import annotations

import threading
from typing import Any

import pytest
from cloudevents.core.admission import (
    AdmissionDeniedError,
    MemorySink,
    ReceiveContext,
)
from cloudevents.core.bindings.amqp import from_amqp
from cloudevents.core.bindings.amqp import to_binary as amqp_binary
from cloudevents.core.bindings.http import from_http
from cloudevents.core.bindings.http import to_structured as http_structured
from cloudevents.core.formats.json import JSONFormat
from cloudevents.core.receiver import receive_amqp, receive_http
from cloudevents.core.v1.event import CloudEvent

SOURCE_A = "https://partner-a.example/events/42"
SOURCE_B = "https://partner-b.example/events/7"


class ObservingJSONFormat(JSONFormat):
    def __init__(self) -> None:
        super().__init__()
        self.read_calls = 0
        self.read_data_calls = 0
        self.on_read: Any = None
        self.on_read_data: Any = None

    @property
    def decode_calls(self) -> int:
        return self.read_calls + self.read_data_calls

    def read(self, event_factory: Any | None, data: str | bytes) -> Any:
        self.read_calls += 1
        if self.on_read is not None:
            self.on_read("read")
        return super().read(event_factory, data)

    def read_data(
        self, body: bytes, datacontenttype: str | None
    ) -> dict[str, Any] | str | bytes | None:
        self.read_data_calls += 1
        if self.on_read_data is not None:
            self.on_read_data("read_data")
        return super().read_data(body, datacontenttype)


def make_event(source: str, event_id: str) -> CloudEvent:
    return CloudEvent(
        {
            "specversion": "1.0",
            "type": "com.example.partner.event",
            "source": source,
            "id": event_id,
            "connection": "event-claim-not-connection-owner",
            "datacontenttype": "application/json",
        },
        {"ok": True, "id": event_id},
    )


def make_policy(grants: dict[str, set[str]]) -> Any:
    calls: list[tuple[Any, str | None]] = []

    def admit(context: ReceiveContext, event: CloudEvent) -> bool:
        source = event.get_source()
        calls.append((context.connection_id, source))
        return source in grants.get(context.connection_id, set())

    admit.calls = calls  # type: ignore[attr-defined]
    return admit


def test_revocation_during_structured_decode_blocks_delivery_after_decode() -> None:
    grants = {
        "http-partner": {SOURCE_A},
        "amqp-partner": {SOURCE_B},
    }
    policy = make_policy(grants)

    http_format = ObservingJSONFormat()
    decode_entered = threading.Event()
    release_decode = threading.Event()

    def wait_in_decode(_stage: str) -> None:
        decode_entered.set()
        assert release_decode.wait(5), "timed out waiting for test revocation"

    http_format.on_read = wait_in_decode

    amqp_format = ObservingJSONFormat()
    http_sink = MemorySink()
    amqp_sink = MemorySink()
    http_context = ReceiveContext("http-partner", protocol="http")
    amqp_context = ReceiveContext("amqp-partner", protocol="amqp")

    http_message = http_structured(make_event(SOURCE_A, "structured-1"), http_format)
    amqp_message = amqp_binary(make_event(SOURCE_B, "binary-1"), amqp_format)

    outcome: dict[str, Any] = {}

    def receive_blocked_message() -> None:
        outcome["result"] = receive_http(
            http_message,
            http_format,
            context=http_context,
            admission=policy,
            sink=http_sink,
        )

    worker = threading.Thread(target=receive_blocked_message)
    worker.start()

    try:
        assert decode_entered.wait(2), "structured decode callback did not start"

        # The other connection remains independently admissible while partner A
        # is parked inside its decoder.
        allowed = receive_amqp(
            amqp_message,
            amqp_format,
            context=amqp_context,
            admission=policy,
            sink=amqp_sink,
        )
        assert allowed.accepted is True
        assert allowed.delivered is True
        assert allowed.stage == "delivered"
        assert allowed.decode_calls == 1
        assert amqp_sink.delivery_count == 1
        delivered_event = amqp_sink.events[0]
        assert delivered_event.get_source() == SOURCE_B
        assert (
            delivered_event.get_extension("connection")
            == "event-claim-not-connection-owner"
        )
        assert amqp_format.read_data_calls == 1
        assert amqp_format.read_calls == 0
        assert amqp_format.decode_calls == 1

        # Revocation lands while A's decode callback is waiting. The decoder was
        # selected and entered once; admission must observe the new grant table.
        grants.pop("http-partner")
    finally:
        release_decode.set()
        worker.join(5)

    assert not worker.is_alive(), "blocked receive worker did not finish"
    denied = outcome["result"]

    assert denied.accepted is False
    assert denied.delivered is False
    assert denied.stage == "source_admission"
    assert denied.stage == "admission"
    assert denied.decode_calls == 1
    assert isinstance(denied.error, AdmissionDeniedError)
    assert denied.error.stage == "source_admission"
    assert denied.error.stage == "policy"
    assert denied.source == SOURCE_A
    assert denied.connection_id == "http-partner"

    # Decoding happened exactly once, but the application sink saw no delivery.
    assert http_format.read_calls == 1
    assert http_format.read_data_calls == 0
    assert http_format.decode_calls == 1
    assert http_sink.delivery_count == 0
    assert http_sink.events == []

    # Policy was evaluated after decode with both transport context and source.
    assert policy.calls == [  # type: ignore[attr-defined]
        ("amqp-partner", SOURCE_B),
        ("http-partner", SOURCE_A),
    ]


def test_from_http_raises_denied_receipt_at_admission_stage() -> None:
    format_ = ObservingJSONFormat()
    message = http_structured(make_event(SOURCE_A, "structured-2"), format_)
    context = ReceiveContext("revoked-http", protocol="http")

    with pytest.raises(AdmissionDeniedError) as exc_info:
        from_http(
            message,
            format_,
            context=context,
            admission=lambda ctx, event: False,
        )

    assert exc_info.value.stage == "admission"
    assert exc_info.value.receive_result.delivered is False
    assert format_.decode_calls == 1


def test_from_amqp_keyword_policy_denies_before_sink_and_keeps_extensions() -> None:
    format_ = ObservingJSONFormat()
    sink = MemorySink()
    message = amqp_binary(make_event(SOURCE_B, "binary-2"), format_)

    with pytest.raises(AdmissionDeniedError) as exc_info:
        from_amqp(
            message,
            format_,
            context={"connection_id": "revoked-amqp", "protocol": "amqp"},
            policy=lambda context, source: source == "wrong",
            sink=sink,
        )

    assert exc_info.value.stage == "source_admission"
    assert sink.delivery_count == 0
    assert format_.decode_calls == 1


def test_same_source_is_bound_to_transport_connection_not_extension() -> None:
    format_ = ObservingJSONFormat()
    message = http_structured(make_event(SOURCE_A, "same-source"), format_)
    approved_sink = MemorySink()
    rejected_sink = MemorySink()

    def policy(context: ReceiveContext, event: CloudEvent) -> bool:
        return context.connection_id == "pinned-partner"

    approved = receive_http(
        message,
        format_,
        context=ReceiveContext("pinned-partner", protocol="http"),
        admission=policy,
        sink=approved_sink,
    )
    rejected = receive_http(
        message,
        format_,
        context=ReceiveContext("other-partner", protocol="http"),
        admission=policy,
        sink=rejected_sink,
    )

    assert approved.delivered is True
    assert rejected.accepted is False
    assert rejected.stage == "policy"
    assert approved_sink.delivery_count == 1
    assert rejected_sink.delivery_count == 0
    assert (
        approved.event.get_extension("connection") == "event-claim-not-connection-owner"
    )
    assert rejected.event is not None
    assert (
        rejected.event.get_extension("connection") == "event-claim-not-connection-owner"
    )
