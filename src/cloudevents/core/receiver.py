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

"""High-level receive pipeline with optional source admission."""

from __future__ import annotations

from typing import Any, cast

from cloudevents.core.admission import (
    AdmissionContext,
    AdmissionDecision,
    AdmissionDeniedError,
    ConnectionContext,
    ConnectionSourcePolicy,
    MemorySink,
    ReceiveContext,
    ReceiveResult,
    normalize_reception_call,
)
from cloudevents.core.bindings import amqp as amqp_bindings
from cloudevents.core.bindings import http as http_bindings
from cloudevents.core.bindings.amqp import AMQPMessage
from cloudevents.core.bindings.http import HTTPMessage
from cloudevents.core.formats.json import JSONFormat


def _as_result(value: Any) -> ReceiveResult:
    if isinstance(value, ReceiveResult):
        return value
    # Defensive fallback; receive_* always requests a result from the bindings.
    return ReceiveResult(
        accepted=True,
        delivered=False,
        stage="delivered",
        event=value,
    )


def receive_http(
    message: HTTPMessage,
    event_format: Any = None,
    event_factory: Any = None,
    *extra_args: Any,
    raise_on_denied: bool = False,
    **options: Any,
) -> ReceiveResult:
    """Receive one HTTP message and return an observable result."""
    event_format, event_factory, options = normalize_reception_call(
        event_format, event_factory, extra_args, options
    )
    options.setdefault("return_result", True)
    options["raise_on_denied"] = raise_on_denied
    if event_format is None:
        event_format = JSONFormat()
    return _as_result(
        http_bindings.from_http(message, event_format, event_factory, **options)
    )


def receive_amqp(
    message: AMQPMessage,
    event_format: Any = None,
    event_factory: Any = None,
    *extra_args: Any,
    raise_on_denied: bool = False,
    **options: Any,
) -> ReceiveResult:
    """Receive one AMQP message and return an observable result."""
    event_format, event_factory, options = normalize_reception_call(
        event_format, event_factory, extra_args, options
    )
    options.setdefault("return_result", True)
    options["raise_on_denied"] = raise_on_denied
    if event_format is None:
        event_format = JSONFormat()
    return _as_result(
        amqp_bindings.from_amqp(message, event_format, event_factory, **options)
    )


def receive(
    message: HTTPMessage | AMQPMessage | Any,
    event_format: Any = None,
    event_factory: Any = None,
    *extra_args: Any,
    protocol: str | None = None,
    raise_on_denied: bool = False,
    **options: Any,
) -> ReceiveResult:
    """Receive a message, inferring HTTP vs AMQP from its type when possible."""
    selected_protocol = (protocol or options.pop("transport", None) or "").lower()

    if isinstance(message, HTTPMessage) or selected_protocol in {"http", "https"}:
        return receive_http(
            message,
            event_format,
            event_factory,
            *extra_args,
            raise_on_denied=raise_on_denied,
            **options,
        )
    if isinstance(message, AMQPMessage) or selected_protocol in {"amqp", "amqps"}:
        return receive_amqp(
            message,
            event_format,
            event_factory,
            *extra_args,
            raise_on_denied=raise_on_denied,
            **options,
        )

    if hasattr(message, "application_data") and hasattr(
        message, "application_properties"
    ):
        return receive_amqp(
            message,
            event_format,
            event_factory,
            *extra_args,
            raise_on_denied=raise_on_denied,
            **options,
        )
    if hasattr(message, "headers") and hasattr(message, "body"):
        return receive_http(
            message,
            event_format,
            event_factory,
            *extra_args,
            raise_on_denied=raise_on_denied,
            **options,
        )

    raise TypeError(
        "Unable to infer binding protocol; pass protocol='http' or protocol='amqp'"
    )


class Receiver:
    """Configured receiver for one host application/sink."""

    def __init__(
        self,
        *positional: Any,
        protocol: str | None = None,
        admission: Any = None,
        policy: Any = None,
        source_admission: Any = None,
        sink: Any = None,
        context: Any = None,
        connection: Any = None,
        event_format: Any = None,
        format: Any = None,
        event_factory: Any = None,
        raise_on_denied: bool = False,
        **defaults: Any,
    ) -> None:
        positional_format, positional_factory, positional_options = (
            normalize_reception_call(None, None, positional, {})
        )
        self.protocol = protocol
        self.admission = (
            admission or source_admission or policy or positional_options.get("policy")
        )
        self.sink = sink or positional_options.get("sink")
        self.context = context or positional_options.get("context")
        self.connection = connection
        self.event_format = event_format or format or positional_format
        self.event_factory = event_factory or positional_factory
        self.raise_on_denied = raise_on_denied
        for key in ("policy", "context", "sink"):
            positional_options.pop(key, None)
        self.defaults = {**positional_options, **defaults}

    def receive(
        self,
        message: Any,
        event_format: Any = None,
        *,
        context: Any = None,
        connection: Any = None,
        admission: Any = None,
        policy: Any = None,
        sink: Any = None,
        protocol: str | None = None,
        raise_on_denied: bool | None = None,
        **options: Any,
    ) -> ReceiveResult:
        event_factory = options.pop(
            "event_factory", options.pop("factory", self.event_factory)
        )
        merged: dict[str, Any] = dict(self.defaults)
        merged.update(options)
        merged.update(
            {
                "context": context if context is not None else self.context,
                "connection": connection if connection is not None else self.connection,
                "admission": admission
                if admission is not None
                else (policy if policy is not None else self.admission),
                "sink": sink if sink is not None else self.sink,
            }
        )
        return receive(
            message,
            event_format or self.event_format,
            event_factory,
            protocol=protocol or self.protocol,
            raise_on_denied=(
                self.raise_on_denied if raise_on_denied is None else raise_on_denied
            ),
            **merged,
        )

    def receive_http(self, message: Any, *args: Any, **kwargs: Any) -> ReceiveResult:
        kwargs.setdefault("protocol", "http")
        return self.receive(message, *args, **kwargs)

    def receive_event(self, message: Any, *args: Any, **kwargs: Any) -> ReceiveResult:
        return self.receive(message, *args, **kwargs)

    def __call__(self, message: Any, *args: Any, **kwargs: Any) -> ReceiveResult:
        return self.receive(message, *args, **kwargs)

    def receive_amqp(self, message: Any, *args: Any, **kwargs: Any) -> ReceiveResult:
        kwargs.setdefault("protocol", "amqp")
        return self.receive(message, *args, **kwargs)

    def receive_http_message(
        self, message: Any, *args: Any, **kwargs: Any
    ) -> ReceiveResult:
        kwargs.setdefault("protocol", "http")
        return self.receive(message, *args, **kwargs)


EventReceiver = Receiver
CloudEventReceiver = Receiver
CloudEventsReceiver = Receiver
SourceAdmissionReceiver = Receiver
AdmissionReceiver = Receiver
EventHubReceiver = Receiver
ReceivePipeline = Receiver
ReceptionPipeline = Receiver

receive_event = receive
receive_message = receive
accept_event = receive
receive_cloud_event = receive
receive_http_event = receive_http
receive_amqp_event = receive_amqp


class InMemoryReceiver(Receiver):
    """Receiver with a built-in thread-safe :class:`MemorySink`."""

    def __init__(self, *args: Any, sink: Any = None, **kwargs: Any) -> None:
        self.memory_sink: Any = sink if sink is not None else MemorySink()
        super().__init__(*args, sink=self.memory_sink, **kwargs)
        self.results: list[ReceiveResult] = []

    def receive(self, *args: Any, **kwargs: Any) -> ReceiveResult:
        result = super().receive(*args, **kwargs)
        self.results.append(result)
        return result

    @property
    def events(self) -> list[Any]:
        return cast(list[Any], self.memory_sink.events)

    @property
    def received_events(self) -> list[Any]:
        return cast(list[Any], self.memory_sink.events)

    @property
    def messages(self) -> list[Any]:
        return cast(list[Any], self.memory_sink.events)

    @property
    def deliveries(self) -> list[Any]:
        return cast(list[Any], self.memory_sink.deliveries)

    @property
    def delivery_count(self) -> int:
        return int(getattr(self.memory_sink, "delivery_count", len(self.deliveries)))

    @property
    def count(self) -> int:
        return self.delivery_count


MemoryReceiver = InMemoryReceiver
InMemoryEventReceiver = InMemoryReceiver
MemoryEventReceiver = InMemoryReceiver


__all__ = [
    "AdmissionContext",
    "AdmissionDecision",
    "AdmissionDeniedError",
    "AdmissionReceiver",
    "CloudEventReceiver",
    "CloudEventsReceiver",
    "ConnectionContext",
    "ConnectionSourcePolicy",
    "EventReceiver",
    "EventHubReceiver",
    "InMemoryReceiver",
    "MemoryReceiver",
    "MemorySink",
    "ReceiveContext",
    "ReceivePipeline",
    "ReceiveResult",
    "Receiver",
    "ReceptionPipeline",
    "SourceAdmissionReceiver",
    "accept_event",
    "receive",
    "receive_amqp",
    "receive_amqp_event",
    "receive_cloud_event",
    "receive_event",
    "receive_http",
    "receive_http_event",
    "receive_message",
]
