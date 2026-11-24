"""High-level, decision-returning receivers for HTTP and Kafka."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, TypeAlias

from cloudevents.core.base import EventFactory
from cloudevents.core.bindings import http as http_binding
from cloudevents.core.bindings import kafka as kafka_binding
from cloudevents.core.bindings.common import CONTENT_TYPE_HEADER
from cloudevents.core.decision import (
    Binding,
    ReceiveDecision,
)
from cloudevents.core.formats.base import Format
from cloudevents.core.formats.json import JSONFormat
from cloudevents.core.formats.registry import FormatRegistry

EventHandler = Callable[..., Any]
RegistryLike: TypeAlias = FormatRegistry | Mapping[str, Format] | None


def _header_content_type(message: Any) -> str | None:
    headers = getattr(message, "headers", {})
    for header_name, header_value in headers.items():
        normalized_name = (
            header_name.decode("utf-8").lower()
            if isinstance(header_name, bytes)
            else str(header_name).lower()
        )
        if normalized_name != CONTENT_TYPE_HEADER:
            continue
        if isinstance(header_value, bytes):
            return header_value.decode("utf-8")
        return str(header_value)
    return None


def _resolve_format(
    message: Any,
    event_format: Format | str | None,
    registry: RegistryLike,
) -> Format:
    content_type = _header_content_type(message)

    format_name: str | None = None
    if isinstance(event_format, str):
        format_name = event_format
        event_format = None

    if event_format is not None:
        return event_format

    formats = FormatRegistry.coerce(registry)
    selected_type = format_name or content_type
    selected = formats.get(selected_type)
    return selected if selected is not None else JSONFormat()


def _make_decision(
    binding: str,
    decision: ReceiveDecision | None,
    receipt: ReceiveDecision | None,
    decision_id: str | None,
    idempotency_key: str | None,
    observer: ReceiveDecision | None = None,
    recorder: ReceiveDecision | None = None,
) -> ReceiveDecision:
    result = decision or receipt or observer or recorder or ReceiveDecision()
    result.binding = binding
    if decision_id is not None:
        result.decision_id = decision_id
    if idempotency_key is not None:
        result.idempotency_key = idempotency_key
    elif result.idempotency_key is None:
        result.idempotency_key = result.decision_id
    return result


def receive_http(
    message: http_binding.HTTPMessage,
    event_format: Format | str | None = None,
    event_factory: EventFactory | None = None,
    *,
    registry: RegistryLike = None,
    formats: RegistryLike = None,
    handler: EventHandler | None = None,
    on_event: EventHandler | None = None,
    decision: ReceiveDecision | None = None,
    receipt: ReceiveDecision | None = None,
    observer: ReceiveDecision | None = None,
    recorder: ReceiveDecision | None = None,
    decision_id: str | None = None,
    idempotency_key: str | None = None,
    raise_on_error: bool = False,
) -> ReceiveDecision:
    """Receive one HTTP message and return its complete decision/receipt."""

    observer = _make_decision(
        Binding.HTTP,
        decision,
        receipt,
        decision_id,
        idempotency_key,
        observer,
        recorder,
    )
    selected_format = _resolve_format(
        message, event_format, registry if registry is not None else formats
    )
    observer.content_type = _header_content_type(message)

    try:
        event = http_binding.from_http(
            message,
            selected_format,
            event_factory,
            decision=observer,
        )
    except Exception as exc:
        observer.fail(exc)
        if raise_on_error:
            raise
        return observer

    observer.event = event
    event_handler = handler or on_event
    if event_handler is not None:
        try:
            observer.deliver_to(event_handler)
        except Exception:
            if raise_on_error:
                raise
    return observer


def receive_kafka(
    message: kafka_binding.KafkaMessage,
    event_format: Format | str | None = None,
    event_factory: EventFactory | None = None,
    *,
    registry: RegistryLike = None,
    formats: RegistryLike = None,
    handler: EventHandler | None = None,
    on_event: EventHandler | None = None,
    decision: ReceiveDecision | None = None,
    receipt: ReceiveDecision | None = None,
    observer: ReceiveDecision | None = None,
    recorder: ReceiveDecision | None = None,
    decision_id: str | None = None,
    idempotency_key: str | None = None,
    raise_on_error: bool = False,
) -> ReceiveDecision:
    """Receive one Kafka message and return its complete decision/receipt."""

    observer = _make_decision(
        Binding.KAFKA,
        decision,
        receipt,
        decision_id,
        idempotency_key,
        observer,
        recorder,
    )
    selected_format = _resolve_format(
        message, event_format, registry if registry is not None else formats
    )
    observer.content_type = _header_content_type(message)

    try:
        event = kafka_binding.from_kafka(
            message,
            selected_format,
            event_factory,
            decision=observer,
        )
    except Exception as exc:
        observer.fail(exc)
        if raise_on_error:
            raise
        return observer

    observer.event = event
    event_handler = handler or on_event
    if event_handler is not None:
        try:
            observer.deliver_to(event_handler)
        except Exception:
            if raise_on_error:
                raise
    return observer


def receive(
    message: http_binding.HTTPMessage | kafka_binding.KafkaMessage,
    event_format: Format | str | None = None,
    event_factory: EventFactory | None = None,
    **kwargs: Any,
) -> ReceiveDecision:
    """Dispatch to :func:`receive_http` or :func:`receive_kafka` by message type."""

    if isinstance(message, http_binding.HTTPMessage):
        return receive_http(message, event_format, event_factory, **kwargs)
    if isinstance(message, kafka_binding.KafkaMessage):
        return receive_kafka(message, event_format, event_factory, **kwargs)
    raise TypeError("message must be an HTTPMessage or KafkaMessage")


@dataclass
class CloudEventReceiver:
    """Receiver with shared format registry, handler, and decision history."""

    event_format: Format | None = None
    event_factory: EventFactory | None = None
    registry: RegistryLike = None
    handler: EventHandler | None = None
    raise_on_error: bool = False
    decisions: list[ReceiveDecision] = field(default_factory=list)

    @property
    def receipts(self) -> list[ReceiveDecision]:
        return self.decisions

    @property
    def last_decision(self) -> ReceiveDecision | None:
        return self.decisions[-1] if self.decisions else None

    def receive_http(
        self,
        message: http_binding.HTTPMessage,
        event_format: Format | str | None = None,
        event_factory: EventFactory | None = None,
        *,
        handler: EventHandler | None = None,
        **kwargs: Any,
    ) -> ReceiveDecision:
        decision = receive_http(
            message,
            event_format if event_format is not None else self.event_format,
            event_factory or self.event_factory,
            registry=kwargs.pop("registry", self.registry),
            handler=handler or self.handler,
            raise_on_error=kwargs.pop("raise_on_error", self.raise_on_error),
            **kwargs,
        )
        self.decisions.append(decision)
        return decision

    def receive_kafka(
        self,
        message: kafka_binding.KafkaMessage,
        event_format: Format | str | None = None,
        event_factory: EventFactory | None = None,
        *,
        handler: EventHandler | None = None,
        **kwargs: Any,
    ) -> ReceiveDecision:
        decision = receive_kafka(
            message,
            event_format if event_format is not None else self.event_format,
            event_factory or self.event_factory,
            registry=kwargs.pop("registry", self.registry),
            handler=handler or self.handler,
            raise_on_error=kwargs.pop("raise_on_error", self.raise_on_error),
            **kwargs,
        )
        self.decisions.append(decision)
        return decision

    def receive(
        self,
        message: http_binding.HTTPMessage | kafka_binding.KafkaMessage,
        **kwargs: Any,
    ) -> ReceiveDecision:
        if isinstance(message, http_binding.HTTPMessage):
            return self.receive_http(message, **kwargs)
        if isinstance(message, kafka_binding.KafkaMessage):
            return self.receive_kafka(message, **kwargs)
        raise TypeError("message must be an HTTPMessage or KafkaMessage")


class ReceiptBook:
    """In-memory idempotency table keyed by caller-controlled receipt key."""

    def __init__(self) -> None:
        self._receipts: dict[str, ReceiveDecision] = {}

    @property
    def receipts(self) -> Mapping[str, ReceiveDecision]:
        return dict(self._receipts)

    def get(self, idempotency_key: str) -> ReceiveDecision | None:
        return self._receipts.get(idempotency_key)

    def forget(self, idempotency_key: str) -> None:
        self._receipts.pop(idempotency_key, None)

    def receive_http(
        self,
        idempotency_key: str,
        message: http_binding.HTTPMessage,
        event_format: Format | str | None = None,
        event_factory: EventFactory | None = None,
        **kwargs: Any,
    ) -> ReceiveDecision:
        existing = self.get(idempotency_key)
        if existing is not None:
            return existing
        decision = receive_http(
            message,
            event_format,
            event_factory,
            idempotency_key=idempotency_key,
            **kwargs,
        )
        self._receipts[idempotency_key] = decision
        return decision

    def receive_kafka(
        self,
        idempotency_key: str,
        message: kafka_binding.KafkaMessage,
        event_format: Format | str | None = None,
        event_factory: EventFactory | None = None,
        **kwargs: Any,
    ) -> ReceiveDecision:
        existing = self.get(idempotency_key)
        if existing is not None:
            return existing
        decision = receive_kafka(
            message,
            event_format,
            event_factory,
            idempotency_key=idempotency_key,
            **kwargs,
        )
        self._receipts[idempotency_key] = decision
        return decision


IdempotentReceiptBook = ReceiptBook


# Discoverable function aliases.
receive_http_message = receive_http
receive_kafka_message = receive_kafka
decide_http = receive_http
decide_kafka = receive_kafka
http_receive = receive_http
kafka_receive = receive_kafka
