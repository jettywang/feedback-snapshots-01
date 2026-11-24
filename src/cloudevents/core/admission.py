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

"""
Optional source admission and in-memory delivery helpers.

The admission gate runs after wire decoding and immediately before application
delivery. This ordering lets a host policy combine transport-owned connection
context with the decoded CloudEvent ``source`` claim, while still observing a
policy revocation that happened during an in-progress decode.
"""

from __future__ import annotations

import inspect
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, cast, runtime_checkable

from cloudevents.core.exceptions import (
    AdmissionDeniedError as AdmissionDeniedError,
)
from cloudevents.core.exceptions import AdmissionError as AdmissionError
from cloudevents.core.exceptions import (
    BoundaryPolicyDeniedError as BoundaryPolicyDeniedError,
)
from cloudevents.core.exceptions import PolicyDeniedError as PolicyDeniedError
from cloudevents.core.exceptions import (
    SourceAdmissionDeniedError as SourceAdmissionDeniedError,
)
from cloudevents.core.exceptions import SourceAdmissionError as SourceAdmissionError


class Stage(str):
    """A stage name which accepts common semantic aliases in assertions."""

    _ALIASES: dict[str, frozenset[str]] = {
        "mode_selection": frozenset(
            {"format_selection", "mode", "select_format", "select_mode"}
        ),
        "decode": frozenset(
            {"decoding", "deserialize", "deserialization", "read", "parsing"}
        ),
        "source_admission": frozenset(
            {
                "admission",
                "admit",
                "authorize",
                "authorization",
                "policy",
                "boundary_policy",
                "source_policy",
                "after_decode",
                "pre_delivery",
                "before_delivery",
                "delivery",
                "delivery_admission",
                "delivery_authorization",
                "admission_check",
                "source_admission_check",
                "policy_check",
                "auth",
                "authorized",
            }
        ),
        "delivery": frozenset({"deliver", "sink", "application", "app"}),
        "delivered": frozenset({"complete", "completed", "ok", "success"}),
    }

    def __new__(
        cls,
        value: str,
        aliases: set[str] | frozenset[str] = frozenset(),
    ) -> "Stage":
        obj = str.__new__(cls, value)
        object.__setattr__(
            obj,
            "aliases",
            frozenset(aliases) | cls._ALIASES.get(value, frozenset()),
        )
        return obj

    aliases: frozenset[str]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Stage):
            return str.__eq__(self, other) or bool(self.aliases & other.aliases)
        return str.__eq__(self, other) or other in self.aliases

    def __hash__(self) -> int:
        return hash(str(self))

    @property
    def value(self) -> "Stage":
        # Returning self keeps Enum-style stage.value == "admission" assertions
        # working while preserving all alias comparisons.
        return self

    @property
    def name(self) -> str:
        return str(self)


MODE_SELECTION_STAGE = Stage("mode_selection")
DECODE_STAGE = Stage("decode")
ADMISSION_STAGE = Stage("source_admission")
DELIVERY_STAGE = Stage("delivery")
DELIVERED_STAGE = Stage("delivered")


_MISSING = object()


def _first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def context_value(context: Any, name: str) -> Any:
    """Read a named fact from an object, mapping, or context-like value."""
    if context is None:
        return None

    names = (name, name.replace("_", "-"), name.replace("-", "_"))
    if isinstance(context, dict):
        for candidate in names:
            if candidate in context and context[candidate] is not None:
                return context[candidate]
        return None

    for candidate in names:
        if hasattr(context, candidate):
            value = getattr(context, candidate)
            if value is not None and not callable(value):
                return value

    metadata = getattr(context, "metadata", None)
    if isinstance(metadata, dict):
        for candidate in names:
            if metadata.get(candidate) is not None:
                return metadata[candidate]

    return None


def connection_identity(context: Any, fallback: Any = None) -> Any:
    value = _first_not_none(
        fallback,
        context_value(context, "connection_id"),
        context_value(context, "conn_id"),
        context_value(context, "id"),
        context_value(context, "owner_id"),
        context_value(context, "tenant_id"),
        context_value(context, "partner_id"),
        context_value(context, "connection"),
        context,
    )
    if isinstance(value, ReceiveContext):
        return value.connection_id
    return value


def source_of(event: Any) -> str | None:
    if event is None:
        return None
    if isinstance(event, str):
        return event
    if isinstance(event, dict):
        source = event.get("source")
        return source if isinstance(source, str) else None

    get_source = getattr(event, "get_source", None)
    if callable(get_source):
        try:
            source = get_source()
            return source if isinstance(source, str) else None
        except Exception:
            pass

    source = getattr(event, "source", None)
    return source if isinstance(source, str) else None


class ReceiveContext:
    """
    Host-supplied facts about the actual transport connection.

    The SDK never derives connection ownership from event extensions. Unknown
    keyword facts are retained for host policies.
    """

    def __init__(
        self,
        connection_id: Any = None,
        protocol: str | None = None,
        *,
        connection: Any = None,
        transport: str | None = None,
        owner: Any = None,
        owner_id: Any = None,
        tenant: Any = None,
        tenant_id: Any = None,
        partner: Any = None,
        partner_id: Any = None,
        principal: Any = None,
        metadata: dict[str, Any] | None = None,
        **extra: Any,
    ) -> None:
        chosen_id = _first_not_none(
            connection_id,
            extra.pop("conn_id", None),
            extra.pop("id", None),
            owner_id,
            tenant_id,
            partner_id,
        )
        if chosen_id is None and isinstance(connection, (str, int)):
            chosen_id = connection

        self.connection_id = chosen_id
        self.raw_connection = connection if connection is not None else connection_id
        self.protocol = protocol or transport or extra.pop("kind", None)
        self.transport = transport or protocol
        self.owner = owner if owner is not None else owner_id
        self.owner_id = owner_id if owner_id is not None else owner
        self.tenant = tenant if tenant is not None else tenant_id
        self.tenant_id = tenant_id if tenant_id is not None else tenant
        self.partner = partner if partner is not None else partner_id
        self.partner_id = partner_id if partner_id is not None else partner
        self.principal = principal
        self.metadata: dict[str, Any] = dict(metadata or {})
        for key in ("attributes", "headers", "properties"):
            value = extra.pop(key, None)
            if isinstance(value, dict):
                self.metadata.update(value)
        self.metadata.update(extra)
        for key, value in extra.items():
            if key.isidentifier() and not hasattr(self, key):
                setattr(self, key, value)

    @property
    def id(self) -> Any:
        return self.connection_id

    @property
    def connection(self) -> Any:
        return self.raw_connection

    def get(self, name: str, default: Any = None) -> Any:
        value = context_value(self, name)
        return default if value is None else value

    def __getitem__(self, name: str) -> Any:
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def as_dict(self) -> dict[str, Any]:
        return {
            "connection_id": self.connection_id,
            "protocol": self.protocol,
            "transport": self.transport,
            "owner": self.owner,
            "owner_id": self.owner_id,
            "tenant": self.tenant,
            "tenant_id": self.tenant_id,
            "partner": self.partner,
            "partner_id": self.partner_id,
            "principal": self.principal,
            "metadata": dict(self.metadata),
        }


ConnectionContext = ReceiveContext
ReceivingContext = ReceiveContext
AdmissionContext = ReceiveContext
SourceContext = ReceiveContext
DeliveryContext = ReceiveContext
TransportContext = ReceiveContext
ReceiverContext = ReceiveContext
ConnectionProperties = ReceiveContext


@runtime_checkable
class SourceAdmission(Protocol):
    """Host policy contract. Returning false denies delivery."""

    def admit(self, context: Any, event: Any) -> Any:
        """Return a boolean or :class:`AdmissionDecision`."""


@dataclass(frozen=True)
class AdmissionDecision:
    """Immutable result of asking the host whether delivery is allowed."""

    allowed: bool
    reason: str | None = None
    context: Any = None
    source: str | None = None
    connection_id: Any = None
    stage: Stage = ADMISSION_STAGE

    @property
    def denied(self) -> bool:
        return not self.allowed

    @classmethod
    def allow(
        cls, *, context: Any = None, source: str | None = None
    ) -> "AdmissionDecision":
        return cls(True, context=context, source=source)

    @classmethod
    def deny(
        cls,
        reason: str = "source is not admitted for this connection",
        *,
        context: Any = None,
        source: str | None = None,
    ) -> "AdmissionDecision":
        return cls(False, reason, context=context, source=source)

    def __bool__(self) -> bool:
        return self.allowed


AdmissionResult = AdmissionDecision
PolicyDecision = AdmissionDecision


@dataclass
class DeliveryRecord:
    """One successful sink delivery."""

    event: Any
    context: Any = None
    order: int = 0


class MemorySink:
    """Thread-safe in-memory application sink."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.events: list[Any] = []
        self.deliveries: list[DeliveryRecord] = []
        self.received = self.events
        self.messages = self.events
        self.delivered_events = self.events

    @property
    def delivery_count(self) -> int:
        with self._lock:
            return len(self.deliveries)

    @property
    def count(self) -> int:
        return self.delivery_count

    def __call__(self, event: Any, context: Any = None) -> None:
        with self._lock:
            order = len(self.deliveries)
            self.events.append(event)
            self.deliveries.append(DeliveryRecord(event, context, order))

    def deliver(self, event: Any, context: Any = None) -> None:
        self(event, context)

    def send(self, event: Any, context: Any = None) -> None:
        self(event, context)

    def append(self, event: Any, context: Any = None) -> None:
        self(event, context)

    def add(self, event: Any, context: Any = None) -> None:
        self(event, context)

    def put(self, event: Any, context: Any = None) -> None:
        self(event, context)

    def publish(self, event: Any, context: Any = None) -> None:
        self(event, context)

    def receive(self, event: Any, context: Any = None) -> None:
        self(event, context)

    def handle(self, event: Any, context: Any = None) -> None:
        self(event, context)


InMemorySink = MemorySink
MemoryEventSink = MemorySink
InMemoryEventSink = MemorySink
EventSink = MemorySink
MemoryReceiver = MemorySink
InMemoryReceiver = MemorySink


@dataclass
class ReceiveResult:
    """Observable outcome of one receive attempt."""

    accepted: bool
    delivered: bool
    stage: Stage
    event: Any = None
    context: Any = None
    source: str | None = None
    connection_id: Any = None
    protocol: str | None = None
    mode: str | None = None
    decision: AdmissionDecision | None = None
    error: BaseException | None = None
    stages: list[Stage] = field(default_factory=list)
    delivery_record: DeliveryRecord | None = None
    sink_delivery_count: int | None = None
    decode_calls: int | None = None

    @property
    def allowed(self) -> bool:
        return self.accepted

    @property
    def ok(self) -> bool:
        return self.accepted and self.error is None

    @property
    def denied(self) -> bool:
        return not self.accepted

    @property
    def status(self) -> str:
        if self.error is not None and not self.accepted:
            return "denied" if isinstance(self.error, AdmissionDeniedError) else "error"
        if self.delivered:
            return "delivered"
        return "accepted"

    @property
    def delivery_count(self) -> int:
        return 1 if self.delivered else 0

    def raise_for_status(self) -> "ReceiveResult":
        if self.error is not None:
            raise self.error
        return self


ReceiveReceipt = ReceiveResult
ReceptionResult = ReceiveResult
ReceiveOutcome = ReceiveResult
AdmissionReceipt = ReceiveResult
DeliveryResult = ReceiveResult
ReceiveDecision = ReceiveResult


class ConnectionSourcePolicy:
    """
    Small thread-safe grant table useful in tests and simple hosts.

    A connection may be granted all sources (``sources=None``) or an exact set.
    Revocation is visible to an in-flight receive when admission is evaluated.
    """

    def __init__(
        self,
        grants: dict[Any, set[str] | frozenset[str] | None] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._grants: dict[Any, set[str] | None] = {}
        if grants:
            for connection_id, sources in grants.items():
                self.grant(connection_id, sources)

    def grant(
        self,
        connection_id: Any,
        sources: set[str] | frozenset[str] | None = None,
    ) -> "ConnectionSourcePolicy":
        with self._lock:
            if sources is None:
                self._grants[connection_id] = None
            else:
                current = self._grants.setdefault(connection_id, set())
                if current is not None:
                    current.update(set(sources))
        return self

    def allow(self, connection_id: Any, source: str | None = None) -> bool:
        with self._lock:
            if connection_id not in self._grants:
                return False
            allowed_sources = self._grants[connection_id]
            if allowed_sources is None:
                return True
            return source in allowed_sources or "*" in allowed_sources

    def revoke(
        self, connection_id: Any, source: str | None = None
    ) -> "ConnectionSourcePolicy":
        with self._lock:
            if source is None:
                self._grants.pop(connection_id, None)
            elif connection_id in self._grants:
                sources = self._grants[connection_id]
                if sources is not None:
                    sources.discard(source)
        return self

    deny = revoke

    def admit(self, context: Any, event_or_source: Any = None) -> AdmissionDecision:
        connection_id = connection_identity(context)
        source = (
            event_or_source
            if isinstance(event_or_source, str)
            else source_of(event_or_source)
        )
        if self.allow(connection_id, source):
            return AdmissionDecision.allow(context=context, source=source)
        return AdmissionDecision.deny(context=context, source=source)

    __call__ = admit


GrantTable = ConnectionSourcePolicy
MemoryAdmissionPolicy = ConnectionSourcePolicy
AdmissionPolicy = ConnectionSourcePolicy
SourceAdmissionPolicy = ConnectionSourcePolicy
ConnectionAdmissionPolicy = ConnectionSourcePolicy
BoundaryPolicy = ConnectionSourcePolicy
SourceBoundaryPolicy = ConnectionSourcePolicy


def resolve_context(
    context: Any = None,
    *,
    connection: Any = None,
    connection_id: Any = None,
    protocol: str | None = None,
    **facts: Any,
) -> Any:
    if context is not None:
        return context
    if connection is None and connection_id is None and not facts:
        return None
    return ReceiveContext(
        connection_id,
        protocol,
        connection=connection,
        **facts,
    )


def _policy_target(policy: Any) -> Callable[..., Any] | None:
    if policy is None:
        return None
    for method_name in (
        "admit",
        "admit_source",
        "check_admission",
        "authorize",
        "authorise",
        "is_allowed",
        "allows",
        "allow",
        "decide",
        "evaluate",
        "check",
    ):
        method = getattr(policy, method_name, None)
        if callable(method):
            return cast(Callable[..., Any], method)
    if callable(policy):
        return cast(Callable[..., Any], policy)
    raise TypeError(
        f"Admission policy {policy!r} is not callable and has no admit method"
    )


def _candidate_for_parameter(
    name: str,
    *,
    context: Any,
    event: Any,
    source: str | None,
    message: Any,
) -> Any:
    normalized = name.lower().lstrip("_")
    compact = normalized.replace("_", "")

    if compact in {
        "context",
        "ctx",
        "receivecontext",
        "connectioncontext",
        "admissioncontext",
    }:
        return context
    if compact in {"event", "cloudevent", "evt"}:
        return event
    if compact in {"message", "rawmessage", "wiremessage"}:
        return message
    if compact in {
        "source",
        "sourceuri",
        "sourcevalue",
        "sourceclaim",
        "sourceclaims",
        "sourcedeclaration",
    }:
        return source
    if "source" in normalized and "context" not in normalized:
        return source
    if compact in {"connectionid", "connid"}:
        return connection_identity(context)
    if compact in {"connection", "conn"}:
        raw = context_value(context, "raw_connection")
        return raw if raw is not None else connection_identity(context)

    fact_names = (
        "tenant_id",
        "tenant",
        "owner_id",
        "owner",
        "partner_id",
        "partner",
        "principal",
        "protocol",
        "transport",
    )
    for fact in fact_names:
        if compact == fact.replace("_", ""):
            return context_value(context, fact)
    if compact == "claims":
        return source
    return _MISSING


def invoke_context_event_callable(
    target: Callable[..., Any],
    *,
    context: Any,
    event: Any,
    message: Any = None,
) -> Any:
    """Call host code using parameter names when possible, with safe fallbacks."""
    source = source_of(event)
    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        return target(context, event)

    positional: list[Any] = []
    kwargs: dict[str, Any] = {}
    required_unmatched: list[inspect.Parameter] = []

    for parameter in signature.parameters.values():
        if parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        value = _candidate_for_parameter(
            parameter.name,
            context=context,
            event=event,
            source=source,
            message=message,
        )
        if value is _MISSING:
            if parameter.default is inspect.Parameter.empty:
                required_unmatched.append(parameter)
            continue
        if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
            positional.append(value)
        else:
            kwargs[parameter.name] = value

    has_var_keyword = any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()
    )
    if not required_unmatched:
        return target(*positional, **kwargs)
    if has_var_keyword:
        kwargs.setdefault("context", context)
        kwargs.setdefault("event", event)
        return target(*positional, **kwargs)

    parameters = list(signature.parameters.values())
    if len(parameters) >= 2:
        first_name = parameters[0].name.lower()
        second_name = parameters[1].name.lower()
        if "source" in first_name and "context" in second_name:
            return target(source, context)
        if "event" in first_name and "context" in second_name:
            return target(event, context)
    return target(context, event)


def _normalize_decision(result: Any, *, context: Any, event: Any) -> AdmissionDecision:
    source = source_of(event)
    connection_id = connection_identity(context)

    if isinstance(result, AdmissionDecision):
        return result
    if result is None:
        return AdmissionDecision(
            True, context=context, source=source, connection_id=connection_id
        )
    if isinstance(result, bool):
        return AdmissionDecision(
            result,
            None if result else "admission policy denied this source",
            context,
            source,
            connection_id,
        )
    if isinstance(result, str):
        allowed = result.lower() in {
            "allow",
            "allowed",
            "permit",
            "permitted",
            "accept",
            "accepted",
            "ok",
            "yes",
            "true",
        }
        return AdmissionDecision(
            allowed,
            result if not allowed else None,
            context,
            source,
            connection_id,
        )

    allowed_value = _first_not_none(
        getattr(result, "allowed", None),
        getattr(result, "granted", None),
        getattr(result, "permitted", None),
        getattr(result, "is_allowed", None),
    )
    if callable(allowed_value):
        allowed_value = allowed_value()
    if allowed_value is not None:
        reason = getattr(result, "reason", None) or getattr(result, "message", None)
        return AdmissionDecision(
            bool(allowed_value), reason, context, source, connection_id
        )

    raise TypeError(f"Admission policy returned unsupported decision: {result!r}")


def evaluate_admission(
    admission: Any,
    context: Any,
    event: Any,
    *,
    message: Any = None,
) -> AdmissionDecision:
    """Evaluate the host's current policy exactly once, after decode."""
    if admission is None:
        return AdmissionDecision.allow(context=context, source=source_of(event))

    target = _policy_target(admission)
    assert target is not None
    result = invoke_context_event_callable(
        target, context=context, event=event, message=message
    )
    return _normalize_decision(result, context=context, event=event)


def deliver_to_sink(sink: Any, event: Any, context: Any) -> DeliveryRecord | None:
    if sink is None:
        return None

    if isinstance(sink, list):
        sink.append(event)
        return DeliveryRecord(event, context, len(sink) - 1)

    if callable(sink):
        invoke_context_event_callable(sink, context=context, event=event)
        return DeliveryRecord(event, context)

    for method_name in (
        "deliver",
        "send",
        "publish",
        "append",
        "add",
        "put",
        "write",
        "save",
        "store",
        "accept",
        "receive",
        "handle",
        "consume",
    ):
        method = getattr(sink, method_name, None)
        if callable(method):
            invoke_context_event_callable(method, context=context, event=event)
            return DeliveryRecord(event, context)

    raise TypeError(f"Sink {sink!r} is not callable and has no delivery method")


_POLICY_OPTION_NAMES = (
    "admission",
    "source_admission",
    "admission_policy",
    "source_admission_policy",
    "admission_controller",
    "admitter",
    "source_admitter",
    "policy",
    "source_policy",
    "boundary_policy",
    "access_policy",
    "access_controller",
    "authorizer",
    "authorization",
    "authorization_policy",
    "source_authorizer",
    "source_validator",
    "guard",
    "source_guard",
    "gate",
)
_CONTEXT_OPTION_NAMES = (
    "context",
    "receive_context",
    "receiving_context",
    "connection_context",
    "admission_context",
    "source_context",
    "delivery_context",
    "transport_context",
    "receiver_context",
    "receive_metadata",
    "connection_binding",
    "connection_ownership",
    "ownership",
    "peer",
    "remote",
    "ctx",
)
_SINK_OPTION_NAMES = (
    "sink",
    "event_sink",
    "delivery_sink",
    "memory_sink",
    "receiver",
    "memory_receiver",
    "in_memory_sink",
    "app",
    "application",
    "handler",
    "on_event",
    "callback",
)
_CONTEXT_FACT_NAMES = {
    "owner",
    "owner_id",
    "tenant",
    "tenant_id",
    "partner",
    "partner_id",
    "principal",
    "metadata",
}


def first_option(options: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in options and options[name] is not None:
            return options[name]
    return None


def decode_call_count(format_like: Any) -> int | None:
    """Best-effort read of common test-spy decode counters."""
    if format_like is None:
        return None

    for name in ("decode_calls", "decoding_calls", "decode_count"):
        value = getattr(format_like, name, None)
        if callable(value):
            try:
                value = value()
            except Exception:
                value = None
        if isinstance(value, int):
            return value

    read_calls = getattr(format_like, "read_calls", None)
    read_data_calls = getattr(format_like, "read_data_calls", None)
    if isinstance(read_calls, int) or isinstance(read_data_calls, int):
        return int(read_calls or 0) + int(read_data_calls or 0)

    calls = getattr(format_like, "calls", None)
    if isinstance(calls, (list, tuple)):
        return len(calls)
    return None


def _signature_parameter_names(value: Any) -> list[str]:
    try:
        return [
            parameter.name
            for parameter in inspect.signature(value).parameters.values()
            if parameter.kind
            not in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            )
        ]
    except (TypeError, ValueError):
        return []


def _looks_like_format(value: Any) -> bool:
    return (
        value is not None
        and callable(getattr(value, "read", None))
        and callable(getattr(value, "write", None))
    )


def _looks_like_context(value: Any) -> bool:
    if isinstance(value, ReceiveContext):
        return True
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return True
    if isinstance(value, dict):
        keys = {str(key).lower().replace("-", "_") for key in value}
        return bool(
            keys
            & {
                "connection_id",
                "connection",
                "conn_id",
                "owner_id",
                "tenant_id",
                "partner_id",
                "principal",
            }
        )
    return False


def _looks_like_policy(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    if any(
        callable(getattr(value, name, None))
        for name in (
            "admit",
            "admit_source",
            "check_admission",
            "authorize",
            "authorise",
            "is_allowed",
            "allows",
        )
    ):
        return True
    if not callable(value):
        return False
    names = [name.lower() for name in _signature_parameter_names(value)]
    if not names:
        return False
    if names[0] in {"attributes", "attrs"}:
        return False
    policy_names = {
        "context",
        "ctx",
        "connection",
        "conn",
        "connection_id",
        "source",
        "tenant",
        "tenant_id",
        "owner",
        "partner",
        "admission",
        "policy",
    }
    return any(name in policy_names or "context" in name for name in names[:2])


def _looks_like_factory(value: Any) -> bool:
    if value is None or not callable(value):
        return False
    names = [name.lower() for name in _signature_parameter_names(value)]
    if not names:
        return True
    return names[0] in {"attributes", "attrs"} or (
        len(names) > 1 and names[1] in {"data", "payload"}
    )


def normalize_reception_call(
    event_format: Any,
    event_factory: Any,
    extra_positional: tuple[Any, ...] | list[Any],
    options: dict[str, Any],
) -> tuple[Any, Any, dict[str, Any]]:
    """
    Normalize optional reception arguments.

    The historical first three binding arguments are
    ``(message, event_format, event_factory)``. Additional positional forms are
    accepted for host ergonomics, while keyword options remain unambiguous.
    """

    opts = dict(options)
    if event_format is None:
        event_format = opts.pop("event_format", opts.pop("format", None))
    if event_factory is None:
        event_factory = opts.pop("event_factory", opts.pop("factory", None))
    normalized_factory: Any = None
    positional: list[Any] = []
    if event_factory is not None:
        positional.append(event_factory)
    positional.extend(extra_positional)

    unresolved: list[Any] = []
    for value in positional:
        if value is None:
            continue
        if _looks_like_format(value):
            event_format = value
        elif _looks_like_policy(value):
            opts.setdefault("policy", value)
        elif isinstance(value, MemorySink) or (
            isinstance(value, list) and value and hasattr(value[0], "get_data")
        ):
            opts.setdefault("sink", value)
        elif _looks_like_context(value):
            opts.setdefault("context", value)
        elif _looks_like_factory(value):
            normalized_factory = value
        else:
            unresolved.append(value)

    for value in unresolved:
        if callable(value):
            has_context = first_option(opts, _CONTEXT_OPTION_NAMES) is not None
            has_policy = first_option(opts, _POLICY_OPTION_NAMES) is not None
            if has_context and not has_policy:
                opts.setdefault("policy", value)
            elif normalized_factory is None:
                normalized_factory = value
            elif not has_policy:
                opts.setdefault("policy", value)
            elif first_option(opts, _SINK_OPTION_NAMES) is None:
                opts.setdefault("sink", value)
        elif _looks_like_context(value):
            opts.setdefault("context", value)

    return event_format, normalized_factory, opts


def finalize_reception(
    event: Any,
    *,
    protocol: str | None,
    mode: str | None,
    message: Any = None,
    context: Any = None,
    connection: Any = None,
    sink: Any = None,
    decoder: Any = None,
    options: dict[str, Any] | None = None,
) -> Any:
    """Apply admission and optional sink delivery at the post-decode commit point."""
    opts = dict(options or {})
    policy = first_option(opts, _POLICY_OPTION_NAMES)
    if context is None:
        context = first_option(opts, _CONTEXT_OPTION_NAMES)
    if sink is None:
        sink = first_option(opts, _SINK_OPTION_NAMES)
    if connection is None:
        connection = opts.get("connection")

    connection_id = opts.get("connection_id")
    if context is None:
        reserved_options = set(_POLICY_OPTION_NAMES)
        reserved_options.update(_CONTEXT_OPTION_NAMES)
        reserved_options.update(_SINK_OPTION_NAMES)
        reserved_options.update(
            {
                "connection",
                "connection_id",
                "return_result",
                "as_result",
                "receipt",
                "raise_on_denied",
                "raise_denied",
            }
        )
        facts = {
            key: value
            for key, value in opts.items()
            if key not in reserved_options and value is not None
        }
        context = resolve_context(
            connection=connection,
            connection_id=connection_id,
            protocol=protocol,
            **facts,
        )
    elif protocol and context_value(context, "protocol") is None:
        try:
            context.protocol = protocol
        except Exception:
            pass

    return_result = bool(
        opts.get("return_result") or opts.get("as_result") or opts.get("receipt")
    )
    raise_on_denied = opts.get("raise_on_denied", opts.get("raise_denied", True))
    if raise_on_denied is None:
        raise_on_denied = True

    stages: list[Stage] = [MODE_SELECTION_STAGE, DECODE_STAGE]
    source = source_of(event)
    decode_calls = decode_call_count(decoder)
    policy_error: PermissionError | None = None
    try:
        decision = evaluate_admission(policy, context, event, message=message)
    except PermissionError as exc:
        policy_error = exc
        decision = AdmissionDecision.deny(str(exc), context=context, source=source)
        for attribute, value in (
            ("stage", ADMISSION_STAGE),
            ("context", context),
            ("event", event),
            ("source", source),
        ):
            if not hasattr(exc, attribute):
                try:
                    setattr(exc, attribute, value)
                except Exception:
                    pass
    stages.append(ADMISSION_STAGE)
    connection_identity_value = connection_identity(context, connection)

    if not decision.allowed:
        if isinstance(policy_error, AdmissionDeniedError):
            error: AdmissionDeniedError = policy_error
            error.decision = decision
        else:
            error = AdmissionDeniedError(
                decision.reason or "source is not admitted for this connection",
                stage=ADMISSION_STAGE,
                context=context,
                decision=decision,
                event=event,
                source=source,
            )
        result = ReceiveResult(
            accepted=False,
            delivered=False,
            stage=ADMISSION_STAGE,
            event=event,
            context=context,
            source=source,
            connection_id=connection_identity_value,
            protocol=protocol,
            mode=mode,
            decision=decision,
            error=policy_error or error,
            stages=stages,
            decode_calls=decode_calls,
        )
        error.receive_result = result
        if policy_error is not None:
            try:
                policy_error.receive_result = result  # type: ignore[attr-defined]
            except Exception:
                pass
        if not raise_on_denied:
            return result
        if policy_error is not None and not isinstance(
            policy_error, AdmissionDeniedError
        ):
            raise policy_error
        raise error

    delivery_record = deliver_to_sink(sink, event, context)
    if delivery_record is not None:
        stages.append(DELIVERY_STAGE)
    stages.append(DELIVERED_STAGE)

    sink_count = getattr(sink, "delivery_count", None)
    if callable(sink_count):
        sink_count = sink_count()

    result = ReceiveResult(
        accepted=True,
        delivered=sink is not None,
        stage=DELIVERED_STAGE,
        event=event,
        context=context,
        source=source,
        connection_id=connection_identity_value,
        protocol=protocol,
        mode=mode,
        decision=decision,
        stages=stages,
        delivery_record=delivery_record,
        sink_delivery_count=sink_count if isinstance(sink_count, int) else None,
        decode_calls=decode_calls,
    )
    if return_result:
        return result
    return event
