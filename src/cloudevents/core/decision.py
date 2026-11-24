"""Observable receive decisions and failure-preserving receipts.

A receive decision records one content-mode choice, at most one selected
format decode, event construction/validation, and optional delivery to the
application.  The object is also the receipt: failed receives retain the
stages which completed before the failure.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Final, Iterator, cast
from uuid import uuid4

from cloudevents.core.base import BaseCloudEvent, EventFactory
from cloudevents.core.formats.base import Format
from cloudevents.core.spec import SPECVERSION_V1_0

EventHandler = Callable[[BaseCloudEvent], Any]


class Binding:
    """Supported binding names used in receipts."""

    HTTP: Final[str] = "http"
    KAFKA: Final[str] = "kafka"


class ContentMode:
    """CloudEvents transport content modes."""

    BINARY: Final[str] = "binary"
    STRUCTURED: Final[str] = "structured"
    UNKNOWN: Final[str] = "unknown"


class ReceiveStage:
    """Canonical receive stages."""

    SELECT_MODE: Final[str] = "select_mode"
    READ: Final[str] = "read"
    VALIDATE: Final[str] = "validate"
    DELIVER: Final[str] = "deliver"
    RECEIVE: Final[str] = "receive"


class StageStatus:
    PENDING: Final[str] = "pending"
    STARTED: Final[str] = "started"
    COMPLETED: Final[str] = "completed"
    FAILED: Final[str] = "failed"


_STAGE_ALIASES: dict[str, set[str]] = {
    ReceiveStage.SELECT_MODE: {
        "mode",
        "mode_selection",
        "mode_selected",
        "select",
        "selection",
        "content_mode",
    },
    ReceiveStage.READ: {
        "decode",
        "decoding",
        "format",
        "format_read",
        "read_data",
        "read_event",
    },
    ReceiveStage.VALIDATE: {
        "validation",
        "build",
        "event_factory",
        "factory",
        "verify",
    },
    ReceiveStage.DELIVER: {
        "delivery",
        "delivered",
        "handler",
        "dispatch",
    },
}


def version_aware_event_factory(
    attributes: dict[str, Any],
    data: dict[str, Any] | str | bytes | None,
) -> BaseCloudEvent:
    """Build the correct event version from a decoded specversion attribute."""
    from cloudevents.core.bindings.common import get_event_factory_for_version

    specversion = attributes.get("specversion", SPECVERSION_V1_0)
    return get_event_factory_for_version(specversion)(attributes, data)


def attach_decision(error: BaseException, decision: ReceiveDecision) -> None:
    """Attach the receipt to an exception without changing its type."""

    for attribute_name in ("decision", "receipt", "receive_decision"):
        try:
            setattr(error, attribute_name, decision)
        except Exception:
            # Some exception implementations may forbid new attributes.
            pass


@dataclass
class StageRecord:
    """State and evidence for one stage of a receive decision."""

    stage: str
    status: str = StageStatus.PENDING
    mode: str | None = None
    callback: str | None = None
    error: BaseException | None = field(default=None, repr=False, compare=False)
    error_type: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.stage

    @property
    def completed(self) -> bool:
        return self.status == StageStatus.COMPLETED

    @property
    def failed(self) -> bool:
        return self.status == StageStatus.FAILED

    def complete(self, **metadata: Any) -> StageRecord:
        if self.status != StageStatus.FAILED:
            self.status = StageStatus.COMPLETED
        if metadata:
            self.metadata.update(metadata)
        return self

    def fail(self, error: BaseException, **metadata: Any) -> StageRecord:
        self.status = StageStatus.FAILED
        self.error = error
        self.error_type = type(error).__name__
        self.error_message = str(error)
        if metadata:
            self.metadata.update(metadata)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "status": self.status,
            "mode": self.mode,
            "callback": self.callback,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "metadata": dict(self.metadata),
        }


@dataclass
class ReceiveDecision:
    """One observable mode-selection/validation/delivery decision.

    ``ReceiveDecision`` is intentionally usable as its own idempotent receipt.
    ``deliver_to`` does not invoke an application handler twice on the same
    decision object.
    """

    binding: str = ContentMode.UNKNOWN
    decision_id: str = field(default_factory=lambda: uuid4().hex)
    idempotency_key: str | None = None
    mode: str | None = None
    content_type: str | None = None
    event: BaseCloudEvent | None = None
    error: BaseException | None = None
    stages: list[StageRecord] = field(default_factory=list)
    delivered: bool = False
    delivery_attempts: int = 0
    delivery_result: Any = None
    delivery_error: BaseException | None = field(
        default=None, repr=False, compare=False
    )
    format_calls: int = 0
    read_calls: int = 0
    read_data_calls: int = 0
    write_calls: int = 0
    factory_calls: int = 0
    handler_calls: int = 0

    def __post_init__(self) -> None:
        if self.idempotency_key is None:
            self.idempotency_key = self.decision_id

    @property
    def receipt(self) -> ReceiveDecision:
        return self

    @property
    def ok(self) -> bool:
        return self.error is None and self.event is not None

    @property
    def succeeded(self) -> bool:
        return self.ok

    @property
    def failed(self) -> bool:
        return self.error is not None

    @property
    def was_delivered(self) -> bool:
        return self.delivered

    @property
    def stage_names(self) -> list[str]:
        return [record.stage for record in self.stages]

    @property
    def records(self) -> list[StageRecord]:
        return self.stages

    @property
    def completed_stages(self) -> list[str]:
        return [record.stage for record in self.stages if record.completed]

    @property
    def completed_stage_records(self) -> list[StageRecord]:
        return [record for record in self.stages if record.completed]

    @property
    def failed_stages(self) -> list[str]:
        return [record.stage for record in self.stages if record.failed]

    @property
    def failed_stage(self) -> str | None:
        for record in reversed(self.stages):
            if record.failed:
                return record.stage
        return None

    @property
    def decode_calls(self) -> int:
        return self.read_calls + self.read_data_calls

    @property
    def calls(self) -> dict[str, int]:
        return {
            "format": self.format_calls,
            "decode": self.decode_calls,
            "read": self.read_calls,
            "read_data": self.read_data_calls,
            "factory": self.factory_calls,
            "handler": self.handler_calls,
        }

    def begin_stage(
        self,
        stage: str,
        *,
        mode: str | None = None,
        callback: str | None = None,
        **metadata: Any,
    ) -> StageRecord:
        record = StageRecord(
            stage=stage,
            status=StageStatus.STARTED,
            mode=mode or self.mode,
            callback=callback,
            metadata=metadata,
        )
        self.stages.append(record)
        return record

    @contextmanager
    def stage_scope(self, stage: str, **metadata: Any) -> Iterator[StageRecord]:
        """Context manager for externally instrumented stages."""

        record = self.begin_stage(stage, **metadata)
        try:
            yield record
        except BaseException as exc:
            record.fail(exc)
            raise
        else:
            record.complete()

    def record_mode(self, mode: str, content_type: str | None = None) -> StageRecord:
        self.mode = mode
        if content_type is not None:
            self.content_type = content_type
        existing = self._find_stage(ReceiveStage.SELECT_MODE)
        if existing is not None:
            existing.mode = mode
            if content_type is not None:
                existing.metadata["content_type"] = content_type
            return existing.complete()

        record = StageRecord(
            stage=ReceiveStage.SELECT_MODE,
            status=StageStatus.COMPLETED,
            mode=mode,
            metadata={"content_type": content_type},
        )
        self.stages.append(record)
        return record

    def complete_stage(self, stage: str | StageRecord | None = None) -> StageRecord:
        record = self._find_stage(stage)
        if record is None:
            name = stage if isinstance(stage, str) else ReceiveStage.RECEIVE
            record = StageRecord(name, StageStatus.COMPLETED)
            self.stages.append(record)
        return record.complete()

    def fail_stage(
        self, stage: str | StageRecord | None, error: BaseException
    ) -> StageRecord:
        record = self._find_stage(stage)
        if record is None:
            name = stage if isinstance(stage, str) else ReceiveStage.RECEIVE
            record = self.begin_stage(name)
        return record.fail(error)

    def fail(self, error: BaseException) -> None:
        if self.error is None:
            self.error = error

        active = self._find_active_stage()
        if active is not None:
            active.fail(error)
            return

        if self.stages and self.stages[-1].failed:
            return

        self.fail_stage(ReceiveStage.RECEIVE, error)

    def observe_format(self, event_format: Any) -> Any:
        if isinstance(event_format, ObservedFormat):
            if event_format.decision is self:
                return event_format
            return ObservedFormat(event_format.wrapped, self)
        return ObservedFormat(event_format, self)

    def observe_factory(self, event_factory: EventFactory | None) -> EventFactory:
        factory = event_factory or version_aware_event_factory
        if getattr(factory, "_cloudevents_decision_factory", False):
            return factory

        decision = self

        def observed_factory(
            attributes: dict[str, Any],
            data: dict[str, Any] | str | bytes | None,
        ) -> BaseCloudEvent:
            decision.factory_calls += 1
            # A structured format callback has successfully decoded enough to
            # invoke the event factory.  Binary read_data is already complete.
            decision.complete_stage(ReceiveStage.READ)
            validation = decision.begin_stage(ReceiveStage.VALIDATE)
            try:
                event = factory(attributes, data)
            except BaseException as exc:
                validation.fail(exc)
                if decision.error is None:
                    decision.error = exc
                raise
            validation.complete()
            decision.event = event
            return event

        observed_factory._cloudevents_decision_factory = True  # type: ignore[attr-defined]
        return observed_factory

    def deliver_to(self, handler: EventHandler) -> Any:
        if self.delivered:
            return self.delivery_result
        if self.event is None:
            raise ValueError("Cannot deliver a receive decision without an event")

        self.delivery_attempts += 1
        self.handler_calls += 1
        stage = self.begin_stage(ReceiveStage.DELIVER)
        try:
            result = handler(self.event)
        except BaseException as exc:
            stage.fail(exc)
            self.delivery_error = exc
            if self.error is None:
                self.error = exc
            raise
        stage.complete()
        self.delivered = True
        self.delivery_result = result
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "idempotency_key": self.idempotency_key,
            "binding": self.binding,
            "mode": self.mode,
            "content_type": self.content_type,
            "ok": self.ok,
            "delivered": self.delivered,
            "calls": self.calls,
            "stages": [stage.to_dict() for stage in self.stages],
            "failed_stage": self.failed_stage,
            "error_type": type(self.error).__name__ if self.error else None,
            "error_message": str(self.error) if self.error else None,
        }

    def _find_active_stage(self) -> StageRecord | None:
        for record in reversed(self.stages):
            if record.status in (StageStatus.PENDING, StageStatus.STARTED):
                return record
        return None

    def _find_stage(self, stage: str | StageRecord | None) -> StageRecord | None:
        if isinstance(stage, StageRecord):
            return stage
        if stage is None:
            return self._find_active_stage()

        aliases = _STAGE_ALIASES.get(stage, set())
        for record in reversed(self.stages):
            if record.stage == stage or record.stage in aliases:
                return record
            if stage in _STAGE_ALIASES.get(record.stage, set()):
                return record
        return None


class ObservedFormat:
    """Format proxy which counts decode calls and records their stage."""

    def __init__(self, wrapped: Format, decision: ReceiveDecision) -> None:
        self.wrapped: Format = wrapped
        self.decision = decision

    def read(
        self,
        event_factory: EventFactory | None,
        data: str | bytes,
    ) -> BaseCloudEvent:
        self.decision.format_calls += 1
        self.decision.read_calls += 1
        stage = self.decision.begin_stage(ReceiveStage.READ, callback="read")
        try:
            result = self.wrapped.read(
                self.decision.observe_factory(event_factory), data
            )
        except BaseException as exc:
            if stage.status == StageStatus.STARTED:
                stage.fail(exc)
            if self.decision.error is None:
                self.decision.error = exc
            raise
        else:
            self.decision.complete_stage(stage)
            return cast(BaseCloudEvent, result)

    def read_data(
        self,
        body: bytes,
        datacontenttype: str | None,
    ) -> dict[str, Any] | str | bytes | None:
        self.decision.format_calls += 1
        self.decision.read_data_calls += 1
        stage = self.decision.begin_stage(ReceiveStage.READ, callback="read_data")
        try:
            result = self.wrapped.read_data(body, datacontenttype)
        except BaseException as exc:
            stage.fail(exc)
            if self.decision.error is None:
                self.decision.error = exc
            raise
        else:
            stage.complete()
            return cast(
                "dict[str, Any] | str | bytes | None",
                result,
            )

    def write(self, event: BaseCloudEvent) -> bytes:
        self.decision.write_calls += 1
        return cast(bytes, self.wrapped.write(event))

    def write_data(
        self,
        data: dict[str, Any] | str | bytes | None,
        datacontenttype: str | None,
    ) -> bytes:
        self.decision.write_calls += 1
        return cast(bytes, self.wrapped.write_data(data, datacontenttype))

    def get_content_type(self) -> str:
        return cast(str, self.wrapped.get_content_type())

    def __getattr__(self, name: str) -> Any:
        return getattr(self.wrapped, name)


ReceiveReceipt = ReceiveDecision
DecisionReceipt = ReceiveDecision
Receipt = ReceiveDecision
Decision = ReceiveDecision
ReceiveOutcome = ReceiveDecision
ObservedReceiver = ReceiveDecision
