from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from cloudevents.core.bindings import http, kafka
from cloudevents.core.decision import ReceiveDecision, ReceiveStage
from cloudevents.core.formats.json import JSONFormat
from cloudevents.core.formats.registry import FormatRegistry
from cloudevents.core.receive import (
    CloudEventReceiver,
    ReceiptBook,
    receive_http,
    receive_kafka,
)
from cloudevents.core.v1.event import CloudEvent


class SimulatedReadFailure(RuntimeError):
    pass


class RecordingFormat:
    """Local format spy whose selected read can be made to fail."""

    def __init__(self, fail_at: str | bool | None = None) -> None:
        self._json = JSONFormat()
        self.fail_at = fail_at
        self.read_count = 0
        self.read_data_count = 0
        self.calls: list[str] = []

    @property
    def call_count(self) -> int:
        return self.read_count + self.read_data_count

    def _fails(self, callback: str) -> bool:
        return self.fail_at is True or self.fail_at == callback

    def read(self, event_factory: Any | None, data: str | bytes) -> CloudEvent:
        self.read_count += 1
        self.calls.append("read")
        if self._fails("read"):
            raise SimulatedReadFailure("structured read failed")
        return self._json.read(event_factory, data)

    def read_data(
        self, body: bytes, datacontenttype: str | None
    ) -> dict[str, Any] | str | bytes | None:
        self.read_data_count += 1
        self.calls.append("read_data")
        if self._fails("read_data"):
            raise SimulatedReadFailure("binary read_data failed")
        return self._json.read_data(body, datacontenttype)

    def write(self, event: CloudEvent) -> bytes:
        self.calls.append("write")
        return self._json.write(event)

    def write_data(
        self,
        data: dict[str, Any] | str | bytes | None,
        datacontenttype: str | None,
    ) -> bytes:
        return self._json.write_data(data, datacontenttype)

    def get_content_type(self) -> str:
        return self._json.get_content_type()


@dataclass(frozen=True)
class BindingCase:
    name: str
    binding: Any
    receive: Any


BINDINGS = [
    pytest.param(BindingCase("http", http, receive_http), id="http"),
    pytest.param(BindingCase("kafka", kafka, receive_kafka), id="kafka"),
]
MODES = [
    pytest.param("structured", id="structured"),
    pytest.param("binary", id="binary"),
]


def make_event() -> CloudEvent:
    return CloudEvent(
        attributes={
            "id": "decision-1",
            "source": "/receive/test",
            "type": "com.example.decision",
            "specversion": "1.0",
            "datacontenttype": "application/json",
        },
        data={"deliver": True, "count": 1},
    )


def make_message(case: BindingCase, mode: str) -> Any:
    return getattr(case.binding, f"to_{mode}")(make_event(), JSONFormat())


def make_registry(recorder: RecordingFormat) -> FormatRegistry:
    return FormatRegistry(
        {
            JSONFormat.CONTENT_TYPE: recorder,
            JSONFormat.DEFAULT_CONTENT_TYPE: recorder,
        }
    )


@pytest.mark.parametrize("case", BINDINGS)
@pytest.mark.parametrize("mode", MODES)
def test_successful_receive_records_one_decode_and_delivery(
    case: BindingCase, mode: str
) -> None:
    message = make_message(case, mode)
    recorder = RecordingFormat()
    delivered: list[CloudEvent] = []

    decision = case.receive(
        message,
        registry=make_registry(recorder),
        handler=delivered.append,
    )

    assert isinstance(decision, ReceiveDecision)
    assert decision.binding == case.name
    assert decision.mode == mode
    assert decision.ok
    assert decision.error is None
    assert recorder.call_count == 1
    assert recorder.calls == ["read" if mode == "structured" else "read_data"]
    assert decision.decode_calls == 1
    assert decision.factory_calls == 1
    assert decision.handler_calls == 1
    assert decision.stage_names == [
        ReceiveStage.SELECT_MODE,
        ReceiveStage.READ,
        ReceiveStage.VALIDATE,
        ReceiveStage.DELIVER,
    ]
    assert decision.completed_stages == decision.stage_names
    assert all(stage.completed for stage in decision.stages)
    assert decision.delivered is True
    assert len(delivered) == 1
    assert delivered[0].get_id() == "decision-1"
    assert delivered[0].get_data() == {"deliver": True, "count": 1}


@pytest.mark.parametrize("case", BINDINGS)
@pytest.mark.parametrize("mode", MODES)
def test_failed_format_read_preserves_completed_stages_and_no_delivery(
    case: BindingCase, mode: str
) -> None:
    message = make_message(case, mode)
    fail_at = "read" if mode == "structured" else "read_data"
    recorder = RecordingFormat(fail_at=fail_at)
    delivered: list[CloudEvent] = []

    decision = case.receive(
        message,
        registry=make_registry(recorder),
        handler=delivered.append,
    )

    assert not decision.ok
    assert decision.event is None
    assert isinstance(decision.error, SimulatedReadFailure)
    assert recorder.call_count == 1
    assert recorder.calls == [fail_at]
    assert decision.decode_calls == 1
    assert decision.factory_calls == 0
    assert decision.handler_calls == 0
    assert decision.stage_names == [
        ReceiveStage.SELECT_MODE,
        ReceiveStage.READ,
    ]
    assert decision.completed_stages == [ReceiveStage.SELECT_MODE]
    assert decision.failed_stage == ReceiveStage.READ
    assert decision.stages[0].completed
    assert decision.stages[1].failed
    assert "validate" not in decision.stage_names
    assert "deliver" not in decision.stage_names
    assert decision.delivered is False
    assert delivered == []
    assert decision.to_dict()["failed_stage"] == ReceiveStage.READ


@pytest.mark.parametrize("case", BINDINGS)
def test_native_binding_populates_raised_failure_receipt(
    case: BindingCase,
) -> None:
    message = make_message(case, "structured")
    recorder = RecordingFormat(fail_at="read")
    receipt = ReceiveDecision()

    with pytest.raises(SimulatedReadFailure):
        case.binding.from_kafka(
            message, recorder, receipt=receipt
        ) if case.name == "kafka" else case.binding.from_http(
            message, recorder, receipt=receipt
        )

    assert receipt.mode == "structured"
    assert receipt.read_calls == 1
    assert receipt.completed_stages == [ReceiveStage.SELECT_MODE]
    assert receipt.failed_stage == ReceiveStage.READ
    assert isinstance(receipt.error, SimulatedReadFailure)


@pytest.mark.parametrize("case", BINDINGS)
def test_raise_on_error_keeps_failure_receipt(case: BindingCase) -> None:
    message = make_message(case, "structured")
    recorder = RecordingFormat(fail_at=True)
    decision = ReceiveDecision()

    with pytest.raises(SimulatedReadFailure) as exc_info:
        case.receive(
            message,
            recorder,
            decision=decision,
            raise_on_error=True,
        )

    assert exc_info.value.receipt is decision
    assert decision.read_calls == 1
    assert decision.completed_stages == [ReceiveStage.SELECT_MODE]
    assert decision.delivered is False


def test_delivery_on_one_decision_is_idempotent() -> None:
    message = make_message(BindingCase("http", http, receive_http), "structured")
    decision = receive_http(message, RecordingFormat())
    delivered: list[CloudEvent] = []

    first = decision.deliver_to(delivered.append)
    second = decision.deliver_to(delivered.append)

    assert first is None
    assert second is None
    assert len(delivered) == 1
    assert decision.handler_calls == 1
    assert decision.delivery_attempts == 1
    assert decision.delivered is True


def test_receiver_records_one_decision_per_receive() -> None:
    receiver = CloudEventReceiver(handler=lambda event: None)
    http_message = make_message(BindingCase("http", http, receive_http), "structured")
    kafka_message = make_message(
        BindingCase("kafka", kafka, receive_kafka), "structured"
    )

    http_decision = receiver.receive_http(http_message)
    kafka_decision = receiver.receive_kafka(kafka_message)

    assert [decision.binding for decision in receiver.decisions] == [
        "http",
        "kafka",
    ]
    assert receiver.last_decision is kafka_decision
    assert http_decision.ok and kafka_decision.ok
    assert http_decision.delivered and kafka_decision.delivered


def test_receipt_book_reuses_failed_decision_without_second_decode() -> None:
    case = BindingCase("http", http, receive_http)
    message = make_message(case, "structured")
    recorder = RecordingFormat(fail_at="read")
    book = ReceiptBook()

    first = book.receive_http(
        "idem-fail-1", message, recorder, registry=make_registry(recorder)
    )
    second = book.receive_http(
        "idem-fail-1",
        message,
        RecordingFormat(),
        registry=FormatRegistry(),
    )

    assert first is second
    assert first.idempotency_key == "idem-fail-1"
    assert recorder.call_count == 1
    assert first.completed_stages == [ReceiveStage.SELECT_MODE]
    assert first.failed_stage == ReceiveStage.READ
    assert first.delivered is False
