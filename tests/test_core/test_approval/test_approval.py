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

"""Tests for transport-independent CloudEvent content approvals."""

from datetime import datetime, timezone
from typing import Any, Callable

import pytest

from cloudevents.core.approval import (
    ApprovalError,
    ApprovalMismatchError,
    ApprovalPhase,
    ApprovalSerializationError,
    EventApproval,
    approve,
    verify,
    verify_event,
)
from cloudevents.core.bindings import amqp, http, kafka, rabbitmq
from cloudevents.core.formats.json import JSONFormat
from cloudevents.core.v03.event import CloudEvent as CloudEventV03
from cloudevents.core.v1.event import CloudEvent


def make_event(**overrides: Any) -> CloudEvent:
    attributes: dict[str, Any] = {
        "id": "evt-1",
        "source": "/orders",
        "type": "com.example.order.created",
        "specversion": "1.0",
        "subject": "orders/42",
        "time": datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "tenant": "acme",
        "region": "eu-west-1",
    }
    attributes.update(overrides.pop("attributes", {}))
    data = overrides.pop("data", {"order_id": 42, "total": 10.5, "paid": True})
    return CloudEvent(attributes=attributes, data=data)


def approval_jobs(
    event: CloudEvent,
    approval: EventApproval | None = None,
) -> list[tuple[str, Callable[[], object]]]:
    """Queue the same event for delivery through two different bindings."""
    return [
        ("http-binary", lambda: http.to_binary_event(event, approval=approval)),
        (
            "http-structured",
            lambda: http.to_structured_event(event, approval=approval),
        ),
        ("kafka-binary", lambda: kafka.to_binary_event(event, approval=approval)),
        (
            "kafka-structured",
            lambda: kafka.to_structured_event(event, approval=approval),
        ),
        ("amqp-binary", lambda: amqp.to_binary_event(event, approval=approval)),
        (
            "amqp-structured",
            lambda: amqp.to_structured_event(event, approval=approval),
        ),
        ("rabbitmq-binary", lambda: rabbitmq.to_binary_event(event, approval=approval)),
        (
            "rabbitmq-structured",
            lambda: rabbitmq.to_structured_event(event, approval=approval),
        ),
    ]


def test_approve_and_verify_unchanged_event() -> None:
    event = make_event()
    approval = approve(event)

    verify(approval, event)
    verify_event(event, approval)
    assert approval.matches(event)


def test_approval_survives_binding_switch_for_same_event() -> None:
    event = make_event()
    approval = approve(event)

    # The approval is transport independent: every binding + content mode is a
    # legitimate delivery choice for the same approved event.
    for name, send in approval_jobs(event, approval):
        message = send()
        assert message is not None, name
        verify(approval, event)

    assert approval.extensions == ("region", "tenant")
    assert approval.specversion == "1.0"


def test_approval_verifies_after_parse_of_sent_message() -> None:
    event = make_event(attributes={"counter": "7"})
    approval = approve(event)

    binary = http.to_binary_event(event)
    parsed = http.from_binary_event(binary)
    assert parsed.get_extension("counter") == "7"
    verify(approval, parsed)

    structured = kafka.to_structured_event(event)
    parsed_again = kafka.from_structured_event(structured)
    verify(approval, parsed_again)


@pytest.mark.parametrize(
    "binding_to",
    [
        http.to_binary_event,
        http.to_structured_event,
        kafka.to_binary_event,
        kafka.to_structured_event,
        amqp.to_binary_event,
        amqp.to_structured_event,
        rabbitmq.to_binary_event,
        rabbitmq.to_structured_event,
    ],
)
def test_modified_data_is_rejected_before_publish(
    binding_to: Callable[..., object],
) -> None:
    event = make_event()
    approval = approve(event)

    data = event.get_data()
    assert isinstance(data, dict)
    data["total"] = 99.0  # tamper with approved payload

    with pytest.raises(ApprovalMismatchError) as error:
        binding_to(event, approval=approval)

    assert error.value.phase is ApprovalPhase.PRE_PUBLISH
    assert error.value.mismatches == ("data.total",)
    assert str(error.value).startswith("[phase=pre_publish]")


def test_modified_extension_is_rejected_before_publish() -> None:
    event = make_event()
    approval = approve(event)

    event.get_attributes()["tenant"] = "evil-corp"

    with pytest.raises(ApprovalMismatchError) as error:
        http.to_binary_event(event, approval=approval)

    assert error.value.phase is ApprovalPhase.PRE_PUBLISH
    assert error.value.mismatches == ("attributes.tenant",)


def test_added_extension_is_rejected_normally() -> None:
    event = make_event()
    approval = approve(event)

    event.get_attributes()["injected"] = "value"

    with pytest.raises(ApprovalMismatchError) as error:
        kafka.to_binary_event(event, approval=approval)

    assert error.value.phase is ApprovalPhase.PRE_PUBLISH
    assert "attributes.injected" in error.value.mismatches


def test_removed_extension_is_rejected() -> None:
    event = make_event()
    approval = approve(event)

    del event.get_attributes()["tenant"]

    with pytest.raises(ApprovalMismatchError):
        http.to_structured_event(event, approval=approval)


def test_modified_standard_attribute_is_rejected() -> None:
    event = make_event()
    approval = approve(event)

    event.get_attributes()["subject"] = "orders/43"

    with pytest.raises(ApprovalMismatchError) as error:
        amqp.to_binary_event(event, approval=approval)

    assert error.value.phase is ApprovalPhase.PRE_PUBLISH
    assert error.value.mismatches == ("attributes.subject",)


def test_type_confusion_is_detected() -> None:
    event = make_event(data={"order_id": 42})
    approval = approve(event)

    event.get_data()["order_id"] = "42"
    with pytest.raises(ApprovalMismatchError):
        verify(approval, event)

    # Python considers True == 1; the canonical form must not.
    event = make_event(data={"flag": True})
    approval = approve(event)
    event.get_data()["flag"] = 1
    with pytest.raises(ApprovalMismatchError):
        verify(approval, event)


def test_explicit_verify_uses_verify_phase_by_default() -> None:
    event = make_event()
    approval = approve(event)
    event.get_attributes()["type"] = "com.example.other"

    with pytest.raises(ApprovalMismatchError) as error:
        verify(approval, event)

    assert error.value.phase is ApprovalPhase.VERIFY
    assert str(error.value).startswith("[phase=verify]")


def test_compact_token_round_trip() -> None:
    event = make_event()
    approval = approve(event)

    token = approval.to_dict()
    assert token["extensions"] == ["region", "tenant"]
    assert "canonical" not in token

    restored = EventApproval.from_dict(token)
    verify(restored, event)

    event.get_attributes()["tenant"] = "other"
    with pytest.raises(ApprovalMismatchError) as error:
        http.to_binary_event(event, approval=restored)
    assert error.value.phase is ApprovalPhase.PRE_PUBLISH
    # A compact token has no payload copy for path-level diagnostics.
    assert error.value.mismatches == ()
    assert "digest does not match" in str(error.value)


@pytest.mark.parametrize(
    "token",
    [
        {},
        {"approval_version": 1, "algorithm": "sha256"},
        {"approval_version": 99, "algorithm": "sha256", "digest": "00"},
        {"approval_version": 1, "algorithm": "nope", "digest": "00"},
        {"approval_version": 1, "algorithm": "sha256", "digest": ""},
        "not-a-mapping",
    ],
)
def test_malformed_token_has_approve_phase(token: Any) -> None:
    with pytest.raises(ApprovalSerializationError) as error:
        EventApproval.from_dict(token)  # type: ignore[arg-type]

    assert error.value.phase is ApprovalPhase.APPROVE


def test_approve_failure_has_approve_phase() -> None:
    event = make_event(data={"bad": object()})

    with pytest.raises(ApprovalError) as error:
        approve(event)

    assert error.value.phase is ApprovalPhase.APPROVE
    assert not isinstance(error.value, ApprovalMismatchError)


def test_approve_rejects_unsupported_algorithm() -> None:
    with pytest.raises(ApprovalError) as error:
        approve(make_event(), algorithm="definitely-not-a-hash")

    assert error.value.phase is ApprovalPhase.APPROVE


def test_approve_rejects_non_finite_numbers() -> None:
    with pytest.raises(ApprovalError) as error:
        approve(make_event(data={"ratio": float("nan")}))

    assert error.value.phase is ApprovalPhase.APPROVE


def test_bindings_without_approval_are_unchanged() -> None:
    event = make_event()

    # No approval passed: previous behavior is preserved exactly.
    assert http.to_binary_event(event).headers["ce-id"] == "evt-1"
    assert kafka.to_structured_event(event).headers["content-type"]
    assert amqp.to_binary_event(event).application_data
    assert rabbitmq.to_binary_event(event).body


def test_v03_event_extension_approval() -> None:
    event = CloudEventV03(
        attributes={
            "id": "evt-3",
            "source": "/legacy",
            "type": "com.example.legacy",
            "specversion": "0.3",
            "schemaurl": "https://example.com/schema",
            "tenant": "acme",
        },
        data={"value": 1},
    )
    approval = approve(event)

    # schemaurl is a standard v0.3 attribute, not an extension.
    assert approval.extensions == ("tenant",)
    assert approval.specversion == "0.3"

    message = http.to_structured_event(event, approval=approval)
    assert b"schemaurl" in message.body

    event.get_attributes()["tenant"] = "other"
    with pytest.raises(ApprovalMismatchError) as error:
        http.to_structured_event(event, approval=approval)
    assert error.value.phase is ApprovalPhase.PRE_PUBLISH


def test_kafka_partition_key_not_part_of_approval() -> None:
    event = make_event(attributes={"partitionkey": "orders"})
    approval = approve(event)

    # Transport metadata derived from the event does not affect the approval.
    message = kafka.to_structured_event(event, approval=approval)
    assert message.key == "orders"
    verify(approval, event)


def test_datetime_and_bytes_data_are_covered() -> None:
    event = make_event(
        data={
            "when": datetime(2024, 5, 6, 7, 8, 9, 123456, tzinfo=timezone.utc),
            "blob": b"\x00\x01\x02",
        }
    )
    approval = approve(event)

    data = event.get_data()
    assert isinstance(data, dict)
    data["blob"] = b"\x00\x01\x03"
    with pytest.raises(ApprovalMismatchError) as error:
        http.to_binary_event(event, approval=approval)
    assert "data.blob" in error.value.mismatches


def test_queued_jobs_detect_tampering_for_both_bindings() -> None:
    """Queue one synthetic event through two bindings, then tamper once."""
    event = make_event()
    approval = approve(event)
    queue = approval_jobs(event, approval)

    # Legitimate delivery through either binding keeps the approval valid.
    results = [send() for _, send in queue]
    assert len(results) == len(queue)

    event.get_data()["order_id"] = 43

    for name, send in queue:
        with pytest.raises(ApprovalMismatchError) as error:
            send()
        assert error.value.phase is ApprovalPhase.PRE_PUBLISH, name


def test_keyed_approval_round_trip() -> None:
    event = make_event()
    approval = approve(event, key=b"shared-secret")
    assert approval.keyed

    verify(approval, event)

    token = approval.to_dict()
    assert token["keyed"] is True
    assert "shared-secret" not in str(token)
    assert "shared-secret" not in repr(approval)

    restored = EventApproval.from_dict(token, key="shared-secret")
    verify(restored, event)

    http.to_binary_event(event, approval=restored)

    event.get_data()["order_id"] = 43
    with pytest.raises(ApprovalMismatchError) as error:
        http.to_binary_event(event, approval=restored)
    assert error.value.phase is ApprovalPhase.PRE_PUBLISH


def test_keyed_approval_digest_cannot_be_recomputed_without_key() -> None:
    event = make_event()
    approval = approve(event, key=b"shared-secret")
    event.get_data()["total"] = 1.0

    # Hashing the modified content without the shared key produces a different
    # digest, so the keyed approval cannot be reproduced.
    forged = approve(event)
    assert forged.digest != approval.digest
    with pytest.raises(ApprovalMismatchError) as error:
        verify(approval, event)
    assert error.value.phase is ApprovalPhase.VERIFY
    assert not approval.matches(event)

    # And the forged token does not approve the original content either.
    with pytest.raises(ApprovalMismatchError):
        verify(EventApproval.from_dict(forged.to_dict()), make_event())


def test_wrong_key_fails_verification() -> None:
    event = make_event()
    token = approve(event, key=b"shared-secret").to_dict()

    with pytest.raises(ApprovalMismatchError) as error:
        verify(EventApproval.from_dict(token, key=b"wrong"), event)

    assert error.value.phase is ApprovalPhase.VERIFY


def test_keyed_token_without_key_cannot_be_verified() -> None:
    event = make_event()
    restored = EventApproval.from_dict(
        approve(event, key=b"shared-secret").to_dict()
    )

    with pytest.raises(ApprovalError) as error:
        verify(restored, event)

    assert error.value.phase is ApprovalPhase.VERIFY
    assert not isinstance(error.value, ApprovalMismatchError)


def test_plain_and_keyed_digests_differ() -> None:
    event = make_event()
    assert approve(event).digest != approve(event, key=b"k").digest


def test_token_extension_metadata_must_match_event() -> None:
    event = make_event()
    token = approve(event).to_dict()

    # The digest is untouched, so only the recorded extension set can be
    # detected; a worker must not trust a stale or edited extension list.
    token["extensions"] = ["tenant"]
    restored = EventApproval.from_dict(token)

    with pytest.raises(ApprovalMismatchError) as error:
        http.to_binary_event(event, approval=restored)

    assert error.value.phase is ApprovalPhase.PRE_PUBLISH
    assert error.value.mismatches == ("extensions.region",)


def test_extension_metadata_check_runs_after_digest() -> None:
    """A content change is reported as content, not as extension metadata."""
    event = make_event()
    approval = approve(event)
    event.get_attributes()["tenant"] = "other"

    with pytest.raises(ApprovalMismatchError) as error:
        verify(approval, event)

    assert error.value.mismatches == ("attributes.tenant",)


def test_token_without_extension_list_skips_metadata_check() -> None:
    event = make_event()
    token = approve(event).to_dict()
    token["extensions"] = None

    restored = EventApproval.from_dict(token)
    verify(restored, event)

    event.get_attributes()["tenant"] = "other"
    with pytest.raises(ApprovalMismatchError):
        verify(restored, event)


def test_key_not_exposed_through_dataclass_introspection() -> None:
    import dataclasses

    approval = approve(make_event(), key=b"top-secret")

    assert "top-secret" not in repr(approval)
    assert "top-secret" not in str(dataclasses.asdict(approval))
    assert "_shared_key" not in {f.name for f in dataclasses.fields(approval)}
    assert "top-secret" not in str(approval.to_dict())
