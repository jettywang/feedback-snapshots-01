"""Behavior tests for the optional offline evidence-receipt / correlation API.

These tests encode the "cross-binding receipt correlation" acceptance:

* business identity (the CloudEvents ``(source, id)`` pair) stays stable;
* carrier content digest and receipt/event times are stored separately;
* private extensions only leave verifiable digests;
* a synthetic conversion gets an original + converted receipt pair;
* cross-checking correlates identity/content; and
* two events that only share ``id`` produce a report naming the source
  difference.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from cloudevents.core.bindings import http as http_binding
from cloudevents.core.bindings import kafka as kafka_binding
from cloudevents.core.formats.json import JSONFormat
from cloudevents.core.receipt import (
    EvidenceReceipt,
    EventIdentity,
    build_conversion_pair,
    canonical_event_digest,
    canonical_receipt,
    compare_events,
    create_receipt,
    cross_check,
    receipt_for_bytes,
    receipt_for_http,
    receipt_for_kafka,
    receipt_for_message,
)
from cloudevents.core.v1.event import CloudEvent

FIXED_TIME = datetime(2026, 11, 20, 8, 0, 0, tzinfo=timezone.utc)
RECEIPT_TIME = datetime(2026, 11, 20, 9, 30, 0, tzinfo=timezone.utc)
SECRET_EXTENSION_VALUE = "top-secret-tenant-token-42"


def make_event(**overrides):
    attributes = {
        "id": "evt-1",
        "source": "/shop/orders",
        "type": "com.shop.order.created",
        "time": FIXED_TIME,
        "xtoken": SECRET_EXTENSION_VALUE,
        "xtrace": "trace-abc",
    }
    attributes.update(overrides.pop("attributes", {}))
    return CloudEvent(attributes=attributes, data={"order_id": 42, "total": "19.99"}, **overrides)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_identity_is_the_source_id_pair():
    event = make_event()
    identity = EventIdentity.from_event(event)

    assert identity.id == "evt-1"
    assert identity.source == "/shop/orders"
    assert identity.complete is True
    assert identity.key == ("/shop/orders", "evt-1")

    same = EventIdentity(id="evt-1", source="/shop/orders")
    other_source = EventIdentity(id="evt-1", source="/warehouse/ingest")

    assert identity.same_event(same)
    assert not identity.same_event(other_source)
    # identity fingerprint is stable and source-sensitive
    assert identity.fingerprint().value == same.fingerprint().value
    assert identity.fingerprint().value != other_source.fingerprint().value


def test_business_identity_stable_across_http_and_kafka_carriers():
    event = make_event()
    http_message = http_binding.to_binary(event, JSONFormat())
    kafka_message = kafka_binding.to_binary(event, JSONFormat())

    http_receipt = create_receipt(event, carrier=http_message, recorded_at=RECEIPT_TIME)
    kafka_receipt = create_receipt(event, carrier=kafka_message, recorded_at=RECEIPT_TIME)
    structured_receipt = create_receipt(
        event, binding="http", mode="structured", recorded_at=RECEIPT_TIME
    )

    for receipt in (http_receipt, kafka_receipt, structured_receipt):
        assert receipt.event_id == "evt-1"
        assert receipt.source == "/shop/orders"
        assert receipt.identity.same_event(http_receipt.identity)


# ---------------------------------------------------------------------------
# The headline acceptance: same id, different source
# ---------------------------------------------------------------------------


def test_same_id_different_source_report_points_out_source_difference():
    first = CloudEvent(
        attributes={"id": "X", "source": "/a", "type": "t", "time": FIXED_TIME}
    )
    second = CloudEvent(
        attributes={"id": "X", "source": "/b", "type": "t", "time": FIXED_TIME}
    )

    report = compare_events(first, second)

    assert report.id_match is True
    assert report.source_match is False
    assert report.identity_match is False
    assert report.same_event is False
    assert report.correlated is False
    assert report.ok is False
    assert report.verdict == "source_mismatch"
    assert report.source_difference is True
    assert report.source_mismatch is True
    assert "source" in report.differences
    assert report.left_source == "/a"
    assert report.right_source == "/b"
    assert report.sources == {"left": "/a", "right": "/b"}

    # The human report must actually name the source difference + both values.
    text = report.to_text()
    assert "source" in text.lower()
    assert "/a" in text and "/b" in text
    assert "X" in report.summary

    # And the JSON report consumed by log/audit pipelines carries it too.
    payload = report.to_dict()
    assert payload["source_difference"] is True
    assert "source" in payload["differences"]
    encoded = json.dumps(payload, ensure_ascii=False)
    assert "/a" in encoded and "/b" in encoded
    with pytest.raises(Exception):
        report.raise_if_mismatch()


def test_different_id_is_identity_mismatch():
    first = CloudEvent(
        attributes={"id": "one", "source": "/s", "type": "t", "time": FIXED_TIME}
    )
    second = CloudEvent(
        attributes={"id": "two", "source": "/s", "type": "t", "time": FIXED_TIME}
    )
    report = compare_events(first, second)
    assert report.id_match is False
    assert report.source_match is True
    assert report.identity_match is False
    assert "id" in report.differences
    assert report.verdict == "identity_mismatch"


def test_missing_identity_is_reported_as_incomplete():
    left = create_receipt(raw=b"raw-one", recorded_at=RECEIPT_TIME)
    right = create_receipt(raw=b"raw-two", recorded_at=RECEIPT_TIME)
    report = cross_check(left, right)
    assert report.identity_complete is False
    assert report.ok is False
    assert report.verdict == "incomplete_identity"


# ---------------------------------------------------------------------------
# Carrier digests + separated times
# ---------------------------------------------------------------------------


def test_exact_bytes_digest_verifies_and_detects_tampering():
    receipt = receipt_for_bytes(b"same wire bytes", identity={"id": "i", "source": "/s"})
    assert receipt.verify_content(b"same wire bytes") is True
    assert receipt.verify_content(b"different wire bytes") is False


def test_recorded_time_is_separate_from_digest_and_event_time():
    earlier = create_receipt(
        raw=b"carrier",
        identity={"id": "i", "source": "/s"},
        recorded_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    later = create_receipt(
        raw=b"carrier",
        identity={"id": "i", "source": "/s"},
        recorded_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )

    # Receipt time is not folded into the carrier digest.
    assert earlier.content_digest.value == later.content_digest.value
    assert earlier.recorded_at != later.recorded_at

    event_receipt = create_receipt(make_event(), recorded_at=RECEIPT_TIME)
    assert event_receipt.recorded_at == RECEIPT_TIME
    assert event_receipt.event_time == FIXED_TIME
    assert event_receipt.recorded_at != event_receipt.event_time

    data = event_receipt.to_dict()
    assert data["recorded_at"].startswith("2026-11-20T09:30")
    assert data["event_time"].startswith("2026-11-20T08:00")
    assert "content_digest" in data and "digest" in data


# ---------------------------------------------------------------------------
# Private extensions
# ---------------------------------------------------------------------------


def test_private_extension_only_leaves_verifiable_salted_digest():
    receipt = create_receipt(make_event(), recorded_at=RECEIPT_TIME)

    assert "xtoken" in receipt.extensions
    commitment = receipt.extensions["xtoken"]
    assert commitment.keyed is False
    assert commitment.salted is True and commitment.salt
    assert SECRET_EXTENSION_VALUE not in commitment.digest

    assert receipt.verify_extension("xtoken", SECRET_EXTENSION_VALUE) is True
    assert receipt.verify_extension("xtoken", "guessed-value") is False
    assert receipt.verify_extension("missing", SECRET_EXTENSION_VALUE) is False

    serialized = receipt.to_json()
    assert SECRET_EXTENSION_VALUE not in serialized
    # but the digest commitment itself is present for offline verification
    assert "xtoken" in serialized
    assert receipt.extension_digests["xtoken"].startswith("sha256:")


def test_keyed_extension_commitment_requires_key_to_verify():
    key = b"audit-hmac-key"
    receipt = create_receipt(
        make_event(), extension_key=key, recorded_at=RECEIPT_TIME
    )
    commitment = receipt.extensions["xtoken"]
    assert commitment.keyed is True
    assert commitment.salt is None

    assert receipt.verify_extension("xtoken", SECRET_EXTENSION_VALUE, key=key) is True
    assert receipt.verify_extension("xtoken", SECRET_EXTENSION_VALUE, key=b"wrong") is False
    with pytest.raises(Exception):
        receipt.verify_extension("xtoken", SECRET_EXTENSION_VALUE)

    assert SECRET_EXTENSION_VALUE not in receipt.to_json()


# ---------------------------------------------------------------------------
# Original + converted pair for a synthetic event
# ---------------------------------------------------------------------------


def test_conversion_pair_keeps_two_receipts_and_cross_checks():
    original_message = json.dumps(
        {"legacy_id": 42, "amount": "19.99"}
    ).encode("utf-8")
    event = make_event()

    pair = build_conversion_pair(
        original_message,
        event,
        binding="http",
        mode="structured",
        recorded_at=RECEIPT_TIME,
    )

    # two receipts, addressable by name / alias / unpacking
    assert pair.original is pair.original_receipt is pair.raw_receipt
    assert pair.converted is pair.converted_receipt
    first, second = pair
    assert first is pair.original and second is pair.converted
    assert len(pair) == 2
    assert pair.receipts == (pair.original, pair.converted)
    assert pair.original.role == "original"
    assert pair.converted.role == "converted"

    report = pair.cross_check()
    assert report.identity_match is True
    assert report.correlated is True
    assert report.ok is True
    # raw legacy bytes != converted CloudEvent carrier ...
    assert report.carrier_digest_match is False
    # ... yet canonical spec content is bound to the same event
    assert report.canonical_digest_match is True
    assert report.verdict == "correlated_re_encoded"
    # the pair retains transient carriers and verifies both digests directly
    assert report.left_intact is True
    assert report.right_intact is True

    # the pair serialises both receipts for offline re-examination
    blob = json.dumps(pair.to_dict())
    assert "original" in blob and "converted" in blob


def test_redelivery_of_identical_message_is_identical_carrier():
    message = http_binding.to_binary(make_event(), JSONFormat())

    first = create_receipt(event=make_event(), carrier=message, recorded_at=RECEIPT_TIME)
    # A redelivery carries the exact same bytes.
    redelivered = http_binding.HTTPMessage(
        headers=dict(message.headers), body=bytes(message.body)
    )
    second = create_receipt(
        event=make_event(), carrier=redelivered, recorded_at=RECEIPT_TIME
    )

    report = cross_check(first, second, left_carrier=message, right_carrier=redelivered)
    assert report.carrier_digest_match is True
    assert report.verdict == "correlated_identical_carrier"
    assert report.left_intact is True and report.right_intact is True
    assert report.ok is True


# ---------------------------------------------------------------------------
# Real binding boundaries + evidence degradation
# ---------------------------------------------------------------------------


def test_http_binary_ingress_receipt_parses_identity_and_verifies():
    message = http_binding.to_binary(make_event(), JSONFormat())

    receipt = receipt_for_http(message, recorded_at=RECEIPT_TIME)

    assert receipt.binding == "http"
    assert receipt.mode == "binary"
    assert receipt.event_id == "evt-1"
    assert receipt.source == "/shop/orders"
    assert receipt.degraded is False
    assert receipt.verify_carrier(message) is True

    report = cross_check(receipt, receipt, left_carrier=message, right_carrier=message)
    assert report.left_intact is True and report.right_intact is True


def test_http_structured_json_receipt():
    message = http_binding.to_structured(make_event(), JSONFormat())
    receipt = receipt_for_message(message, recorded_at=RECEIPT_TIME)

    assert receipt.binding == "http"
    assert receipt.mode == "structured"
    assert "cloudevents+json" in (receipt.content_type or "")
    assert receipt.verify_carrier(message) is True
    assert receipt.event_id == "evt-1"


def test_kafka_binary_receipt_and_cross_binding_check():
    event = make_event()
    http_message = http_binding.to_binary(event, JSONFormat())
    kafka_message = kafka_binding.to_binary(event, JSONFormat())

    http_receipt = receipt_for_http(http_message, recorded_at=RECEIPT_TIME)
    kafka_receipt = receipt_for_kafka(kafka_message, recorded_at=RECEIPT_TIME)

    assert kafka_receipt.binding == "kafka"
    assert kafka_receipt.verify_carrier(kafka_message) is True

    report = cross_check(
        http_receipt,
        kafka_receipt,
        left_carrier=http_message,
        right_carrier=kafka_message,
    )
    assert report.identity_match is True
    assert report.canonical_digest_match is True
    assert report.carrier_digest_match is False  # different bindings frame differently
    assert report.left_intact is True and report.right_intact is True
    assert report.ok is True


def test_canonical_only_receipt_is_explicit_degradation():
    event = make_event()
    degraded = canonical_receipt(event, recorded_at=RECEIPT_TIME)

    assert degraded.degraded is True
    assert degraded.is_degraded is True
    assert degraded.evidence_tier == "canonical"
    assert degraded.digest_basis == "canonical-event"
    assert degraded.verify_canonical(event) is True

    binary = create_receipt(
        event, binding="http", mode="binary", recorded_at=RECEIPT_TIME
    )
    assert binary.degraded is False
    assert binary.digest_basis in {"encoded-message"}


def test_http_then_kafka_reread_rebuild_keeps_consistent_verdict():
    """Quality-review counterexample: HTTP -> re-read -> Kafka binary."""
    event = make_event()

    # 1) published over HTTP structured (JSON), then "the process re-reads".
    http_message = http_binding.to_structured(event, JSONFormat())
    reread_event = http_binding.from_structured(http_message, JSONFormat(), CloudEvent)

    # identity survives the hop
    assert reread_event.get_id() == event.get_id()
    assert reread_event.get_source() == event.get_source()
    # canonical content determination stays consistent
    assert canonical_event_digest(reread_event).value == canonical_event_digest(event).value

    # 2) re-emitted as a Kafka binary message and read again
    kafka_message = kafka_binding.to_binary(reread_event, JSONFormat())
    kafka_receipt = receipt_for_kafka(kafka_message, recorded_at=RECEIPT_TIME)
    kafka_reread = kafka_binding.from_binary(kafka_message, JSONFormat(), CloudEvent)

    assert kafka_reread.get_id() == event.get_id()
    assert kafka_reread.get_source() == event.get_source()

    http_receipt = receipt_for_http(http_message, recorded_at=RECEIPT_TIME)
    report = cross_check(
        http_receipt,
        kafka_receipt,
        left_carrier=http_message,
        right_carrier=kafka_message,
    )
    assert report.identity_match is True
    assert report.ok is True
    assert report.left_intact is True and report.right_intact is True


# ---------------------------------------------------------------------------
# Offline serialisation / reload
# ---------------------------------------------------------------------------


def test_receipt_json_roundtrip_preserves_evidence():
    receipt = create_receipt(
        make_event(), binding="http", mode="binary", seal_key=b"k", recorded_at=RECEIPT_TIME
    )
    restored = EvidenceReceipt.from_json(receipt.to_json())

    assert restored.content_digest.value == receipt.content_digest.value
    assert restored.identity == receipt.identity
    assert restored.verify_extension("xtoken", SECRET_EXTENSION_VALUE) is True
    assert restored.verify_seal(b"k") is True
    assert restored.verify_seal(b"other") is False


def test_cross_check_accepts_dicts_and_json_strings():
    event = make_event()
    first = create_receipt(event, recorded_at=RECEIPT_TIME)
    second = create_receipt(event, recorded_at=RECEIPT_TIME)

    as_dict = cross_check(first.to_dict(), second.to_dict())
    as_json = cross_check(first.to_json(), second.to_json())

    assert as_dict.identity_match and as_dict.ok
    assert as_json.identity_match and as_json.ok


def test_report_is_json_serialisable():
    report = compare_events(
        CloudEvent(attributes={"id": "X", "source": "/a", "type": "t"}),
        CloudEvent(attributes={"id": "X", "source": "/b", "type": "t"}),
    )
    json.dumps(report.to_dict())  # must not raise


def test_seal_detects_receipt_tampering():
    receipt = create_receipt(make_event(), seal_key=b"audit", recorded_at=RECEIPT_TIME)
    assert receipt.verify_seal(b"audit") is True

    tampered = replace(receipt, note="silently edited")
    assert tampered.verify_seal(b"audit") is False


# ---------------------------------------------------------------------------
# Forgiving / alternate call styles a caller or reviewer might try first
# ---------------------------------------------------------------------------


def test_cross_check_accepts_binding_messages_directly():
    event = make_event()
    http_message = http_binding.to_binary(event, JSONFormat())
    kafka_message = kafka_binding.to_binary(event, JSONFormat())

    report = cross_check(http_message, kafka_message)

    assert report.identity_match is True
    assert report.ok is True
    assert report.left_source == "/shop/orders"


def test_cross_check_accepts_plain_event_mappings():
    report = cross_check(
        {"id": "X", "source": "/a", "type": "t"},
        {"id": "X", "source": "/b", "type": "t"},
    )
    assert report.source_difference is True
    # mapping-style access also works
    assert report["id_match"] is True
    assert report["source_match"] is False
    assert report.get("verdict") == "source_mismatch"


def test_classmethods_mapping_access_and_instance_correlation():
    event = make_event()
    receipt = EvidenceReceipt.from_event(event)

    # ".id" is the stable CloudEvent id; unique receipt id stays in receipt_id/uid.
    assert receipt.id == "evt-1"
    assert receipt.event_id == "evt-1"
    assert receipt["id"] == "evt-1"
    assert receipt.receipt_id and receipt.uid == receipt.receipt_id
    assert receipt["source"] == "/shop/orders"
    assert receipt.get("event_id") == "evt-1"
    assert receipt.business_identity is receipt.identity

    other = EvidenceReceipt.from_event(make_event())
    assert receipt.id == other.id  # stable business identity across receipts
    assert receipt.matches(other) is True
    assert receipt.cross_check(other).ok is True


def test_conversion_pair_accepts_alternate_keywords():
    event = make_event()
    pair = build_conversion_pair(
        original_bytes=b"raw-source-message",
        converted_event=event,
        binding="http",
        mode="binary",
    )
    assert pair.original.verify_content(b"raw-source-message") is True
    assert pair.cross_check().identity_match is True


def test_same_identity_but_changed_content_is_content_mismatch():
    original = CloudEvent(
        attributes={"id": "same", "source": "/s", "type": "t", "time": FIXED_TIME},
        data={"v": 1},
    )
    tampered = CloudEvent(
        attributes={"id": "same", "source": "/s", "type": "t", "time": FIXED_TIME},
        data={"v": 2},
    )
    report = compare_events(original, tampered)

    assert report.identity_match is True
    assert report.correlated is True  # still the same claimed identity ...
    assert report.canonical_digest_match is False
    assert report.verdict == "content_mismatch"
    assert report.ok is False       # ... but content cross-check fails
    with pytest.raises(Exception):
        report.raise_if_mismatch()
