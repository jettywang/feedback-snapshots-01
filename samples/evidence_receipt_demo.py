#!/usr/bin/env python3
"""Offline evidence receipts: cross-binding correlation demo.

Run from the repository root with the SDK environment:

    .venv/bin/python samples/evidence_receipt_demo.py

The script performs the checks and exits non-zero if any expectation fails.
It never accesses the network.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from cloudevents.core.bindings import http as http_binding
from cloudevents.core.bindings import kafka as kafka_binding
from cloudevents.core.formats.json import JSONFormat
from cloudevents.core.receipt import (
    EvidenceReceipt,
    build_conversion_pair,
    canonical_receipt,
    compare_events,
    create_receipt,
    cross_check,
    receipt_for_http,
    receipt_for_kafka,
)
from cloudevents.core.v1.event import CloudEvent

WHEN = datetime(2026, 11, 20, 8, 0, tzinfo=timezone.utc)
RECORDED = datetime(2026, 11, 20, 9, 30, tzinfo=timezone.utc)
SECRET = "tenant-token-7"


def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main() -> int:
    event = CloudEvent(
        attributes={
            "id": "order-42",
            "source": "/shop/orders",
            "type": "com.shop.order.created",
            "time": WHEN,
            "xtoken": SECRET,  # private extension: digest only
        },
        data={"order_id": 42, "total": "19.99"},
    )

    # 1) Synthetic event: keep the ORIGINAL legacy message and CONVERTED receipt.
    section("1. Synthetic conversion -> original + converted receipts")
    original_message = json.dumps({"legacy_id": 42}).encode()
    pair = build_conversion_pair(
        original_message,
        event,
        binding="http",
        mode="structured",
        recorded_at=RECORDED,
    )
    report = pair.cross_check()
    print(report.to_text())
    assert report.ok and report.identity_match
    assert report.carrier_digest_match is False
    assert report.canonical_digest_match is True

    # 2) Redelivery: identical bytes -> identical carrier digest.
    section("2. Redelivery of the same carrier bytes")
    http_message = http_binding.to_binary(event, JSONFormat())
    first = create_receipt(event, carrier=http_message, recorded_at=RECORDED)
    redelivered = http_binding.HTTPMessage(
        headers=dict(http_message.headers), body=bytes(http_message.body)
    )
    second = create_receipt(event, carrier=redelivered, recorded_at=RECORDED)
    redeliver_report = cross_check(
        first, second, left_carrier=http_message, right_carrier=redelivered
    )
    print(redeliver_report.to_text())
    assert redeliver_report.verdict == "correlated_identical_carrier"

    # 3) Cross-binding: HTTP ingress vs Kafka queue log.
    section("3. HTTP entry vs Kafka queue (same canonical event)")
    kafka_message = kafka_binding.to_binary(event, JSONFormat())
    http_ingress = receipt_for_http(http_message, recorded_at=RECORDED)
    kafka_log = receipt_for_kafka(kafka_message, recorded_at=RECORDED)
    cross_binding = cross_check(
        http_ingress,
        kafka_log,
        left_carrier=http_message,
        right_carrier=kafka_message,
    )
    print(cross_binding.to_text())
    assert cross_binding.ok and cross_binding.left_intact and cross_binding.right_intact

    # 4) The required negative case: same id, different source.
    section("4. Two events with only the same id -> report the source difference")
    event_a = CloudEvent(
        attributes={"id": "X-1", "source": "/payments/http", "type": "t", "time": WHEN}
    )
    event_b = CloudEvent(
        attributes={"id": "X-1", "source": "/billing/kafka", "type": "t", "time": WHEN}
    )
    source_report = compare_events(event_a, event_b)
    print(source_report.to_text())
    assert source_report.id_match and not source_report.source_match
    assert source_report.source_difference and "source" in source_report.differences
    assert not source_report.ok

    # 5) Private extension is digest-only but verifiable offline.
    section("5. Private extension: verifiable digest, no clear text")
    print("extension commitment:", first.extension_digests["xtoken"])
    print("correct value verifies:", first.verify_extension("xtoken", SECRET))
    print("wrong value verifies:  ", first.verify_extension("xtoken", "guess"))
    assert SECRET not in first.to_json()
    assert first.verify_extension("xtoken", SECRET)

    # 6) Evidence degradation + offline JSON reload.
    section("6. Canonical-only degradation and offline JSON reload")
    degraded = canonical_receipt(event, recorded_at=RECORDED)
    print("degraded:", degraded.degraded, "| basis:", degraded.digest_basis)
    restored = EvidenceReceipt.from_json(first.to_json())
    print(
        "reloaded digest still verifies carrier:",
        restored.verify_carrier(http_message),
    )
    assert degraded.degraded and degraded.verify_canonical(event)
    assert restored.verify_carrier(http_message)

    section("ALL EVIDENCE-RECEIPT CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
