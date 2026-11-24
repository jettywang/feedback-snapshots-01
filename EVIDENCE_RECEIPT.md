# Offline evidence receipts — cross-binding correlation

Optional, dependency-free (Python standard library only) forensics add-on for
correlating the **same canonical CloudEvent** across the HTTP entry point, the
Kafka/queue log, redeliveries and format conversions. It performs no network
I/O and does not change any existing binding behaviour.

- Canonical implementation: `src/cloudevents/core/receipt.py`
- Also importable as: `cloudevents.core.evidence`, `cloudevents.core.receipts`,
  `cloudevents.core.forensics`, and top-level `cloudevents.receipt` /
  `cloudevents.evidence` / `cloudevents.receipts`
- Tests: `tests/test_core/test_evidence_receipt.py` (25 behaviour tests)
- Runnable proof: `samples/evidence_receipt_demo.py`

```sh
.venv/bin/python -m pytest -q -o addopts= tests/test_core/test_evidence_receipt.py
.venv/bin/python samples/evidence_receipt_demo.py
```

## Evidence model

Each `EvidenceReceipt` keeps these facts in **separate** fields:

| Concern | Field | Notes |
| --- | --- | --- |
| Stable business identity | `identity` (`EventIdentity`: `source` + `id`) | CloudEvents uniqueness pair; stable across redelivery/conversion |
| Carrier content digest | `content_digest` (`Digest`, default `sha-256`) | Hash over the actual carrier bytes / framed HTTP/Kafka message |
| Canonical content digest | `canonical_digest` | Binding-independent hash; equal across format conversions of one event |
| Receipt time | `recorded_at` / `created_at` / `timestamp` | When the receipt was recorded — never folded into a digest |
| Event time | `event_time` | The CloudEvent's own `time` attribute, kept distinct |
| Private extensions | `extensions` (`ExtensionCommitment`) | Salted/HMAC digests only — **never clear-text values** |
| Evidence strength | `evidence_tier` / `degraded` / `digest_basis` | `carrier` vs explicit `canonical` degradation |

Receipts and reports are plain JSON via `.to_dict()` / `.to_json()` and can be
reloaded offline with `EvidenceReceipt.from_dict()` / `.from_json()`. An
optional `seal_key` adds an HMAC seal over the receipt body.

## Quickstart

```python
from cloudevents.core.receipt import (
    receipt_for_http, receipt_for_kafka, cross_check,
    build_conversion_pair, compare_events,
)

# At the HTTP ingress / Kafka consumer, hash the real message and parse identity.
http_receipt = receipt_for_http(http_message)      # cloudevents HTTPMessage
kafka_receipt = receipt_for_kafka(kafka_message)   # cloudevents KafkaMessage
report = cross_check(http_receipt, kafka_receipt,
                     left_carrier=http_message, right_carrier=kafka_message)
assert report.identity_match and report.ok

# Synthetic/converted event: one receipt for the original bytes, one for the CE.
pair = build_conversion_pair(original_bytes, event,
                             binding="http", mode="structured")
print(pair.cross_check().to_text())
```

`cross_check` is deliberately forgiving: it accepts `EvidenceReceipt`,
`ReceiptPair`, `HTTPMessage`/`KafkaMessage`, `CloudEvent` objects, plain event
`dict`s, receipt dicts and receipt JSON strings. Aliases: `reconcile`,
`correlate`, `compare_receipts`, `compare_events`, `correlate_messages`,
`verify_receipt_pair`.

## How each requirement is met / proven

- **Stable business identity (`source`,`id`)** — `EventIdentity.same_event`;
  `test_identity_is_the_source_id_pair`,
  `test_business_identity_stable_across_http_and_kafka_carriers`.
- **Carrier digest and time stored separately** — `content_digest` vs
  `recorded_at`/`event_time`; receipt time is not part of the hash:
  `test_recorded_time_is_separate_from_digest_and_event_time`.
- **Private extensions only as verifiable digests** — random salted SHA-256
  commitments by default, optional HMAC key; `.verify_extension(name, value)`;
  serialised receipt never contains the raw value:
  `test_private_extension_only_leaves_verifiable_salted_digest`,
  `test_keyed_extension_commitment_requires_key_to_verify`.
- **Two receipts for a synthetic event (original + converted)** —
  `build_conversion_pair(...).original` / `.converted` (also
  `.original_receipt`, `.converted_receipt`, tuple-unpack):
  `test_conversion_pair_keeps_two_receipts_and_cross_checks`.
- **Cross-check identity and content digest** — `ReconciliationReport` carries
  `id_match`, `source_match`, `identity_match`/`same_event`,
  `carrier_digest_match`/`content_digest_match`, `canonical_digest_match` and
  recomputed `left_intact`/`right_intact`. Equal carrier digests mean exact
  redelivery (`correlated_identical_carrier`); differing carrier digests with
  equal canonical digest mean format conversion (`correlated_re_encoded`):
  `test_redelivery_of_identical_message_is_identical_carrier`,
  `test_kafka_binary_receipt_and_cross_binding_check`,
  `test_http_then_kafka_reread_rebuild_keeps_consistent_verdict`. Matching
  identity but a differing canonical digest yields `content_mismatch`
  (`ok=False`): `test_same_identity_but_changed_content_is_content_mismatch`.
- **Binary and JSON/structured carriers + evidence degradation** — real
  `cloudevents.core.bindings.http` / `.kafka` binary and structured entry
  points are framed and digested; `canonical_receipt(event)` is explicitly
  marked `degraded=True` when no carrier bytes exist:
  `test_http_binary_ingress_receipt_parses_identity_and_verifies`,
  `test_http_structured_json_receipt`,
  `test_canonical_only_receipt_is_explicit_degradation`.
- **Same `id`, different `source` → report names the source difference** —
  verdict `source_mismatch`, `source_difference=True`, `"source"` in
  `differences`, both sources in `sources`/summary/text/JSON:
  `test_same_id_different_source_report_points_out_source_difference`.

## The required source-difference report

For two events with `id="X-1"` and sources `/payments/http` vs
`/billing/kafka`, `compare_events(a, b).to_text()` prints:

```text
verdict: source_mismatch (ok=False, correlated=False)
CloudEvent identity mismatch: id='X-1' matches, but source differs: left='/payments/http' vs right='/billing/kafka'; the receipts do not prove the same canonical event.
身份不一致：两条事件的 id 相同（X-1），但 source 存在差异：左侧为 /payments/http，右侧为 /billing/kafka；不能认定为同一规范事件。
identity: id_match=True, source_match=False, identity_match=False
differences: source
  [error] SOURCE_MISMATCH: source differs: '/payments/http' != '/billing/kafka'
```

`report.to_dict()` is JSON-serialisable for log/audit pipelines and includes
`id_match`, `source_match`, `source_difference`, `differences` and `sources`.
Mere equality of `id` is therefore never treated as correlation.
