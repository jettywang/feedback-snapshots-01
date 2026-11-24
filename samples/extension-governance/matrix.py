"""
Executable matrix: one historical extension through two SDK generations and
four bindings, with catalogue decisions and separate record streams.

Run:
    python samples/extension-governance/matrix.py            # human table
    python samples/extension-governance/matrix.py --json     # CI artifact
    python samples/extension-governance/matrix.py --assert   # fail on drift
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy import Catalogue, ExtensionSpec, ExtensionStatus, Mode  # noqa: E402
from compat import admit_new, ingest_attributes  # noqa: E402

from cloudevents.core.bindings.amqp import (  # noqa: E402
    AMQPMessage,
    from_binary as amqp_from_binary,
    to_binary as amqp_to_binary,
)
from cloudevents.core.bindings.http import (  # noqa: E402
    HTTPMessage,
    from_binary as http_from_binary,
    from_structured as http_from_structured,
    to_binary as http_to_binary,
    to_structured as http_to_structured,
)
from cloudevents.core.bindings.kafka import (  # noqa: E402
    KafkaMessage,
    from_binary as kafka_from_binary,
    to_binary as kafka_to_binary,
)
from cloudevents.core.bindings.rabbitmq import (  # noqa: E402
    RabbitMQMessage,
    from_binary as rabbit_from_binary,
    to_binary as rabbit_to_binary,
)
from cloudevents.core.formats.json import JSONFormat  # noqa: E402
from cloudevents.core.v1.event import CloudEvent as CoreV1  # noqa: E402
from cloudevents.core.v03.event import CloudEvent as CoreV03  # noqa: E402
from cloudevents.v1.http import (  # noqa: E402
    CloudEvent as LegacyEvent,
    from_http as legacy_from_http,
    to_binary as legacy_to_binary,
    to_structured as legacy_to_structured,
)
from cloudevents.v1.kafka import (  # noqa: E402
    from_binary as legacy_kafka_from_binary,
    to_binary as legacy_kafka_to_binary,
)

FIXED_TIME = "2020-01-01T00:00:00Z"
BASE_JSON = {
    "id": "evt-1",
    "source": "/legacy/producer",
    "type": "com.example.order.created",
    "time": FIXED_TIME,
    "datacontenttype": "application/json",
}

CATALOGUE = Catalogue(
    [
        ExtensionSpec(
            canonical_name="legacytraceid",
            owner="platform-observability",
            versions=frozenset({"0.3", "1.0"}),
            value_types=frozenset({str}),
            deprecated_in="1.0",
            aliases={"legacytrace-id": "legacytraceid"},
        ),
        ExtensionSpec(
            canonical_name="attemptcount",
            owner="platform-delivery",
            versions=frozenset({"1.0"}),
            value_types=frozenset({int}),
        ),
        ExtensionSpec(
            canonical_name="partitionkey",
            owner="platform-messaging",
            versions=frozenset({"0.3", "1.0"}),
            value_types=frozenset({str, bytes}),
        ),
    ],
    quarantined={
        "legacy-trace-id": "legacytraceid",
        "legacy_trace_id": "legacytraceid",
        "legacytrace-id": "legacytraceid",
    },
)

HISTORICAL_NAMES = [
    "legacytraceid",  # already canonical
    "LegacyTraceId",  # mixed case, produced by an older service
    "legacy-trace-id",  # hyphenated historical spelling
    "legacy_trace_id",  # underscored historical spelling
]


@dataclass
class Row:
    extension: str
    sdk: str
    specversion: str
    binding: str
    wire_shape: str
    outcome: str
    observed: str
    status: str
    record_kind: str
    policy_accept: bool
    sdk_accept: bool


def _short(value: Any) -> str:
    text = repr(value)
    return text if len(text) <= 110 else text[:107] + "..."


def _decision(name: str, value: Any, version: str, binding: str, mode: Mode):
    return CATALOGUE.evaluate(
        name, value, version, binding=binding, stage="produce", mode=mode
    )


def legacy_rows(name: str, version: str) -> list[Row]:
    rows: list[Row] = []
    attrs = {**BASE_JSON, "specversion": version, name: "trace-abc"}
    event = LegacyEvent(attrs, {"order_id": 7})

    # Structured HTTP: the legacy SDK lower-cases attribute names at ingest.
    headers, body = legacy_to_structured(event)
    structured_payload = json.loads(body)
    rows.append(
        Row(
            extension=name,
            sdk="legacy v1",
            specversion=version,
            binding="HTTP structured",
            wire_shape=_short(
                {k: v for k, v in structured_payload.items() if k not in BASE_JSON}
            ),
            outcome="parse",
            observed=_short(
                {k: v for k, v in structured_payload.items() if k not in BASE_JSON}
            ),
            status="n/a (legacy has no catalogue)",
            record_kind="n/a",
            policy_accept=True,
            sdk_accept=True,
        )
    )

    headers, _ = legacy_to_binary(event)
    rows.append(
        Row(
            extension=name,
            sdk="legacy v1",
            specversion=version,
            binding="HTTP binary",
            wire_shape=_short({k: v for k, v in headers.items() if k.startswith("ce-")}),
            outcome="emit",
            observed=_short(
                {k: v for k, v in headers.items() if k not in
                 ("ce-id", "ce-source", "ce-type", "ce-specversion", "ce-time",
                  "content-type")}
            ),
            status="n/a (legacy has no catalogue)",
            record_kind="n/a",
            policy_accept=True,
            sdk_accept=True,
        )
    )

    kafka = legacy_kafka_to_binary(event)
    rows.append(
        Row(
            extension=name,
            sdk="legacy v1",
            specversion=version,
            binding="Kafka binary",
            wire_shape=_short(
                {k: v for k, v in kafka.headers.items()
                 if k not in (b"ce_id", b"ce_source", b"ce_type", b"ce_specversion",
                              b"ce_time", b"content-type")}
            ),
            outcome="emit",
            observed=_short(
                {k: v for k, v in kafka.headers.items()
                 if k not in (b"ce_id", b"ce_source", b"ce_type",
                              b"ce_specversion", b"ce_time", b"content-type")}
            ),
            status="n/a (legacy has no catalogue)",
            record_kind="n/a",
            policy_accept=True,
            sdk_accept=True,
        )
    )
    return rows


def core_structured_rows(name: str, version: str, mode: Mode) -> list[Row]:
    payload = {**BASE_JSON, "specversion": version, name: "trace-abc"}
    decision = _decision(name, "trace-abc", version, "HTTP structured", mode)
    try:
        event = http_from_structured(
            HTTPMessage({"content-type": "application/cloudevents+json"},
                        json.dumps(payload).encode()),
            JSONFormat(),
        )
        observed = _short(
            {k: v for k, v in event.get_attributes().items()
             if k not in ("id", "source", "type", "specversion",
                          "datacontenttype", "time")}
        )
        outcome = "pass" if name in event.get_attributes() else "drop"
    except Exception as exc:  # noqa: BLE001 - the matrix records the failure
        observed = f"{type(exc).__name__}: {exc}"
        outcome = "reject"
    return [
        Row(
            extension=name,
            sdk="core v2",
            specversion=version,
            binding="HTTP structured",
            wire_shape=_short(payload),
            outcome=outcome,
            observed=observed,
            status=decision.status.value,
            record_kind=decision.record_kind,
            policy_accept=decision.accepted,
            sdk_accept=outcome != "reject",
        )
    ]


def core_binary_rows(name: str, version: str, mode: Mode) -> list[Row]:
    common = {
        "ce-id": "evt-1",
        "ce-source": "/legacy/producer",
        "ce-type": "com.example.order.created",
        "ce-time": FIXED_TIME,
        "ce-specversion": version,
    }
    rows = []
    for binding, parse, headers, content_type in (
        (
            "HTTP binary",
            http_from_binary,
            {**common, "ce-" + name: "trace-abc"},
            "application/json",
        ),
        (
            "RabbitMQ binary",
            rabbit_from_binary,
            {**common, "ce-" + name: "trace-abc"},
            "application/json",
        ),
        (
            "AMQP binary",
            amqp_from_binary,
            {
                "cloudEvents_id": "evt-1",
                "cloudEvents_source": "/legacy/producer",
                "cloudEvents_type": "com.example.order.created",
                "cloudEvents_time": FIXED_TIME,
                "cloudEvents_specversion": version,
                "cloudEvents_" + name: "trace-abc",
            },
            "application/json",
        ),
    ):
        decision = _decision(name, "trace-abc", version, binding, mode)
        try:
            if binding == "HTTP binary":
                event = parse(
                    HTTPMessage(headers, b'{"order_id": 7}'), JSONFormat()
                )
            elif binding == "RabbitMQ binary":
                event = parse(
                    RabbitMQMessage(headers, content_type, b'{"order_id": 7}'),
                    JSONFormat(),
                )
            else:
                event = parse(
                    AMQPMessage({"content-type": content_type}, headers,
                                b'{"order_id": 7}'),
                    JSONFormat(),
                )
            ext = {
                k: v for k, v in event.get_attributes().items()
                if k not in ("id", "source", "type", "specversion",
                             "datacontenttype", "time")
            }
            observed = _short(ext)
            outcome = "pass" if ext else "drop"
            if ext and name not in ext:
                outcome = "rename"
        except Exception as exc:  # noqa: BLE001
            observed = f"{type(exc).__name__}: {exc}"
            outcome = "reject"
        rows.append(
            Row(
                extension=name,
                sdk="core v2",
                specversion=version,
                binding=binding,
                wire_shape=_short(headers),
                outcome=outcome,
                observed=observed,
                status=decision.status.value,
                record_kind=decision.record_kind,
                policy_accept=decision.accepted,
                sdk_accept=outcome != "reject",
            )
        )
    return rows


def core_kafka_rows(name: str, version: str, mode: Mode) -> list[Row]:
    decision = _decision(name, "trace-abc", version, "Kafka binary", mode)
    headers = {
        "ce_id": b"evt-1",
        "ce_source": b"/legacy/producer",
        "ce_type": b"com.example.order.created",
        "ce_time": FIXED_TIME.encode(),
        "ce_specversion": version.encode(),
        ("ce_" + name): b"trace-abc",
    }
    try:
        event = kafka_from_binary(
            KafkaMessage(headers, None, b'{"order_id": 7}'), JSONFormat()
        )
        ext = {
            k: v for k, v in event.get_attributes().items()
            if k not in ("id", "source", "type", "specversion",
                         "datacontenttype", "time")
        }
        observed = _short(ext)
        outcome = "pass" if ext else "drop"
        if ext and name not in ext:
            outcome = "rename"
    except Exception as exc:  # noqa: BLE001
        observed = f"{type(exc).__name__}: {exc}"
        outcome = "reject"
    return [
        Row(
            extension=name,
            sdk="core v2",
            specversion=version,
            binding="Kafka binary",
            wire_shape=_short(headers),
            outcome=outcome,
            observed=observed,
            status=decision.status.value,
            record_kind=decision.record_kind,
            policy_accept=decision.accepted,
            sdk_accept=outcome != "reject",
        )
    ]


def core_emit_rows(version: str, name: str, value: Any, mode: Mode) -> list[Row]:
    """What a producer emits today; each binding normalises value types."""

    rows = []
    base = {
        "id": "evt-1",
        "source": "/new/producer",
        "type": "com.example.order.created",
        "time": datetime(2020, 1, 1, tzinfo=timezone.utc),
        "specversion": version,
        name: value,
    }
    cls = CoreV1 if version == "1.0" else CoreV03
    event = cls(base, {"order_id": 7})

    variants: list[tuple[str, Callable[[], Any]]] = [
        (
            "HTTP structured",
            lambda: json.loads(http_to_structured(event, JSONFormat()).body)[name],
        ),
        (
            "HTTP binary",
            lambda: http_to_binary(event, JSONFormat()).headers["ce-" + name],
        ),
        (
            "Kafka binary",
            lambda: kafka_to_binary(event, JSONFormat())
            .headers["ce_" + name]
            .decode("utf-8"),
        ),
        (
            "RabbitMQ binary",
            lambda: rabbit_to_binary(event, JSONFormat()).headers["ce-" + name],
        ),
        (
            "AMQP binary",
            lambda: amqp_to_binary(event, JSONFormat())
            .application_properties["cloudEvents_" + name],
        ),
    ]
    for binding, read in variants:
        emitted = read()
        decision = _decision(name, emitted, version, binding, mode)
        rows.append(
            Row(
                extension=name,
                sdk="core v2",
                specversion=version,
                binding=binding,
                wire_shape=f"{type(value).__name__} -> {type(emitted).__name__}",
                outcome="type-preserved"
                if type(emitted) is type(value)
                else "type-drift",
                observed=_short(emitted),
                status=decision.status.value,
                record_kind=decision.record_kind,
                policy_accept=decision.accepted,
                sdk_accept=True,
            )
        )
    return rows


def version_drift_rows(mode: Mode) -> list[Row]:
    """Version-owned attributes and unknown names get their own record streams."""

    rows: list[Row] = []
    cases = [
        ("schemaurl", "1.0", "https://schema.example/order.json"),
        ("dataschema", "0.3", "https://schema.example/order.json"),
        ("datacontentencoding", "1.0", "base64"),
        ("futuretraceid", "1.0", "trace-xyz"),
    ]
    for name, version, value in cases:
        decision = _decision(name, value, version, "HTTP structured", mode)
        payload = {**BASE_JSON, "specversion": version, name: value}
        try:
            http_from_structured(
                HTTPMessage({}, json.dumps(payload).encode()), JSONFormat()
            )
            sdk_accept = True
        except Exception:  # noqa: BLE001
            sdk_accept = False
        rows.append(
            Row(
                extension=name,
                sdk="core v2",
                specversion=version,
                binding="HTTP structured",
                wire_shape=_short(payload),
                outcome="parsed-as-extension" if sdk_accept else "reject",
                observed="accepted by SDK without catalogue",
                status=decision.status.value,
                record_kind=decision.record_kind,
                policy_accept=decision.accepted,
                sdk_accept=sdk_accept,
            )
        )
    return rows


def shim_rows() -> list[Row]:
    """Show that ingest rewriting makes a legacy envelope readable by core v1."""

    rows: list[Row] = []
    for name in ("legacy-trace-id", "legacy_trace_id"):
        legacy_attrs = {
            **BASE_JSON,
            "specversion": "1.0",
            name: "trace-abc",
        }
        ingested = ingest_attributes(
            legacy_attrs, "1.0", binding="HTTP structured", catalogue=CATALOGUE
        )
        # The historical wire time is a string; the core v1 model requires a
        # timezone-aware datetime.  That is a separate adapter concern from
        # extension-name rewriting.
        ingested.attributes["time"] = datetime(2020, 1, 1, tzinfo=timezone.utc)
        try:
            CoreV1(ingested.attributes, {"order_id": 7})
            sdk_accept = True
        except Exception:  # noqa: BLE001
            sdk_accept = False
        decision = ingested.decisions[0]
        rows.append(
            Row(
                extension=name,
                sdk="ingest adapter",
                specversion="1.0",
                binding="HTTP structured",
                wire_shape=_short(ingested.attributes),
                outcome="rewrite"
                if "legacytraceid" in ingested.attributes
                else "reject",
                observed=_short(ingested.attributes.get("legacytraceid")),
                status=decision.status.value,
                record_kind=decision.record_kind,
                policy_accept=True,
                sdk_accept=sdk_accept,
            )
        )
    return rows


def build_rows(mode: Mode = Mode.ENFORCE) -> list[Row]:
    rows: list[Row] = []
    for version in ("1.0", "0.3"):
        for name in HISTORICAL_NAMES:
            rows.extend(legacy_rows(name, version))
            rows.extend(core_structured_rows(name, version, mode))
            rows.extend(core_binary_rows(name, version, mode))
            rows.extend(core_kafka_rows(name, version, mode))
    rows.extend(version_drift_rows(mode))
    rows.extend(shim_rows())
    rows.extend(core_emit_rows("1.0", "attemptcount", 3, mode))
    return rows


def print_table(rows: list[Row], mode: Mode) -> None:
    print(f"mode={mode.value}  rows={len(rows)}")
    widths = {
        "extension": 20,
        "sdk": 13,
        "specversion": 12,
        "binding": 18,
        "outcome": 16,
        "status": 21,
        "record_kind": 18,
    }
    header = (
        "extension".ljust(widths["extension"])
        + "sdk".ljust(widths["sdk"])
        + "ver".ljust(widths["specversion"])
        + "binding".ljust(widths["binding"])
        + "outcome".ljust(widths["outcome"])
        + "status".ljust(widths["status"])
        + "record_kind".ljust(widths["record_kind"])
        + "policy/sdk".ljust(13)
        + "observed"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            row.extension.ljust(widths["extension"])
            + row.sdk.ljust(widths["sdk"])
            + row.specversion.ljust(widths["specversion"])
            + row.binding.ljust(widths["binding"])
            + row.outcome.ljust(widths["outcome"])
            + row.status.ljust(widths["status"])
            + row.record_kind.ljust(widths["record_kind"])
            + f"{str(row.policy_accept):6}/{str(row.sdk_accept):6}"
            + row.observed
        )


def assert_contract(rows: list[Row]) -> None:
    """Pin the facts the governance design depends on."""

    def find(extension, sdk, version, binding, outcome=None):
        return [
            r for r in rows
            if r.extension == extension
            and r.sdk == sdk
            and r.specversion == version
            and r.binding == binding
            and (outcome is None or r.outcome == outcome)
        ]

    checks = [
        (
            "core structured rejects mixed case",
            bool(find("LegacyTraceId", "core v2", "1.0", "HTTP structured", "reject")),
        ),
        (
            "core HTTP binary folds mixed case to lower case",
            any(
                r.observed.find("legacytraceid") >= 0
                for r in find("LegacyTraceId", "core v2", "1.0", "HTTP binary")
            ),
        ),
        (
            "core AMQP keeps mixed case and rejects it",
            bool(find("LegacyTraceId", "core v2", "1.0", "AMQP binary", "reject")),
        ),
        (
            "core Kafka folds mixed case",
            bool(find("LegacyTraceId", "core v2", "1.0", "Kafka binary")),
        ),
        (
            "legacy structured lower-cases mixed case",
            any(
                r.observed.find("legacytraceid") >= 0
                for r in find("LegacyTraceId", "legacy v1", "1.0", "HTTP structured")
            ),
        ),
        (
            "legacy binary preserves hyphen and underscore",
            any(
                "legacy-trace-id" in r.observed
                for r in find("legacy-trace-id", "legacy v1", "1.0", "HTTP binary")
            )
            and any(
                "legacy_trace_id" in r.observed
                for r in find("legacy_trace_id", "legacy v1", "1.0", "HTTP binary")
            ),
        ),
        (
            "version-owned schemaurl in 1.0 is version-mismatch",
            any(
                r.extension == "schemaurl"
                and r.status == "version-mismatch"
                and r.record_kind == "version"
                for r in rows
            ),
        ),
        (
            "unknown extension has its own record kind",
            any(
                r.extension == "futuretraceid"
                and r.status == "unknown"
                and r.record_kind == "unknown-extension"
                for r in rows
            ),
        ),
        (
            "ingest adapter rewrites hyphen to canonical name",
            any(
                r.sdk == "ingest adapter"
                and r.extension == "legacy-trace-id"
                and r.outcome == "rewrite"
                and r.sdk_accept
                for r in rows
            ),
        ),
        (
            "AMQP keeps int extension while HTTP/Rabbit/Kafka stringify",
            any(r.outcome == "type-preserved" and r.binding == "AMQP binary" for r in rows)
            and any(r.outcome == "type-drift" and r.binding == "HTTP binary" for r in rows),
        ),
    ]
    failed = [label for label, ok in checks if not ok]
    if failed:
        raise AssertionError("contract drift: " + ", ".join(failed))


def shadow_report(rows: list[Row]) -> dict[str, Any]:
    """Compare observe decisions with enforce would_accept for the same wire data."""

    by_kind: dict[str, int] = {}
    disagreements = 0
    for row in rows:
        if row.record_kind != "n/a":
            by_kind[row.record_kind] = by_kind.get(row.record_kind, 0) + 1
            if row.status == "admitted" and not row.policy_accept:
                disagreements += 1
    return {"counts_by_record_kind": by_kind, "shadow_disagreements": disagreements}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--assert", dest="do_assert", action="store_true")
    parser.add_argument(
        "--mode", choices=[m.value for m in Mode], default=Mode.ENFORCE.value
    )
    args = parser.parse_args()
    mode = Mode(args.mode)
    rows = build_rows(mode)

    if args.do_assert:
        assert_contract(rows)

    if args.json:
        print(
            json.dumps(
                {
                    "mode": mode.value,
                    "rows": [asdict(row) for row in rows],
                    "shadow": shadow_report(rows),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print_table(rows, mode)
        print()
        print("shadow report:", json.dumps(shadow_report(rows), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
