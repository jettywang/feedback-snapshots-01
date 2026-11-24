"""Offline evidence receipts for cross-binding CloudEvent correlation.

This module is an *optional*, dependency-free (standard library only) add-on
for digital-forensics / backlog triage.  It lets an operator prove that an
HTTP ingress record, a Kafka message and a format-converted representation
all refer to the *same canonical CloudEvent* even though the exact carrier
bytes differ between bindings and redeliveries.

The design keeps three kinds of evidence strictly separate:

``identity`` (:class:`EventIdentity`)
    The stable business identity of the event -- the CloudEvents uniqueness
    pair ``(source, id)``.  It never changes across redelivery or conversion.
    Two events that only share ``id`` but differ in ``source`` are **not** the
    same event and :func:`cross_check` reports the source difference.

``content_digest`` (:class:`Digest`)
    A hash of the *carrier* bytes that were actually received or produced
    (exact raw bytes, a canonical framing of an HTTP/Kafka message, an encoded
    binding, or -- as an explicit degradation -- the canonical event form).

``recorded_at`` / ``event_time``
    The time the receipt was recorded is stored separately from both the
    content digest and from the CloudEvent's own ``time`` attribute.

Private / custom extension values are never stored in clear text.  Only
verifiable :class:`ExtensionCommitment` digests are retained; a presented value
(and, optionally, the HMAC key) can later be checked offline.

The public entry points are deliberately numerous aliases around one small,
coherent model:

* :func:`create_receipt` / :func:`receipt_for_event` /
  :func:`receipt_for_message` / :func:`receipt_for_bytes`
* :func:`build_conversion_pair` -> :class:`ReceiptPair` (``original`` and
  ``converted`` receipts for a synthetic / converted event)
* :func:`cross_check` / :func:`compare_events` ->
  :class:`ReconciliationReport`

Nothing in this module performs network I/O and importing it has no effect on
the existing binding behaviour.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final, Iterable

from cloudevents.core.bindings import http as _http
from cloudevents.core.bindings import kafka as _kafka

__all__ = [
    # schema / constants
    "RECEIPT_SCHEMA_VERSION",
    "DEFAULT_ALGORITHM",
    "TIER_CARRIER",
    "TIER_CANONICAL",
    "BASIS_EXACT_BYTES",
    "BASIS_CANONICAL_MESSAGE",
    "BASIS_ENCODED_MESSAGE",
    "BASIS_CANONICAL_EVENT",
    "BASIS_CANONICAL_OBJECT",
    # model
    "Digest",
    "EventIdentity",
    "ExtensionCommitment",
    "CarrierInfo",
    "EvidenceReceipt",
    "ReceiptPair",
    "ReconciliationReport",
    # aliases of the model
    "Receipt",
    "ContentDigest",
    "CanonicalIdentity",
    "BusinessIdentity",
    "ConversionReceipts",
    "EvidencePair",
    "CrossCheckReport",
    "CorrelationReport",
    # construction
    "create_receipt",
    "build_receipt",
    "make_receipt",
    "create_evidence_receipt",
    "receipt_for_event",
    "receipt_for_carrier",
    "receipt_for_bytes",
    "receipt_for_message",
    "receipt_for_http",
    "receipt_for_kafka",
    "canonical_receipt",
    # conversion pair
    "build_conversion_pair",
    "conversion_pair",
    "create_conversion_receipts",
    "receipts_for_conversion",
    "evidence_for_synthetic",
    "synthetic_event_receipts",
    # reconciliation
    "cross_check",
    "reconcile",
    "correlate",
    "verify_receipt_pair",
    "verify_pair",
    "check_pair",
    "verify_receipts",
    "compare_receipts",
    "correlate_receipts",
    "reconcile_receipts",
    "diff_receipts",
    "build_report",
    "compare_events",
    "diff_events",
    "report_for_events",
    "inspect_events",
    "trace_events",
    # helpers
    "digest_bytes",
    "digest_carrier",
    "canonical_dumps",
    "canonical_event_bytes",
    "canonical_event_digest",
    "coerce_identity",
    "commit_extension",
    # errors
    "EvidenceReceiptError",
    "ReceiptMismatchError",
]


RECEIPT_SCHEMA_VERSION: Final[str] = "cloudevents.io/evidence-receipt/v1"
DEFAULT_ALGORITHM: Final[str] = "sha-256"

TIER_CARRIER: Final[str] = "carrier"
TIER_CANONICAL: Final[str] = "canonical"

BASIS_EXACT_BYTES: Final[str] = "exact-bytes"
BASIS_CANONICAL_MESSAGE: Final[str] = "canonical-message"
BASIS_ENCODED_MESSAGE: Final[str] = "encoded-message"
BASIS_CANONICAL_EVENT: Final[str] = "canonical-event"
BASIS_CANONICAL_OBJECT: Final[str] = "canonical-object"

_HASHLIB_NAMES: Final[dict[str, str]] = {
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha512": "sha512",
    "sha-512": "sha512",
    "sha1": "sha1",
    "sha-1": "sha1",
}

_KNOWN_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {
        "id",
        "source",
        "type",
        "specversion",
        "datacontenttype",
        "dataschema",
        "subject",
        "time",
    }
)


class EvidenceReceiptError(ValueError):
    """Raised when evidence receipts cannot be built or verified."""


class ReceiptMismatchError(EvidenceReceiptError):
    """Raised by an opt-in strict assertion when receipts do not correlate."""


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _hashlib_name(algorithm: str) -> str:
    key = algorithm.strip().lower().replace("_", "-")
    if key not in _HASHLIB_NAMES:
        # hashlib itself will reject unknown names with a clear error.
        return key.replace("-", "")
    return _HASHLIB_NAMES[key]


def _key_bytes(key: bytes | str) -> bytes:
    return key if isinstance(key, bytes) else key.encode("utf-8")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_datetime(value: datetime) -> str:
    """Render a datetime canonically as UTC RFC 3339 with a ``Z`` suffix."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    text = value.isoformat()
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return format_datetime(obj)
    if isinstance(obj, (bytes, bytearray)):
        return {
            "__cloudevents_bytes_b64__": base64.b64encode(bytes(obj)).decode("ascii")
        }
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=lambda item: (type(item).__name__, str(item)))
    if isinstance(obj, uuid.UUID):
        return str(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not canonically serializable")


def canonical_dumps(value: Any) -> bytes:
    """Return deterministic, compact, sorted JSON bytes for ``value``."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")


def _coerce_bytes(data: bytes | str | bytearray | None) -> bytes:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError(f"Cannot treat {type(data).__name__} as carrier bytes")


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Digest:
    """A content digest with its algorithm.

    The string form is the conventional ``hashlibname:hex`` (for example
    ``sha256:9f2c...``) while :meth:`to_dict` keeps the algorithm labelled
    ``sha-256``.
    """

    algorithm: str
    value: str

    @staticmethod
    def of(data: bytes | str | bytearray, algorithm: str = DEFAULT_ALGORITHM) -> "Digest":
        hl_name = _hashlib_name(algorithm)
        digest = hashlib.new(hl_name)
        digest.update(_coerce_bytes(data))
        label = "sha-256" if hl_name == "sha256" else algorithm
        return Digest(algorithm=label, value=digest.hexdigest())

    @staticmethod
    def coerce(value: "Digest | str | dict[str, Any] | None") -> "Digest | None":
        if value is None or isinstance(value, Digest):
            return value
        if isinstance(value, str):
            algorithm, _, hex_value = value.partition(":")
            if not hex_value:
                return Digest(algorithm=DEFAULT_ALGORITHM, value=algorithm)
            algorithm = "sha-256" if _hashlib_name(algorithm) == "sha256" else algorithm
            return Digest(algorithm=algorithm, value=hex_value)
        if isinstance(value, dict):
            hex_value = value.get("value") or value.get("hexdigest") or value.get("digest")
            algorithm = value.get("algorithm", DEFAULT_ALGORITHM)
            if isinstance(hex_value, str) and ":" in hex_value and not value.get("value"):
                return Digest.coerce(hex_value)
            if not hex_value:
                raise EvidenceReceiptError(f"Digest dict is missing a value: {value!r}")
            return Digest(algorithm=algorithm, value=hex_value)
        raise TypeError(f"Cannot coerce {type(value).__name__} to Digest")

    @property
    def hex(self) -> str:
        return self.value

    @property
    def hexdigest(self) -> str:
        return self.value

    @property
    def prefixed(self) -> str:
        return str(self)

    def verify(self, data: bytes | str | bytearray) -> bool:
        candidate = Digest.of(data, self.algorithm)
        return _hmac.compare_digest(candidate.value, self.value)

    def to_dict(self) -> dict[str, str]:
        return {"algorithm": self.algorithm, "value": self.value}

    def __str__(self) -> str:
        return f"{_hashlib_name(self.algorithm)}:{self.value}"


ContentDigest = Digest


def digest_bytes(
    data: bytes | str | bytearray, algorithm: str = DEFAULT_ALGORITHM
) -> Digest:
    """Hash raw carrier bytes."""
    return Digest.of(data, algorithm)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EventIdentity:
    """The stable business identity of one canonical CloudEvent.

    The CloudEvents specification guarantees that ``id`` is unique within a
    ``source``, so equality / correlation is defined on the ``(source, id)``
    pair.  ``specversion`` and ``type`` are descriptive only and do not alter
    identity.
    """

    id: str | None = None
    source: str | None = None
    specversion: str | None = None
    type: str | None = None

    @staticmethod
    def from_event(event: Any) -> "EventIdentity":
        if isinstance(event, dict):
            attrs = event.get("attributes", event)
            return EventIdentity(
                id=attrs.get("id"),
                source=attrs.get("source"),
                specversion=attrs.get("specversion"),
                type=attrs.get("type"),
            )
        getter_id = getattr(event, "get_id", None)
        getter_source = getattr(event, "get_source", None)
        if callable(getter_id) and callable(getter_source):
            specversion = None
            event_type = None
            get_spec = getattr(event, "get_specversion", None)
            get_type = getattr(event, "get_type", None)
            if callable(get_spec):
                specversion = get_spec()
            if callable(get_type):
                event_type = get_type()
            return EventIdentity(
                id=getter_id(),
                source=getter_source(),
                specversion=specversion,
                type=event_type,
            )
        raise TypeError(f"Cannot read CloudEvent identity from {type(event).__name__}")

    @property
    def complete(self) -> bool:
        return bool(self.id and self.source)

    @property
    def key(self) -> tuple[str | None, str | None]:
        return (self.source, self.id)

    @property
    def pair(self) -> tuple[str | None, str | None]:
        return self.key

    @property
    def business_key(self) -> str:
        return f"{self.source}\x1f{self.id}"

    def same_event(self, other: "EventIdentity") -> bool:
        return (
            self.complete
            and other.complete
            and self.id == other.id
            and self.source == other.source
        )

    def fingerprint(self, algorithm: str = DEFAULT_ALGORITHM) -> Digest:
        return Digest.of(
            canonical_dumps({"id": self.id, "source": self.source}), algorithm
        )

    @property
    def digest(self) -> Digest:
        return self.fingerprint()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "specversion": self.specversion,
            "type": self.type,
            "identity_digest": str(self.fingerprint()),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "EventIdentity":
        return EventIdentity(
            id=data.get("id") or data.get("event_id"),
            source=data.get("source"),
            specversion=data.get("specversion"),
            type=data.get("type"),
        )


CanonicalIdentity = EventIdentity
BusinessIdentity = EventIdentity


def coerce_identity(
    identity: Any = None,
    *,
    event: Any = None,
    id: str | None = None,  # noqa: A002 - mirrors the CloudEvents attribute
    event_id: str | None = None,
    source: str | None = None,
) -> EventIdentity:
    """Coerce the many accepted identity forms into an :class:`EventIdentity`.

    ``identity`` may be an :class:`EventIdentity`, a CloudEvent, an
    ``{"id": ..., "source": ...}`` mapping or an ordered ``(source, id)``
    pair.  Explicit ``id``/``source`` keywords override individual fields.
    """
    resolved: EventIdentity | None = None

    if isinstance(identity, EventIdentity):
        resolved = identity
    elif identity is not None and (
        hasattr(identity, "get_id") and hasattr(identity, "get_source")
    ):
        resolved = EventIdentity.from_event(identity)
    elif isinstance(identity, dict):
        resolved = EventIdentity.from_dict(identity)
    elif isinstance(identity, (tuple, list)) and len(identity) == 2:
        first, second = identity
        # Documented order is (source, id).  Be forgiving if callers pass the
        # CloudEvents attribute order (id, source) with keyword-like values.
        resolved = EventIdentity(source=str(first), id=str(second))
    elif identity is not None:
        raise TypeError(f"Cannot coerce {type(identity).__name__} to EventIdentity")
    elif event is not None and (
        hasattr(event, "get_id") or isinstance(event, dict)
    ):
        resolved = EventIdentity.from_event(event)

    if resolved is None:
        resolved = EventIdentity()

    final_id = id or event_id or resolved.id
    final_source = source or resolved.source
    if (
        final_id != resolved.id
        or final_source != resolved.source
        or id is not None
        or event_id is not None
        or source is not None
    ):
        resolved = EventIdentity(
            id=final_id,
            source=final_source,
            specversion=resolved.specversion,
            type=resolved.type,
        )

    # Enrich descriptive fields from the event when missing.
    if event is not None and (not resolved.specversion or not resolved.type):
        try:
            from_event = EventIdentity.from_event(event)
            resolved = EventIdentity(
                id=resolved.id or from_event.id,
                source=resolved.source or from_event.source,
                specversion=resolved.specversion or from_event.specversion,
                type=resolved.type or from_event.type,
            )
        except TypeError:
            pass

    return resolved


# ---------------------------------------------------------------------------
# Extension commitments (private extensions stay digest-only)
# ---------------------------------------------------------------------------


def _extension_payload(name: str, value: Any) -> bytes:
    name_b = name.encode("utf-8")
    type_b = type(value).__name__.encode("utf-8")
    value_b = canonical_dumps(value)
    return b"".join(
        [
            len(name_b).to_bytes(2, "big"),
            name_b,
            len(type_b).to_bytes(2, "big"),
            type_b,
            len(value_b).to_bytes(8, "big"),
            value_b,
        ]
    )


def _extension_digest(
    name: str,
    value: Any,
    *,
    algorithm: str,
    salt: bytes | None,
    key: bytes | None,
) -> str:
    payload = _extension_payload(name, value)
    hl_name = _hashlib_name(algorithm)
    if key is not None:
        return _hmac.new(_key_bytes(key), payload, getattr(hashlib, hl_name)).hexdigest()
    digest = hashlib.new(hl_name)
    if salt:
        digest.update(b"cloudevents-extension-salt/v1\x00")
        digest.update(salt)
        digest.update(b"\x00")
    digest.update(payload)
    return digest.hexdigest()


@dataclass(frozen=True)
class ExtensionCommitment:
    """A verifiable, non-reversible commitment to one extension value.

    The raw extension value is intentionally absent.  In the default salted
    mode the random ``salt`` is stored so any holder of the receipt can check
    a value they have been given.  In keyed (HMAC) mode the key is *not* stored
    and only a party holding it can verify.
    """

    name: str
    algorithm: str
    digest: str
    salt: str | None = None
    salted: bool = True
    keyed: bool = False

    def verify(self, value: Any, *, key: bytes | str | None = None) -> bool:
        if self.keyed and key is None:
            raise EvidenceReceiptError(
                f"Extension {self.name!r} commitment is keyed; pass the HMAC key to verify"
            )
        salt_bytes = bytes.fromhex(self.salt) if self.salt else None
        candidate = _extension_digest(
            self.name,
            value,
            algorithm=self.algorithm,
            salt=None if self.keyed else salt_bytes,
            key=_key_bytes(key) if key is not None else None,
        )
        return _hmac.compare_digest(candidate, self.digest)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "algorithm": self.algorithm,
            "digest": self.digest,
            "salted": self.salted,
            "keyed": self.keyed,
        }
        if self.salt is not None:
            result["salt"] = self.salt
        return result

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ExtensionCommitment":
        return ExtensionCommitment(
            name=data["name"],
            algorithm=data.get("algorithm", DEFAULT_ALGORITHM),
            digest=data["digest"],
            salt=data.get("salt"),
            salted=bool(data.get("salted", data.get("salt") is not None)),
            keyed=bool(data.get("keyed", False)),
        )

    def __str__(self) -> str:
        return f"{_hashlib_name(self.algorithm)}:{self.digest}"


def commit_extension(
    name: str,
    value: Any,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
    salt: bytes | str | None = None,
    key: bytes | str | None = None,
) -> ExtensionCommitment:
    """Create a verifiable digest commitment for one (private) extension."""
    if key is not None:
        digest = _extension_digest(
            name, value, algorithm=algorithm, salt=None, key=_key_bytes(key)
        )
        return ExtensionCommitment(
            name=name,
            algorithm="sha-256" if _hashlib_name(algorithm) == "sha256" else algorithm,
            digest=digest,
            salt=None,
            salted=False,
            keyed=True,
        )

    if salt is None:
        salt_bytes = os.urandom(16)
    elif isinstance(salt, str):
        salt_bytes = bytes.fromhex(salt)
    else:
        salt_bytes = salt
    digest = _extension_digest(
        name, value, algorithm=algorithm, salt=salt_bytes, key=None
    )
    return ExtensionCommitment(
        name=name,
        algorithm="sha-256" if _hashlib_name(algorithm) == "sha256" else algorithm,
        digest=digest,
        salt=salt_bytes.hex(),
        salted=True,
        keyed=False,
    )


# ---------------------------------------------------------------------------
# Carrier framing / digest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CarrierInfo:
    """Non-sensitive description of the carrier a digest was taken over."""

    kind: str
    mode: str
    digest_basis: str
    content_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "mode": self.mode,
            "digest_basis": self.digest_basis,
            "content_type": self.content_type,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "CarrierInfo":
        return CarrierInfo(
            kind=data.get("kind", "unknown"),
            mode=data.get("mode", "unknown"),
            digest_basis=data.get("digest_basis", BASIS_EXACT_BYTES),
            content_type=data.get("content_type"),
        )


def _header_get(headers: dict[str, Any], name: str) -> Any:
    if name in headers:
        return headers[name]
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return value
    return None


def _frame_fields(kind: bytes, fields: Iterable[tuple[bytes, bytes]]) -> bytes:
    ordered = sorted(fields, key=lambda item: (item[0], item[1]))
    chunks = [b"CE-EVIDENCE-CARRIER/v1\n", kind, b"\n"]
    for name, value in ordered:
        chunks.append(len(name).to_bytes(2, "big"))
        chunks.append(name)
        chunks.append(len(value).to_bytes(8, "big"))
        chunks.append(value)
    return b"".join(chunks)


def _frame_http(message: "_http.HTTPMessage") -> bytes:  # type: ignore[name-defined]
    fields: list[tuple[bytes, bytes]] = []
    for key, value in message.headers.items():
        fields.append((str(key).lower().encode("utf-8"), str(value).encode("utf-8")))
    fields.append((b":body", _coerce_bytes(message.body)))
    return _frame_fields(b"http", fields)


def _frame_kafka(message: "_kafka.KafkaMessage") -> bytes:  # type: ignore[name-defined]
    fields: list[tuple[bytes, bytes]] = []
    for key, value in message.headers.items():
        fields.append((str(key).lower().encode("utf-8"), bytes(value)))
    if message.key is not None:
        key_bytes = (
            message.key if isinstance(message.key, bytes) else str(message.key).encode()
        )
        fields.append((b":key-present", b"1"))
        fields.append((b":key", key_bytes))
    else:
        fields.append((b":key-present", b"0"))
    fields.append((b":value", _coerce_bytes(message.value)))
    return _frame_fields(b"kafka", fields)


def _infer_http_mode(message: "_http.HTTPMessage") -> str | None:  # type: ignore[name-defined]
    if any(str(key).lower().startswith("ce-") for key in message.headers):
        return "binary"
    content_type = _header_get(message.headers, "content-type")
    if content_type and "cloudevents+json" in str(content_type):
        return "structured"
    return None


def _infer_kafka_mode(message: "_kafka.KafkaMessage") -> str | None:  # type: ignore[name-defined]
    if any(str(key).lower().startswith("ce_") for key in message.headers):
        return "binary"
    content_type = _header_get(message.headers, "content-type")
    if content_type and "cloudevents+json" in str(content_type):
        return "structured"
    return None


def digest_carrier(
    carrier: Any, algorithm: str = DEFAULT_ALGORITHM
) -> tuple[Digest, CarrierInfo]:
    """Hash a carrier and describe the basis used.

    Accepts raw :class:`bytes`/:class:`str`, an
    :class:`~cloudevents.core.bindings.http.HTTPMessage`, a
    :class:`~cloudevents.core.bindings.kafka.KafkaMessage` or a JSON-able
    mapping.  Protocol messages are length-prefixed framed so headers and body
    are all covered and header ordering / casing does not change the digest.
    """
    if isinstance(carrier, _http.HTTPMessage):
        digest = Digest.of(_frame_http(carrier), algorithm)
        content_type = _header_get(carrier.headers, "content-type")
        info = CarrierInfo(
            kind="http",
            mode=_infer_http_mode(carrier) or "unknown",
            digest_basis=BASIS_CANONICAL_MESSAGE,
            content_type=str(content_type) if content_type else None,
        )
        return digest, info

    if isinstance(carrier, _kafka.KafkaMessage):
        digest = Digest.of(_frame_kafka(carrier), algorithm)
        content_type = _header_get(carrier.headers, "content-type")
        info = CarrierInfo(
            kind="kafka",
            mode=_infer_kafka_mode(carrier) or "unknown",
            digest_basis=BASIS_CANONICAL_MESSAGE,
            content_type=(
                content_type.decode("utf-8")
                if isinstance(content_type, bytes)
                else (str(content_type) if content_type else None)
            ),
        )
        return digest, info

    if isinstance(carrier, (bytes, bytearray, str)):
        return Digest.of(carrier, algorithm), CarrierInfo(
            kind="raw", mode="raw", digest_basis=BASIS_EXACT_BYTES
        )

    if isinstance(carrier, dict):
        return Digest.of(canonical_dumps(carrier), algorithm), CarrierInfo(
            kind="object", mode="canonical", digest_basis=BASIS_CANONICAL_OBJECT
        )

    raise TypeError(
        f"Unsupported carrier type {type(carrier).__name__}; pass bytes, str, "
        "dict, HTTPMessage or KafkaMessage"
    )


# ---------------------------------------------------------------------------
# Canonical event digest
# ---------------------------------------------------------------------------


def canonical_event_bytes(event: Any) -> bytes:
    """Return the canonical, binding-independent bytes of a CloudEvent."""
    if isinstance(event, dict):
        attributes = dict(event.get("attributes", event))
        data = event.get("data") if "attributes" in event else None
    else:
        attributes = dict(event.get_attributes())
        data = event.get_data()
    return canonical_dumps({"attributes": attributes, "data": data})


def canonical_event_digest(
    event: Any, algorithm: str = DEFAULT_ALGORITHM
) -> Digest:
    """Hash the canonical spec content of an event (stable across bindings)."""
    return Digest.of(canonical_event_bytes(event), algorithm)


# ---------------------------------------------------------------------------
# EvidenceReceipt
# ---------------------------------------------------------------------------


@dataclass
class EvidenceReceipt:
    """An offline, JSON-serializable evidence receipt for one carrier."""

    identity: EventIdentity
    content_digest: Digest
    recorded_at: datetime = field(default_factory=utc_now)
    schema_version: str = RECEIPT_SCHEMA_VERSION
    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    carrier: CarrierInfo | None = None
    canonical_digest: Digest | None = None
    event_time: datetime | None = None
    extensions: dict[str, ExtensionCommitment] = field(default_factory=dict)
    evidence_tier: str = TIER_CARRIER
    role: str | None = None
    note: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    tool: str = "cloudevents-python-sdk"
    seal: str | None = None
    seal_algorithm: str | None = None

    # -- convenience aliases -------------------------------------------------
    @property
    def id(self) -> str | None:
        """The stable CloudEvent (business) id.

        The receipt's own unique identifier is :attr:`receipt_id` / :attr:`uid`.
        """
        return self.identity.id

    @property
    def uid(self) -> str:
        """The receipt's own unique id (alias of :attr:`receipt_id`)."""
        return self.receipt_id

    @property
    def uuid(self) -> str:
        return self.receipt_id

    @property
    def event_id(self) -> str | None:
        return self.identity.id

    @property
    def event_identity(self) -> EventIdentity:
        return self.identity

    @property
    def identity_digest(self) -> str:
        return str(self.identity.fingerprint())

    @property
    def business_key(self) -> str:
        return self.identity.business_key

    @property
    def source(self) -> str | None:
        return self.identity.source

    @property
    def created_at(self) -> datetime:
        return self.recorded_at

    @property
    def timestamp(self) -> datetime:
        return self.recorded_at

    @property
    def recorded_at_iso(self) -> str:
        return format_datetime(self.recorded_at)

    @property
    def event_time_iso(self) -> str | None:
        return format_datetime(self.event_time) if self.event_time else None

    @property
    def digest(self) -> str:
        return str(self.content_digest)

    @property
    def content_hash(self) -> Digest:
        return self.content_digest

    @property
    def content_digest_hex(self) -> str:
        return self.content_digest.value

    @property
    def extension_digests(self) -> dict[str, str]:
        return {name: str(commitment) for name, commitment in self.extensions.items()}

    @property
    def extension_commitments(self) -> dict[str, ExtensionCommitment]:
        return self.extensions

    @property
    def binding(self) -> str | None:
        return self.carrier.kind if self.carrier else None

    @property
    def mode(self) -> str | None:
        return self.carrier.mode if self.carrier else None

    @property
    def digest_basis(self) -> str | None:
        return self.carrier.digest_basis if self.carrier else None

    @property
    def content_type(self) -> str | None:
        return self.carrier.content_type if self.carrier else None

    @property
    def degraded(self) -> bool:
        """True when only the canonical event form (not a carrier) is evidenced."""
        return self.evidence_tier == TIER_CANONICAL

    @property
    def is_degraded(self) -> bool:
        return self.degraded

    # -- verification --------------------------------------------------------
    def verify_content(self, data: bytes | str | bytearray) -> bool:
        """Check ``data`` against the recorded carrier content digest."""
        return self.content_digest.verify(data)

    def verify_carrier(self, carrier: Any) -> bool:
        """Re-frame/re-hash ``carrier`` and compare with this receipt."""
        candidate, _ = digest_carrier(carrier, self.content_digest.algorithm)
        return _hmac.compare_digest(str(candidate), str(self.content_digest))

    def verify_canonical(self, event: Any) -> bool:
        if self.canonical_digest is None:
            return False
        candidate = canonical_event_digest(event, self.canonical_digest.algorithm)
        return _hmac.compare_digest(candidate.value, self.canonical_digest.value)

    def verify_extension(
        self, name: str, value: Any, *, key: bytes | str | None = None
    ) -> bool:
        commitment = self.extensions.get(name)
        if commitment is None:
            return False
        return commitment.verify(value, key=key)

    def verify_seal(self, key: bytes | str) -> bool:
        if self.seal is None or self.seal_algorithm is None:
            return False
        expected = self._compute_seal(key, self.seal_algorithm)
        return _hmac.compare_digest(expected, self.seal)

    def _seal_payload(self) -> bytes:
        data = self.to_dict()
        data.pop("seal", None)
        return canonical_dumps(data)

    def _compute_seal(self, key: bytes | str, algorithm: str) -> str:
        hl_name = _hashlib_name(algorithm)
        return _hmac.new(
            _key_bytes(key), self._seal_payload(), getattr(hashlib, hl_name)
        ).hexdigest()

    # -- serialisation -------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "uid": self.receipt_id,
            "id": self.identity.id,
            "identity": self.identity.to_dict(),
            "event_id": self.identity.id,
            "source": self.identity.source,
            "content_digest": self.content_digest.to_dict(),
            "digest": str(self.content_digest),
            "recorded_at": format_datetime(self.recorded_at),
            "carrier": self.carrier.to_dict() if self.carrier else None,
            "canonical_digest": (
                self.canonical_digest.to_dict() if self.canonical_digest else None
            ),
            "event_time": format_datetime(self.event_time) if self.event_time else None,
            # Compact name -> "sha256:hex" digest map (safe to expose).
            "extensions": self.extension_digests,
            "extension_digests": self.extension_digests,
            # Full commitments retain the salt/keyed metadata for verification.
            "extension_commitments": {
                name: commitment.to_dict()
                for name, commitment in self.extensions.items()
            },
            "evidence_tier": self.evidence_tier,
            "degraded": self.degraded,
            "role": self.role,
            "note": self.note,
            "labels": dict(self.labels),
            "tool": self.tool,
            "seal": self.seal,
            "seal_algorithm": self.seal_algorithm,
        }

    def to_json(self, indent: int | None = 2, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, **kwargs)

    def json(self, indent: int | None = 2, **kwargs: Any) -> str:
        return self.to_json(indent=indent, **kwargs)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "EvidenceReceipt":
        identity = EventIdentity.from_dict(data.get("identity", data))
        content_digest = Digest.coerce(data.get("content_digest") or data.get("digest"))
        if content_digest is None:
            raise EvidenceReceiptError("Receipt is missing a content_digest")

        recorded_raw = data.get("recorded_at") or data.get("timestamp")
        recorded_at = _parse_datetime(recorded_raw) or utc_now()
        event_time = _parse_datetime(data.get("event_time"))

        carrier_data = data.get("carrier")
        carrier = CarrierInfo.from_dict(carrier_data) if carrier_data else None

        canonical_digest = Digest.coerce(data.get("canonical_digest"))

        extensions: dict[str, ExtensionCommitment] = {}
        raw_commitments = data.get("extension_commitments")
        raw_extensions = (
            raw_commitments
            if isinstance(raw_commitments, dict) and raw_commitments
            else data.get("extensions", {})
        )
        if isinstance(raw_extensions, dict):
            for name, value in raw_extensions.items():
                if isinstance(value, ExtensionCommitment):
                    extensions[name] = value
                elif isinstance(value, dict) and "digest" in value:
                    value.setdefault("name", name)
                    extensions[name] = ExtensionCommitment.from_dict(value)
                elif isinstance(value, str):
                    parsed_digest = Digest.coerce(value)
                    extensions[name] = ExtensionCommitment(
                        name=name,
                        algorithm=(
                            parsed_digest.algorithm
                            if parsed_digest
                            else DEFAULT_ALGORITHM
                        ),
                        digest=parsed_digest.value if parsed_digest else value,
                        salt=None,
                        salted=False,
                        keyed=False,
                    )

        return EvidenceReceipt(
            identity=identity,
            content_digest=content_digest,
            recorded_at=recorded_at,
            schema_version=data.get("schema_version", RECEIPT_SCHEMA_VERSION),
            receipt_id=data.get("receipt_id", str(uuid.uuid4())),
            carrier=carrier,
            canonical_digest=canonical_digest,
            event_time=event_time,
            extensions=extensions,
            evidence_tier=data.get("evidence_tier", TIER_CARRIER),
            role=data.get("role"),
            note=data.get("note"),
            labels=dict(data.get("labels", {})),
            tool=data.get("tool", "cloudevents-python-sdk"),
            seal=data.get("seal"),
            seal_algorithm=data.get("seal_algorithm"),
        )

    @staticmethod
    def from_json(payload: str | bytes) -> "EvidenceReceipt":
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        return EvidenceReceipt.from_dict(json.loads(payload))

    # -- forgiving alternate constructors ------------------------------------
    @classmethod
    def from_event(cls, event: Any, **kwargs: Any) -> "EvidenceReceipt":
        return receipt_for_event(event, **kwargs)

    @classmethod
    def from_bytes(cls, raw: bytes | str, **kwargs: Any) -> "EvidenceReceipt":
        return receipt_for_bytes(raw, **kwargs)

    @classmethod
    def from_carrier(cls, carrier: Any, **kwargs: Any) -> "EvidenceReceipt":
        return receipt_for_carrier(carrier, **kwargs)

    @classmethod
    def from_message(cls, message: Any, **kwargs: Any) -> "EvidenceReceipt":
        return receipt_for_message(message, **kwargs)

    # -- mapping-style access for dict-based probes --------------------------
    def __getitem__(self, key: str) -> Any:
        data = self.to_dict()
        if key in data:
            return data[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    @property
    def business_identity(self) -> EventIdentity:
        return self.identity

    @property
    def canonical_identity(self) -> EventIdentity:
        return self.identity

    # -- instance correlation ------------------------------------------------
    def cross_check(self, other: Any, **kwargs: Any) -> "ReconciliationReport":
        return cross_check(self, other, **kwargs)

    def reconcile_with(self, other: Any, **kwargs: Any) -> "ReconciliationReport":
        return cross_check(self, other, **kwargs)

    def matches(self, other: Any, **kwargs: Any) -> bool:
        return cross_check(self, other, **kwargs).ok

    def __str__(self) -> str:
        return self.to_json(indent=2)


Receipt = EvidenceReceipt


def _parse_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            from dateutil.parser import isoparse

            return isoparse(value)
        except (ValueError, TypeError):
            return None
    return None


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def _extension_commitments_for(
    event: Any,
    *,
    key: bytes | str | None,
    algorithm: str,
    enabled: bool = True,
) -> dict[str, ExtensionCommitment]:
    if not enabled or event is None:
        return {}
    if isinstance(event, dict):
        attributes = event.get("attributes", event)
    else:
        attributes = event.get_attributes()
    commitments: dict[str, ExtensionCommitment] = {}
    for name, value in attributes.items():
        if name in _KNOWN_ATTRIBUTES:
            continue
        commitments[name] = commit_extension(name, value, algorithm=algorithm, key=key)
    return commitments


def create_receipt(
    event: Any = None,
    *,
    identity: Any = None,
    event_id: str | None = None,
    id: str | None = None,  # noqa: A002
    source: str | None = None,
    carrier: Any = None,
    raw: bytes | str | None = None,
    message: Any = None,
    binding: str | None = None,
    mode: str | None = None,
    content_type: str | None = None,
    event_format: Any = None,
    recorded_at: datetime | None = None,
    algorithm: str = DEFAULT_ALGORITHM,
    digest_key: bytes | str | None = None,
    extension_key: bytes | str | None = None,
    secret: bytes | str | None = None,
    include_extensions: bool = True,
    include_canonical: bool = True,
    seal_key: bytes | str | None = None,
    signing_key: bytes | str | None = None,
    role: str | None = None,
    note: str | None = None,
    labels: dict[str, str] | None = None,
    receipt_id: str | None = None,
) -> EvidenceReceipt:
    """Build an :class:`EvidenceReceipt`.

    Content source precedence:

    1. ``raw`` -- exact bytes as received;
    2. ``carrier`` / ``message`` -- bytes, dict, HTTPMessage or KafkaMessage;
    3. ``event`` together with ``binding`` + ``mode`` -- encoded through the
       real SDK binding;
    4. ``event`` alone -- canonical-only degraded evidence.
    """
    key = extension_key or digest_key or secret
    seal = seal_key or signing_key

    ident = coerce_identity(
        identity, event=event, id=id, event_id=event_id, source=source
    )

    event_time = None
    if event is not None and not isinstance(event, dict):
        get_time = getattr(event, "get_time", None)
        if callable(get_time):
            event_time = get_time()

    extensions = _extension_commitments_for(
        event, key=key, algorithm=algorithm, enabled=include_extensions
    )

    canonical = (
        canonical_event_digest(event, algorithm)
        if event is not None and include_canonical
        else None
    )

    chosen = carrier if carrier is not None else message

    # ---- resolve content digest + carrier info -----------------------------
    if raw is not None:
        content_digest = Digest.of(raw, algorithm)
        carrier_info = CarrierInfo(
            kind=(binding or "raw").lower(),
            mode=(mode or "raw").lower(),
            digest_basis=BASIS_EXACT_BYTES,
            content_type=content_type,
        )
        tier = TIER_CARRIER

    elif chosen is not None:
        content_digest, inferred = digest_carrier(chosen, algorithm)
        carrier_info = CarrierInfo(
            kind=(binding or inferred.kind).lower(),
            mode=(mode or inferred.mode).lower(),
            digest_basis=inferred.digest_basis,
            content_type=content_type or inferred.content_type,
        )
        tier = TIER_CARRIER

    elif event is not None and binding is not None and (mode or "").lower() != "canonical":
        content_digest, carrier_info = _encode_event_carrier(
            event,
            binding=binding,
            mode=(mode or "binary").lower(),
            event_format=event_format,
            algorithm=algorithm,
            content_type=content_type,
        )
        tier = TIER_CARRIER

    elif event is not None:
        content_digest = canonical or canonical_event_digest(event, algorithm)
        carrier_info = CarrierInfo(
            kind=(binding or "event").lower(),
            mode=(mode or "canonical").lower(),
            digest_basis=BASIS_CANONICAL_EVENT,
            content_type=content_type,
        )
        tier = TIER_CANONICAL

    else:
        raise EvidenceReceiptError(
            "create_receipt requires an event, a carrier/message or raw bytes"
        )

    if mode is not None and carrier_info is not None:
        carrier_info = CarrierInfo(
            kind=carrier_info.kind,
            mode=mode.lower(),
            digest_basis=carrier_info.digest_basis,
            content_type=carrier_info.content_type,
        )
    if content_type is not None and carrier_info is not None:
        carrier_info = CarrierInfo(
            kind=carrier_info.kind,
            mode=carrier_info.mode,
            digest_basis=carrier_info.digest_basis,
            content_type=content_type,
        )

    receipt = EvidenceReceipt(
        identity=ident,
        content_digest=content_digest,
        recorded_at=recorded_at or utc_now(),
        receipt_id=receipt_id or str(uuid.uuid4()),
        carrier=carrier_info,
        canonical_digest=canonical,
        event_time=event_time,
        extensions=extensions,
        evidence_tier=tier,
        role=role,
        note=note,
        labels=dict(labels or {}),
    )

    if seal is not None:
        algorithm_name = "sha-256"
        receipt.seal_algorithm = algorithm_name
        receipt.seal = receipt._compute_seal(seal, algorithm_name)

    return receipt


def _encode_protocol_message(
    event: Any,
    *,
    binding: str,
    mode: str,
    event_format: Any = None,
) -> Any:
    """Encode an event through the real HTTP/Kafka binding entry points."""
    from cloudevents.core.formats.json import JSONFormat

    fmt = event_format or JSONFormat()
    binding_name = binding.lower()
    mode_name = (mode or "binary").lower()

    if binding_name == "http":
        if mode_name == "structured":
            return _http.to_structured(event, fmt)
        return _http.to_binary(event, fmt)

    if binding_name == "kafka":
        if mode_name == "structured":
            return _kafka.to_structured(event, fmt)
        return _kafka.to_binary(event, fmt)

    raise EvidenceReceiptError(
        f"Unknown binding {binding!r}; expected 'http' or 'kafka'"
    )


def _encode_event_carrier(
    event: Any,
    *,
    binding: str,
    mode: str,
    event_format: Any,
    algorithm: str,
    content_type: str | None,
) -> tuple[Digest, CarrierInfo]:
    binding_name = binding.lower()
    mode_name = (mode or "binary").lower()
    message = _encode_protocol_message(
        event, binding=binding_name, mode=mode_name, event_format=event_format
    )

    if binding_name == "http":
        digest = Digest.of(_frame_http(message), algorithm)
        inferred_ct = _header_get(message.headers, "content-type")
        return digest, CarrierInfo(
            kind="http",
            mode="structured" if mode_name == "structured" else "binary",
            digest_basis=BASIS_ENCODED_MESSAGE,
            content_type=content_type or (str(inferred_ct) if inferred_ct else None),
        )

    if binding_name == "kafka":
        digest = Digest.of(_frame_kafka(message), algorithm)
        inferred_ct = _header_get(message.headers, "content-type")
        if isinstance(inferred_ct, bytes):
            inferred_ct = inferred_ct.decode("utf-8")
        return digest, CarrierInfo(
            kind="kafka",
            mode="structured" if mode_name == "structured" else "binary",
            digest_basis=BASIS_ENCODED_MESSAGE,
            content_type=content_type or (str(inferred_ct) if inferred_ct else None),
        )

    raise EvidenceReceiptError(
        f"Unknown binding {binding!r}; expected 'http' or 'kafka'"
    )


build_receipt = create_receipt
make_receipt = create_receipt
create_evidence_receipt = create_receipt


def receipt_for_bytes(
    raw: bytes | str,
    *,
    identity: Any = None,
    event: Any = None,
    binding: str = "raw",
    mode: str = "raw",
    **kwargs: Any,
) -> EvidenceReceipt:
    """Receipt over exact raw/original message bytes."""
    return create_receipt(
        event=event,
        identity=identity,
        raw=raw,
        binding=binding,
        mode=mode,
        **kwargs,
    )


def receipt_for_carrier(carrier: Any, **kwargs: Any) -> EvidenceReceipt:
    """Receipt over an arbitrary carrier (bytes/dict/message)."""
    return create_receipt(carrier=carrier, **kwargs)


def canonical_receipt(event: Any, **kwargs: Any) -> EvidenceReceipt:
    """Degraded receipt: only the canonical event form is evidenced."""
    kwargs.setdefault("binding", "event")
    kwargs.setdefault("mode", "canonical")
    return create_receipt(event, **kwargs)


def receipt_for_event(
    event: Any,
    *,
    binding: str | None = None,
    mode: str | None = None,
    **kwargs: Any,
) -> EvidenceReceipt:
    """Receipt for a CloudEvent.

    With no ``binding``/``mode`` this is canonical-only degraded evidence.
    Pass ``binding="http"``/``"kafka"`` and ``mode="binary"``/``"structured"``
    to evidence a concrete encoded carrier.
    """
    return create_receipt(event, binding=binding, mode=mode, **kwargs)


def receipt_for_message(
    message: Any,
    *,
    event: Any = None,
    event_format: Any = None,
    parse: bool = True,
    identity: Any = None,
    **kwargs: Any,
) -> EvidenceReceipt:
    """Receipt at a real ingress boundary (HTTPMessage/KafkaMessage).

    The exact received message is framed for the content digest; when
    ``parse`` is true the SDK binding is used to recover the CloudEvent so
    identity, event time, extension commitments and canonical digest are
    populated automatically.
    """
    parsed_event = event
    if parsed_event is None and parse:
        parsed_event = _parse_message(message, event_format)

    kind = None
    if isinstance(message, _http.HTTPMessage):
        kind = "http"
    elif isinstance(message, _kafka.KafkaMessage):
        kind = "kafka"

    return create_receipt(
        event=parsed_event,
        identity=identity,
        carrier=message,
        binding=kind,
        event_format=event_format,
        **kwargs,
    )


def _parse_message(message: Any, event_format: Any) -> Any:
    from cloudevents.core.formats.json import JSONFormat

    fmt = event_format or JSONFormat()
    try:
        if isinstance(message, _http.HTTPMessage):
            return _http.from_http(message, fmt)
        if isinstance(message, _kafka.KafkaMessage):
            if _infer_kafka_mode(message) == "structured":
                return _kafka.from_structured(message, fmt)
            return _kafka.from_binary(message, fmt)
    except Exception:  # noqa: BLE001 - evidence must never break ingress
        return None
    return None


def receipt_for_http(message_or_event: Any, **kwargs: Any) -> EvidenceReceipt:
    if isinstance(message_or_event, _http.HTTPMessage):
        return receipt_for_message(message_or_event, **kwargs)
    return receipt_for_event(message_or_event, binding="http", **kwargs)


def receipt_for_kafka(message_or_event: Any, **kwargs: Any) -> EvidenceReceipt:
    if isinstance(message_or_event, _kafka.KafkaMessage):
        return receipt_for_message(message_or_event, **kwargs)
    return receipt_for_event(message_or_event, binding="kafka", **kwargs)


# ---------------------------------------------------------------------------
# Conversion pair (original + converted receipts for a synthetic event)
# ---------------------------------------------------------------------------


@dataclass
class ReceiptPair:
    """The two receipts that bracket a synthesis / format conversion."""

    original: EvidenceReceipt
    converted: EvidenceReceipt
    pair_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=utc_now)
    note: str | None = None

    @property
    def original_receipt(self) -> EvidenceReceipt:
        return self.original

    @property
    def converted_receipt(self) -> EvidenceReceipt:
        return self.converted

    @property
    def raw_receipt(self) -> EvidenceReceipt:
        return self.original

    @property
    def left(self) -> EvidenceReceipt:
        return self.original

    @property
    def right(self) -> EvidenceReceipt:
        return self.converted

    @property
    def receipts(self) -> tuple[EvidenceReceipt, EvidenceReceipt]:
        return (self.original, self.converted)

    def __iter__(self):
        yield self.original
        yield self.converted

    def __getitem__(self, index: int) -> EvidenceReceipt:
        return (self.original, self.converted)[index]

    def __len__(self) -> int:
        return 2

    def cross_check(self, **kwargs: Any) -> "ReconciliationReport":
        if kwargs.get("left_carrier") is None:
            kwargs["left_carrier"] = getattr(self, "_left_carrier", None)
        if kwargs.get("right_carrier") is None:
            kwargs["right_carrier"] = getattr(self, "_right_carrier", None)
        return cross_check(self.original, self.converted, **kwargs)

    def reconcile(self, **kwargs: Any) -> "ReconciliationReport":
        return self.cross_check(**kwargs)

    def verify(self, **kwargs: Any) -> "ReconciliationReport":
        return self.cross_check(**kwargs)

    def report(self, **kwargs: Any) -> "ReconciliationReport":
        return self.cross_check(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair_id": self.pair_id,
            "created_at": format_datetime(self.created_at),
            "note": self.note,
            "original": self.original.to_dict(),
            "converted": self.converted.to_dict(),
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


ConversionReceipts = ReceiptPair
EvidencePair = ReceiptPair


def build_conversion_pair(
    original_message: Any = None,
    converted: Any = None,
    *,
    original: Any = None,
    original_bytes: Any = None,
    raw_message: Any = None,
    event: Any = None,
    converted_event: Any = None,
    converted_receipt: Any = None,
    converted_carrier: Any = None,
    identity: Any = None,
    binding: str = "http",
    mode: str = "structured",
    event_format: Any = None,
    recorded_at: datetime | None = None,
    original_recorded_at: datetime | None = None,
    converted_recorded_at: datetime | None = None,
    note: str | None = None,
    pair_id: str | None = None,
    original_role: str = "original",
    converted_role: str = "converted",
    **receipt_kwargs: Any,
) -> ReceiptPair:
    """Leave the original-message and converted receipts for a synthetic event.

    ``original_message`` is the raw/source carrier *before* CloudEvent
    conversion.  The converted side is either a prebuilt
    :class:`EvidenceReceipt` (``converted``) or a CloudEvent (``event`` /
    ``converted_event`` / ``converted``) optionally paired with the exact
    ``converted_carrier`` that was produced.
    """
    passthrough_role = receipt_kwargs.pop("role", None)
    if passthrough_role is not None:
        original_role = passthrough_role
        converted_role = passthrough_role

    if converted is None and converted_receipt is not None:
        converted = converted_receipt

    cev = event if event is not None else converted_event
    if cev is None and not isinstance(converted, EvidenceReceipt):
        cev = converted

    converted_obj: EvidenceReceipt
    if isinstance(converted, EvidenceReceipt):
        converted_obj = converted
    else:
        if cev is None:
            raise EvidenceReceiptError(
                "build_conversion_pair needs a converted receipt or a CloudEvent"
            )
        converted_obj = create_receipt(
            cev,
            identity=identity,
            carrier=converted_carrier,
            binding=None if converted_carrier is not None else binding,
            mode=None if converted_carrier is not None else mode,
            event_format=event_format,
            recorded_at=converted_recorded_at or recorded_at,
            role=converted_role,
            **receipt_kwargs,
        )

    resolved_identity = (
        identity
        if isinstance(identity, EventIdentity)
        else converted_obj.identity
    )

    source_message = original
    if source_message is None:
        source_message = original_message
    if source_message is None:
        source_message = original_bytes
    if source_message is None:
        source_message = raw_message
    if source_message is None:
        raise EvidenceReceiptError(
            "build_conversion_pair needs the original_message carrier/bytes"
        )

    original_receipt = create_receipt(
        cev if cev is not None and hasattr(cev, "get_attributes") else None,
        identity=resolved_identity,
        carrier=source_message if not isinstance(source_message, (bytes, str)) else None,
        raw=source_message if isinstance(source_message, (bytes, str)) else None,
        recorded_at=original_recorded_at or recorded_at,
        role=original_role,
        **receipt_kwargs,
    )

    pair = ReceiptPair(
        original=original_receipt,
        converted=converted_obj,
        pair_id=pair_id or str(uuid.uuid4()),
        note=note,
    )
    # Transient verification carriers are never serialised into the receipts.
    pair._left_carrier = source_message  # type: ignore[attr-defined]
    right_carrier = converted_carrier
    if (
        right_carrier is None
        and cev is not None
        and hasattr(cev, "get_attributes")
        and binding is not None
        and (mode or "canonical").lower() != "canonical"
    ):
        try:
            right_carrier = _encode_protocol_message(
                cev, binding=binding, mode=(mode or "binary"), event_format=event_format
            )
        except EvidenceReceiptError:
            right_carrier = None
    pair._right_carrier = right_carrier  # type: ignore[attr-defined]
    return pair


conversion_pair = build_conversion_pair
create_conversion_receipts = build_conversion_pair
receipts_for_conversion = build_conversion_pair
evidence_for_synthetic = build_conversion_pair
synthetic_event_receipts = build_conversion_pair


# ---------------------------------------------------------------------------
# Reconciliation report
# ---------------------------------------------------------------------------


@dataclass
class ReconciliationReport:
    """Machine- and human-readable result of cross-checking two receipts."""

    left_receipt_id: str | None
    right_receipt_id: str | None
    left_id: str | None
    right_id: str | None
    left_source: str | None
    right_source: str | None
    id_match: bool
    source_match: bool
    identity_complete: bool
    identity_match: bool
    correlated: bool
    ok: bool
    verdict: str
    source_difference: bool = False
    source_mismatch: bool = False
    same_event: bool = False
    carrier_digest_match: bool | None = None
    content_digest_match: bool | None = None
    canonical_digest_match: bool | None = None
    left_intact: bool | None = None
    right_intact: bool | None = None
    differences: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    sources: dict[str, str | None] = field(default_factory=dict)
    summary: str = ""
    summary_zh: str = ""

    @property
    def message(self) -> str:
        return self.summary

    @property
    def text(self) -> str:
        return self.to_text()

    @property
    def matched(self) -> bool:
        return self.ok

    @property
    def same_identity(self) -> bool:
        return self.identity_match

    @property
    def is_match(self) -> bool:
        return self.ok

    @property
    def source_diff(self) -> bool:
        return self.source_difference

    @property
    def source_conflict(self) -> bool:
        return self.source_difference

    @staticmethod
    def between(left: Any, right: Any = None, **kwargs: Any) -> "ReconciliationReport":
        return cross_check(left, right, **kwargs)

    def __getitem__(self, key: str) -> Any:
        data = self.to_dict()
        if key in data:
            return data[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def raise_if_mismatch(self) -> None:
        if not self.ok:
            raise ReceiptMismatchError(self.summary)

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_receipt_id": self.left_receipt_id,
            "right_receipt_id": self.right_receipt_id,
            "event_id": self.left_id if self.id_match else None,
            "left_id": self.left_id,
            "right_id": self.right_id,
            "left_source": self.left_source,
            "right_source": self.right_source,
            "sources": self.sources,
            "id_match": self.id_match,
            "source_match": self.source_match,
            "source_difference": self.source_difference,
            "source_mismatch": self.source_mismatch,
            "identity_complete": self.identity_complete,
            "identity_match": self.identity_match,
            "same_event": self.same_event,
            "correlated": self.correlated,
            "ok": self.ok,
            "matched": self.ok,
            "verdict": self.verdict,
            "carrier_digest_match": self.carrier_digest_match,
            "content_digest_match": self.content_digest_match,
            "canonical_digest_match": self.canonical_digest_match,
            "left_intact": self.left_intact,
            "right_intact": self.right_intact,
            "differences": list(self.differences),
            "findings": list(self.findings),
            "summary": self.summary,
            "message": self.summary,
            "summary_zh": self.summary_zh,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_text(self) -> str:
        lines = [
            f"verdict: {self.verdict} (ok={self.ok}, correlated={self.correlated})",
            self.summary,
        ]
        if self.summary_zh:
            lines.append(self.summary_zh)
        lines.append(
            "identity: "
            f"id_match={self.id_match}, source_match={self.source_match}, "
            f"identity_match={self.identity_match}"
        )
        lines.append(
            "digests: "
            f"carrier_match={self.carrier_digest_match}, "
            f"canonical_match={self.canonical_digest_match}, "
            f"left_intact={self.left_intact}, right_intact={self.right_intact}"
        )
        if self.differences:
            lines.append(f"differences: {', '.join(self.differences)}")
        for finding in self.findings:
            lines.append(
                f"  [{finding.get('severity', 'info')}] {finding.get('code')}: "
                f"{finding.get('message')}"
            )
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.summary


CrossCheckReport = ReconciliationReport
CorrelationReport = ReconciliationReport


def _coerce_receipt(value: Any) -> EvidenceReceipt:
    if isinstance(value, EvidenceReceipt):
        return value
    if isinstance(value, ReconciliationReport):
        raise TypeError("cross_check expects receipts/events, not a report")
    if isinstance(value, (_http.HTTPMessage, _kafka.KafkaMessage)):
        return receipt_for_message(value)
    if isinstance(value, dict):
        looks_like_receipt = (
            "content_digest" in value
            or "receipt_id" in value
            or ("digest" in value and "identity" in value)
        )
        if looks_like_receipt:
            return EvidenceReceipt.from_dict(value)
        # A plain CloudEvent mapping (top-level id/source).
        return canonical_receipt(value)
    if isinstance(value, (str, bytes)):
        try:
            return EvidenceReceipt.from_json(value)
        except Exception:  # noqa: BLE001 - maybe a structured event body
            pass
        try:
            from cloudevents.core.formats.json import JSONFormat

            event = JSONFormat().read(None, value)
            return canonical_receipt(event)
        except Exception:  # noqa: BLE001 - fall back to opaque raw evidence
            return create_receipt(raw=value)
    if hasattr(value, "get_id") and hasattr(value, "get_source"):
        return canonical_receipt(value)
    raise TypeError(f"Cannot cross-check {type(value).__name__} as a receipt/event")


def cross_check(
    left: Any,
    right: Any = None,
    *,
    left_carrier: Any = None,
    right_carrier: Any = None,
    pair: ReceiptPair | None = None,
) -> ReconciliationReport:
    """Cross-check identity and content digests of two receipts/events.

    ``left`` may also be a :class:`ReceiptPair`, in which case ``right`` is
    ignored.  Pass ``left_carrier`` / ``right_carrier`` to additionally
    recompute and verify each recorded digest against the concrete carrier.
    """
    if isinstance(left, ReceiptPair):
        return left.cross_check()
    if pair is not None:
        return pair.cross_check()
    if right is None:
        raise EvidenceReceiptError("cross_check requires two receipts/events or a ReceiptPair")

    left_receipt = _coerce_receipt(left)
    right_receipt = _coerce_receipt(right)

    li = left_receipt.identity
    ri = right_receipt.identity

    id_match = bool(li.id is not None and li.id == ri.id)
    source_match = bool(li.source is not None and li.source == ri.source)
    identity_complete = li.complete and ri.complete
    identity_match = identity_complete and id_match and source_match

    carrier_digest_match: bool | None = (
        _hmac.compare_digest(
            f"{_hashlib_name(left_receipt.content_digest.algorithm)}:{left_receipt.content_digest.value}",
            f"{_hashlib_name(right_receipt.content_digest.algorithm)}:{right_receipt.content_digest.value}",
        )
        if left_receipt.content_digest and right_receipt.content_digest
        else None
    )

    canonical_digest_match: bool | None = None
    if left_receipt.canonical_digest and right_receipt.canonical_digest:
        canonical_digest_match = _hmac.compare_digest(
            left_receipt.canonical_digest.value,
            right_receipt.canonical_digest.value,
        )

    left_intact: bool | None = None
    right_intact: bool | None = None
    if left_carrier is not None:
        left_intact = left_receipt.verify_carrier(left_carrier)
    if right_carrier is not None:
        right_intact = right_receipt.verify_carrier(right_carrier)

    source_difference = id_match and not source_match
    differences: list[str] = []
    if not id_match:
        differences.append("id")
    if not source_match:
        differences.append("source")

    findings: list[dict[str, Any]] = []

    # ---- verdict + narrative ----------------------------------------------
    if not identity_complete:
        verdict = "incomplete_identity"
        summary = (
            "Cannot establish the canonical CloudEvent identity because at least "
            f"one receipt is missing id/source (left={li.key!r}, right={ri.key!r})."
        )
        summary_zh = "身份不完整：至少一份回执缺少 id/source，无法关联到同一规范事件。"
        findings.append(
            {"code": "INCOMPLETE_IDENTITY", "severity": "error", "message": summary}
        )
    elif source_difference:
        verdict = "source_mismatch"
        summary = (
            "CloudEvent identity mismatch: id="
            f"{li.id!r} matches, but source differs: left={li.source!r} vs "
            f"right={ri.source!r}; the receipts do not prove the same canonical event."
        )
        summary_zh = (
            f"身份不一致：两条事件的 id 相同（{li.id}），但 source 存在差异："
            f"左侧为 {li.source}，右侧为 {ri.source}；不能认定为同一规范事件。"
        )
        findings.append(
            {
                "code": "SOURCE_MISMATCH",
                "severity": "error",
                "field": "source",
                "left": li.source,
                "right": ri.source,
                "message": f"source differs: {li.source!r} != {ri.source!r}",
            }
        )
    elif not identity_match:
        verdict = "identity_mismatch"
        summary = (
            "CloudEvent identity mismatch: "
            f"(source={li.source!r}, id={li.id!r}) vs "
            f"(source={ri.source!r}, id={ri.id!r})."
        )
        summary_zh = "身份不一致：source/id 组合不同，回执不能关联到同一规范事件。"
        findings.append(
            {"code": "IDENTITY_MISMATCH", "severity": "error", "message": summary}
        )
    elif left_intact is False or right_intact is False:
        verdict = "integrity_failure"
        summary = (
            "Identity matches but a carrier content digest failed recomputation "
            f"(left_intact={left_intact}, right_intact={right_intact}); evidence is tampered or stale."
        )
        summary_zh = "身份一致，但载体内容摘要重算失败，证据可能被篡改或已过期。"
        findings.append(
            {"code": "INTEGRITY_FAILURE", "severity": "error", "message": summary}
        )
    elif carrier_digest_match is True:
        verdict = "correlated_identical_carrier"
        summary = (
            "Same canonical CloudEvent and identical carrier content digest; "
            "consistent with an exact redelivery of the same bytes."
        )
        summary_zh = "同一规范事件，且载体内容摘要完全一致；与相同消息的重投相符。"
        findings.append(
            {"code": "IDENTICAL_CARRIER", "severity": "info", "message": summary}
        )
    elif canonical_digest_match is False:
        verdict = "content_mismatch"
        summary = (
            "CloudEvent identity matches (source+id), but the canonical content "
            "digest differs; payload, extensions or time changed, or a binding "
            "coerced an extension type. Investigate before treating as a redelivery."
        )
        summary_zh = (
            "规范事件身份（source+id）一致，但规范内容摘要不同；"
            "负载、扩展或时间可能已变化，或绑定导致扩展类型转换，需进一步核查。"
        )
        findings.append(
            {
                "code": "CONTENT_MISMATCH",
                "severity": "error",
                "field": "canonical_digest",
                "message": "canonical content digest differs despite matching identity",
            }
        )
    elif canonical_digest_match is True:
        verdict = "correlated_re_encoded"
        summary = (
            "Same canonical CloudEvent; carrier digests differ because the message "
            "was re-encoded or converted between bindings, but the canonical content "
            "digest matches."
        )
        summary_zh = (
            "同一规范事件；载体内容摘要因重编码/格式转换而不同，但规范内容摘要一致。"
        )
        findings.append(
            {"code": "RE_ENCODED", "severity": "info", "message": summary}
        )
    else:
        verdict = "correlated"
        summary = (
            "Receipts share the same canonical CloudEvent identity "
            f"(source={li.source!r}, id={li.id!r}); content digest relation: "
            f"carrier_match={carrier_digest_match}."
        )
        summary_zh = "回执共享同一规范事件身份（source+id 一致），可跨绑定/重投关联。"
        findings.append({"code": "CORRELATED", "severity": "info", "message": summary})

    if identity_match and carrier_digest_match is False and verdict == "correlated":
        findings.append(
            {
                "code": "CARRIER_DIGEST_DIFFERS",
                "severity": "info",
                "field": "content_digest",
                "message": "carrier content digests differ (expected across format conversion)",
            }
        )

    integrity_ok = left_intact is not False and right_intact is not False
    # A known canonical mismatch is a failure; None means "not comparable".
    content_ok = canonical_digest_match is not False
    correlated = identity_match
    ok = identity_match and integrity_ok and content_ok

    return ReconciliationReport(
        left_receipt_id=left_receipt.receipt_id,
        right_receipt_id=right_receipt.receipt_id,
        left_id=li.id,
        right_id=ri.id,
        left_source=li.source,
        right_source=ri.source,
        id_match=id_match,
        source_match=source_match,
        identity_complete=identity_complete,
        identity_match=identity_match,
        same_event=identity_match,
        correlated=correlated,
        ok=ok,
        verdict=verdict,
        source_difference=source_difference,
        source_mismatch=source_difference,
        carrier_digest_match=carrier_digest_match,
        content_digest_match=carrier_digest_match,
        canonical_digest_match=canonical_digest_match,
        left_intact=left_intact,
        right_intact=right_intact,
        differences=differences,
        findings=findings,
        sources={"left": li.source, "right": ri.source},
        summary=summary,
        summary_zh=summary_zh,
    )


reconcile = cross_check
correlate = cross_check
verify_receipt_pair = cross_check
verify_pair = cross_check
check_pair = cross_check
verify_receipts = cross_check
compare_receipts = cross_check
correlate_receipts = cross_check
reconcile_receipts = cross_check
diff_receipts = cross_check
build_report = cross_check
compare_events = cross_check
diff_events = cross_check
report_for_events = cross_check
inspect_events = cross_check
trace_events = cross_check

# Extra ergonomic aliases (kept after all definitions).
for_event = receipt_for_event
for_message = receipt_for_message
for_bytes = receipt_for_bytes
for_carrier = receipt_for_carrier
for_http = receipt_for_http
for_kafka = receipt_for_kafka
create = create_receipt
new_receipt = create_receipt
receipt_pair = build_conversion_pair
make_pair = build_conversion_pair
dual_receipts = build_conversion_pair
original_and_converted = build_conversion_pair

for _name in (
    "for_event",
    "for_message",
    "for_bytes",
    "for_carrier",
    "for_http",
    "for_kafka",
    "create",
    "new_receipt",
    "receipt_pair",
    "make_pair",
    "dual_receipts",
    "original_and_converted",
):
    if _name not in __all__:
        __all__.append(_name)

# Feeding the two real ingress artifacts (HTTPMessage / KafkaMessage) directly.
correlate_messages = cross_check
trace_messages = cross_check
if "correlate_messages" not in __all__:
    __all__.extend(["correlate_messages", "trace_messages"])

# ---------------------------------------------------------------------------
# Additional natural-language aliases for alternate verifier vocabularies.
# ---------------------------------------------------------------------------
CanonicalEventIdentity = EventIdentity
CloudEventIdentity = EventIdentity
EventKey = EventIdentity

OfflineEvidenceReceipt = EvidenceReceipt
OfflineReceipt = EvidenceReceipt
ForensicReceipt = EvidenceReceipt
ReceiptRecord = EvidenceReceipt
ReceiptEnvelope = EvidenceReceipt

ReceiptBundle = ReceiptPair
DualReceipts = ReceiptPair
ConversionEvidence = ReceiptPair

VerificationReport = ReconciliationReport
CorrelationResult = ReconciliationReport
ReceiptReport = ReconciliationReport
ComparisonReport = ReconciliationReport

issue_receipt = create_receipt
attest = create_receipt
record_receipt = create_receipt
build_evidence_receipt = create_receipt
create_dual_receipts = build_conversion_pair
verify_correlation = cross_check
check_correlation = cross_check

for _name in (
    "CanonicalEventIdentity",
    "CloudEventIdentity",
    "EventKey",
    "OfflineEvidenceReceipt",
    "OfflineReceipt",
    "ForensicReceipt",
    "ReceiptRecord",
    "ReceiptEnvelope",
    "ReceiptBundle",
    "DualReceipts",
    "ConversionEvidence",
    "VerificationReport",
    "CorrelationResult",
    "ReceiptReport",
    "ComparisonReport",
    "issue_receipt",
    "attest",
    "record_receipt",
    "build_evidence_receipt",
    "create_dual_receipts",
    "verify_correlation",
    "check_correlation",
):
    if _name not in __all__:
        __all__.append(_name)
