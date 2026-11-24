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

"""
Content approval for CloudEvents.

A service can approve the content of a CloudEvent once (attributes, extensions
and data) and later hand the resulting :class:`EventApproval` to an
asynchronous worker.  The worker may pick a different protocol binding or
content mode for delivery; the approval is transport independent, so switching
from, for example, HTTP binary mode to Kafka structured mode keeps the approval
valid.  Any change to the approved attributes, extensions or data is detected
before the event is serialised for publishing.

Example:
    >>> from cloudevents.core.v1.event import CloudEvent
    >>> from cloudevents.core.approval import approve
    >>> from cloudevents.core.bindings import http
    >>>
    >>> event = CloudEvent(
    ...     attributes={
    ...         "type": "com.example.order",
    ...         "source": "/orders",
    ...         "tenant": "acme",
    ...     },
    ...     data={"order_id": "42"},
    ... )
    >>> approval = approve(event)
    >>>
    >>> # Later, in a worker that may use any binding/content mode:
    >>> message = http.to_binary_event(event, approval=approval)
"""

import base64
import hashlib
import hmac
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from cloudevents.core.base import BaseCloudEvent
from cloudevents.core.exceptions import BaseCloudEventException

APPROVAL_VERSION = 1
DEFAULT_ALGORITHM = "sha256"
SUPPORTED_ALGORITHMS = frozenset(hashlib.algorithms_guaranteed)

#: Attributes defined by the CloudEvents specifications.  Everything else in
#: ``event.get_attributes()`` is an extension attribute covered by approvals.
STANDARD_ATTRIBUTES = frozenset(
    {
        "id",
        "source",
        "type",
        "specversion",
        "datacontenttype",
        "dataschema",
        "subject",
        "time",
        # v0.3 names
        "datacontentencoding",
        "schemaurl",
    }
)


class ApprovalPhase(str, Enum):
    """
    Stage at which an approval check failed.

    Every :class:`ApprovalError` carries one of these values so callers (and
    logs) can tell whether the failure happened while approving content, while
    explicitly verifying an event, or while preparing a transport message for
    publishing.
    """

    APPROVE = "approve"
    """The content could not be approved (for example unsupported data types)."""

    VERIFY = "verify"
    """An explicit verification call found content that differs from the approval."""

    PRE_PUBLISH = "pre_publish"
    """A protocol binding rejected the event immediately before serialisation."""


class ApprovalError(BaseCloudEventException):
    """
    Raised when CloudEvent content cannot be approved or no longer matches.

    :ivar phase: The :class:`ApprovalPhase` in which the failure happened.
    :ivar mismatches: Canonical paths of the content differences, when known.
    """

    def __init__(
        self,
        phase: ApprovalPhase,
        message: str,
        mismatches: Sequence[str] = (),
    ) -> None:
        self.phase: ApprovalPhase = phase
        self.mismatches: tuple[str, ...] = tuple(mismatches)
        super().__init__(f"[phase={phase.value}] {message}")


class ApprovalMismatchError(ApprovalError):
    """Raised when an event's content differs from the approved content."""


class ApprovalSerializationError(ApprovalError):
    """Raised when an approval token cannot be serialised or restored."""


def _canonical_datetime(value: datetime) -> str:
    """Render a datetime in a stable RFC 3339 representation."""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc)
    text = value.isoformat(timespec="microseconds")
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


def _canonical_value(value: Any, path: str) -> Any:
    """
    Convert a Python value into a deterministic, JSON-compatible structure.

    Type tags keep values that Python considers equal but that are not
    interchangeable distinct (``True``/``1``, ``1``/``1.0``, ``"1"``/``1``,
    bytes/str).  Values that cannot be represented faithfully are rejected
    instead of being silently coerced.
    """
    if isinstance(value, datetime):
        return {"$type": "datetime", "$value": _canonical_datetime(value)}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {
            "$type": "bytes",
            "$value": base64.b64encode(bytes(value)).decode("ascii"),
        }
    if isinstance(value, bool):
        return {"$type": "bool", "$value": value}
    if isinstance(value, int):
        return {"$type": "int", "$value": value}
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ApprovalError(
                ApprovalPhase.APPROVE,
                f"Unsupported non-finite number at {path}; "
                "CloudEvent content must be finite JSON numbers",
            )
        return {"$type": "float", "$value": repr(value)}
    if isinstance(value, str):
        return {"$type": "str", "$value": value}
    if value is None:
        return {"$type": "null", "$value": None}
    if isinstance(value, Mapping):
        entries: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ApprovalError(
                    ApprovalPhase.APPROVE,
                    f"Unsupported non-string mapping key at {path}; "
                    "CloudEvent content must use JSON object keys",
                )
            entries[key] = _canonical_value(item, f"{path}.{key}")
        return {"$type": "object", "$value": entries}
    if isinstance(value, (list, tuple)):
        return {
            "$type": "array",
            "$value": [
                _canonical_value(item, f"{path}[{index}]")
                for index, item in enumerate(value)
            ],
        }
    raise ApprovalError(
        ApprovalPhase.APPROVE,
        f"Unsupported value at {path} of type {type(value).__name__}; "
        "CloudEvent content must be JSON-compatible",
    )


def _approved_attributes(event: BaseCloudEvent) -> dict[str, Any]:
    """Return the attributes covered by an approval (``None`` values omitted)."""
    return {
        name: value
        for name, value in event.get_attributes().items()
        if value is not None
    }


def _canonical_content(event: BaseCloudEvent) -> dict[str, Any]:
    """
    Build the canonical tree covered by an approval.

    The tree is a canonical object node containing all non-``None`` attributes
    (including ``specversion``) and the data, so every part of the delivered
    content is covered by the digest and differences can be reported by path.
    """
    return {
        "$type": "object",
        "$value": {
            "attributes": _canonical_value(
                _approved_attributes(event), "attributes"
            ),
            "data": _canonical_value(event.get_data(), "data"),
        },
    }


def _canonical_bytes(content: Mapping[str, Any]) -> bytes:
    return json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _flatten_canonical(
    node: Any,
    path: str,
    leaves: dict[str, tuple[str, Any]],
) -> None:
    """
    Flatten a canonical tree into ``path -> (leaf type, leaf value)`` entries.

    Container shape changes are recorded as ``array_len``/``object`` markers so
    a mismatch can point at a meaningful location rather than at the internal
    ``$type``/``$value`` wrappers.
    """
    node_type = node["$type"]
    value = node["$value"]

    if node_type == "object":
        if not value:
            leaves[path or "$"] = ("object", ())
        for key, child in value.items():
            _flatten_canonical(child, f"{path}.{key}" if path else key, leaves)
        return

    if node_type == "array":
        leaves[path or "$"] = ("array_len", len(value))
        for index, child in enumerate(value):
            _flatten_canonical(child, f"{path}[{index}]", leaves)
        return

    leaves[path or "$"] = (node_type, value)


def _diff_paths(expected: Any, actual: Any) -> list[str]:
    """Return human-readable paths at which two canonical trees differ."""
    expected_leaves: dict[str, tuple[str, Any]] = {}
    actual_leaves: dict[str, tuple[str, Any]] = {}
    _flatten_canonical(expected, "", expected_leaves)
    _flatten_canonical(actual, "", actual_leaves)

    return sorted(
        path
        for path in set(expected_leaves) | set(actual_leaves)
        if expected_leaves.get(path) != actual_leaves.get(path)
    )


def _normalise_key(key: bytes | str | None) -> bytes | None:
    """Normalise an optional shared key to bytes."""
    if key is None:
        return None
    if isinstance(key, str):
        return key.encode("utf-8")
    return bytes(key)


def _content_digest(
    algorithm: str,
    encoded: bytes,
    key: bytes | None,
) -> str:
    """Hash (or HMAC) canonical content bytes."""
    if key is None:
        return hashlib.new(algorithm, encoded).hexdigest()
    return hmac.new(key, encoded, algorithm).hexdigest()


def _mismatch_summary(paths: Iterable[str]) -> str:
    paths = tuple(paths)
    if not paths:
        return "content digest does not match"
    return "content differs at: " + ", ".join(paths)


@dataclass(frozen=True)
class EventApproval:
    """
    A transport-independent approval of a CloudEvent's content.

    The approval covers all standard attributes, every extension attribute
    present in the event and the event data.  It can be handed to a different
    process (see :meth:`to_dict` / :meth:`from_dict`) and verified against the
    event right before any protocol binding serialises it.
    """

    digest: str
    algorithm: str = DEFAULT_ALGORITHM
    specversion: str = "1.0"
    extensions: tuple[str, ...] | None = None
    """Recorded extension names; ``None`` when the token does not record them."""
    keyed: bool = False
    """Whether the digest is an HMAC computed with a shared key."""
    canonical: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        # The shared key is kept off the dataclass fields so that
        # ``dataclasses.asdict()`` and ``fields()`` never expose it.
        object.__setattr__(self, "_shared_key", None)

    @property
    def _key(self) -> bytes | None:
        return getattr(self, "_shared_key", None)

    def verify(
        self,
        event: BaseCloudEvent,
        *,
        phase: ApprovalPhase = ApprovalPhase.VERIFY,
    ) -> None:
        """
        Raise :class:`ApprovalMismatchError` if ``event`` is not approved.

        :param event: The event held by the worker.
        :param phase: Phase marker attached to a failure.
        """
        if self.keyed and self._key is None:
            raise ApprovalError(
                phase,
                "Approval was created with a shared key; "
                "provide the key to verify it",
            )

        content = _canonical_content(event)
        encoded = _canonical_bytes(content)
        actual_digest = _content_digest(self.algorithm, encoded, self._key)

        if hmac.compare_digest(self.digest, actual_digest):
            self._check_recorded_extensions(event, phase)
            return

        paths: list[str] = []
        if self.canonical is not None:
            paths = _diff_paths(json.loads(self.canonical), content)
        raise ApprovalMismatchError(
            phase,
            "CloudEvent content does not match the approved content: "
            + _mismatch_summary(paths),
            mismatches=paths,
        )

    def _check_recorded_extensions(
        self,
        event: BaseCloudEvent,
        phase: ApprovalPhase,
    ) -> None:
        """Ensure the token's recorded extension names still describe the event."""
        if self.extensions is None:
            return

        actual = tuple(
            sorted(set(_approved_attributes(event)) - STANDARD_ATTRIBUTES)
        )
        if tuple(self.extensions) == actual:
            return

        changed = sorted(set(self.extensions) ^ set(actual))
        raise ApprovalMismatchError(
            phase,
            "Approved extension set does not match the event extensions: "
            f"approved {list(self.extensions)}, event has {list(actual)}",
            mismatches=tuple(f"extensions.{name}" for name in changed),
        )

    def matches(self, event: BaseCloudEvent) -> bool:
        """Return whether ``event`` still matches this approval."""
        try:
            self.verify(event)
        except ApprovalMismatchError:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        """
        Return a compact, JSON-serialisable approval token.

        The token carries the digest, not the event payload, so it can be
        stored in a job record or message header.  Content differences cannot
        be listed individually when verifying from a compact token.
        """
        return {
            "approval_version": APPROVAL_VERSION,
            "algorithm": self.algorithm,
            "digest": self.digest,
            "specversion": self.specversion,
            "extensions": (
                list(self.extensions) if self.extensions is not None else None
            ),
            "keyed": self.keyed,
        }

    @classmethod
    def from_dict(
        cls,
        token: Mapping[str, Any],
        *,
        key: bytes | str | None = None,
    ) -> "EventApproval":
        """
        Restore an approval token produced by :meth:`to_dict`.

        :raises ApprovalSerializationError: If the token is malformed or uses
            an unsupported hash algorithm.
        """
        if not isinstance(token, Mapping):
            raise ApprovalSerializationError(
                ApprovalPhase.APPROVE,
                f"Malformed approval token: expected a mapping, got "
                f"{type(token).__name__}",
            )

        try:
            version = int(token["approval_version"])
            algorithm = str(token["algorithm"])
            digest = str(token["digest"])
            specversion = str(token.get("specversion", "1.0"))
            raw_extensions = token.get("extensions")
            extensions = (
                tuple(str(name) for name in raw_extensions)
                if raw_extensions is not None
                else None
            )
            keyed = bool(token.get("keyed", False))
        except (KeyError, TypeError, ValueError) as error:
            raise ApprovalSerializationError(
                ApprovalPhase.APPROVE,
                f"Malformed approval token: {error!r}",
            ) from error

        if version != APPROVAL_VERSION:
            raise ApprovalSerializationError(
                ApprovalPhase.APPROVE,
                f"Unsupported approval token version: {version}",
            )
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ApprovalSerializationError(
                ApprovalPhase.APPROVE,
                f"Unsupported approval algorithm: {algorithm}",
            )
        if not digest:
            raise ApprovalSerializationError(
                ApprovalPhase.APPROVE,
                "Approval token is missing its digest",
            )

        restored = cls(
            digest=digest,
            algorithm=algorithm,
            specversion=specversion,
            extensions=extensions,
            keyed=keyed,
        )
        object.__setattr__(restored, "_shared_key", _normalise_key(key))
        return restored


def approve(
    event: BaseCloudEvent,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
    key: bytes | str | None = None,
) -> EventApproval:
    """
    Approve the current content of ``event``.

    The returned approval is transport independent: it remains valid when a
    worker delivers the event through a different protocol binding or content
    mode, as long as the attributes, approved extensions and data are unchanged.

    :param event: The CloudEvent whose content is being approved.
    :param algorithm: Hash algorithm used for the content digest.
    :param key: Optional shared secret.  When provided the digest becomes an
        HMAC, so a worker that lacks the key cannot alter the content and
        re-compute a matching approval; the key itself is never serialised.
    :raises ApprovalError: If the event contains values that cannot be
        canonicalised; the error carries ``phase=approve``.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ApprovalError(
            ApprovalPhase.APPROVE,
            f"Unsupported approval algorithm: {algorithm}",
        )

    normalised_key = _normalise_key(key)
    content = _canonical_content(event)
    encoded = _canonical_bytes(content)
    extensions = sorted(
        set(_approved_attributes(event)) - STANDARD_ATTRIBUTES
    )

    approval = EventApproval(
        digest=_content_digest(algorithm, encoded, normalised_key),
        algorithm=algorithm,
        specversion=event.get_specversion(),
        extensions=tuple(extensions),
        keyed=normalised_key is not None,
        canonical=encoded,
    )
    object.__setattr__(approval, "_shared_key", normalised_key)
    return approval


def verify(
    approval: EventApproval,
    event: BaseCloudEvent,
    *,
    phase: ApprovalPhase = ApprovalPhase.VERIFY,
) -> None:
    """
    Verify that ``event`` still matches ``approval``.

    :param approval: The approval created when the content was approved.
    :param event: The event held by the worker.
    :param phase: Phase marker attached to a failure.
    :raises ApprovalMismatchError: If the content differs.
    """
    approval.verify(event, phase=phase)


def verify_event(
    event: BaseCloudEvent,
    approval: EventApproval,
    *,
    phase: ApprovalPhase = ApprovalPhase.VERIFY,
) -> None:
    """Convenience wrapper for :func:`verify` with the event first."""
    approval.verify(event, phase=phase)


def require_approval(
    event: BaseCloudEvent,
    approval: EventApproval | None,
    *,
    phase: ApprovalPhase = ApprovalPhase.PRE_PUBLISH,
) -> None:
    """
    Verify ``event`` when an approval is supplied; do nothing otherwise.

    Protocol bindings call this before serialising so a modified event is
    rejected before anything is published, with ``phase=pre_publish``.
    """
    if approval is not None:
        approval.verify(event, phase=phase)


# Discoverable aliases used in documentation and by callers.
approve_event = approve
ApprovalToken = EventApproval
