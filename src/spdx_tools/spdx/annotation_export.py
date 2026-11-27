# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Controlled export of SPDX annotations for sharing.

SPDX annotations are often used to carry investigation notes next to the elements they refer to.
Some of those notes may contain material that must not leave the organization.  This module keeps
the investigation link (the annotated ``spdx_id``) intact while replacing restricted annotations
with a minimal, approved view.  Restricted annotations are replaced by a deterministic audit
reference so that an internal reviewer can map the shared annotation back to the original record.

Only the data in :class:`Annotation` is touched.  Packages, files, snippets and relationships are
copied unchanged, so the resulting document still validates and can be converted between all SPDX
2.x formats.
"""

import hashlib
import hmac
import json
import os
import re
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum, auto
from pathlib import Path

from beartype.typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from spdx_tools.spdx.datetime_conversions import datetime_to_iso_string
from spdx_tools.spdx.model import Actor, ActorType, Annotation, AnnotationType, Document

STABLE_ID_PREFIX = "ann-"
STABLE_ID_PATTERN = re.compile(r"ann-[0-9a-f]{64}")
DEFAULT_REDACTED_COMMENT_TEMPLATE = "[restricted annotation] audit reference: {stable_id}"
DEFAULT_REDACTED_ANNOTATOR_NAME = "SPDX-ANNOTATION-REDACTED"
DEFAULT_REDACTED_ANNOTATION_TYPE = AnnotationType.OTHER
DEFAULT_REDACTED_ANNOTATION_DATE = datetime(1970, 1, 1)


def _default_redacted_annotator() -> Actor:
    return Actor(ActorType.TOOL, DEFAULT_REDACTED_ANNOTATOR_NAME)


class AnnotationField(Enum):
    """Fields of an annotation that can be approved for a restricted annotation."""

    ANNOTATION_TYPE = auto()
    ANNOTATOR = auto()
    ANNOTATION_DATE = auto()
    COMMENT = auto()


DEFAULT_APPROVED_FIELDS: FrozenSet[AnnotationField] = frozenset(
    {AnnotationField.ANNOTATION_TYPE, AnnotationField.ANNOTATOR, AnnotationField.ANNOTATION_DATE}
)


@dataclass(frozen=True)
class AnnotationExportPolicy:
    """Controls which annotations are restricted and which fields may be shared.

    An annotation is restricted when any selector matches.  The selectors are intentionally
    explicit: there is no implicit "all annotations are secret" mode, because that would hide
    public annotations as well.  Use :meth:`restrict_all` when that is really intended.

    ``allowed_fields`` only applies to restricted annotations.  Public annotations are copied
    verbatim.  The annotated ``spdx_id`` is always kept so that the investigation pointer remains
    in the shared document.  A restricted annotation always carries a stable audit reference in
    its comment, even if the ``COMMENT`` field is approved; in that case the original comment is
    followed by the reference marker.
    """

    restricted_stable_ids: FrozenSet[str] = frozenset()
    restricted_spdx_ids: FrozenSet[str] = frozenset()
    restricted_annotator_names: FrozenSet[str] = frozenset()
    restricted_annotation_types: FrozenSet[AnnotationType] = frozenset()
    restricted_comment_substrings: Tuple[str, ...] = ()
    predicate: Optional[Callable[[Annotation], bool]] = None
    allowed_fields: FrozenSet[AnnotationField] = DEFAULT_APPROVED_FIELDS
    comment_template: str = DEFAULT_REDACTED_COMMENT_TEMPLATE
    salt: Optional[str] = None
    redacted_annotator: Actor = field(default_factory=_default_redacted_annotator)
    redacted_annotation_type: AnnotationType = DEFAULT_REDACTED_ANNOTATION_TYPE
    redacted_annotation_date: datetime = DEFAULT_REDACTED_ANNOTATION_DATE

    def __post_init__(self):
        if not isinstance(self.comment_template, str) or "{stable_id}" not in self.comment_template:
            raise ValueError("comment_template must contain the '{stable_id}' placeholder")
        try:
            self.comment_template.format(stable_id=STABLE_ID_PREFIX + "0" * 64)
        except (KeyError, IndexError, ValueError) as err:
            raise ValueError(f"comment_template contains an invalid placeholder: {err}")
        if not isinstance(self.allowed_fields, frozenset) or not all(
            isinstance(field, AnnotationField) for field in self.allowed_fields
        ):
            raise ValueError("allowed_fields must be a set of AnnotationField members")
        if not isinstance(self.redacted_annotator, Actor):
            raise ValueError("redacted_annotator must be an Actor")
        if self.redacted_annotator.actor_type == ActorType.TOOL and self.redacted_annotator.email is not None:
            raise ValueError("redacted_annotator must not have an email if its actor_type is TOOL")
        if not isinstance(self.redacted_annotation_type, AnnotationType):
            raise ValueError("redacted_annotation_type must be an AnnotationType")
        if not isinstance(self.redacted_annotation_date, datetime):
            raise ValueError("redacted_annotation_date must be a datetime")
        if self.salt is not None and not isinstance(self.salt, str):
            raise ValueError("salt must be a string or None")

    def is_restricted(self, annotation: Annotation, document: Optional[Document] = None, occurrence: int = 0) -> bool:
        if self.predicate is not None and self.predicate(annotation):
            return True
        if annotation.spdx_id in self.restricted_spdx_ids:
            return True
        if annotation.annotator.name in self.restricted_annotator_names:
            return True
        if annotation.annotation_type in self.restricted_annotation_types:
            return True
        if any(fragment in annotation.annotation_comment for fragment in self.restricted_comment_substrings):
            return True
        if self.restricted_stable_ids:
            namespace = document.creation_info.document_namespace if document is not None else None
            if annotation_stable_id(annotation, namespace, self.salt, occurrence) in self.restricted_stable_ids:
                return True
        return False

    def with_restricted_stable_ids(self, stable_ids: Iterable[str]) -> "AnnotationExportPolicy":
        return replace(self, restricted_stable_ids=self.restricted_stable_ids | frozenset(stable_ids))

    def has_selectors(self) -> bool:
        return bool(
            self.predicate
            or self.restricted_stable_ids
            or self.restricted_spdx_ids
            or self.restricted_annotator_names
            or self.restricted_annotation_types
            or self.restricted_comment_substrings
        )

    def redact(self, annotation: Annotation, stable_id: str) -> Annotation:
        if AnnotationField.COMMENT in self.allowed_fields:
            comment = f"{annotation.annotation_comment}\n\n{self.comment_template.format(stable_id=stable_id)}"
        else:
            comment = self.comment_template.format(stable_id=stable_id)

        return Annotation(
            spdx_id=annotation.spdx_id,
            annotation_type=(
                annotation.annotation_type
                if AnnotationField.ANNOTATION_TYPE in self.allowed_fields
                else self.redacted_annotation_type
            ),
            annotator=deepcopy(
                annotation.annotator if AnnotationField.ANNOTATOR in self.allowed_fields else self.redacted_annotator
            ),
            annotation_date=(
                annotation.annotation_date
                if AnnotationField.ANNOTATION_DATE in self.allowed_fields
                else self.redacted_annotation_date
            ),
            annotation_comment=comment,
        )

    def removed_fields(self) -> Tuple[str, ...]:
        return tuple(sorted(field.name.lower() for field in AnnotationField if field not in self.allowed_fields))

    @classmethod
    def restrict_all(cls, **kwargs: Any) -> "AnnotationExportPolicy":
        return cls(predicate=lambda _annotation: True, **kwargs)

    @classmethod
    def from_dict(cls, policy_dict: Mapping[str, Any], require_selectors: bool = True) -> "AnnotationExportPolicy":
        """Build a policy from the JSON-compatible representation used by the CLI.

        ``require_selectors`` guards against a policy that silently selects nothing.  Callers that
        add a selector separately (for example the CLI's ``--annotation-redact-all`` flag) may turn
        it off.
        """
        if not isinstance(policy_dict, Mapping):
            raise ValueError("annotation export policy must be a JSON object")

        restricted = policy_dict.get("restricted", {})
        if not isinstance(restricted, Mapping):
            raise ValueError("'restricted' must be a JSON object")

        restrict_all = policy_dict.get("restrict_all", False)
        if not isinstance(restrict_all, bool):
            raise ValueError("'restrict_all' must be true or false")

        allowed_field_names = policy_dict.get("allowed_fields")
        if allowed_field_names is None:
            allowed_fields = DEFAULT_APPROVED_FIELDS
        else:
            if isinstance(allowed_field_names, str) or not isinstance(allowed_field_names, Iterable):
                raise ValueError("'allowed_fields' must be a list of annotation field names")
            allowed_fields = frozenset(_parse_field_name(name) for name in allowed_field_names)

        annotation_types = frozenset(
            _parse_annotation_type(name) for name in _as_list(restricted.get("annotation_types"), "annotation_types")
        )

        comment_template = policy_dict.get("comment_template", DEFAULT_REDACTED_COMMENT_TEMPLATE)
        salt = policy_dict.get("salt")

        redacted_annotator = _default_redacted_annotator()
        if "redacted_annotator" in policy_dict:
            redacted_annotator = _parse_actor(policy_dict["redacted_annotator"])

        redacted_annotation_type = DEFAULT_REDACTED_ANNOTATION_TYPE
        if "redacted_annotation_type" in policy_dict:
            redacted_annotation_type = _parse_annotation_type(policy_dict["redacted_annotation_type"])

        redacted_annotation_date = DEFAULT_REDACTED_ANNOTATION_DATE
        if "redacted_annotation_date" in policy_dict:
            redacted_annotation_date = _parse_date(policy_dict["redacted_annotation_date"])

        policy = cls(
            restricted_stable_ids=frozenset(
                _as_list(restricted.get("stable_ids", policy_dict.get("stable_ids")), "stable_ids")
            ),
            restricted_spdx_ids=frozenset(
                _as_list(restricted.get("spdx_ids", policy_dict.get("spdx_ids")), "spdx_ids")
            ),
            restricted_annotator_names=frozenset(
                _as_list(
                    restricted.get("annotator_names", policy_dict.get("annotator_names")),
                    "annotator_names",
                )
            ),
            restricted_annotation_types=annotation_types,
            restricted_comment_substrings=tuple(
                _as_list(
                    restricted.get("comment_substrings", policy_dict.get("comment_substrings")),
                    "comment_substrings",
                )
            ),
            allowed_fields=allowed_fields,
            comment_template=comment_template,
            salt=salt,
            redacted_annotator=redacted_annotator,
            redacted_annotation_type=redacted_annotation_type,
            redacted_annotation_date=redacted_annotation_date,
        )
        if restrict_all:
            policy = replace(policy, predicate=lambda _annotation: True)
        if require_selectors and not policy.has_selectors():
            raise ValueError(
                "policy does not select any annotations; add at least one selector under 'restricted' "
                "or set 'restrict_all' to true"
            )
        return policy


@dataclass(frozen=True)
class AnnotationAuditEntry:
    """Internal pointer from a shared annotation to its original record.

    The entry deliberately does not repeat the restricted comment.  It only records the stable
    identifier and locating metadata; the full original record stays in the internal document and
    is looked up via :func:`find_original_annotations` or
    :func:`find_original_with_audit_entries`.
    """

    stable_id: str
    spdx_id: str
    annotation_type: str
    annotator: str
    annotation_date: str
    removed_fields: Tuple[str, ...] = ()
    document_namespace: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stable_id": self.stable_id,
            "spdx_id": self.spdx_id,
            "annotation_type": self.annotation_type,
            "annotator": self.annotator,
            "annotation_date": self.annotation_date,
            "removed_fields": list(self.removed_fields),
            "document_namespace": self.document_namespace,
        }

    @classmethod
    def from_dict(cls, entry_dict: Mapping[str, Any]) -> "AnnotationAuditEntry":
        return cls(
            stable_id=entry_dict["stable_id"],
            spdx_id=entry_dict["spdx_id"],
            annotation_type=entry_dict["annotation_type"],
            annotator=entry_dict["annotator"],
            annotation_date=entry_dict["annotation_date"],
            removed_fields=tuple(entry_dict.get("removed_fields", ())),
            document_namespace=entry_dict.get("document_namespace"),
        )


@dataclass
class AnnotationExportResult:
    """The shared document plus the internal-only mapping of restricted annotations."""

    document: Document
    audit_entries: List[AnnotationAuditEntry] = field(default_factory=list)
    originals_by_stable_id: Dict[str, Annotation] = field(default_factory=dict)

    @property
    def shared_document(self) -> Document:
        return self.document

    @property
    def restricted_count(self) -> int:
        return len(self.audit_entries)

    def find_original(self, stable_id: str) -> Optional[Annotation]:
        return self.originals_by_stable_id.get(stable_id)


def annotation_stable_id(
    annotation: Annotation,
    document_namespace: Optional[str] = None,
    salt: Optional[str] = None,
    occurrence: int = 0,
) -> str:
    """Return a deterministic identifier derived from the original annotation.

    The identifier is an HMAC-SHA256 over a canonical representation of all annotation fields and
    the document namespace.  It does not reveal the annotation text, but an internal reviewer who
    still has the original document can recompute it.  A policy-specific ``salt`` may be supplied
    to make offline guessing of low-entropy comments harder; the same salt is needed for lookup.

    ``occurrence`` disambiguates byte-for-byte identical annotations in the same document so that
    each original record still has its own audit reference.
    """
    canonical = {
        "schema": "spdx-annotation-v1",
        "document_namespace": document_namespace or "",
        "spdx_id": annotation.spdx_id,
        "annotation_type": annotation.annotation_type.name,
        "annotator": annotation.annotator.to_serialized_string(),
        "annotation_date": datetime_to_iso_string(annotation.annotation_date),
        "annotation_comment": annotation.annotation_comment,
        "occurrence": occurrence,
    }
    payload = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hmac.new((salt or "").encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{STABLE_ID_PREFIX}{digest}"


def extract_stable_id(comment: Optional[str]) -> Optional[str]:
    """Extract the audit reference from a shared annotation comment, if present."""
    if not comment:
        return None
    match = STABLE_ID_PATTERN.search(comment)
    return match.group(0) if match else None


def build_annotation_index(document: Document, salt: Optional[str] = None) -> Dict[str, List[Annotation]]:
    """Index every annotation in ``document`` by its stable identifier.

    Internal audit can use this on the original document to resolve the stable identifiers found
    in a shared document.  The namespace is taken from the document itself.
    """
    namespace = document.creation_info.document_namespace
    index: Dict[str, List[Annotation]] = {}
    for annotation, stable_id, _occurrence in _iter_stable_ids(document.annotations, namespace, salt):
        index.setdefault(stable_id, []).append(annotation)
    return index


def _iter_stable_ids(
    annotations: Iterable[Annotation], namespace: Optional[str], salt: Optional[str]
) -> Iterable[Tuple[Annotation, str, int]]:
    occurrences: Dict[str, int] = {}
    for annotation in annotations:
        base_id = annotation_stable_id(annotation, namespace, salt)
        occurrence = occurrences.get(base_id, 0)
        occurrences[base_id] = occurrence + 1
        yield annotation, annotation_stable_id(annotation, namespace, salt, occurrence), occurrence


def find_original_annotations(document: Document, stable_id: str, salt: Optional[str] = None) -> List[Annotation]:
    """Return original annotations matching ``stable_id`` (normally zero or one)."""
    return build_annotation_index(document, salt).get(stable_id, [])


def export_annotations_for_sharing(
    document: Document, policy: Optional[AnnotationExportPolicy] = None
) -> AnnotationExportResult:
    """Create a shareable copy of ``document`` according to ``policy``.

    The input document is never modified.  Public annotations are copied unchanged; restricted
    annotations keep their target ``spdx_id`` but only the approved fields plus a stable audit
    reference.  The returned audit entries are internal locators, not copies of the restricted
    content, and must not be written next to the shared document unless the recipient is authorized
    to use them.
    """
    policy = policy if policy is not None else AnnotationExportPolicy()
    shared_document = deepcopy(document)
    namespace = document.creation_info.document_namespace

    shared_annotations: List[Annotation] = []
    audit_entries: List[AnnotationAuditEntry] = []
    originals_by_stable_id: Dict[str, Annotation] = {}

    for annotation, stable_id, occurrence in _iter_stable_ids(document.annotations, namespace, policy.salt):
        if not policy.is_restricted(annotation, document, occurrence):
            shared_annotations.append(deepcopy(annotation))
            continue

        shared_annotations.append(policy.redact(annotation, stable_id))
        originals_by_stable_id.setdefault(stable_id, deepcopy(annotation))
        audit_entries.append(
            AnnotationAuditEntry(
                stable_id=stable_id,
                spdx_id=annotation.spdx_id,
                annotation_type=annotation.annotation_type.name,
                annotator=annotation.annotator.to_serialized_string(),
                annotation_date=datetime_to_iso_string(annotation.annotation_date),
                removed_fields=policy.removed_fields(),
                document_namespace=namespace,
            )
        )

    shared_document.annotations = shared_annotations
    return AnnotationExportResult(shared_document, audit_entries, originals_by_stable_id)


def write_annotation_audit_file(entries: Iterable[AnnotationAuditEntry], file_name: str) -> None:
    """Write the internal audit mapping to a JSON file with owner-only permissions where possible."""
    payload = {
        "schema": "spdx-annotation-audit-v1",
        "entries": [entry.to_dict() for entry in entries],
    }
    path = Path(file_name)
    with path.open("w", encoding="utf-8") as out:
        json.dump(payload, out, indent=2, ensure_ascii=False)
        out.write("\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_annotation_export_policy(file_name: str, require_selectors: bool = True) -> AnnotationExportPolicy:
    with open(file_name, encoding="utf-8") as policy_file:
        policy_dict = json.load(policy_file)
    return AnnotationExportPolicy.from_dict(policy_dict, require_selectors=require_selectors)


def load_annotation_audit_file(file_name: str) -> List[AnnotationAuditEntry]:
    """Load an audit mapping previously written by :func:`write_annotation_audit_file`."""
    with open(file_name, encoding="utf-8") as audit_file:
        payload = json.load(audit_file)
    if not isinstance(payload, Mapping) or not isinstance(payload.get("entries"), list):
        raise ValueError("annotation audit file must contain an 'entries' list")
    return [AnnotationAuditEntry.from_dict(entry) for entry in payload["entries"]]


def list_stable_ids(document: Document) -> List[str]:
    """Return the audit references of all restricted annotations in a shared document."""
    stable_ids = []
    for annotation in document.annotations:
        stable_id = extract_stable_id(annotation.annotation_comment)
        if stable_id is not None:
            stable_ids.append(stable_id)
    return stable_ids


def find_original_with_audit_entries(
    shared_document: Document,
    original_document: Document,
    audit_entries: Iterable[AnnotationAuditEntry],
    salt: Optional[str] = None,
) -> Dict[str, List[Annotation]]:
    """Resolve audit references found in ``shared_document`` back to ``original_document``.

    The ``audit_entries`` are used to confirm that a reference is known, while the original
    document provides the full record (including comments) for the returned mapping.  Annotations
    that are public in the shared document are not part of the mapping.
    """
    known_ids = {entry.stable_id for entry in audit_entries}
    index = build_annotation_index(original_document, salt)
    result: Dict[str, List[Annotation]] = {}
    for stable_id in list_stable_ids(shared_document):
        if stable_id in known_ids:
            result[stable_id] = index.get(stable_id, [])
    return result


def find_original_with_audit_file(
    shared_document: Document,
    original_document: Document,
    annotation_audit_file: str,
    salt: Optional[str] = None,
) -> Dict[str, List[Annotation]]:
    """Like :func:`find_original_with_audit_entries`, but reads the audit mapping from a file."""
    return find_original_with_audit_entries(
        shared_document, original_document, load_annotation_audit_file(annotation_audit_file), salt
    )


def resolve_shared_annotation(
    shared_annotation: Annotation,
    original_document: Document,
    audit_entries: Iterable[AnnotationAuditEntry],
    salt: Optional[str] = None,
) -> Optional[Annotation]:
    """Return the original annotation for one shared annotation, or ``None`` if it is not restricted."""
    stable_id = extract_stable_id(shared_annotation.annotation_comment)
    if stable_id is None or stable_id not in {entry.stable_id for entry in audit_entries}:
        return None
    matches = find_original_annotations(original_document, stable_id, salt)
    return matches[0] if matches else None


def _as_list(value: Any, field_name: str) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ValueError(f"'{field_name}' must be a list")
    return list(value)


def _parse_field_name(name: Any) -> AnnotationField:
    if not isinstance(name, str):
        raise ValueError(f"annotation field names must be strings, got: {name!r}")
    try:
        return AnnotationField[name.strip().upper()]
    except KeyError:
        valid = ", ".join(sorted(field.name.lower() for field in AnnotationField))
        raise ValueError(f"unknown annotation field {name!r}; valid fields are: {valid}")


def _parse_annotation_type(name: Any) -> AnnotationType:
    if not isinstance(name, str):
        raise ValueError(f"annotation types must be strings, got: {name!r}")
    try:
        return AnnotationType[name.strip().upper()]
    except KeyError:
        valid = ", ".join(sorted(annotation_type.name for annotation_type in AnnotationType))
        raise ValueError(f"unknown annotation type {name!r}; valid types are: {valid}")


def _parse_actor(actor_dict: Any) -> Actor:
    if not isinstance(actor_dict, Mapping):
        raise ValueError("'redacted_annotator' must be a JSON object")
    actor_type_name = actor_dict.get("actor_type", "TOOL")
    actor_type = _parse_actor_type(actor_type_name)
    name = actor_dict.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("'redacted_annotator.name' must be a non-empty string")
    email = actor_dict.get("email")
    if email is not None and not isinstance(email, str):
        raise ValueError("'redacted_annotator.email' must be a string or null")
    return Actor(actor_type, name, email)


def _parse_actor_type(name: Any) -> ActorType:
    if not isinstance(name, str):
        raise ValueError(f"actor types must be strings, got: {name!r}")
    try:
        return ActorType[name.strip().upper()]
    except KeyError:
        valid = ", ".join(sorted(actor_type.name for actor_type in ActorType))
        raise ValueError(f"unknown actor type {name!r}; valid types are: {valid}")


def _parse_date(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("'redacted_annotation_date' must be an ISO-8601 string")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError("'redacted_annotation_date' must use the format YYYY-MM-DDTHH:MM:SSZ")
