"""
Opt-in recording and verification of reference resolution evidence.

A `Recorder` can be handed to a `referencing.Registry`'s resolver, which then
reports every successful resolution it performs.  The resulting `Evidence`
contains identities and digests -- never document contents -- and can be
serialized, stored alongside an audit log, compared with a later replay, or
reconciled against documents obtained at another time.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urljoin
import base64
import hashlib
import json
import math

from referencing._attrs import frozen

if TYPE_CHECKING:
    from referencing._core import Resource
    from referencing.typing import URI

#: The version of the serialized evidence format.
FORMAT_VERSION = "referencing-evidence-1"

#: The known kinds of fragment a reference may use.
FRAGMENT_KINDS = ("resource", "pointer", "anchor")

#: The known kinds of change reported when reconciling evidence.
CHANGE_KINDS = (
    "document-added",
    "document-removed",
    "document-missing",
    "document-mismatch",
    "document-changed",
    "resolution-added",
    "resolution-removed",
    "resolution-changed",
)


class Tracer(Protocol):
    """
    The interface resolvers use to report resolutions to a recorder.

    This is an internal protocol; use `Recorder` rather than implementing it.
    """

    def resolution(
        self,
        *,
        ref: str,
        base_uri: URI,
        source: Resource[Any] | None,
        target: Resource[Any],
        target_uri: URI,
        fragment_kind: str,
        fragment: str,
        resolved_digest: str,
        retrieved: bool,
    ) -> None:
        """
        Record one successful resolution.
        """
        ...  # pragma: no cover


def _fallback(value: Any) -> Any:
    """
    Convert values JSON cannot represent into stable stand-ins.
    """
    if isinstance(value, Mapping):
        pairs = [
            [_canonical_text(key), _fallback(each)]
            for key, each in value.items()
        ]
        pairs.sort(key=lambda pair: pair[0])
        return {"__mapping__": pairs}
    if isinstance(value, (str, bool)) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return {"__float__": "nan"}
        if math.isinf(value):
            return {"__float__": "inf" if value > 0 else "-inf"}
        return value
    if isinstance(value, (bytes, bytearray)):
        encoded = base64.b64encode(bytes(value)).decode("ascii")
        return {"__bytes__": encoded}
    if isinstance(value, Sequence):
        return [_fallback(each) for each in value]
    cls = type(value)
    return {"__type__": f"{cls.__module__}.{cls.__qualname__}"}


def _canonical_text(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return json.dumps(
            _fallback(value),
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )


def digest_of(contents: Any) -> str:
    """
    Return a deterministic, content-addressed digest for some document.

    JSON documents are hashed after canonical serialization, so whitespace
    and object key order in the original source do not affect the digest.
    """
    encoded = _canonical_text(contents).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _canonical_uri(uri: URI, resource: Resource[Any]) -> URI | None:
    identifier = resource.id()
    if identifier is None:
        return None
    return urljoin(uri, identifier).rstrip("#")


def _dialect(resource: Resource[Any]) -> URI | None:
    contents = resource.contents
    if not isinstance(contents, Mapping):
        return None
    dialect = contents.get("$schema")
    if isinstance(dialect, str):
        return dialect
    return None


def _document(uri: URI, resource: Resource[Any]) -> Document:
    specification = resource._specification
    return Document(
        uri=uri.rstrip("#"),
        canonical_uri=_canonical_uri(uri, resource),
        specification=specification.name,
        dialect=_dialect(resource),
        digest=digest_of(resource.contents),
    )


@frozen
class Document:
    """
    The verifiable identity of one document which took part in a resolution.
    """

    #: The URI at which the document was found.
    uri: URI

    #: The canonical URI declared by the document itself, if it declares one.
    canonical_uri: URI | None

    #: The name of the specification used to interpret the document.
    specification: str

    #: The dialect identifier the document declared, if it declared one.
    dialect: URI | None

    #: A content digest, independent of formatting and object key order.
    digest: str

    def audit(self) -> dict[str, str | None]:
        """
        Return a JSON-serializable description (never document contents).
        """
        return {
            "uri": self.uri,
            "canonical_uri": self.canonical_uri,
            "specification": self.specification,
            "dialect": self.dialect,
            "digest": self.digest,
        }


@frozen
class Resolution:
    """
    A single successful resolution, including what it actually depended on.
    """

    #: The reference, exactly as it was passed to the resolver.
    ref: str

    #: The base URI against which ``ref`` was resolved.
    base_uri: URI

    #: The document containing the reference, if it is known.
    source: Document | None

    #: The document which ``ref`` resolved into.
    target: Document

    #: One of ``"resource"``, ``"pointer"`` or ``"anchor"``.
    fragment_kind: str

    #: The pointer or anchor name (empty when referring to a whole document).
    fragment: str

    #: A digest of the resolved value (which may be a part of ``target``).
    resolved_digest: str

    #: Whether the target had to be retrieved externally, rather than being
    #: already present in (or crawlable from) the registry.
    retrieved: bool

    def audit(self) -> dict[str, Any]:
        """
        Return a JSON-serializable description (never document contents).
        """
        return {
            "ref": self.ref,
            "base_uri": self.base_uri,
            "source": None if self.source is None else self.source.audit(),
            "target": self.target.audit(),
            "fragment_kind": self.fragment_kind,
            "fragment": self.fragment,
            "resolved_digest": self.resolved_digest,
            "retrieved": self.retrieved,
        }

    def _key(self) -> tuple[str, str, str, str, str]:
        source_uri = "" if self.source is None else self.source.uri
        return (
            source_uri,
            self.ref,
            self.base_uri,
            self.fragment_kind,
            self.fragment,
        )


@frozen
class Change:
    """
    One difference found while reconciling or verifying evidence.
    """

    #: A short machine-readable category, see `CHANGE_KINDS`.
    kind: str

    #: What the change is about (a document URI, or a reference).
    subject: str

    #: The digest or state before the change, if meaningful.
    before: str | None = None

    #: The digest or state after the change, if meaningful.
    after: str | None = None

    def describe(self) -> str:
        """
        Return a single-line human readable summary.
        """
        if self.before is None and self.after is None:
            return f"{self.kind}: {self.subject}"
        return (
            f"{self.kind}: {self.subject} "
            f"({self.before!s} -> {self.after!s})"
        )


def _describe_resolution(resolution: Resolution) -> str:
    if resolution.source is None or not resolution.source.uri:
        source = ""
    else:
        source = f"{resolution.source.uri} "
    return f"{source}-> {resolution.ref}"


@frozen
class Evidence:
    """
    A record of the resolutions which took place, suitable for auditing.

    Evidence can be serialized with `to_json` (which never includes document
    contents), compared for exact reproducibility with ``==``, reconciled with
    a later replay via `reconcile`, and checked against documents obtained
    later via `verify`.
    """

    resolutions: tuple[Resolution, ...] = ()

    @classmethod
    def from_json(cls, data: str) -> Evidence:
        """
        Load evidence previously produced by `to_json`.
        """
        loaded = json.loads(data)
        if loaded.get("format") != FORMAT_VERSION:
            message = f"Unsupported evidence format: {loaded.get('format')!r}"
            raise ValueError(message)
        return cls(
            resolutions=tuple(
                Resolution(
                    ref=each["ref"],
                    base_uri=each["base_uri"],
                    source=(
                        None
                        if each["source"] is None
                        else Document(**each["source"])
                    ),
                    target=Document(**each["target"]),
                    fragment_kind=each["fragment_kind"],
                    fragment=each["fragment"],
                    resolved_digest=each["resolved_digest"],
                    retrieved=each["retrieved"],
                )
                for each in loaded["resolutions"]
            ),
        )

    def to_json(self, *, indent: int | None = None) -> str:
        """
        Serialize this evidence; document contents are never included.
        """
        return json.dumps(
            {
                "format": FORMAT_VERSION,
                "resolutions": [each.audit() for each in self.resolutions],
            },
            sort_keys=True,
            ensure_ascii=False,
            indent=indent,
            separators=None if indent is not None else (",", ":"),
        )

    def documents(self) -> dict[URI, Document]:
        """
        Return the distinct documents which this evidence depends on.
        """
        found: dict[URI, Document] = {}
        for resolution in self.resolutions:
            for document in (resolution.source, resolution.target):
                if document is not None:
                    found.setdefault(document.uri, document)
        return found

    def dependencies(self) -> dict[URI, tuple[Resolution, ...]]:
        """
        Group resolutions by the document they actually depend on.

        Resolutions resolving into a pointer or anchor are grouped under the
        containing document together with whole-document references, so a
        document shared by several entry points (or reached via different
        fragments) is visible as a single target.
        """
        found: dict[URI, list[Resolution]] = {}
        for resolution in self.resolutions:
            found.setdefault(resolution.target.uri, []).append(resolution)
        return {uri: tuple(each) for uri, each in found.items()}

    def log_lines(self) -> list[str]:
        """
        Return content-free single-line summaries suitable for a log.

        Only identities, fragments and digests appear, never document bodies.
        """
        lines = []
        for resolution in self.resolutions:
            if resolution.source is None:
                source = "<unknown>"
            else:
                source = resolution.source.uri or "<anonymous>"
            lines.append(
                " ".join(
                    [
                        source,
                        f"-> {resolution.target.uri}",
                        f"({resolution.fragment_kind}: {resolution.fragment})",
                        f"ref={resolution.ref}",
                        f"document={resolution.target.digest}",
                        f"value={resolution.resolved_digest}",
                    ],
                ),
            )
        return lines

    def verify(self, documents: Mapping[URI, Any]) -> list[Change]:
        """
        Check recorded digests against documents obtained at another time.

        Only documents which appear in this evidence are considered, so
        unrelated supplied documents are ignored.  Values may be either raw
        contents or `referencing.Resource` instances.
        """
        changes = []
        for uri, document in sorted(self.documents().items()):
            supplied = documents.get(uri)
            if supplied is None and document.canonical_uri is not None:
                supplied = documents.get(document.canonical_uri)
            if supplied is None:
                changes.append(Change(kind="document-missing", subject=uri))
                continue
            contents = getattr(supplied, "contents", supplied)
            actual = digest_of(contents)
            if actual != document.digest:
                changes.append(
                    Change(
                        kind="document-mismatch",
                        subject=uri,
                        before=document.digest,
                        after=actual,
                    ),
                )
        return changes

    def reconcile(self, other: Evidence) -> list[Change]:
        """
        Report differences between this (earlier) evidence and ``other``.

        Only differences involving documents or resolutions whose evidence
        actually changed will be reported, so replacing a single document
        yields only the changes related to it.
        """
        changes = []
        ours, theirs = self.documents(), other.documents()
        for uri in sorted(ours.keys() | theirs.keys()):
            before, after = ours.get(uri), theirs.get(uri)
            if before is None:
                changes.append(Change(kind="document-added", subject=uri))
            elif after is None:
                changes.append(Change(kind="document-removed", subject=uri))
            elif before != after:
                changes.append(
                    Change(
                        kind="document-changed",
                        subject=uri,
                        before=before.digest,
                        after=after.digest,
                    ),
                )

        ours_by_key = {each._key(): each for each in self.resolutions}
        theirs_by_key = {each._key(): each for each in other.resolutions}
        for key in sorted(ours_by_key.keys() | theirs_by_key.keys()):
            before, after = ours_by_key.get(key), theirs_by_key.get(key)
            if before is None:
                changes.append(
                    Change(
                        kind="resolution-added",
                        subject=_describe_resolution(after),
                    ),
                )
            elif after is None:
                changes.append(
                    Change(
                        kind="resolution-removed",
                        subject=_describe_resolution(before),
                    ),
                )
            elif (
                before.target.digest,
                before.resolved_digest,
            ) != (after.target.digest, after.resolved_digest):
                changes.append(
                    Change(
                        kind="resolution-changed",
                        subject=_describe_resolution(before),
                        before=before.target.digest,
                        after=after.target.digest,
                    ),
                )
        changes.sort(key=lambda change: (change.kind, change.subject))
        return changes


class Recorder:
    """
    Collect resolutions from one or more resolvers.

    Pass an instance as the ``evidence`` argument to `Registry.resolver` or
    `Registry.resolver_with_root`, then call `evidence` for an immutable
    record of what happened.

    Recorders begin empty, and are never automatically cleared, so a single
    recorder can span many resolver entry points if desired.
    """

    def __init__(self) -> None:
        self._resolutions: list[Resolution] = []

    def __repr__(self) -> str:
        size = len(self._resolutions)
        pluralized = "resolution" if size == 1 else "resolutions"
        return f"<Recorder ({size} {pluralized})>"

    def resolution(
        self,
        *,
        ref: str,
        base_uri: URI,
        source: Resource[Any] | None,
        target: Resource[Any],
        target_uri: URI,
        fragment_kind: str,
        fragment: str,
        resolved_digest: str,
        retrieved: bool,
    ) -> None:
        """
        Record one resolution (called by resolvers, not end-user API).
        """
        self._resolutions.append(
            Resolution(
                ref=ref,
                base_uri=base_uri,
                source=(
                    None
                    if source is None or target_uri is None
                    else _document(base_uri, source)
                ),
                target=_document(target_uri or base_uri, target),
                fragment_kind=fragment_kind,
                fragment=fragment,
                resolved_digest=resolved_digest,
                retrieved=retrieved,
            ),
        )

    def evidence(self) -> Evidence:
        """
        Return an immutable snapshot of everything recorded so far.
        """
        return Evidence(resolutions=tuple(self._resolutions))

    def clear(self) -> None:
        """
        Forget all recorded resolutions.
        """
        self._resolutions.clear()
