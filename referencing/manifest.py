"""
Offline manifests for verifying resources before deployment.

A `Manifest` records, for each dependency, the identity it is expected to
declare and the digest of the contents which are allowed to be used. Manifests
can be built from an existing registry, imported in bulk from local JSON
files, serialized, and checked without retrieving anything over the network.

The digest and the identity are separate pins. A digest covers a dependency's
contents with its own top-level identity keyword (``$id`` or legacy ``id``)
removed, so changing a resource's declared identity is reported as an identity
failure rather than as both an identity and a content failure. Verification
reports missing, changed-content, and changed-identity dependencies
independently, and never modifies the registry being inspected.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable, Iterator, Mapping
from hashlib import new as _new_hash
from hmac import compare_digest
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic
from urllib.parse import urljoin, urlsplit

from attrs import field

from referencing import exceptions
from referencing._attrs import frozen
from referencing.typing import URI, D

if TYPE_CHECKING:
    from referencing._core import Registry, Resource, Specification

#: The version of the serialized manifest format.
MANIFEST_VERSION = 1

#: The digest algorithm used when one is not specified.
DEFAULT_ALGORITHM = "sha256"

#: The keywords which may declare a resource's identity.
IDENTITY_KEYS = ("$id", "id")


def canonical_json(contents: object) -> str:
    """
    Serialize JSON-compatible contents in a stable (canonical) form.

    Object keys are sorted, whitespace is omitted, and non-ASCII characters
    are preserved. Digests are computed over the UTF-8 encoding of this
    representation.
    """
    try:
        return json.dumps(
            contents,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(  # noqa: TRY003
            f"Contents are not canonically serializable as JSON: {error}",
        ) from error


def canonical_content(contents: object) -> str:
    """
    Canonicalize contents for digesting, ignoring a declared identity.

    Only the top-level identity keyword is removed. Identities declared by
    nested subresources remain part of the digested contents.
    """
    if isinstance(contents, Mapping):
        contents = {
            keyword: value
            for keyword, value in contents.items()
            if keyword not in IDENTITY_KEYS
        }
    return canonical_json(contents)


def _check_algorithm(algorithm: str) -> str:
    algorithm = algorithm.lower()
    try:
        _new_hash(algorithm)
    except ValueError as error:
        raise ValueError(  # noqa: TRY003
            f"Unknown digest algorithm {algorithm!r}",
        ) from error
    return algorithm


def content_digest(
    contents: object,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
) -> str:
    """
    Compute a dependency's content digest, in ``algorithm:hexdigest`` form.

    The top-level identity keyword is excluded from the digest, since the
    expected identity is pinned separately by `Entry.id`. All other contents
    are included, using `canonical_content`, so equivalent JSON values (for
    example values whose object keys are ordered differently) have the same
    digest.
    """
    algorithm = _check_algorithm(algorithm)
    hasher = _new_hash(algorithm)
    hasher.update(canonical_content(contents).encode("utf-8"))
    return f"{algorithm}:{hasher.hexdigest()}"


def digest(
    contents: object,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
) -> str:
    """
    Compute a digest (an alias for `content_digest`).
    """
    return content_digest(contents, algorithm=algorithm)


def _normalize_digest(value: str | Mapping[str, str]) -> str:
    if isinstance(value, Mapping):
        if len(value) != 1:
            raise ValueError(  # noqa: TRY003
                f"Invalid digest {value!r}",
            )
        algorithm, hexdigest = next(iter(value.items()))
        value = f"{algorithm}:{hexdigest}"
    if not isinstance(value, str):
        raise ValueError(  # noqa: TRY003
            f"Invalid digest {value!r}",
        )

    algorithm: str
    hexdigest: str
    if ":" in value:
        algorithm, _, hexdigest = value.partition(":")
    elif "-" in value:
        algorithm, _, encoded = value.partition("-")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError(  # noqa: TRY003
                f"Invalid digest {value!r}",
            ) from error
        return f"{_check_algorithm(algorithm)}:{raw.hex()}"
    else:
        algorithm, hexdigest = DEFAULT_ALGORITHM, value

    algorithm = _check_algorithm(algorithm)
    expected_length = _new_hash(algorithm).digest_size * 2
    if len(hexdigest) != expected_length:
        raise ValueError(  # noqa: TRY003
            f"Invalid {algorithm} digest {hexdigest!r}",
        )
    try:
        int(hexdigest, 16)
    except ValueError as error:
        raise ValueError(  # noqa: TRY003
            f"Invalid {algorithm} digest {hexdigest!r}",
        ) from error
    return f"{algorithm}:{hexdigest.lower()}"


def _normalize_identity(identity: str | None) -> URI | None:
    if not identity:
        return None
    return identity.rstrip("#")


def _identity_key(contents: object) -> str | None:
    if not isinstance(contents, Mapping):
        return None
    for keyword in IDENTITY_KEYS:
        if isinstance(contents.get(keyword), str):
            return keyword
    return None


def _declared_identity(uri: URI, resource: Resource[D]) -> URI | None:
    identity = resource.id()
    if identity is None:
        keyword = _identity_key(resource.contents)
        if keyword is not None:
            identity = resource.contents[keyword]  # type: ignore[index]
    if identity is None:
        return None
    return _normalize_identity(urljoin(uri, identity))


def _entry_from_json(
    uri: URI,
    value: Entry | str | Mapping[str, Any],
) -> Entry:
    if isinstance(value, Entry):
        return value
    if isinstance(value, str):
        return Entry(digest=value, id=uri)
    if not isinstance(value, Mapping):
        raise ValueError(  # noqa: TRY003
            f"Manifest entry for {uri!r} must be a digest or an object",
        )

    digest_value = value.get("digest")
    if isinstance(digest_value, Mapping):
        if len(digest_value) != 1:
            raise ValueError(  # noqa: TRY003
                f"Manifest entry for {uri!r} has multiple digests",
            )
        algorithm, hexdigest = next(iter(digest_value.items()))
        if not isinstance(hexdigest, str):
            raise ValueError(  # noqa: TRY003
                f"Manifest entry for {uri!r} has an invalid digest",
            )
        digest_value = f"{algorithm}:{hexdigest}"
    elif digest_value is None:
        for keyword, candidate in value.items():
            if keyword not in {"id", "identity", "uri", "path", "file"} and (
                isinstance(candidate, str)
            ):
                digest_value = f"{keyword}:{candidate}"
                break
    if not isinstance(digest_value, str):
        raise ValueError(  # noqa: TRY003
            f"Manifest entry for {uri!r} has no string 'digest'",
        )

    identity = value.get("id", value.get("identity", value.get("uri", uri)))
    if identity is not None and not isinstance(identity, str):
        raise ValueError(  # noqa: TRY003
            f"Manifest entry for {uri!r} has an invalid 'id'",
        )
    path = value.get("path", value.get("file"))
    if path is not None and not isinstance(path, str):
        raise ValueError(  # noqa: TRY003
            f"Manifest entry for {uri!r} has an invalid 'path'",
        )
    return Entry(digest=digest_value, id=identity, path=path)


def _as_entries(
    entries: Mapping[URI, Entry | str | Mapping[str, Any]],
) -> Mapping[URI, Entry]:
    converted: dict[URI, Entry] = {}
    for uri, entry in entries.items():
        if not isinstance(uri, str):
            raise ValueError(  # noqa: TRY003
                f"Manifest URIs must be strings, not {uri!r}",
            )
        converted[uri] = _entry_from_json(uri, entry)
    return MappingProxyType(converted)


def _as_mapping(value: Mapping[URI, Any]) -> Mapping[URI, Any]:
    return MappingProxyType(dict(value))


def _by_uri(
    failure: ContentMismatch | IdentityMismatch | MissingDependency,
) -> URI:
    return failure.uri


@frozen
class Entry:
    """
    The expected identity and allowed content digest of one dependency.
    """

    #: The digest of the allowed contents, in ``algorithm:hexdigest`` form.
    digest: str = field(converter=_normalize_digest)

    #: The identity the resource is expected to declare, if any.
    #:
    #: ``None`` means the resource is expected to declare no identity, for
    #: example because its specification has no identifier keyword.
    id: URI | None = field(default=None, converter=_normalize_identity)

    #: The local file holding the contents, used for offline bulk importing.
    #:
    #: Relative paths are resolved against the manifest's base directory.
    path: str | None = None

    @property
    def algorithm(self) -> str:
        """
        The digest algorithm of this entry.
        """
        return self.digest.partition(":")[0]

    @property
    def hexdigest(self) -> str:
        """
        The hexadecimal portion of this entry's digest.
        """
        return self.digest.partition(":")[2]

    @property
    def identity(self) -> URI | None:
        """
        The expected identity of this entry (an alias for `id`).
        """
        return self.id

    @property
    def file(self) -> str | None:
        """
        The local file of this entry (an alias for `path`).
        """
        return self.path

    @classmethod
    def from_resource(
        cls,
        uri: URI,
        resource: Resource[D],
        *,
        algorithm: str = DEFAULT_ALGORITHM,
        path: str | None = None,
    ) -> Entry:
        """
        Create an entry from a resource stored under the given URI.
        """
        return cls(
            digest=content_digest(resource.contents, algorithm=algorithm),
            id=_declared_identity(uri, resource),
            path=path,
        )


@frozen
class ContentMismatch(exceptions.Unresolvable):
    """
    A dependency's contents do not match the digest which was allowed.
    """

    expected_digest: str = ""
    actual_digest: str = ""

    @property
    def uri(self) -> URI:
        """
        The URI of the dependency.
        """
        return self.ref

    @property
    def expected(self) -> str:
        """
        The digest which the manifest allowed.
        """
        return self.expected_digest

    @property
    def actual(self) -> str:
        """
        The digest which the provided contents actually have.
        """
        return self.actual_digest

    def __str__(self) -> str:
        return (
            f"Contents of {self.ref!r} have digest {self.actual_digest!r}, "
            f"not the expected {self.expected_digest!r}"
        )


@frozen
class IdentityMismatch(exceptions.Unresolvable):
    """
    A dependency does not declare the identity which was expected.
    """

    expected_id: URI | None = None
    actual_id: URI | None = None

    @property
    def uri(self) -> URI:
        """
        The URI of the dependency.
        """
        return self.ref

    @property
    def expected(self) -> URI | None:
        """
        The identity which the manifest expected.
        """
        return self.expected_id

    @property
    def actual(self) -> URI | None:
        """
        The identity which the provided contents actually declare.
        """
        return self.actual_id

    def __str__(self) -> str:
        return (
            f"Resource {self.ref!r} declares identity {self.actual_id!r}, "
            f"not the expected {self.expected_id!r}"
        )


@frozen
class MissingDependency:
    """
    A dependency named by the manifest is absent from a registry.
    """

    uri: URI

    @property
    def ref(self) -> URI:
        """
        The URI of the missing dependency (an alias for `uri`).
        """
        return self.uri

    def __str__(self) -> str:
        return f"Missing dependency {self.uri!r}"


class ManifestError(Exception):
    """
    Base class for manifest-related errors.
    """


class ManifestFormatError(ManifestError, ValueError):
    """
    A serialized manifest could not be understood.
    """


class ManifestImportError(ManifestError):
    """
    A manifest's local files could not be imported.
    """


class VerificationError(ManifestError):
    """
    A registry failed verification against a manifest.

    The full `Verification` result is available as its `result` attribute.
    """

    def __init__(self, result: Verification[Any]) -> None:
        self.result = result
        super().__init__(str(self))

    def __str__(self) -> str:
        result = self.result
        failures = []
        if result.content_mismatches:
            failures.append(
                f"{len(result.content_mismatches)} content mismatch(es)",
            )
        if result.identity_mismatches:
            failures.append(
                f"{len(result.identity_mismatches)} identity mismatch(es)",
            )
        if result.missing:
            failures.append(f"{len(result.missing)} missing dependency(ies)")
        return "Manifest verification failed: " + ", ".join(failures)


class VerificationKind:
    """
    The possible results of a `Verification`.

    Its values are plain strings, so they compare equal to their names.
    """

    #: Every dependency was present, unchanged, and as expected.
    OK = "ok"

    #: At least one dependency's contents changed.
    CONTENT = "content"

    #: At least one dependency's declared identity changed.
    IDENTITY = "identity"

    #: At least one dependency is absent.
    MISSING = "missing"

    #: Failures of more than one kind were found.
    MULTIPLE = "multiple"


@frozen
class Verification(Generic[D]):
    """
    The result of verifying a registry against a `Manifest`.

    Failures are collected independently, so a dependency which both changes
    its contents and changes its identity reports both. The `registry`
    attribute is the registry which was inspected, and is never modified.
    """

    #: The registry against which verification was performed.
    registry: Registry[D]

    #: Dependencies whose contents did not match their allowed digest.
    content_mismatches: Mapping[URI, ContentMismatch] = field(
        factory=dict,
        converter=_as_mapping,
    )

    #: Dependencies whose declared identity did not match the expectation.
    identity_mismatches: Mapping[URI, IdentityMismatch] = field(
        factory=dict,
        converter=_as_mapping,
    )

    #: URIs named by the manifest which were not present in the registry.
    missing: frozenset[URI] = field(
        factory=frozenset,
        converter=frozenset,
    )

    @property
    def ok(self) -> bool:
        """
        Whether every dependency was present, unchanged, and as expected.
        """
        return not (
            self.content_mismatches
            or self.identity_mismatches
            or self.missing
        )

    @property
    def verified(self) -> bool:
        """
        An alias for `ok`.
        """
        return self.ok

    @property
    def kind(self) -> str:
        """
        The kind of result, as a `VerificationKind` value.
        """
        kinds = {
            kind
            for kind, failed in (
                (VerificationKind.CONTENT, self.content_mismatches),
                (VerificationKind.IDENTITY, self.identity_mismatches),
                (VerificationKind.MISSING, self.missing),
            )
            if failed
        }
        if not kinds:
            return VerificationKind.OK
        if len(kinds) > 1:
            return VerificationKind.MULTIPLE
        return kinds.pop()

    @property
    def content(self) -> bool:
        """
        Whether at least one dependency's contents changed.
        """
        return bool(self.content_mismatches)

    @property
    def identity(self) -> bool:
        """
        Whether at least one dependency's declared identity changed.
        """
        return bool(self.identity_mismatches)

    @property
    def is_missing(self) -> bool:
        """
        Whether at least one dependency is absent.
        """
        return bool(self.missing)

    @property
    def content_changed(self) -> tuple[ContentMismatch, ...]:
        """
        The content mismatches, sorted by URI.
        """
        return tuple(sorted(self.content_mismatches.values(), key=_by_uri))

    @property
    def identity_changed(self) -> tuple[IdentityMismatch, ...]:
        """
        The identity mismatches, sorted by URI.
        """
        return tuple(sorted(self.identity_mismatches.values(), key=_by_uri))

    @property
    def missing_dependencies(self) -> frozenset[URI]:
        """
        An alias for `missing`.
        """
        return self.missing

    @property
    def errors(
        self,
    ) -> tuple[ContentMismatch | IdentityMismatch | MissingDependency, ...]:
        """
        Every failure, sorted by URI.
        """
        failures: list[
            ContentMismatch | IdentityMismatch | MissingDependency
        ] = [
            *self.content_mismatches.values(),
            *self.identity_mismatches.values(),
            *(MissingDependency(uri=uri) for uri in self.missing),
        ]
        return tuple(sorted(failures, key=_by_uri))

    @property
    def failures(
        self,
    ) -> tuple[ContentMismatch | IdentityMismatch | MissingDependency, ...]:
        """
        An alias for `errors`.
        """
        return self.errors

    def raise_for_errors(self) -> None:
        """
        Raise `VerificationError` if any dependency failed verification.
        """
        if not self:
            raise VerificationError(self)

    def __bool__(self) -> bool:
        return self.ok


def _locate(
    crawled: Registry[D],
    uri: URI,
    entry: Entry,
    claimed: frozenset[URI],
) -> tuple[URI, Resource[D]] | None:
    """
    Locate the resource for an entry in an already-crawled registry.

    First the entry's own URI is tried. Failing that, a resource registered
    elsewhere whose contents exactly match the allowed digest is used, as
    long as no other manifest entry already claims its location -- which lets
    an identity edit which also moved the resource be reported as an identity
    mismatch instead of incorrectly as a missing dependency.
    """
    try:
        return uri, crawled[uri]
    except exceptions.NoSuchResource:
        pass

    candidates: list[tuple[URI, Resource[D]]] = []
    seen: set[int] = set()
    for slot, resource in crawled.items():
        if slot in claimed or id(resource) in seen:
            continue
        seen.add(id(resource))
        if compare_digest(
            entry.digest,
            content_digest(resource.contents, algorithm=entry.algorithm),
        ):
            candidates.append((slot, resource))
    if len(candidates) != 1:
        return None
    return candidates[0]


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ManifestImportError(
            f"Unable to read {path}: {error}",
        ) from error
    except ValueError as error:
        raise ManifestFormatError(
            f"Invalid JSON in {path}: {error}",
        ) from error


@frozen
class Manifest(Mapping[URI, Entry]):
    """
    An offline, immutable set of expected dependency identities and digests.

    A manifest can be built from a registry with `from_registry`, imported in
    bulk from local JSON files with `from_directory` or `from_files`, and
    loaded from its serialized form with `from_file`. It can then verify a
    registry with `verify`, import its local files with `to_registry`, or act
    as a `Registry` retrieval function via `retrieve` (or by being called).

    Verification only considers resources already present in the registry
    (including subresources found by crawling it), so it never performs
    retrieval and needs no network access.
    """

    _entries: Mapping[URI, Entry] = field(
        factory=dict,
        converter=_as_entries,
        alias="entries",
    )

    #: The directory against which relative entry paths are resolved.
    base: Path | None = None

    @property
    def entries(self) -> Mapping[URI, Entry]:
        """
        The expected dependencies, keyed by URI.
        """
        return self._entries

    @property
    def files(self) -> Mapping[URI, str]:
        """
        The local files of this manifest, keyed by URI.
        """
        return MappingProxyType(
            {
                uri: entry.path
                for uri, entry in self.items()
                if entry.path is not None
            },
        )

    @classmethod
    def from_registry(
        cls,
        registry: Registry[D],
        *,
        algorithm: str = DEFAULT_ALGORITHM,
    ) -> Manifest:
        """
        Build a manifest from every resource in a registry.

        The registry is crawled first, so resources reachable via their
        declared identities (including subresources) are included. Entries
        are keyed by the URI under which each resource is registered, which
        for a crawled registry is its declared identity whenever it has one.
        """
        crawled = registry.crawl()
        entries: dict[URI, Entry] = {}
        seen: set[int] = set()
        for uri in sorted(crawled):
            resource = crawled[uri]
            if id(resource) in seen:
                continue
            seen.add(id(resource))
            identity = _declared_identity(uri, resource)
            key = uri if identity is None else identity
            entries[key] = Entry.from_resource(
                uri,
                resource,
                algorithm=algorithm,
            )
        return cls(entries)

    @classmethod
    def from_resources(
        cls,
        resources: Iterable[tuple[URI, Resource[D]]],
        *,
        algorithm: str = DEFAULT_ALGORITHM,
    ) -> Manifest:
        """
        Build a manifest from resources paired with the URIs storing them.

        Entries are keyed by the given URIs, which need not be the resources'
        declared identities.
        """
        entries: dict[URI, Entry] = {}
        for uri, resource in resources:
            entries[uri.rstrip("#")] = Entry.from_resource(
                uri,
                resource,
                algorithm=algorithm,
            )
        return cls(entries)

    @classmethod
    def from_directory(
        cls,
        directory: str | Path,
        *,
        pattern: str = "*.json",
        recursive: bool = True,
        exclude: Iterable[str] = (),
        algorithm: str = DEFAULT_ALGORITHM,
        default_specification: Specification[D] | None = None,
    ) -> Manifest:
        """
        Bulk-import a manifest from local JSON files in a directory.

        Each file is keyed by its absolute declared ``$id`` (or legacy ``id``)
        when it has one, and otherwise by its path relative to the directory.
        Its expected identity is the declared identity resolved against that
        key, so local files which reference one another can be verified
        without any network access.

        ``exclude`` may contain glob patterns (matched against each file's
        relative path) of files to ignore, for example the manifest's own
        serialized form.
        """
        root = Path(directory)
        if not root.is_dir():
            raise ManifestImportError(f"Not a directory: {root}")

        paths = root.rglob(pattern) if recursive else root.glob(pattern)
        excluded = tuple(exclude)

        def included(path: Path) -> bool:
            relative = path.relative_to(root)
            return not any(relative.match(each) for each in excluded)

        manifest = cls._from_paths(
            (path for path in paths if included(path)),
            base=root,
            algorithm=algorithm,
            default_specification=default_specification,
        )
        return manifest

    @classmethod
    def from_files(
        cls,
        paths: Iterable[str | Path],
        *,
        algorithm: str = DEFAULT_ALGORITHM,
        default_specification: Specification[D] | None = None,
    ) -> Manifest:
        """
        Bulk-import a manifest from an iterable of local JSON files.

        Files are keyed by their absolute declared identity when they have
        one, and otherwise by their path (resolved against the manifest's
        base).
        """
        objects = sorted(Path(each) for each in paths)
        base = objects[0].parent if objects else None

        return cls._from_paths(
            objects,
            base=base,
            algorithm=algorithm,
            default_specification=default_specification,
        )

    @classmethod
    def _from_paths(
        cls,
        paths: Iterable[Path],
        *,
        base: Path | None,
        algorithm: str,
        default_specification: Specification[D] | None,
    ) -> Manifest:
        entries: dict[URI, Entry] = {}
        for path in paths:
            if not path.is_file():
                continue
            contents = _read_json(path)
            try:
                relative = path.relative_to(base) if base is not None else path
            except ValueError:
                relative = path
            uri = relative.as_posix()
            keyword = _identity_key(contents)
            declared = contents[keyword] if keyword is not None else None
            if declared is not None and urlsplit(declared).scheme:
                uri = declared  # type: ignore[assignment]
            if uri in entries:
                raise ManifestImportError(
                    f"Duplicate manifest URI {uri!r}",
                )
            resource = _resource_from_contents(
                contents,
                default_specification=default_specification,
            )
            entries[uri] = Entry(
                digest=content_digest(contents, algorithm=algorithm),
                id=_declared_identity(uri, resource),
                path=relative.as_posix(),
            )
        return cls(entries, base=base)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Manifest:
        """
        Load a manifest from its deserialized JSON representation.

        Both the ``{"version": ..., "resources": {...}}`` format produced by
        `to_dict` and a plain mapping of URIs to entries are accepted.
        """
        if not isinstance(data, Mapping):
            raise ManifestFormatError("A manifest must be an object")

        resources: object = data
        version = data.get("version")
        candidate = data.get("resources")
        if isinstance(candidate, (Mapping, list)):
            if version is not None and version != MANIFEST_VERSION:
                raise ManifestFormatError(
                    f"Unsupported manifest version {version!r}",
                )
            resources = candidate

        entries: dict[URI, Entry] = {}
        if isinstance(resources, Mapping):
            for uri, value in resources.items():
                if not isinstance(uri, str):
                    raise ManifestFormatError(
                        f"Manifest URIs must be strings, not {uri!r}",
                    )
                try:
                    entries[uri] = _entry_from_json(uri, value)
                except ValueError as error:
                    raise ManifestFormatError(str(error)) from error
        elif isinstance(resources, list):
            for value in resources:
                if not isinstance(value, Mapping):
                    raise ManifestFormatError(
                        "Manifest resource lists must contain objects",
                    )
                uri = value.get("uri")
                if not isinstance(uri, str):
                    raise ManifestFormatError(
                        "Manifest resource objects must have a string 'uri'",
                    )
                try:
                    entries[uri] = _entry_from_json(uri, value)
                except ValueError as error:
                    raise ManifestFormatError(str(error)) from error
        else:
            raise ManifestFormatError(
                "Manifest resources must be an object or a list",
            )
        return cls(entries)

    @classmethod
    def from_json(
        cls,
        text: str,
        *,
        base: str | Path | None = None,
    ) -> Manifest:
        """
        Load a manifest from JSON text.
        """
        try:
            data = json.loads(text)
        except ValueError as error:
            raise ManifestFormatError(
                f"Invalid manifest JSON: {error}",
            ) from error
        manifest = cls.from_dict(data)
        if base is None:
            return manifest
        return cls(manifest.entries, base=Path(base))

    @classmethod
    def from_file(cls, path: str | Path) -> Manifest:
        """
        Load a manifest from a JSON file, resolving paths relative to it.
        """
        path = Path(path)
        return cls.from_json(
            path.read_text(encoding="utf-8"),
            base=path.parent,
        )

    @classmethod
    def load(cls, path: str | Path) -> Manifest:
        """
        Load a manifest from a JSON file (an alias for `from_file`).
        """
        return cls.from_file(path)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize this manifest to a JSON-compatible dictionary.
        """
        resources: dict[str, Any] = {}
        for uri, entry in sorted(self.items()):
            serialized: dict[str, Any] = {
                "digest": entry.digest,
                "id": entry.id,
            }
            if entry.path is not None:
                serialized["path"] = entry.path
            resources[uri] = serialized
        return {"version": MANIFEST_VERSION, "resources": resources}

    def to_json(self, *, indent: int | None = None) -> str:
        """
        Serialize this manifest to JSON text.
        """
        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
            ensure_ascii=False,
        )

    def to_file(self, path: str | Path, *, indent: int | None = 2) -> None:
        """
        Serialize this manifest to a JSON file.
        """
        Path(path).write_text(
            self.to_json(indent=indent) + "\n",
            encoding="utf-8",
        )

    save = to_file

    def verify(self, registry: Registry[D] | None = None) -> Verification[D]:
        """
        Verify a registry against this manifest without retrieving anything.

        If no registry is given, this manifest's local files are imported and
        the resulting registry is verified, entirely offline. Only resources
        already present (or found by crawling) are considered, so missing
        files are reported as missing dependencies rather than raised.
        Missing, content-mismatched, and identity-mismatched dependencies are
        reported independently, and the given registry is never modified.
        """
        if registry is None:
            registry = self._registry_from_files()
        crawled = registry.crawl()
        claimed = frozenset(self)
        content_mismatches: dict[URI, ContentMismatch] = {}
        identity_mismatches: dict[URI, IdentityMismatch] = {}
        missing: set[URI] = set()
        for uri, entry in self.items():
            located = _locate(crawled, uri, entry, claimed)
            if located is None:
                missing.add(uri)
                continue

            slot, resource = located
            actual_digest = content_digest(
                resource.contents,
                algorithm=entry.algorithm,
            )
            if not compare_digest(entry.digest, actual_digest):
                content_mismatches[uri] = ContentMismatch(
                    ref=uri,
                    expected_digest=entry.digest,
                    actual_digest=actual_digest,
                )

            actual_identity = _declared_identity(slot, resource)
            if actual_identity != entry.id:
                identity_mismatches[uri] = IdentityMismatch(
                    ref=uri,
                    expected_id=entry.id,
                    actual_id=actual_identity,
                )

        return Verification(
            registry=registry,
            content_mismatches=content_mismatches,
            identity_mismatches=identity_mismatches,
            missing=frozenset(missing),
        )

    def check(self, registry: Registry[D] | None = None) -> Verification[D]:
        """
        Verify a registry (an alias for `verify`).
        """
        return self.verify(registry)

    def assert_valid(self, registry: Registry[D] | None = None) -> None:
        """
        Verify a registry, raising `VerificationError` on any failure.
        """
        self.verify(registry).raise_for_errors()

    def to_registry(
        self,
        *,
        default_specification: Specification[D] | None = None,
    ) -> Registry[D]:
        """
        Import this manifest's local files into a registry, offline.

        Resources are registered under the manifest's URIs, so declared
        identities and expectations are checked by `verify` rather than
        silently changing which URI is looked up. A missing local file raises
        `ManifestImportError`; use `verify` without a registry to report one
        as a missing dependency instead.
        """
        from referencing import Registry

        pairs = []
        for uri, entry in self.items():
            if entry.path is None:
                raise ManifestImportError(
                    f"Manifest entry {uri!r} has no local path",
                )
            contents = _read_json(self._file(entry))
            pairs.append(
                (
                    uri,
                    _resource_from_contents(
                        contents,
                        default_specification=default_specification,
                    ),
                ),
            )
        return Registry().with_resources(pairs)

    def load_registry(self, **kwargs: Any) -> Registry[D]:
        """
        An alias for `to_registry`.
        """
        return self.to_registry(**kwargs)

    def retrieve(self, uri: URI) -> Resource[D]:
        """
        Retrieve a dependency from its local file, verifying it first.

        This can be used as a `Registry` retrieval function, either as
        ``Registry(retrieve=manifest.retrieve)`` or by passing the manifest
        itself, which is callable. Unknown URIs raise `NoSuchResource`, and
        contents which fail verification are rejected with `ContentMismatch`
        or `IdentityMismatch`.
        """
        try:
            entry = self[uri]
        except KeyError:
            raise exceptions.NoSuchResource(ref=uri) from None
        if entry.path is None:
            raise exceptions.NoSuchResource(ref=uri)

        path = self._file(entry)
        if not path.is_file():
            raise exceptions.NoSuchResource(ref=uri)
        contents = _read_json(path)

        actual_digest = content_digest(contents, algorithm=entry.algorithm)
        if not compare_digest(entry.digest, actual_digest):
            raise ContentMismatch(
                ref=uri,
                expected_digest=entry.digest,
                actual_digest=actual_digest,
            )

        resource = _resource_from_contents(contents)
        actual_identity = _declared_identity(uri, resource)
        if actual_identity != entry.id:
            raise IdentityMismatch(
                ref=uri,
                expected_id=entry.id,
                actual_id=actual_identity,
            )
        return resource

    def __call__(self, uri: URI) -> Resource[D]:
        return self.retrieve(uri)

    def _registry_from_files(self) -> Registry[D]:
        from referencing import Registry

        pairs = []
        for uri, entry in self.items():
            if entry.path is None:
                continue
            path = self._file(entry)
            if not path.is_file():
                continue
            pairs.append((uri, _resource_from_contents(_read_json(path))))
        return Registry().with_resources(pairs)

    def _file(self, entry: Entry) -> Path:
        path = Path(entry.path or "")
        if not path.is_absolute() and self.base is not None:
            path = self.base / path
        return path

    def __getitem__(self, uri: URI) -> Entry:
        return self._entries[uri]

    def __iter__(self) -> Iterator[URI]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


def _resource_from_contents(
    contents: object,
    *,
    default_specification: Specification[Any] | None = None,
) -> Resource[Any]:
    from referencing import Resource
    from referencing.jsonschema import DRAFT202012

    if default_specification is None:
        default_specification = DRAFT202012
    return Resource.from_contents(
        contents,  # type: ignore[arg-type]
        default_specification=default_specification,
    )


def verify(
    manifest: Manifest,
    registry: Registry[D] | None = None,
) -> Verification[D]:
    """
    Verify a registry against a manifest (an alias for `Manifest.verify`).
    """
    return manifest.verify(registry)


#: A convenience alias for the entry type.
ManifestEntry = Entry

#: A convenience alias for the verification result type.
VerificationResult = Verification

#: A convenience alias for the verification error type.
ManifestVerificationError = VerificationError
