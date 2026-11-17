"""
Optional provenance auditing for outgoing request headers.

This module allows signing backends and other security-sensitive callers
to confirm *where* each raw header on an outgoing request originated:
client defaults, the request-level `headers=...` argument, automatically
populated defaults, the authentication flow, or a redirect rebuild.

Auditing always operates on the raw `(name, value)` pairs that are sent
on the wire. Comma-merged values (such as `headers[name]`) are never used
to determine uniqueness, since merging hides duplicates.
"""

from __future__ import annotations

import typing

__all__ = [
    "HeaderAuditEntry",
    "HeaderAuditOverride",
    "HeaderAuditPolicy",
    "HeaderAuditRemoval",
    "HeaderAuditReport",
    "HeaderSource",
]


class HeaderSource:
    """
    The set of origins that a request header can be attributed to.
    """

    CLIENT = "client"  # Client-level default headers.
    REQUEST = "request"  # Request-level `headers=...`, or a manually built request.
    DEFAULT = "default"  # Automatically populated, eg. `Host`, `Content-Length`.
    AUTH = "auth"  # Applied by the authentication flow.
    REDIRECT = "redirect"  # Applied while rebuilding a request for a redirect.
    UNKNOWN = "unknown"  # Anything else, eg. event hooks mutating a request.


KNOWN_SOURCES = frozenset(
    {
        HeaderSource.CLIENT,
        HeaderSource.REQUEST,
        HeaderSource.DEFAULT,
        HeaderSource.AUTH,
        HeaderSource.REDIRECT,
        HeaderSource.UNKNOWN,
    }
)


class HeaderAuditOverride:
    """
    A header pair that was replaced by another pair with the same name.
    """

    def __init__(self, name: bytes, value: bytes, source: str) -> None:
        self.name = name
        self.value = value
        self.source = source

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, HeaderAuditOverride)
            and self.name == other.name
            and self.value == other.value
            and self.source == other.source
        )

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f"{class_name}({self.name!r}, {self.value!r}, source={self.source!r})"


class HeaderAuditRemoval:
    """
    A header pair that was present at one point, then removed before sending.
    """

    def __init__(self, name: bytes, value: bytes, source: str, removed_by: str) -> None:
        self.name = name
        self.value = value
        self.source = source
        self.removed_by = removed_by

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, HeaderAuditRemoval)
            and self.name == other.name
            and self.value == other.value
            and self.source == other.source
            and self.removed_by == other.removed_by
        )

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return (
            f"{class_name}({self.name!r}, {self.value!r}, "
            f"source={self.source!r}, removed_by={self.removed_by!r})"
        )


class HeaderAuditEntry:
    """
    A single raw header pair on the final request, with its provenance.

    Instances correspond one-to-one with `request.headers.raw`.
    """

    def __init__(
        self,
        name: bytes,
        value: bytes,
        source: str,
        overrides: typing.Iterable[HeaderAuditOverride] = (),
    ) -> None:
        self.name = name
        self.value = value
        self.source = source
        self.overrides = tuple(overrides)

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, HeaderAuditEntry)
            and self.name == other.name
            and self.value == other.value
            and self.source == other.source
            and self.overrides == other.overrides
        )

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f"{class_name}({self.name!r}, {self.value!r}, source={self.source!r})"


class HeaderAuditReport:
    """
    The provenance of every raw header pair on a request that is being sent.

    * `entries` corresponds one-to-one with `request.headers.raw`,
      in the same order.
    * `removals` records pairs that were dropped along the way, such as
      `Authorization` being stripped on a cross-origin redirect.
    """

    def __init__(
        self,
        entries: typing.Iterable[HeaderAuditEntry],
        removals: typing.Iterable[HeaderAuditRemoval] = (),
    ) -> None:
        self.entries = tuple(entries)
        self.removals = tuple(removals)

    @property
    def raw(self) -> list[tuple[bytes, bytes]]:
        """
        The audited raw header pairs. Always equal to `request.headers.raw`.
        """
        return [(entry.name, entry.value) for entry in self.entries]

    def entries_for(self, name: str) -> list[HeaderAuditEntry]:
        """
        Return every final entry for a header name, without any merging.
        """
        name_bytes = name.lower().encode("utf-8")
        return [entry for entry in self.entries if entry.name.lower() == name_bytes]

    def sources_for(self, name: str) -> set[str]:
        """
        Return the set of origins that a header name was populated from.
        """
        return {entry.source for entry in self.entries_for(name)}

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f"{class_name}({list(self.entries)!r}, removals={list(self.removals)!r})"


class _TrackedHeader:
    def __init__(
        self,
        name: bytes,
        value: bytes,
        source: str,
        overrides: typing.Iterable[HeaderAuditOverride] = (),
    ) -> None:
        self.name = name
        self.value = value
        self.source = source
        self.overrides = tuple(overrides)


class HeaderAuditTrail:
    """
    Records how the raw headers on a request evolve across each stage of
    the client send pipeline, keeping raw pairs and override relations.
    """

    def __init__(self) -> None:
        self._entries: list[_TrackedHeader] = []
        self._removals: list[HeaderAuditRemoval] = []

    def record(self, raw: list[tuple[bytes, bytes]], source: str) -> None:
        """
        Reconcile the tracked headers against a new raw header state,
        attributing any differences to `source`.
        """
        unmatched = list(self._entries)
        entries: list[_TrackedHeader] = []
        added: list[_TrackedHeader] = []
        for name, value in raw:
            lowered = name.lower()
            for index, candidate in enumerate(unmatched):
                if candidate.name.lower() == lowered and candidate.value == value:
                    entries.append(candidate)
                    del unmatched[index]
                    break
            else:
                tracked = _TrackedHeader(name, value, source)
                entries.append(tracked)
                added.append(tracked)

        removed = unmatched
        for tracked in added:
            lowered = tracked.name.lower()
            tracked.overrides = tuple(
                HeaderAuditOverride(item.name, item.value, item.source)
                for item in removed
                if item.name.lower() == lowered
            )
        self._removals.extend(
            HeaderAuditRemoval(item.name, item.value, item.source, removed_by=source)
            for item in removed
        )
        self._entries = entries

    def finalize(self, raw: list[tuple[bytes, bytes]]) -> HeaderAuditReport:
        """
        Reconcile against the final raw headers and build the audit report.
        Any last-minute changes, such as event hook mutations, are
        attributed to `HeaderSource.UNKNOWN`.
        """
        self.record(list(raw), HeaderSource.UNKNOWN)
        entries = [
            HeaderAuditEntry(item.name, item.value, item.source, item.overrides)
            for item in self._entries
        ]
        return HeaderAuditReport(entries, self._removals)


class HeaderAuditPolicy:
    """
    Declare which origins sensitive headers are allowed to come from,
    and which of them may legitimately appear more than once.

    * `allowed_sources` maps a header name such as `"Authorization"` to
      the source (or sources) it may originate from, for example
      `{"Authorization": "auth"}`.
    * `allow_duplicates` lists header names that are explicitly allowed
      to appear multiple times in the raw headers. Any sensitive header
      that appears more than once and is not listed here is a violation.
    * `on_violation` is either `"reject"` to raise `HeaderAuditError`
      before the request is sent, or `"report"` to only make the report
      available on the request.
    """

    def __init__(
        self,
        allowed_sources: typing.Mapping[str, str | typing.Iterable[str]],
        *,
        allow_duplicates: typing.Iterable[str] = (),
        on_violation: typing.Literal["reject", "report"] = "reject",
    ) -> None:
        if on_violation not in ("reject", "report"):
            raise ValueError(
                f"Invalid 'on_violation' mode: {on_violation!r}. "
                "Expected 'reject' or 'report'."
            )

        normalized_sources: dict[bytes, frozenset[str]] = {}
        for name, sources in allowed_sources.items():
            if isinstance(sources, str):
                source_set = frozenset({sources})
            else:
                source_set = frozenset(sources)
            unknown = source_set - KNOWN_SOURCES
            if unknown:
                raise ValueError(
                    f"Invalid header source(s) for {name!r}: "
                    f"{sorted(unknown)!r}. Expected one of {sorted(KNOWN_SOURCES)!r}."
                )
            normalized_sources[name.lower().encode("utf-8")] = source_set

        self.allowed_sources = normalized_sources
        self.allow_duplicates = frozenset(
            name.lower().encode("utf-8") for name in allow_duplicates
        )
        self.on_violation = on_violation

    def evaluate(self, report: HeaderAuditReport) -> list[str]:
        """
        Return a list of policy violations for an audit report.
        An empty list indicates that the report satisfies the policy.
        """
        entries_by_name: dict[bytes, list[HeaderAuditEntry]] = {}
        for entry in report.entries:
            entries_by_name.setdefault(entry.name.lower(), []).append(entry)

        violations: list[str] = []
        for name, allowed in self.allowed_sources.items():
            entries = entries_by_name.get(name, [])
            display_name = name.decode("utf-8")
            if len(entries) > 1 and name not in self.allow_duplicates:
                sources = sorted(entry.source for entry in entries)
                violations.append(
                    f"Header {display_name!r} appears {len(entries)} times "
                    f"(sources: {sources!r}), but duplicates have not been "
                    "explicitly allowed."
                )
            for entry in entries:
                if entry.source not in allowed:
                    violations.append(
                        f"Header {display_name!r} includes a value from "
                        f"source {entry.source!r}, which is not one of the "
                        f"allowed source(s) {sorted(allowed)!r}."
                    )
        return violations
