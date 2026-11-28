"""Static data model for the endpoint address audit.

Everything in this module is plain, serialisable data.  No object created
here can bind a socket, read a TLS key or start a listener: the audit only
ever reasons about the *text* of endpoint descriptions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Family(enum.Enum):
    """Address family a range belongs to."""

    INET4 = "inet4"
    INET6 = "inet6"
    UNIX = "unix"
    UNKNOWN = "unknown"


class HostKind(enum.Enum):
    """How concrete the host part of an IP binding is."""

    WILDCARD = "wildcard"
    ADDRESS = "address"
    NAME = "name"
    UNKNOWN = "unknown"


class Verdict(enum.Enum):
    """Result of comparing two listening ranges."""

    OVERLAP = "overlap"
    SEPARATE = "separate"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SourceCoordinate:
    """Pointer back to the place an endpoint was declared.

    The coordinate is deliberately generic so that both text manifests and
    JSON documents (or future configuration sources) can be traced back to
    the exact declaration being reported on.
    """

    source: str
    line: int | None = None
    column: int | None = None
    service: str | None = None

    def render(self) -> str:
        location = self.source
        if self.line is not None:
            location = f"{location}:{self.line}"
            if self.column is not None:
                location = f"{location}:{self.column}"
        if self.service:
            location = f"{location} ({self.service})"
        return location

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "line": self.line,
            "column": self.column,
            "service": self.service,
        }


@dataclass(frozen=True)
class HostBinding:
    """The host portion of an IP socket binding."""

    kind: HostKind
    family: Family
    value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "family": self.family.value,
            "value": self.value,
        }


@dataclass(frozen=True)
class ListenRange:
    """One concrete or uncertain set of network addresses.

    IP ranges carry a L{HostBinding} plus a port; UNIX ranges carry a
    filesystem path; fully unknown ranges (port 0, runtime-only plugins,
    unrecognised schemes) keep their uncertainty instead of guessing.
    """

    family: Family
    host: HostBinding | None = None
    port: int | None = None
    path: str | None = None
    certain: bool = True
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family.value,
            "host": None if self.host is None else self.host.to_dict(),
            "port": self.port,
            "path": self.path,
            "certain": self.certain,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Issue:
    """A non-fatal or fatal problem found while parsing one declaration."""

    code: str
    message: str
    coordinate: SourceCoordinate

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "coordinate": self.coordinate.to_dict(),
        }


@dataclass
class ParsedEntry:
    """One service endpoint declaration after static analysis.

    Wrapper layers (TLS, HAProxy, ...) are recorded in C{layers} but never
    participate in address comparison: two ranges are compared only on the
    underlying host/port or socket path.
    """

    description: str
    coordinate: SourceCoordinate
    scheme: str | None = None
    layers: tuple[str, ...] = ()
    ranges: list[ListenRange] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def has_fatal_issue(self) -> bool:
        return any(issue.code.startswith("FATAL") for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "coordinate": self.coordinate.to_dict(),
            "scheme": self.scheme,
            "layers": list(self.layers),
            "ranges": [rng.to_dict() for rng in self.ranges],
            "issues": [issue.to_dict() for issue in self.issues],
            "notes": list(self.notes),
        }
