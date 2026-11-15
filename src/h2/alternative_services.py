"""
h2/alternative_services
~~~~~~~~~~~~~~~~~~~~~~~

A restricted cache for RFC 7838 alternative services.

An :class:`AlternativeServiceAvailable
<h2.events.AlternativeServiceAvailable>` event is only an advertisement.  It
does not say that the connection at the advertised address is entitled to
receive requests or credentials for the advertised origin.  The origin in an
ALTSVC frame is supplied by the peer, a connection may be coalesced or
redirected, and the alternative's address is not the origin's identity.

This module therefore stores advertisements as inert candidates.  A candidate
becomes usable only after the application explicitly supplies a
:class:`TlsIdentity` that it has established and verified for the original
origin.  The cache never opens connections, sends requests, or handles
credentials.  Malformed or untrusted advertisements are rejected atomically,
so they cannot overwrite a candidate that is still valid.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum

from .events import AlternativeServiceAvailable

__all__ = [
    "AdvertisementSource",
    "AdmissionStatus",
    "AlternativeServiceCache",
    "AlternativeServiceCandidate",
    "AlternativeServiceUpdate",
    "Origin",
    "TlsIdentity",
    "parse_origin",
]


# Alt-Svc uses HTTP tokens, quoted strings, and decimal ports.  Advertisements
# are untrusted input, so keep every grammar check strict.
_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.-]*")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_IPV4_RE = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}")

_DEFAULT_PORTS = {"http": 80, "https": 443}

#: RFC 7838 gives ``ma`` a default value of one day.
_DEFAULT_MAX_AGE = 86400

#: RFC 7838's alternative authority is ``host:port``.  IPv6 literals use
#: brackets.  The host may be empty, meaning "the origin's host".
_MAX_PORT = 65535
_MIN_PORT = 1


class AdvertisementSource(Enum):
    """
    The source of an advertisement's origin and the field value.

    ``CONNECTION`` covers an ALTSVC frame received on stream 0.  Per RFC 7838
    that frame carries its origin explicitly.  ``STREAM`` covers an ALTSVC
    frame received on a request or pushed stream; h2 infers the origin from the
    stream's ``:authority``.  ``HEADER`` covers an ``alt-svc`` response header,
    whose origin is supplied by the application and which is the only form
    allowed to use the ``clear`` token.
    """

    CONNECTION = "connection"
    STREAM = "stream"
    HEADER = "header"


class AdmissionStatus(Enum):
    """
    The result of offering one advertisement to the cache.
    """

    ACCEPTED = "accepted"
    CLEARED = "cleared"
    UNTRUSTED_ORIGIN = "untrusted-origin"
    UNVERIFIED_CONNECTION = "unverified-connection"
    WRONG_STREAM = "wrong-stream"
    MALFORMED = "malformed"
    CLEAR_NOT_ALLOWED = "clear-not-allowed"
    UNSUPPORTED_PROTOCOL = "unsupported-protocol"
    TOO_MANY_CANDIDATES = "too-many-candidates"

    @property
    def accepted(self) -> bool:
        """
        Whether the operation changed the cache in a usable way.
        """
        return self in (AdmissionStatus.ACCEPTED, AdmissionStatus.CLEARED)


def _ascii_lower(value: str) -> str:
    """
    Lowercase an ASCII string, rejecting non-ASCII input.

    ``str.lower`` can change non-ASCII code points, which is not appropriate
    for HTTP fields or host names.
    """
    try:
        value.encode("ascii")
    except UnicodeEncodeError as e:
        msg = "value is not ASCII"
        raise ValueError(msg) from e
    return value.lower()


def _require_ascii(value: bytes | bytearray | str, *, what: str) -> str:
    """
    Decode bytes as ASCII, or return a string after checking it is ASCII.
    """
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("ascii")
        except UnicodeDecodeError as e:
            msg = f"{what} is not ASCII"
            raise ValueError(msg) from e
    if isinstance(value, str):
        try:
            value.encode("ascii")
        except UnicodeEncodeError as e:
            msg = f"{what} is not ASCII"
            raise ValueError(msg) from e
        return value
    msg = f"{what} must be bytes or str"
    raise TypeError(msg)


def _validate_host(host: str) -> str:
    """
    Validate and canonicalize a DNS name or IP address.
    """
    if not host:
        msg = "empty host"
        raise ValueError(msg)
    if host.startswith("[") or host.endswith("]"):
        msg = "brackets are not valid in a bare host"
        raise ValueError(msg)

    host = _ascii_lower(host.rstrip("."))
    if not host:
        msg = "empty host"
        raise ValueError(msg)

    try:
        ipaddress.ip_address(host)
    except ValueError as e:
        if _IPV4_RE.fullmatch(host):
            msg = "invalid IPv4 address"
            raise ValueError(msg) from e
        if any(not _DNS_LABEL_RE.fullmatch(label) for label in host.split(".")):
            msg = "invalid host name"
            raise ValueError(msg) from e
    return host


def _parse_port(port_text: str) -> int:
    """
    Parse a decimal port in the inclusive range 1-65535.
    """
    if not port_text or not port_text.isdigit():
        msg = "port is not a decimal number"
        raise ValueError(msg)
    port = int(port_text, 10)
    if not _MIN_PORT <= port <= _MAX_PORT:
        msg = "port is out of range"
        raise ValueError(msg)
    return port


def _split_host_port(value: str, *, empty_host: str | None) -> tuple[str, int]:
    """
    Split an Alt-Svc ``host:port`` alternative authority.

    An empty host means the host of the origin being advertised.  ``empty_host``
    is that origin host, or ``None`` when no origin is available.
    """
    if not value:
        msg = "empty alternative authority"
        raise ValueError(msg)
    if any(char in value for char in "/?#@"):
        msg = "alternative authority contains forbidden characters"
        raise ValueError(msg)

    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            msg = "unterminated IPv6 literal"
            raise ValueError(msg)
        host = value[1:end]
        port_text = value[end + 1 :]
        if not port_text.startswith(":"):
            msg = "missing alternative port"
            raise ValueError(msg)
        try:
            ipaddress.IPv6Address(host)
        except ValueError as e:
            msg = "invalid IPv6 literal"
            raise ValueError(msg) from e
        host = _ascii_lower(host)
        port_text = port_text[1:]
    else:
        if value.count(":") != 1:
            msg = "alternative must be host:port"
            raise ValueError(msg)
        host_text, port_text = value.split(":", 1)
        if host_text:
            host = _validate_host(host_text)
        elif empty_host is not None:
            host = empty_host
        else:
            msg = "alternative host is required"
            raise ValueError(msg)

    return host, _parse_port(port_text)


@dataclass(frozen=True)
class Origin:
    """
    A canonical HTTP origin.

    The scheme and host are lowercase.  The port is always stored, and default
    ports are omitted from :func:`str`'s output.  Canonicalization is shared by
    trusted origins and advertised origins, so ``https://example.com:443`` and
    the authority ``example.com`` compare equal.
    """

    scheme: str
    host: str
    port: int

    def __post_init__(self) -> None:
        scheme = _ascii_lower(self.scheme)
        if not _SCHEME_RE.fullmatch(scheme):
            msg = "invalid origin scheme"
            raise ValueError(msg)
        host = _validate_host(self.host)
        if not isinstance(self.port, int) or not _MIN_PORT <= self.port <= _MAX_PORT:
            msg = "origin port is out of range"
            raise ValueError(msg)
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "host", host)

    def __str__(self) -> str:
        authority = f"[{self.host}]" if ":" in self.host else self.host
        if self.port != _DEFAULT_PORTS.get(self.scheme):
            authority = f"{authority}:{self.port}"
        return f"{self.scheme}://{authority}"

    @property
    def authority(self) -> str:
        """
        The canonical authority: host and, when non-default, port.
        """
        return str(self).split("://", 1)[1]

    @property
    def ascii_bytes(self) -> bytes:
        """
        The canonical ASCII serialization.
        """
        return str(self).encode("ascii")

    @classmethod
    def parse(cls, origin: Origin | bytes | bytearray | str, *, default_scheme: str = "https") -> Origin:
        """
        Parse and canonicalize an origin or authority.
        """
        return parse_origin(origin, default_scheme=default_scheme)


def _parse_authority_host(rest: str, scheme: str) -> tuple[str, int]:
    """
    Parse the host and optional port portion of an origin.
    """
    port_text = ""
    if rest.startswith("["):
        end = rest.find("]")
        if end < 0:
            msg = "unterminated IPv6 literal"
            raise ValueError(msg)
        host = rest[1:end]
        tail = rest[end + 1 :]
        if tail:
            if not tail.startswith(":"):
                msg = "invalid origin authority"
                raise ValueError(msg)
            port_text = tail[1:]
        try:
            ipaddress.IPv6Address(host)
        except ValueError as e:
            msg = "invalid IPv6 literal"
            raise ValueError(msg) from e
        host = _ascii_lower(host)
    else:
        if rest.count(":") > 1:
            msg = "IPv6 literals must be bracketed"
            raise ValueError(msg)
        if ":" in rest:
            host_text, port_text = rest.rsplit(":", 1)
        else:
            host_text = rest
        host = _validate_host(host_text)

    if port_text:
        return host, _parse_port(port_text)
    default = _DEFAULT_PORTS.get(scheme)
    if default is None:
        msg = "an explicit port is required for this scheme"
        raise ValueError(msg)
    return host, default


def parse_origin(
    origin: Origin | bytes | bytearray | str,
    *,
    default_scheme: str = "https",
) -> Origin:
    """
    Parse an origin or authority into a canonical :class:`Origin`.

    h2 infers a stream-level ALTSVC origin from the request's ``:authority``,
    which has no scheme; ``default_scheme`` supplies it.  Explicit origins may
    include a scheme, and h2 also passes through the origin exactly as the peer
    sent it, so a bare authority is accepted and canonicalized with
    ``default_scheme``.  User information, paths, queries, and fragments are
    rejected so that distinct URLs cannot be collapsed into one origin.
    """
    if isinstance(origin, Origin):
        return origin

    text = _require_ascii(origin, what="origin").strip()
    if not text:
        msg = "empty origin"
        raise ValueError(msg)

    if "://" in text:
        scheme_text, rest = text.split("://", 1)
    else:
        scheme_text, rest = default_scheme, text

    scheme = _ascii_lower(scheme_text)
    if not _SCHEME_RE.fullmatch(scheme):
        msg = "invalid origin scheme"
        raise ValueError(msg)

    if rest.endswith("/"):
        rest = rest[:-1]
    if not rest or any(char in rest for char in "/?#@"):
        msg = "origin contains a path, query, fragment, or userinfo"
        raise ValueError(msg)

    host, port = _parse_authority_host(rest, scheme)
    return Origin(scheme=scheme, host=host, port=port)


def _normalize_peer_name(name: bytes | bytearray | str) -> str:
    """
    Normalize one verified peer name.
    """
    text = _ascii_lower(_require_ascii(name, what="peer name").strip().rstrip("."))
    if not text:
        msg = "empty peer name"
        raise ValueError(msg)
    if text.startswith("*."):
        suffix = _validate_host(text[2:])
        if "." not in suffix:
            msg = "wildcard peer name is too broad"
            raise ValueError(msg)
        return f"*.{suffix}"
    return _validate_host(text)


@dataclass(frozen=True, init=False)
class TlsIdentity:
    """
    TLS identity information explicitly supplied by the application.

    The cache cannot discover a TLS identity and must not infer one from an h2
    connection.  Construct this object only after the application has verified
    the peer certificate chain and that the peer is authorized for
    ``origin``.

    ``peer_names`` must contain the verified names that support that
    authorization, for example the DNS names from the certificate's subject
    alternative names.  A verified identity must name at least one peer, and
    ``origin``'s host must be covered by one of them.

    For an alternative service, RFC 7838 requires the alternative to
    authenticate itself as authoritative for the *origin*, not for its own
    address.  Pass the identity established on the connection to the
    alternative and verify it against the origin.  Never populate
    ``verified=True`` from advertisement data: the object is immutable so an
    identity established for one connection cannot later be repointed at
    another origin.
    """

    origin: Origin
    verified: bool
    peer_names: frozenset[str]

    def __init__(
        self,
        origin: Origin | bytes | bytearray | str,
        *,
        verified: bool,
        peer_names: Iterable[bytes | bytearray | str] = (),
    ) -> None:
        object.__setattr__(self, "origin", parse_origin(origin))
        object.__setattr__(self, "verified", bool(verified))
        names = frozenset(_normalize_peer_name(name) for name in peer_names)
        if self.verified and not names:
            msg = "a verified TLS identity requires at least one peer name"
            raise ValueError(msg)
        object.__setattr__(self, "peer_names", names)

    @property
    def authorized_origin(self) -> Origin:
        """
        The original origin this identity authorizes.
        """
        return self.origin

    def covers_host(self, host: str) -> bool:
        """
        Whether one of the verified peer names covers ``host``.
        """
        host = _validate_host(host)
        for name in self.peer_names:
            if name == host:
                return True
            if name.startswith("*."):
                suffix = name[1:]
                if host.endswith(suffix) and host.count(".") == suffix.count("."):
                    return True
        return False

    def authorizes(self, origin: Origin | bytes | bytearray | str) -> bool:
        """
        Whether this verified identity is authorized for ``origin``.

        The identity is tied to its original origin and its verified names must
        cover that origin's host.  An alternative service's address does not
        grant authority.
        """
        if not self.verified:
            return False
        try:
            parsed = parse_origin(origin)
        except (TypeError, ValueError):
            return False
        return parsed == self.origin and self.covers_host(self.origin.host)


@dataclass(frozen=True)
class AlternativeServiceCandidate:
    """
    One inert alternative service candidate.

    A candidate carries no credentials and no request.  It records only what
    was advertised.  :meth:`AlternativeServiceCache.candidates` returns inert
    records; use :meth:`AlternativeServiceCache.authorize` with an identity
    established on a connection to the candidate before sending anything.
    """

    origin: Origin
    protocol_id: str
    host: str
    port: int
    advertised_at: float
    expires_at: float
    source: AdvertisementSource
    stream_id: int | None
    persist: bool

    @property
    def authority(self) -> str:
        """
        The host and port of this candidate.
        """
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def is_expired(self, now: float) -> bool:
        """
        Whether this candidate's freshness lifetime has elapsed.
        """
        return now >= self.expires_at

    def accepts_identity(self, tls_identity: TlsIdentity) -> bool:
        """
        Whether ``tls_identity`` authorizes the candidate's original origin.
        """
        return tls_identity.authorizes(self.origin)


@dataclass(frozen=True)
class AlternativeServiceUpdate:
    """
    The outcome of offering one advertisement or clear operation.
    """

    status: AdmissionStatus
    origin: Origin | None = None
    source: AdvertisementSource | None = None
    added: tuple[AlternativeServiceCandidate, ...] = ()
    removed: tuple[AlternativeServiceCandidate, ...] = ()
    detail: str | None = None

    @property
    def accepted(self) -> bool:
        """
        Whether the advertisement was accepted or cleared the cache.
        """
        return self.status.accepted


@dataclass(frozen=True)
class _ParsedAlternative:
    protocol_id: str
    host: str
    port: int
    max_age: int
    persist: bool


def _split_alt_values(value: str) -> list[str]:
    """
    Split an Alt-Svc field value on commas outside quoted strings.
    """
    values: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False

    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif quoted and char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char == "," and not quoted:
            part = "".join(current).strip()
            if not part:
                msg = "empty alternative in field value"
                raise ValueError(msg)
            values.append(part)
            current = []
        else:
            current.append(char)

    if quoted or escaped:
        msg = "unterminated quoted string"
        raise ValueError(msg)
    part = "".join(current).strip()
    if not part:
        msg = "empty Alt-Svc field value"
        raise ValueError(msg)
    values.append(part)
    return values


def _parse_quoted(value: str, start: int) -> tuple[str, int]:
    """
    Parse a quoted string and return it with the position after its end quote.
    """
    if start >= len(value) or value[start] != '"':
        msg = "expected a quoted string"
        raise ValueError(msg)

    result: list[str] = []
    escaped = False
    for index in range(start + 1, len(value)):
        char = value[index]
        if escaped:
            result.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return "".join(result), index + 1
        else:
            result.append(char)

    msg = "unterminated quoted string"
    raise ValueError(msg)


def _parse_parameters(parameters: str) -> tuple[int, bool]:
    """
    Parse and validate ``ma``, ``persist``, and extension parameters.

    Unknown parameters are syntax-checked but given no meaning.  ``ma`` and
    ``persist`` are decimal tokens per RFC 7838; a quoted value is rejected.
    """
    max_age = _DEFAULT_MAX_AGE
    saw_max_age = False
    persist = False

    for parameter in parameters.split(";"):
        parameter = parameter.strip()
        if not parameter:
            continue

        if "=" not in parameter:
            if not _TOKEN_RE.fullmatch(parameter):
                msg = "invalid Alt-Svc parameter"
                raise ValueError(msg)
            if parameter.lower() == "persist":
                persist = True
            continue
        name, raw_value = parameter.split("=", 1)
        name = name.strip()
        raw_value = raw_value.strip()
        if not _TOKEN_RE.fullmatch(name):
            msg = "invalid Alt-Svc parameter name"
            raise ValueError(msg)

        if name.lower() == "ma":
            if saw_max_age:
                msg = "duplicate ma parameter"
                raise ValueError(msg)
            if not raw_value.isdigit():
                msg = "invalid ma parameter"
                raise ValueError(msg)
            saw_max_age = True
            max_age = min(int(raw_value, 10), 2**31 - 1)
        elif name.lower() == "persist":
            if raw_value not in ("0", "1"):
                msg = "invalid persist parameter"
                raise ValueError(msg)
            persist = raw_value == "1"
        elif raw_value.startswith('"'):
            _parse_parameter_value(raw_value)
        elif not _TOKEN_RE.fullmatch(raw_value):
            msg = "invalid Alt-Svc parameter value"
            raise ValueError(msg)

    return max_age, persist


def _parse_parameter_value(raw_value: str) -> str:
    """
    Parse a quoted extension parameter value strictly.
    """
    value, position = _parse_quoted(raw_value, 0)
    if position != len(raw_value):
        msg = "unexpected data after parameter value"
        raise ValueError(msg)
    return value


def _parse_alternative(value: str, *, origin: Origin) -> _ParsedAlternative:
    """
    Parse one ``protocol-id="host:port"; params`` alternative.
    """
    match = _TOKEN_RE.match(value)
    if match is None:
        msg = "missing protocol identifier"
        raise ValueError(msg)
    protocol_id = match.group(0)
    position = match.end()

    while position < len(value) and value[position].isspace():
        position += 1
    if position >= len(value) or value[position] != "=":
        msg = "missing '=' after protocol identifier"
        raise ValueError(msg)
    position += 1
    while position < len(value) and value[position].isspace():
        position += 1

    authority, position = _parse_quoted(value, position)
    while position < len(value) and value[position].isspace():
        position += 1
    if position < len(value) and value[position] != ";":
        msg = "unexpected data after alternative authority"
        raise ValueError(msg)

    parameters = value[position + 1 :] if position < len(value) else ""
    max_age, persist = _parse_parameters(parameters)
    host, port = _split_host_port(authority, empty_host=origin.host)
    return _ParsedAlternative(
        protocol_id=protocol_id,
        host=host,
        port=port,
        max_age=max_age,
        persist=persist,
    )


def _parse_field_value(value: bytes, *, origin: Origin) -> list[_ParsedAlternative]:
    """
    Parse a complete Alt-Svc field value.

    Parsing is all-or-nothing.  If any alternative or parameter is malformed,
    no part of the field may be applied.
    """
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as e:
        msg = "Alt-Svc field value is not ASCII"
        raise ValueError(msg) from e

    text = text.strip()
    if not text:
        msg = "empty Alt-Svc field value"
        raise ValueError(msg)
    return [_parse_alternative(part, origin=origin) for part in _split_alt_values(text)]


def _event_origin(event: AlternativeServiceAvailable) -> bytes | bytearray | str | None:
    """
    Read an event's origin without assuming a concrete attribute type.
    """
    origin: bytes | bytearray | str | None = event.origin
    return origin


def _event_field(event: AlternativeServiceAvailable) -> bytes | bytearray | None:
    """
    Read an event's field value without assuming a concrete attribute type.
    """
    field: bytes | bytearray | None = event.field_value
    return field


class AlternativeServiceCache:
    """
    A bounded, security-restricted cache of RFC 7838 alternative services.

    Only origins in ``trusted_origins`` are accepted.  Every advertisement must
    also be accompanied by a :class:`TlsIdentity` that the application has
    verified for that origin.  Candidates expire according to ``ma`` using
    ``clock``, and a malformed or unacceptable field value never modifies the
    cache.

    The cache performs no network I/O and holds no credentials.  Obtaining a
    candidate with :meth:`candidates` is not authorization to use it: call
    :meth:`authorize` after the TLS handshake with the candidate has been
    verified against the original origin, and only then send a request.

    This class is not thread-safe, matching
    :class:`H2Connection <h2.connection.H2Connection>`.
    """

    def __init__(
        self,
        trusted_origins: Iterable[Origin | bytes | bytearray | str],
        *,
        clock: Callable[[], float] | None = None,
        supported_protocols: Iterable[str] = ("h2",),
        default_scheme: str = "https",
        max_field_length: int = 8192,
        max_candidates_per_origin: int = 8,
    ) -> None:
        if max_field_length <= 0:
            msg = "max_field_length must be positive"
            raise ValueError(msg)
        if max_candidates_per_origin <= 0:
            msg = "max_candidates_per_origin must be positive"
            raise ValueError(msg)

        self._default_scheme = _ascii_lower(default_scheme)
        if not _SCHEME_RE.fullmatch(self._default_scheme):
            msg = "invalid default scheme"
            raise ValueError(msg)

        self._trusted_origins = frozenset(parse_origin(origin, default_scheme=self._default_scheme) for origin in trusted_origins)
        self._clock = clock if clock is not None else time.monotonic
        self._protocol_preference = tuple(dict.fromkeys(supported_protocols))
        if not self._protocol_preference:
            msg = "at least one supported protocol is required"
            raise ValueError(msg)
        self._supported_protocols = frozenset(self._protocol_preference)
        self._max_field_length = max_field_length
        self._max_candidates_per_origin = max_candidates_per_origin
        self._candidates: dict[Origin, dict[str, tuple[AlternativeServiceCandidate, ...]]] = {}

    @property
    def trusted_origins(self) -> frozenset[Origin]:
        """
        The canonical origins this cache may store candidates for.
        """
        return self._trusted_origins

    @property
    def supported_protocols(self) -> frozenset[str]:
        """
        The protocol identifiers the cache considers.
        """
        return self._supported_protocols

    def _prune_origin(self, origin: Origin, now: float) -> list[AlternativeServiceCandidate]:
        """
        Remove and return expired candidates for one origin.
        """
        protocols = self._candidates.get(origin)
        if protocols is None:
            return []

        removed: list[AlternativeServiceCandidate] = []
        for protocol_id, candidates in list(protocols.items()):
            live = [candidate for candidate in candidates if not candidate.is_expired(now)]
            removed.extend(candidate for candidate in candidates if candidate.is_expired(now))
            if live:
                protocols[protocol_id] = tuple(live)
            else:
                del protocols[protocol_id]

        if not protocols:
            del self._candidates[origin]
        return removed

    def purge_expired(self) -> tuple[AlternativeServiceCandidate, ...]:
        """
        Remove expired candidates for every origin and return them.
        """
        now = self._clock()
        removed: list[AlternativeServiceCandidate] = []
        for origin in list(self._candidates):
            removed.extend(self._prune_origin(origin, now))
        return tuple(removed)

    def _validate_offer(
        self,
        origin: Origin,
        *,
        tls_identity: TlsIdentity,
        source: AdvertisementSource,
    ) -> AlternativeServiceUpdate | None:
        """
        Reject an advertisement whose origin is not trusted and verified.
        """
        if origin not in self._trusted_origins:
            return AlternativeServiceUpdate(
                AdmissionStatus.UNTRUSTED_ORIGIN,
                origin=origin,
                source=source,
                detail="origin is not in the trusted origin set",
            )
        if not isinstance(tls_identity, TlsIdentity) or not tls_identity.authorizes(origin):
            return AlternativeServiceUpdate(
                AdmissionStatus.UNVERIFIED_CONNECTION,
                origin=origin,
                source=source,
                detail="TLS identity is not verified for this origin",
            )
        return None

    def _apply_field(
        self,
        origin: Origin,
        field_value: bytes | bytearray,
        *,
        source: AdvertisementSource,
        stream_id: int | None,
        allow_clear: bool,
    ) -> AlternativeServiceUpdate:
        """
        Apply an already-authorized field value atomically.
        """
        if not isinstance(field_value, (bytes, bytearray)) or not field_value:
            return AlternativeServiceUpdate(
                AdmissionStatus.MALFORMED,
                origin=origin,
                source=source,
                detail="empty or non-bytes field value",
            )
        if len(field_value) > self._max_field_length:
            return AlternativeServiceUpdate(
                AdmissionStatus.MALFORMED,
                origin=origin,
                source=source,
                detail="field value is too long",
            )

        raw_text = bytes(field_value).strip()
        if not raw_text:
            return AlternativeServiceUpdate(
                AdmissionStatus.MALFORMED,
                origin=origin,
                source=source,
                detail="empty field value",
            )
        try:
            text = raw_text.decode("ascii")
        except UnicodeDecodeError:
            return AlternativeServiceUpdate(
                AdmissionStatus.MALFORMED,
                origin=origin,
                source=source,
                detail="field value is not ASCII",
            )

        if text.lower() == "clear":
            if not allow_clear:
                # RFC 7838 restricts "clear" to the alt-svc header field.
                return AlternativeServiceUpdate(
                    AdmissionStatus.CLEAR_NOT_ALLOWED,
                    origin=origin,
                    source=source,
                    detail="the clear token is not permitted in an ALTSVC frame",
                )
            cleared = self._candidates.pop(origin, {})
            removed = tuple(candidate for candidates in cleared.values() for candidate in candidates)
            return AlternativeServiceUpdate(
                AdmissionStatus.CLEARED,
                origin=origin,
                source=source,
                removed=removed,
            )

        try:
            parsed = _parse_field_value(bytes(field_value), origin=origin)
        except ValueError as e:
            return AlternativeServiceUpdate(
                AdmissionStatus.MALFORMED,
                origin=origin,
                source=source,
                detail=str(e),
            )

        now = self._clock()
        self._prune_origin(origin, now)

        supported = [item for item in parsed if item.protocol_id in self._supported_protocols]
        if not supported:
            return AlternativeServiceUpdate(
                AdmissionStatus.UNSUPPORTED_PROTOCOL,
                origin=origin,
                source=source,
                detail="no supported protocol identifiers",
            )

        # Build the replacement on a copy.  No cache state changes until all
        # checks pass, so a rejected advertisement cannot erase or downgrade a
        # still-valid candidate.
        protocols: dict[str, list[AlternativeServiceCandidate]] = {
            protocol_id: list(candidates) for protocol_id, candidates in self._candidates.get(origin, {}).items()
        }
        added: list[AlternativeServiceCandidate] = []
        replaced: list[AlternativeServiceCandidate] = []

        grouped: dict[str, list[_ParsedAlternative]] = {}
        for alternative in supported:
            grouped.setdefault(alternative.protocol_id, []).append(alternative)

        for protocol_id, alternatives in grouped.items():
            replaced.extend(protocols.get(protocol_id, ()))
            fresh = [
                AlternativeServiceCandidate(
                    origin=origin,
                    protocol_id=protocol_id,
                    host=alternative.host,
                    port=alternative.port,
                    advertised_at=now,
                    expires_at=now + alternative.max_age,
                    source=source,
                    stream_id=stream_id,
                    persist=alternative.persist,
                )
                for alternative in alternatives
                if alternative.max_age > 0
            ]
            if fresh:
                protocols[protocol_id] = fresh
                added.extend(fresh)
            else:
                # ma=0 means the alternative is no longer available.
                protocols.pop(protocol_id, None)

        if sum(len(candidates) for candidates in protocols.values()) > self._max_candidates_per_origin:
            return AlternativeServiceUpdate(
                AdmissionStatus.TOO_MANY_CANDIDATES,
                origin=origin,
                source=source,
                detail="advertisement would exceed the per-origin candidate limit",
            )

        if protocols:
            self._candidates[origin] = {protocol_id: tuple(candidates) for protocol_id, candidates in protocols.items()}
        else:
            self._candidates.pop(origin, None)

        return AlternativeServiceUpdate(
            AdmissionStatus.ACCEPTED,
            origin=origin,
            source=source,
            added=tuple(added),
            removed=tuple(replaced),
        )

    def offer(self, event: AlternativeServiceAvailable, tls_identity: TlsIdentity) -> AlternativeServiceUpdate:
        """
        Offer an :class:`AlternativeServiceAvailable` event to the cache.

        The event's ``stream_id`` selects how its origin is interpreted.
        Stream 0 events must carry an explicit origin.  Stream events
        (``stream_id > 0``) must carry the bare authority h2 inferred from that
        stream and must not include a scheme.  In both cases the origin must be
        trusted and ``tls_identity`` must be verified for it.

        A stream-level advertisement is only a proposal for that stream's
        origin.  It never authorizes a connection to the advertised address.
        Rejected advertisements leave the cache unchanged.
        """
        if not isinstance(event, AlternativeServiceAvailable):
            return AlternativeServiceUpdate(
                AdmissionStatus.MALFORMED,
                detail="not an AlternativeServiceAvailable event",
            )
        stream_id = getattr(event, "stream_id", None)
        if not isinstance(stream_id, int) or stream_id < 0:
            return AlternativeServiceUpdate(
                AdmissionStatus.WRONG_STREAM,
                detail="invalid stream id",
            )
        if stream_id == 0:
            return self.offer_connection(event, tls_identity=tls_identity)
        return self.offer_stream(event, tls_identity=tls_identity)

    def _offer_event(
        self,
        event: AlternativeServiceAvailable,
        *,
        tls_identity: TlsIdentity,
        source: AdvertisementSource,
        stream_id: int | None,
    ) -> AlternativeServiceUpdate:
        origin_raw = _event_origin(event)
        if not isinstance(origin_raw, (bytes, bytearray, str)) or not origin_raw:
            status = AdmissionStatus.WRONG_STREAM if source is AdvertisementSource.STREAM else AdmissionStatus.UNTRUSTED_ORIGIN
            return AlternativeServiceUpdate(
                status,
                source=source,
                detail="event has no origin",
            )

        if source is AdvertisementSource.STREAM:
            has_scheme = b"://" in origin_raw if isinstance(origin_raw, (bytes, bytearray)) else "://" in origin_raw
            if has_scheme:
                return AlternativeServiceUpdate(
                    AdmissionStatus.WRONG_STREAM,
                    source=source,
                    detail="stream-level origin must be a bare authority",
                )

        try:
            origin = parse_origin(
                origin_raw,
                default_scheme=self._default_scheme,
            )
        except (TypeError, ValueError) as e:
            status = AdmissionStatus.MALFORMED if source is AdvertisementSource.CONNECTION else AdmissionStatus.UNTRUSTED_ORIGIN
            return AlternativeServiceUpdate(
                status,
                source=source,
                detail=f"invalid origin: {e}",
            )

        rejection = self._validate_offer(origin, tls_identity=tls_identity, source=source)
        if rejection is not None:
            return rejection

        field_value = _event_field(event)
        if not isinstance(field_value, (bytes, bytearray)):
            return AlternativeServiceUpdate(
                AdmissionStatus.MALFORMED,
                origin=origin,
                source=source,
                detail="event has no byte field value",
            )

        return self._apply_field(
            origin,
            field_value,
            source=source,
            stream_id=stream_id,
            allow_clear=False,
        )

    def offer_connection(self, event: AlternativeServiceAvailable, tls_identity: TlsIdentity) -> AlternativeServiceUpdate:
        """
        Offer a connection-level ALTSVC event (stream 0).

        Its origin must have come from the frame.  An event from a stream is
        rejected as :attr:`AdmissionStatus.WRONG_STREAM` without changing the
        cache.
        """
        if not isinstance(event, AlternativeServiceAvailable):
            return AlternativeServiceUpdate(AdmissionStatus.MALFORMED, detail="not an AlternativeServiceAvailable event")
        if getattr(event, "stream_id", 0) != 0:
            return AlternativeServiceUpdate(
                AdmissionStatus.WRONG_STREAM,
                source=AdvertisementSource.CONNECTION,
                detail="connection-level advertisement arrived on a stream",
            )
        return self._offer_event(
            event,
            tls_identity=tls_identity,
            source=AdvertisementSource.CONNECTION,
            stream_id=0,
        )

    def offer_stream(self, event: AlternativeServiceAvailable, tls_identity: TlsIdentity) -> AlternativeServiceUpdate:
        """
        Offer a stream-level ALTSVC event.

        Its origin must be the bare authority h2 inferred from the stream.  An
        event without a positive stream id, a stream-0 event, or an event
        claiming a scheme is rejected as :attr:`AdmissionStatus.WRONG_STREAM`
        without changing the cache.
        """
        if not isinstance(event, AlternativeServiceAvailable):
            return AlternativeServiceUpdate(AdmissionStatus.MALFORMED, detail="not an AlternativeServiceAvailable event")
        stream_id = getattr(event, "stream_id", 0)
        if not isinstance(stream_id, int) or stream_id <= 0:
            return AlternativeServiceUpdate(
                AdmissionStatus.WRONG_STREAM,
                source=AdvertisementSource.STREAM,
                detail="stream-level advertisement has no valid stream",
            )
        return self._offer_event(
            event,
            tls_identity=tls_identity,
            source=AdvertisementSource.STREAM,
            stream_id=stream_id,
        )

    def offer_events(
        self,
        events: Iterable[AlternativeServiceAvailable],
        tls_identity: TlsIdentity,
    ) -> tuple[AlternativeServiceUpdate, ...]:
        """
        Offer a sequence of ALTSVC events, preserving their order.

        Each event is evaluated independently against the current cache state,
        so a later rejected advertisement cannot undo an accepted one, and an
        earlier accepted advertisement cannot make a later untrusted one valid.
        """
        return tuple(self.offer(event, tls_identity) for event in events)

    def apply_header(
        self,
        origin: Origin | bytes | bytearray | str,
        field_value: bytes | bytearray,
        tls_identity: TlsIdentity,
    ) -> AlternativeServiceUpdate:
        """
        Apply an ``alt-svc`` response header value for ``origin``.

        The caller supplies the origin explicitly because a
        :class:`ResponseReceived <h2.events.ResponseReceived>` event does not
        carry the request authority.  Unlike an ALTSVC frame, a header may use
        the ``clear`` token.  The origin must be trusted and covered by the
        verified identity.
        """
        source = AdvertisementSource.HEADER
        try:
            parsed_origin = parse_origin(origin, default_scheme=self._default_scheme)
        except (TypeError, ValueError) as e:
            return AlternativeServiceUpdate(
                AdmissionStatus.UNTRUSTED_ORIGIN,
                source=source,
                detail=f"invalid origin: {e}",
            )

        rejection = self._validate_offer(parsed_origin, tls_identity=tls_identity, source=source)
        if rejection is not None:
            return rejection

        return self._apply_field(
            parsed_origin,
            field_value,
            source=source,
            stream_id=None,
            allow_clear=True,
        )

    def clear(self, origin: Origin | bytes | bytearray | str, tls_identity: TlsIdentity) -> AlternativeServiceUpdate:
        """
        Clear all candidates for a trusted, identity-verified origin.

        This is equivalent to applying ``alt-svc: clear`` and is provided for
        callers that handle the clear instruction outside header parsing.
        """
        return self.apply_header(origin, b"clear", tls_identity=tls_identity)

    def candidates(self, origin: Origin | bytes | bytearray | str) -> tuple[AlternativeServiceCandidate, ...]:
        """
        Return live, inert candidates for a trusted origin.

        Expired records are removed first.  The returned candidates are not
        usable targets; pass one to :meth:`authorize` after the TLS handshake.
        """
        try:
            parsed_origin = parse_origin(origin, default_scheme=self._default_scheme)
        except (TypeError, ValueError):
            return ()
        if parsed_origin not in self._trusted_origins:
            return ()

        self._prune_origin(parsed_origin, self._clock())
        protocols = self._candidates.get(parsed_origin)
        if not protocols:
            return ()
        return tuple(candidate for candidates in protocols.values() for candidate in candidates)

    def _is_live(self, candidate: AlternativeServiceCandidate, now: float) -> bool:
        """
        Whether ``candidate`` is still exactly one of the cache's live records.
        """
        protocols = self._candidates.get(candidate.origin)
        if not protocols:
            return False
        return candidate in protocols.get(candidate.protocol_id, ()) and not candidate.is_expired(now)

    def authorize(
        self,
        origin: Origin | bytes | bytearray | str,
        candidate: AlternativeServiceCandidate,
        tls_identity: TlsIdentity,
    ) -> bool:
        """
        Decide whether requests or credentials may be sent to ``candidate``.

        Call this only after connecting to the candidate and verifying its TLS
        handshake against the *original origin*.  ``tls_identity`` must be the
        verified identity from that connection.  The candidate must also still
        be a live, unexpired, trusted record.

        Returning ``True`` is the only authorization to send a request.  The
        cache itself never sends anything.
        """
        if not isinstance(candidate, AlternativeServiceCandidate):
            return False
        if not isinstance(tls_identity, TlsIdentity):
            return False
        try:
            parsed_origin = parse_origin(origin, default_scheme=self._default_scheme)
        except (TypeError, ValueError):
            return False
        if candidate.origin != parsed_origin:
            return False
        if parsed_origin not in self._trusted_origins:
            return False
        if not tls_identity.authorizes(parsed_origin):
            return False
        now = self._clock()
        self._prune_origin(parsed_origin, now)
        return self._is_live(candidate, now)

    def select(
        self,
        origin: Origin | bytes | bytearray | str,
        tls_identity: TlsIdentity,
    ) -> AlternativeServiceCandidate | None:
        """
        Choose one live candidate once the identity has been verified.

        Selection requires a verified :class:`TlsIdentity` for the original
        ``origin``.  The identity must be the one established on the connection
        to the candidate and verified against that origin.  Expired, untrusted,
        and wrong-stream records are never returned.

        This method performs no I/O.  Use :meth:`authorize` to re-check a
        specific candidate immediately before sending a request.
        """
        if not isinstance(tls_identity, TlsIdentity):
            return None
        try:
            parsed_origin = parse_origin(origin, default_scheme=self._default_scheme)
        except (TypeError, ValueError):
            return None
        if parsed_origin not in self._trusted_origins or not tls_identity.authorizes(parsed_origin):
            return None

        now = self._clock()
        self._prune_origin(parsed_origin, now)
        protocols = self._candidates.get(parsed_origin)
        if not protocols:
            return None
        for protocol_id in self._protocol_preference:
            candidates = protocols.get(protocol_id)
            if candidates:
                return candidates[0]
        return None
