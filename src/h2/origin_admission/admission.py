"""
Per-stream origin admission logic.

The adapter in this module turns a decoded HTTP/2 request header block into an
:class:`Origin` (RFC 6454: ``scheme``, ``host`` and ``port``) and then checks
two independent conditions before the request may be dispatched:

* ``certificate name coverage`` -- the trusted TLS connection information
  supplied by the caller proves that the peer is entitled to speak for the
  requested host; and
* ``caller access`` -- the application allow set supplied by the caller
  contains that origin for the authenticated caller.

Every public type is immutable and every decision is recorded, so any request
that is dispatched can be traced back to the exact admission result for its
own stream. A rejection only marks that single stream and never alters the
identity of any other stream multiplexed on the same connection.
"""
from __future__ import annotations

import enum
import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeAlias

if TYPE_CHECKING:
    from h2.events import RequestReceived, TrailersReceived

Header: TypeAlias = tuple[bytes, bytes]
HeaderBlock: TypeAlias = Sequence[Header]

_SCHEME_RE = re.compile(rb"^[a-z][a-z0-9+.\-]*$")
_DNS_LABEL_RE = re.compile(rb"^[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?$")
_TRAILER_FORBIDDEN_HEADERS = frozenset((b":method", b":scheme", b":path", b":authority", b"host"))


class RejectionReason(enum.Enum):
    """Why an origin could not be admitted on a stream."""

    MALFORMED_AUTHORITY = "malformed_authority"
    """The ``:authority`` (or ``Host``) value is not a syntactically valid
    host or ``host:port`` authority."""

    MISSING_PSEUDO_HEADER = "missing_pseudo_header"
    """One of the required request pseudo-headers (``:scheme``,
    ``:path`` or an authority) is absent or duplicated."""

    INVALID_SCHEME = "invalid_scheme"
    """The ``:scheme`` value is not a valid lowercase RFC 3986 scheme."""

    HOST_CONFLICT = "host_conflict"
    """Both ``:authority`` and ``Host`` are present and they disagree."""

    CERTIFICATE_NAME_MISMATCH = "certificate_name_mismatch"
    """The trusted certificate does not cover the requested host."""

    ORIGIN_NOT_ALLOWED = "origin_not_allowed"
    """The certificate covers the host, but the caller is not allowed to
    access this origin (it is absent from the application allow set)."""

    TRAILER_PSEUDO_HEADER = "trailer_pseudo_header"
    """The trailer block contains a pseudo-header or a ``Host`` header that
    could otherwise attempt to rewrite the already fixed origin."""

    UNKNOWN_STREAM = "unknown_stream"
    """Trailers arrived for a stream that never completed admission."""


class AdmissionError(ValueError):
    """
    Raised when the adapter API is used incorrectly.

    Ordinary request rejections are returned as :class:`AdmissionDecision`
    objects rather than raised, so that a bad stream can never tear down the
    shared connection. This exception is reserved for programming errors such
    as admitting the same stream id twice.
    """

    @classmethod
    def duplicate_stream(cls, stream_id: int) -> AdmissionError:
        """Build the error for admitting a single stream more than once."""
        message = f"Stream {stream_id} was already admitted; each request stream may be admitted exactly once."
        return cls(message)


def _as_bytes(value: bytes | str) -> bytes:
    if isinstance(value, str):
        return value.encode("ascii")
    return bytes(value)


def _normalize_headers(headers: HeaderBlock | Iterable[tuple[bytes | str, bytes | str]]) -> list[Header]:
    return [(_as_bytes(name), _as_bytes(value)) for name, value in headers]


def _headers_of(event: RequestReceived | TrailersReceived) -> list[Header]:
    return _normalize_headers(event.headers)


@dataclass(frozen=True, slots=True)
class Origin:
    """
    An RFC 6454 origin, identified by scheme, host and port.

    Two origins compare equal exactly when their schemes, hosts and ports
    match. Default ports are normalized, so ``https://example.com`` and
    ``https://example.com:443`` are the same origin.
    """

    scheme: str
    host: str
    port: int

    @property
    def is_ip_literal(self) -> bool:
        """Whether the host is an IP literal rather than a DNS name."""
        return self.host.startswith("[")

    def __str__(self) -> str:
        host = self.host
        return f"{self.scheme}://{host}:{self.port}"


@dataclass(frozen=True, slots=True)
class TLSCertificateInfo:
    """
    Trusted TLS connection information supplied by the caller.

    The caller is responsible for the full TLS handshake and chain
    verification. Only the names extracted from the verified leaf
    certificate are passed in, split into DNS names (including any wildcard
    DNS names such as ``*.example.com``) and IP address literals.
    """

    dns_names: frozenset[str] = field(default_factory=frozenset)
    ip_addresses: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def create(
        cls,
        dns_names: Iterable[str] = (),
        ip_addresses: Iterable[str] = (),
    ) -> TLSCertificateInfo:
        """Build certificate information from iterables of verified names."""
        return cls(
            dns_names=frozenset(dns_names),
            ip_addresses=frozenset(ip_addresses),
        )


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """The admission result for a single request stream."""

    stream_id: int
    allowed: bool
    origin: Origin | None
    reason: RejectionReason | None
    detail: str
    status_code: int | None
    certificate_covered: bool

    @property
    def rejection_reason(self) -> RejectionReason | None:
        """The rejection reason, or ``None`` when the request is allowed."""
        return self.reason


@dataclass(frozen=True, slots=True)
class TrailerDecision:
    """The result of inspecting a trailer block on an admitted stream."""

    stream_id: int
    allowed: bool
    reason: RejectionReason | None
    detail: str
    status_code: int | None
    origin: Origin | None


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """
    One recorded decision, used to trace business dispatch back to
    admission.
    """

    stream_id: int
    allowed: bool
    origin: Origin | None
    reason: RejectionReason | None
    detail: str
    status_code: int | None
    certificate_covered: bool
    phase: str


def _reject(
    stream_id: int,
    reason: RejectionReason,
    detail: str,
    status_code: int,
    *,
    origin: Origin | None = None,
    certificate_covered: bool = False,
) -> AdmissionDecision:
    return AdmissionDecision(
        stream_id=stream_id,
        allowed=False,
        origin=origin,
        reason=reason,
        detail=detail,
        status_code=status_code,
        certificate_covered=certificate_covered,
    )


def _parse_port(port_text: bytes) -> int | None:
    if not port_text:
        return None
    if not port_text.isascii() or not port_text.isdigit():
        return 0
    port = int(port_text)
    return port if 0 < port < 65536 else 0


def _split_ip_literal_authority(authority: bytes) -> tuple[bytes, int | None] | None:
    closing = authority.find(b"]")
    if closing == -1:
        return None
    literal = authority[1:closing]
    remainder = authority[closing + 1 :]
    if remainder and (not remainder.startswith(b":") or remainder.count(b":") != 1):
        return None
    port = _parse_port(remainder[1:] if remainder else b"")
    if port == 0:
        return None
    try:
        ipaddress.IPv6Address(literal.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None
    return b"[" + literal + b"]", port


def _split_regular_authority(authority: bytes) -> tuple[bytes, int | None] | None:
    if authority.count(b":") > 1 or b"[" in authority or b"]" in authority:
        return None
    host, separator, port_text = authority.partition(b":")
    port = _parse_port(port_text) if separator else None
    if port == 0:
        return None
    return host, port


def _split_authority(authority: bytes) -> tuple[bytes, int | None] | None:
    """Split an authority value into a raw host and an optional port."""
    if not authority or authority.startswith(b":") or authority.endswith(b":"):
        return None
    if authority.startswith(b"["):
        return _split_ip_literal_authority(authority)
    return _split_regular_authority(authority)


def _validate_dns_host(host: bytes) -> bool:
    normalized = host[:-1] if host.endswith(b".") else host
    if not normalized or len(normalized) > 253:
        return False
    labels = normalized.split(b".")
    return all(_DNS_LABEL_RE.fullmatch(label) and len(label) <= 63 for label in labels)


def _build_origin(scheme: bytes, authority: bytes) -> tuple[Origin | None, RejectionReason | None]:
    parsed = _split_authority(authority)
    if parsed is None:
        return None, RejectionReason.MALFORMED_AUTHORITY
    raw_host, port = parsed
    if raw_host.startswith(b"["):
        try:
            host = "[" + ipaddress.IPv6Address(raw_host[1:-1].decode("ascii")).compressed.lower() + "]"
        except (ValueError, UnicodeDecodeError):
            return None, RejectionReason.MALFORMED_AUTHORITY
    else:
        lowercase_host = raw_host.lower()
        if not _validate_dns_host(lowercase_host):
            return None, RejectionReason.MALFORMED_AUTHORITY
        host = lowercase_host.decode("ascii")
    if port is None:
        if scheme == b"https":
            port = 443
        elif scheme == b"http":
            port = 80
        else:
            return None, RejectionReason.MALFORMED_AUTHORITY
    return Origin(scheme=scheme.decode("ascii"), host=host, port=port), None


def _extract_request(headers: list[Header]) -> tuple[bytes | None, bytes | None, bytes | None, bytes | None, bool]:
    scheme: bytes | None = None
    path: bytes | None = None
    authority: bytes | None = None
    host: bytes | None = None
    duplicate = False
    for name, value in headers:
        if name == b":scheme":
            if scheme is not None:
                duplicate = True
            scheme = value
        elif name == b":path":
            if path is not None:
                duplicate = True
            path = value
        elif name == b":authority":
            if authority is not None:
                duplicate = True
            authority = value
        elif name == b"host":
            if host is not None:
                duplicate = True
            host = value
    return scheme, path, authority, host, duplicate


def _ip_is_covered(host: str, certificate: TLSCertificateInfo) -> bool:
    try:
        normalized = ipaddress.ip_address(host)
    except ValueError:
        return False
    return str(normalized) in certificate.ip_addresses


def _dns_name_matches(host: str, presented: str) -> bool:
    candidate = presented.lower().rstrip(".")
    if not candidate.startswith("*."):
        return candidate == host
    suffix = candidate[1:]
    if not host.endswith(suffix):
        return False
    prefix = host[: -len(suffix)]
    return bool(prefix) and "." not in prefix and prefix != "*"


def _certificate_covers(origin: Origin, certificate: TLSCertificateInfo | None) -> bool:
    if certificate is None:
        return False
    host = origin.host[1:-1] if origin.is_ip_literal else origin.host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return _ip_is_covered(host, certificate)
    # A trailing dot marks an absolute DNS name; the certificate SANs omit it.
    host = host[:-1] if host.endswith(".") else host
    return any(_dns_name_matches(host, presented) for presented in certificate.dns_names)


class OriginAdmissionAdapter:
    """
    Admit HTTP/2 request streams to origins on a shared connection.

    One adapter instance is bound to one accepted HTTP/2 connection. The
    trusted :class:`TLSCertificateInfo` describes that single TLS connection,
    while ``allowed_origins`` is the application allow set for the caller
    authenticated on this connection. Both are supplied by the caller and are
    never inferred from the request traffic itself.

    Like the underlying h2 connection, an adapter is not thread-safe; it is
    expected to be driven from the single task that owns that connection.
    Stream state is kept strictly per stream id, so rejecting one stream only
    writes that stream's entry and never mutates any other stream's identity.
    """

    def __init__(
        self,
        tls_certificate: TLSCertificateInfo | None,
        allowed_origins: Iterable[Origin],
    ) -> None:
        self._certificate = tls_certificate
        self._allowed_origins = frozenset(allowed_origins)
        self._decisions: dict[int, AdmissionDecision] = {}
        self._audit_trail: list[AuditEntry] = []

    @property
    def allowed_origins(self) -> frozenset[Origin]:
        """The application allow set this adapter enforces."""
        return self._allowed_origins

    @property
    def audit_trail(self) -> tuple[AuditEntry, ...]:
        """All decisions in the order they were made."""
        return tuple(self._audit_trail)

    def admitted_streams(self) -> tuple[int, ...]:
        """Stream ids whose requests were admitted and may be dispatched."""
        return tuple(stream_id for stream_id, decision in self._decisions.items() if decision.allowed)

    def origin_for_stream(self, stream_id: int) -> Origin | None:
        """The fixed origin of an admitted stream, if it was allowed."""
        decision = self._decisions.get(stream_id)
        if decision is None or not decision.allowed:
            return None
        return decision.origin

    def decision_for_stream(self, stream_id: int) -> AdmissionDecision | None:
        """The full admission decision recorded for a stream."""
        return self._decisions.get(stream_id)

    def admit_request_headers(
        self,
        stream_id: int,
        headers: HeaderBlock | Iterable[tuple[bytes | str, bytes | str]],
    ) -> AdmissionDecision:
        """
        Admit a request header block received on ``stream_id``.

        A decision is always returned. Rejected streams are recorded but never
        dispatched, and their rejection does not touch any other stream.
        """
        if stream_id in self._decisions:
            raise AdmissionError.duplicate_stream(stream_id)
        decision = self._evaluate(stream_id, _normalize_headers(headers))
        self._decisions[stream_id] = decision
        self._audit_trail.append(
            AuditEntry(
                stream_id=stream_id,
                allowed=decision.allowed,
                origin=decision.origin,
                reason=decision.reason,
                detail=decision.detail,
                status_code=decision.status_code,
                certificate_covered=decision.certificate_covered,
                phase="request",
            ),
        )
        return decision

    def admit_request_event(self, event: RequestReceived) -> AdmissionDecision:
        """Admit the header block carried by a ``h2`` ``RequestReceived`` event."""
        return self.admit_request_headers(event.stream_id, _headers_of(event))

    def inspect_trailers(
        self,
        stream_id: int,
        headers: HeaderBlock | Iterable[tuple[bytes | str, bytes | str]],
    ) -> TrailerDecision:
        """
        Inspect a trailer block and reject any attempt to change identity.

        The origin of a stream is fixed when its request headers are admitted.
        A trailer block containing a pseudo-header or ``Host`` field is
        rejected; ordinary trailers leave the recorded origin untouched.
        """
        normalized = _normalize_headers(headers)
        decision = self._decisions.get(stream_id)
        if decision is None:
            trailer_decision = TrailerDecision(
                stream_id=stream_id,
                allowed=False,
                reason=RejectionReason.UNKNOWN_STREAM,
                detail=f"Stream {stream_id} has no admission result; trailers cannot establish an origin.",
                status_code=400,
                origin=None,
            )
        else:
            forbidden = [name for name, _ in normalized if name in _TRAILER_FORBIDDEN_HEADERS]
            if forbidden:
                trailer_decision = TrailerDecision(
                    stream_id=stream_id,
                    allowed=False,
                    reason=RejectionReason.TRAILER_PSEUDO_HEADER,
                    detail=(
                        f"Trailers must not carry {sorted(name.decode('ascii') for name in forbidden)!r}; "
                        "the origin is fixed by the request headers."
                    ),
                    status_code=400,
                    origin=decision.origin,
                )
            else:
                trailer_decision = TrailerDecision(
                    stream_id=stream_id,
                    allowed=True,
                    reason=None,
                    detail="Trailers accepted; the fixed origin is unchanged.",
                    status_code=None,
                    origin=decision.origin,
                )
        self._audit_trail.append(
            AuditEntry(
                stream_id=stream_id,
                allowed=trailer_decision.allowed,
                origin=trailer_decision.origin,
                reason=trailer_decision.reason,
                detail=trailer_decision.detail,
                status_code=trailer_decision.status_code,
                certificate_covered=decision.certificate_covered if decision is not None else False,
                phase="trailer",
            ),
        )
        return trailer_decision

    def inspect_trailer_event(self, event: TrailersReceived) -> TrailerDecision:
        """Inspect the header block carried by a ``h2`` ``TrailersReceived`` event."""
        return self.inspect_trailers(event.stream_id, _headers_of(event))

    def _resolve_authority(
        self,
        stream_id: int,
        scheme: bytes,
        authority_value: bytes | None,
        host_value: bytes | None,
    ) -> tuple[Origin | None, AdmissionDecision | None]:
        effective_authority = authority_value if authority_value is not None else host_value
        if effective_authority is None:
            missing = _reject(
                stream_id,
                RejectionReason.MISSING_PSEUDO_HEADER,
                "Request header block has neither :authority nor Host.",
                400,
            )
            return None, missing
        if authority_value is not None and host_value is not None and authority_value != host_value:
            conflict = _reject(
                stream_id,
                RejectionReason.HOST_CONFLICT,
                f":authority {authority_value!r} conflicts with Host {host_value!r}.",
                400,
            )
            return None, conflict
        origin, build_error = _build_origin(scheme, effective_authority)
        if origin is None:
            malformed = _reject(
                stream_id,
                build_error or RejectionReason.MALFORMED_AUTHORITY,
                f"Authority {effective_authority!r} is not a valid host or host:port value.",
                400,
            )
            return None, malformed
        return origin, None

    def _check_access(
        self,
        stream_id: int,
        scheme: bytes,
        origin: Origin,
    ) -> AdmissionDecision | None:
        # Certificate name coverage is a property of the trusted TLS
        # connection and only applies to TLS-protected origins. The caller's
        # application allow set is always checked independently afterwards.
        certificate_covered = False
        if scheme == b"https":
            certificate_covered = _certificate_covers(origin, self._certificate)
            if not certificate_covered:
                return _reject(
                    stream_id,
                    RejectionReason.CERTIFICATE_NAME_MISMATCH,
                    f"The trusted certificate does not cover host {origin.host}.",
                    421,
                    origin=origin,
                )
        if origin not in self._allowed_origins:
            return _reject(
                stream_id,
                RejectionReason.ORIGIN_NOT_ALLOWED,
                f"Origin {origin} is not in the caller allow set.",
                403,
                origin=origin,
                certificate_covered=certificate_covered,
            )
        return None

    def _evaluate(self, stream_id: int, headers: list[Header]) -> AdmissionDecision:
        scheme, path, authority_value, host_value, duplicate = _extract_request(headers)
        if scheme is None or path is None or (authority_value is None and host_value is None) or duplicate:
            return _reject(
                stream_id,
                RejectionReason.MISSING_PSEUDO_HEADER,
                "Request must each contain exactly one :scheme and :path and one :authority or Host header.",
                400,
            )
        if not scheme.isascii() or _SCHEME_RE.fullmatch(scheme) is None:
            return _reject(
                stream_id,
                RejectionReason.INVALID_SCHEME,
                f"Invalid :scheme value {scheme!r}; expected a lowercase RFC 3986 scheme token.",
                400,
            )
        origin, authority_decision = self._resolve_authority(stream_id, scheme, authority_value, host_value)
        if origin is None:
            assert authority_decision is not None
            return authority_decision
        access_decision = self._check_access(stream_id, scheme, origin)
        if access_decision is not None:
            return access_decision
        return AdmissionDecision(
            stream_id=stream_id,
            allowed=True,
            origin=origin,
            reason=None,
            detail=f"Origin {origin} is allowed for this caller.",
            status_code=None,
            certificate_covered=scheme == b"https",
        )
