"""Static parser for Twisted stream-server endpoint descriptions.

The parser deliberately re-implements only the *address-relevant* subset of
Twisted's endpoint grammar.  It never calls C{serverFromString}: the built-in
C{ssl} and C{tls} parsers read PEM private keys during parsing, and any
real endpoint object could be asked to listen.  Instead the description text
is reduced to L{ListenRange} data plus wrapper-layer metadata.

Wrapper layers (C{tls}, C{ssl}, C{haproxy}) carry certificate or proxy
options that cannot distinguish two otherwise identical listening ranges, so
they are recorded in L{ParsedEntry.layers} and ignored by the overlap logic.
"""

from __future__ import annotations

import ipaddress

from .extensions import DiscloserRegistry
from .model import (
    Family,
    HostBinding,
    HostKind,
    Issue,
    ListenRange,
    ParsedEntry,
    SourceCoordinate,
)
from .tokens import parse_arguments

_SCHEME_DEFAULT_FAMILY = {
    "tcp": Family.INET4,
    "ssl": Family.INET4,
    "tcp6": Family.INET6,
    "tls": Family.INET6,
}

_IP_WRAPPER_SCHEMES = ("tcp", "tcp6", "ssl", "tls")
_UNIX_SCHEME = "unix"
_WRAPPER_SCHEMES = ("haproxy", "tls", "ssl")

# Keyword options that never influence the listening address.  ssl/tls
# certificate options and haproxy/proxy tuning are intentionally excluded
# from address comparison.
_NON_ADDRESS_KEYWORDS = {
    "backlog",
    "privatekey",
    "certkey",
    "sslmethod",
    "extracertchain",
    "dhparameters",
    "path",
    "mode",
    "lockfile",
}


def _issue(entry: ParsedEntry, code: str, message: str) -> None:
    entry.issues.append(Issue(code, message, entry.coordinate))


def _note(entry: ParsedEntry, message: str) -> None:
    entry.notes.append(message)


def _parse_port(raw: str | None, entry: ParsedEntry) -> int | None:
    if raw is None:
        _issue(entry, "FATAL_BAD_PORT", "endpoint declares no port")
        return None
    try:
        port = int(raw)
    except (TypeError, ValueError):
        _issue(entry, "FATAL_BAD_PORT", f"port {raw!r} is not an integer")
        return None
    if not 0 <= port <= 65535:
        _issue(entry, "FATAL_BAD_PORT", f"port {port} is outside 0-65535")
        return None
    if port == 0:
        _note(
            entry,
            "port 0 lets the OS choose at listen time; the concrete port is "
            "not knowable before startup",
        )
    return port


def _classify_host(
    raw: str,
    default_family: Family,
    entry: ParsedEntry,
) -> HostBinding:
    if raw in ("", "0.0.0.0", "::"):
        if raw == "0.0.0.0":
            return HostBinding(HostKind.WILDCARD, Family.INET4, raw)
        if raw == "::":
            return HostBinding(HostKind.WILDCARD, Family.INET6, raw)
        return HostBinding(HostKind.WILDCARD, default_family, None)
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        # A hostname would require DNS and possibly the runtime naming layer
        # to resolve; do not guess, keep the uncertainty.
        _note(
            entry,
            f"interface {raw!r} is a hostname rather than an IP literal; its "
            "resolved addresses cannot be determined statically",
        )
        return HostBinding(HostKind.NAME, Family.UNKNOWN, raw)
    literal_family = Family.INET6 if address.version == 6 else Family.INET4
    if literal_family != default_family:
        _issue(
            entry,
            "FAMILY_MISMATCH",
            f"interface {raw!r} is {literal_family.value} but scheme "
            f"{entry.scheme!r} constructs an {default_family.value} endpoint; "
            "the declared scheme family is retained",
        )
    # The scheme-selected constructor decides the binding family in Twisted
    # (TCP4ServerEndpoint vs TCP6ServerEndpoint); the literal family mismatch
    # is reported but does not rewrite the range family.
    return HostBinding(HostKind.ADDRESS, default_family, raw)


def _unknown_keywords(entry: ParsedEntry, kwargs: dict[str, str]) -> None:
    for key in sorted(kwargs):
        if key.lower() not in _NON_ADDRESS_KEYWORDS and key.lower() != "interface":
            _issue(
                entry,
                "UNKNOWN_KWARG",
                f"keyword {key!r} is not used by the static address analysis",
            )


def _build_ip_range(
    scheme: str,
    args: list[str],
    kwargs: dict[str, str],
    entry: ParsedEntry,
) -> ListenRange | None:
    default_family = _SCHEME_DEFAULT_FAMILY[scheme]
    port_raw = kwargs.get("port")
    positional = list(args)
    if port_raw is None:
        if scheme == "tls" and positional:
            # tls: takes a PEM directory as its first positional argument,
            # then the port, mirroring _TLSServerEndpointParser.
            positional.pop(0)
        if not positional:
            _issue(entry, "FATAL_BAD_PORT", "endpoint declares no port")
            return None
        port_raw = positional[0]
    port = _parse_port(port_raw, entry)
    if port is None:
        return None
    interface = kwargs.get("interface")
    if interface is None:
        # Match Twisted constructor defaults exactly.
        interface = "::" if default_family is Family.INET6 else ""
    host = _classify_host(interface, default_family, entry)
    certain = port != 0 and host.kind is not HostKind.NAME
    reason = None
    if port == 0:
        reason = "ephemeral port chosen at runtime"
    elif host.kind is HostKind.NAME:
        reason = "hostname resolution happens at runtime"
    return ListenRange(
        family=host.family,
        host=host,
        port=port,
        certain=certain,
        reason=reason,
    )


def _build_unix_range(
    args: list[str],
    kwargs: dict[str, str],
    entry: ParsedEntry,
) -> ListenRange | None:
    path = kwargs.get("address")
    if path is None:
        path = args[0] if args else None
    if not path:
        _issue(entry, "FATAL_BAD_PATH", "unix endpoint declares no socket path")
        return None
    return ListenRange(family=Family.UNIX, path=path, certain=True)


def _unknown_range(
    scheme: str,
    args: list[str],
    kwargs: dict[str, str],
    entry: ParsedEntry,
    registry: DiscloserRegistry,
) -> ListenRange:
    disclosure = registry.disclose(scheme, args, kwargs)
    if disclosure is not None:
        rng = disclosure.as_range()
        _note(
            entry,
            f"range voluntarily disclosed by extension for scheme {scheme!r}",
        )
        return rng
    _issue(
        entry,
        "UNKNOWN_SCHEME",
        f"scheme {scheme!r} has no static address rule and no discloser is "
        "registered; its addresses can only be reported at runtime",
    )
    return ListenRange(
        family=Family.UNKNOWN,
        certain=False,
        reason=f"runtime-only scheme {scheme!r}",
    )


def parse_endpoint(
    description: str,
    coordinate: SourceCoordinate,
    registry: DiscloserRegistry | None = None,
) -> ParsedEntry:
    """Parse one endpoint description into a L{ParsedEntry}.

    The function is total: malformed descriptions produce a L{ParsedEntry}
    carrying a fatal L{Issue} rather than raising, so a whole manifest can be
    reviewed and every error keeps its source coordinate.
    """

    registry = registry if registry is not None else DiscloserRegistry()
    entry = ParsedEntry(description=description, coordinate=coordinate)
    try:
        args, kwargs = parse_arguments(description)
    except ValueError as exc:
        _issue(entry, "FATAL_GRAMMAR", str(exc))
        return entry

    if not args or not args[0]:
        _issue(entry, "FATAL_GRAMMAR", "endpoint description has no scheme prefix")
        return entry

    scheme = args[0].lower()
    entry.scheme = scheme
    remaining_args = list(args[1:])
    layers: list[str] = []

    # Unwrap nested haproxy layers; each wrapper shares the exact address of
    # whatever endpoint it wraps and adds no address information of its own.
    current_scheme = scheme
    while current_scheme == "haproxy":
        layers.append("haproxy")
        if not remaining_args:
            _issue(
                entry,
                "FATAL_GRAMMAR",
                "haproxy wrapper has no wrapped endpoint description",
            )
            return entry
        current_scheme = remaining_args.pop(0).lower()

    if current_scheme in _IP_WRAPPER_SCHEMES:
        entry.scheme = current_scheme
        if current_scheme in ("ssl", "tls"):
            layers.append(current_scheme)
        rng = _build_ip_range(current_scheme, remaining_args, kwargs, entry)
        if rng is not None:
            entry.ranges.append(rng)
        _unknown_keywords(entry, kwargs)
    elif current_scheme == _UNIX_SCHEME:
        entry.scheme = current_scheme
        rng = _build_unix_range(remaining_args, kwargs, entry)
        if rng is not None:
            entry.ranges.append(rng)
        _unknown_keywords(entry, kwargs)
    else:
        entry.scheme = current_scheme
        entry.ranges.append(
            _unknown_range(current_scheme, remaining_args, kwargs, entry, registry)
        )

    entry.layers = tuple(layers)
    return entry
