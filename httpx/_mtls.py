"""
Restricted, embeddable client-certificate (mTLS) identity selection.

This module lets a backend application expose *named, pre-registered* mTLS
identities to its callers, rather than accepting arbitrary certificate file
paths or mutating a shared ``SSLContext`` per request.

A request names the identity it is explicitly authorized to use through the
:func:`client_identity` request extension. The transport then:

1. Resolves that name against the registry (unknown names fail before any
   connection is made).
2. Confirms the identity's allow-list permits the request *origin*. This is
   re-checked for every hop, so redirects and authentication follow-ups cannot
   smuggle an identity somewhere it was never authorized.
3. Routes the request through that identity's own connection pool, so each
   identity keeps its own TLS connections and they are never shared across
   identities.

The mTLS identity travels in a request *extension*, never in an HTTP header,
and is entirely independent of HTTP-level ``Authorization`` credentials.
"""

from __future__ import annotations

import os
import tempfile
import typing
from types import TracebackType

if typing.TYPE_CHECKING:
    import ssl  # pragma: no cover

    import httpx  # pragma: no cover

from ._config import DEFAULT_LIMITS, Limits
from ._exceptions import (
    ClientIdentityNotRegistered,
    ClientIdentityNotRequested,
    ClientIdentityOriginDenied,
)
from ._models import Request, Response
from ._urls import URL
from ._transports.base import AsyncBaseTransport, BaseTransport
from ._transports.default import AsyncHTTPTransport, HTTPTransport

__all__ = [
    "MTLS_CLIENT_IDENTITY_EXTENSION",
    "AsyncClientIdentityTransport",
    "ClientIdentity",
    "ClientIdentityTransport",
    "client_identity",
]

#: Request extension key carrying the name of the authorized mTLS identity.
MTLS_CLIENT_IDENTITY_EXTENSION = "mtls_client_identity"

Origin = typing.Tuple[str, str, int | None]

T = typing.TypeVar("T", bound="ClientIdentityTransport")
A = typing.TypeVar("A", bound="AsyncClientIdentityTransport")

# A factory builds the per-identity transport. It receives the identity and
# the SSL context carrying that identity's client certificate chain.
SyncTransportFactory = typing.Callable[
    ["ClientIdentity", "ssl.SSLContext"], BaseTransport
]
AsyncTransportFactory = typing.Callable[
    ["ClientIdentity", "ssl.SSLContext"], AsyncBaseTransport
]


def client_identity(name: str) -> typing.Dict[str, str]:
    """
    Build the request extensions that authorize a request to act as a
    specific, pre-registered mTLS identity.

    Pass the result as the request's ``extensions=`` argument (or merge it
    into an existing extensions mapping). The value is a *name* registered
    with the transport, never a file path or raw key material.

        >>> client.get(url, extensions=httpx.client_identity("partner-a"))
    """
    if not isinstance(name, str) or not name:
        raise ValueError("An mTLS client identity name must be a non-empty string.")
    return {MTLS_CLIENT_IDENTITY_EXTENSION: name}


def _origin_key(url: URL) -> Origin:
    return (url.scheme, url.host, url.port)


def _normalize_origins(origins: typing.Iterable[str | URL]) -> typing.FrozenSet[Origin]:
    normalized: set[Origin] = set()
    for origin in origins:
        url = URL(origin)
        if not url.scheme or not url.host:
            raise ValueError(
                f"Identity origin {origin!r} must include a scheme and host, "
                "e.g. 'https://api.example.com'."
            )
        normalized.add(_origin_key(url))
    if not normalized:
        raise ValueError("A client identity must permit at least one origin.")
    return frozenset(normalized)


def _load_ssl_context_from_pem(
    cert_pem: bytes,
    key_pem: bytes,
    password: bytes | None,
    verify: ssl.SSLContext | str | bool,
    trust_env: bool,
) -> ssl.SSLContext:
    # `SSLContext.load_cert_chain` only reads material from the filesystem,
    # so stage the in-memory PEM blobs in private temp files and remove them
    # as soon as the chain is loaded. This keeps certificate material under
    # the application's control rather than asking callers for file paths.
    from ._config import create_ssl_context

    context = create_ssl_context(verify=verify, trust_env=trust_env)
    cert_fd, cert_path = tempfile.mkstemp(prefix="httpx-mtls-cert-", suffix=".pem")
    try:
        key_fd, key_path = tempfile.mkstemp(prefix="httpx-mtls-key-", suffix=".pem")
        try:
            with os.fdopen(cert_fd, "wb") as cert_file:
                cert_file.write(cert_pem)
            with os.fdopen(key_fd, "wb") as key_file:
                key_file.write(key_pem)
            context.load_cert_chain(
                certfile=cert_path, keyfile=key_path, password=password
            )
        finally:
            os.unlink(key_path)
    finally:
        os.unlink(cert_path)
    return context


class ClientIdentity:
    """
    A pre-registered mTLS identity.

    The certificate material is supplied once, at registration time, either as
    a ready ``ssl.SSLContext`` or as in-memory PEM blobs. Each identity also
    carries the explicit set of request *origins* it is allowed to reach.

    Instances are opaque to callers: they select an identity by name through
    :func:`client_identity`, they cannot point a request at an arbitrary file.
    """

    def __init__(
        self,
        name: str,
        *,
        origins: typing.Iterable[str | URL],
        ssl_context: ssl.SSLContext | None = None,
        cert_pem: bytes | None = None,
        key_pem: bytes | None = None,
        key_password: bytes | None = None,
        verify: ssl.SSLContext | str | bool = True,
        trust_env: bool = True,
    ) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError("A client identity name must be a non-empty string.")

        has_pem = cert_pem is not None or key_pem is not None
        if ssl_context is None and not has_pem:
            raise ValueError(
                f"Identity {name!r} requires either an 'ssl_context' or "
                "'cert_pem'/'key_pem' material."
            )
        if ssl_context is not None and has_pem:
            raise ValueError(
                f"Identity {name!r} cannot be given both 'ssl_context' and "
                "PEM certificate material."
            )
        if has_pem and (cert_pem is None or key_pem is None):
            raise ValueError(
                f"Identity {name!r} requires both 'cert_pem' and 'key_pem'."
            )

        self.name = name
        self.allowed_origins = _normalize_origins(origins)
        if ssl_context is not None:
            self.ssl_context = ssl_context
        else:
            assert cert_pem is not None and key_pem is not None
            self.ssl_context = _load_ssl_context_from_pem(
                cert_pem=cert_pem,
                key_pem=key_pem,
                password=key_password,
                verify=verify,
                trust_env=trust_env,
            )

    def permits(self, url: URL) -> bool:
        return _origin_key(url) in self.allowed_origins

    def __repr__(self) -> str:
        origins = ", ".join(
            f"{scheme}://{host}" + (f":{port}" if port is not None else "")
            for scheme, host, port in sorted(self.allowed_origins)
        )
        return f"ClientIdentity(name={self.name!r}, origins=[{origins}])"


class _BaseClientIdentityTransport:
    """
    Shared authorization logic for the sync and async identity transports.

    All checks happen before a per-identity transport (and therefore a
    connection) is touched, and every redirect/auth hop re-enters this path
    because the high-level client calls ``handle_request`` /
    ``handle_async_request`` once per hop.
    """

    def __init__(
        self,
        identities: typing.Iterable[ClientIdentity],
        *,
        limits: Limits = DEFAULT_LIMITS,
        http1: bool = True,
        http2: bool = False,
    ) -> None:
        self.limits = limits
        self.http1 = http1
        self.http2 = http2
        self._identities: typing.Dict[str, ClientIdentity] = {}
        for identity in identities:
            if identity.name in self._identities:
                raise ValueError(
                    f"A client identity named {identity.name!r} is already registered."
                )
            self._identities[identity.name] = identity
        if not self._identities:
            raise ValueError(
                "An identity transport must be given at least one registered identity."
            )

    def _authorize(self, request: Request) -> ClientIdentity:
        name = request.extensions.get(MTLS_CLIENT_IDENTITY_EXTENSION)
        if name is None:
            raise ClientIdentityNotRequested(
                "Request did not specify an authorized mTLS client identity. "
                "Pass one via the 'httpx.client_identity(...)' request extension."
            )
        identity = self._identities.get(name)
        if identity is None:
            raise ClientIdentityNotRegistered(
                f"No mTLS client identity named {name!r} is registered."
            )
        if not identity.permits(request.url):
            raise ClientIdentityOriginDenied(
                f"Identity {name!r} is not authorized for origin "
                f"{request.url.scheme}://{request.url.netloc.decode('ascii')}."
            )
        return identity


class ClientIdentityTransport(_BaseClientIdentityTransport, BaseTransport):
    """
    A synchronous transport that sends each request using the explicitly
    authorized, pre-registered mTLS identity.

    Each identity owns a dedicated :class:`HTTPTransport` (and therefore its
    own connection pool); connections established under one identity are
    never reused for another.
    """

    def __init__(
        self,
        identities: typing.Iterable[ClientIdentity],
        *,
        limits: Limits = DEFAULT_LIMITS,
        http1: bool = True,
        http2: bool = False,
        transport_factory: SyncTransportFactory | None = None,
    ) -> None:
        super().__init__(identities, limits=limits, http1=http1, http2=http2)
        self._transport_factory = transport_factory or self._default_factory
        self._pools: typing.Dict[str, BaseTransport] = {}

    def _default_factory(
        self, identity: ClientIdentity, ssl_context: ssl.SSLContext
    ) -> BaseTransport:
        return HTTPTransport(
            verify=ssl_context,
            limits=self.limits,
            http1=self.http1,
            http2=self.http2,
        )

    def _pool_for(self, identity: ClientIdentity) -> BaseTransport:
        pool = self._pools.get(identity.name)
        if pool is None:
            # Lazily created on first *authorized* request, so an unauthorized
            # request never triggers a connection pool or handshake.
            pool = self._transport_factory(identity, identity.ssl_context)
            self._pools[identity.name] = pool
        return pool

    def handle_request(self, request: Request) -> Response:
        identity = self._authorize(request)
        transport = self._pool_for(identity)
        return transport.handle_request(request)

    def close(self) -> None:
        # The identity transport owns every per-identity pool it created, so
        # it is responsible for closing them all exactly once.
        for transport in self._pools.values():
            transport.close()
        self._pools.clear()

    def __enter__(self: T) -> T:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        self.close()


class AsyncClientIdentityTransport(_BaseClientIdentityTransport, AsyncBaseTransport):
    """
    An asynchronous transport that sends each request using the explicitly
    authorized, pre-registered mTLS identity.

    See :class:`ClientIdentityTransport`; this is the ``asyncio``/``trio``
    counterpart with a dedicated connection pool per identity.
    """

    def __init__(
        self,
        identities: typing.Iterable[ClientIdentity],
        *,
        limits: Limits = DEFAULT_LIMITS,
        http1: bool = True,
        http2: bool = False,
        transport_factory: AsyncTransportFactory | None = None,
    ) -> None:
        super().__init__(identities, limits=limits, http1=http1, http2=http2)
        self._transport_factory = transport_factory or self._default_factory
        self._pools: typing.Dict[str, AsyncBaseTransport] = {}

    def _default_factory(
        self, identity: ClientIdentity, ssl_context: ssl.SSLContext
    ) -> AsyncBaseTransport:
        return AsyncHTTPTransport(
            verify=ssl_context,
            limits=self.limits,
            http1=self.http1,
            http2=self.http2,
        )

    def _pool_for(self, identity: ClientIdentity) -> AsyncBaseTransport:
        pool = self._pools.get(identity.name)
        if pool is None:
            pool = self._transport_factory(identity, identity.ssl_context)
            self._pools[identity.name] = pool
        return pool

    async def handle_async_request(self, request: Request) -> Response:
        identity = self._authorize(request)
        transport = self._pool_for(identity)
        return await transport.handle_async_request(request)

    async def aclose(self) -> None:
        for transport in self._pools.values():
            await transport.aclose()
        self._pools.clear()

    async def __aenter__(self: A) -> A:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        await self.aclose()
