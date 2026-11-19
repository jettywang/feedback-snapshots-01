from abc import ABC
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration


class InvalidServerNetworkConfigurationError(Exception):
    """Raised when trying to create a ServerNetworkConfiguration with invalid settings."""


class ServerHostnameCouldNotBeResolved(Exception):
    """Raised when trying to create a ServerNetworkLocationViaDirectConnection but DNS lookup failed."""


@dataclass(frozen=True)
class ConnectionToServerFailed(Exception):
    """Parent class for all exceptions raised when a connecting to a server failed."""

    server_location: "ServerNetworkLocation"
    network_configuration: "ServerNetworkConfiguration"
    error_message: str

    def __str__(self) -> str:
        return f'{self.server_location.display_string} -> "{self.error_message}".'


@dataclass(frozen=True)
class ConnectionToServerTimedOut(ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class ServerRejectedConnection(ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class ConnectionToHttpProxyFailed(ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class ConnectionToHttpProxyTimedOut(ConnectionToHttpProxyFailed):
    pass


@dataclass(frozen=True)
class HttpProxyRejectedConnection(ConnectionToHttpProxyFailed):
    pass


@dataclass(frozen=True)
class ServerRejectedOpportunisticTlsNegotiation(ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class TlsHandshakeFailed(ABC, ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class ServerRejectedTlsHandshake(TlsHandshakeFailed):
    """The server rejected the TLS handshake for a reason unrelated to client authentication.

    Examples include an unsupported TLS version or cipher suite, a failed server-side validation of the
    ClientHello, or the server aborting the handshake with a generic TLS alert.
    """


@dataclass(frozen=True)
class ServerTlsConfigurationNotSupported(TlsHandshakeFailed):
    pass


@dataclass(frozen=True)
class ClientAuthenticationConfigurationError(TlsHandshakeFailed, ABC):
    """Base class for handshake failures caused by the server's client authentication configuration."""


@dataclass(frozen=True)
class ServerRequestedClientAuthentication(ClientAuthenticationConfigurationError):
    """The server asked for a client certificate and the caller did not supply one that satisfies the request.

    The TLS connection itself was established far enough to negotiate a cipher suite; only the client
    authentication step could not be completed. This must not be reported as "TLS not supported".
    """


@dataclass(frozen=True)
class ServerRejectedClientCertificate(ClientAuthenticationConfigurationError):
    """The caller supplied a client certificate but the server rejected it.

    This typically means the certificate is not signed by a CA the server trusts, is expired/revoked, or the
    server answered with a "bad certificate"/"certificate unknown"/"illegal parameter" alert.
    """


@dataclass(frozen=True)
class TlsHandshakeTimedOut(TlsHandshakeFailed):
    """Raised when the initial socket connection to the server succeeded, but the TLS handshake then timed out.

    This means that the server is definitely reachable/online, but its TLS stack is buggy or it does not support the TLS
    versions SSLyze enabled in the handshake.

    See https://github.com/nabla-c0d3/sslyze/issues/445 for more details.
    """

    pass
