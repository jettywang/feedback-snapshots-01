from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union

from nassl.ephemeral_key_info import EphemeralKeyInfo
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import ClientCertificateRequested, SslClient, BaseSslClient

from sslyze.errors import (
    ServerRejectedTlsHandshake,
    ServerTlsConfigurationNotSupported,
    TlsHandshakeTimedOut,
    ConnectionToServerFailed,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum
from sslyze.plugins.openssl_cipher_suites._tls12_workaround import WorkaroundForTls12ForCipherSuites


class CipherSuiteScanStatusEnum(str, Enum):
    """The outcome of testing a single (TLS version, OpenSSL backend, cipher suite) combination.

    ACCEPTED: A handshake completed and the server negotiated the cipher suite.
    REJECTED: The server was reached but explicitly refused to negotiate the cipher suite.
    TRANSPORT_ERROR: The connection could not be completed (timeout, reset, ...); the server never gave a clear
        answer so the cell is left untested rather than counted as rejected. Such cells are eligible for a retry.
    NOT_CAPABLE: SSLyze/OpenSSL cannot run this cipher suite with this TLS version/backend; no connection was made.
    """

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    NOT_CAPABLE = "NOT_CAPABLE"


class OpenSslBackendEnum(str, Enum):
    """Which OpenSSL implementation (bundled inside nassl) was used for a connection."""

    MODERN = "MODERN"
    LEGACY = "LEGACY"


def get_openssl_backend_for_cipher_suite(tls_version: TlsVersionEnum, cipher_suite: CipherSuite) -> OpenSslBackendEnum:
    """Figure out which OpenSSL backend must be used to test a cipher suite at a given TLS version.

    TLS 1.3 only exists in the modern OpenSSL and uses its own cipher suite API.
    For TLS 1.2 the backend depends on the cipher suite (some weak suites are only in the legacy OpenSSL).
    SSL 2.0/3.0, TLS 1.0/1.1 can only be tested with the legacy OpenSSL.
    """
    if tls_version == TlsVersionEnum.TLS_1_3:
        return OpenSslBackendEnum.MODERN
    if tls_version == TlsVersionEnum.TLS_1_2:
        requires_legacy = WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(cipher_suite.openssl_name)
        return OpenSslBackendEnum.LEGACY if requires_legacy else OpenSslBackendEnum.MODERN
    return OpenSslBackendEnum.LEGACY


@dataclass(frozen=True)
class CipherSuiteAcceptedByServer:
    """
    ephemeral_key: The ephemeral key negotiated with the server when using (EC) DH cipher suites. None if the cipher
        suite does not use ephemeral keys or if the ephemeral key could not be retrieved.
    """

    cipher_suite: CipherSuite
    ephemeral_key: Optional[EphemeralKeyInfo]


@dataclass(frozen=True)
class CipherSuiteRejectedByServer:
    cipher_suite: CipherSuite
    error_message: str


@dataclass(frozen=True)
class CipherSuiteTransportError:
    """The connection for this cipher suite failed before the server could accept or reject it.

    This is not a rejection: the cell stays untested and can be retried.
    """

    cipher_suite: CipherSuite
    error_message: str


@dataclass(frozen=True)
class CipherSuiteNotCapable:
    """SSLyze/OpenSSL cannot attempt this cipher suite with the requested TLS version/backend.

    No network connection was ever made for this cell.
    """

    cipher_suite: CipherSuite
    reason: str


# Exceptions that mean "the connection did not complete", as opposed to "the server said no".
# They are the only outcomes eligible for a retry.
RETRYABLE_TRANSPORT_ERRORS = (
    TlsHandshakeTimedOut,
    ConnectionToServerFailed,
)


def connect_with_cipher_suite(
    server_connectivity_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, cipher_suite: CipherSuite
) -> Union[CipherSuiteAcceptedByServer, CipherSuiteRejectedByServer, CipherSuiteTransportError]:
    """Initiates a SSL handshake with the server using the SSL version and the cipher suite specified.

    Negotiation rejections are returned as CipherSuiteRejectedByServer. Transport-level failures (timeout, connection
    reset, ...) are returned as CipherSuiteTransportError so the caller can retry them instead of misreporting them as
    a server rejection.
    """
    backend = get_openssl_backend_for_cipher_suite(tls_version, cipher_suite)
    requires_legacy_openssl = backend == OpenSslBackendEnum.LEGACY

    ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, should_use_legacy_openssl=requires_legacy_openssl
    )
    _set_cipher_suite_string(tls_version, cipher_suite.openssl_name, ssl_connection.ssl_client)

    ephemeral_key = None
    try:
        # Perform the SSL handshake
        ssl_connection.connect()
        ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()

    except ServerTlsConfigurationNotSupported:
        # SSLyze rejected the handshake because the server's DH config was too insecure; this means the
        # cipher suite is actually supported
        pass

    except ClientCertificateRequested:
        # When the handshake failed due to ClientCertificateRequested
        ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()
        pass

    except ServerRejectedTlsHandshake as e:
        return CipherSuiteRejectedByServer(cipher_suite=cipher_suite, error_message=e.error_message)

    except RETRYABLE_TRANSPORT_ERRORS as e:
        # Timeouts/connection failures are not a clear "no" from the server. Sometimes triggered by servers that
        # don't support (at all) a specific version of TLS (Amazon Cloudfront does that with TLS 1.3), but there is
        # no easy way to differentiate this from a network glitch/timeout, so it must stay retryable rather than be
        # counted as a rejection.
        return CipherSuiteTransportError(cipher_suite=cipher_suite, error_message=e.error_message)

    finally:
        ssl_connection.close()

    return CipherSuiteAcceptedByServer(cipher_suite=cipher_suite, ephemeral_key=ephemeral_key)


def _set_cipher_suite_string(tls_version: TlsVersionEnum, cipher_suite_str: str, ssl_client: BaseSslClient) -> None:
    # Only enable the cipher suite to test; not trivial anymore since OpenSSL 1.1.1 and TLS 1.3
    if isinstance(ssl_client, SslClient):
        # With the modern OpenSSL client we have to manage TLS 1.3-specific cipher functions
        if tls_version == TlsVersionEnum.TLS_1_3:
            ssl_client.set_ciphersuites(cipher_suite_str)  # TLS 1.3 method
        else:
            ssl_client.set_cipher_list(cipher_suite_str)  # Legacy method
    elif isinstance(ssl_client, LegacySslClient):
        # With the legacy OpenSSL client, nothing special to do
        ssl_client.set_cipher_list(cipher_suite_str)
    else:
        raise RuntimeError("Should never happen")
