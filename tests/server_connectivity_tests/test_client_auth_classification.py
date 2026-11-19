"""Deterministic, network-free tests of the connectivity probing logic around client authentication.

A hand-written handshake double (``FakeSslConnection``) replaces the real SslConnection so that the behavior of
``check_connectivity_to_server()`` can be exercised for:

* a server that merely *requests* a client certificate (optional client auth),
* a server that *requires* a client certificate,
* a server that returns a plain TLS alert unrelated to client authentication,
* a caller that supplies its own client certificate.

The fakes record which work was actually performed (socket open, handshake, write/read, retries) and which
connection explicitly refused to work, so the tests can assert both the final classification and the reason why
a given check was blocked.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from unittest import mock

import pytest

from nassl import _nassl
from nassl.ssl_client import ClientCertificateRequested, SslClient

from sslyze.connection_helpers.tls_connection import _HANDSHAKE_REJECTED_TLS_ERRORS

from sslyze.errors import (
    ConnectionToServerFailed,
    ServerRejectedTlsHandshake,
    ServerTlsConfigurationNotSupported,
)
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerTlsProbingResult,
    TlsVersionEnum,
    check_connectivity_to_server,
)
from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration


class _RaisableServerRejectedTlsHandshake(ServerRejectedTlsHandshake):
    """A mutable copy of the frozen error so it can actually be raised (traceback attached) by the fake."""


@dataclass
class FakeSslClient(SslClient):
    behavior: "HandshakeBehavior"
    call_log: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Do not call SslClient.__init__: this is a pure test double with no native state.
        pass

    def set_cipher_list(self, cipher_list: str) -> None:
        self.call_log.append(f"set_cipher_list:{cipher_list}")

    def set_ciphersuites(self, cipher_suites: str) -> None:
        self.call_log.append(f"set_ciphersuites:{cipher_suites}")

    def set_tlsext_host_name(self, server_name: str) -> None:
        self.call_log.append(f"set_sni:{server_name}")

    def get_current_cipher_name(self) -> str:
        return "TLS_AES_256_GCM_SHA384"

    def get_client_CA_list(self) -> List[str]:
        return ["CN=Fake Client CA"]

    def do_handshake(self) -> None:
        self.call_log.append("do_handshake")
        outcome = self.behavior.handshake_outcome
        if outcome is not None:
            raise outcome

    def write(self, data: bytes) -> int:
        self.call_log.append(f"write:{data!r}")
        # In TLS 1.3 the CertificateRequest/alert only surfaces when reading the server's post-handshake response
        return len(data)

    def read(self, size: int) -> bytes:
        self.call_log.append(f"read:{size}")
        post_handshake = self.behavior.post_handshake_outcome
        if post_handshake is not None:
            raise post_handshake
        # Optional client auth: the server keeps the connection open and waits for more data
        raise socket_timeout()

    def set_groups(self, groups) -> None:
        self.call_log.append(f"set_groups:{groups}")

    def get_ephemeral_key(self):
        self.call_log.append("get_ephemeral_key")
        return object()

    def shutdown(self) -> None:
        self.call_log.append("shutdown")


def socket_timeout() -> TimeoutError:
    import socket

    return socket.timeout("timed out")


@dataclass
class HandshakeBehavior:
    """Describes how the fake server reacts to a single SslConnection instance."""

    handshake_outcome: Optional[Exception] = None
    post_handshake_outcome: Optional[Exception] = None


class FakeSslConnection:
    """SslConnection test double; instantiation order and ignore-client-auth flags are recorded."""

    instances: List["FakeSslConnection"] = []

    def __init__(
        self,
        server_location,
        network_configuration,
        tls_version,
        should_ignore_client_auth,
        should_use_legacy_openssl=None,
        ca_certificates_path=None,
        should_enable_server_name_indication=True,
    ) -> None:
        self.should_ignore_client_auth = should_ignore_client_auth
        self.tls_version = tls_version
        self._server_location = server_location
        self.network_configuration = network_configuration
        self.behavior = self._behavior_for(should_ignore_client_auth)
        self.ssl_client = FakeSslClient(behavior=self.behavior)
        self.closed = False
        FakeSslConnection.instances.append(self)

    def _behavior_for(self, should_ignore_client_auth: bool) -> HandshakeBehavior:
        if should_ignore_client_auth:
            return FakeSslConnection.ignoring_auth_behavior
        return FakeSslConnection.probing_behavior

    def connect(self, should_retry_connection: bool = True) -> None:
        assert should_retry_connection is False, "Connectivity probing must not retry connections"
        try:
            self.ssl_client.do_handshake()
        except ClientCertificateRequested:
            # Mirror the real SslConnection: the raw nassl exception is propagated unchanged
            raise
        except _nassl.OpenSSLError as e:
            message = e.args[0]
            for known_error, human_message in _HANDSHAKE_REJECTED_TLS_ERRORS.items():
                if known_error in message:
                    raise ServerRejectedTlsHandshake(
                        server_location=self._server_location,  # type: ignore[attr-defined]
                        network_configuration=self.network_configuration,
                        error_message=human_message,
                    )
            raise

    def close(self) -> None:
        self.closed = True
        self.ssl_client.shutdown()

    # Configured per test:
    probing_behavior: HandshakeBehavior = HandshakeBehavior()
    ignoring_auth_behavior: HandshakeBehavior = HandshakeBehavior()


@pytest.fixture
def fake_ssl_connection():
    FakeSslConnection.instances = []
    FakeSslConnection.probing_behavior = HandshakeBehavior()
    FakeSslConnection.ignoring_auth_behavior = HandshakeBehavior()
    with mock.patch("sslyze.server_connectivity.SslConnection", FakeSslConnection):
        yield FakeSslConnection
    FakeSslConnection.instances = []


def _server_location_and_config():
    server_location = ServerNetworkLocation(hostname="localhost", port=8443, ip_address="127.0.0.1")
    network_config = ServerNetworkConfiguration(tls_server_name_indication="localhost")
    return server_location, network_config


class TestClientAuthRequirementDetection:
    def test_optional_client_auth_is_not_reported_as_tls_unsupported(self, fake_ssl_connection):
        # Given a server that requests a client certificate during the first (probing) handshake
        fake_ssl_connection.probing_behavior = HandshakeBehavior(
            handshake_outcome=ClientCertificateRequested(ca_list=["CN=Fake Client CA"])
        )
        # And that accepts the connection when the certificate request is ignored (optional client auth)
        fake_ssl_connection.ignoring_auth_behavior = HandshakeBehavior(
            # The read() call times out: the server is simply waiting for more application data
            post_handshake_outcome=None
        )

        server_location, network_config = _server_location_and_config()

        # When testing connectivity
        result = check_connectivity_to_server(server_location, network_config)

        # Then TLS is detected as supported and client auth is OPTIONAL, not "TLS not supported"
        assert result.highest_tls_version_supported == TlsVersionEnum.TLS_1_3
        assert result.client_auth_requirement == ClientAuthRequirementEnum.OPTIONAL

        # And the probe honored the caller's option by ignoring the auth request on the second connection
        second_connection = fake_ssl_connection.instances[1]
        assert second_connection.should_ignore_client_auth is True
        assert second_connection.ssl_client.call_log[0:2] == ["do_handshake", "write:b'A'"]

    def test_required_client_auth_tls_1_3_is_detected(self, fake_ssl_connection):
        # Given a server that requests a client certificate and rejects the connection when none is provided
        fake_ssl_connection.probing_behavior = HandshakeBehavior(
            handshake_outcome=ClientCertificateRequested(ca_list=[])
        )
        server_location, network_config = _server_location_and_config()
        fake_ssl_connection.ignoring_auth_behavior = HandshakeBehavior(
            post_handshake_outcome=_RaisableServerRejectedTlsHandshake(
                server_location=server_location,
                network_configuration=network_config,
                error_message="TLS alert: handshake failure",
            )
        )

        # When testing connectivity
        result = check_connectivity_to_server(server_location, network_config)

        # Then client auth is correctly detected as REQUIRED
        assert result.client_auth_requirement == ClientAuthRequirementEnum.REQUIRED
        assert result.highest_tls_version_supported == TlsVersionEnum.TLS_1_3

    def test_required_client_auth_tls_1_3_via_post_handshake_request(self, fake_ssl_connection):
        # Given a TLS 1.3 server where the CertificateRequest only arrives after the handshake (post-handshake auth)
        fake_ssl_connection.probing_behavior = HandshakeBehavior(
            handshake_outcome=ClientCertificateRequested(ca_list=[])
        )
        # After write() succeeds, read() raises ClientCertificateRequested because nassl converts the server's
        # "certificate required" alert: the connection cannot proceed without a client certificate => REQUIRED
        fake_ssl_connection.ignoring_auth_behavior = HandshakeBehavior(
            post_handshake_outcome=ClientCertificateRequested(ca_list=[])
        )

        server_location, network_config = _server_location_and_config()

        result = check_connectivity_to_server(server_location, network_config)

        assert result.client_auth_requirement == ClientAuthRequirementEnum.REQUIRED

    def test_plain_alert_is_not_confused_with_client_auth(self, fake_ssl_connection):
        # Given a server that answers every TLS 1.3 probe with a generic handshake alert (no CertificateRequest)
        alert = _nassl.OpenSSLError("sslv3 alert handshake failure")
        fake_ssl_connection.probing_behavior = HandshakeBehavior(handshake_outcome=alert)
        fake_ssl_connection.ignoring_auth_behavior = HandshakeBehavior(handshake_outcome=alert)

        server_location, network_config = _server_location_and_config()

        # When testing connectivity, the TLS 1.3 probe is rejected and lower versions are attempted
        # All of them fail the same way, so connectivity testing reports that TLS is not supported
        with pytest.raises(ServerTlsConfigurationNotSupported):
            check_connectivity_to_server(server_location, network_config)

        # And no client-auth detection connection was ever opened (the server never requested a certificate)
        assert all(
            conn.should_ignore_client_auth is False for conn in fake_ssl_connection.instances
        )

    def test_unexpected_error_is_surfaced_not_swallowed(self, fake_ssl_connection):
        # Given a server that triggers an unknown OpenSSL error (not part of the known rejection list)
        weird_error = _nassl.OpenSSLError("some completely unexpected openssl error")
        fake_ssl_connection.probing_behavior = HandshakeBehavior(handshake_outcome=weird_error)

        server_location, network_config = _server_location_and_config()

        # When testing connectivity, the unknown error is wrapped as a connection failure rather than swallowed
        with pytest.raises(ConnectionToServerFailed):
            check_connectivity_to_server(server_location, network_config)


class TestIgnoreClientAuthOption:
    """The caller's existing choice of ignoring (or not) client-auth requests must be strictly preserved."""

    def _connectivity_info(self, client_auth_requirement, with_credentials=False):
        server_location, network_config = _server_location_and_config()
        if with_credentials:
            from sslyze.server_setting import ClientAuthenticationCredentials
            from pathlib import Path

            creds = ClientAuthenticationCredentials(
                certificate_chain_path=Path("tests/openssl_server/client-cert.pem"),
                key_path=Path("tests/openssl_server/client-key.pem"),
            )
            network_config = ServerNetworkConfiguration(
                tls_server_name_indication="localhost", tls_client_auth_credentials=creds
            )
        probing_result = ServerTlsProbingResult(
            highest_tls_version_supported=TlsVersionEnum.TLS_1_3,
            cipher_suite_supported="TLS_AES_256_GCM_SHA384",
            client_auth_requirement=client_auth_requirement,
            supports_ecdh_key_exchange=True,
        )
        from sslyze.server_connectivity import ServerConnectivityInfo

        return ServerConnectivityInfo(
            server_location=server_location,
            network_configuration=network_config,
            tls_probing_result=probing_result,
        )

    def test_optional_auth_is_ignored_when_no_credentials(self, fake_ssl_connection):
        server_info = self._connectivity_info(ClientAuthRequirementEnum.OPTIONAL)

        connection = server_info.get_preconfigured_tls_connection()

        assert connection.should_ignore_client_auth is True

    def test_required_auth_is_not_ignored_when_no_credentials(self, fake_ssl_connection):
        server_info = self._connectivity_info(ClientAuthRequirementEnum.REQUIRED)

        connection = server_info.get_preconfigured_tls_connection()

        # So that plugins surface ClientCertificateRequested instead of silently continuing
        assert connection.should_ignore_client_auth is False

    def test_supplied_credentials_always_disable_ignoring(self, fake_ssl_connection):
        server_info = self._connectivity_info(
            ClientAuthRequirementEnum.OPTIONAL, with_credentials=True
        )

        connection = server_info.get_preconfigured_tls_connection()

        assert connection.should_ignore_client_auth is False
