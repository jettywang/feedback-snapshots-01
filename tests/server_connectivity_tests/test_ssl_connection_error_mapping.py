"""Unit tests for the error translation performed inside SslConnection.connect().

These tests stub the socket and the nassl SSL client so that specific OpenSSL alerts can be injected
deterministically. They verify that a client-certificate rejection is classified differently from a plain
handshake failure, while certificate validation is never disabled to make a scan pass.
"""

from pathlib import Path
from unittest import mock

import pytest

from nassl import _nassl
from nassl.ssl_client import ClientCertificateRequested

from sslyze.connection_helpers.tls_connection import SslConnection
from sslyze.errors import (
    ServerRejectedClientCertificate,
    ServerRejectedTlsHandshake,
    ServerRequestedClientAuthentication,
)
from sslyze.server_connectivity import TlsVersionEnum
from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration


def _location_and_config(with_client_cert: bool):
    location = ServerNetworkLocation(hostname="localhost", port=8443, ip_address="127.0.0.1")
    if not with_client_cert:
        config = ServerNetworkConfiguration(tls_server_name_indication="localhost")
        return location, config

    credentials = mock.Mock()
    credentials.certificate_chain_path = Path("tests/openssl_server/client-cert.pem")
    credentials.key_path = Path("tests/openssl_server/client-key.pem")
    credentials.key_type = mock.Mock()
    credentials.key_type.value = 1
    credentials.key_password = ""
    config = ServerNetworkConfiguration(
        tls_server_name_indication="localhost", tls_client_auth_credentials=credentials
    )
    return location, config


class _FakeNasslClient:
    def __init__(self, handshake_error: Exception):
        self._handshake_error = handshake_error
        self.cipher_list_set = False
        self.sni_set = False

    def set_cipher_list(self, _cipher_list):
        self.cipher_list_set = True

    def set_tlsext_host_name(self, _name):
        self.sni_set = True

    def set_underlying_socket(self, _sock):
        pass

    def do_handshake(self):
        raise self._handshake_error

    def shutdown(self):
        pass


def _connect_with_handshake_error(handshake_error: Exception, with_client_cert: bool):
    location, config = _location_and_config(with_client_cert)
    fake_client = _FakeNasslClient(handshake_error)

    connection = SslConnection(
        server_location=location,
        network_configuration=config,
        tls_version=TlsVersionEnum.TLS_1_2,
        should_ignore_client_auth=False,
    )
    connection.ssl_client = fake_client

    with mock.patch("sslyze.connection_helpers.tls_connection._open_socket", return_value=mock.Mock()):
        connection.connect(should_retry_connection=False)


class TestSslConnectionErrorMapping:
    def test_bad_certificate_alert_with_supplied_cert_is_rejected_client_certificate(self):
        # Given a caller that supplied a client certificate, and a server rejecting it with "bad certificate"
        error = _nassl.OpenSSLError("sslv3 alert bad certificate")

        # The failure is classified as a rejected client certificate, not a generic handshake failure
        with pytest.raises(ServerRejectedClientCertificate):
            _connect_with_handshake_error(error, with_client_cert=True)

    def test_bad_certificate_alert_without_cert_stays_generic_handshake_failure(self):
        # Given a caller with no client certificate, the same alert stays a generic handshake rejection:
        # re-routing it to a client-auth category would claim a certificate was rejected when none was sent
        error = _nassl.OpenSSLError("sslv3 alert bad certificate")

        with pytest.raises(ServerRejectedTlsHandshake):
            _connect_with_handshake_error(error, with_client_cert=False)

    def test_plain_alert_is_always_a_handshake_failure(self):
        # A "handshake failure" alert unrelated to client certificates is never reclassified
        error = _nassl.OpenSSLError("sslv3 alert handshake failure")

        with pytest.raises(ServerRejectedTlsHandshake):
            _connect_with_handshake_error(error, with_client_cert=True)

    def test_client_certificate_requested_is_propagated_raw(self):
        # The nassl ClientCertificateRequested exception is propagated unchanged so plugins can still recover
        # the negotiated cipher suite / certificate chain
        error = ClientCertificateRequested(ca_list=[])

        with pytest.raises(ClientCertificateRequested):
            _connect_with_handshake_error(error, with_client_cert=False)

    def test_unknown_ca_alert_with_supplied_cert_is_rejected_client_certificate(self):
        error = _nassl.OpenSSLError("tlsv1 alert unknown ca")

        with pytest.raises(ServerRejectedClientCertificate):
            _connect_with_handshake_error(error, with_client_cert=True)

    def test_certificate_required_alert_without_cert_is_client_auth_request(self):
        # An explicit TLS 1.3 "certificate required" alert with no certificate configured unambiguously means
        # the server needs a client certificate: report it as such rather than as a generic connectivity failure
        error = _nassl.OpenSSLError("tlsv13 alert certificate required")

        with pytest.raises(ServerRequestedClientAuthentication):
            _connect_with_handshake_error(error, with_client_cert=False)

    def test_certificate_required_alert_with_supplied_cert_is_rejected_certificate(self):
        # If a certificate was supplied yet the server still demands one, the configured one was not accepted
        error = _nassl.OpenSSLError("tlsv13 alert certificate required")

        with pytest.raises(ServerRejectedClientCertificate):
            _connect_with_handshake_error(error, with_client_cert=True)
