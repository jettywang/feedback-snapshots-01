import pytest
from typing import Optional

from sslyze.connection_helpers import tls_connection
from sslyze.connection_helpers.opportunistic_tls_helpers import OpportunisticTlsError, _LdapHelper
from sslyze.connection_helpers.tls_connection import SslConnection
from sslyze.errors import ServerRejectedConnection, ServerRejectedOpportunisticTlsNegotiation
from sslyze.server_connectivity import TlsVersionEnum
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation
from sslyze.connection_helpers.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum


def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    length_as_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_as_bytes)]) + length_as_bytes


def _tlv(tag: int, content: bytes, force_long_form: bool = False) -> bytes:
    if force_long_form and len(content) < 0x80:
        return bytes([tag, 0x81, len(content)]) + content
    return bytes([tag]) + _ber_len(len(content)) + content


def _ldap_message(message_id: int, protocol_op: bytes, force_long_form: bool = False) -> bytes:
    return _tlv(0x30, _tlv(0x02, bytes([message_id])) + protocol_op, force_long_form=force_long_form)


def _extended_response(result_code: int, diagnostic_message: bytes = b"", extra_fields: bytes = b"") -> bytes:
    ldap_result = _tlv(0x0A, bytes([result_code])) + _tlv(0x04, b"") + _tlv(0x04, diagnostic_message)
    return _tlv(0x78, ldap_result + extra_fields)


class _FakeSocket:
    """A socket that serves pre-recorded bytes, optionally one byte at a time."""

    def __init__(self, incoming: bytes, chunk_size: Optional[int] = None):
        self._incoming = incoming
        self._chunk_size = chunk_size
        self.sent_data = b""

    def send(self, data: bytes) -> int:
        self.sent_data += data
        return len(data)

    def recv(self, size: int) -> bytes:
        if not self._incoming:
            return b""
        if self._chunk_size is not None:
            size = min(size, self._chunk_size)
        chunk, self._incoming = self._incoming[:size], self._incoming[size:]
        return chunk

    @property
    def unread_data(self) -> bytes:
        return self._incoming


class TestLdapStartTlsNegotiation:
    def test_successful_response_grants_upgrade(self):
        # Given a server that accepts StartTLS with a minimal ExtendedResponse (OpenLDAP-style)
        sock = _FakeSocket(_ldap_message(message_id=1, protocol_op=_extended_response(result_code=0)))

        # When performing the StartTLS negotiation, it succeeds
        _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

        # And the StartTLS extended request was sent
        assert sock.sent_data == _LdapHelper.START_TLS_CMD

    def test_successful_response_with_optional_fields_grants_upgrade(self):
        # Given a server that includes the optional responseName and responseValue fields (ApacheDS-style)
        extra_fields = _tlv(0x8A, b"1.3.6.1.4.1.1466.20037") + _tlv(0x8B, b"")
        sock = _FakeSocket(_ldap_message(message_id=1, protocol_op=_extended_response(0, extra_fields=extra_fields)))

        # When performing the StartTLS negotiation, it succeeds
        _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

    def test_long_form_length_and_fragmented_delivery_grant_upgrade(self):
        # Given a success response using long-form length encoding, delivered one byte at a time
        response = _ldap_message(message_id=1, protocol_op=_extended_response(0), force_long_form=True)
        assert response[1] == 0x81
        sock = _FakeSocket(response, chunk_size=1)

        # When performing the StartTLS negotiation, it succeeds
        _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

    def test_response_for_another_message_id_is_rejected(self):
        # Given a success response but for a different request
        sock = _FakeSocket(_ldap_message(message_id=2, protocol_op=_extended_response(result_code=0)))

        # The upgrade is rejected
        with pytest.raises(OpportunisticTlsError, match="different request"):
            _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

    def test_non_success_result_with_success_text_is_rejected(self):
        # Given a failure result whose diagnostic message contains the text "Start TLS request accepted"
        response = _ldap_message(
            message_id=1,
            protocol_op=_extended_response(result_code=53, diagnostic_message=b"Start TLS request accepted"),
        )
        sock = _FakeSocket(response)

        # The upgrade is rejected: the result code, not the text, is authoritative
        with pytest.raises(OpportunisticTlsError, match="unwillingToPerform"):
            _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

    def test_embedded_decoy_message_is_rejected(self):
        # Given a failure result whose diagnostic message embeds a full valid success response as a decoy
        decoy = _ldap_message(message_id=1, protocol_op=_extended_response(result_code=0))
        response = _ldap_message(
            message_id=1,
            protocol_op=_extended_response(result_code=1, diagnostic_message=decoy),
        )
        sock = _FakeSocket(response)

        # The upgrade is rejected
        with pytest.raises(OpportunisticTlsError, match="operationsError"):
            _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

    def test_success_response_to_another_operation_is_rejected(self):
        # Given a successful BindResponse (ie. a success response to another request) instead of an ExtendedResponse
        bind_response = _tlv(0x61, _tlv(0x0A, b"\x00") + _tlv(0x04, b"") + _tlv(0x04, b""))
        sock = _FakeSocket(_ldap_message(message_id=1, protocol_op=bind_response))

        # The upgrade is rejected
        with pytest.raises(OpportunisticTlsError, match="ExtendedResponse"):
            _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

    def test_truncated_response_is_a_transport_error(self):
        # Given a server that closes the connection in the middle of the LDAP message
        full_response = _ldap_message(message_id=1, protocol_op=_extended_response(result_code=0))
        sock = _FakeSocket(full_response[:5])

        # The failure surfaces as a transport error, not as a protocol rejection
        with pytest.raises(ConnectionError):
            _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

    def test_oversized_response_is_rejected(self):
        # Given a response that claims a huge length
        sock = _FakeSocket(b"\x30\x83\xff\xff\xff")

        # The upgrade is rejected without trying to read that much data
        with pytest.raises(OpportunisticTlsError, match="too large"):
            _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

    def test_socket_is_handed_over_to_tls_with_no_byte_consumed(self):
        # Given a success response immediately followed by bytes belonging to the upcoming TLS handshake
        tls_bytes = b"\x16\x03\x01\x00\x2efaketls"
        sock = _FakeSocket(_ldap_message(message_id=1, protocol_op=_extended_response(0)) + tls_bytes)

        # When performing the StartTLS negotiation, it succeeds
        _LdapHelper().prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

        # And the helper consumed exactly the LDAP message, leaving the TLS bytes untouched for the TLS client
        assert sock.unread_data == tls_bytes


class TestLdapStartTlsErrorReporting:
    def _make_ssl_connection(self) -> SslConnection:
        server_location = ServerNetworkLocation(hostname="ldap.example.com", port=389, ip_address="127.0.0.1")
        network_configuration = ServerNetworkConfiguration(
            tls_server_name_indication="ldap.example.com",
            tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.LDAP,
        )
        return SslConnection(
            server_location=server_location,
            network_configuration=network_configuration,
            tls_version=TlsVersionEnum.TLS_1_2,
            should_ignore_client_auth=False,
        )

    def test_protocol_rejection_is_reported_as_opportunistic_tls_rejection(self, mocker):
        # Given a server that rejects StartTLS with a valid LDAP error response
        response = _ldap_message(
            message_id=1,
            protocol_op=_extended_response(result_code=53, diagnostic_message=b"Start TLS request accepted"),
        )
        mocker.patch.object(tls_connection, "_open_socket", return_value=_FakeSocket(response))

        # When connecting, the failure is reported as a rejected opportunistic TLS negotiation
        with pytest.raises(ServerRejectedOpportunisticTlsNegotiation):
            self._make_ssl_connection().connect(should_retry_connection=False)

    def test_transport_interruption_is_reported_as_connection_error(self, mocker):
        # Given a server that drops the connection in the middle of the StartTLS negotiation
        full_response = _ldap_message(message_id=1, protocol_op=_extended_response(result_code=0))
        mocker.patch.object(tls_connection, "_open_socket", return_value=_FakeSocket(full_response[:5]))

        # When connecting, the failure is reported as a rejected/failed connection, distinguishable
        # from a protocol-level StartTLS rejection
        with pytest.raises(ServerRejectedConnection):
            self._make_ssl_connection().connect(should_retry_connection=False)
