import socket
from typing import List

import pytest

from sslyze.connection_helpers import tls_connection
from sslyze.connection_helpers.opportunistic_tls_helpers import (
    OpportunisticTlsError,
    ProtocolWithOpportunisticTlsEnum,
    _SmtpHelper,
)
from sslyze.errors import ServerRejectedOpportunisticTlsNegotiation
from sslyze.server_connectivity import TlsVersionEnum
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation

EHLO_HOSTNAME = "sslyze.scan"
EXPECTED_SENT_COMMANDS = f"EHLO {EHLO_HOSTNAME}\r\nSTARTTLS\r\n".encode("utf-8")

# A full SMTP STARTTLS negotiation, as sent by the server
SERVER_SESSION = (
    b"220-mail.example.com ESMTP ready\r\n"
    b"220 and uses a multiline greeting\r\n"
    b"250-mail.example.com greets you\r\n"
    b"250-SIZE 1048576\r\n"
    b"250-STARTTLS\r\n"
    b"250 OK\r\n"
    b"220 Ready to start TLS\r\n"
)

# Bytes that belong to the stage after the plaintext negotiation (e.g. a pipelined TLS record);
# the negotiation must never consume them
BYTES_AFTER_UPGRADE = b"\x16\x03\x01\x00\x2eTLS-DATA"


class MeteringSocket:
    """A fake socket that serves a scripted session split into chunks and records what is written to it.

    Only sendall() is provided on purpose: any attempt at a bare send() (which would be vulnerable
    to partial writes) fails loudly with an AttributeError.
    """

    def __init__(self, session_bytes: bytes, split_points: List[int]):
        points = [0] + sorted(set(split_points)) + [len(session_bytes)]
        self._chunks = [session_bytes[start:end] for start, end in zip(points, points[1:]) if start != end]
        self._chunk_being_served = b""
        self.sent_bytes = bytearray()
        self.closed = False

    def recv(self, size: int) -> bytes:
        # Never return more than what remains of the chunk currently being served,
        # to simulate short reads at the chunk boundaries
        if not self._chunk_being_served:
            if not self._chunks:
                return b""
            self._chunk_being_served = self._chunks.pop(0)
        data = self._chunk_being_served[:size]
        self._chunk_being_served = self._chunk_being_served[size:]
        return data

    def sendall(self, data: bytes) -> None:
        self.sent_bytes += data

    def close(self) -> None:
        self.closed = True

    @property
    def remaining_bytes(self) -> bytes:
        return self._chunk_being_served + b"".join(self._chunks)


class TimingOutSocket:
    """A fake socket that always times out when read from."""

    def __init__(self):
        self.closed = False

    def recv(self, size: int) -> bytes:
        raise socket.timeout("timed out")

    def sendall(self, data: bytes) -> None:
        pass

    def close(self) -> None:
        self.closed = True


def _run_negotiation(session_bytes: bytes, split_points: List[int]) -> MeteringSocket:
    sock = MeteringSocket(session_bytes, split_points)
    _SmtpHelper(smtp_ehlo_hostname=EHLO_HOSTNAME).prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]
    return sock


class TestSmtpStartTlsNegotiation:
    @pytest.mark.parametrize("split_point", range(len(SERVER_SESSION) + 1))
    def test_succeeds_with_session_split_at_every_boundary(self, split_point):
        # Given the exact same server session, split into two chunks at every possible boundary
        session_bytes = SERVER_SESSION + BYTES_AFTER_UPGRADE

        # When performing the STARTTLS negotiation
        sock = _run_negotiation(session_bytes, [split_point])

        # Then the expected commands were sent, in the right order
        assert bytes(sock.sent_bytes) == EXPECTED_SENT_COMMANDS
        # And the negotiation stopped exactly at the end of the 220 reply to STARTTLS:
        # bytes belonging to the next stage were not consumed
        assert sock.remaining_bytes == BYTES_AFTER_UPGRADE
        # And the socket was left open for the TLS handshake
        assert not sock.closed

    def test_succeeds_with_session_split_at_every_boundary_simultaneously(self):
        # Given the server session delivered one byte per chunk
        session_bytes = SERVER_SESSION + BYTES_AFTER_UPGRADE

        # When performing the STARTTLS negotiation
        sock = _run_negotiation(session_bytes, list(range(len(session_bytes))))

        # Then it succeeds and behaves exactly like an unfragmented session
        assert bytes(sock.sent_bytes) == EXPECTED_SENT_COMMANDS
        assert sock.remaining_bytes == BYTES_AFTER_UPGRADE

    def test_rejected_greeting_is_not_overridden_by_success_text_in_reply(self):
        # Given a greeting that rejects the connection but mentions "220 Ready to start TLS" in its text
        session_bytes = (
            b"554-No service here; 220 Ready to start TLS is definitely not what this is\r\n" b"554 Go away\r\n"
        )

        # When performing the negotiation, it fails instead of entering TLS
        with pytest.raises(OpportunisticTlsError, match="220 service ready"):
            _run_negotiation(session_bytes, [])

    def test_rejected_starttls_is_not_overridden_by_later_text(self):
        # Given a server that rejects STARTTLS with a multiline 454 reply,
        # followed by bytes that look like a success reply
        session_bytes = (
            b"220 mail.example.com ESMTP ready\r\n"
            b"250-mail.example.com greets you\r\n"
            b"250 STARTTLS\r\n"
            b"454-STARTTLS is temporarily unavailable\r\n"
            b"454 Try again later\r\n"
            b"220 Ready to start TLS\r\n"
        )

        # When performing the negotiation, it fails on the 454 reply
        sock = MeteringSocket(session_bytes, [])
        with pytest.raises(OpportunisticTlsError, match="SMTP STARTTLS rejected"):
            _SmtpHelper(smtp_ehlo_hostname=EHLO_HOSTNAME).prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]

        # And the fake "220" reply that followed was never consumed
        assert sock.remaining_bytes == b"220 Ready to start TLS\r\n"

    def test_unterminated_multiline_reply_is_not_treated_as_success(self):
        # Given an EHLO reply whose multiline response is never terminated
        session_bytes = (
            b"220 mail.example.com ESMTP ready\r\n" b"250-mail.example.com greets you\r\n" b"250-STARTTLS\r\n"
        )

        # When performing the negotiation, it fails because the server closed the connection,
        # instead of reporting that the server does not support TLS
        with pytest.raises(OpportunisticTlsError, match="closed the connection"):
            _run_negotiation(session_bytes, [])

    def test_ehlo_reply_without_starttls_extension(self):
        # Given a server that does not advertise STARTTLS
        session_bytes = (
            b"220 mail.example.com ESMTP ready\r\n" b"250-mail.example.com greets you\r\n" b"250 SIZE 1048576\r\n"
        )

        # When performing the negotiation, it fails with the "not supported" error
        with pytest.raises(OpportunisticTlsError, match="does not support STARTTLS"):
            _run_negotiation(session_bytes, [])

    def test_ehlo_rejected(self):
        # Given a server that rejects EHLO
        session_bytes = b"220 mail.example.com ESMTP ready\r\n" b"502 Command not implemented\r\n"

        # When performing the negotiation, it fails
        with pytest.raises(OpportunisticTlsError, match="SMTP EHLO was rejected"):
            _run_negotiation(session_bytes, [])

    def test_server_closes_connection_during_greeting(self):
        # Given a server that closes the connection right away
        with pytest.raises(OpportunisticTlsError, match="closed the connection"):
            _run_negotiation(b"", [])

    def test_malformed_reply_line(self):
        # Given a server that sends a reply line that is not a valid SMTP reply
        with pytest.raises(OpportunisticTlsError, match="malformed SMTP reply line"):
            _run_negotiation(b"garbage in here\r\n", [])

    def test_inconsistent_codes_in_multiline_reply(self):
        # Given a multiline reply whose lines do not all carry the same reply code
        session_bytes = b"220-mail.example.com ESMTP ready\r\n" b"250 not the same code\r\n"

        with pytest.raises(OpportunisticTlsError, match="inconsistent SMTP multiline reply"):
            _run_negotiation(session_bytes, [])

    def test_failed_negotiation_closes_the_socket(self):
        # Given a server that rejects the negotiation
        session_bytes = b"554 Go away\r\n"
        sock = MeteringSocket(session_bytes, [])

        # When the negotiation fails, the socket is closed right away
        with pytest.raises(OpportunisticTlsError):
            _SmtpHelper(smtp_ehlo_hostname=EHLO_HOSTNAME).prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]
        assert sock.closed

    def test_timeout_is_propagated_and_socket_closed(self):
        # Given a server that never replies
        sock = TimingOutSocket()

        # When the negotiation times out, the timeout is propagated as-is (so the caller can retry)
        # instead of being misreported as the server not supporting TLS
        with pytest.raises(socket.timeout):
            _SmtpHelper(smtp_ehlo_hostname=EHLO_HOSTNAME).prepare_socket_for_tls_handshake(sock)  # type: ignore[arg-type]
        assert sock.closed


class TestSmtpStartTlsNegotiationViaSslConnection:
    def test_negotiation_error_is_attributed_to_pre_handshake_and_socket_closed(self, monkeypatch):
        # Given an SMTP server that rejects the STARTTLS negotiation
        sock = MeteringSocket(b"554 Go away\r\n", [])
        monkeypatch.setattr(tls_connection, "_open_socket", lambda *args, **kwargs: sock)

        server_location = ServerNetworkLocation(hostname="smtp.example.com", port=587, ip_address="1.2.3.4")
        network_configuration = ServerNetworkConfiguration(
            tls_server_name_indication="smtp.example.com",
            tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.SMTP,
        )
        ssl_connection = tls_connection.SslConnection(
            server_location=server_location,
            network_configuration=network_configuration,
            tls_version=TlsVersionEnum.TLS_1_2,
            should_ignore_client_auth=True,
        )

        # When connecting, the failure is attributed to the opportunistic TLS pre-negotiation
        with pytest.raises(ServerRejectedOpportunisticTlsNegotiation):
            ssl_connection._do_pre_handshake()

        # And the socket was closed
        assert sock.closed
