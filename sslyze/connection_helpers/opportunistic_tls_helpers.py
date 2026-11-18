import socket
import struct
from abc import abstractmethod, ABC
from enum import Enum
from smtplib import SMTP, SMTPException
from typing import ClassVar, Optional


class ProtocolWithOpportunisticTlsEnum(str, Enum):
    """The list of plaintext protocols supported by SSLyze for opportunistic TLS upgrade (such as STARTTLS).

    This allows SSLyze to figure out how to complete an SSL/TLS handshake with the server.
    """

    SMTP = "SMTP"
    XMPP = "XMPP"
    XMPP_SERVER = "XMPP_SERVER"
    FTP = "FTP"
    POP3 = "POP3"
    LDAP = "LDAP"
    IMAP = "IMAP"
    RDP = "RDP"
    POSTGRES = "POSTGRES"

    @classmethod
    def from_default_port(cls, port: int) -> Optional["ProtocolWithOpportunisticTlsEnum"]:
        """Given a port number, return the protocol that uses this port number by default."""
        try:
            return _DEFAULT_PORTS[port]
        except KeyError:
            return None


_DEFAULT_PORTS = {
    587: ProtocolWithOpportunisticTlsEnum.SMTP,
    25: ProtocolWithOpportunisticTlsEnum.SMTP,
    5222: ProtocolWithOpportunisticTlsEnum.XMPP,
    5269: ProtocolWithOpportunisticTlsEnum.XMPP_SERVER,
    109: ProtocolWithOpportunisticTlsEnum.POP3,
    110: ProtocolWithOpportunisticTlsEnum.POP3,
    143: ProtocolWithOpportunisticTlsEnum.IMAP,
    220: ProtocolWithOpportunisticTlsEnum.IMAP,
    21: ProtocolWithOpportunisticTlsEnum.FTP,
    3268: ProtocolWithOpportunisticTlsEnum.LDAP,
    389: ProtocolWithOpportunisticTlsEnum.LDAP,
    3389: ProtocolWithOpportunisticTlsEnum.RDP,
    5432: ProtocolWithOpportunisticTlsEnum.POSTGRES,
}


class OpportunisticTlsError(Exception):
    pass


class _OpportunisticTlsHelper(ABC):
    @abstractmethod
    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        """Send the right protocol-specific requests to prepare the server for the TLS handshake."""
        pass


class _SmtpHelper(_OpportunisticTlsHelper):
    """Perform an SMTP StartTLS negotiation."""

    def __init__(self, smtp_ehlo_hostname: str):
        self._smtp_ehlo_hostname = smtp_ehlo_hostname

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        # SMTP parsing has some complicated areas and some unusual but legal
        # server behavior - this code uses Python's smtplib to handle the protocol.
        smtp = SMTP(local_hostname=self._smtp_ehlo_hostname)
        smtp.sock = sock

        try:
            code, server_reply_as_bytes = smtp.getreply()
        except SMTPException as exc:
            raise OpportunisticTlsError(f"Unexpected error while performing the SMTP EHLO handshake: {str(exc)}")

        if code != 220:
            server_reply_as_str = server_reply_as_bytes.decode()
            raise OpportunisticTlsError(
                f"Server did not send a '220 service ready' SMTP message: {server_reply_as_str}"
            )

        try:
            code, server_reply_as_bytes = smtp.ehlo()
        except SMTPException as exc:
            raise OpportunisticTlsError(f"Unexpected error while performing the SMTP EHLO handshake: {str(exc)}")

        if code != 250:
            server_reply_as_str = server_reply_as_bytes.decode()
            raise OpportunisticTlsError(f"SMTP EHLO was rejected: {server_reply_as_str}")

        if not smtp.has_extn("starttls"):
            raise OpportunisticTlsError("Server does not support STARTTLS with SMTP")

        try:
            code, server_reply_as_bytes = smtp.docmd("STARTTLS")
        except SMTPException as exc:
            raise OpportunisticTlsError(f"Unexpected error while performing the SMTP EHLO handshake: {str(exc)}")

        if code != 220:
            server_reply_as_str = server_reply_as_bytes.decode()
            raise OpportunisticTlsError(f"SMTP STARTTLS rejected: {server_reply_as_str}")


class _XmppHelper(_OpportunisticTlsHelper):
    """Perform an XMPP StartTLS negotiation."""

    XMPP_OPEN_STREAM = (
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' "
        "xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='{xmpp_to}' xml:lang='en' version='1.0'>"
    )
    XMPP_STARTTLS = b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"

    def __init__(self, xmpp_to: str) -> None:
        self._xmpp_to = xmpp_to

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        # Open an XMPP stream
        sock.send(self.XMPP_OPEN_STREAM.format(xmpp_to=self._xmpp_to).encode("utf-8"))

        # Get the server's features and check for an error
        server_resp = sock.recv(4096)
        if b"<stream:error>" in server_resp:
            raise OpportunisticTlsError("Error opening XMPP stream, try --xmpp_to")
        elif b"</stream:features>" not in server_resp:
            # Get all the server features before initiating startTLS
            sock.recv(4096)

        # Send a STARTTLS message
        sock.send(self.XMPP_STARTTLS)
        xmpp_resp = sock.recv(2048)

        if b"host-unknown" in xmpp_resp:
            raise OpportunisticTlsError("Error opening XMPP stream: server returned host-unknown error, try --xmpp_to")

        if b"proceed" not in xmpp_resp:
            raise OpportunisticTlsError("XMPP STARTTLS not supported")


class _XmppServerHelper(_XmppHelper):
    XMPP_OPEN_STREAM = (
        "<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' "
        "xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='{xmpp_to}' xml:lang='en' version='1.0'>"
    )


class _LdapMessageRejection(OpportunisticTlsError):
    """The server sent an LDAP response that does not grant the StartTLS upgrade."""


class _LdapHelper(_OpportunisticTlsHelper):
    """Performs an LDAP StartTLS negotiation (RFC 4511 section 4.14).

    The upgrade is granted only if the server returns a well-formed LDAPMessage whose messageID matches our
    StartTLS request and whose protocolOp is an ExtendedResponse with a success(0) resultCode. Anything else
    (including responses containing the text "Start TLS request accepted") is rejected.
    """

    START_TLS_CMD = b"0\x1d\x02\x01\x01w\x18\x80\x161.3.6.1.4.1.1466.20037"

    _REQUEST_MESSAGE_ID = 1
    _TAG_SEQUENCE = 0x30
    _TAG_INTEGER = 0x02
    _TAG_ENUMERATED = 0x0A
    _TAG_OCTET_STRING = 0x04
    _TAG_EXTENDED_RESPONSE = 0x78  # [APPLICATION 24]
    _TAG_REFERRAL = 0xA3  # LDAPResult [3]
    _TAG_RESPONSE_NAME = 0x8A  # ExtendedResponse [10]
    _TAG_RESPONSE_VALUE = 0x8B  # ExtendedResponse [11]
    _RESULT_CODE_SUCCESS = 0
    # Hard cap on the size of the StartTLS response we are willing to read; it is tiny in practice
    _MAX_RESPONSE_SIZE = 64 * 1024

    _RESULT_CODE_NAMES = {
        0: "success",
        1: "operationsError",
        2: "protocolError",
        10: "referral",
        49: "invalidCredentials",
        50: "insufficientAccessRights",
        52: "unavailable",
        53: "unwillingToPerform",
    }

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        sock.send(self.START_TLS_CMD)
        message_content = self._read_ldap_message(sock)
        self._validate_start_tls_response(message_content)

    @classmethod
    def _recv_exactly(cls, sock: socket.socket, size: int) -> bytes:
        chunks = []
        remaining = size
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                # Transport interrupted before the TLS client took over; let it surface as a connection error
                raise ConnectionError("Server closed the connection during the LDAP StartTLS negotiation")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @classmethod
    def _parse_length(cls, data: bytes, offset: int) -> tuple:
        """Parse a BER definite length at data[offset]; return (length, offset of the content)."""
        if offset >= len(data):
            raise _LdapMessageRejection("Truncated LDAP message: missing length")
        first_byte = data[offset]
        offset += 1
        if first_byte == 0x80:
            raise _LdapMessageRejection("LDAP message uses indefinite-length encoding, which LDAP forbids")
        if first_byte & 0x80:
            length_bytes_count = first_byte & 0x7F
            if length_bytes_count > 4:
                raise _LdapMessageRejection("LDAP message uses an oversized long-form length")
            if offset + length_bytes_count > len(data):
                raise _LdapMessageRejection("Truncated LDAP message: incomplete long-form length")
            length = int.from_bytes(data[offset : offset + length_bytes_count], "big")
            offset += length_bytes_count
        else:
            length = first_byte
        return length, offset

    @classmethod
    def _read_ldap_message(cls, sock: socket.socket) -> bytes:
        """Read exactly one BER-encoded LDAPMessage from the socket and return the content of its SEQUENCE."""
        header = cls._recv_exactly(sock, 2)
        if header[0] != cls._TAG_SEQUENCE:
            raise _LdapMessageRejection(f"Expected an LDAPMessage SEQUENCE, got tag 0x{header[0]:02x}")
        if header[1] & 0x80:
            length_bytes_count = header[1] & 0x7F
            if length_bytes_count == 0:
                raise _LdapMessageRejection("LDAP message uses indefinite-length encoding, which LDAP forbids")
            if length_bytes_count > 4:
                raise _LdapMessageRejection("LDAP message uses an oversized long-form length")
            header += cls._recv_exactly(sock, length_bytes_count)
        content_length, content_offset = cls._parse_length(header, 1)
        if content_length > cls._MAX_RESPONSE_SIZE:
            raise _LdapMessageRejection(
                f"LDAP StartTLS response is too large ({content_length} bytes > {cls._MAX_RESPONSE_SIZE})"
            )
        return cls._recv_exactly(sock, content_length)

    @classmethod
    def _parse_tlv(cls, data: bytes, offset: int) -> tuple:
        """Parse the BER TLV at data[offset]; return (tag, content, offset of the next TLV)."""
        if offset >= len(data):
            raise _LdapMessageRejection("Truncated LDAP message: missing field")
        tag = data[offset]
        length, content_offset = cls._parse_length(data, offset + 1)
        end_offset = content_offset + length
        if end_offset > len(data):
            raise _LdapMessageRejection("Truncated LDAP message: field extends past the message boundary")
        return tag, data[content_offset:end_offset], end_offset

    @classmethod
    def _validate_start_tls_response(cls, message_content: bytes) -> None:
        tag, message_id_bytes, offset = cls._parse_tlv(message_content, 0)
        if tag != cls._TAG_INTEGER or not message_id_bytes:
            raise _LdapMessageRejection("Malformed LDAP message: missing messageID")
        message_id = int.from_bytes(message_id_bytes, "big")
        if message_id != cls._REQUEST_MESSAGE_ID:
            raise _LdapMessageRejection(
                f"LDAP response is for a different request (messageID {message_id} instead of"
                f" {cls._REQUEST_MESSAGE_ID})"
            )

        tag, extended_response, offset = cls._parse_tlv(message_content, offset)
        if tag != cls._TAG_EXTENDED_RESPONSE:
            raise _LdapMessageRejection(f"Expected an ExtendedResponse, got protocolOp tag 0x{tag:02x}")
        if offset != len(message_content):
            raise _LdapMessageRejection("Unexpected trailing data in the LDAP message")

        tag, result_code_bytes, offset = cls._parse_tlv(extended_response, 0)
        if tag != cls._TAG_ENUMERATED or not result_code_bytes:
            raise _LdapMessageRejection("Malformed ExtendedResponse: missing resultCode")
        result_code = int.from_bytes(result_code_bytes, "big")

        tag, _matched_dn, offset = cls._parse_tlv(extended_response, offset)
        if tag != cls._TAG_OCTET_STRING:
            raise _LdapMessageRejection("Malformed ExtendedResponse: missing matchedDN")
        tag, diagnostic_message, offset = cls._parse_tlv(extended_response, offset)
        if tag != cls._TAG_OCTET_STRING:
            raise _LdapMessageRejection("Malformed ExtendedResponse: missing diagnosticMessage")

        # Optional referral ([3]) within LDAPResult; skip it if present
        if offset < len(extended_response) and extended_response[offset] == cls._TAG_REFERRAL:
            _, _, offset = cls._parse_tlv(extended_response, offset)

        if result_code != cls._RESULT_CODE_SUCCESS:
            result_name = cls._RESULT_CODE_NAMES.get(result_code, "unknown")
            diagnostic_as_text = diagnostic_message.decode("utf-8", errors="replace")
            raise _LdapMessageRejection(
                f"LDAP StartTLS was rejected: {result_name} ({result_code});"
                f" diagnostic message: {diagnostic_as_text!r}"
            )

        # Optional responseName ([10]) and responseValue ([11]); skip them for compatibility (e.g. ApacheDS)
        if offset < len(extended_response) and extended_response[offset] == cls._TAG_RESPONSE_NAME:
            _, _, offset = cls._parse_tlv(extended_response, offset)
        if offset < len(extended_response) and extended_response[offset] == cls._TAG_RESPONSE_VALUE:
            _, _, offset = cls._parse_tlv(extended_response, offset)
        if offset != len(extended_response):
            raise _LdapMessageRejection("Unexpected trailing data in the ExtendedResponse")


class _RdpHelper(_OpportunisticTlsHelper):
    """Perform an RDP StartTLS negotiation."""

    ERR_NO_STARTTLS = "RDP AUTH TLS was rejected"

    START_TLS_CMD = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
    START_TLS_OK = b"Start TLS request accepted."

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        sock.send(self.START_TLS_CMD)
        data = sock.recv(4)
        if not data or len(data) != 4 or data[:2] != b"\x03\x00":
            raise OpportunisticTlsError(self.ERR_NO_STARTTLS)
        packet_len = struct.unpack(">H", data[2:])[0] - 4
        data = sock.recv(packet_len)

        if not data or len(data) != packet_len:
            raise OpportunisticTlsError(self.ERR_NO_STARTTLS)


class _GenericOpportunisticTlsHelper(_OpportunisticTlsHelper, ABC):
    # To be defined in subclasses
    ERR_NO_STARTTLS: ClassVar[str]  # Error to display to the user when StartTLS failed

    START_TLS_CMD: ClassVar[bytes]  # How to initiate StartTLS with the server
    START_TLS_OK: ClassVar[bytes]  # What is returned by the server when StartTLS was successful

    SHOULD_WAIT_FOR_SERVER_BANNER = True

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        # Grab the banner
        if self.SHOULD_WAIT_FOR_SERVER_BANNER:
            sock.recv(2048)

        # Send Start TLS
        sock.send(self.START_TLS_CMD)
        if self.START_TLS_OK not in sock.recv(2048):
            raise OpportunisticTlsError(self.ERR_NO_STARTTLS)


class _ImapHelper(_GenericOpportunisticTlsHelper):
    ERR_NO_STARTTLS = "IMAP START TLS was rejected"

    START_TLS_CMD = b". STARTTLS\r\n"
    START_TLS_OK = b". OK"


class _Pop3Helper(_GenericOpportunisticTlsHelper):
    ERR_NO_STARTTLS = "POP START TLS was rejected"

    START_TLS_CMD = b"STLS\r\n"
    START_TLS_OK = b"+OK"


class _FtpHelper(_GenericOpportunisticTlsHelper):
    ERR_NO_STARTTLS = "FTP AUTH TLS was rejected"

    START_TLS_CMD = b"AUTH TLS\r\n"
    START_TLS_OK = b"234"


class _PostgresHelper(_GenericOpportunisticTlsHelper):
    ERR_NO_STARTTLS = "Postgres AUTH TLS was rejected"

    START_TLS_CMD = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
    START_TLS_OK = b"S"
    SHOULD_WAIT_FOR_SERVER_BANNER = False


_START_TLS_HELPER_CLASSES = {
    ProtocolWithOpportunisticTlsEnum.SMTP: _SmtpHelper,
    ProtocolWithOpportunisticTlsEnum.XMPP: _XmppHelper,
    ProtocolWithOpportunisticTlsEnum.XMPP_SERVER: _XmppServerHelper,
    ProtocolWithOpportunisticTlsEnum.POP3: _Pop3Helper,
    ProtocolWithOpportunisticTlsEnum.IMAP: _ImapHelper,
    ProtocolWithOpportunisticTlsEnum.FTP: _FtpHelper,
    ProtocolWithOpportunisticTlsEnum.LDAP: _LdapHelper,
    ProtocolWithOpportunisticTlsEnum.RDP: _RdpHelper,
    ProtocolWithOpportunisticTlsEnum.POSTGRES: _PostgresHelper,
}


def get_opportunistic_tls_helper(
    protocol: ProtocolWithOpportunisticTlsEnum, xmpp_to_hostname: Optional[str], smtp_ehlo_hostname: Optional[str]
) -> _OpportunisticTlsHelper:
    helper_cls = _START_TLS_HELPER_CLASSES[protocol]
    if protocol in [ProtocolWithOpportunisticTlsEnum.XMPP, ProtocolWithOpportunisticTlsEnum.XMPP_SERVER]:
        if xmpp_to_hostname is None:
            raise ValueError("Received None for xmpp_to_hostname")
        opportunistic_tls_helper = helper_cls(xmpp_to=xmpp_to_hostname)
    elif protocol == ProtocolWithOpportunisticTlsEnum.SMTP:
        opportunistic_tls_helper = helper_cls(smtp_ehlo_hostname=smtp_ehlo_hostname)
    else:
        opportunistic_tls_helper = helper_cls()

    return opportunistic_tls_helper
