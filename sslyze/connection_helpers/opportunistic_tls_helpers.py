import socket
import struct
from abc import abstractmethod, ABC
from enum import Enum
from typing import ClassVar, List, Optional, Tuple


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
    """Perform an SMTP StartTLS negotiation.

    The negotiation is implemented directly on top of the socket (instead of smtplib) so that:
    * The full reply to each command (greeting, EHLO, STARTTLS) is tracked, including multiline
      replies, however fragmented the underlying reads are.
    * Bytes are consumed one at a time, ensuring that no data belonging to the subsequent TLS
      handshake is ever read from the socket during the plaintext negotiation.
    """

    # Upper bound on the size of a single reply line, to prevent a broken or malicious server
    # from making the client read an unbounded amount of data
    _MAX_REPLY_LINE_LENGTH = 8192

    def __init__(self, smtp_ehlo_hostname: str):
        self._smtp_ehlo_hostname = smtp_ehlo_hostname

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        try:
            self._do_starttls_negotiation(sock)
        except Exception:
            # The negotiation failed; the socket cannot be reused so close it right away.
            # socket.timeout and OSError are re-raised as-is so the caller's retry logic applies;
            # protocol-level problems were already converted to OpportunisticTlsError
            sock.close()
            raise

    def _do_starttls_negotiation(self, sock: socket.socket) -> None:
        # Wait for the server greeting
        code, reply_lines = self._read_full_reply(sock)
        if code != 220:
            raise OpportunisticTlsError(
                f"Server did not send a '220 service ready' SMTP message: {_format_smtp_reply(reply_lines)}"
            )

        # Send EHLO and parse the server's extensions
        self._send_command(sock, f"EHLO {self._smtp_ehlo_hostname}\r\n".encode("utf-8"))
        code, reply_lines = self._read_full_reply(sock)
        if code != 250:
            raise OpportunisticTlsError(f"SMTP EHLO was rejected: {_format_smtp_reply(reply_lines)}")

        if not any(line.split(" ", 1)[0].upper() == "STARTTLS" for line in reply_lines):
            raise OpportunisticTlsError("Server does not support STARTTLS with SMTP")

        # Request the TLS upgrade; only a complete 220 reply means the handshake can start
        self._send_command(sock, b"STARTTLS\r\n")
        code, reply_lines = self._read_full_reply(sock)
        if code != 220:
            raise OpportunisticTlsError(f"SMTP STARTTLS rejected: {_format_smtp_reply(reply_lines)}")

    @staticmethod
    def _send_command(sock: socket.socket, command: bytes) -> None:
        # sendall() to transparently handle partial writes
        sock.sendall(command)

    @classmethod
    def _read_full_reply(cls, sock: socket.socket) -> Tuple[int, List[str]]:
        """Read a complete, possibly multiline, SMTP reply.

        Returns the reply code and the text of each reply line. A rejection code or an
        unterminated multiline reply can never be mistaken for a success, regardless of what
        text the server puts in subsequent lines.
        """
        reply_code: Optional[int] = None
        reply_lines: List[str] = []
        while True:
            line = cls._read_reply_line(sock)
            if len(line) < 3 or not line[:3].isdigit():
                raise OpportunisticTlsError(f"Received a malformed SMTP reply line: {line!r}")

            line_code = int(line[:3])
            if reply_code is None:
                reply_code = line_code
            elif line_code != reply_code:
                raise OpportunisticTlsError(
                    f"Received an inconsistent SMTP multiline reply: {_format_smtp_reply(reply_lines + [line])}"
                )

            # Per RFC 5321, a "-" after the reply code means more lines are coming;
            # a space (or nothing) marks the last line of the reply
            separator = line[3:4]
            if separator == "-":
                reply_lines.append(line[4:])
            elif separator in (" ", ""):
                reply_lines.append(line[4:])
                return reply_code, reply_lines
            else:
                raise OpportunisticTlsError(f"Received a malformed SMTP reply line: {line!r}")

    @classmethod
    def _read_reply_line(cls, sock: socket.socket) -> str:
        """Read a single CRLF-terminated reply line, one byte at a time.

        Reading one byte at a time guarantees that no byte past the end of the reply (i.e. data
        belonging to the next stage of the connection, such as the TLS handshake) is consumed.
        Short reads are handled by looping; a timeout is propagated to the caller as-is.
        """
        line_bytes = bytearray()
        while True:
            next_byte = sock.recv(1)
            if not next_byte:
                raise OpportunisticTlsError(
                    "Server unexpectedly closed the connection during the SMTP STARTTLS negotiation"
                )
            line_bytes += next_byte
            if next_byte == b"\n":
                break
            if len(line_bytes) > cls._MAX_REPLY_LINE_LENGTH:
                raise OpportunisticTlsError("Received an SMTP reply line that was too long")

        return line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")


def _format_smtp_reply(reply_lines: List[str]) -> str:
    return " ".join(reply_lines)


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


class _LdapHelper(_OpportunisticTlsHelper):
    """Performs an LDAP StartTLS negotiation."""

    START_TLS_CMD = b"0\x1d\x02\x01\x01w\x18\x80\x161.3.6.1.4.1.1466.20037"
    START_TLS_OK = b"\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04"
    START_TLS_OK2 = b"Start TLS request accepted"
    START_TLS_OK_APACHEDS = (
        b"\x30\x26\x02\x01\x01\x78\x21\x0a\x01\x00\x04\x00\x04\x00\x8a\x16\x31\x2e\x33\x2e\x36"
        b"\x2e\x31\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x2e\x32\x30\x30\x33\x37\x8b\x00"
    )

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        sock.send(self.START_TLS_CMD)
        data = sock.recv(2048)
        if self.START_TLS_OK not in data and self.START_TLS_OK_APACHEDS not in data and self.START_TLS_OK2 not in data:
            raise OpportunisticTlsError(f"LDAP AUTH TLS was rejected; returned: {repr(data)}")


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
