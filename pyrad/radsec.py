# radsec.py
#
# RFC 6614 RadSec (RADIUS over TLS): an asyncio TLS transport adapter.
#
# This module is independent of the UDP transports (pyrad.server_async and
# pyrad.client_async). It reuses pyrad's Packet classes for encoding and
# decoding and the same packet handler call signature, but the trust
# decision is based on the authenticated TLS peer certificate, never on the
# connection address or on packet attributes.
"""RADIUS over TLS (RadSec, RFC 6614) on top of asyncio.

RadSec carries RADIUS packets over a mutually authenticated TLS connection.
Each RADIUS packet occupies one length-prefixed frame (RFC 6614 section 2.4
and RFC 2865 section 3): the four-octet RADIUS header starts with code and
identifier and its two-octet Length field gives the whole packet, including
the header. A TLS stream can deliver several frames at once (coalescing) or
a frame in several chunks (fragmentation); :class:`RadSecFramer` reassembles
it from the Length field.

Trust model
-----------
UDP RADIUS identifies a client by its source address and looks up a shared
secret per address. RadSec cannot work that way: the connection is
authenticated by TLS instead. The server requires and verifies the client
certificate, and the application maps the authenticated certificate to a
:class:`RadSecPeer`. Only that mapping decides the RADIUS identity and its
permissions; the TCP address and packet attributes are never used for it.

Shared secret
-------------
RFC 6614 section 2.5 states that TLS provides the confidentiality and
integrity the RADIUS shared secret provides over UDP, so the shared secret
is not used to authenticate the connection and any value may be used. There
is therefore one configured RadSec secret for the whole listener (and one on
the client), not a per-source-address secret. The value is still used for the
RADIUS authenticators and Message-Authenticator, so both ends must use the
same value.
"""

__docformat__ = "restructuredtext en"

import asyncio
import logging
import ssl
import struct
import time

from pyrad.packet import (
    Packet,
    AuthPacket,
    AcctPacket,
    CoAPacket,
    AccessAccept,
    AccessReject,
    AccountingResponse,
    DisconnectACK,
    DisconnectNAK,
    DisconnectRequest,
    CoARequest,
    CoAACK,
    CoANAK,
    AccountingRequest,
    AccessRequest,
    PacketError,
)
from pyrad.server import CheckMessageAuthenticator, ServerPacketError

# RADIUS packets are at most 4096 octets (RFC 2865); pyrad's Packet decoder
# already rejects anything longer than 8192. RadSec uses the smaller bound
# for the length-prefixed stream frames.
RADSEC_DEFAULT_MAX_FRAME = 4096
RADSEC_HEADER_SIZE = 4
RADSEC_MIN_PACKET = 20

# RFC 6614 2.5: the secret does not authenticate the TLS connection, any
# value works. A single fixed value is used instead of a per-address UDP
# secret; both ends must agree on it for the RADIUS authenticators.
RADSEC_DEFAULT_SECRET = b'radsec'


class RadSecError(Exception):
    """Base class for errors of the RadSec transport."""


class RadSecPeerError(RadSecError):
    """The TLS peer could not be mapped to a trusted RADIUS identity.

    Raised when a connection presents no verifiable certificate or a
    certificate the application does not trust. The connection is closed and
    no business handler is called.
    """


class RadSecFrameError(RadSecError):
    """A received frame is invalid: bad Length, oversized or truncated.

    The connection carrying the frame is closed; a half frame at end of
    stream raises :class:`RadSecTruncatedError` instead.
    """


class RadSecTruncatedError(RadSecFrameError):
    """The stream ended in the middle of a frame (a half frame)."""


class RadSecPeer:
    """A trusted RADIUS identity derived from an authenticated TLS peer.

    Created by the ``peer_factory`` of :class:`RadSecServer` from the
    verified certificate of a connection. The RADIUS packets received on that
    connection are decoded with :attr:`secret` and handled in the context of
    this peer; the connection address never takes part in the decision.

    :ivar identity: stable name of the trusted RADIUS identity, e.g. the
        common name or a SAN of the certificate
    :type identity: str
    :ivar secret: RADIUS shared secret used on this connection (RFC 6614 2.5)
    :type secret: bytes
    :ivar peercert: the verified TLS certificate, as returned by
        :meth:`ssl.SSLSocket.getpeercert`
    :type peercert: dict
    """

    def __init__(self, identity, secret=None, peercert=None):
        if secret is not None and not isinstance(secret, bytes):
            raise TypeError('secret must be a binary string')
        self.identity = identity
        self.secret = secret
        self.peercert = peercert

    def __repr__(self):
        return 'RadSecPeer(identity=%r)' % (self.identity,)


def certificate_identity(peercert):
    """Return a stable identity string from a verified certificate.

    Uses the first subject common name, falling back to the first DNS
    subject alternative name. The certificate has already been verified by
    TLS against the configured CA before this is called.

    :param peercert: verified peer certificate
    :type peercert: dict
    :return: identity, or None if the certificate has no common name or DNS
        SAN
    :rtype: str
    """
    if not peercert:
        return None
    subject = peercert.get('subject', ())
    for rdn in subject:
        for (name, value) in rdn:
            if name == 'commonName' and value:
                return value
    for (name, value) in peercert.get('subjectAltName', ()):
        if name == 'DNS' and value:
            return value
    return None


class RadSecFramer:
    """Reassemble length-prefixed RADIUS frames from a byte stream.

    Fed arbitrary byte chunks with :meth:`feed`; each complete frame is
    returned as soon as it is available, so coalesced frames are split and
    fragmented frames are joined. The Length field (octets 2-3, network byte
    order) is authoritative: a declared length below the 20-octet RADIUS
    header, above ``max_frame`` or larger than the data actually received
    makes the frame invalid. A stream that ends with an incomplete frame is
    a truncated (half) frame.

    :ivar max_frame: maximum accepted frame length in octets
    :type max_frame: int
    """

    def __init__(self, max_frame=RADSEC_DEFAULT_MAX_FRAME):
        if max_frame < RADSEC_MIN_PACKET:
            raise ValueError('max_frame must be at least %d' % RADSEC_MIN_PACKET)
        self.max_frame = max_frame
        self._buffer = bytearray()

    @property
    def pending(self):
        """Number of buffered bytes that have not formed a complete frame."""
        return len(self._buffer)

    def feed(self, data):
        """Add received bytes and yield the complete frames they contain.

        :param data: bytes read from the TLS stream
        :type data: bytes
        :return: generator of complete frame byte strings
        :rtype: generator
        :raise RadSecFrameError: a declared Length is invalid or oversized
        """
        self._buffer.extend(data)
        while len(self._buffer) >= RADSEC_HEADER_SIZE:
            (length,) = struct.unpack('!H', bytes(self._buffer[2:4]))
            if length < RADSEC_MIN_PACKET or length > self.max_frame:
                raise RadSecFrameError(
                    'RADIUS frame length %d out of range (20..%d)'
                    % (length, self.max_frame))
            if len(self._buffer) < length:
                # wait for the rest of a fragmented frame
                break
            frame = bytes(self._buffer[:length])
            del self._buffer[:length]
            yield frame

    def finish(self):
        """Check that no partial frame remains when the stream ends.

        :raise RadSecTruncatedError: bytes of an unfinished frame are buffered
        """
        if self._buffer:
            buffered = len(self._buffer)
            self._buffer.clear()
            raise RadSecTruncatedError(
                'Stream ended in the middle of a RADIUS frame (%d buffered '
                'octet(s))' % buffered)


def server_ssl_context(certfile, keyfile, cafile, password=None,
                       minimum_version=ssl.TLSVersion.TLSv1_2):
    """Build the TLS context of a RadSec server.

    The server always requires and verifies a client certificate
    (mutual TLS); a connection without a valid certificate signed by the CA
    in ``cafile`` is refused during the TLS handshake.

    :param certfile: server certificate chain (PEM)
    :type certfile: str
    :param keyfile: private key of the server certificate (PEM)
    :type keyfile: str
    :param cafile: CA certificates trusted to sign client certificates (PEM)
    :type cafile: str
    :param password: password of an encrypted private key
    :type password: str or bytes
    :param minimum_version: minimum TLS protocol version, TLS 1.2 by default
    :type minimum_version: ssl.TLSVersion
    :return: configured server context
    :rtype: ssl.SSLContext
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile, password=password)
    context.load_verify_locations(cafile=cafile)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    context.minimum_version = minimum_version
    return context


def client_ssl_context(certfile, keyfile, cafile, server_hostname,
                       password=None,
                       minimum_version=ssl.TLSVersion.TLSv1_2):
    """Build the TLS context and server hostname of a RadSec client.

    The client presents its own certificate for mutual TLS and verifies the
    server against the CA in ``cafile``. Host name verification is enabled
    when ``server_hostname`` is given; pass ``None`` to verify the chain and
    trust anchor only (e.g. for tests with address-only endpoints).

    :param certfile: client certificate chain (PEM)
    :type certfile: str
    :param keyfile: private key of the client certificate (PEM)
    :type keyfile: str
    :param cafile: CA certificate trusted to sign the server certificate (PEM)
    :type cafile: str
    :param server_hostname: name to verify the server certificate against,
        or None to disable host name verification
    :type server_hostname: str or None
    :param password: password of an encrypted private key
    :type password: str or bytes
    :param minimum_version: minimum TLS protocol version, TLS 1.2 by default
    :type minimum_version: ssl.TLSVersion
    :return: tuple of the configured client context and the server hostname
        (an empty string when host name verification is disabled)
    :rtype: tuple
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile, keyfile, password=password)
    context.load_verify_locations(cafile=cafile)
    context.minimum_version = minimum_version
    if server_hostname is None:
        context.check_hostname = False
        check_hostname = ''
    else:
        check_hostname = server_hostname
    context.verify_mode = ssl.CERT_REQUIRED
    return context, check_hostname


class _RadSecConnection:
    """One accepted RadSec connection: framer, peer and frame watchdog."""

    def __init__(self, server, reader, writer, peer, max_frame,
                 frame_timeout):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.peer = peer
        self.framer = RadSecFramer(max_frame)
        self.frame_timeout = frame_timeout
        self._closed = False

    @property
    def addr(self):
        return self.writer.get_extra_info('peername')

    async def serve(self):
        try:
            await self._read_frames()
        except (RadSecFrameError, RadSecTruncatedError) as exc:
            self.server.logger.warning(
                'RadSec peer %s: closing connection, %s', self.peer, exc)
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError) as exc:
            self.server.logger.info(
                'RadSec peer %s: connection ended: %s', self.peer, exc)
        except Exception:
            if self.server.debug:
                self.server.logger.exception(
                    'RadSec peer %s: unexpected connection error', self.peer)
            else:
                self.server.logger.error(
                    'RadSec peer %s: unexpected connection error', self.peer)
        finally:
            await self.close()

    async def _read_frames(self):
        # deadline of the frame currently being assembled, measured from its
        # first byte, so a peer that trickles a half frame cannot keep it
        # buffered longer than frame_timeout
        deadline = None
        while True:
            if deadline is None:
                wait = self.frame_timeout
            else:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    raise RadSecTruncatedError(
                        'Timed out waiting for the rest of a RADIUS frame')
            data = await asyncio.wait_for(
                self.reader.read(self.server.read_size), timeout=wait)
            if not data:
                # clean EOF: a buffered half frame is a truncation error
                self.framer.finish()
                break
            complete = list(self.framer.feed(data))
            if self.framer.pending:
                if deadline is None:
                    deadline = time.monotonic() + self.frame_timeout
            else:
                # whole frame(s) consumed, reset for the next one
                deadline = None
            for frame in complete:
                self._handle_frame(frame)

    def _handle_frame(self, frame):
        try:
            req = Packet(packet=frame, dict=self.server.dict)
        except Exception as exc:
            # never feed an undecodable frame to a business handler
            self.server.logger.warning(
                'RadSec peer %s: dropping undecodable frame: %s',
                self.peer, exc)
            raise RadSecFrameError('undecodable RADIUS frame: %s' % exc)

        try:
            if req.code in (AccessAccept, AccessReject, AccountingResponse,
                            CoAACK, CoANAK, DisconnectACK, DisconnectNAK):
                raise ServerPacketError('Invalid response packet %d' % req.code)
            if req.code == AccessRequest:
                req = AuthPacket(secret=self.peer.secret,
                                 dict=self.server.dict, packet=frame)
                CheckMessageAuthenticator(req, self.server.enforce_ma)
            elif req.code == AccountingRequest:
                req = AcctPacket(secret=self.peer.secret,
                                 dict=self.server.dict, packet=frame)
                if self.server.enable_pkt_verify and \
                        not req.VerifyAcctRequest():
                    raise PacketError('Packet verification failed')
            elif req.code in (CoARequest, DisconnectRequest):
                req = CoAPacket(secret=self.peer.secret,
                                dict=self.server.dict, packet=frame)
                if self.server.enable_pkt_verify and \
                        not req.VerifyCoARequest():
                    raise PacketError('Packet verification failed')
            else:
                raise ServerPacketError(
                    'Unknown RADIUS request code %d' % req.code)
        except (ServerPacketError, PacketError) as exc:
            self.server.logger.warning(
                'RadSec peer %s: dropping packet: %s', self.peer, exc)
            return

        req.radsec_peer = self.peer
        try:
            self.server.handle_request(self, req)
        except Exception as exc:
            if self.server.debug:
                self.server.logger.exception(
                    'RadSec peer %s: error in packet handler', self.peer)
            else:
                self.server.logger.error(
                    'RadSec peer %s: error in packet handler: %s',
                    self.peer, exc)

    def send_response(self, reply):
        """Send an encoded reply packet on this connection.

        :param reply: reply packet, e.g. from
            :meth:`RadSecServer.create_reply_packet`
        :type reply: pyrad.packet.Packet
        """
        if self._closed:
            raise RadSecError('connection is closed')
        self.writer.write(reply.ReplyPacket())

    async def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            await self.writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        self.writer.close()
        # wait_closed can raise if the peer already reset the TLS connection
        try:
            await self.writer.wait_closed()
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
            pass


class RadSecServer:
    """A RadSec (RFC 6614) server on top of asyncio.

    Listens with a TLS server context that requires a client certificate,
    maps each authenticated certificate to a trusted :class:`RadSecPeer` and
    handles the RADIUS packets of the connection in the context of that peer.
    The UDP code and its address-based ``hosts`` table are not used.

    Subclass it and implement :meth:`handle_auth_packet`,
    :meth:`handle_acct_packet`, :meth:`handle_coa_packet` and
    :meth:`handle_disconnect_packet`, then await :meth:`start` and finally
    :meth:`close`. The handlers are plain synchronous methods like those of
    :class:`pyrad.server_async.ServerAsync`; start a task for asynchronous
    work and reply from that task.
    """

    def __init__(self, ssl_context, dictionary, peer_factory,
                 secret=RADSEC_DEFAULT_SECRET,
                 max_frame=RADSEC_DEFAULT_MAX_FRAME,
                 frame_timeout=30.0,
                 logger_name='pyrad',
                 enable_pkt_verify=True,
                 enforce_ma=False,
                 debug=False):
        """
        :param ssl_context: server TLS context requiring client certificates,
            e.g. from :func:`server_ssl_context`
        :type ssl_context: ssl.SSLContext
        :param dictionary: RADIUS dictionary used to decode requests
        :type dictionary: pyrad.dictionary.Dictionary
        :param peer_factory: callable taking the verified peer certificate
            and returning a :class:`RadSecPeer`, or None to refuse the
            connection. This is the only place that grants a RADIUS identity.
        :type peer_factory: callable
        :param secret: RadSec shared secret used for packets of peers that do
            not set their own (RFC 6614 2.5); must match the client
        :type secret: bytes
        :param max_frame: maximum accepted RADIUS frame length in octets
        :type max_frame: int
        :param frame_timeout: maximum seconds to wait for further bytes of a
            frame once a connection has data
        :type frame_timeout: float
        :param logger_name: name of the logger
        :type logger_name: str
        :param enable_pkt_verify: verify the authenticator of Accounting, CoA
            and Disconnect requests
        :type enable_pkt_verify: bool
        :param enforce_ma: drop Access-Requests without a
            Message-Authenticator (an invalid one is always dropped)
        :type enforce_ma: bool
        :param debug: log tracebacks instead of one-line messages
        :type debug: bool
        """
        if not isinstance(secret, bytes):
            raise TypeError('secret must be a binary string')
        self.ssl_context = ssl_context
        self.dict = dictionary
        self.peer_factory = peer_factory
        self.secret = secret
        self.max_frame = max_frame
        # one generous read can contain several coalesced frames or a whole
        # oversized frame; RadSecFramer is what bounds and splits them, so the
        # read size must not be tied to max_frame
        self.read_size = 65536
        self.frame_timeout = frame_timeout
        self.logger = logging.getLogger(logger_name)
        self.enable_pkt_verify = enable_pkt_verify
        self.enforce_ma = enforce_ma
        self.debug = debug
        self._server = None
        self._connections = set()

    async def start(self, host='127.0.0.1', port=2083, **kwargs):
        """Start listening for RadSec connections.

        :param host: address to bind
        :type host: str
        :param port: port to bind, the RadSec port (RFC 6614) is 2083
        :type port: int
        :param kwargs: extra arguments of
            :meth:`asyncio.AbstractEventLoop.create_server`, e.g. ``sock``
        :return: the started asyncio server
        :rtype: asyncio.base_events.Server
        """
        self._server = await asyncio.get_running_loop().create_server(
            self._protocol_factory, host=host, port=port,
            ssl=self.ssl_context, **kwargs)
        return self._server

    async def start_on_socket(self, sock, **kwargs):
        """Start serving on an already connected, non-blocking socket.

        Used to attach a single pre-connected transport (mainly for tests in
        environments where binding a listening port is not allowed). The
        socket is wrapped with the TLS server handshake and handled like a
        connection accepted by :meth:`start`.

        :param sock: connected socket, set to non-blocking
        :type sock: socket.socket
        :return: the transport of the connection
        :rtype: asyncio.BaseTransport
        """
        transport, _ = await asyncio.get_running_loop().connect_accepted_socket(
            self._protocol_factory, sock, ssl=self.ssl_context, **kwargs)
        return transport

    def _protocol_factory(self):
        # generous buffer so coalesced or oversized frames reach the framer
        # intact; RadSecFramer enforces the authoritative frame bound.
        reader = asyncio.StreamReader(limit=65536 + RADSEC_HEADER_SIZE)
        # the client_connected_cb receives this reader and its writer once
        # the TLS handshake (including client certificate verification) is
        # done
        return asyncio.StreamReaderProtocol(
            reader, self._on_client_connected)

    async def _on_client_connected(self, reader, writer):
        # StreamReaderProtocol passes the bound reader/writer here after the
        # TLS handshake has completed and the client certificate was verified.
        peer = self._authenticate_peer(writer)
        if peer is None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
                pass
            return
        connection = _RadSecConnection(
            self, reader, writer, peer, self.max_frame, self.frame_timeout)
        self._connections.add(connection)
        try:
            await connection.serve()
        finally:
            self._connections.discard(connection)

    def _authenticate_peer(self, writer):
        """Map the verified certificate to a trusted peer, or refuse.

        Only the TLS certificate is used; the connection address and packet
        contents are never consulted.
        """
        peercert = writer.get_extra_info('peercert')
        try:
            peer = self.peer_factory(peercert)
        except Exception as exc:
            self.logger.warning('RadSec peer_factory raised: %s', exc)
            return None
        if peer is None:
            self.logger.warning(
                'Refusing RadSec connection: no trusted identity for '
                'certificate %s', peercert)
            return None
        if not isinstance(peer, RadSecPeer):
            raise TypeError(
                'peer_factory must return a RadSecPeer or None, got %s'
                % type(peer).__name__)
        if peer.peercert is None:
            peer.peercert = peercert
        if peer.secret is None:
            # the listener-wide RadSec secret (RFC 6614 2.5) applies unless
            # the peer carries its own; it is never chosen by source address
            peer.secret = self.secret
        return peer
    def handle_request(self, connection, req):
        """Dispatch a decoded request to the matching packet handler."""
        if isinstance(req, AuthPacket):
            self.handle_auth_packet(connection, req, connection.addr)
        elif isinstance(req, AcctPacket):
            self.handle_acct_packet(connection, req, connection.addr)
        elif isinstance(req, CoAPacket):
            if req.code == DisconnectRequest:
                self.handle_disconnect_packet(connection, req, connection.addr)
            else:
                self.handle_coa_packet(connection, req, connection.addr)
        else:
            raise ServerPacketError('Unsupported packet type %d' % req.code)

    @staticmethod
    def create_reply_packet(pkt, **attributes):
        """Create a reply to a received request.

        The reply type follows the request (Access-Accept, Accounting-Response,
        CoA-ACK or Disconnect-ACK) and keeps its secret, id, authenticator and
        dictionary. Send it with
        :meth:`_RadSecConnection.send_response`.
        """
        return pkt.CreateReply(**attributes)

    async def close(self):
        """Close the listener and all accepted connections."""
        for connection in list(self._connections):
            await connection.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def handle_auth_packet(self, connection, pkt, addr):
        """Handle an Access-Request; override in a subclass.

        :param connection: the RadSec connection of the trusted peer
        :type connection: _RadSecConnection
        :param pkt: the request, decoded with the peer secret
        :type pkt: pyrad.packet.AuthPacket
        :param addr: peer address, informational only
        """
        raise NotImplementedError

    def handle_acct_packet(self, connection, pkt, addr):
        """Handle an Accounting-Request; override in a subclass."""
        raise NotImplementedError

    def handle_coa_packet(self, connection, pkt, addr):
        """Handle a CoA-Request; override in a subclass."""
        raise NotImplementedError

    def handle_disconnect_packet(self, connection, pkt, addr):
        """Handle a Disconnect-Request; override in a subclass."""
        raise NotImplementedError


class RadSecClient:
    """A RadSec (RFC 6614) client on top of asyncio.

    Opens one mutually authenticated TLS connection to a RadSec server and
    multiplexes RADIUS requests over it. Requests are matched to replies by
    their identifier, like the UDP client, but retransmission is pointless on
    a reliable transport: an unanswered request fails with
    :class:`TimeoutError` after ``timeout`` seconds instead.
    """

    def __init__(self, ssl_context, server_hostname, dictionary,
                 secret=RADSEC_DEFAULT_SECRET,
                 max_frame=RADSEC_DEFAULT_MAX_FRAME,
                 timeout=30.0,
                 logger_name='pyrad',
                 enforce_ma=False):
        """
        :param ssl_context: client TLS context with the client certificate,
            e.g. from :func:`client_ssl_context`
        :type ssl_context: ssl.SSLContext
        :param server_hostname: SNI / host name to verify, or '' to disable
            host name verification
        :type server_hostname: str
        :param dictionary: RADIUS dictionary for the packets
        :type dictionary: pyrad.dictionary.Dictionary
        :param secret: RadSec shared secret, matching the server (RFC 6614
            2.5)
        :type secret: bytes
        :param max_frame: maximum accepted reply frame length in octets
        :type max_frame: int
        :param timeout: seconds to wait for a reply
        :type timeout: float
        :param logger_name: name of the logger
        :type logger_name: str
        :param enforce_ma: require a Message-Authenticator in replies to
            Access-Request and Status-Server
        :type enforce_ma: bool
        """
        if not isinstance(secret, bytes):
            raise TypeError('secret must be a binary string')
        self.ssl_context = ssl_context
        self.server_hostname = server_hostname
        self.dict = dictionary
        self.secret = secret
        self.max_frame = max_frame
        self.timeout = timeout
        self.logger = logging.getLogger(logger_name)
        self.enforce_ma = enforce_ma
        self.reader = None
        self.writer = None
        self.framer = None
        self._pending = {}
        self._next_id = 0
        self._reader_task = None
        self._closed = False

    async def connect(self, host='127.0.0.1', port=2083, **kwargs):
        """Connect to a RadSec server.

        :param host: server address
        :type host: str
        :param port: server port, the RadSec port is 2083
        :type port: int
        :param kwargs: extra arguments of
            :meth:`asyncio.AbstractEventLoop.create_connection`, e.g. ``sock``
        """
        self.reader, self.writer = await asyncio.open_connection(
            host=host, port=port, ssl=self.ssl_context,
            server_hostname=self._server_hostname(), **kwargs)
        self._connected()

    async def connect_socket(self, sock):
        """Connect over an already connected, non-blocking socket.

        Mainly for tests without a bindable port. Host name verification is
        disabled when the client was created without a server hostname.
        """
        # an empty server_hostname is what asyncio requires to skip the
        # otherwise mandatory host name for a connection over a bare socket
        self.reader, self.writer = await asyncio.open_connection(
            sock=sock, ssl=self.ssl_context,
            server_hostname=self.server_hostname or '')
        self._connected()

    def _server_hostname(self):
        return self.server_hostname or None

    def _connected(self):
        self.framer = RadSecFramer(self.max_frame)
        self._reader_task = asyncio.ensure_future(self._read_loop())

    async def _read_loop(self):
        try:
            while True:
                data = await self.reader.read(self.max_frame)
                if not data:
                    # clean end of stream: a buffered half frame is an error,
                    # and any request still waiting can never get a reply
                    self.framer.finish()
                    self._fail_all(
                        ConnectionAbortedError('RadSec server closed the '
                                               'connection'))
                    break
                for frame in self.framer.feed(data):
                    self._handle_frame(frame)
        except (RadSecFrameError, RadSecTruncatedError) as exc:
            self.logger.warning('RadSec server sent an invalid frame: %s', exc)
            self._fail_all(ConnectionError('Invalid frame from server: %s' % exc))
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError) as exc:
            self._fail_all(ConnectionAbortedError('RadSec connection lost: %s' % exc))
        finally:
            self._closed = True

    def _handle_frame(self, frame):
        try:
            reply = Packet(packet=frame, dict=self.dict)
        except Exception as exc:
            self.logger.warning('Ignoring undecodable RadSec reply: %s', exc)
            return
        entry = self._pending.get(reply.id)
        if entry is None:
            self.logger.warning('Ignoring RadSec reply for unknown id %d', reply.id)
            return
        request = entry['packet']
        reply.dict = request.dict
        reply.secret = request.secret
        reply.request_authenticator = request.authenticator
        if request.VerifyReply(reply, frame, enforce_ma=self.enforce_ma):
            future = entry['future']
            self._pending.pop(reply.id, None)
            if not future.done():
                future.set_result(reply)
        else:
            self.logger.warning('Ignoring invalid RadSec reply for id %d', reply.id)

    def _fail_all(self, exc):
        for entry in self._pending.values():
            if not entry['future'].done():
                entry['future'].set_exception(exc)
        self._pending.clear()

    def _allocate_id(self):
        for _ in range(256):
            candidate = self._next_id
            self._next_id = (self._next_id + 1) % 256
            if candidate not in self._pending:
                return candidate
        raise RadSecError('No free packet id, 256 requests are pending')

    def create_auth_packet(self, **args):
        """Create an :class:`~pyrad.packet.AuthPacket` for this connection.

        Gets the client dictionary, secret and a free identifier, and a
        Message-Authenticator by default (countermeasure against
        CVE-2024-3596). Encrypt PAP passwords with
        :meth:`~pyrad.packet.AuthPacket.PwCrypt`.
        """
        args.setdefault('message_authenticator', True)
        return AuthPacket(dict=self.dict, id=self._allocate_id(),
                          secret=self.secret, **args)

    def create_acct_packet(self, **args):
        """Create an :class:`~pyrad.packet.AcctPacket` for this connection."""
        return AcctPacket(dict=self.dict, id=self._allocate_id(),
                          secret=self.secret, **args)

    def create_coa_packet(self, **args):
        """Create a :class:`~pyrad.packet.CoAPacket` for this connection."""
        return CoAPacket(dict=self.dict, id=self._allocate_id(),
                         secret=self.secret, **args)

    async def send_packet(self, pkt):
        """Send a request and await its verified reply.

        :param pkt: a request created with one of the ``create_*`` methods
        :type pkt: pyrad.packet.Packet
        :return: the verified reply packet; inspect ``reply.code``
        :rtype: pyrad.packet.Packet
        :raise TimeoutError: no valid reply arrived within ``timeout``
        :raise ConnectionAbortedError: the connection was closed first
        """
        if self.writer is None or self._closed:
            raise RadSecError('RadSec connection is not open')
        if pkt.id in self._pending:
            raise RadSecError('Packet with id %d already pending' % pkt.id)
        raw = pkt.RequestPacket()
        future = asyncio.get_running_loop().create_future()
        self._pending[pkt.id] = {'packet': pkt, 'future': future}
        try:
            self.writer.write(raw)
            await self.writer.drain()
        except Exception:
            self._pending.pop(pkt.id, None)
            raise
        try:
            return await asyncio.wait_for(future, timeout=self.timeout)
        except asyncio.TimeoutError:
            self._pending.pop(pkt.id, None)
            raise TimeoutError('Timeout waiting for RadSec reply') from None

    async def close(self):
        """Close the connection; pending requests fail."""
        if self.writer is not None:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
                pass
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, RadSecError, ConnectionError):
                pass
        self._fail_all(ConnectionAbortedError('RadSec client closed'))
        self._closed = True
