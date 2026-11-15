"""Tests of the RadSec (RFC 6614, RADIUS over TLS) transport.

The environment these tests run in cannot bind a listening TCP port, so the
TLS server and client are connected over a local, already-connected
non-blocking socket pair instead (``RadSecServer.start_on_socket`` and
``RadSecClient.connect_socket``). Everything above the transport - mutual
TLS authentication, certificate-to-identity mapping, RADIUS frame
reassembly and the packet handlers - is exercised exactly as over a real
socket. Certificates are generated in memory by ``radsec_certs``; there is
no external authentication server.
"""
import asyncio
import shutil
import socket
import ssl
import struct
import tempfile
import unittest
from io import StringIO

from pyrad import packet, radsec
from pyrad.dictionary import Dictionary
from pyrad.radsec import (
    RadSecClient,
    RadSecFramer,
    RadSecFrameError,
    RadSecPeer,
    RadSecServer,
    RadSecTruncatedError,
    client_ssl_context,
    server_ssl_context,
    certificate_identity,
)
from pyrad.tests.radsec_certs import create_cert_bundle

SECRET = b'radsec-test-secret'
PASSWORD = 'password'
DICTIONARY = '''
ATTRIBUTE User-Name             1  string
ATTRIBUTE User-Password         2  string
ATTRIBUTE Reply-Message         18 string
ATTRIBUTE Acct-Status-Type      40 integer
ATTRIBUTE Acct-Session-Id       44 string
VALUE     Acct-Status-Type      Start 1
'''


class RecordingServer(RadSecServer):
    """Server that records requests and answers Access-Requests itself."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = []
        self.peers = []

    def handle_auth_packet(self, connection, pkt, addr):
        self.received.append(pkt)
        self.peers.append(pkt.radsec_peer)
        reply = self.create_reply_packet(pkt, Reply_Message='hello')
        if pkt.PwDecrypt(pkt[2][0]) == PASSWORD:
            reply.code = packet.AccessAccept
        else:
            reply.code = packet.AccessReject
        connection.send_response(reply)

    def handle_acct_packet(self, connection, pkt, addr):
        self.received.append(pkt)
        self.peers.append(pkt.radsec_peer)
        connection.send_response(self.create_reply_packet(pkt))

    def handle_coa_packet(self, connection, pkt, addr):
        self.received.append(pkt)
        connection.send_response(self.create_reply_packet(pkt))

    def handle_disconnect_packet(self, connection, pkt, addr):
        self.received.append(pkt)
        reply = self.create_reply_packet(pkt)
        reply.code = packet.DisconnectACK
        connection.send_response(reply)


def trusted_peer_factory(peercert):
    identity = certificate_identity(peercert)
    if identity == 'trusted-client':
        return RadSecPeer(identity=identity)
    return None


class RadSecTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.tmpdir = tempfile.mkdtemp()
        self.paths = create_cert_bundle(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def server_context(self):
        return server_ssl_context(
            self.paths['server_crt'], self.paths['server_key'],
            self.paths['ca_crt'])

    def client_context(self, rogue=False, hostname=None):
        label = 'rogue' if rogue else 'client'
        return client_ssl_context(
            self.paths[label + '_crt'], self.paths[label + '_key'],
            self.paths['ca_crt'], hostname)

    def make_server(self, peer_factory=trusted_peer_factory, **kwargs):
        options = dict(secret=SECRET, frame_timeout=5.0)
        options.update(kwargs)
        return RecordingServer(self.server_context(), self.dict,
                               peer_factory, **options)

    def make_client(self, context=None, **kwargs):
        if context is None:
            context = self.client_context()
        options = dict(secret=SECRET, timeout=5.0)
        options.update(kwargs)
        return RadSecClient(context[0], context[1], self.dict, **options)

    def socket_pair(self):
        server_sock, client_sock = socket.socketpair(socket.AF_UNIX)
        server_sock.setblocking(False)
        client_sock.setblocking(False)
        return server_sock, client_sock

    def make_silent_server(self, **kwargs):
        # accepts and authenticates peers but never answers a request
        server = self.make_server(peer_factory=trusted_peer_factory, **kwargs)
        server.handle_auth_packet = lambda connection, pkt, addr: None
        return server

    async def connect_silent_pair(self, server=None, **client_kwargs):
        server = server or self.make_silent_server()
        client = self.make_client(**client_kwargs)
        server_sock, client_sock = self.socket_pair()
        await asyncio.gather(
            server.start_on_socket(server_sock),
            client.connect_socket(client_sock),
        )
        return server, client

    async def connect_pair(self, server=None, client=None,
                           server_kwargs=None, **client_kwargs):
        server = server or self.make_server(**(server_kwargs or {}))
        client = client or self.make_client(**client_kwargs)
        server_sock, client_sock = self.socket_pair()
        # establish both TLS ends concurrently so handshake bytes flow
        await asyncio.gather(
            server.start_on_socket(server_sock),
            client.connect_socket(client_sock),
        )
        return server, client


class FramerTests(unittest.TestCase):
    def testCoalescedAndFragmentedFrames(self):
        framer = RadSecFramer()
        frame_a = self._frame(1)
        frame_b = self._frame(2)
        # both frames in one read (coalescing), then byte-by-byte (fragmented)
        frames = list(framer.feed(frame_a + frame_b))
        self.assertEqual(frames, [frame_a, frame_b])
        framer = RadSecFramer()
        collected = []
        for byte in frame_a:
            collected.extend(framer.feed(bytes((byte,))))
        self.assertEqual(collected, [frame_a])

    def testLengthFieldIsAuthoritative(self):
        # Length says 40 but only the header is present: wait, then fail at EOF
        framer = RadSecFramer()
        header = struct.pack('!BBH', packet.AccessRequest, 1, 40) + b'0' * 16
        self.assertEqual(list(framer.feed(header)), [])
        with self.assertRaises(RadSecTruncatedError):
            framer.finish()

    def testOversizedLengthRejected(self):
        framer = RadSecFramer(max_frame=100)
        header = struct.pack('!BBH', packet.AccessRequest, 1, 101) + b'0' * 16
        with self.assertRaises(RadSecFrameError):
            list(framer.feed(header))

    def testLengthBelowHeaderRejected(self):
        framer = RadSecFramer()
        header = struct.pack('!BBH', packet.AccessRequest, 1, 19) + b'0' * 16
        with self.assertRaises(RadSecFrameError):
            list(framer.feed(header))

    def testTrailingPartialFrameIsTruncation(self):
        framer = RadSecFramer()
        full = self._frame(3)
        partial = struct.pack('!BBH', packet.AccessRequest, 9, 50) + b'0' * 16
        frames = list(framer.feed(full + partial))
        self.assertEqual(frames, [full])
        with self.assertRaises(RadSecTruncatedError):
            framer.finish()

    @staticmethod
    def _frame(identifier):
        pkt = packet.AuthPacket(id=identifier, secret=b'x')
        return pkt.RequestPacket()


class RadSecRoundTripTests(RadSecTestBase):
    async def testMutualTlsAuthAndMultipleRequests(self):
        server, client = await self.connect_pair()
        try:
            for index in range(3):
                req = client.create_auth_packet(User_Name='alice')
                req['User-Password'] = req.PwCrypt(PASSWORD)
                reply = await client.send_packet(req)
                self.assertEqual(reply.code, packet.AccessAccept)
                self.assertEqual(reply['Reply-Message'], ['hello'])
            # the server saw the certificate-derived identity, not an address
            self.assertEqual(len(server.received), 3)
            self.assertTrue(all(
                peer.identity == 'trusted-client' for peer in server.peers))
            # packets were decoded with the configured RadSec secret
            self.assertTrue(all(
                pkt.secret == SECRET for pkt in server.received))
        finally:
            await client.close()
            await server.close()

    async def testAccountingAndAccessReject(self):
        server, client = await self.connect_pair()
        try:
            acct = client.create_acct_packet(
                User_Name='alice', Acct_Status_Type='Start',
                Acct_Session_Id='1')
            reply = await client.send_packet(acct)
            self.assertEqual(reply.code, packet.AccountingResponse)

            req = client.create_auth_packet(User_Name='alice')
            req['User-Password'] = req.PwCrypt('wrong-password')
            reply = await client.send_packet(req)
            self.assertEqual(reply.code, packet.AccessReject)
            self.assertEqual(len(server.received), 2)
        finally:
            await client.close()
            await server.close()

    async def testMultipleRequestsMultiplexedOnOneConnection(self):
        server, client = await self.connect_pair()
        try:
            requests = []
            for index in range(3):
                req = client.create_auth_packet(User_Name='alice')
                req['User-Password'] = req.PwCrypt(PASSWORD)
                requests.append(req)
            # concurrent requests share the one TLS connection; replies are
            # matched by identifier despite the coalesced frames
            replies = await asyncio.gather(
                *(client.send_packet(req) for req in requests))
            self.assertEqual([r.code for r in replies],
                             [packet.AccessAccept] * 3)
            self.assertEqual(len(server.received), 3)
        finally:
            await client.close()
            await server.close()


class RadSecSecurityTests(RadSecTestBase):
    async def testCertificateFromUntrustedCaIsRejected(self):
        # the server trusts only the test CA; the rogue client cert is signed
        # by another CA and the TLS handshake must fail
        server = self.make_server()
        client = self.make_client(context=self.client_context(rogue=True))
        server_sock, client_sock = self.socket_pair()
        with self.assertRaises(ssl.SSLError):
            await asyncio.gather(
                server.start_on_socket(server_sock),
                client.connect_socket(client_sock),
            )
        # no connection, hence no handler invocation
        self.assertEqual(server.received, [])
        await server.close()

    async def testUnknownPeerIsRejectedAfterValidHandshake(self):
        # a cert that validates against the CA but maps to no identity
        def reject_all(peercert):
            return None

        server = self.make_server(peer_factory=reject_all)
        client = self.make_client()
        server_sock, client_sock = self.socket_pair()
        server_transport, _ = await asyncio.gather(
            server.start_on_socket(server_sock),
            client.connect_socket(client_sock),
        )
        # let the server close the accepted connection itself
        await asyncio.sleep(0.1)
        self.assertEqual(server.received, [])
        self.assertEqual(server._connections, set())
        await client.close()
        await server.close()

    async def testSecretMismatchDropsAuthenticator(self):
        # both peers authenticate, but a different RadSec secret makes the
        # Message-Authenticator verification fail and the handler not run
        server = self.make_server(secret=SECRET)
        client = self.make_client(secret=b'a-different-secret')
        server_sock, client_sock = self.socket_pair()
        await asyncio.gather(
            server.start_on_socket(server_sock),
            client.connect_socket(client_sock),
        )
        with self.assertRaises(TimeoutError):
            req = client.create_auth_packet(User_Name='alice')
            req['User-Password'] = req.PwCrypt(PASSWORD)
            await client.send_packet(req)
        self.assertEqual(server.received, [])
        await client.close()
        await server.close()

    async def testOversizedFrameClosesConnectionWithoutHandler(self):
        # a complete frame whose Length field exceeds the configured maximum
        server, client = await self.connect_pair(
            server_kwargs={'max_frame': 2048})
        # the client only relays the raw bytes and must not reject them first
        client.framer = RadSecFramer(5000)
        try:
            req = client.create_auth_packet(User_Name='alice')
            raw = req.RequestPacket()
            # keep the real packet body but claim a length over the limit;
            # pad so the promised number of bytes actually arrives
            evil = struct.pack('!BBH', packet.AccessRequest, req.id, 4000) \
                + raw[4:] + b'0' * (4000 - len(raw))
            client.writer.write(evil)
            await client.writer.drain()
            await asyncio.sleep(0.1)
            self.assertEqual(server.received, [])
            self.assertEqual(server._connections, set())
        finally:
            await client.close()
            await server.close()

    async def testTruncatedFrameDoesNotCallHandler(self):
        server, client = await self.connect_pair()
        try:
            req = client.create_auth_packet(User_Name='alice')
            raw = req.RequestPacket()
            # a header that promises a full packet followed by EOF
            client.writer.write(raw[:20])
            await client.writer.drain()
            client.writer.close()
            await asyncio.sleep(0.1)
            self.assertEqual(server.received, [])
            self.assertEqual(server._connections, set())
        finally:
            await server.close()

    async def testHalfFrameTimeout(self):
        server = self.make_server(frame_timeout=0.2)
        client = self.make_client(timeout=1.0)
        server_sock, client_sock = self.socket_pair()
        await asyncio.gather(
            server.start_on_socket(server_sock),
            client.connect_socket(client_sock),
        )
        try:
            req = client.create_auth_packet(User_Name='alice')
            raw = req.RequestPacket()
            # send only the header (declares a longer frame) and then stall
            client.writer.write(raw[:20])
            await client.writer.drain()
            await asyncio.sleep(0.5)
            self.assertEqual(server.received, [])
            self.assertEqual(server._connections, set())
        finally:
            await client.close()
            await server.close()


class RadSecClientErrorTests(RadSecTestBase):
    async def testClientIgnoresInvalidReplyAndKeepsRequestPending(self):
        # silent server: the test injects the replies itself, so no valid
        # reply can complete the request before the forged one is rejected
        server, client = await self.connect_silent_pair()
        try:
            req = client.create_auth_packet(User_Name='alice')
            req['User-Password'] = req.PwCrypt(PASSWORD)
            future = asyncio.ensure_future(client.send_packet(req))
            await self._wait_until(lambda: req.id in client._pending)
            server_connection = next(iter(server._connections))
            # a well-formed frame whose Response Authenticator was signed
            # with another secret: VerifyReply must reject it
            forged = packet.AuthPacket(
                code=packet.AccessAccept, id=req.id, secret=b'forged',
                authenticator=req.authenticator, dict=self.dict)
            forged.message_authenticator = True
            server_connection.writer.write(forged.ReplyPacket())
            await asyncio.sleep(0.1)
            # the forged reply is ignored, the request stays pending
            self.assertFalse(future.done())
            self.assertIn(req.id, client._pending)
            # a valid reply afterwards still completes it
            valid_reply = packet.AuthPacket(
                code=packet.AccessAccept, id=req.id, secret=SECRET,
                authenticator=req.authenticator, dict=self.dict)
            valid_reply.message_authenticator = True
            server_connection.writer.write(valid_reply.ReplyPacket())
            reply = await asyncio.wait_for(future, timeout=2)
            self.assertEqual(reply.code, packet.AccessAccept)
        finally:
            await client.close()
            await server.close()

    async def testClientClosesOnInvalidFrameFromServer(self):
        # an invalid Length frame is a transport-level error: pending
        # requests fail instead of hanging forever.
        server, client = await self.connect_silent_pair()
        try:
            req = client.create_auth_packet(User_Name='alice')
            req['User-Password'] = req.PwCrypt(PASSWORD)
            future = asyncio.ensure_future(client.send_packet(req))
            await self._wait_until(lambda: req.id in client._pending)
            server_connection = next(iter(server._connections))
            bad_length = struct.pack('!BBH', packet.AccessAccept, req.id, 19)
            server_connection.writer.write(bad_length + b'x' * 16)
            with self.assertRaises(ConnectionError):
                await future
        finally:
            await client.close()
            await server.close()

    @staticmethod
    async def _wait_until(condition):
        while not condition():
            await asyncio.sleep(0.01)

    async def testServerCloseFailsPendingRequest(self):
        # a silent server that drops the connection must fail the pending
        # request instead of leaving it waiting for the full timeout
        server, client = await self.connect_silent_pair()
        try:
            req = client.create_auth_packet(User_Name='alice')
            req['User-Password'] = req.PwCrypt(PASSWORD)
            future = asyncio.ensure_future(client.send_packet(req))
            await self._wait_until(lambda: req.id in client._pending)
            await server.close()
            with self.assertRaises(ConnectionAbortedError):
                await future
        finally:
            await client.close()

    async def testSendBeforeConnectFails(self):
        client = self.make_client()
        req = client.create_auth_packet(User_Name='alice')
        with self.assertRaises(radsec.RadSecError):
            await client.send_packet(req)

    async def testDuplicateIdentifierRejected(self):
        server, client = await self.connect_silent_pair()
        try:
            first = client.create_auth_packet(User_Name='alice')
            first['User-Password'] = first.PwCrypt(PASSWORD)
            future = asyncio.ensure_future(client.send_packet(first))
            await self._wait_until(lambda: first.id in client._pending)
            # a second request forced onto the same identifier is refused
            second = client.create_auth_packet(User_Name='bob')
            second.id = first.id
            with self.assertRaises(radsec.RadSecError):
                await client.send_packet(second)
            # the original request is untouched and still pending
            self.assertIn(first.id, client._pending)
            future.cancel()
        finally:
            await client.close()
            await server.close()


class CertificateIdentityTests(unittest.TestCase):
    def testCommonNameIdentity(self):
        peercert = {'subject': ((('commonName', 'trusted-client'),),)}
        self.assertEqual(certificate_identity(peercert), 'trusted-client')

    def testSansFallbackAndEmptyCert(self):
        self.assertIsNone(certificate_identity({}))
        peercert = {'subject': (), 'subjectAltName': (('DNS', 'host.example'),)}
        self.assertEqual(certificate_identity(peercert), 'host.example')

    def testPeerSecretMustBeBytes(self):
        with self.assertRaises(TypeError):
            RadSecPeer(identity='x', secret='not-bytes')
        peer = RadSecPeer(identity='x')
        self.assertIsNone(peer.secret)
