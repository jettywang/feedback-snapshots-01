"""Tests of the asyncio client and server, running against each other on
the loopback interface."""
import asyncio
import contextlib
import datetime
import hashlib
import logging
import struct
import socket
import unittest
from io import StringIO
from unittest import mock

from pyrad import packet
from pyrad.client_async import ClientAsync, DatagramProtocolClient
from pyrad.dictionary import Dictionary
from pyrad.server import RemoteHost
from pyrad.server_async import DatagramProtocolServer, ServerAsync, ServerType

SECRET = b'secret'
PASSWORD = 'password'
LOCALHOST = '127.0.0.1'
EAP_CHALLENGE = b'0123456789abcdef'

DICTIONARY = '''
ATTRIBUTE User-Name             1  string
ATTRIBUTE User-Password         2  string
ATTRIBUTE Reply-Message         18 string
ATTRIBUTE Acct-Status-Type      40 integer
ATTRIBUTE Acct-Session-Id       44 string
ATTRIBUTE Acct-Delay-Time       41 integer
ATTRIBUTE State                 24 octets
ATTRIBUTE Tunnel-Password       69 string has_tag,encrypt=2
ATTRIBUTE EAP-Message           79 octets
ATTRIBUTE Message-Authenticator 80 octets
VALUE     Acct-Status-Type      Start 1
'''


def free_ports(count):
    sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind((LOCALHOST, 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


@contextlib.contextmanager
def without_reuse_port():
    """Simulate a platform without SO_REUSEPORT, e.g. Windows."""
    reuse_port = getattr(socket, 'SO_REUSEPORT', None)
    if reuse_port is not None:
        del socket.SO_REUSEPORT
    try:
        yield
    finally:
        if reuse_port is not None:
            socket.SO_REUSEPORT = reuse_port


class RadiusServer(ServerAsync):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = []

    def handle_auth_packet(self, protocol, pkt, addr):
        self.received.append(pkt)
        if 79 in pkt:
            protocol.send_response(self.eap_md5_reply(pkt), addr)
            return
        reply = self.CreateReplyPacket(pkt, Reply_Message='hello')
        if pkt.PwDecrypt(pkt[2][0]) == PASSWORD:
            reply.code = packet.AccessAccept
            reply['Tunnel-Password:1'] = 'a-tunnel-password-longer-than-16'
        else:
            reply.code = packet.AccessReject
        protocol.send_response(reply, addr)

    def eap_md5_reply(self, pkt):
        """Answer an EAP-Response/Identity with an MD5 challenge and an
        EAP-Response/MD5-Challenge with Access-Accept or -Reject."""
        eap = pkt[79][0]
        reply = self.CreateReplyPacket(pkt)
        if pkt['User-Name'] != ['alice']:
            reply.code = packet.AccessReject
            return reply
        if eap[4] == 1:  # Identity
            reply.code = packet.AccessChallenge
            reply[79] = [struct.pack('!BBHBB', 1, 7, 22, 4, 16) + EAP_CHALLENGE]
            reply[24] = [b'state']
            return reply
        digest = hashlib.md5(b'\x07' + PASSWORD.encode() + EAP_CHALLENGE).digest()
        accept = eap == struct.pack('!BBHBB', 2, 7, 22, 4, 16) + digest \
            and pkt[24] == [b'state']
        reply.code = packet.AccessAccept if accept else packet.AccessReject
        return reply

    def handle_acct_packet(self, protocol, pkt, addr):
        self.received.append(pkt)
        protocol.send_response(self.CreateReplyPacket(pkt), addr)

    def handle_coa_packet(self, protocol, pkt, addr):
        self.received.append(pkt)
        protocol.send_response(self.CreateReplyPacket(pkt), addr)

    def handle_disconnect_packet(self, protocol, pkt, addr):
        self.received.append(pkt)
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.DisconnectACK
        protocol.send_response(reply, addr)


class AsyncRoundTripTests(unittest.TestCase):
    """ClientAsync sending requests to ServerAsync."""

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.ports = dict(zip(('auth_port', 'acct_port', 'coa_port'), free_ports(3)))

    def run_with(self, test, hosts=None, client_secret=SECRET, **server_args):
        """Run test(client, server) with a started server and client."""
        if hosts is None:
            hosts = {LOCALHOST: RemoteHost(LOCALHOST, SECRET, 'localhost')}

        async def run():
            loop = asyncio.get_running_loop()
            server = RadiusServer(hosts=hosts, dictionary=self.dict, loop=loop,
                                **self.ports, **server_args)
            await server.initialize_transports(enable_auth=True, enable_acct=True,
                                               enable_coa=True, addresses=[LOCALHOST])
            client = ClientAsync(server=LOCALHOST, secret=client_secret, dict=self.dict,
                                 loop=loop, timeout=0.5, retries=1, **self.ports)
            await client.initialize_transports(enable_auth=True, enable_acct=True,
                                               enable_coa=True)
            try:
                return await test(client, server)
            finally:
                await client.deinitialize_transports()
                await server.deinitialize_transports()

        return asyncio.run(run())

    def auth_request(self, client, password=PASSWORD):
        req = client.CreateAuthPacket(User_Name='alice')
        req['User-Password'] = req.PwCrypt(password)
        return req

    def testAccessAccept(self):
        async def test(client, server):
            client.enforce_ma = True
            return await client.SendPacket(self.auth_request(client))
        reply = self.run_with(test)
        self.assertEqual(reply.code, packet.AccessAccept)
        self.assertEqual(reply['Reply-Message'], ['hello'])
        # salt encrypted with the request authenticator
        self.assertEqual(reply['Tunnel-Password:1'], ['a-tunnel-password-longer-than-16'])

    def eap_md5_request(self, client, password=PASSWORD):
        req = client.CreateAuthPacket(auth_type='eap-md5', User_Name='alice')
        req['User-Password'] = password
        return req

    def testEapMd5(self):
        # ClientAsync sent eap-md5 packets as they were, with the cleartext
        # User-Password and without answering the challenge
        async def test(client, server):
            req = self.eap_md5_request(client)
            first_id = req.id
            reply = await client.SendPacket(req)
            return req, first_id, reply, server.received
        req, first_id, reply, received = self.run_with(test)
        self.assertEqual(reply.code, packet.AccessAccept)
        (identity, response) = received
        self.assertEqual(identity[79], [struct.pack('!BBHB', 2, identity[79][0][1], 10, 1)
                                        + b'alice'])
        self.assertNotIn(2, identity)
        self.assertNotIn(2, response)
        self.assertEqual(response[24], [b'state'])
        self.assertNotEqual(response.id, first_id)
        self.assertEqual(req['User-Password'], [PASSWORD])

    def testEapMd5WithoutChallenge(self):
        # the server rejects the EAP-Identity without a challenge
        async def test(client, server):
            req = client.CreateAuthPacket(auth_type='eap-md5', User_Name='mallory')
            req['User-Password'] = PASSWORD
            reply = await client.SendPacket(req)
            return req, reply, server.received
        req, reply, received = self.run_with(test)
        self.assertEqual(reply.code, packet.AccessReject)
        self.assertEqual(len(received), 1)
        self.assertEqual(req['User-Password'], [PASSWORD])

    def testEapMd5LongIdentity(self):
        # RFC 3579 section 3.1: the EAP-Response/Identity is split over
        # several EAP-Message attributes
        user_name = 'a' * 253

        async def test(client, server):
            req = client.CreateAuthPacket(auth_type='eap-md5', User_Name=user_name)
            req['User-Password'] = PASSWORD
            reply = await client.SendPacket(req)
            return reply, server.received
        reply, received = self.run_with(test)
        self.assertEqual(reply.code, packet.AccessReject)
        (identity,) = received
        self.assertEqual(identity['User-Name'], [user_name])
        eap = b''.join(identity[79])
        self.assertEqual(eap[2:], struct.pack('!HB', 258, 1) + user_name.encode())

    def testEapMd5WrongPassword(self):
        async def test(client, server):
            return await client.SendPacket(self.eap_md5_request(client, 'wrong'))
        self.assertEqual(self.run_with(test).code, packet.AccessReject)

    def testEapMd5WithoutPassword(self):
        async def test(client, server):
            req = client.CreateAuthPacket(auth_type='eap-md5', User_Name='alice')
            with self.assertRaises(ValueError):
                client.SendPacket(req)
            return dict(client.protocol_auth.pending_requests)
        self.assertEqual(self.run_with(test), {})

    def testEapMd5Cancelled(self):
        async def test(client, server):
            req = self.eap_md5_request(client)
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(client.SendPacket(req), timeout=0)
            await asyncio.sleep(0)
            return req, dict(client.protocol_auth.pending_requests)
        req, pending = self.run_with(test)
        self.assertEqual(pending, {})
        self.assertEqual(req['User-Password'], [PASSWORD])

    def testAccessReject(self):
        async def test(client, server):
            return await client.SendPacket(self.auth_request(client, 'wrong'))
        self.assertEqual(self.run_with(test).code, packet.AccessReject)

    def testAccounting(self):
        async def test(client, server):
            req = client.CreateAcctPacket(User_Name='alice', Acct_Status_Type='Start',
                                          Acct_Session_Id='1')
            return await client.SendPacket(req)
        reply = self.run_with(test)
        self.assertEqual(reply.code, packet.AccountingResponse)

    def testCoA(self):
        async def test(client, server):
            return await client.SendPacket(client.CreateCoAPacket(User_Name='alice'))
        self.assertEqual(self.run_with(test).code, packet.CoAACK)

    def testDisconnect(self):
        async def test(client, server):
            req = client.CreateCoAPacket(code=packet.DisconnectRequest, User_Name='alice')
            return await client.SendPacket(req)
        self.assertEqual(self.run_with(test).code, packet.DisconnectACK)

    def testPacketVerificationFailure(self):
        # by default the server drops requests with an invalid request
        # authenticator
        async def test(client, server):
            with self.assertRaises(TimeoutError):
                await client.SendPacket(client.CreateAcctPacket(User_Name='alice'))
            with self.assertRaises(TimeoutError):
                await client.SendPacket(client.CreateCoAPacket(User_Name='alice'))
            return server.received
        self.assertEqual(self.run_with(test, client_secret=b'wrong'), [])

    def testPacketVerificationDisabled(self):
        async def test(client, server):
            # the client drops the reply, which is signed with another secret
            with self.assertRaises(TimeoutError):
                await client.SendPacket(client.CreateAcctPacket(User_Name='alice'))
            return server.received
        received = self.run_with(test, client_secret=b'wrong', enable_pkt_verify=False)
        self.assertNotEqual(received, [])

    def testUnknownHost(self):
        async def test(client, server):
            with self.assertRaises(TimeoutError):
                await client.SendPacket(self.auth_request(client))
            return server.received
        self.assertEqual(self.run_with(test, hosts={}), [])

    def testTransportsAreNotBoundTwice(self):
        async def test(client, server):
            protocols = list(server.auth_protocols)
            await server.initialize_transports(enable_auth=True, addresses=[LOCALHOST])
            await client.initialize_transports(enable_auth=True)
            self.assertEqual(server.auth_protocols, protocols)
            return await client.SendPacket(self.auth_request(client))
        self.assertEqual(self.run_with(test).code, packet.AccessAccept)


class AsyncClientTests(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.client = ClientAsync(server=LOCALHOST, secret=SECRET, dict=self.dict,
                                  loop=self.loop)

    def tearDown(self):
        self.loop.close()

    def testNoTransportsSelected(self):
        with self.assertRaises(Exception):
            self.loop.run_until_complete(self.client.initialize_transports())

    def testTransportNotInitialized(self):
        self.assertRaises(Exception, self.client.CreateAuthPacket)
        self.assertRaises(Exception, self.client.CreateAcctPacket)
        self.assertRaises(Exception, self.client.CreateCoAPacket)
        for pkt in (packet.AuthPacket(), packet.AcctPacket(), packet.CoAPacket()):
            self.assertRaises(Exception, self.client.SendPacket, pkt)

    def testCloseTransportCancelsRetryTask(self):
        # the retry task ends as cancelled instead of swallowing the
        # CancelledError, and close_transport still returns normally
        async def test():
            await self.client.initialize_transports(enable_auth=True)
            task = self.client.protocol_auth.timeout_future
            await self.client.deinitialize_transports()
            return task
        task = self.loop.run_until_complete(test())
        self.assertTrue(task.cancelled())

    def testEapMd5TransportNotInitialized(self):
        pkt = packet.AuthPacket(auth_type='eap-md5', secret=SECRET, dict=self.dict,
                                User_Name='alice')
        pkt['User-Password'] = PASSWORD
        self.assertRaises(Exception, self.client.SendPacket, pkt)
        self.assertEqual(pkt['User-Password'], [PASSWORD])

    def testEapMd5SendFails(self):
        # the User-Password is restored if the identity can't be sent
        async def test():
            loop = asyncio.get_running_loop()
            self.client.protocol_auth = self.mock_protocol()
            pkt = self.client.CreateAuthPacket(auth_type='eap-md5', User_Name='alice')
            pkt['User-Password'] = PASSWORD
            # a pending request with the same id
            self.client.protocol_auth.send_packet(
                packet.AuthPacket(id=pkt.id, secret=SECRET, dict=self.dict),
                loop.create_future())
            with self.assertRaises(Exception):
                self.client.SendPacket(pkt)
            return pkt
        pkt = self.loop.run_until_complete(test())
        self.assertEqual(pkt['User-Password'], [PASSWORD])

    def testLoopOutsideRunningLoop(self):
        # without a loop and outside of a running loop, the current event
        # loop is used
        client = ClientAsync(server=LOCALHOST, secret=SECRET, dict=self.dict)
        asyncio.set_event_loop(self.loop)
        try:
            self.assertIs(client.loop, self.loop)
        finally:
            asyncio.set_event_loop(None)

    def testCreateAuthPacketDecodesMessageAuthenticator(self):
        self.client.protocol_auth = self.mock_protocol()
        raw = packet.AuthPacket(secret=SECRET).RequestPacket()
        decoded = self.client.CreateAuthPacket(packet=raw)
        self.assertFalse(decoded.message_authenticator)
        self.assertNotIn(80, decoded)
        self.assertTrue(self.client.CreateAuthPacket().message_authenticator)

    def testUnsupportedPacket(self):
        self.assertRaises(Exception, self.client.SendPacket, packet.Packet())

    def testCreatePacket(self):
        self.assertRaises(Exception, self.client.CreatePacket, None)
        pkt = self.client.CreatePacket(id=10, User_Name='alice')
        self.assertEqual((pkt.id, pkt['User-Name']), (10, ['alice']))
        # 0 is a valid id
        self.assertEqual(self.client.CreatePacket(id=0).id, 0)

    def testPacketIdOfPendingRequestIsSkipped(self):
        # ids wrapped around to the id of a still pending request, and
        # sending the request failed with 'Packet with id N already present'
        async def test():
            loop = asyncio.get_running_loop()
            protocol = self.mock_protocol()
            pending = packet.AuthPacket(id=protocol.create_id(), secret=SECRET,
                                        dict=self.dict)
            protocol.send_packet(pending, loop.create_future())
            # 255 requests which are answered (here: cancelled)
            for _ in range(255):
                future = loop.create_future()
                protocol.send_packet(packet.AuthPacket(id=protocol.create_id(),
                                                       secret=SECRET, dict=self.dict),
                                     future)
                future.cancel()
                await asyncio.sleep(0)
            self.assertEqual(list(protocol.pending_requests), [pending.id])
            req = packet.AuthPacket(id=protocol.create_id(), secret=SECRET, dict=self.dict)
            self.assertNotEqual(req.id, pending.id)
            protocol.send_packet(req, loop.create_future())
        self.loop.run_until_complete(test())

    def testAllPacketIdsPending(self):
        async def test():
            loop = asyncio.get_running_loop()
            protocol = self.mock_protocol()
            for _ in range(256):
                protocol.send_packet(packet.AuthPacket(id=protocol.create_id(),
                                                       secret=SECRET, dict=self.dict),
                                     loop.create_future())
            self.assertEqual(sorted(protocol.pending_requests), list(range(256)))
            with self.assertRaisesRegex(Exception, 'No free packet id'):
                protocol.create_id()
            # an id becomes free again
            protocol.pending_requests[42]['future'].cancel()
            await asyncio.sleep(0)
            self.assertEqual(protocol.create_id(), 42)
        self.loop.run_until_complete(test())

    def testInvalidReplies(self):
        async def test():
            await self.client.initialize_transports(enable_auth=True)
            protocol = self.client.protocol_auth
            req = self.client.CreateAuthPacket(User_Name='alice')
            future = self.client.SendPacket(req)
            # garbage, a reply to an unknown request and a forged reply
            protocol.datagram_received(b'garbage', (LOCALHOST, 1812))
            other = packet.AuthPacket(code=packet.AccessAccept, id=(req.id + 1) % 256,
                                      secret=SECRET, authenticator=16 * b'\x00')
            protocol.datagram_received(other.ReplyPacket(), (LOCALHOST, 1812))
            forged = req.CreateReply()
            forged.secret = b'wrong'
            protocol.datagram_received(forged.ReplyPacket(), (LOCALHOST, 1812))
            self.assertFalse(future.done())
            self.assertIn(req.id, protocol.pending_requests)
            self.assertEqual(str(protocol), f'DatagramProtocolClient(server={LOCALHOST}, port=1812)')
            await self.client.deinitialize_transports()
        self.loop.run_until_complete(test())

    def testDefaultLoop(self):
        async def test():
            client = ClientAsync(server=LOCALHOST, secret=SECRET, dict=self.dict)
            return client.loop is asyncio.get_running_loop()
        self.assertTrue(asyncio.run(test()))

    def testLoopResolvedWhenUsed(self):
        # created outside of a running loop (asyncio.get_event_loop() raises
        # there since Python 3.14), and used with more than one loop
        client = ClientAsync(server=LOCALHOST, secret=SECRET, dict=self.dict)

        async def test():
            return client.loop is asyncio.get_running_loop()
        self.assertTrue(asyncio.run(test()))
        self.assertTrue(asyncio.run(test()))
        client.loop = self.loop
        self.assertIs(client.loop, self.loop)

    def testDuplicatePacketId(self):
        async def test():
            await self.client.initialize_transports(enable_auth=True)
            req = self.client.CreateAuthPacket(User_Name='alice')
            self.client.SendPacket(req)
            with self.assertRaises(Exception):
                self.client.protocol_auth.send_packet(req, self.loop.create_future())
            await self.client.deinitialize_transports()
        self.loop.run_until_complete(test())

    def testLocalAddress(self):
        ports = dict(zip(('local_auth_port', 'local_acct_port', 'local_coa_port'),
                         free_ports(3)))

        async def test():
            await self.client.initialize_transports(enable_auth=True, enable_acct=True,
                                                    enable_coa=True, local_addr=LOCALHOST,
                                                    **ports)
            bound = [protocol.transport.get_extra_info('sockname')
                     for protocol in (self.client.protocol_auth, self.client.protocol_acct,
                                      self.client.protocol_coa)]
            await self.client.deinitialize_transports()
            return bound
        self.assertEqual(self.loop.run_until_complete(test()),
                         [(LOCALHOST, ports['local_auth_port']),
                          (LOCALHOST, ports['local_acct_port']),
                          (LOCALHOST, ports['local_coa_port'])])

    def testLocalAddressWithoutPort(self):
        # local_addr used to be ignored without a local port
        async def test():
            loop = asyncio.get_running_loop()
            with mock.patch.object(loop, 'create_datagram_endpoint',
                                   wraps=loop.create_datagram_endpoint) as connect:
                await self.client.initialize_transports(enable_auth=True, enable_acct=True,
                                                        local_addr=LOCALHOST,
                                                        local_acct_port=free_ports(1)[0])
            await self.client.deinitialize_transports()
            return connect.call_args_list
        calls = self.loop.run_until_complete(test())
        self.assertEqual(calls[1].kwargs['local_addr'], (LOCALHOST, 0))
        self.assertEqual(calls[0].kwargs['local_addr'][0], LOCALHOST)
        self.assertNotEqual(calls[0].kwargs['local_addr'][1], 0)

    def testWithoutReusePort(self):
        # reuse_port=True raised ValueError without SO_REUSEPORT
        async def test():
            with without_reuse_port():
                await self.client.initialize_transports(enable_auth=True)
            self.assertIsNotNone(self.client.protocol_auth.transport)
            await self.client.deinitialize_transports()
        self.loop.run_until_complete(test())

    def testInitializeFailureCanBeRetried(self):
        # a transport which couldn't be opened used to stay registered, so a
        # retry was skipped and SendPacket failed with AttributeError
        async def test():
            loop = asyncio.get_running_loop()
            connect = loop.create_datagram_endpoint

            async def fail_auth(protocol, **kwargs):
                if protocol.port == 1812:
                    raise OSError('bind failed')
                return await connect(protocol, **kwargs)
            with mock.patch.object(loop, 'create_datagram_endpoint', fail_auth):
                with self.assertRaises(OSError):
                    await self.client.initialize_transports(enable_auth=True,
                                                            enable_acct=True)
            self.assertIsNone(self.client.protocol_auth)
            self.assertRaises(Exception, self.client.CreateAuthPacket)
            # the transport opened successfully is kept
            self.assertIsNotNone(self.client.protocol_acct.transport)
            await self.client.initialize_transports(enable_auth=True, enable_acct=True)
            self.assertIsNotNone(self.client.protocol_auth.transport)
            future = self.client.SendPacket(self.client.CreateAuthPacket(User_Name='alice'))
            await self.client.deinitialize_transports()
            with self.assertRaises(ConnectionAbortedError):
                await future
        self.loop.run_until_complete(test())

    def testInitializeCancelledAfterConnectionMade(self):
        # cancelled after connection_made, e.g. by asyncio.wait_for, asyncio
        # closes the transport; the closed transport stayed registered, so
        # a retry was skipped and requests only timed out
        async def test():
            loop = asyncio.get_running_loop()
            connect = loop.create_datagram_endpoint

            async def cancel_auth(protocol, **kwargs):
                transport, _ = await connect(protocol, **kwargs)
                if protocol.port == 1812:
                    transport.close()
                    raise asyncio.CancelledError()
                return transport, protocol
            with mock.patch.object(loop, 'create_datagram_endpoint', cancel_auth):
                with self.assertRaises(asyncio.CancelledError):
                    await self.client.initialize_transports(enable_auth=True,
                                                            enable_acct=True)
            self.assertIsNone(self.client.protocol_auth)
            self.assertIsNotNone(self.client.protocol_acct)
            await self.client.initialize_transports(enable_auth=True)
            self.assertFalse(self.client.protocol_auth.transport.is_closing())
            await self.client.deinitialize_transports()
        self.loop.run_until_complete(test())

    def testRetryTimeout(self):
        timeout = 0.3

        async def test():
            loop = asyncio.get_running_loop()
            protocol = DatagramProtocolClient(LOCALHOST, 1812, mock.Mock(), self.client,
                                              retries=1, timeout=timeout)
            sent = []
            protocol.transport = mock.Mock()
            protocol.transport.sendto.side_effect = lambda data: sent.append(loop.time())
            handler = asyncio.ensure_future(protocol.__timeout_handler__())
            # send while the timeout handler is sleeping
            await asyncio.sleep(timeout / 2)
            future = loop.create_future()
            protocol.send_packet(packet.AuthPacket(id=1, secret=SECRET, dict=self.dict),
                                 future)
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(future, 5 * timeout)
            sent.append(loop.time())
            handler.cancel()
            await asyncio.wait([handler])
            self.assertTrue(handler.cancelled())
            self.assertEqual(protocol.pending_requests, {})
            return sent
        (request, retry, failed) = self.loop.run_until_complete(test())
        # a request is retried and fails only after the timeout has passed
        self.assertGreaterEqual(retry - request, timeout * 0.9)
        self.assertGreaterEqual(failed - retry, timeout * 0.9)
        self.assertLess(failed - request, 3 * timeout)

    def mock_protocol(self, timeout=0.2, retries=0):
        protocol = DatagramProtocolClient(LOCALHOST, 1812, mock.Mock(), self.client,
                                          retries=retries, timeout=timeout)
        protocol.transport = mock.Mock()
        return protocol

    def run_with_clock_step(self, step, timeout):
        """Send a request, step the wall clock and run the timeout handler
        for a moment. Return the future of the request."""
        class SteppedDatetime(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.datetime.now(tz) + step

        async def test():
            loop = asyncio.get_running_loop()
            protocol = self.mock_protocol(timeout=timeout)
            future = loop.create_future()
            protocol.send_packet(packet.AuthPacket(id=1, secret=SECRET, dict=self.dict),
                                 future)
            # the client used to measure timeouts with the wall clock
            with mock.patch('pyrad.client_async.datetime', SteppedDatetime, create=True):
                handler = asyncio.ensure_future(protocol.__timeout_handler__())
                await asyncio.wait([future], timeout=1)
            handler.cancel()
            await asyncio.wait([handler])
            self.assertTrue(handler.cancelled())
            return future
        return self.loop.run_until_complete(test())

    def testClockStepBackwards(self):
        # the request used to time out only after the clock caught up
        future = self.run_with_clock_step(-datetime.timedelta(hours=1), timeout=0.2)
        self.assertTrue(future.done())
        self.assertIsInstance(future.exception(), TimeoutError)

    def testClockStepForwards(self):
        # the request used to time out right away
        future = self.run_with_clock_step(datetime.timedelta(hours=1), timeout=30)
        self.assertFalse(future.done())
        future.cancel()

    def testCancelledRequest(self):
        # a request cancelled by the caller (e.g. with asyncio.wait_for) used
        # to kill the timeout handler, so later requests never timed out
        async def test():
            loop = asyncio.get_running_loop()
            protocol = self.mock_protocol()
            handler = asyncio.ensure_future(protocol.__timeout_handler__())
            cancelled = loop.create_future()
            protocol.send_packet(packet.AuthPacket(id=1, secret=SECRET, dict=self.dict),
                                 cancelled)
            cancelled.cancel()
            await asyncio.sleep(0)
            self.assertEqual(protocol.pending_requests, {})
            future = loop.create_future()
            protocol.send_packet(packet.AuthPacket(id=2, secret=SECRET, dict=self.dict),
                                 future)
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(future, 2)
            self.assertFalse(handler.done())
            handler.cancel()
            await asyncio.wait([handler])
            self.assertTrue(handler.cancelled())
        self.loop.run_until_complete(test())

    def testReplyForCancelledRequest(self):
        async def test():
            protocol = self.mock_protocol()
            req = packet.AuthPacket(id=1, secret=SECRET, dict=self.dict)
            future = asyncio.get_running_loop().create_future()
            protocol.send_packet(req, future)
            future.cancel()
            protocol.datagram_received(req.CreateReply().ReplyPacket(), (LOCALHOST, 1812))
            protocol.logger.error.assert_not_called()
            self.assertEqual(protocol.pending_requests, {})
        self.loop.run_until_complete(test())

    def testEncodeErrorIsNotPending(self):
        async def test():
            protocol = self.mock_protocol()
            req = packet.AuthPacket(id=1, secret=SECRET, dict=self.dict)
            req[1] = [300 * b'x']
            with self.assertRaises(Exception):
                protocol.send_packet(req, asyncio.get_running_loop().create_future())
            self.assertEqual(protocol.pending_requests, {})
        self.loop.run_until_complete(test())

    def testRetrySendError(self):
        async def test():
            protocol = self.mock_protocol(retries=1)
            handler = asyncio.ensure_future(protocol.__timeout_handler__())
            future = asyncio.get_running_loop().create_future()
            protocol.send_packet(packet.AuthPacket(id=1, secret=SECRET, dict=self.dict),
                                 future)
            protocol.transport.sendto.side_effect = OSError('send failed')
            with self.assertRaises(OSError):
                await asyncio.wait_for(future, 2)
            self.assertFalse(handler.done())
            handler.cancel()
            await asyncio.wait([handler])
            self.assertTrue(handler.cancelled())
        self.loop.run_until_complete(test())

    def testCloseTransportFailsPendingRequests(self):
        async def test():
            await self.client.initialize_transports(enable_auth=True)
            future = self.client.SendPacket(self.client.CreateAuthPacket(User_Name='alice'))
            await self.client.deinitialize_transports()
            with self.assertRaises(ConnectionAbortedError):
                await asyncio.wait_for(future, 2)
        self.loop.run_until_complete(test())

    def testProtocol(self):
        logger = mock.Mock()
        protocol = DatagramProtocolClient(LOCALHOST, 1812, logger, self.client)
        protocol.error_received(OSError('error'))
        logger.error.assert_called_once()
        protocol.connection_lost(OSError('lost'))
        logger.warning.assert_called_once()
        protocol.connection_lost(None)
        logger.info.assert_called_once()


class FakeDatagramTransport:
    """Controllable stand-in for an asyncio datagram transport.

    It records the raw bytes written with sendto and never opens a socket,
    so the transaction/reuse tests run fully offline, without a NAS.
    """

    def __init__(self):
        self.sent = []
        self.closed = False

    def sendto(self, data, addr=None):
        self.sent.append(data)

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    def get_extra_info(self, name):
        if name == 'socket':
            sock = mock.Mock()
            sock.getsockname.return_value = (LOCALHOST, 40000)
            return sock
        if name == 'sockname':
            return (LOCALHOST, 40000)
        return None


class AsyncTransactionReuseTests(unittest.TestCase):
    """ID exhaustion, release, reuse, stale and duplicate replies and the
    Future lifecycle of the async client, driven through
    FakeDatagramTransport without a real NAS or a socket.

    Every reply that completes a request is recorded together with the
    exact request bytes of the pending entry it completed. This proves that
    a reply only ever completes the transaction it was authenticated for,
    never a later request that reused the same 8-bit identifier.
    """

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.dict = Dictionary(StringIO(DICTIONARY))
        # (raw reply, request packet, raw request bytes completed by it)
        self.matched = []

    def tearDown(self):
        self.loop.close()

    def start_protocol(self, client, attr, port, retries, timeout):
        protocol = DatagramProtocolClient(LOCALHOST, port, mock.Mock(), client,
                                          retries=retries, timeout=timeout)
        protocol.transport = FakeDatagramTransport()
        setattr(client, attr, protocol)
        protocol.timeout_future = self.loop.create_task(
            protocol.__timeout_handler__())
        return protocol

    def start_client(self, retries=1, timeout=0.15, enable_acct=False):
        client = ClientAsync(server=LOCALHOST, secret=SECRET, dict=self.dict,
                             loop=self.loop, retries=retries, timeout=timeout)
        self.start_protocol(client, 'protocol_auth', 1812, retries, timeout)
        if enable_acct:
            self.start_protocol(client, 'protocol_acct', 1813, retries, timeout)
        return client

    def deliver(self, protocol, data, addr=(LOCALHOST, 1812)):
        """Feed a datagram to the protocol and record which pending request
        the reply completes, with the exact bytes of that request."""
        before = dict((id, dict(req)) for id, req in protocol.pending_requests.items())
        protocol.datagram_received(data, addr)
        for id, req in before.items():
            if id in protocol.pending_requests:
                continue
            future = req['future']
            if future.done() and not future.cancelled() and future.exception() is None:
                self.matched.append((data, req['packet'], req['raw']))

    def assert_every_reply_matches_its_request(self, client):
        self.assertTrue(self.matched)
        for reply_bytes, request_packet, request_raw in self.matched:
            decoded = packet.Packet(packet=reply_bytes, dict=self.dict)
            self.assertTrue(request_packet.VerifyReply(
                decoded, reply_bytes, enforce_ma=client.enforce_ma))
            # the proof recorded the bytes actually sent for this transaction
            self.assertEqual(request_packet.RequestPacket(), request_raw)

    async def stop_timer(self, protocol):
        task = protocol.timeout_future
        self.assertFalse(task.done())
        task.cancel()
        await asyncio.wait([task])
        self.assertTrue(task.cancelled())
        self.assertEqual(protocol.pending_requests, {})

    def testAllIdsExhaustedThenReleasedAndReused(self):
        async def test():
            client = self.start_client()
            protocol = client.protocol_auth
            futures = []
            for _ in range(256):
                pkt = packet.AuthPacket(id=protocol.create_id(), secret=SECRET,
                                        dict=self.dict)
                future = self.loop.create_future()
                protocol.send_packet(pkt, future)
                futures.append(future)
            self.assertEqual(sorted(protocol.pending_requests), list(range(256)))
            with self.assertRaisesRegex(Exception, 'No free packet id'):
                protocol.create_id()

            # cancellation releases an id, which is then handed out again
            protocol.pending_requests[42]['future'].cancel()
            await asyncio.sleep(0)
            self.assertNotIn(42, protocol.pending_requests)
            self.assertEqual(protocol.create_id(), 42)

            # every id and every pending entry is reclaimed in the end
            for future in futures:
                future.cancel()
            await asyncio.sleep(0)
            self.assertEqual(protocol.pending_requests, {})
            # the whole id range is available again
            self.assertEqual(len({protocol.create_id() for _ in range(256)}), 256)
            await self.stop_timer(protocol)
        self.loop.run_until_complete(test())

    def testStaleReplyAfterTimeoutCannotCompleteReusedId(self):
        async def test():
            client = self.start_client(retries=0, timeout=0.15)
            protocol = client.protocol_auth
            old = client.CreateAuthPacket(User_Name='alice')
            reused_id = old.id
            old_future = client.SendPacket(old)
            old_raw = protocol.pending_requests[reused_id]['raw']
            old_reply = old.CreateReply().ReplyPacket()

            # the request times out and its id is recycled
            await asyncio.sleep(0.4)
            self.assertTrue(old_future.done())
            self.assertIsInstance(old_future.exception(), TimeoutError)
            self.assertEqual(protocol.pending_requests, {})

            # a new transaction gets the same id but a fresh authenticator
            new = packet.AuthPacket(id=reused_id, secret=SECRET, dict=self.dict,
                                    User_Name='bob')
            new_future = self.loop.create_future()
            protocol.send_packet(new, new_future)
            self.assertEqual(new.id, reused_id)
            self.assertNotEqual(new.authenticator, old.authenticator)
            new_raw = protocol.pending_requests[reused_id]['raw']
            self.assertNotEqual(old_raw, new_raw)

            # the still valid reply of the old transaction arrives late, from
            # another endpoint: real authentication fails against the new
            # request, so it must not complete or remove it
            protocol.datagram_received(old_reply, ('198.51.100.7', 4900))
            self.assertFalse(new_future.done())
            self.assertIn(reused_id, protocol.pending_requests)
            self.assertEqual(self.matched, [])

            # only a reply signed for the new transaction completes it
            self.deliver(protocol, new.CreateReply().ReplyPacket(),
                         (LOCALHOST, 1812))
            self.assertTrue(new_future.done())
            self.assertEqual(new_future.result().code, packet.AccessAccept)
            self.assertEqual(protocol.pending_requests, {})
            self.assertEqual(len(self.matched), 1)
            self.assertEqual(self.matched[0][2], new_raw)
            self.assert_every_reply_matches_its_request(client)
            await self.stop_timer(protocol)
        self.loop.run_until_complete(test())

    def testStaleReplyAfterCancelCannotCompleteReusedId(self):
        async def test():
            client = self.start_client(retries=0)
            protocol = client.protocol_auth
            old = client.CreateAuthPacket(User_Name='alice')
            reused_id = old.id
            old_future = client.SendPacket(old)
            old_reply = old.CreateReply().ReplyPacket()
            old_future.cancel()
            await asyncio.sleep(0)
            self.assertEqual(protocol.pending_requests, {})

            # the id is reused by a new request while the old Future is done
            new = packet.AuthPacket(id=reused_id, secret=SECRET, dict=self.dict,
                                    User_Name='bob')
            new_future = self.loop.create_future()
            protocol.send_packet(new, new_future)
            self.assertIn(reused_id, protocol.pending_requests)

            # the late reply to the cancelled request must not touch the new
            # Future, and the old done-callback must not remove the new entry
            protocol.datagram_received(old_reply, ('198.51.100.7', 4900))
            self.assertFalse(new_future.done())
            self.assertIs(protocol.pending_requests[reused_id]['future'], new_future)
            self.assertTrue(old_future.cancelled())
            self.assertEqual(self.matched, [])

            self.deliver(protocol, new.CreateReply().ReplyPacket())
            self.assertEqual(new_future.result().code, packet.AccessAccept)
            self.assertEqual(len(self.matched), 1)
            self.assert_every_reply_matches_its_request(client)
            await self.stop_timer(protocol)
        self.loop.run_until_complete(test())

    def testDuplicateRepliesCompleteOnlyOnce(self):
        async def test():
            client = self.start_client()
            protocol = client.protocol_auth
            req = client.CreateAuthPacket(User_Name='alice')
            future = client.SendPacket(req)
            reply = req.CreateReply().ReplyPacket()

            self.deliver(protocol, reply, (LOCALHOST, 1812))
            self.assertEqual(future.result().code, packet.AccessAccept)
            # the replayed duplicate finds no pending request and is ignored
            self.deliver(protocol, reply, ('198.51.100.7', 4900))
            self.assertEqual(future.result().code, packet.AccessAccept)
            self.assertEqual(protocol.pending_requests, {})
            self.assertEqual(len(self.matched), 1)
            self.assertEqual(self.matched[0][0], reply)
            self.assert_every_reply_matches_its_request(client)
            await self.stop_timer(protocol)
        self.loop.run_until_complete(test())

    def testRepliesFromDifferentSourceEndpoints(self):
        async def test():
            client = self.start_client()
            protocol = client.protocol_auth

            # matching is by id and authenticator, not by source endpoint:
            # a correctly signed reply from another endpoint is accepted
            req = client.CreateAuthPacket(User_Name='alice')
            future = client.SendPacket(req)
            self.deliver(protocol, req.CreateReply().ReplyPacket(),
                         ('10.0.0.99', 5000))
            self.assertEqual(future.result().code, packet.AccessAccept)

            # a forged reply (wrong secret), regardless of its source, is
            # rejected and leaves the request pending
            other = client.CreateAuthPacket(User_Name='mallory')
            other_future = client.SendPacket(other)
            forged = other.CreateReply()
            forged.secret = b'wrong'
            protocol.datagram_received(forged.ReplyPacket(), ('8.8.8.8', 1))
            self.assertFalse(other_future.done())
            self.assertIn(other.id, protocol.pending_requests)
            self.assertEqual(len(self.matched), 1)

            self.deliver(protocol, other.CreateReply().ReplyPacket(),
                         ('10.0.0.99', 5001))
            self.assertEqual(other_future.result().code, packet.AccessAccept)
            self.assertEqual(protocol.pending_requests, {})
            self.assert_every_reply_matches_its_request(client)
            await self.stop_timer(protocol)
        self.loop.run_until_complete(test())

    def testAccountingRetransmissionContract(self):
        async def test():
            client = self.start_client(retries=3, timeout=0.15, enable_acct=True)
            acct = client.protocol_acct
            # the handler is created in start_client before requests are sent,
            # and sleeps before its first scan; restart it after sending so
            # the retransmission timing below is deterministic
            acct.timeout_future.cancel()
            await asyncio.wait([acct.timeout_future])

            # the client retransmits the identical datagram, it does not add
            # Acct-Delay-Time or re-sign the request
            req = client.CreateAcctPacket(Acct_Status_Type='Start',
                                          Acct_Session_Id='session-1')
            future = client.SendPacket(req)
            original_raw = acct.transport.sent[-1]
            acct.timeout_future = self.loop.create_task(
                acct.__timeout_handler__())
            await asyncio.sleep(0.3)
            self.assertEqual(acct.transport.sent, [original_raw, original_raw])
            self.assertIn(req.id, acct.pending_requests)

            # contract: a response to the original attempt, still valid for
            # the request bytes the client actually sent, completes it
            self.deliver(acct, req.CreateReply().ReplyPacket(),
                         (LOCALHOST, 1813))
            self.assertEqual(future.result().code, packet.AccountingResponse)

            # a server that re-signed a retransmitted request after changing
            # Acct-Delay-Time (and hence its Request Authenticator) must not
            # match the pending transaction
            req2 = client.CreateAcctPacket(Acct_Status_Type='Start',
                                           Acct_Session_Id='session-2')
            future2 = client.SendPacket(req2)
            rebuilt = packet.AcctPacket(id=req2.id, secret=SECRET, dict=self.dict,
                                        Acct_Status_Type='Start',
                                        Acct_Session_Id='session-2',
                                        Acct_Delay_Time=5)
            rebuilt_raw = rebuilt.RequestPacket()
            self.assertNotEqual(rebuilt.authenticator, req2.authenticator)
            self.assertNotEqual(rebuilt_raw, acct.pending_requests[req2.id]['raw'])
            rebuilt_reply = rebuilt.CreateReply().ReplyPacket()
            self.assertFalse(req2.VerifyReply(
                packet.Packet(packet=rebuilt_reply, dict=self.dict), rebuilt_reply))
            acct.datagram_received(rebuilt_reply, (LOCALHOST, 1813))
            self.assertFalse(future2.done())
            self.assertIn(req2.id, acct.pending_requests)

            # the response signed for the actual request still completes it
            self.deliver(acct, req2.CreateReply().ReplyPacket(),
                         (LOCALHOST, 1813))
            self.assertEqual(future2.result().code, packet.AccountingResponse)
            self.assertEqual(acct.pending_requests, {})
            self.assert_every_reply_matches_its_request(client)
            await self.stop_timer(acct)
            await self.stop_timer(client.protocol_auth)
        self.loop.run_until_complete(test())

    def testCloseTransportReclaimsIdsFuturesAndTimers(self):
        async def test():
            client = self.start_client(enable_acct=True)
            auth, acct = client.protocol_auth, client.protocol_acct
            auth_future = client.SendPacket(
                client.CreateAuthPacket(User_Name='alice'))
            acct_future = client.SendPacket(
                client.CreateAcctPacket(Acct_Status_Type='Start',
                                        Acct_Session_Id='session'))
            timers = [auth.timeout_future, acct.timeout_future]

            await client.deinitialize_transports()
            for future in (auth_future, acct_future):
                with self.assertRaises(ConnectionAbortedError):
                    await future
            for timer in timers:
                self.assertTrue(timer.cancelled())
            self.assertIsNone(client.protocol_auth)
            self.assertIsNone(client.protocol_acct)
        self.loop.run_until_complete(test())

    def testFullClientLifecycleOffline(self):
        # the public ClientAsync API end to end, with create_datagram_endpoint
        # replaced by the fake transport, so no socket and no NAS are used
        async def fake_endpoint(protocol, **kwargs):
            transport = FakeDatagramTransport()
            protocol.connection_made(transport)
            return transport, protocol

        async def test():
            self.loop.create_datagram_endpoint = fake_endpoint
            client = ClientAsync(server=LOCALHOST, secret=SECRET, dict=self.dict,
                                 loop=self.loop, retries=0, timeout=0.15)
            await client.initialize_transports(enable_auth=True)
            protocol = client.protocol_auth
            self.assertIsInstance(protocol.transport, FakeDatagramTransport)

            futures = []
            for _ in range(256):
                futures.append(client.SendPacket(
                    client.CreateAuthPacket(User_Name='alice')))
            self.assertEqual(len(protocol.pending_requests), 256)
            with self.assertRaisesRegex(Exception, 'No free packet id'):
                client.CreateAuthPacket()

            for future in futures:
                future.cancel()
            await asyncio.sleep(0)
            self.assertEqual(protocol.pending_requests, {})

            # ids are reusable and a normal transaction still works, recording
            # the request bytes its reply was matched against
            req = client.CreateAuthPacket(User_Name='bob')
            future = client.SendPacket(req)
            self.deliver(protocol, req.CreateReply().ReplyPacket(),
                         ('198.51.100.7', 4900))
            self.assertEqual(future.result().code, packet.AccessAccept)
            self.assert_every_reply_matches_its_request(client)

            timer = protocol.timeout_future
            await client.deinitialize_transports()
            self.assertTrue(timer.cancelled())
            self.assertIsNone(client.protocol_auth)
        self.loop.run_until_complete(test())


class AsyncServerProtocolTests(unittest.TestCase):
    """Packets dropped by DatagramProtocolServer."""

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.handled = []
        self.server = type('Server', (), {})()
        self.server.dict = self.dict
        self.server.debug = False
        self.server.enable_pkt_verify = True
        self.server.enforce_ma = False
        self.hosts = {'0.0.0.0': RemoteHost('0.0.0.0', SECRET, 'any')}

    def receive(self, server_type, pkt, source=(LOCALHOST, 1812)):
        protocol = DatagramProtocolServer(
            LOCALHOST, 1812, logging.getLogger('pyrad-test'), self.server, server_type,
            self.hosts, lambda protocol, req, addr: self.handled.append(req))
        data = pkt if isinstance(pkt, bytes) else pkt.RequestPacket()
        protocol.datagram_received(data, source)
        return protocol

    def testDefaultHost(self):
        self.receive(ServerType.Auth, packet.AuthPacket(secret=SECRET, dict=self.dict,
                                                        User_Name='alice'))
        self.assertEqual(len(self.handled), 1)

    def testMappedAddress(self):
        # IPv4 client of a dual stack server bound to '::'
        self.hosts = {LOCALHOST: RemoteHost(LOCALHOST, SECRET, 'local')}
        self.receive(ServerType.Auth, packet.AuthPacket(secret=SECRET, dict=self.dict,
                                                        User_Name='alice'),
                     source=('::ffff:' + LOCALHOST, 1812, 0, 0))
        self.assertEqual(len(self.handled), 1)
        self.assertEqual(self.handled[0].secret, SECRET)

    def testGarbage(self):
        self.receive(ServerType.Auth, b'garbage')
        self.assertEqual(self.handled, [])

    def testResponsePacket(self):
        reply = packet.AuthPacket(code=packet.AccessAccept, secret=SECRET,
                                  authenticator=16 * b'\x00')
        self.receive(ServerType.Auth, reply.ReplyPacket())
        self.assertEqual(self.handled, [])

    def testWrongPort(self):
        acct = packet.AcctPacket(secret=SECRET, dict=self.dict)
        auth = packet.AuthPacket(secret=SECRET, dict=self.dict)
        self.receive(ServerType.Auth, acct)
        self.receive(ServerType.Acct, auth)
        self.receive(ServerType.Coa, auth)
        self.assertEqual(self.handled, [])

    def testInvalidCoARequest(self):
        req = packet.CoAPacket(secret=b'wrong', dict=self.dict)
        self.receive(ServerType.Coa, req)
        self.server.debug = True
        self.receive(ServerType.Coa, req)
        self.assertEqual(self.handled, [])

    def testProtocol(self):
        protocol = self.receive(ServerType.Auth, b'garbage')
        self.assertEqual(str(protocol), f'DatagramProtocolServer(ip={LOCALHOST}, port=1812)')
        self.assertIs(protocol(), protocol)
        protocol.error_received(OSError('error'))
        protocol.connection_lost(None)
        protocol.connection_lost(OSError('lost'))


class AsyncServerTests(unittest.TestCase):
    def testLoopOutsideRunningLoop(self):
        # without a loop and outside of a running loop, the current event
        # loop is used
        loop = asyncio.new_event_loop()
        server = RadiusServer()
        asyncio.set_event_loop(loop)
        try:
            self.assertIs(server.loop, loop)
        finally:
            asyncio.set_event_loop(None)
            loop.close()

    def testNoTransportsSelected(self):
        loop = asyncio.new_event_loop()
        server = RadiusServer(loop=loop)
        with self.assertRaises(Exception):
            loop.run_until_complete(server.initialize_transports())
        loop.close()

    def testRequestHandlerErrors(self):
        loop = asyncio.new_event_loop()
        server = RadiusServer(loop=loop)
        protocol = type('Protocol', (), {'ip': LOCALHOST, 'port': 1812})()
        # unexpected request type and exception in a handler are logged
        protocol.server_type = ServerType.Coa
        server.__request_handler__(protocol, packet.CoAPacket(code=packet.CoAACK), None)
        protocol.server_type = ServerType.Auth
        for server.debug in (False, True):
            server.__request_handler__(protocol, None, None)
        loop.close()

    def testLoopResolvedWhenUsed(self):
        server = RadiusServer()

        async def test():
            return server.loop is asyncio.get_running_loop()
        self.assertTrue(asyncio.run(test()))
        self.assertTrue(asyncio.run(test()))

    def testDefaultLoopAndAddress(self):
        ports = dict(zip(('auth_port', 'acct_port', 'coa_port'), free_ports(3)))

        async def test():
            server = RadiusServer(**ports)
            self.assertIs(server.loop, asyncio.get_running_loop())
            await server.initialize_transports(enable_acct=True, enable_coa=True)
            protocols = server.acct_protocols + server.coa_protocols
            self.assertEqual([proto.ip for proto in protocols], [LOCALHOST, LOCALHOST])
            # already bound transports are not bound again
            await server.initialize_transports(enable_acct=True, enable_coa=True)
            self.assertEqual(server.acct_protocols + server.coa_protocols, protocols)
            await server.deinitialize_transports()
        asyncio.run(test())

    def testWithoutReusePort(self):
        # reuse_port=True raised ValueError without SO_REUSEPORT
        ports = dict(zip(('auth_port', 'acct_port', 'coa_port'), free_ports(3)))

        async def test():
            server = RadiusServer(**ports)
            with without_reuse_port():
                await server.initialize_transports(enable_auth=True)
            self.assertIsNotNone(server.auth_protocols[0].transport)
            await server.deinitialize_transports()
        asyncio.run(test())

    def testInitializeCancelledAfterConnectionMade(self):
        # a closed transport stayed registered and a retry was a no-op
        ports = dict(zip(('auth_port', 'acct_port', 'coa_port'), free_ports(3)))

        async def test():
            loop = asyncio.get_running_loop()
            server = RadiusServer(loop=loop, **ports)
            connect = loop.create_datagram_endpoint

            async def cancel_auth(protocol, **kwargs):
                transport, _ = await connect(protocol, **kwargs)
                if protocol.server_type == ServerType.Auth:
                    transport.close()
                    raise asyncio.CancelledError()
                return transport, protocol
            with mock.patch.object(loop, 'create_datagram_endpoint', cancel_auth):
                with self.assertRaises(asyncio.CancelledError):
                    await server.initialize_transports(enable_auth=True, enable_acct=True)
            self.assertEqual(server.auth_protocols, [])
            self.assertEqual(len(server.acct_protocols), 1)
            await server.initialize_transports(enable_auth=True)
            self.assertFalse(server.auth_protocols[0].transport.is_closing())
            await server.deinitialize_transports()
        asyncio.run(test())

    def testInitializeFailureCanBeRetried(self):
        # a transport which couldn't be bound used to stay registered, so a
        # retry was a no-op and nothing listened
        ports = dict(zip(('auth_port', 'acct_port', 'coa_port'), free_ports(3)))

        async def test():
            loop = asyncio.get_running_loop()
            server = RadiusServer(loop=loop, **ports)
            connect = loop.create_datagram_endpoint

            async def fail_auth(protocol, **kwargs):
                if protocol.server_type == ServerType.Auth:
                    raise OSError('bind failed')
                return await connect(protocol, **kwargs)
            with mock.patch.object(loop, 'create_datagram_endpoint', fail_auth):
                with self.assertRaises(OSError):
                    await server.initialize_transports(enable_auth=True, enable_acct=True)
            self.assertEqual(server.auth_protocols, [])
            # the transport bound successfully is kept
            self.assertEqual(len(server.acct_protocols), 1)
            await server.initialize_transports(enable_auth=True, enable_acct=True)
            self.assertEqual(len(server.acct_protocols), 1)
            self.assertEqual(len(server.auth_protocols), 1)
            self.assertIsNotNone(server.auth_protocols[0].transport)
            await server.deinitialize_transports()
        asyncio.run(test())
