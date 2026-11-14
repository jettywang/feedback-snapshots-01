"""End-to-end behaviour of the shared-secret compatibility window.

These tests drive the blocking :class:`~pyrad.server.Server` packet
handlers directly (no sockets, so they run without loopback binding) with
a fake clock and two local secrets, and verify the replies and the hidden
attributes with the exact secret that authenticated each request. They
cover the situation before and after a rotation, the expiry of a retired
secret, and a configuration reload that happens while a handler is still
processing a request.
"""
import logging
import threading
import unittest
from datetime import datetime, timedelta, timezone
from io import StringIO

from pyrad.dictionary import Dictionary
from pyrad.packet import (AuthPacket, AcctPacket, AccessAccept)
from pyrad.secrets import SecretRing, SharedSecret
from pyrad.server import RemoteHost, Server, ServerPacketError
from pyrad.server_async import DatagramProtocolServer, ServerType


DICTIONARY = '''
ATTRIBUTE User-Name              1  string
ATTRIBUTE User-Password          2  string
ATTRIBUTE Reply-Message         18 string
ATTRIBUTE Acct-Status-Type      40 integer
ATTRIBUTE Tunnel-Password       69 string has_tag,encrypt=2
ATTRIBUTE Message-Authenticator 80 octets
VALUE     Acct-Status-Type      Start 1
'''

OLD_SECRET = b'old-shared-secret'
NEW_SECRET = b'new-shared-secret'
PASSWORD = 'hunter2'
PEER = '10.0.0.5'


class FakeClock:
    def __init__(self):
        self.now = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


def make_dict():
    return Dictionary(StringIO(DICTIONARY))


class RotatingServer(Server):
    def __init__(self, host, dictionary):
        super().__init__(hosts={PEER: host}, dict=dictionary)
        self.handled = []
        # the handler blocks on this event, letting the test rotate the
        # configuration while a request is being processed
        self.gate = threading.Event()
        self.gate.set()

    def HandleAuthPacket(self, pkt):
        self.handled.append(pkt)
        self.gate.wait(5)
        reply = self.CreateReplyPacket(pkt, Reply_Message='welcome')
        # a hidden attribute must use the secret pinned to the request
        reply['Tunnel-Password:1'] = 'tunnel-secret-value'
        if pkt.PwDecrypt(pkt[2][0]) == PASSWORD:
            reply.code = AccessAccept
        # emulate the socket send by keeping the encoded bytes
        self.sent = reply.ReplyPacket()

    def HandleAcctPacket(self, pkt):
        self.handled.append(pkt)
        reply = self.CreateReplyPacket(pkt)
        self.sent = reply.ReplyPacket()


def build_auth_request(dictionary, secret):
    """A client-side Access-Request signed with ``secret``."""
    req = AuthPacket(dict=dictionary, secret=secret,
                     User_Name='alice')
    req['User-Password'] = req.PwCrypt(PASSWORD)
    req.add_message_authenticator()
    return req.RequestPacket(), req


def build_acct_request(dictionary, secret):
    req = AcctPacket(dict=dictionary, secret=secret,
                     Acct_Status_Type=1)
    return req.RequestPacket(), req


def decode_reply(dictionary, request, raw_reply, candidate_secret):
    """Decode a reply and verify it against ``candidate_secret``.

    VerifyReply uses the secret of the request object, so an independent
    verifier carrying the candidate secret is built. The decoded reply is
    also given the Request Authenticator so that salt-encrypted hidden
    attributes can be decrypted.
    """
    decoded = AuthPacket(dict=dictionary, secret=candidate_secret,
                         packet=raw_reply)
    decoded.request_authenticator = request.authenticator
    verifier = AuthPacket(dict=dictionary, secret=candidate_secret,
                          id=request.id,
                          authenticator=request.authenticator)
    ok = verifier.VerifyReply(decoded, raw_reply, enforce_ma=True)
    return ok, decoded


def decode_acct_reply(dictionary, request, raw_reply, candidate_secret):
    from pyrad.packet import AcctPacket as Acct
    decoded = Acct(dict=dictionary, secret=candidate_secret,
                   packet=raw_reply)
    verifier = Acct(dict=dictionary, secret=candidate_secret,
                    id=request.id, authenticator=request.authenticator)
    return verifier.VerifyReply(decoded, raw_reply), decoded


def rotated_host(clock, max_attempts=None, valid_days=7):
    return RemoteHost(PEER, secrets=[
        SharedSecret(NEW_SECRET, label='current', version=2),
        SharedSecret(
            OLD_SECRET, label='retired-1', version=1,
            retired_at=clock(),
            valid_after_retirement=timedelta(days=valid_days),
            max_attempts=max_attempts),
    ], clock=clock)


class RotationTestBase(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.dictionary = make_dict()
        self.host = rotated_host(self.clock)
        self.server = RotatingServer(self.host, self.dictionary)

    def receive_auth(self, secret):
        raw, original = build_auth_request(self.dictionary, secret)
        pkt = self.server.CreateAuthPacket(packet=raw)
        pkt.source = (PEER, 1812)
        pkt.fd = None
        self.server._HandleAuthPacket(pkt)
        return pkt, original

    def receive_acct(self, secret):
        raw, original = build_acct_request(self.dictionary, secret)
        pkt = self.server.CreateAcctPacket(packet=raw)
        pkt.source = (PEER, 1813)
        pkt.fd = None
        self.server._HandleAcctPacket(pkt)
        return pkt, original


class BeforeAndAfterRotationTests(RotationTestBase):
    def testNewSecretRequestGetsVerifiableReply(self):
        pkt, original = self.receive_auth(NEW_SECRET)
        self.assertEqual(pkt.secret, NEW_SECRET)
        self.assertEqual(pkt.matched_secret_label, 'current')
        raw_reply = self.server.sent
        ok, reply = decode_reply(self.dictionary, original, raw_reply,
                                 NEW_SECRET)
        self.assertTrue(ok)
        # the hidden attribute round-trips with the new secret
        self.assertEqual(reply['Tunnel-Password:1'],
                         ['tunnel-secret-value'])

    def testRetiredSecretStillAcceptedWithinWindow(self):
        pkt, original = self.receive_auth(OLD_SECRET)
        self.assertEqual(pkt.secret, OLD_SECRET)
        self.assertEqual(pkt.matched_secret_label, 'retired-1')
        raw_reply = self.server.sent
        ok, _ = decode_reply(self.dictionary, original, raw_reply,
                             OLD_SECRET)
        self.assertTrue(ok)
        # the reply signed with the old secret must not verify as the new one
        forged_ok, _ = decode_reply(self.dictionary, original, raw_reply,
                                    NEW_SECRET)
        self.assertFalse(forged_ok)

    def testAccountingUsesRetiredSecretAndVerifies(self):
        pkt, original = self.receive_acct(OLD_SECRET)
        self.assertEqual(pkt.secret, OLD_SECRET)
        raw_reply = self.server.sent
        ok, _ = decode_acct_reply(self.dictionary, original, raw_reply,
                                  OLD_SECRET)
        self.assertTrue(ok)

    def testUnknownSecretIsDropped(self):
        raw, _ = build_auth_request(self.dictionary, b'attacker')
        pkt = self.server.CreateAuthPacket(packet=raw)
        pkt.source = (PEER, 1812)
        pkt.fd = None
        self.assertRaises(ServerPacketError,
                          self.server._HandleAuthPacket, pkt)


class ExpiryAndAttemptLimitTests(RotationTestBase):
    def testRetiredSecretRejectedAfterWindow(self):
        self.clock.advance(days=8)
        raw, _ = build_auth_request(self.dictionary, OLD_SECRET)
        pkt = self.server.CreateAuthPacket(packet=raw)
        pkt.source = (PEER, 1812)
        pkt.fd = None
        self.assertRaises(ServerPacketError,
                          self.server._HandleAuthPacket, pkt)
        # the new secret still works
        self.receive_auth(NEW_SECRET)

    def testAttemptLimitStopsRetiredSecret(self):
        host = rotated_host(self.clock, max_attempts=2)
        self.server = RotatingServer(host, self.dictionary)
        self.receive_auth(OLD_SECRET)
        self.receive_auth(OLD_SECRET)
        # third old-secret request is refused; retrying it changes nothing
        raw, _ = build_auth_request(self.dictionary, OLD_SECRET)
        pkt = self.server.CreateAuthPacket(packet=raw)
        pkt.source = (PEER, 1812)
        pkt.fd = None
        self.assertRaises(ServerPacketError,
                          self.server._HandleAuthPacket, pkt)
        self.assertRaises(ServerPacketError,
                          self.server._HandleAuthPacket, pkt)

    def testExpiredSecretCannotReenterThroughReload(self):
        self.clock.advance(days=8)
        # a reload keeps the same peer object but with a fresh ring; the
        # expired retired secret is absent from the new configuration
        new_ring = SecretRing(
            [SharedSecret(NEW_SECRET, label='current', version=3)],
            clock=self.clock)
        self.host.secrets = new_ring
        raw, _ = build_auth_request(self.dictionary, OLD_SECRET)
        pkt = self.server.CreateAuthPacket(packet=raw)
        pkt.source = (PEER, 1812)
        pkt.fd = None
        self.assertRaises(ServerPacketError,
                          self.server._HandleAuthPacket, pkt)


class ConcurrentReloadTests(RotationTestBase):
    def testReloadWhileHandlerWaitsKeepsReplyKey(self):
        self.server.gate.clear()
        raw, original = build_auth_request(self.dictionary, OLD_SECRET)
        pkt = self.server.CreateAuthPacket(packet=raw)
        pkt.source = (PEER, 1812)
        pkt.fd = None

        started = threading.Event()

        def handle():
            # _HandleAuthPacket selects and pins the secret, then enters
            # the gated handler
            started.set()
            self.server._HandleAuthPacket(pkt)

        worker = threading.Thread(target=handle)
        worker.start()
        self.assertTrue(started.wait(5))

        # rotate to a brand-new secret while the handler is still waiting
        self.server.hosts[PEER] = RemoteHost(PEER, secrets=[
            SharedSecret(b'third-secret', label='current', version=3),
        ], clock=self.clock)
        self.server.gate.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())

        # the in-flight request was pinned to the old secret and the reply
        # is still signed with it, regardless of the swapped configuration
        self.assertEqual(pkt.secret, OLD_SECRET)
        raw_reply = self.server.sent
        ok, _ = decode_reply(self.dictionary, original, raw_reply,
                             OLD_SECRET)
        self.assertTrue(ok)
        third_ok, _ = decode_reply(self.dictionary, original, raw_reply,
                                   b'third-secret')
        self.assertFalse(third_ok)


class AsyncRotationTests(RotationTestBase):
    """The asyncio server applies the same selection and pinning.

    DatagramProtocolServer.datagram_received is driven directly, without a
    socket, so the test runs without loopback binding.
    """

    def make_protocol(self, server_type):
        fake_server = type('AsyncServer', (), {})()
        fake_server.dict = self.dictionary
        fake_server.enable_pkt_verify = True
        fake_server.enforce_ma = False
        fake_server.debug = False
        handled = []
        protocol = DatagramProtocolServer(
            '127.0.0.1', 1812, logging.getLogger('pyrad-test'),
            fake_server, server_type, self.server.hosts,
            lambda proto, req, addr: handled.append((req, addr)))
        return protocol, handled

    def testAuthCurrentAndRetiredAndWrong(self):
        protocol, handled = self.make_protocol(ServerType.Auth)
        for secret, expected in ((NEW_SECRET, 1), (OLD_SECRET, 2),
                                 (b'attacker', 2)):
            raw, _ = build_auth_request(self.dictionary, secret)
            protocol.datagram_received(raw, (PEER, 1812))
            self.assertEqual(len(handled), expected)
        self.assertEqual(handled[0][0].secret, NEW_SECRET)
        self.assertEqual(handled[1][0].secret, OLD_SECRET)

    def testAuthRetiredRejectedAfterExpiry(self):
        protocol, handled = self.make_protocol(ServerType.Auth)
        self.clock.advance(days=8)
        raw, _ = build_auth_request(self.dictionary, OLD_SECRET)
        protocol.datagram_received(raw, (PEER, 1812))
        self.assertEqual(handled, [])

    def testAcctRetiredAcceptedThenAttemptLimit(self):
        host = rotated_host(self.clock, max_attempts=1)
        self.server = RotatingServer(host, self.dictionary)
        protocol, handled = self.make_protocol(ServerType.Acct)
        raw, _ = build_acct_request(self.dictionary, OLD_SECRET)
        protocol.datagram_received(raw, (PEER, 1813))
        self.assertEqual(len(handled), 1)
        self.assertEqual(handled[0][0].secret, OLD_SECRET)
        # the second request with the retired secret is over the budget
        protocol.datagram_received(raw, (PEER, 1813))
        self.assertEqual(len(handled), 1)

    def testReloadDoesNotChangeAlreadyPinnedRequest(self):
        protocol, handled = self.make_protocol(ServerType.Auth)
        raw, original = build_auth_request(self.dictionary, OLD_SECRET)
        protocol.datagram_received(raw, (PEER, 1812))
        self.assertEqual(len(handled), 1)
        req, _ = handled[0]
        # swap the whole configuration after reception
        self.server.hosts[PEER] = RemoteHost(PEER, secrets=[
            SharedSecret(b'third-secret', label='current', version=3),
        ], clock=self.clock)
        # the request keeps the secret it arrived with; its reply uses it
        reply = req.CreateReply()
        raw_reply = reply.ReplyPacket()
        ok, _ = decode_reply(self.dictionary, original, raw_reply,
                             OLD_SECRET)
        self.assertTrue(ok)
        self.assertEqual(req.secret, OLD_SECRET)


if __name__ == '__main__':
    unittest.main()
