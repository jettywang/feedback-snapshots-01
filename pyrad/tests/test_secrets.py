"""Tests for the bounded shared-secret compatibility window used while
RADIUS clients rotate their shared secret.

No sockets are used: time is driven by an explicit fake clock, so the
expiry and attempt-limit behaviour is deterministic.
"""
import threading
import unittest
from datetime import datetime, timedelta, timezone
from io import StringIO

from pyrad.dictionary import Dictionary
from pyrad.secrets import SecretRing, SharedSecret
from pyrad.server import RemoteHost, SelectSecret, ServerPacketError
from pyrad.packet import AuthPacket, AcctPacket, CoAPacket


DICTIONARY = '''
ATTRIBUTE User-Name             1  string
ATTRIBUTE User-Password         2  string
ATTRIBUTE Message-Authenticator 80 octets
'''


def make_dict():
    return Dictionary(StringIO(DICTIONARY))


class FakeClock:
    """A controllable timezone-aware clock."""

    def __init__(self, start=None):
        self.now = start or datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


def retired(secret, label, clock, valid_days=1, max_attempts=None,
            retired_before=0, version=1):
    return SharedSecret(
        secret, label=label,
        retired_at=clock() - timedelta(days=retired_before),
        valid_after_retirement=timedelta(days=valid_days),
        max_attempts=max_attempts, version=version)


class SharedSecretTests(unittest.TestCase):
    def testCurrentNeverExpires(self):
        clock = FakeClock()
        current = SharedSecret(b'new', label='new')
        clock.advance(days=9999)
        self.assertTrue(current.current)
        self.assertFalse(current.expired(clock()))

    def testRetiredExpiresAfterWindow(self):
        clock = FakeClock()
        old = retired(b'old', 'old', clock, valid_days=2)
        self.assertFalse(old.expired(clock()))
        clock.advance(days=1)
        self.assertFalse(old.expired(clock()))
        clock.advance(days=1)
        # the window is closed at retired_at + valid_after_retirement
        self.assertTrue(old.expired(clock()))

    def testRetiredExpiresAfterAttemptBudget(self):
        clock = FakeClock()
        old = retired(b'old', 'old', clock, max_attempts=2)
        self.assertFalse(old.expired(clock()))
        old.attempts = 2
        self.assertTrue(old.expired(clock()))

    def testNegativeAttemptLimitRejected(self):
        self.assertRaises(ValueError, SharedSecret, b'x',
                          max_attempts=-1)

    def testReprHidesSecret(self):
        secret = SharedSecret(b'top-secret-value', label='k1')
        self.assertNotIn('top-secret-value', repr(secret))
        self.assertIn('k1', repr(secret))


class SecretRingTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def testCurrentFirstThenRetired(self):
        ring = SecretRing([
            SharedSecret(b'new', label='new', version=2),
            retired(b'old', 'old', self.clock, version=1),
        ], clock=self.clock)
        labels = [entry.label for entry in ring.candidates()]
        self.assertEqual(labels, ['new', 'old'])
        self.assertEqual(ring.secret, b'new')

    def testExpiredSecretDropsOutOfCandidates(self):
        ring = SecretRing([
            SharedSecret(b'new', label='new'),
            retired(b'old', 'old', self.clock, valid_days=1),
        ], clock=self.clock)
        self.assertEqual(len(ring.candidates()), 2)
        self.clock.advance(days=2)
        self.assertEqual([e.label for e in ring.candidates()], ['new'])

    def testAttemptBudgetAdmitsThenBlocks(self):
        ring = SecretRing([
            SharedSecret(b'new', label='new'),
            retired(b'old', 'old', self.clock, max_attempts=2),
        ], clock=self.clock)
        old = ring.candidates()[1]
        self.assertTrue(ring.record_attempt(old))
        self.assertTrue(ring.record_attempt(old))
        # budget exhausted: a further request is refused, and the secret
        # disappears from the candidate set
        self.assertFalse(ring.record_attempt(old))
        self.assertNotIn(old, ring.candidates())
        self.assertEqual(old.attempts, 2)

    def testCurrentSecretAttemptsNotLimited(self):
        ring = SecretRing([SharedSecret(b'new')], clock=self.clock)
        current = ring.current
        for _ in range(100):
            self.assertTrue(ring.record_attempt(current))
        self.assertEqual(current.attempts, 0)

    def testTwoCurrentSecretsRejected(self):
        self.assertRaises(
            ValueError, SecretRing,
            [SharedSecret(b'a'), SharedSecret(b'b')])

    def testReloadCannotReadmitExpiredSecret(self):
        ring = SecretRing([
            SharedSecret(b'new', label='new'),
            retired(b'old', 'old', self.clock, valid_days=1),
        ], clock=self.clock)
        old = ring.candidates()[1]
        ring.record_attempt(old)
        self.clock.advance(days=2)
        # even a retry of the very same request finds no valid old secret
        self.assertEqual([e.label for e in ring.candidates()], ['new'])
        self.assertFalse(ring.record_attempt(old))

    def testConcurrentAttemptsRespectBudget(self):
        ring = SecretRing([
            SharedSecret(b'new', label='new'),
            retired(b'old', 'old', self.clock, max_attempts=50),
        ], clock=self.clock)
        old = ring.candidates()[1]
        results = []

        def worker():
            for _ in range(100):
                if ring.record_attempt(old):
                    results.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 50)
        self.assertEqual(old.attempts, 50)


class RemoteHostTests(unittest.TestCase):
    def testSingleSecretBackwardCompatible(self):
        host = RemoteHost('127.0.0.1', b'only', 'peer')
        self.assertEqual(host.secret, b'only')
        self.assertEqual(len(host.secrets), 1)
        self.assertTrue(host.secrets.current.current)

    def testSecretSetterReplacesRing(self):
        host = RemoteHost('127.0.0.1', b'a', 'peer')
        host.secret = b'b'
        self.assertEqual(host.secret, b'b')
        self.assertEqual(len(host.secrets), 1)

    def testSecretAndSecretsMutuallyExclusive(self):
        self.assertRaises(
            ValueError, RemoteHost, '127.0.0.1', b'a',
            secrets=[SharedSecret(b'b')])


def auth_request(secret):
    dictionary = make_dict()
    pkt = AuthPacket(dict=dictionary, secret=secret, User_Name='alice')
    pkt.add_message_authenticator()
    return AuthPacket(dict=dictionary, secret=secret,
                      packet=pkt.RequestPacket())


class SelectSecretAuthTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.old_secret = b'old-secret'
        self.new_secret = b'new-secret'
        self.host = RemoteHost('127.0.0.1', secrets=[
            SharedSecret(self.new_secret, label='new', version=2),
            retired(self.old_secret, 'old', self.clock,
                    valid_days=2, max_attempts=3, version=1),
        ], clock=self.clock)

    def testCurrentSecretAuthenticatesAndPins(self):
        pkt = auth_request(self.new_secret)
        entry = SelectSecret(self.host, pkt)
        self.assertEqual(entry.label, 'new')
        self.assertEqual(pkt.secret, self.new_secret)
        self.assertEqual(pkt.matched_secret_label, 'new')
        self.assertEqual(pkt.matched_secret_version, 2)
        # a current secret is not charged
        self.assertEqual(self.host.secrets.current.attempts, 0)

    def testRetiredSecretStillAcceptedWithinWindow(self):
        pkt = auth_request(self.old_secret)
        entry = SelectSecret(self.host, pkt)
        self.assertEqual(entry.label, 'old')
        self.assertEqual(pkt.secret, self.old_secret)
        self.assertEqual(entry.attempts, 1)

    def testUnknownSecretRejected(self):
        pkt = auth_request(b'intruder-secret')
        self.assertRaises(ServerPacketError, SelectSecret, self.host, pkt)

    def testRetiredSecretRejectedAfterExpiry(self):
        self.clock.advance(days=3)
        pkt = auth_request(self.old_secret)
        self.assertRaises(ServerPacketError, SelectSecret, self.host, pkt)

    def testRetiredSecretRejectedAfterAttemptLimit(self):
        for _ in range(3):
            SelectSecret(self.host, auth_request(self.old_secret))
        # the fourth request with the old secret must fail, and retrying
        # the same packet does not bring the budget back
        pkt = auth_request(self.old_secret)
        self.assertRaises(ServerPacketError, SelectSecret, self.host, pkt)
        self.assertRaises(ServerPacketError, SelectSecret, self.host, pkt)

    def testReloadDuringProcessingKeepsPinnedSecret(self):
        pkt = auth_request(self.old_secret)
        entry = SelectSecret(self.host, pkt)
        # configuration rotates again while the handler is still running:
        # the packet keeps the secret it was authenticated with
        self.host.secrets = SecretRing(
            [SharedSecret(b'third-secret', label='third', version=3)],
            clock=self.clock)
        self.assertEqual(pkt.secret, self.old_secret)
        self.assertEqual(entry.secret, self.old_secret)
        reply = pkt.CreateReply()
        self.assertEqual(reply.secret, self.old_secret)


class SelectSecretAcctTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.old_secret = b'old-acct'
        self.new_secret = b'new-acct'
        self.host = RemoteHost('127.0.0.1', secrets=[
            SharedSecret(self.new_secret, label='new', version=2),
            retired(self.old_secret, 'old', self.clock,
                    valid_days=1, max_attempts=2, version=1),
        ], clock=self.clock)

    def _acct(self, secret):
        req = AcctPacket(secret=secret)
        return AcctPacket(secret=secret, packet=req.RequestPacket())

    def testAcctCurrentAndRetired(self):
        self.assertEqual(
            SelectSecret(self.host, self._acct(self.new_secret)).label,
            'new')
        old = SelectSecret(self.host, self._acct(self.old_secret))
        self.assertEqual(old.label, 'old')

    def testAcctWrongSecretRejected(self):
        self.assertRaises(ServerPacketError, SelectSecret, self.host,
                          self._acct(b'nope'))

    def testCoaWrongSecretRejected(self):
        req = CoAPacket(secret=b'nope')
        pkt = CoAPacket(secret=b'nope', packet=req.RequestPacket())
        self.assertRaises(ServerPacketError, SelectSecret, self.host, pkt)


class NoSecretLoggingTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.secret = b'very-secret'
        self.host = RemoteHost('127.0.0.1', secrets=[
            SharedSecret(b'current', label='current', version=2),
            retired(self.secret, 'retired-1', self.clock,
                    valid_days=1, version=1),
        ], clock=self.clock)

    def testLogRecordsNeverContainSecretMaterial(self):
        import logging
        import io
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger('pyrad')
        logger.addHandler(handler)
        try:
            # a rejected packet logs a one-line drop message
            pkt = auth_request(b'wrong')
            self.assertRaises(ServerPacketError, SelectSecret,
                              self.host, pkt)
            # an accepted retired secret logs at debug level
            logger.setLevel(logging.DEBUG)
            SelectSecret(self.host, auth_request(self.secret))
        finally:
            logger.removeHandler(handler)
        output = stream.getvalue()
        self.assertNotIn('very-secret', output)
        self.assertNotIn(self.secret.decode(), output)
        # only labels / versions identify the secret, never the material
        self.assertIn('version', output)


if __name__ == '__main__':
    unittest.main()
