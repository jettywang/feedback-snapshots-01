"""Tests for the example RFC 5176 CoA/Disconnect policy adapter.

The adapter lives under ``example/dynauth``; these tests exercise the policy
engine through real RADIUS packets (signed requests, verified replies) using
the in-process transport, so no socket is required.
"""

import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pyrad import packet  # noqa: E402

from example.dynauth.client import DynAuthClient  # noqa: E402
from example.dynauth.constants import COA_REQUEST  # noqa: E402
from example.dynauth.fixtures import (  # noqa: E402
    DICTIONARY_PATH,
    NAS_1,
    NAS_2,
    SECRET_OPS,
    SECRET_SUPPORT,
    SENDER_OPS,
    SENDER_SUPPORT,
    SENDER_UNKNOWN,
    build_sender_policies,
    build_senders,
    build_sessions,
)
from example.dynauth.policy import AuditLog  # noqa: E402
from example.dynauth.session_store import SessionStore  # noqa: E402
from example.dynauth.transport import LoopbackTransport, build_engine  # noqa: E402


class PolicyAdapterTest(unittest.TestCase):

    def setUp(self):
        self.store = SessionStore(build_sessions())
        self.audit = AuditLog()
        engine = build_engine(self.store, build_sender_policies(),
                              audit=self.audit)
        self.transport = LoopbackTransport(
            engine, build_senders(), DICTIONARY_PATH)
        self.ops = DynAuthClient(SECRET_OPS, DICTIONARY_PATH, SENDER_OPS)
        self.support = DynAuthClient(
            SECRET_SUPPORT, DICTIONARY_PATH, SENDER_SUPPORT)
        self.initial = self._snapshot()

    def _snapshot(self):
        return {key: session.snapshot()
                for key, session in self.store._sessions.items()}

    def _exchange(self, client, source, raw, request):
        reply_raw = self.transport.send(raw, (source, 3799))
        self.assertIsNotNone(reply_raw)
        return client.verify_reply(request, reply_raw)

    def _coa(self, client=..., **attrs):
        client = self.ops if client is ... else client
        raw, request = client.build_request(COA_REQUEST, **attrs)
        return self._exchange(client, client.source_address, raw, request)

    def _disconnect(self, client=..., **attrs):
        client = self.ops if client is ... else client
        raw, request = client.disconnect(**attrs)
        return self._exchange(client, client.source_address, raw, request)

    def testLegalCoaChangesAttributes(self):
        reply = self._coa(**{
            "NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001",
            "Filter-Id": "restricted", "Session-Timeout": 1200})
        self.assertEqual(reply.code, packet.CoAACK)
        session = self.store.get(NAS_1, "sess-1001")
        self.assertEqual(session.attributes["Filter-Id"], "restricted")
        self.assertEqual(session.attributes["Session-Timeout"], 1200)
        self.assertTrue(session.active)

    def testReplayedCoaReturnsSameResultWithoutSecondMutation(self):
        raw, request = self.ops.build_request(COA_REQUEST, **{
            "NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001",
            "Filter-Id": "restricted", "Session-Timeout": 1200})
        first = self._exchange(self.ops, SENDER_OPS, raw, request)
        before = self._snapshot()
        second_raw = self.transport.send(raw, (SENDER_OPS, 3799))
        second = self.ops.verify_reply(request, second_raw)
        self.assertEqual(first.code, second.code)
        self.assertEqual(before, self._snapshot())
        self.assertTrue(self.audit.all()[-1].replayed)

    def testReplayedNakReturnsSameErrorAndHasNoSideEffect(self):
        raw, request = self.ops.disconnect(**{
            "NAS-IP-Address": NAS_2, "Acct-Session-Id": "sess-2001"})
        first_raw = self.transport.send(raw, (SENDER_OPS, 3799))
        first = self.ops.verify_reply(request, first_raw)
        self.assertEqual(first.code, packet.DisconnectNAK)
        before = self._snapshot()
        second_raw = self.transport.send(raw, (SENDER_OPS, 3799))
        second = self.ops.verify_reply(request, second_raw)
        self.assertEqual(second.code, packet.DisconnectNAK)
        self.assertEqual(second["Error-Cause"], first["Error-Cause"])
        self.assertEqual(before, self._snapshot())
        self.assertTrue(self.audit.all()[-1].replayed)

    def testLegalDisconnectByFramedIp(self):
        reply = self._disconnect(**{
            "NAS-IP-Address": NAS_1, "Framed-IP-Address": "192.0.2.12"})
        self.assertEqual(reply.code, packet.DisconnectACK)
        self.assertFalse(self.store.get(NAS_1, "sess-1002").active)

    def testCrossNasDisconnectIsProhibited(self):
        before = self._snapshot()
        reply = self._disconnect(**{
            "NAS-IP-Address": NAS_2, "Acct-Session-Id": "sess-2001"})
        self.assertEqual(reply.code, packet.DisconnectNAK)
        self.assertEqual(reply["Error-Cause"][0],
                         "Administratively-Prohibited")
        self.assertEqual(before, self._snapshot())
        self.assertTrue(self.store.get(NAS_2, "sess-2001").active)

    def testCoaOnlySenderCannotDisconnect(self):
        reply = self._disconnect(
            client=self.support,
            **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001"})
        self.assertEqual(reply.code, packet.DisconnectNAK)
        self.assertEqual(reply["Error-Cause"][0],
                         "Administratively-Prohibited")
        self.assertEqual(self.initial, self._snapshot())

    def testUserNameAloneIsRejected(self):
        reply = self._disconnect(**{
            "NAS-IP-Address": NAS_1, "User-Name": "alice"})
        self.assertEqual(reply.code, packet.DisconnectNAK)
        self.assertEqual(reply["Error-Cause"][0], "Missing-Attribute")
        self.assertEqual(self.initial, self._snapshot())

    def testAmbiguousLocatorIsRejected(self):
        reply = self._disconnect(**{
            "NAS-IP-Address": NAS_1,
            "Calling-Station-Id": "AA-BB-SHARED-0001"})
        self.assertEqual(reply.code, packet.DisconnectNAK)
        self.assertEqual(reply["Error-Cause"][0],
                         "Session-Context-Not-Removable")
        self.assertTrue(self.store.get(NAS_1, "sess-1003").active)
        self.assertTrue(self.store.get(NAS_1, "sess-1004").active)

    def testUnknownSessionReturnsSessionContextNotFound(self):
        reply = self._coa(
            client=self.support,
            **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "missing",
               "Filter-Id": "x"})
        self.assertEqual(reply.code, packet.CoANAK)
        self.assertEqual(reply["Error-Cause"][0],
                         "Session-Context-Not-Found")
        self.assertEqual(self.initial, self._snapshot())

    def testUnsupportedCoaAttributeIsRejectedAtomically(self):
        # NAS-Port (5) is a locator-supported code in the dictionary but is
        # not an authorized change; bundle it with a valid change to prove no
        # partial application happens.
        reply = self._coa(**{
            "NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001",
            "Filter-Id": "restricted", "NAS-Port": 7})
        self.assertEqual(reply.code, packet.CoANAK)
        self.assertEqual(reply["Error-Cause"][0],
                         "Unsupported-Extension")
        self.assertEqual(self.initial, self._snapshot())

    def testCoaWithoutChangeAttributeIsRejected(self):
        reply = self._coa(**{
            "NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001"})
        self.assertEqual(reply.code, packet.CoANAK)
        self.assertEqual(reply["Error-Cause"][0], "Missing-Attribute")
        self.assertEqual(self.initial, self._snapshot())

    def testTamperedReplyFailsAuthenticatorVerification(self):
        raw, request = self.ops.disconnect(**{
            "NAS-IP-Address": NAS_1, "Framed-IP-Address": "192.0.2.12"})
        reply_raw = self.transport.send(raw, (SENDER_OPS, 3799))
        # Flip a byte in the Response Authenticator field.
        tampered = bytearray(reply_raw)
        tampered[5] ^= 0xFF
        with self.assertRaises(packet.PacketError):
            self.ops.verify_reply(request, bytes(tampered))

    def testBadSharedSecretIsDroppedSilently(self):
        attacker = DynAuthClient(b"wrong-secret", DICTIONARY_PATH, SENDER_OPS)
        raw, request = attacker.disconnect(
            **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001"})
        self.assertIsNone(self.transport.send(raw, (SENDER_OPS, 3799)))
        self.assertEqual(self.initial, self._snapshot())

    def testUnregisteredSenderIsDroppedSilently(self):
        client = DynAuthClient(
            SECRET_OPS, DICTIONARY_PATH, SENDER_UNKNOWN)
        raw, request = client.disconnect(
            **{"NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001"})
        self.assertIsNone(
            self.transport.send(raw, (SENDER_UNKNOWN, 3799)))
        self.assertEqual(self.initial, self._snapshot())

    def testMessageAuthenticatorIsVerified(self):
        client = DynAuthClient(
            SECRET_SUPPORT, DICTIONARY_PATH, SENDER_SUPPORT,
            with_message_authenticator=True)
        raw, request = client.build_request(COA_REQUEST, **{
            "NAS-IP-Address": NAS_1, "Acct-Session-Id": "sess-1001",
            "Filter-Id": "vpn"})
        reply = self._exchange(client, SENDER_SUPPORT, raw, request)
        self.assertEqual(reply.code, packet.CoAACK)
        # Tamper with the Message-Authenticator value (attribute code 80):
        # the transport must drop the packet instead of acting on it.
        tampered = bytearray(raw)
        offset = 20
        while offset < len(tampered):
            code = tampered[offset]
            length = tampered[offset + 1]
            if code == 80:
                tampered[offset + 2] ^= 0xFF
                break
            offset += length
        else:
            self.fail("Message-Authenticator attribute not found")
        self.assertIsNone(
            self.transport.send(bytes(tampered), (SENDER_SUPPORT, 3799)))


if __name__ == "__main__":
    unittest.main()
