import hashlib
import os
import select
import socket
import struct
import threading
import time
import types
import unittest
from io import StringIO
from unittest import mock
from .mock import MockPacket
from .mock import MockPoll
from .mock import MockSocket
from pyrad.client import Client
from pyrad.client import Timeout
from pyrad.packet import AuthPacket
from pyrad.packet import AccountingResponse
from pyrad.packet import AcctPacket
from pyrad.packet import AccessAccept
from pyrad.packet import AccessChallenge
from pyrad.packet import AccessReject
from pyrad.packet import AccessRequest
from pyrad.packet import AccountingRequest
from pyrad.dictionary import Dictionary

BIND_IP = "127.0.0.1"
BIND_PORT = 53535

ACCT_DICTIONARY = '''
ATTRIBUTE User-Name             1  string
ATTRIBUTE Acct-Status-Type      40 integer
ATTRIBUTE Acct-Delay-Time       41 integer
ATTRIBUTE Salted                200 string encrypt=2
VALUE     Acct-Status-Type      Start 1
'''

EAP_DICTIONARY = '''
ATTRIBUTE User-Name             1  string
ATTRIBUTE State                 24 octets
ATTRIBUTE EAP-Message           79 octets
ATTRIBUTE Message-Authenticator 80 octets
'''


class ConstructionTests(unittest.TestCase):
    def setUp(self):
        self.server = object()

    def testSimpleConstruction(self):
        client = Client(self.server)
        self.assertTrue(client.server is self.server)
        self.assertEqual(client.authport, 1812)
        self.assertEqual(client.acctport, 1813)
        self.assertEqual(client.secret, b'')
        self.assertEqual(client.retries, 3)
        self.assertEqual(client.timeout, 5)
        self.assertTrue(client.dict is None)

    def testParameterOrder(self):
        marker = object()
        client = Client(self.server, 123, 456, 789, "secret", marker)
        self.assertTrue(client.server is self.server)
        self.assertEqual(client.authport, 123)
        self.assertEqual(client.acctport, 456)
        self.assertEqual(client.coaport, 789)
        self.assertEqual(client.secret, "secret")
        self.assertTrue(client.dict is marker)

    def testNamedParameters(self):
        marker = object()
        client = Client(server=self.server, authport=123, acctport=456,
                        secret="secret", dict=marker)
        self.assertTrue(client.server is self.server)
        self.assertEqual(client.authport, 123)
        self.assertEqual(client.acctport, 456)
        self.assertEqual(client.secret, "secret")
        self.assertTrue(client.dict is marker)


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.server = object()
        self.client = Client(self.server)
        self.orgsocket = socket.socket
        socket.socket = MockSocket

    def tearDown(self):
        socket.socket = self.orgsocket

    def testReopen(self):
        self.client._SocketOpen()
        sock = self.client._socket
        self.client._SocketOpen()
        self.assertTrue(sock is self.client._socket)

    def testBind(self):
        self.client.bind((BIND_IP, BIND_PORT))
        self.assertEqual(self.client._socket.address, (BIND_IP, BIND_PORT))
        self.assertEqual(self.client._socket.options,
                         [(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)])

    def testBindClosesSocket(self):
        s = MockSocket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client._socket = s
        self.client._poll = MockPoll()
        self.client.bind((BIND_IP, BIND_PORT))
        self.assertEqual(s.closed, True)

    def testSendPacket(self):
        def MockSend(self, pkt, port):
            self._mock_pkt = pkt
            self._mock_port = port

        _SendPacket = Client._SendPacket
        Client._SendPacket = MockSend

        self.client.SendPacket(AuthPacket())
        self.assertEqual(self.client._mock_port, self.client.authport)

        self.client.SendPacket(AcctPacket())
        self.assertEqual(self.client._mock_port, self.client.acctport)

        Client._SendPacket = _SendPacket

    def testNoRetries(self):
        self.client.retries = 0
        self.assertRaises(Timeout, self.client._SendPacket, None, None)

    def testSingleRetry(self):
        self.client.retries = 1
        self.client.timeout = 0
        packet = MockPacket(AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(self.client._socket.output,
                         [("request packet", (self.server, 432))])

    def testDoubleRetry(self):
        self.client.retries = 2
        self.client.timeout = 0
        packet = MockPacket(AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(self.client._socket.output,
                         [("request packet", (self.server, 432)),
                          ("request packet", (self.server, 432))])

    def testAuthDelay(self):
        self.client.retries = 2
        self.client.timeout = 1
        packet = MockPacket(AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertFalse("Acct-Delay-Time" in packet)

    def testSingleAccountDelay(self):
        self.client.retries = 2
        self.client.timeout = 1
        packet = MockPacket(AccountingRequest)
        packet.dict = Dictionary(StringIO(ACCT_DICTIONARY))
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(packet["Acct-Delay-Time"], [1])

    def testDoubleAccountDelay(self):
        self.client.retries = 3
        self.client.timeout = 1
        packet = MockPacket(AccountingRequest)
        packet.dict = Dictionary(StringIO(ACCT_DICTIONARY))
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(packet["Acct-Delay-Time"], [2])

    def testAccountDelayWithoutDictionary(self):
        self.client.retries = 2
        self.client.timeout = 0
        packet = MockPacket(AccountingRequest)
        packet.dict = None
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertFalse("Acct-Delay-Time" in packet)
        self.assertEqual(len(self.client._socket.output), 2)

    def testIgnorePacketError(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b'valid reply')
        packet = MockPacket(AccountingRequest, verify=True, error=True)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)

    def testValidReply(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b'valid reply')
        self.client._poll = MockPoll()
        MockPoll.results = [(1, select.POLLIN)]
        packet = MockPacket(AccountingRequest, verify=True)
        reply = self.client._SendPacket(packet, 432)
        self.assertTrue(reply is packet.reply)

    def testInvalidReply(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b'invalid reply')
        MockPoll.results = [(1, select.POLLIN)]
        packet = MockPacket(AccountingRequest, verify=False)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.server = object()
        self.client = Client(self.server, secret=b'zeer geheim')

    def testCreateAuthPacket(self):
        packet = self.client.CreateAuthPacket(id=15)
        self.assertTrue(isinstance(packet, AuthPacket))
        self.assertTrue(packet.dict is self.client.dict)
        self.assertEqual(packet.id, 15)
        self.assertEqual(packet.secret, b'zeer geheim')

    def testCreateAuthPacketDecodesMessageAuthenticator(self):
        # decoding a received packet keeps what it contains
        raw = AuthPacket(secret=b'zeer geheim').RequestPacket()
        decoded = self.client.CreateAuthPacket(packet=raw)
        self.assertFalse(decoded.message_authenticator)
        self.assertNotIn(80, decoded)
        self.assertEqual(decoded.RequestPacket(), raw)
        self.assertTrue(self.client.CreateAuthPacket().message_authenticator)

    def testCreateAcctPacket(self):
        packet = self.client.CreateAcctPacket(id=15)
        self.assertTrue(isinstance(packet, AcctPacket))
        self.assertTrue(packet.dict is self.client.dict)
        self.assertEqual(packet.id, 15)
        self.assertEqual(packet.secret, b'zeer geheim')


class EapMd5Tests(unittest.TestCase):
    """The EAP-MD5 exchange in SendPacket, with _SendPacket faked."""

    challenge = b'0123456789abcdef'

    def setUp(self):
        self.client = Client(object(), secret=b'secret')
        self.sent = []
        self.replies = []

    def fakeSendPacket(self, pkt, port):
        self.sent.append((port, pkt[79][0], pkt.get(24), 2 in pkt))
        return self.replies.pop(0)

    def reply(self, code, attributes={}):
        reply = AuthPacket(code=code, secret=b'secret')
        for (key, value) in attributes.items():
            reply[key] = value
        return reply

    def send(self, attributes):
        pkt = self.client.CreateAuthPacket(auth_type='eap-md5')
        for (key, value) in attributes.items():
            pkt[key] = value
        self.client._SendPacket = self.fakeSendPacket
        return self.client.SendPacket(pkt)

    def eapRequest(self, eap_id=7, name=b''):
        return (struct.pack('!BBHBB', 1, eap_id, 22 + len(name), 4, 16)
                + self.challenge + name)

    def testIdentity(self):
        # the EAP-Identity is the User-Name, not the password (#151)
        accept = self.reply(AccessAccept)
        self.replies = [accept]
        self.assertIs(self.send({1: [b'alice'], 2: [b'password']}), accept)
        ((port, eap, state, user_password),) = self.sent
        self.assertEqual(port, self.client.authport)
        self.assertEqual(eap[0:1], b'\x02')  # EAP-Response
        self.assertEqual(eap[2:], struct.pack('!HB', 10, 1) + b'alice')
        self.assertIsNone(state)
        self.assertFalse(user_password)

    def testLongIdentity(self):
        # RFC 3579 section 3.1: an EAP-Response/Identity longer than 253
        # bytes is split over several EAP-Message attributes
        for length in (248, 249, 253):
            identity = b'a' * length
            encoded = []

            def fakeSendPacket(pkt, port):
                encoded.append(AuthPacket(secret=b'secret', packet=pkt.RequestPacket()))
                return self.reply(AccessAccept)

            pkt = self.client.CreateAuthPacket(auth_type='eap-md5')
            pkt[1] = [identity]
            pkt[2] = [b'password']
            self.client._SendPacket = fakeSendPacket
            self.client.SendPacket(pkt)
            ((request,),) = [encoded]
            self.assertTrue(all(len(value) <= 253 for value in request[79]))
            eap = b''.join(request[79])
            self.assertEqual(eap[2:], struct.pack('!HB', length + 5, 1) + identity)

    def testChallenge(self):
        accept = self.reply(AccessAccept)
        self.replies = [self.reply(AccessChallenge, {79: [self.eapRequest()], 24: [b'state']}),
                        accept]
        self.assertIs(self.send({1: [b'alice'], 2: [b'password']}), accept)
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sent[0][1][4:], b'\x01alice')
        (port, eap, state, user_password) = self.sent[1]
        digest = hashlib.md5(b'\x07' + b'password' + self.challenge).digest()
        self.assertEqual(eap, struct.pack('!BBHBB', 2, 7, 22, 4, 16) + digest)
        self.assertEqual(state, [b'state'])
        # RFC 3579 section 3.3: no User-Password with EAP-Message
        self.assertFalse(user_password)

    def testUserPasswordIsRestored(self):
        self.replies = [self.reply(AccessChallenge, {79: [self.eapRequest()]}),
                        self.reply(AccessReject)]
        pkt = self.client.CreateAuthPacket(auth_type='eap-md5')
        pkt[1] = [b'alice']
        pkt[2] = [b'password']
        self.client._SendPacket = self.fakeSendPacket
        self.client.SendPacket(pkt)
        self.assertEqual(pkt[2], [b'password'])

    def testChallengeWithName(self):
        # the Name after the Value is not part of the MD5 challenge
        accept = self.reply(AccessAccept)
        self.replies = [self.reply(AccessChallenge, {79: [self.eapRequest(name=b'server')],
                                                     24: [b'state']}),
                        accept]
        self.assertIs(self.send({1: [b'alice'], 2: [b'password']}), accept)
        eap = self.sent[1][1]
        digest = hashlib.md5(b'\x07' + b'password' + self.challenge).digest()
        self.assertEqual(eap, struct.pack('!BBHBB', 2, 7, 22, 4, 16) + digest)

    def testChallengeSplitOverEapMessages(self):
        # RFC 3579 section 3.1
        request = self.eapRequest()
        accept = self.reply(AccessAccept)
        self.replies = [self.reply(AccessChallenge, {79: [request[:10], request[10:]]}),
                        accept]
        self.assertIs(self.send({1: [b'alice'], 2: [b'password']}), accept)
        digest = hashlib.md5(b'\x07' + b'password' + self.challenge).digest()
        self.assertEqual(self.sent[1][1], struct.pack('!BBHBB', 2, 7, 22, 4, 16) + digest)

    def testChallengeWithoutState(self):
        accept = self.reply(AccessAccept)
        self.replies = [self.reply(AccessChallenge, {79: [self.eapRequest()]}), accept]
        self.assertIs(self.send({1: [b'alice'], 2: [b'password'], 24: [b'old']}), accept)
        self.assertIsNone(self.sent[1][2])

    def testOtherChallengeIsReturned(self):
        # a challenge which is not EAP-MD5, e.g. another EAP type
        for eap in ([struct.pack('!BBHB', 1, 7, 6, 13) + b'\x20'], []):
            challenge = self.reply(AccessChallenge, {79: eap} if eap else {})
            self.replies = [challenge]
            self.sent = []
            self.assertIs(self.send({1: [b'alice'], 2: [b'password']}), challenge)
            self.assertEqual(len(self.sent), 1)

    def testMissingUserNameOrPassword(self):
        self.client._SendPacket = self.fakeSendPacket
        for attributes in ({1: [b'alice']}, {2: [b'password']}):
            pkt = self.client.CreateAuthPacket(auth_type='eap-md5')
            for (key, value) in attributes.items():
                pkt[key] = value
            self.assertRaises(ValueError, self.client.SendPacket, pkt)
        self.assertEqual(self.sent, [])

    def testChallengeNewIdAndAuthenticator(self):
        # RFC 2865 section 4.4: the answer to an Access-Challenge is a new
        # Access-Request with a new Identifier and Request Authenticator
        self.client.dict = Dictionary(StringIO(EAP_DICTIONARY))
        self.replies = [self.reply(AccessChallenge, {79: [self.eapRequest()], 24: [b'state']}),
                        self.reply(AccessAccept)]
        requests = []

        def fakeSendPacket(pkt, port):
            requests.append(pkt.RequestPacket())
            return self.replies.pop(0)

        pkt = self.client.CreateAuthPacket(auth_type='eap-md5', User_Name='alice')
        pkt[2] = [b'password']
        self.client._SendPacket = fakeSendPacket
        self.client.SendPacket(pkt)
        (first, second) = requests
        self.assertNotEqual(first[1], second[1])
        self.assertNotEqual(first[4:20], second[4:20])
        self.assertEqual(second[1], pkt.id)
        self.assertEqual(second[4:20], pkt.authenticator)
        decoded = AuthPacket(secret=b'secret', dict=self.client.dict, packet=second)
        self.assertTrue(decoded.verify_message_authenticator())
        self.assertNotIn(2, decoded)

    def testChallengeIgnoredForPap(self):
        challenge = self.reply(AccessChallenge)
        self.replies = [challenge]
        pkt = self.client.CreateAuthPacket()
        pkt[79] = [b'eap']
        self.client._SendPacket = self.fakeSendPacket
        self.assertIs(self.client.SendPacket(pkt), challenge)
        self.assertEqual(len(self.sent), 1)


class EapMd5WireTests(unittest.TestCase):
    """The EAP-MD5 exchange with the client socket faked, so that the
    scripted server runs synchronously inside sendto().

    All packets are really encoded and decoded; the requests on the wire
    and the input of every MD5 hash involving the password are recorded,
    to prove that the password is only used for the legitimate challenge
    of the current authentication.
    """

    password = b's0leil'
    challenge = b'0123456789abcdef'

    def setUp(self):
        self.dict = Dictionary(StringIO(EAP_DICTIONARY))
        self.client = Client('127.0.0.1', secret=b'secret', dict=self.dict,
                             retries=1, timeout=0.5)
        self.received = []    # the decoded requests, in arrival order
        self.raw = []         # the raw requests, in arrival order
        self.md5_inputs = []  # data of every hashlib.md5 call with the password
        real_md5 = hashlib.md5

        def recording_md5(data=b'', **kwargs):
            if self.password in data:
                self.md5_inputs.append(data)
            return real_md5(data, **kwargs)

        self.real_md5 = real_md5
        patcher = mock.patch('pyrad.client.hashlib.md5', recording_md5)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.client._CloseSocket()

    def send(self, pkt):
        """Send pkt with a fake client socket: sendto() decodes the really
        encoded request, runs the scripted server and queues its replies
        for recv()."""
        test = self

        class FakeSocket:
            def __init__(self, family, type):
                self.replies = []
                (self.read_end, self.write_end) = os.pipe()

            def fileno(self):
                return self.read_end

            def sendto(self, data, target):
                test.raw.append(data)
                request = AuthPacket(secret=b'secret', dict=test.dict, packet=data)
                test.received.append(request)
                for reply in test.script(request):
                    self.replies.append(reply)
                    os.write(self.write_end, b'x')

            def recv(self, size):
                os.read(self.read_end, 1)
                return self.replies.pop(0)

            def setsockopt(self, *args):
                pass

            def close(self):
                os.close(self.read_end)
                os.close(self.write_end)

        real_socket = socket.socket
        socket.socket = FakeSocket
        try:
            return self.client.SendPacket(pkt)
        finally:
            socket.socket = real_socket

    def reply(self, request, code, attributes={}):
        reply = request.CreateReply()
        reply.code = code
        for (key, value) in attributes.items():
            reply[key] = value
        return reply.ReplyPacket()

    def eapChallenge(self, request, eap_id=7, state=b'state'):
        return self.reply(request, AccessChallenge,
                          {79: [struct.pack('!BBHBB', 1, eap_id, 22, 4, 16)
                                + self.challenge],
                           24: [state]})

    def request(self):
        pkt = self.client.CreateAuthPacket(auth_type='eap-md5')
        pkt[1] = [b'alice']
        pkt[2] = [self.password]
        return pkt

    def hashInput(self, eap_id=7):
        return struct.pack('!B', eap_id) + self.password + self.challenge

    def testChallengeResponseOnTheWire(self):
        def script(request):
            if len(self.received) == 1:
                return [self.eapChallenge(request)]
            return [self.reply(request, AccessAccept)]

        self.script = script
        pkt = self.request()
        reply = self.send(pkt)

        self.assertEqual(reply.code, AccessAccept)
        self.assertEqual(len(self.received), 2)
        (identity, response) = self.received
        # the EAP-Response/Identity carries the User-Name
        eap = identity[79][0]
        self.assertEqual(eap[0], 2)  # EAP-Response
        self.assertEqual(eap[4], 1)  # Identity
        self.assertEqual(eap[5:], b'alice')
        # RFC 3579 section 3.3: no cleartext User-Password on the wire
        self.assertNotIn(2, identity)
        self.assertNotIn(2, response)
        self.assertNotIn(self.password, b''.join(self.raw))
        # the answer to the challenge is a new request (RFC 2865 section 4.4)
        self.assertNotEqual(response.id, identity.id)
        self.assertNotEqual(response.authenticator, identity.authenticator)
        # the EAP Identifier and the State of the challenge are returned
        digest = self.real_md5(self.hashInput()).digest()
        self.assertEqual(response[79], [struct.pack('!BBHBB', 2, 7, 22, 4, 16) + digest])
        self.assertEqual(response[24], [b'state'])
        # the password was hashed exactly once, for this challenge only
        self.assertEqual(self.md5_inputs, [self.hashInput()])
        self.assertEqual(pkt[2], [self.password])

    def testMalformedChallengeIsNotAnswered(self):
        # a malformed challenge neither crashes the client nor uses the
        # password; it is returned to the caller as the reply
        malformed = [
            # declared Length smaller than the MD5-Challenge header
            struct.pack('!BBHBB', 1, 7, 5, 4, 16) + self.challenge,
            struct.pack('!BBHBB', 1, 7, 4, 4, 16) + self.challenge,
            # declared Length beyond the received EAP packet
            struct.pack('!BBH', 1, 7, 60) + b'\x04\x10' + self.challenge,
            # Value-Size doesn't fit in the declared Length
            struct.pack('!BBHBB', 1, 7, 22, 4, 32) + self.challenge,
        ]

        def script(request):
            eap = malformed[len(self.received) - 1]
            return [self.reply(request, AccessChallenge, {79: [eap]})]

        self.script = script
        for _ in malformed:
            self.md5_inputs = []
            pkt = self.request()
            reply = self.send(pkt)
            self.assertEqual(reply.code, AccessChallenge)
            self.assertEqual(self.md5_inputs, [])
            self.assertEqual(pkt[2], [self.password])
        # no malformed challenge was answered
        self.assertEqual(len(self.received), len(malformed))

    def testDuplicateChallengeIsNotAnsweredAgain(self):
        # a retransmitted challenge, e.g. after a duplicate of the first
        # Access-Request, is not answered a second time
        def script(request):
            return [self.eapChallenge(request)]

        self.script = script
        pkt = self.request()
        reply = self.send(pkt)
        self.assertEqual(reply.code, AccessChallenge)
        self.assertEqual(len(self.received), 2)
        self.assertEqual(self.md5_inputs, [self.hashInput()])
        self.assertEqual(pkt[2], [self.password])

    def testChallengeAfterRejectIsIgnored(self):
        # a challenge after the final reply doesn't use the password
        def script(request):
            return [self.reply(request, AccessReject),
                    self.eapChallenge(request)]

        self.script = script
        pkt = self.request()
        reply = self.send(pkt)
        self.assertEqual(reply.code, AccessReject)
        self.assertEqual(len(self.received), 1)
        self.assertEqual(self.md5_inputs, [])
        self.assertEqual(pkt[2], [self.password])

    def testChallengeOfOtherTransactionIsIgnored(self):
        # challenges which are not a valid reply to the request of this
        # authentication are dropped before they can reach the EAP-MD5 flow
        def stray(request, id, authenticator):
            challenge = AuthPacket(code=AccessChallenge, id=id,
                                   secret=b'secret', authenticator=authenticator,
                                   dict=self.dict)
            challenge[79] = [struct.pack('!BBHBB', 1, 7, 22, 4, 16) + self.challenge]
            return challenge.ReplyPacket()

        def script(request):
            if len(self.received) == 1:
                return [stray(request, (request.id + 1) % 256, request.authenticator),
                        stray(request, request.id, bytes(16)),
                        self.eapChallenge(request)]
            return [self.reply(request, AccessAccept)]

        self.script = script
        pkt = self.request()
        reply = self.send(pkt)
        self.assertEqual(reply.code, AccessAccept)
        self.assertEqual(len(self.received), 2)
        self.assertEqual(self.md5_inputs, [self.hashInput()])
        self.assertEqual(pkt[2], [self.password])

    def testTimeoutRestoresUserPassword(self):
        self.script = lambda request: []
        pkt = self.request()
        self.assertRaises(Timeout, self.send, pkt)
        self.assertEqual(pkt[2], [self.password])
        self.assertEqual(self.md5_inputs, [])
        self.assertEqual(len(self.received), 1)
        self.assertNotIn(2, self.received[0])

    def testTimeoutAfterChallengeRestoresUserPassword(self):
        def script(request):
            if len(self.received) == 1:
                return [self.eapChallenge(request)]
            return []

        self.script = script
        pkt = self.request()
        self.assertRaises(Timeout, self.send, pkt)
        self.assertEqual(pkt[2], [self.password])
        self.assertEqual(self.md5_inputs, [self.hashInput()])
        self.assertEqual(len(self.received), 2)


class LoopbackTests(unittest.TestCase):
    """_SendPacket against a fake server on a loopback socket."""

    def setUp(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(('127.0.0.1', 0))
        self.server.settimeout(5)
        port = self.server.getsockname()[1]
        self.client = Client('127.0.0.1', authport=port, acctport=port,
                             coaport=port, secret=b'secret',
                             retries=1, timeout=0.2)

    def tearDown(self):
        self.client._CloseSocket()
        self.server.close()

    def testClockStepBackwards(self):
        # a step of the wall clock does not extend the timeout
        real_time = time.time
        calls = []

        def stepping_time():
            calls.append(None)
            return real_time() - (3 if len(calls) > 1 else 0)

        clock = types.SimpleNamespace(time=stepping_time, monotonic=time.monotonic)
        start = time.monotonic()
        with mock.patch('pyrad.client.time', clock):
            self.assertRaises(Timeout, self.client.SendPacket,
                              self.client.CreateAcctPacket())
        self.assertLess(time.monotonic() - start, 2)

    def testAccountDelayUndefined(self):
        # a retry does not fail if the dictionary has no Acct-Delay-Time
        self.client.dict = Dictionary(StringIO('ATTRIBUTE User-Name 1 string\n'))
        self.client.retries = 2
        self.client.timeout = 0.1
        pkt = self.client.CreateAcctPacket(User_Name='alice')
        self.assertRaises(Timeout, self.client.SendPacket, pkt)
        self.server.recv(4096)
        self.server.recv(4096)
        self.assertEqual(pkt.keys(), ['User-Name'])

    def testLateReplyToEarlierAttempt(self):
        # every retry changes Acct-Delay-Time and so the Request
        # Authenticator; a late reply to an earlier attempt is accepted
        self.client.dict = Dictionary(StringIO(ACCT_DICTIONARY))
        self.client.retries = 2
        self.client.timeout = 0.5
        received = []

        def serve():
            received.append(self.server.recvfrom(4096))
            received.append(self.server.recvfrom(4096))
            (data, source) = received[0]
            request = AcctPacket(secret=b'secret', dict=self.client.dict, packet=data)
            reply = request.CreateReply()
            reply['Salted'] = 'salt'
            self.server.sendto(reply.ReplyPacket(), source)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            pkt = self.client.CreateAcctPacket(User_Name='alice', Acct_Status_Type='Start')
            reply = self.client.SendPacket(pkt)
        finally:
            thread.join()
        first = received[0][0]
        self.assertNotEqual(first[4:20], received[1][0][4:20])
        self.assertEqual(reply.code, AccountingResponse)
        self.assertEqual(reply.request_authenticator, first[4:20])
        self.assertEqual(reply['Salted'], ['salt'])

    def testAuthWithoutDictionary(self):
        # an Access-Request (with the default Message-Authenticator) can be
        # sent without a dictionary
        self.assertIsNone(self.client.dict)

        def serve():
            (data, source) = self.server.recvfrom(4096)
            request = AuthPacket(secret=b'secret', dict=None, packet=data)
            reply = request.CreateReply()
            reply.code = AccessAccept
            self.server.sendto(reply.ReplyPacket(), source)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            pkt = self.client.CreateAuthPacket()
            pkt[1] = [b'alice']
            reply = self.client.SendPacket(pkt)
        finally:
            thread.join()
        self.assertEqual(reply.code, AccessAccept)
        self.assertIn(80, reply)
