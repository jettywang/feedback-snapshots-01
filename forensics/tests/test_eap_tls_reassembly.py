"""Tests for the offline EAP-TLS reassembly component.

Fixtures are built offline with pyrad itself; no RADIUS server is
involved. Two sessions are interleaved in one capture, including one
retransmitted fragment, one forged packet, one truncated message and
one orphan fragment.
"""

import struct
import unittest

from pyrad import packet as radius_packet

from forensics.eap_tls_reassembly import (
    Direction,
    EapTlsReassembler,
    MessageStatus,
    Verification,
)

SECRET = b'offline-forensics-test-secret'
STATION_A = b'00:11:22:33:44:0a'
STATION_B = b'00:11:22:33:44:0b'

L_FLAG = 0x80
M_FLAG = 0x40
S_FLAG = 0x20

EAP_REQUEST = 1
EAP_RESPONSE = 2


def pattern(seed, length):
    return bytes(((seed + 7 * i) % 256 for i in range(length)))


def eap_tls(code, ident, flags, data=b'', total=None):
    body = bytes([13, flags])
    if flags & L_FLAG:
        body += struct.pack('!I', total)
    body += data
    return struct.pack('!BBH', code, ident, 4 + len(body)) + body


def eap_identity(ident, name=b'probe@example'):
    return struct.pack('!BBH', EAP_RESPONSE, ident, 5 + len(name)) \
        + bytes([1]) + name


def eap_success(ident):
    return struct.pack('!BBH', 3, ident, 4)


def build_request(rad_id, eap_chunks, station, state=None):
    pkt = radius_packet.AuthPacket(code=radius_packet.AccessRequest,
                                   id=rad_id, secret=SECRET)
    pkt.add_message_authenticator()
    pkt[1] = [b'probe@example']
    pkt[31] = [station]
    if state is not None:
        pkt[24] = [state]
    if eap_chunks is not None:
        pkt[79] = eap_chunks if isinstance(eap_chunks, list) else [eap_chunks]
    return pkt, pkt.RequestPacket()


def build_reply(req_pkt, code, eap=None, state=None):
    reply = req_pkt.CreateReply()
    reply.code = code
    if state is not None:
        reply[24] = [state]
    if eap is not None:
        reply[79] = [eap]
    return reply, reply.ReplyPacket()


class InterleavedCapture:
    """Build the two-session interleaved capture once."""

    def __init__(self):
        self.client_a = pattern(3, 500)
        self.server_a = pattern(90, 300)
        self.client_b = pattern(140, 450)
        self.orphan_b = pattern(220, 50)
        self.captures = []
        t = 1700000000.0

        def emit(raw):
            nonlocal t
            self.captures.append((raw, t))
            t += 1.0

        # session A: identity, TLS start, fragmented ClientHello
        pkt, raw = build_request(1, eap_identity(10), STATION_A)
        emit(raw)
        _, raw = build_reply(pkt, radius_packet.AccessChallenge,
                             eap_tls(EAP_REQUEST, 11, S_FLAG), state=b'SA1')
        emit(raw)
        frag = eap_tls(EAP_RESPONSE, 11, L_FLAG | M_FLAG,
                       self.client_a[0:180], 500)
        pkt, raw = build_request(2, [frag[:100], frag[100:]], STATION_A,
                                 state=b'SA1')
        emit(raw)
        _, raw = build_reply(pkt, radius_packet.AccessChallenge,
                             eap_tls(EAP_REQUEST, 12, 0), state=b'SA2')
        emit(raw)
        pkt, raw = build_request(3, eap_tls(EAP_RESPONSE, 12, M_FLAG,
                                            self.client_a[180:360]),
                                 STATION_A, state=b'SA2')
        emit(raw)
        _, raw = build_reply(pkt, radius_packet.AccessChallenge,
                             eap_tls(EAP_REQUEST, 13, 0), state=b'SA3')
        emit(raw)
        pkt, raw = build_request(4, eap_tls(EAP_RESPONSE, 13, 0,
                                            self.client_a[360:500]),
                                 STATION_A, state=b'SA3')
        emit(raw)
        # forged packet: valid shape, corrupted Message-Authenticator
        forged = bytearray(build_request(
            50, eap_tls(EAP_RESPONSE, 13, 0, pattern(60, 40)),
            STATION_A, state=b'SA3')[1])
        forged[25] ^= 0xFF
        emit(bytes(forged))
        # session A: fragmented server message, then accept
        _, raw = build_reply(pkt, radius_packet.AccessChallenge,
                             eap_tls(EAP_REQUEST, 14, L_FLAG | M_FLAG,
                                     self.server_a[0:150], 300), state=b'SA4')
        emit(raw)
        pkt, raw = build_request(5, eap_tls(EAP_RESPONSE, 14, 0), STATION_A,
                                 state=b'SA4')
        emit(raw)
        _, raw = build_reply(pkt, radius_packet.AccessChallenge,
                             eap_tls(EAP_REQUEST, 15, 0,
                                     self.server_a[150:300]), state=b'SA5')
        emit(raw)
        pkt, raw = build_request(6, eap_tls(EAP_RESPONSE, 15, 0), STATION_A,
                                 state=b'SA5')
        emit(raw)
        _, raw = build_reply(pkt, radius_packet.AccessAccept,
                             eap_success(15))
        emit(raw)

        # session B: truncated message, duplicate fragment, orphan bytes
        pkt, raw = build_request(101, eap_identity(20), STATION_B)
        emit(raw)
        _, raw = build_reply(pkt, radius_packet.AccessChallenge,
                             eap_tls(EAP_REQUEST, 21, S_FLAG), state=b'SB1')
        emit(raw)
        pkt, raw_b2 = build_request(102, eap_tls(EAP_RESPONSE, 21,
                                                 L_FLAG | M_FLAG,
                                                 self.client_b[0:200], 450),
                                    STATION_B, state=b'SB1')
        emit(raw_b2)
        _, raw = build_reply(pkt, radius_packet.AccessChallenge,
                             eap_tls(EAP_REQUEST, 22, 0), state=b'SB2')
        emit(raw)
        pkt, raw = build_request(103, eap_tls(EAP_RESPONSE, 22, M_FLAG,
                                              self.client_b[200:400]),
                                 STATION_B, state=b'SB2')
        emit(raw)
        emit(raw_b2)  # retransmission of the first fragment
        # final fragment (id 23) is missing from the capture; the next
        # fragment skips to id 24, so its offset cannot be determined
        pkt, raw = build_request(104, eap_tls(EAP_RESPONSE, 24, 0,
                                              self.orphan_b),
                                 STATION_B, state=b'SB2')
        emit(raw)


class TestInterleavedReassembly(unittest.TestCase):
    def setUp(self):
        capture = InterleavedCapture()
        self.capture = capture
        # feed packets out of order; the reassembler sorts by receive time
        shuffled = list(reversed(capture.captures))
        self.report = EapTlsReassembler(SECRET).process(shuffled)

    def session(self, station):
        return self.report.sessions[(station, None)]

    def testAllGenuinePacketsVerified(self):
        failed = [rec.index for rec in self.report.packets
                  if rec.verification is Verification.FAILED]
        self.assertEqual(len(failed), 1)  # only the forged packet
        forged = self.report.packets[failed[0]]
        self.assertEqual(forged.radius_id, 50)
        verified = [rec for rec in self.report.packets
                    if rec.verification is Verification.VERIFIED]
        self.assertEqual(len(verified), len(self.report.packets) - 2)

    def testDuplicateDetected(self):
        duplicates = [rec for rec in self.report.packets
                      if rec.duplicate_of is not None]
        self.assertEqual(len(duplicates), 1)
        original = self.report.packets[duplicates[0].duplicate_of]
        self.assertEqual(original.radius_id, 102)

    def testSessionAComplete(self):
        sess = self.session(STATION_A)
        self.assertEqual(len(sess.messages), 2)
        client_msg, server_msg = sess.messages
        self.assertEqual(client_msg.status, MessageStatus.COMPLETE)
        self.assertEqual(client_msg.direction, Direction.PEER_TO_SERVER)
        self.assertEqual(client_msg.declared_length, 500)
        self.assertEqual(client_msg.reassembled(), self.capture.client_a)
        self.assertEqual(server_msg.status, MessageStatus.COMPLETE)
        self.assertEqual(server_msg.direction, Direction.SERVER_TO_PEER)
        self.assertEqual(server_msg.reassembled(), self.capture.server_a)

    def testProvenanceOfFragmentedMessage(self):
        sess = self.session(STATION_A)
        msg = sess.messages[0]
        self.assertEqual([seg.offset for seg in msg.segments], [0, 180, 360])
        first = msg.segments[0]
        # EAP header is 10 bytes (4 EAP + 1 type + 1 flags + 4 length);
        # the packet split the 190-byte EAP over two attributes [100, 90]
        self.assertEqual([(s.ordinal, s.start, s.end) for s in first.spans],
                         [(0, 10, 100), (1, 0, 90)])
        for seg in msg.segments:
            self.assertEqual(seg.packet_index,
                             self.report.packets[seg.packet_index].index)

    def testSessionBTruncatedAndOrphan(self):
        sess = self.session(STATION_B)
        self.assertEqual(len(sess.messages), 2)
        truncated, orphan = sess.messages
        self.assertEqual(truncated.status, MessageStatus.TRUNCATED)
        self.assertEqual(truncated.declared_length, 450)
        self.assertEqual(truncated.received, 400)  # duplicate not appended
        self.assertEqual(truncated.reassembled(),
                         self.capture.client_b[0:400])
        self.assertEqual(orphan.status, MessageStatus.UNATTRIBUTABLE)
        self.assertEqual(orphan.received, 50)
        self.assertIsNone(orphan.reassembled())
        self.assertEqual([seg.offset for seg in orphan.segments], [None])

    def testForgedPacketExcluded(self):
        self.assertEqual(self.report.total_reassembled_bytes, 1250)
        self.assertTrue(any('验真失败' in event
                            for event in self.report.events))

    def testRenderLabels(self):
        text = self.report.render()
        self.assertIn('完整', text)
        self.assertIn('截断', text)
        self.assertIn('关联不明', text)
        self.assertIn('Finished', text)  # disclaimer


class TestLimitsAndPolicy(unittest.TestCase):
    def testMessageByteCap(self):
        pkt, raw = build_request(1, eap_identity(1), STATION_A)
        _, chal = build_reply(pkt, radius_packet.AccessChallenge,
                              eap_tls(EAP_REQUEST, 2, S_FLAG), state=b'S')
        _, req2 = build_request(2, eap_tls(EAP_RESPONSE, 2, L_FLAG,
                                           pattern(5, 100), 100),
                                STATION_A, state=b'S')
        report = EapTlsReassembler(SECRET, max_message_bytes=60).process(
            [(raw, 1.0), (chal, 2.0), (req2, 3.0)])
        msg = report.sessions[(STATION_A, None)].messages[0]
        self.assertEqual(msg.received, 60)
        self.assertEqual(msg.status, MessageStatus.TRUNCATED)

    def testTotalByteCap(self):
        pkt, raw = build_request(1, eap_identity(1), STATION_A)
        _, chal = build_reply(pkt, radius_packet.AccessChallenge,
                              eap_tls(EAP_REQUEST, 2, S_FLAG), state=b'S')
        _, req2 = build_request(2, eap_tls(EAP_RESPONSE, 2, L_FLAG,
                                           pattern(5, 100), 100),
                                STATION_A, state=b'S')
        report = EapTlsReassembler(SECRET, max_total_bytes=40).process(
            [(raw, 1.0), (chal, 2.0), (req2, 3.0)])
        self.assertEqual(report.total_reassembled_bytes, 40)

    def testSessionLimit(self):
        _, raw_a = build_request(1, eap_tls(EAP_RESPONSE, 1, L_FLAG,
                                            pattern(1, 20), 20), STATION_A)
        _, raw_b = build_request(2, eap_tls(EAP_RESPONSE, 1, L_FLAG,
                                            pattern(2, 20), 20), STATION_B)
        report = EapTlsReassembler(SECRET, max_sessions=1).process(
            [(raw_a, 1.0), (raw_b, 2.0)])
        self.assertEqual(len(report.sessions), 1)
        self.assertTrue(any('上限' in event for event in report.events))

    def testUnverifiableRequestStillReassembled(self):
        pkt = radius_packet.AuthPacket(code=radius_packet.AccessRequest,
                                       id=7, secret=SECRET)
        pkt[31] = [STATION_A]
        pkt[79] = [eap_tls(EAP_RESPONSE, 1, L_FLAG, pattern(9, 30), 30)]
        raw = pkt.RequestPacket()  # no Message-Authenticator
        report = EapTlsReassembler(SECRET).process([(raw, 1.0)])
        rec = report.packets[0]
        self.assertEqual(rec.verification, Verification.UNVERIFIABLE)
        msg = report.sessions[(STATION_A, None)].messages[0]
        self.assertEqual(msg.status, MessageStatus.COMPLETE)
        strict = EapTlsReassembler(
            SECRET, require_message_authenticator=True).process([(raw, 1.0)])
        self.assertEqual(strict.sessions, {})

    def testReplyWithoutMatchingRequest(self):
        pkt, _ = build_request(1, eap_identity(1), STATION_A)
        _, chal = build_reply(pkt, radius_packet.AccessChallenge,
                              eap_tls(EAP_REQUEST, 2, L_FLAG | M_FLAG,
                                      pattern(4, 40), 40), state=b'S')
        report = EapTlsReassembler(SECRET).process([(chal, 1.0)])
        rec = report.packets[0]
        self.assertEqual(rec.verification, Verification.UNVERIFIABLE)
        self.assertIn(None, report.sessions)
        msg = report.sessions[None].messages[0]
        self.assertEqual(msg.received, 40)

    def testEapLevelDuplicate(self):
        # same EAP fragment re-sent inside a new RADIUS packet
        eap = eap_tls(EAP_RESPONSE, 3, L_FLAG | M_FLAG, pattern(8, 50), 100)
        _, raw1 = build_request(1, eap, STATION_A)
        _, raw2 = build_request(2, eap, STATION_A)
        report = EapTlsReassembler(SECRET).process([(raw1, 1.0), (raw2, 2.0)])
        msg = report.sessions[(STATION_A, None)].messages[0]
        self.assertEqual(msg.received, 50)


if __name__ == '__main__':
    unittest.main()
