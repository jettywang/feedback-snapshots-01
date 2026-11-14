# test_longextended.py
#
# Tests for the restricted support of long extended attributes
# (RFC 6929): fragmentation and reassembly, dictionary definitions and
# packet authentication over the attributes as received.
import struct
import unittest

from io import StringIO
from pyrad import packet
from pyrad.dictionary import Dictionary
from pyrad.packet import LongExtendedKey

DICTIONARY = """
ATTRIBUTE  User-Name              1     string
ATTRIBUTE  Message-Authenticator  80    octets
ATTRIBUTE  Long-Extended-Type-1   245   long-extended
ATTRIBUTE  Long-Extended-Type-2   246   long-extended
ATTRIBUTE  Test-Long-String       245.1 string
ATTRIBUTE  Test-Long-Other        245.2 string
ATTRIBUTE  Test-Long-Data         246.1 octets
"""


def Fragment(type, extended_type, data, more=False, length=None):
    """Encode one fragment of a long extended attribute (RFC 6929)."""
    flags = 0x80 if more else 0
    if length is None:
        length = 4 + len(data)
    return struct.pack('!BBBB', type, length, extended_type, flags) + data


def RawPacket(attributes, code=1, id=2, authenticator=b'1234567890123456'):
    return struct.pack('!BBH16s', code, id, 20 + len(attributes),
                       authenticator) + attributes


class LimitedPacket(packet.Packet):
    max_long_extended_size = 100


class LongExtendedKeyTests(unittest.TestCase):
    def testKeyIsTuple(self):
        key = LongExtendedKey(245, 1)
        self.assertEqual(key, (245, 1))
        self.assertEqual(hash(key), hash((245, 1)))
        self.assertEqual(key[0], 245)
        self.assertEqual(key[1], 1)

    def testInvalidType(self):
        self.assertRaises(ValueError, LongExtendedKey, 241, 1)
        self.assertRaises(ValueError, LongExtendedKey, 26, 1)


class LongExtendedEncodingTests(unittest.TestCase):
    klass = packet.Packet

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.packet = self.klass(secret=b'secret', dict=self.dict)

    def testEncodeShortValue(self):
        self.packet['Test-Long-String'] = 'value'
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         Fragment(245, 1, b'value'))

    def testEncodeFragmentedValue(self):
        value = b'x' * 600
        self.packet['Test-Long-String'] = value
        self.assertEqual(
            self.packet._PktEncodeAttributes(),
            Fragment(245, 1, value[:251], more=True)
            + Fragment(245, 1, value[251:502], more=True)
            + Fragment(245, 1, value[502:]))

    def testEncodeValueOfExactlyOneFragment(self):
        value = b'x' * 251
        self.packet[LongExtendedKey(245, 1)] = [value]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         Fragment(245, 1, value))

    def testEncodeRawUnknownExtendedType(self):
        self.packet[LongExtendedKey(245, 99)] = [b'raw']
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         Fragment(245, 99, b'raw'))

    def testEncodeEmptyValue(self):
        self.packet[LongExtendedKey(245, 1)] = [b'']
        self.assertRaises(ValueError, self.packet._PktEncodeAttributes)

    def testEncodeTooLongValue(self):
        self.packet.max_long_extended_size = 100
        self.packet[LongExtendedKey(245, 1)] = [b'x' * 101]
        try:
            self.packet._PktEncodeAttributes()
        except ValueError as e:
            self.assertIn('too long', str(e))
        else:
            self.fail()

    def testRoundTrip(self):
        value = 'x' * 600
        self.packet['Test-Long-String'] = value
        raw = RawPacket(self.packet._PktEncodeAttributes())
        decoded = self.klass(secret=b'secret', dict=self.dict, packet=raw)
        self.assertEqual(decoded['Test-Long-String'], [value])


class LongExtendedDecodingTests(unittest.TestCase):
    klass = packet.Packet

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))

    def decode(self, attributes, klass=None):
        return (klass or self.klass)(secret=b'secret', dict=self.dict,
                                     packet=RawPacket(attributes))

    def testDecodeThreeFragments(self):
        value = b'A' * 251 + b'B' * 251 + b'C' * 98
        pkt = self.decode(
            Fragment(245, 1, value[:251], more=True)
            + Fragment(245, 1, value[251:502], more=True)
            + Fragment(245, 1, value[502:]))
        self.assertEqual(pkt['Test-Long-String'], [value.decode('ascii')])
        self.assertEqual(pkt.keys(), ['Test-Long-String'])

    def testDecodeUnfragmented(self):
        pkt = self.decode(Fragment(245, 1, b'value'))
        self.assertEqual(pkt['Test-Long-String'], ['value'])

    def testDecodeTwoAttributes(self):
        first = b'one' + b'-' * 248
        pkt = self.decode(
            Fragment(245, 1, first, more=True)
            + Fragment(245, 1, b'-one')
            + Fragment(246, 1, b'two'))
        self.assertEqual(pkt['Test-Long-String'],
                         [(first + b'-one').decode('ascii')])
        self.assertEqual(pkt['Test-Long-Data'], [b'two'])

    def testDecodeAttributeBetweenFragments(self):
        # RFC 6929 section 2.2: fragments mixed with attributes of a
        # different type must be processed
        first = b'one' + b'-' * 248
        pkt = self.decode(
            Fragment(245, 1, first, more=True)
            + struct.pack('!BB', 1, 5) + b'bob'
            + Fragment(245, 1, b'two'))
        self.assertEqual(pkt['Test-Long-String'],
                         [(first + b'two').decode('ascii')])
        self.assertEqual(pkt['User-Name'], ['bob'])

    def testDecodeInterleavedExtendedTypes(self):
        # a fragment of another extended type instead of the continuation
        # of a fragmented attribute is an injection attempt
        attributes = (
            Fragment(245, 1, b'A' * 251, more=True)
            + Fragment(245, 2, b'B' * 10)
            + Fragment(245, 1, b'C' * 10))
        self.assertRaises(packet.PacketError, self.decode, attributes)

    def testDecodeInterleavedExtendedContainers(self):
        attributes = (
            Fragment(245, 1, b'A' * 251, more=True)
            + Fragment(246, 1, b'B' * 10)
            + Fragment(245, 1, b'C' * 10))
        self.assertRaises(packet.PacketError, self.decode, attributes)

    def testDecodeTruncated(self):
        # the last fragment has the More flag set: the reassembled
        # attribute must not show up, not even partially
        attributes = Fragment(245, 1, b'A' * 251, more=True)
        try:
            self.decode(attributes)
        except packet.PacketError as e:
            self.assertIn('Truncated', str(e))
        else:
            self.fail()

    def testDecodeMoreFlagWithoutFullLength(self):
        # RFC 6929 section 2.2: the More flag requires a Length of 255
        attributes = Fragment(245, 1, b'short', more=True)
        self.assertRaises(packet.PacketError, self.decode, attributes)

    def testDecodeTooShort(self):
        self.assertRaises(packet.PacketError, self.decode,
                          struct.pack('!BBBB', 245, 4, 1, 0))

    def testDecodeExceedsMaximumSize(self):
        attributes = (
            Fragment(245, 1, b'A' * 251, more=True)
            + Fragment(245, 1, b'B' * 10))
        try:
            self.decode(attributes, klass=LimitedPacket)
        except packet.PacketError as e:
            self.assertIn('longer than 100', str(e))
        else:
            self.fail()

    def testDecodeUnknownExtendedTypeKeptRaw(self):
        # an undefined extended type is kept as raw value and must not be
        # mistaken for a defined attribute
        pkt = self.decode(Fragment(245, 99, b'raw-value'))
        self.assertEqual(pkt[LongExtendedKey(245, 99)], [b'raw-value'])
        self.assertEqual(pkt[(245, 99)], [b'raw-value'])
        self.assertEqual(pkt.keys(), [LongExtendedKey(245, 99)])
        self.assertNotIn('Test-Long-String', pkt)
        self.assertNotIn('Test-Long-Other', pkt)

    def testDecodeUnknownExtendedTypeRoundTrip(self):
        attributes = (Fragment(245, 99, b'x' * 251, more=True)
                      + Fragment(245, 99, b'y'))
        pkt = self.decode(attributes)
        self.assertEqual(pkt._PktEncodeAttributes(), attributes)


class LongExtendedAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))

    def testMessageAuthenticatorWithFragmentedAttribute(self):
        request = packet.AuthPacket(secret=b'secret', dict=self.dict)
        request['Test-Long-String'] = 'x' * 600
        request.add_message_authenticator()
        raw = request.RequestPacket()
        received = packet.AuthPacket(secret=b'secret', dict=self.dict,
                                     packet=raw)
        # the Message-Authenticator is verified over the attributes
        # exactly as received, not over the reassembled and re-encoded
        # form
        self.assertTrue(received.verify_message_authenticator())
        self.assertEqual(received['Test-Long-String'], ['x' * 600])

    def testMessageAuthenticatorWithTamperedFragment(self):
        request = packet.AuthPacket(secret=b'secret', dict=self.dict)
        request['Test-Long-String'] = 'x' * 600
        request.add_message_authenticator()
        raw = bytearray(request.RequestPacket())
        # flip a bit in the second fragment
        raw[20 + 255 + 10] ^= 0x01
        received = packet.AuthPacket(secret=b'secret', dict=self.dict,
                                     packet=bytes(raw))
        self.assertFalse(received.verify_message_authenticator())

    def testVerifyReplyWithFragmentedAttribute(self):
        request = packet.AuthPacket(id=0, secret=b'secret',
                                    authenticator=b'0123456789ABCDEF',
                                    dict=self.dict)
        request.add_message_authenticator()
        request.RequestPacket()
        raw = request.CreateReply(
            **{'Test-Long-String': 'y' * 600}).ReplyPacket()
        received = request.CreateReply(packet=raw)
        self.assertTrue(request.VerifyReply(received))
        self.assertEqual(received['Test-Long-String'], ['y' * 600])


if __name__ == '__main__':
    unittest.main()
