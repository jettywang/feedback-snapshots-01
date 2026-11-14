"""Independent interoperability regression tests for the hidden password
attributes: User-Password (RFC 2865 section 5.2) and Tunnel-Password
(RFC 2868 section 3.5, dictionary flag encrypt=2).

The reference vectors in this file are computed with hashlib.md5 straight
from the RFCs. They deliberately never call the production crypto
(PwCrypt/PwDecrypt/SaltCrypt/SaltDecrypt), so a regression in the
production code cannot hide behind itself.

Only fixed test secrets are used; they are not real credentials.

Hiding is not authenticating: both algorithms merely obfuscate the
password with the shared secret and the Request Authenticator. They do
not authenticate the packet as a whole -- that is what
Message-Authenticator and the Response Authenticator are for (see
pyrad/tests/test_blastradius.py for the CVE-2024-3596 coverage).
"""
import hashlib
import struct
import unittest
import unittest.mock

from io import StringIO

from pyrad import packet
from pyrad.dictionary import Dictionary

# Fixed test material, never a real secret.
SECRET = b'test-secret'
AUTHENTICATOR = b'0123456789ABCDEF'
WRONG_AUTHENTICATOR = b'FEDCBA0987654321'
# RFC 2868 section 3.5: the most significant bit of the salt must be set.
SALT = b'\x80\x01'
SALT_RANDRANGE = 1  # 32768 + 1 == 0x8001, see SaltCrypt

DICTIONARY = '''
ATTRIBUTE User-Password         2  string encrypt=1
ATTRIBUTE Test-Encrypted-String 5  string encrypt=2
ATTRIBUTE Tunnel-Password       69 string has_tag,encrypt=2
'''


def ref_user_password_encrypt(secret, authenticator, password):
    """RFC 2865 section 5.2: b1 = MD5(secret + RA), bn = MD5(secret + cn-1)."""
    if not password or len(password) % 16:
        password += b'\x00' * (16 - len(password) % 16)
    result = b''
    last = authenticator
    while password:
        digest = hashlib.md5(secret + last).digest()
        block = bytes(a ^ b for a, b in zip(digest, password[:16]))
        result += block
        last = block
        password = password[16:]
    return result


def ref_user_password_decrypt(secret, authenticator, ciphertext):
    """Reverse of the above; chains on the received ciphertext blocks."""
    result = b''
    last = authenticator
    while ciphertext:
        digest = hashlib.md5(secret + last).digest()
        result += bytes(a ^ b for a, b in zip(digest, ciphertext[:16]))
        last = ciphertext[:16]
        ciphertext = ciphertext[16:]
    return result


def ref_tunnel_password_encrypt(secret, authenticator, salt, password):
    """RFC 2868 section 3.5: length-prefixed, zero padded, salted.

    b1 = MD5(secret + RA + salt), bn = MD5(secret + c(n-1)); the result
    includes the 2-octet salt.
    """
    value = bytes((len(password),)) + password
    if len(value) % 16:
        value += b'\x00' * (16 - len(value) % 16)
    result = b''
    last = authenticator + salt
    while value:
        digest = hashlib.md5(secret + last).digest()
        block = bytes(a ^ b for a, b in zip(digest, value[:16]))
        result += block
        last = block
        value = value[16:]
    return salt + result


def ref_tunnel_password_decrypt(secret, authenticator, value):
    """Reverse of the above; takes the salt from the first 2 octets."""
    salt, ciphertext = value[:2], value[2:]
    result = b''
    last = authenticator + salt
    while ciphertext:
        digest = hashlib.md5(secret + last).digest()
        result += bytes(a ^ b for a, b in zip(digest, ciphertext[:16]))
        last = ciphertext[:16]
        ciphertext = ciphertext[16:]
    length = result[0]
    return result[1:1 + length]


def fixed_salt():
    """Make SaltCrypt deterministic: salt 0x8001 (high bit set, RFC 2868)."""
    return unittest.mock.patch('pyrad.packet.random_generator.randrange',
                               return_value=SALT_RANDRANGE)


class UserPasswordInteropTests(unittest.TestCase):
    """User-Password vectors computed independently of pyrad's PwCrypt."""

    klass = packet.AuthPacket

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.packet = self.klass(secret=SECRET, authenticator=AUTHENTICATOR,
                                 dict=self.dict)

    def assertVector(self, password):
        encrypted = self.packet.PwCrypt(password)
        self.assertEqual(encrypted,
                         ref_user_password_encrypt(SECRET, AUTHENTICATOR,
                                                   password))
        if isinstance(password, bytes):
            password = password.decode('utf-8')
        self.assertEqual(self.packet.PwDecrypt(encrypted), password)
        return encrypted

    def testZeroLength(self):
        # A zero-length password is one block of zero padding, so the
        # ciphertext is exactly MD5(secret + Request Authenticator).
        encrypted = self.packet.PwCrypt(b'')
        self.assertEqual(len(encrypted), 16)
        self.assertEqual(encrypted,
                         hashlib.md5(SECRET + AUTHENTICATOR).digest())
        self.assertEqual(self.packet.PwDecrypt(encrypted), '')

    def testBlockBoundary(self):
        # 15 octets: padded to one block; 16 octets: exactly one block,
        # no padding added; 17 octets: crosses into a second block.
        self.assertEqual(len(self.assertVector(b'x' * 15)), 16)
        self.assertEqual(len(self.assertVector(b'x' * 16)), 16)
        self.assertEqual(len(self.assertVector(b'x' * 17)), 32)

    def testMultiBlockChaining(self):
        # The second block chains on the first *ciphertext* block:
        # c2 = p2 ^ MD5(secret + c1), not on the authenticator again.
        encrypted = self.assertVector(b'A' * 17)
        second_plain = b'A' + 15 * b'\x00'
        expected = bytes(a ^ b for a, b in
                         zip(hashlib.md5(SECRET + encrypted[:16]).digest(),
                             second_plain))
        self.assertEqual(encrypted[16:], expected)

    def testMaximumLength(self):
        # RFC 2865 section 5.2: at most 128 octets of password.
        self.assertEqual(len(self.assertVector(b'p' * 128)), 128)
        self.assertRaises(ValueError, self.packet.PwCrypt, b'p' * 129)

    def testTrailingZeroBytes(self):
        # User-Password has no length field: trailing zero octets are
        # indistinguishable from padding and are lost on decrypt. The
        # ciphertext still matches the reference vector exactly.
        encrypted = self.packet.PwCrypt(b'secret\x00\x00')
        self.assertEqual(encrypted, ref_user_password_encrypt(
            SECRET, AUTHENTICATOR, b'secret\x00\x00'))
        self.assertEqual(ref_user_password_decrypt(
            SECRET, AUTHENTICATOR, encrypted), b'secret\x00' + 9 * b'\x00')
        self.assertEqual(self.packet.PwDecrypt(encrypted), 'secret')

    def testEmbeddedZeroByte(self):
        self.assertVector(b'pass\x00word')

    def testWrongAuthenticator(self):
        # A wrong Request Authenticator must not yield the password back.
        encrypted = self.packet.PwCrypt(b'Simplon')
        other = self.klass(secret=SECRET, authenticator=WRONG_AUTHENTICATOR,
                           dict=self.dict)
        self.assertNotEqual(other.PwDecrypt(encrypted), 'Simplon')
        self.assertNotEqual(
            ref_user_password_decrypt(SECRET, WRONG_AUTHENTICATOR, encrypted),
            b'Simplon')

    def testWrongSecret(self):
        encrypted = self.packet.PwCrypt(b'Simplon')
        other = self.klass(secret=b'wrong-secret',
                           authenticator=AUTHENTICATOR, dict=self.dict)
        self.assertNotEqual(other.PwDecrypt(encrypted), 'Simplon')

    def testInvalidLength(self):
        # The encrypted value must be a multiple of 16 octets; anything
        # else is a corrupt attribute, not a password.
        for length in (1, 15, 17, 31, 33):
            self.assertRaises(packet.PacketError, self.packet.PwDecrypt,
                              length * b'x')


class TunnelPasswordInteropTests(unittest.TestCase):
    """Tunnel-Password vectors computed independently of SaltCrypt."""

    klass = packet.AuthPacket

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.packet = self.klass(secret=SECRET, authenticator=AUTHENTICATOR,
                                 dict=self.dict)

    def assertVector(self, password):
        with fixed_salt():
            encrypted = self.packet.SaltCrypt(password)
        self.assertEqual(encrypted, ref_tunnel_password_encrypt(
            SECRET, AUTHENTICATOR, SALT, password))
        self.assertEqual(encrypted[:2], SALT)
        self.assertEqual(ref_tunnel_password_decrypt(SECRET, AUTHENTICATOR,
                                                     encrypted), password)
        self.assertEqual(self.packet.SaltDecrypt(encrypted), password)
        return encrypted

    def testSaltFormat(self):
        # RFC 2868 section 3.5: 2-octet salt with the high bit set,
        # followed by a multiple of 16 octets.
        self.assertTrue(SALT[0] & 0x80)
        self.assertEqual(struct.pack('!H', 32768 + SALT_RANDRANGE), SALT)
        with fixed_salt():
            encrypted = self.packet.SaltCrypt(b'password')
        self.assertEqual(len(encrypted), 2 + 16)
        self.assertEqual((len(encrypted) - 2) % 16, 0)

    def testZeroLength(self):
        # Length octet 0, padded to one block: salt + 16 octets.
        encrypted = self.assertVector(b'')
        self.assertEqual(len(encrypted), 2 + 16)

    def testBlockBoundary(self):
        # 15 octets: length + value is exactly one block, no padding;
        # 16 octets: crosses into a second block.
        self.assertEqual(len(self.assertVector(b't' * 14)), 2 + 16)
        self.assertEqual(len(self.assertVector(b't' * 15)), 2 + 16)
        self.assertEqual(len(self.assertVector(b't' * 16)), 2 + 32)

    def testMultiBlockChaining(self):
        # Every block past the first chains on the previous ciphertext
        # block in both directions; a decrypt that chains on plaintext
        # corrupts everything past octet 15.
        password = bytes(range(100))
        encrypted = self.assertVector(password)
        self.assertEqual(len(encrypted), 2 + 112)

    def testMaximumLength(self):
        # 239 octets is the largest password whose tag + salt + length +
        # padding still fits into one 255-octet attribute.
        encrypted = self.assertVector(b'M' * 239)
        self.assertEqual(len(encrypted), 2 + 240)
        self.assertRaises(ValueError, self.packet.SaltCrypt, b'M' * 256)

    def testTrailingZeroBytes(self):
        # Unlike User-Password, Tunnel-Password is length prefixed, so
        # trailing zero octets survive the round trip exactly.
        self.assertVector(b'tunnel-pass\x00\x00')
        self.assertVector(b'\x00')

    def testTagAndSaltHaveDifferentRoles(self):
        # On the wire a Tunnel-Password is: tag (1 octet, plaintext) +
        # salt (2 octets) + ciphertext. The tag selects the tunnel and is
        # not an input to the cipher; the salt is.
        with fixed_salt():
            self.packet['Tunnel-Password:3'] = 'shared-secret'
        raw = self.packet[69][0]
        self.assertEqual(raw[0], 3)  # tag, sent in the clear
        self.assertEqual(raw[1:3], SALT)
        self.assertEqual(raw[3:], ref_tunnel_password_encrypt(
            SECRET, AUTHENTICATOR, SALT, b'shared-secret')[2:])
        # retagging the same ciphertext still yields the same password
        self.assertEqual(ref_tunnel_password_decrypt(
            SECRET, AUTHENTICATOR, raw[1:]), b'shared-secret')
        # a different salt changes the keystream: not the password
        self.assertNotEqual(ref_tunnel_password_decrypt(
            SECRET, AUTHENTICATOR, b'\x80\x02' + raw[3:]), b'shared-secret')

    def testDuplicateSaltsInSamePacket(self):
        # Two Tunnel-Password attributes in one request may reuse the
        # same salt; each must still decode to its own password.
        with fixed_salt():
            self.packet.AddAttribute('Tunnel-Password:1', 'first-tunnel')
            self.packet.AddAttribute('Tunnel-Password:2',
                                     'second-tunnel-password')
        raw1, raw2 = self.packet[69]
        self.assertEqual(raw1[1:3], raw2[1:3])  # duplicate salt on the wire
        received = self.klass(secret=SECRET, dict=self.dict,
                              packet=self.packet.RequestPacket())
        self.assertEqual(received['Tunnel-Password:1'], ['first-tunnel'])
        self.assertEqual(received['Tunnel-Password:2'],
                         ['second-tunnel-password'])
        self.assertEqual(ref_tunnel_password_decrypt(
            SECRET, AUTHENTICATOR, received[69][0][1:]), b'first-tunnel')
        self.assertEqual(ref_tunnel_password_decrypt(
            SECRET, AUTHENTICATOR, received[69][1][1:]),
            b'second-tunnel-password')

    def testWrongAuthenticator(self):
        with fixed_salt():
            encrypted = self.packet.SaltCrypt(b'tunnel-secret')
        other = self.klass(secret=SECRET, authenticator=WRONG_AUTHENTICATOR,
                           dict=self.dict)
        self.assertNotEqual(other.SaltDecrypt(encrypted), b'tunnel-secret')
        self.assertNotEqual(ref_tunnel_password_decrypt(
            SECRET, WRONG_AUTHENTICATOR, encrypted), b'tunnel-secret')

    def testCorruptedOuterLength(self):
        # Salt + ciphertext must be 2 + a multiple of 16 octets; anything
        # else is a corrupt attribute and must raise, not decode.
        for value in (b'', SALT, SALT + b'x' * 15, SALT + b'x' * 17):
            self.assertRaises(packet.PacketError, self.packet.SaltDecrypt,
                              value)

    def testCorruptedInnerLength(self):
        # Flipping the first ciphertext octet corrupts the length prefix;
        # the result must not come back as the original password.
        with fixed_salt():
            encrypted = bytearray(self.packet.SaltCrypt(b'tunnel-secret'))
        encrypted[2] ^= 0xFF
        self.assertNotEqual(self.packet.SaltDecrypt(bytes(encrypted)),
                            b'tunnel-secret')


class EncryptFlagSeparationTests(unittest.TestCase):
    """encrypt=1 (User-Password) and encrypt=2 (salt encryption) are
    different algorithms; neither must be handled by the other path."""

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.packet = packet.AuthPacket(secret=SECRET,
                                        authenticator=AUTHENTICATOR,
                                        dict=self.dict)

    def testEncrypt1IsNotSaltEncrypted(self):
        # The dictionary encoding does not apply any cipher to an
        # encrypt=1 attribute; User-Password hiding is done explicitly
        # with PwCrypt. A plaintext value goes out as-is.
        self.packet['User-Password'] = 'not-hidden-by-the-codec'
        self.assertEqual(self.packet[2], [b'not-hidden-by-the-codec'])

    def testEncrypt2IsSaltEncrypted(self):
        with fixed_salt():
            self.packet['Test-Encrypted-String'] = 'hidden-by-the-codec'
        raw = self.packet[5][0]
        self.assertEqual(raw[:2], SALT)
        self.assertEqual(ref_tunnel_password_decrypt(SECRET, AUTHENTICATOR,
                                                     raw),
                         b'hidden-by-the-codec')

    def testAlgorithmsAreNotInterchangeable(self):
        password = b'the-same-password'
        user_password = self.packet.PwCrypt(password)
        with fixed_salt():
            tunnel_password = self.packet.SaltCrypt(password)
        # different formats: no salt, 16-octet multiple vs salt + padding
        self.assertNotEqual(user_password, tunnel_password)
        # each decoder structurally rejects the other's output
        self.assertRaises(packet.PacketError, self.packet.SaltDecrypt,
                          user_password)
        self.assertRaises(packet.PacketError, self.packet.PwDecrypt,
                          tunnel_password)
        long_user_password = self.packet.PwCrypt(b'x' * 32)
        self.assertRaises(packet.PacketError, self.packet.SaltDecrypt,
                          long_user_password)


class PacketRoundTripInteropTests(unittest.TestCase):
    """Reference vectors wired through dictionary attribute encoding and
    real packet encode/decode round trips."""

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))

    def testRequestRoundTrip(self):
        request = packet.AuthPacket(secret=SECRET,
                                    authenticator=AUTHENTICATOR,
                                    dict=self.dict)
        request['User-Password'] = request.PwCrypt(b'request-password')
        with fixed_salt():
            request.AddAttribute('Tunnel-Password:1', 'first-tunnel')
            request.AddAttribute('Tunnel-Password:2',
                                 'second-tunnel-crossing-16')

        # the wire bytes of attribute 2 are exactly the reference vector
        self.assertEqual(request[2][0], ref_user_password_encrypt(
            SECRET, AUTHENTICATOR, b'request-password'))

        received = packet.AuthPacket(secret=SECRET, dict=self.dict,
                                     packet=request.RequestPacket())
        self.assertEqual(received.PwDecrypt(received['User-Password'][0]),
                         'request-password')
        self.assertEqual(received['Tunnel-Password:1'], ['first-tunnel'])
        self.assertEqual(received['Tunnel-Password:2'],
                         ['second-tunnel-crossing-16'])
        # and the wire bytes of attribute 69 decode with the reference
        # implementation, tag first, salt second
        for (raw, expected) in zip(received[69],
                                   (b'first-tunnel',
                                    b'second-tunnel-crossing-16')):
            self.assertEqual(raw[1:3], SALT)
            self.assertEqual(ref_tunnel_password_decrypt(
                SECRET, AUTHENTICATOR, raw[1:]), expected)

    def testReplyRoundTrip(self):
        request = packet.AuthPacket(secret=SECRET,
                                    authenticator=AUTHENTICATOR,
                                    dict=self.dict)
        reply = request.CreateReply()
        self.assertEqual(reply.code, packet.AccessAccept)
        with fixed_salt():
            reply.AddAttribute('Tunnel-Password:1', 'reply-tunnel-one')
            reply.AddAttribute('Tunnel-Password:2', 'reply-tunnel-two')

        received = packet.AuthPacket(secret=SECRET, dict=self.dict,
                                     packet=reply.ReplyPacket())
        # a reply hides passwords with the Request Authenticator of the
        # request, which the client sets on the decoded packet
        received.request_authenticator = request.authenticator
        self.assertEqual(received['Tunnel-Password:1'], ['reply-tunnel-one'])
        self.assertEqual(received['Tunnel-Password:2'], ['reply-tunnel-two'])
        for (raw, expected) in zip(received[69],
                                   (b'reply-tunnel-one',
                                    b'reply-tunnel-two')):
            self.assertEqual(ref_tunnel_password_decrypt(
                SECRET, request.authenticator, raw[1:]), expected)

    def testTamperedAuthenticatorOnTheWire(self):
        # Flipping the Request Authenticator on the wire must not turn
        # the hidden attributes into valid passwords.
        request = packet.AuthPacket(secret=SECRET,
                                    authenticator=AUTHENTICATOR,
                                    dict=self.dict)
        request['User-Password'] = request.PwCrypt(b'request-password')
        raw = bytearray(request.RequestPacket())
        raw[4:20] = WRONG_AUTHENTICATOR
        received = packet.AuthPacket(secret=SECRET, dict=self.dict,
                                     packet=bytes(raw))
        self.assertNotEqual(
            received.PwDecrypt(received['User-Password'][0]),
            'request-password')


if __name__ == '__main__':
    unittest.main()
