"""Independent interoperability evidence for RFC 6637 ECDH session-key wrapping.

The reference path in this module deliberately does not call ``ECKDF.derive_key``.
It builds the Concatenation KDF OtherInfo from the RFC text itself:

    curve_OID_len || curve_OID || public_key_alg_ID || 03 || 01 ||
    KDF_hash_ID || KEK_alg_ID || "Anonymous Sender    " ||
    recipient_fingerprint

It also computes the v4 fingerprint directly from the recipient's public-key
packet and performs the RFC 3394 unwrap with ``cryptography``.  The production
decrypt path is then exercised against ciphertexts built entirely by this
reference path.  Intermediate inputs and digests are pinned in
``EXPECTED_MANIFEST`` and ``EXPECTED_GPG`` above the reference helpers.
"""
import binascii
import hashlib
import warnings
from datetime import datetime, timezone

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from pyasn1.codec.der import encoder
from pyasn1.type.univ import ObjectIdentifier

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy.constants import ECPointFormat
from pgpy.constants import EllipticCurveOID
from pgpy.constants import HashAlgorithm
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.errors import PGPDecryptionError
from pgpy.packet import Packet
from pgpy.packet.fields import ECDHCipherText
from pgpy.packet.fields import ECKDF
from pgpy.packet.fields import ECPoint
from pgpy.packet.packets import PrivKeyV4
from pgpy.packet.types import MPI


# RFC 6637 section 8: 20 octets, including four trailing spaces.
ANONYMOUS_SENDER = b'Anonymous Sender    '
ANONYMOUS_SENDER_HEX = '416e6f6e796d6f75732053656e64657220202020'

# RFC 6637 section 8: public key algorithm ID 18 (ECDH), reserved bytes 03 01.
ECDH_ALGORITHM_ID = 18
KDF_RESERVED = b'\x03\x01'

# RFC 4880 section 9.2 and RFC 6637 section 8.
HASH_IDS = {
    HashAlgorithm.SHA256: 8,
    HashAlgorithm.SHA384: 9,
    HashAlgorithm.SHA512: 10,
}
HASH_NAMES = {
    HashAlgorithm.SHA256: 'sha256',
    HashAlgorithm.SHA384: 'sha384',
    HashAlgorithm.SHA512: 'sha512',
}
KEK_IDS = {
    SymmetricKeyAlgorithm.AES128: 7,
    SymmetricKeyAlgorithm.AES192: 8,
    SymmetricKeyAlgorithm.AES256: 9,
}

# RFC 6637 section 11, third column: DER body only (tag and length removed).
RFC6637_CURVE_OIDS = {
    EllipticCurveOID.NIST_P256: '2a8648ce3d030107',
    EllipticCurveOID.NIST_P384: '2b81040022',
    EllipticCurveOID.NIST_P521: '2b81040023',
    # Curve25519 OID used by PGPy's RFC 4880bis extension.
    EllipticCurveOID.Curve25519: '2b060104019755010501',
}

CREATED = datetime(2026, 1, 1, tzinfo=timezone.utc)

REPO_P256_PRIMARY_FINGERPRINT = '9CBF59CE40563202F085B399D01055FBCADD268E'
REPO_P256_SUBKEY_FINGERPRINT = '5E96CB5420B85EED76E67D13A81B93FD16BD9806'
REPO_CV25519_PRIMARY_FINGERPRINT = '7F0F97AD539D51F74B018BD1062E6AC5205D871E'
REPO_CV25519_SUBKEY_FINGERPRINT = '1E317A73C6FEDE47D2478C3CAFC377493D8E897D'


# Pinned intermediate values for every synthetic vector and for the GnuPG-produced
# message vector.  These are the regression anchors.
EXPECTED_MANIFEST = {'cv25519_repo_leadzero': {'ciphertext': 'daad5face137bbfe7c5e54203414bdb861b3c3faaf481efebd5c70790f78a725',
                           'ciphertext_sha256': '866b98f6a2ece151be6d01c7f7f19e40d0cc15388af383e792abff3a9ffeaef9',
                           'fingerprint': '1E317A73C6FEDE47D2478C3CAFC377493D8E897D',
                           'kek': '474325438e399c915606b12dcbb5ddd9',
                           'kek_sha256': 'e35938cbcc9275094cdfd5f605d6f64483c342f2b8bc5ec3b5c108fa042e3112',
                           'm': '07000102030405060708090a0b0c0d0e0f00780505050505',
                           'm_sha256': '462f209f1a5c7c900dff9b6cb46726c4f2582f3b31690aef6a11ce7423dda3fb',
                           'other_info': '0a2b0601040197550105011203010807416e6f6e796d6f75732053656e646572202020201e317a73c6fede47d2478c3cafc377493d8e897d',
                           'other_info_sha256': 'ce36fc5909894dde7a1ed42f7cdad9b07299706af72ce5d92e21aac5ea100cc4',
                           'padding': 5,
                           'session_alg': 7,
                           'session_key': '000102030405060708090a0b0c0d0e0f',
                           'shared_secret': '000330a7d6d3f694badde4b178e98abeb56d46b8016aa108387da27fdd28a96e',
                           'shared_secret_sha256': 'ba55bee200fc795fc1498bc4c99b239b00a81c5bb9b617f727ab5c709fed1bcc',
                           'unpadded_m': '07000102030405060708090a0b0c0d0e0f0078'},
 'nist_p256_repo_leadzero_pad13': {'ciphertext': 'fc180e9264a72b04c311c8859cebf8a823f95596dd7970dbfe119d8ecf363e554efbc13757328506',
                                   'ciphertext_sha256': '82db0ecb24ddc92e679a388109e7d91fe08aa9f90bb2e3214fc54b0695c3ab9d',
                                   'fingerprint': '5E96CB5420B85EED76E67D13A81B93FD16BD9806',
                                   'kek': 'a3985fd9aa235d61b8667e8472f74fc8',
                                   'kek_sha256': '59228953753d5f5db908e036a82f9fdd1255a34f10ba18fde8f9bfe396d03c63',
                                   'm': '07000102030405060708090a0b0c0d0e0f00780d0d0d0d0d0d0d0d0d0d0d0d0d',
                                   'm_sha256': '7208c1405cdaa3eb2c9de5cceffd322a379d419cb9425c44c437464de78d8048',
                                   'other_info': '082a8648ce3d0301071203010807416e6f6e796d6f75732053656e646572202020205e96cb5420b85eed76e67d13a81b93fd16bd9806',
                                   'other_info_sha256': 'b602a5e219224414507ea4b2f39b3044cfc92a545a9ac28f3a0308a0df68cc54',
                                   'padding': 13,
                                   'session_alg': 7,
                                   'session_key': '000102030405060708090a0b0c0d0e0f',
                                   'shared_secret': '000bdc892f0f63a2d7f697b1e591556df0306f830c4d8acb5f2163bda98edd3f',
                                   'shared_secret_sha256': '751d876d983116328e853030958017b3787917cee7800e1317097942f7031034',
                                   'unpadded_m': '07000102030405060708090a0b0c0d0e0f0078'},
 'nist_p256_repo_leadzero_pad21': {'ciphertext': '1d3aa82e4fb87be8710a41efe9a4603481b6a528042edb2bd8050ef8196838b45aac8fffa6ae2f3a2b58f058945ca502',
                                   'ciphertext_sha256': 'c1f456f4ed71bd2f53a2ec17c84c3e127f20894b4de7d29a8393d17c90f1fc21',
                                   'fingerprint': '5E96CB5420B85EED76E67D13A81B93FD16BD9806',
                                   'kek': 'a3985fd9aa235d61b8667e8472f74fc8',
                                   'kek_sha256': '59228953753d5f5db908e036a82f9fdd1255a34f10ba18fde8f9bfe396d03c63',
                                   'm': '07000102030405060708090a0b0c0d0e0f0078151515151515151515151515151515151515151515',
                                   'm_sha256': '623eb8489f6ec75b82f36a5148fc4fe8d9fe8b4f639b7479716e324be29fac7c',
                                   'other_info': '082a8648ce3d0301071203010807416e6f6e796d6f75732053656e646572202020205e96cb5420b85eed76e67d13a81b93fd16bd9806',
                                   'other_info_sha256': 'b602a5e219224414507ea4b2f39b3044cfc92a545a9ac28f3a0308a0df68cc54',
                                   'padding': 21,
                                   'session_alg': 7,
                                   'session_key': '000102030405060708090a0b0c0d0e0f',
                                   'shared_secret': '000bdc892f0f63a2d7f697b1e591556df0306f830c4d8acb5f2163bda98edd3f',
                                   'shared_secret_sha256': '751d876d983116328e853030958017b3787917cee7800e1317097942f7031034',
                                   'unpadded_m': '07000102030405060708090a0b0c0d0e0f0078'},
 'nist_p256_repo_leadzero_pad5': {'ciphertext': '2111e07842137587bca7dd29a86f1c6eceaf537f1bc814877ed448df6618949e',
                                  'ciphertext_sha256': '3847ccfb9f890bc9b9318fc2ea7d43701ef72f5d1ce5dfb0415b66e87499f957',
                                  'fingerprint': '5E96CB5420B85EED76E67D13A81B93FD16BD9806',
                                  'kek': 'a3985fd9aa235d61b8667e8472f74fc8',
                                  'kek_sha256': '59228953753d5f5db908e036a82f9fdd1255a34f10ba18fde8f9bfe396d03c63',
                                  'm': '07000102030405060708090a0b0c0d0e0f00780505050505',
                                  'm_sha256': '462f209f1a5c7c900dff9b6cb46726c4f2582f3b31690aef6a11ce7423dda3fb',
                                  'other_info': '082a8648ce3d0301071203010807416e6f6e796d6f75732053656e646572202020205e96cb5420b85eed76e67d13a81b93fd16bd9806',
                                  'other_info_sha256': 'b602a5e219224414507ea4b2f39b3044cfc92a545a9ac28f3a0308a0df68cc54',
                                  'padding': 5,
                                  'session_alg': 7,
                                  'session_key': '000102030405060708090a0b0c0d0e0f',
                                  'shared_secret': '000bdc892f0f63a2d7f697b1e591556df0306f830c4d8acb5f2163bda98edd3f',
                                  'shared_secret_sha256': '751d876d983116328e853030958017b3787917cee7800e1317097942f7031034',
                                  'unpadded_m': '07000102030405060708090a0b0c0d0e0f0078'},
 'nist_p256_temp_kek_aes192': {'ciphertext': 'eef9b394f397d1ee27725beb337451ebfab08c73266a6a212d28f755df4439ca',
                               'ciphertext_sha256': '9cb60c7c4be7ba97fc3ffa9081958a63871999da190c3cffdb8e29750a5a58a8',
                               'fingerprint': 'A1B2E6A1D152C3853E0E3338A39DF6DE0BA58B8E',
                               'kek': 'f23cb828b810d3ac049fb664ce1d93308105c84003a8edc7',
                               'kek_sha256': 'bceb1f94740b240ac2ad68ada97496ce36e59a42acf2879c50c59a0eccffdef5',
                               'm': '07000102030405060708090a0b0c0d0e0f00780505050505',
                               'm_sha256': '462f209f1a5c7c900dff9b6cb46726c4f2582f3b31690aef6a11ce7423dda3fb',
                               'other_info': '082a8648ce3d0301071203010808416e6f6e796d6f75732053656e64657220202020a1b2e6a1d152c3853e0e3338a39df6de0ba58b8e',
                               'other_info_sha256': '97eadc91e5c35c1de08d0a794596cd3f47f93b380c69fd9a443f15a922923cb6',
                               'padding': 5,
                               'session_alg': 7,
                               'session_key': '000102030405060708090a0b0c0d0e0f',
                               'shared_secret': '958da6366e4c27d451a1290730c1c3a19fac150b492a8a137f6d955694835874',
                               'shared_secret_sha256': '9a2f1eac3a201b498671442ee48626cc6277faa677c16a34b6057aae50369236',
                               'unpadded_m': '07000102030405060708090a0b0c0d0e0f0078'},
 'nist_p256_temp_kek_aes256': {'ciphertext': '284b0b726f37f1e0d107d265593c369789c6bea2b5aec4c847a82bd217b201d1',
                               'ciphertext_sha256': '7486f6697b9e9cd4bc05a1f0e62e22a153e92ec46400a2cac3fb4b91fe6e00b3',
                               'fingerprint': '6E2D82756A8F8F813B180E490C6E0719F8883B15',
                               'kek': 'e0b5ceee6e2bd4754fe87ac4db2e0a06f4f2adff1ddf6cb3cbbbdae7548e56d7',
                               'kek_sha256': 'd35247baa1cd30a2aeadfd6acc0ce217782e1dce7a59e9a019059832888784a2',
                               'm': '07000102030405060708090a0b0c0d0e0f00780505050505',
                               'm_sha256': '462f209f1a5c7c900dff9b6cb46726c4f2582f3b31690aef6a11ce7423dda3fb',
                               'other_info': '082a8648ce3d0301071203010809416e6f6e796d6f75732053656e646572202020206e2d82756a8f8f813b180e490c6e0719f8883b15',
                               'other_info_sha256': '5053daf34cce1182cafc192a53164e965d1d255e4a09752465e85972b9653fd9',
                               'padding': 5,
                               'session_alg': 7,
                               'session_key': '000102030405060708090a0b0c0d0e0f',
                               'shared_secret': '958da6366e4c27d451a1290730c1c3a19fac150b492a8a137f6d955694835874',
                               'shared_secret_sha256': '9a2f1eac3a201b498671442ee48626cc6277faa677c16a34b6057aae50369236',
                               'unpadded_m': '07000102030405060708090a0b0c0d0e0f0078'},
 'nist_p384_temp': {'ciphertext': '4bf5ead23651c068828495c4cae66b6b7a524e3c54db3989631553b1ddd1f6448895256605f3025f',
                    'ciphertext_sha256': 'ddc37498e2eced54c0af8e08c77689292b5f97bc05134ff4f9ffb7f57a97a759',
                    'fingerprint': 'E525B990B99FE71EB19F12DB015CEF9B693C08CF',
                    'kek': '8d113ff1b0ed182332a4c9fd2bf165f886fcecc8b2acd708',
                    'kek_sha256': '2a9deadd75d0fa452cb858d797259a293adaec6c49f5297851ab30299b68a71d',
                    'm': '08000102030405060708090a0b0c0d0e0f101112131415161701140505050505',
                    'm_sha256': 'b593e5faf94b145b9832abea8d3a4b903a177ed057ac7f0b8093b941d3805d12',
                    'other_info': '052b810400221203010908416e6f6e796d6f75732053656e64657220202020e525b990b99fe71eb19f12db015cef9b693c08cf',
                    'other_info_sha256': 'e3854346073f2a1cf3c951b63e94fe97269d88d66a26544a0c88a06e4f62ac1d',
                    'padding': 5,
                    'session_alg': 8,
                    'session_key': '000102030405060708090a0b0c0d0e0f1011121314151617',
                    'shared_secret': '47aed3c0317df39004f0e7524b9a671de7747471916f59ab9efc1eafd6124b6731ae2fb161aaa6f1ca408933f3ebf03b',
                    'shared_secret_sha256': '04b32d6af2983ca1cd267fafd315912dd2cb8a09ec78f0626cedaeacdd81718b',
                    'unpadded_m': '08000102030405060708090a0b0c0d0e0f10111213141516170114'},
 'nist_p521_temp': {'ciphertext': 'a58fa6bf484af7c4ba9bcbbb97506b4abc71d93220aa3ee2d5e79b9233e706bbcfbd32f80a70fc48c3b70ef06176b75c',
                    'ciphertext_sha256': 'fec9baeef1e70969c82caa4b7468486f23e3d61c22e74bfeffa96dbc0533d3af',
                    'fingerprint': '9E3CE1C9620750D4448EB02702FE671B428645E5',
                    'kek': 'ef5bad891112bafc9c1f55471a2503df159fc3fbcf917d7d526732e0f441aad7',
                    'kek_sha256': '49c9f7f16671b7ab4369187ae66f409a7093239d647891fac4ae0e5391f90b8b',
                    'm': '09000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01f00505050505',
                    'm_sha256': 'f4e0b9e295d04ca36a4f0ade90cde72856bc5e233bbd4c4cd1278972894e6a6e',
                    'other_info': '052b810400231203010a09416e6f6e796d6f75732053656e646572202020209e3ce1c9620750d4448eb02702fe671b428645e5',
                    'other_info_sha256': 'd03a7cbb3671991720fa5eb8b5bc17db6e57df95566b46491922e442ab6da223',
                    'padding': 5,
                    'session_alg': 9,
                    'session_key': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                    'shared_secret': '01cbbb56db05f23b336204d77b44f63824d7d546f0d7b817124eebf6cb442183dfa8ad156eb2ec88e74024319a6d590a94c5d8a12971df5ea1cecb96728976ffbb6b',
                    'shared_secret_sha256': 'a04ca88963119435eaf643bc464a85a934e7bc41a46c115320583897977f6cbb',
                    'unpadded_m': '09000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01f0'}}

EXPECTED_GPG = {'ciphertext': '631887fe044a2ff407d28ce8e26290072f5bcd8d23b7457595d5613f80b99e1dd828b2e96ac1f2867fc777e42098a052',
 'ciphertext_sha256': '48dd0137e19b81519ef9b144c09585bde11867eeb623a391927f5ae044f1576d',
 'fingerprint': '1E317A73C6FEDE47D2478C3CAFC377493D8E897D',
 'kek': '895eaa2fbea5ee5cd2b6295c60a79a34',
 'kek_sha256': '8bc054cca3d4ba265f5fbe0c16415711f07e7bddd1375005f029216c8474b612',
 'm': '09414fa07aa0979af1d20e4cce3c5d0bbcf5ea4966dd45d4bd7bc038f5bb3f37d211720505050505',
 'm_sha256': '603765f3d684aef51ba6a127dfd2312159210d87c749d0b2e5b2d8792cdda584',
 'other_info': '0a2b0601040197550105011203010807416e6f6e796d6f75732053656e646572202020201e317a73c6fede47d2478c3cafc377493d8e897d',
 'other_info_sha256': 'ce36fc5909894dde7a1ed42f7cdad9b07299706af72ce5d92e21aac5ea100cc4',
 'shared_secret': 'd0083a376e11543311c81e6f9835c8a6f8c002248f85e5fb6c600eb1440f9527',
 'shared_secret_sha256': 'f372b184acb3bec73c2004a0ee21767d0fc6a99765219e31ec6c4f650c30601b'}





def _sha256_hex(data):
    return hashlib.sha256(bytes(data)).hexdigest()


# Final unseal verdicts: each vector must (a) be decrypted by production,
# (b) yield the same session key through the independent reference path, and
# (c) remain unusable under a different private key of the same curve.
EXPECTED_UNSEAL = {name: {'production': True, 'reference': True, 'cross_key_rejected': True}
                   for name in EXPECTED_MANIFEST}
EXPECTED_UNSEAL['gnupg_cv25519_message'] = {'production': True, 'reference': True, 'cross_key_rejected': True}


def _der_oid_body(dotted):
    """Return an OID's DER body, i.e. without the tag and length octets."""
    encoded = bytes(encoder.encode(ObjectIdentifier(dotted)))
    assert encoded[0] == 0x06
    assert encoded[1] == len(encoded) - 2
    return encoded[2:]


def _curve_oid_body(curve):
    return bytes.fromhex(RFC6637_CURVE_OIDS[curve])


def _v4_fingerprint(public_key_packet):
    """RFC 4880 section 12.2 v4 fingerprint, computed from the packet body."""
    body = bytes(public_key_packet.__bytearray__())[len(public_key_packet.header):]
    assert body[0] == 4
    return hashlib.sha1(b'\x99' + len(body).to_bytes(2, 'big') + body).hexdigest().upper()


def _other_info(curve, hash_alg, kek_alg, fingerprint):
    curve_oid = _curve_oid_body(curve)
    return (bytes([len(curve_oid)]) + curve_oid +
            bytes([ECDH_ALGORITHM_ID]) + KDF_RESERVED +
            bytes([HASH_IDS[hash_alg], KEK_IDS[kek_alg]]) +
            ANONYMOUS_SENDER + bytes.fromhex(str(fingerprint).replace(' ', '')))


def _concat_kdf(shared_secret, other_info, hash_alg, length):
    """NIST SP 800-56A Concat KDF, as profiled by RFC 6637 section 7."""
    output = b''
    counter = 1
    while len(output) < length:
        output += hashlib.new(HASH_NAMES[hash_alg],
                              counter.to_bytes(4, 'big') + bytes(shared_secret) + bytes(other_info)).digest()
        counter += 1
    return output[:length]


def _session_key_m(session_alg, session_key, padding):
    key = bytes(session_key)
    base = bytes([int(session_alg)]) + key + (sum(key) % 65536).to_bytes(2, 'big')
    if padding is None:
        padding = 8 - (len(base) % 8)
    if not 1 <= padding <= 255:
        raise ValueError('invalid padding length')
    if (len(base) + padding) % 8 != 0:
        raise ValueError('session key block is not 8-octet aligned')
    return base + bytes([padding]) * padding


def _mpi_bytes(payload):
    payload = bytes(payload)
    value = int.from_bytes(payload, 'big')
    return value.bit_length().to_bytes(2, 'big') + payload


def _point_bytes(public_key, curve):
    if curve == EllipticCurveOID.Curve25519:
        raw = public_key.public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
        return b'\x40' + raw

    field_len = (curve.key_size + 7) // 8
    numbers = public_key.public_numbers()
    return (b'\x04' + numbers.x.to_bytes(field_len, 'big') +
            numbers.y.to_bytes(field_len, 'big'))


def _reference_private_key(key_packet):
    material = key_packet.keymaterial
    if material.oid == EllipticCurveOID.Curve25519:
        raw = int(material.s).to_bytes((material.oid.key_size + 7) // 8, 'little')
        return x25519.X25519PrivateKey.from_private_bytes(raw)

    public_numbers = ec.EllipticCurvePublicNumbers(material.p.x, material.p.y, material.oid.curve())
    private_numbers = ec.EllipticCurvePrivateNumbers(int(material.s), public_numbers)
    return private_numbers.private_key(default_backend())


def _reference_shared_from_ephemeral(key_packet, ephemeral_private):
    curve = key_packet.keymaterial.oid
    recipient_public = key_packet.pubkey().keymaterial.__pubkey__()
    if curve == EllipticCurveOID.Curve25519:
        return ephemeral_private.exchange(recipient_public)
    return ephemeral_private.exchange(ec.ECDH(), recipient_public)


def _reference_shared_from_ciphertext(key_packet, ciphertext):
    curve = key_packet.keymaterial.oid
    private_key = _reference_private_key(key_packet)
    if curve == EllipticCurveOID.Curve25519:
        return private_key.exchange(x25519.X25519PublicKey.from_public_bytes(ciphertext.p.x))

    public_numbers = ec.EllipticCurvePublicNumbers(ciphertext.p.x, ciphertext.p.y, curve.curve())
    return private_key.exchange(ec.ECDH(), public_numbers.public_key(default_backend()))


def _temporary_prime_key(curve, scalar, hash_alg, kek_alg):
    packet = PrivKeyV4.new(PubKeyAlgorithm.ECDH, curve, created=CREATED)
    material = packet.keymaterial
    private_key = ec.derive_private_key(scalar, curve.curve(), default_backend())
    public_numbers = private_key.public_key().public_numbers()
    material.s = MPI(scalar)
    material.p = ECPoint.from_values(curve.key_size, ECPointFormat.Standard,
                                     MPI(public_numbers.x), MPI(public_numbers.y))
    material.kdf.halg = hash_alg
    material.kdf.encalg = kek_alg
    material._compute_chksum()
    packet.update_hlen()
    return packet


def _temporary_cv25519_key(private_bytes, hash_alg, kek_alg):
    packet = PrivKeyV4.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519, created=CREATED)
    material = packet.keymaterial
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    public_bytes = private_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                         serialization.PublicFormat.Raw)
    material.s = MPI(int.from_bytes(private_bytes, 'little'))
    material.p = ECPoint.from_values(256, ECPointFormat.Native, public_bytes)
    material.kdf.halg = hash_alg
    material.kdf.encalg = kek_alg
    material._compute_chksum()
    packet.update_hlen()
    return packet


def _repo_key(filename, subkey_id):
    key = PGPKey.from_file(filename)[0]
    return key, key.subkeys[subkey_id]._key


def _prime_ephemeral(curve, scalar):
    return ec.derive_private_key(scalar, curve.curve(), default_backend())


def _cv25519_ephemeral(private_bytes):
    return x25519.X25519PrivateKey.from_private_bytes(private_bytes)


def _make_vector(recipient, curve, hash_alg, kek_alg, session_alg, session_key,
                 ephemeral_private, padding, wrong_fingerprint):
    fingerprint = _v4_fingerprint(recipient.pubkey())
    other_info = _other_info(curve, hash_alg, kek_alg, fingerprint)
    shared_secret = _reference_shared_from_ephemeral(recipient, ephemeral_private)
    kek = _concat_kdf(shared_secret, other_info, hash_alg, kek_alg.key_size // 8)
    m = _session_key_m(session_alg, session_key, padding)
    wrapped = aes_key_wrap(kek, m, default_backend())

    point = _point_bytes(ephemeral_private.public_key(), curve)
    raw = _mpi_bytes(point) + bytes([len(wrapped)]) + wrapped
    ciphertext = ECDHCipherText()
    ciphertext.parse(bytearray(raw))

    return {
        'recipient': recipient,
        'curve': curve,
        'hash_alg': hash_alg,
        'kek_alg': kek_alg,
        'session_alg': session_alg,
        'session_key': bytes(session_key),
        'padding': padding,
        'fingerprint': fingerprint,
        'wrong_fingerprint': wrong_fingerprint,
        'other_info': other_info,
        'shared_secret': shared_secret,
        'kek': kek,
        'm': m,
        'ciphertext': bytes(wrapped),
        'ciphertext_packet': ciphertext,
        'raw_ciphertext': raw,
    }


def _build_vectors():
    p256_key, p256_recipient = _repo_key('tests/testdata/keys/ecc.1.sec.asc',
                                         'A81B93FD16BD9806')
    assert str(p256_recipient.fingerprint) == REPO_P256_SUBKEY_FINGERPRINT
    assert str(p256_key.fingerprint) == REPO_P256_PRIMARY_FINGERPRINT

    cv_key, cv_recipient = _repo_key('tests/testdata/keys/ecc.2.sec.asc',
                                     'AFC377493D8E897D')
    assert str(cv_recipient.fingerprint) == REPO_CV25519_SUBKEY_FINGERPRINT
    assert str(cv_key.fingerprint) == REPO_CV25519_PRIMARY_FINGERPRINT

    p256_aes192 = _temporary_prime_key(
        EllipticCurveOID.NIST_P256, 0x0F1E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF,
        HashAlgorithm.SHA256, SymmetricKeyAlgorithm.AES192)
    p256_aes256 = _temporary_prime_key(
        EllipticCurveOID.NIST_P256, 0x0F1E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF,
        HashAlgorithm.SHA256, SymmetricKeyAlgorithm.AES256)
    p384 = _temporary_prime_key(
        EllipticCurveOID.NIST_P384,
        0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,
        HashAlgorithm.SHA384, SymmetricKeyAlgorithm.AES192)
    p521 = _temporary_prime_key(
        EllipticCurveOID.NIST_P521,
        0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,
        HashAlgorithm.SHA512, SymmetricKeyAlgorithm.AES256)

    p256_ephemeral = _prime_ephemeral(EllipticCurveOID.NIST_P256, 0x107F6E5D431BB2A098)
    p384_ephemeral = _prime_ephemeral(EllipticCurveOID.NIST_P384, 5)
    p521_ephemeral = _prime_ephemeral(EllipticCurveOID.NIST_P521, 7)
    cv_ephemeral = _cv25519_ephemeral(bytes([201]) * 32)

    vectors = {}
    vectors['nist_p256_repo_leadzero_pad5'] = _make_vector(
        p256_recipient, EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256,
        SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES128, bytes(range(16)),
        p256_ephemeral, 5, REPO_P256_PRIMARY_FINGERPRINT)
    vectors['nist_p256_repo_leadzero_pad13'] = _make_vector(
        p256_recipient, EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256,
        SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES128, bytes(range(16)),
        p256_ephemeral, 13, REPO_P256_PRIMARY_FINGERPRINT)
    vectors['nist_p256_repo_leadzero_pad21'] = _make_vector(
        p256_recipient, EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256,
        SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES128, bytes(range(16)),
        p256_ephemeral, 21, REPO_P256_PRIMARY_FINGERPRINT)
    vectors['nist_p256_temp_kek_aes192'] = _make_vector(
        p256_aes192, EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256,
        SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128, bytes(range(16)),
        p256_ephemeral, 5, REPO_P256_PRIMARY_FINGERPRINT)
    vectors['nist_p256_temp_kek_aes256'] = _make_vector(
        p256_aes256, EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256,
        SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128, bytes(range(16)),
        p256_ephemeral, 5, REPO_P256_PRIMARY_FINGERPRINT)
    vectors['nist_p384_temp'] = _make_vector(
        p384, EllipticCurveOID.NIST_P384, HashAlgorithm.SHA384,
        SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES192, bytes(range(24)),
        p384_ephemeral, 5, REPO_P256_PRIMARY_FINGERPRINT)
    vectors['nist_p521_temp'] = _make_vector(
        p521, EllipticCurveOID.NIST_P521, HashAlgorithm.SHA512,
        SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES256, bytes(range(32)),
        p521_ephemeral, 5, REPO_P256_PRIMARY_FINGERPRINT)
    vectors['cv25519_repo_leadzero'] = _make_vector(
        cv_recipient, EllipticCurveOID.Curve25519, HashAlgorithm.SHA256,
        SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES128, bytes(range(16)),
        cv_ephemeral, 5, REPO_CV25519_PRIMARY_FINGERPRINT)

    return vectors


VECTORS = _build_vectors()

_CROSS_KEYS = {}


def _cross_key(curve):
    if curve not in _CROSS_KEYS:
        if curve == EllipticCurveOID.NIST_P256:
            _CROSS_KEYS[curve] = _temporary_prime_key(
                curve, 0xBAD0C0DE123456789, HashAlgorithm.SHA256, SymmetricKeyAlgorithm.AES128)
        elif curve == EllipticCurveOID.NIST_P384:
            _CROSS_KEYS[curve] = _temporary_prime_key(
                curve, 0xBADC0DE123456789AB, HashAlgorithm.SHA384, SymmetricKeyAlgorithm.AES192)
        elif curve == EllipticCurveOID.NIST_P521:
            _CROSS_KEYS[curve] = _temporary_prime_key(
                curve, 0xBADC0DE123456789ABCDEF, HashAlgorithm.SHA512, SymmetricKeyAlgorithm.AES256)
        elif curve == EllipticCurveOID.Curve25519:
            _CROSS_KEYS[curve] = _temporary_cv25519_key(
                bytes([0x5A]) * 32, HashAlgorithm.SHA256, SymmetricKeyAlgorithm.AES128)
        else:  # pragma: no cover
            raise AssertionError(curve)
    return _CROSS_KEYS[curve]


def _manifest_entry(vector):
    return {
        'fingerprint': vector['fingerprint'],
        'padding': vector['padding'],
        'session_alg': int(vector['session_alg']),
        'session_key': vector['session_key'].hex(),
        'unpadded_m': _expected_unpadded_m(vector).hex(),
        'other_info': vector['other_info'].hex(),
        'other_info_sha256': _sha256_hex(vector['other_info']),
        'shared_secret': vector['shared_secret'].hex(),
        'shared_secret_sha256': _sha256_hex(vector['shared_secret']),
        'kek': vector['kek'].hex(),
        'kek_sha256': _sha256_hex(vector['kek']),
        'm': vector['m'].hex(),
        'm_sha256': _sha256_hex(vector['m']),
        'ciphertext': vector['ciphertext'].hex(),
        'ciphertext_sha256': _sha256_hex(vector['ciphertext']),
    }


def _reference_unwrap(vector):
    shared = _reference_shared_from_ciphertext(vector['recipient'], vector['ciphertext_packet'])
    fingerprint = _v4_fingerprint(vector['recipient'].pubkey())
    other_info = _other_info(vector['curve'], vector['hash_alg'], vector['kek_alg'], fingerprint)
    kek = _concat_kdf(shared, other_info, vector['hash_alg'], vector['kek_alg'].key_size // 8)

    m = bytes(aes_key_unwrap(kek, vector['ciphertext'], default_backend()))
    assert len(m) % 8 == 0
    session_alg = SymmetricKeyAlgorithm(m[0])
    key_length = session_alg.key_size // 8
    session_key = m[1:1 + key_length]
    checksum = int.from_bytes(m[1 + key_length:3 + key_length], 'big')
    body = m[3 + key_length:]
    padding = body[-1]
    assert 1 <= padding <= len(body)
    assert body[-padding:] == bytes([padding]) * padding
    assert checksum == sum(session_key) % 65536

    return {
        'shared_secret': shared,
        'other_info': other_info,
        'kek': kek,
        'm': m,
        'session_alg': session_alg,
        'session_key': session_key,
    }


def _expected_unpadded_m(vector):
    key = bytes(vector['session_key'])
    return (bytes([int(vector['session_alg'])]) + key +
            (sum(key) % 65536).to_bytes(2, 'big'))


def test_reference_curve_oids_match_rfc6637():
    assert ANONYMOUS_SENDER.hex() == ANONYMOUS_SENDER_HEX
    assert len(ANONYMOUS_SENDER) == 20
    assert ANONYMOUS_SENDER.endswith(b' ' * 4)

    for curve in (EllipticCurveOID.NIST_P256, EllipticCurveOID.NIST_P384,
                  EllipticCurveOID.NIST_P521, EllipticCurveOID.Curve25519):
        body = _curve_oid_body(curve)
        assert _der_oid_body(curve.value) == body
        # The DER encoding is tag || length || body, so removing the tag yields
        # exactly curve_OID_len || curve_OID as required by RFC 6637.
        encoded = bytes(encoder.encode(ObjectIdentifier(curve.value)))
        assert encoded[1:] == bytes([len(body)]) + body

    assert len(_other_info(EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256,
                           SymmetricKeyAlgorithm.AES128, '00' * 20)) == 54
    for curve in (EllipticCurveOID.NIST_P384, EllipticCurveOID.NIST_P521):
        assert len(_other_info(curve, HashAlgorithm.SHA384,
                               SymmetricKeyAlgorithm.AES192, '00' * 20)) == 51


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_other_info_places_recipient_fingerprint_at_the_end(name):
    vector = VECTORS[name]
    oi = vector['other_info']
    oid = _curve_oid_body(vector['curve'])
    offset = 1 + len(oid)

    assert oi[0] == len(oid)
    assert oi[1:offset] == oid
    assert oi[offset] == ECDH_ALGORITHM_ID
    assert oi[offset + 1:offset + 3] == KDF_RESERVED
    assert oi[offset + 3] == HASH_IDS[vector['hash_alg']]
    assert oi[offset + 4] == KEK_IDS[vector['kek_alg']]
    assert oi[offset + 5:offset + 25] == ANONYMOUS_SENDER
    assert oi[offset + 25:offset + 45] == bytes.fromhex(vector['fingerprint'])
    assert len(oi) == offset + 45


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_reference_fingerprint_matches_recipient_public_packet(name):
    vector = VECTORS[name]
    fingerprint = _v4_fingerprint(vector['recipient'].pubkey())
    assert fingerprint == vector['fingerprint']
    assert fingerprint == str(vector['recipient'].fingerprint)
    assert len(bytes.fromhex(fingerprint)) == 20


def test_repo_vector_uses_subkey_fingerprint_not_primary():
    for name in ('nist_p256_repo_leadzero_pad5', 'cv25519_repo_leadzero'):
        vector = VECTORS[name]
        assert vector['fingerprint'] != vector['wrong_fingerprint']
        assert vector['fingerprint'][-16:] != vector['wrong_fingerprint'][-16:]


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_concat_kdf_uses_counter_shared_secret_and_other_info(name):
    vector = VECTORS[name]
    digest = hashlib.new(
        HASH_NAMES[vector['hash_alg']],
        (1).to_bytes(4, 'big') + vector['shared_secret'] + vector['other_info']).digest()
    assert vector['kek'] == digest[:vector['kek_alg'].key_size // 8]
    assert len(vector['kek']) == vector['kek_alg'].key_size // 8


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_production_kdf_matches_independent_reference(name):
    vector = VECTORS[name]
    material = vector['recipient'].keymaterial
    production = material.kdf.derive_key(vector['shared_secret'], material.oid,
                                         PubKeyAlgorithm.ECDH, vector['fingerprint'])
    assert production == vector['kek']


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_production_decrypts_independently_wrapped_session_key(name):
    vector = VECTORS[name]
    recovered = bytes(vector['ciphertext_packet'].decrypt(vector['recipient']))
    assert recovered == _expected_unpadded_m(vector)
    assert recovered[0] == int(vector['session_alg'])
    assert recovered[1:1 + len(vector['session_key'])] == vector['session_key']


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_reference_unwrap_recovers_the_same_session_key(name):
    vector = VECTORS[name]
    result = _reference_unwrap(vector)
    assert result['shared_secret'] == vector['shared_secret']
    assert result['other_info'] == vector['other_info']
    assert result['kek'] == vector['kek']
    assert result['m'] == vector['m']
    assert result['session_alg'] == vector['session_alg']
    assert result['session_key'] == vector['session_key']


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_pinned_kdf_inputs_and_kek_digests(name):
    assert _manifest_entry(VECTORS[name]) == EXPECTED_MANIFEST[name]


def test_pinned_manifest_covers_all_requested_curves_and_kek_sizes():
    curves = {VECTORS[name]['curve'] for name in VECTORS}
    assert curves == {
        EllipticCurveOID.NIST_P256,
        EllipticCurveOID.NIST_P384,
        EllipticCurveOID.NIST_P521,
        EllipticCurveOID.Curve25519,
    }
    kek_sizes = {len(VECTORS[name]['kek']) for name in VECTORS}
    assert kek_sizes == {16, 24, 32}
    for name in ('nist_p256_repo_leadzero_pad5', 'cv25519_repo_leadzero'):
        assert VECTORS[name]['shared_secret'][0] == 0
    assert {VECTORS[name]['padding'] for name in VECTORS} >= {5, 13, 21}


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_same_ciphertext_under_another_key_does_not_yield_the_session_key(name):
    vector = VECTORS[name]
    other = _cross_key(vector['curve'])
    assert _v4_fingerprint(other.pubkey()) != vector['fingerprint']

    with pytest.raises((InvalidUnwrap, PGPDecryptionError, ValueError, TypeError)):
        vector['ciphertext_packet'].decrypt(other)

    # The same failure occurs in the independent path, so this is not an
    # artifact of production error handling.
    other_shared = _reference_shared_from_ciphertext(other, vector['ciphertext_packet'])
    other_oi = _other_info(vector['curve'], vector['hash_alg'], vector['kek_alg'],
                           _v4_fingerprint(other.pubkey()))
    other_kek = _concat_kdf(other_shared, other_oi, vector['hash_alg'],
                            vector['kek_alg'].key_size // 8)
    with pytest.raises(InvalidUnwrap):
        aes_key_unwrap(other_kek, vector['ciphertext'], default_backend())


@pytest.mark.parametrize('name', ('nist_p256_repo_leadzero_pad5', 'cv25519_repo_leadzero'))
def test_omitting_the_leading_zero_breaks_unwrapping(name):
    vector = VECTORS[name]
    assert vector['shared_secret'][0] == 0

    trimmed = vector['shared_secret'].lstrip(b'\x00')
    assert trimmed != vector['shared_secret']

    mutant_kek = _concat_kdf(trimmed, vector['other_info'], vector['hash_alg'],
                             vector['kek_alg'].key_size // 8)
    assert mutant_kek != vector['kek']
    assert _sha256_hex(mutant_kek) != _sha256_hex(vector['kek'])

    with pytest.raises(InvalidUnwrap):
        aes_key_unwrap(mutant_kek, vector['ciphertext'], default_backend())

    # The unmodified reference path still succeeds, so the failure above is
    # caused solely by dropping the leading zero octet.
    assert _reference_unwrap(vector)['kek'] == vector['kek']


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_wrong_recipient_fingerprint_breaks_unwrapping(name):
    vector = VECTORS[name]
    wrong_oi = _other_info(vector['curve'], vector['hash_alg'], vector['kek_alg'],
                           vector['wrong_fingerprint'])
    assert wrong_oi != vector['other_info']

    mutant_kek = _concat_kdf(vector['shared_secret'], wrong_oi, vector['hash_alg'],
                             vector['kek_alg'].key_size // 8)
    assert mutant_kek != vector['kek']

    with pytest.raises(InvalidUnwrap):
        aes_key_unwrap(mutant_kek, vector['ciphertext'], default_backend())


def test_full_fingerprint_is_used_not_only_the_key_id():
    vector = VECTORS['nist_p256_repo_leadzero_pad5']
    fingerprint = bytes.fromhex(vector['fingerprint'])
    mutated = bytes([fingerprint[0] ^ 0xFF]) + fingerprint[1:]
    assert mutated[-8:] == fingerprint[-8:]  # same 64-bit Key ID

    mutant_oi = _other_info(vector['curve'], vector['hash_alg'], vector['kek_alg'],
                            mutated.hex())
    mutant_kek = _concat_kdf(vector['shared_secret'], mutant_oi, vector['hash_alg'],
                             vector['kek_alg'].key_size // 8)
    assert mutant_kek != vector['kek']
    with pytest.raises(InvalidUnwrap):
        aes_key_unwrap(mutant_kek, vector['ciphertext'], default_backend())


@pytest.mark.parametrize('padding', (5, 13, 21))
def test_rfc6637_size_obfuscation_padding_lengths(padding):
    vector = VECTORS['nist_p256_repo_leadzero_pad{}'.format(padding)]
    assert vector['m'][-1] == padding
    assert vector['m'][-padding:] == bytes([padding]) * padding
    assert len(vector['m']) % 8 == 0
    assert len(vector['ciphertext']) == len(vector['m']) + 8
    assert bytes(vector['ciphertext_packet'].decrypt(vector['recipient'])) == _expected_unpadded_m(vector)
    assert _reference_unwrap(vector)['session_key'] == vector['session_key']


@pytest.mark.parametrize('bad_padding', (0, 4, 22))
def test_malformed_padding_is_rejected(bad_padding):
    vector = VECTORS['nist_p256_repo_leadzero_pad5']
    base = _expected_unpadded_m(vector)
    bad_m = base + bytes([5]) * 5
    if bad_padding == 0:
        bad_m = bad_m[:-1] + b'\x00'
    elif bad_padding == 4:
        bad_m = bad_m[:-1] + b'\x04'
    else:
        bad_m = base + bytes([21]) * 21
        bad_m = bad_m[:-1] + bytes([22])

    wrapped = aes_key_wrap(vector['kek'], bad_m, default_backend())
    point = bytes(vector['raw_ciphertext'])
    raw = point[:len(point) - len(vector['ciphertext']) - 1] + bytes([len(wrapped)]) + wrapped
    packet = ECDHCipherText()
    packet.parse(bytearray(raw))

    with pytest.raises(PGPDecryptionError):
        packet.decrypt(vector['recipient'])


def _gpg_vector():
    key = PGPKey.from_file('tests/testdata/keys/ecc.2.sec.asc')[0]
    recipient = key.subkeys['AFC377493D8E897D']._key
    message = PGPMessage.from_file('tests/testdata/messages/message.ecdh.cv25519.asc')
    pkesk = next(p for p in message._sessionkeys if p.pkalg == PubKeyAlgorithm.ECDH)

    fingerprint = _v4_fingerprint(recipient.pubkey())
    assert fingerprint == REPO_CV25519_SUBKEY_FINGERPRINT
    assert pkesk.encrypter == recipient.fingerprint.keyid

    shared = _reference_shared_from_ciphertext(recipient, pkesk.ct)
    other_info = _other_info(EllipticCurveOID.Curve25519, HashAlgorithm.SHA256,
                             SymmetricKeyAlgorithm.AES128, fingerprint)
    kek = _concat_kdf(shared, other_info, HashAlgorithm.SHA256, 16)
    m = bytes(aes_key_unwrap(kek, pkesk.ct.c, default_backend()))

    session_alg = SymmetricKeyAlgorithm(m[0])
    key_length = session_alg.key_size // 8
    session_key = m[1:1 + key_length]
    checksum = int.from_bytes(m[1 + key_length:3 + key_length], 'big')
    padding = m[-1]
    assert padding == 5
    assert m[-padding:] == bytes([padding]) * padding
    assert checksum == sum(session_key) % 65536

    return {
        'key': key,
        'recipient': recipient,
        'message': message,
        'pkesk': pkesk,
        'fingerprint': fingerprint,
        'shared_secret': shared,
        'other_info': other_info,
        'kek': kek,
        'm': m,
        'session_alg': session_alg,
        'session_key': session_key,
        'ciphertext': bytes(pkesk.ct.c),
    }


GPG_VECTOR = _gpg_vector()


def test_gnupg_ecdh_message_vector_is_pinned():
    vector = GPG_VECTOR
    entry = {
        'fingerprint': vector['fingerprint'],
        'other_info': vector['other_info'].hex(),
        'other_info_sha256': _sha256_hex(vector['other_info']),
        'shared_secret': vector['shared_secret'].hex(),
        'shared_secret_sha256': _sha256_hex(vector['shared_secret']),
        'kek': vector['kek'].hex(),
        'kek_sha256': _sha256_hex(vector['kek']),
        'm': vector['m'].hex(),
        'm_sha256': _sha256_hex(vector['m']),
        'ciphertext': vector['ciphertext'].hex(),
        'ciphertext_sha256': _sha256_hex(vector['ciphertext']),
    }
    assert entry == EXPECTED_GPG


def test_gnupg_ecdh_message_unwraps_and_decrypts_independently():
    vector = GPG_VECTOR
    result = _reference_unwrap({
        'recipient': vector['recipient'],
        'ciphertext_packet': vector['pkesk'].ct,
        'ciphertext': vector['ciphertext'],
        'curve': EllipticCurveOID.Curve25519,
        'hash_alg': HashAlgorithm.SHA256,
        'kek_alg': SymmetricKeyAlgorithm.AES128,
    })
    assert result['kek'] == vector['kek']
    assert result['session_alg'] == vector['session_alg']
    assert result['session_key'] == vector['session_key']

    plaintext = bytes(vector['message'].message.decrypt(result['session_key'], result['session_alg']))
    packets = Packet(bytearray(plaintext))
    assert packets.header.tag == 8  # Compressed Data
    literal = packets.packets[0]
    assert literal.header.tag == 11  # Literal Data
    assert bytes(literal.contents) == b'This message will have been encrypted'

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        decrypted = vector['key'].decrypt(vector['message'])
    assert bytes(decrypted.message) == b'This message will have been encrypted'


def _production_encrypt_then_independent_unwrap(public_file, private_file, subkey_id,
                                                curve, hash_alg, kek_alg, cipher,
                                                session_key, plaintext):
    public_key = PGPKey.from_file(public_file)[0]
    public_subkey = public_key.subkeys[subkey_id]
    private_key = PGPKey.from_file(private_file)[0]
    private_subkey = private_key.subkeys[subkey_id]._key

    message = PGPMessage.new(plaintext)
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        encrypted = public_subkey.encrypt(message, cipher=cipher, sessionkey=session_key)

    pkesk = next(p for p in encrypted._sessionkeys if p.pkalg == PubKeyAlgorithm.ECDH)
    fingerprint = _v4_fingerprint(private_subkey.pubkey())
    assert pkesk.encrypter == private_subkey.fingerprint.keyid

    shared = _reference_shared_from_ciphertext(private_subkey, pkesk.ct)
    other_info = _other_info(curve, hash_alg, kek_alg, fingerprint)
    kek = _concat_kdf(shared, other_info, hash_alg, kek_alg.key_size // 8)
    m = bytes(aes_key_unwrap(kek, pkesk.ct.c, default_backend()))

    recovered_alg = SymmetricKeyAlgorithm(m[0])
    key_length = recovered_alg.key_size // 8
    recovered_key = m[1:1 + key_length]
    checksum = int.from_bytes(m[1 + key_length:3 + key_length], 'big')
    assert checksum == sum(recovered_key) % 65536
    padding = m[-1]
    assert m[-padding:] == bytes([padding]) * padding

    assert recovered_alg == cipher
    assert recovered_key == bytes(session_key)

    plaintext_packets = Packet(bytearray(encrypted.message.decrypt(recovered_key, recovered_alg)))
    literal = plaintext_packets.packets[0]
    assert bytes(literal.contents, 'latin-1') == plaintext.encode('utf-8')


@pytest.mark.parametrize('public_file,private_file,subkey_id,curve,hash_alg,kek_alg', (
    ('tests/testdata/keys/ecc.1.pub.asc', 'tests/testdata/keys/ecc.1.sec.asc',
     'A81B93FD16BD9806', EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256,
     SymmetricKeyAlgorithm.AES128),
    ('tests/testdata/keys/ecc.2.pub.asc', 'tests/testdata/keys/ecc.2.sec.asc',
     'AFC377493D8E897D', EllipticCurveOID.Curve25519, HashAlgorithm.SHA256,
     SymmetricKeyAlgorithm.AES128),
))
def test_random_ephemeral_production_ciphertext_unwraps_independently(public_file, private_file,
                                                                      subkey_id, curve, hash_alg,
                                                                      kek_alg):
    session_key = bytes(range(16))
    _production_encrypt_then_independent_unwrap(
        public_file, private_file, subkey_id, curve, hash_alg, kek_alg,
        SymmetricKeyAlgorithm.AES128, session_key, 'independent RFC 6637 unwrap')




@pytest.mark.parametrize('mutant', ('strip_leading_zero', 'wrong_fingerprint'))
def test_deliberately_broken_production_kdf_fails_decryption(monkeypatch, mutant):
    """Mutating production's KDF inputs must turn the pinned vectors red."""
    vector = VECTORS['nist_p256_repo_leadzero_pad5']
    assert vector['shared_secret'][0] == 0

    original = ECKDF.derive_key

    def mutant_derive_key(self, shared_secret, curve, pkalg, fingerprint):
        if mutant == 'strip_leading_zero':
            shared_secret = bytes(shared_secret).lstrip(b'\x00')
        else:
            # use the primary-key fingerprint instead of the encryption subkey's
            fingerprint = REPO_P256_PRIMARY_FINGERPRINT
        return original(self, shared_secret, curve, pkalg, fingerprint)

    monkeypatch.setattr(ECKDF, 'derive_key', mutant_derive_key)

    with pytest.raises((InvalidUnwrap, PGPDecryptionError, ValueError, TypeError)):
        vector['ciphertext_packet'].decrypt(vector['recipient'])


def test_message_ciphertext_retargeted_to_another_key_yields_no_session_key():
    """Move one PKESK to another Curve25519 key; the wrapped session key must stay unusable."""
    public_key = PGPKey.from_file('tests/testdata/keys/ecc.2.pub.asc')[0]
    recipient = public_key.subkeys['AFC377493D8E897D']
    recipient_secret = PGPKey.from_file('tests/testdata/keys/ecc.2.sec.asc')[0]
    other_secret = PGPKey.from_file('tests/testdata/keys/mixed.1.sec.asc')[0].subkeys['B345506C90A428C5']

    assert recipient.key_algorithm == other_secret.key_algorithm == PubKeyAlgorithm.ECDH
    assert recipient._key.keymaterial.oid == other_secret._key.keymaterial.oid
    assert recipient.fingerprint != other_secret.fingerprint

    session_key = bytes(range(16))
    message = PGPMessage.new('retargeted ECDH session key')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        encrypted = recipient.encrypt(message, cipher=SymmetricKeyAlgorithm.AES128, sessionkey=session_key)

    pkesk = next(p for p in encrypted._sessionkeys if p.pkalg == PubKeyAlgorithm.ECDH)
    assert pkesk.encrypter == recipient.fingerprint.keyid

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        assert recipient_secret.decrypt(encrypted).message == 'retargeted ECDH session key'

    wrapped_before = bytes(pkesk.ct.c)
    point_before = (pkesk.ct.p.x, pkesk.ct.p.y, pkesk.ct.p.format)

    pkesk.encrypter = bytearray(binascii.unhexlify(other_secret.fingerprint.keyid))
    assert bytes(pkesk.ct.c) == wrapped_before
    assert (pkesk.ct.p.x, pkesk.ct.p.y, pkesk.ct.p.format) == point_before

    with pytest.raises((InvalidUnwrap, PGPDecryptionError, ValueError, TypeError)):
        other_secret.decrypt(encrypted)

    # The independent reference unwrap also fails under the other key's fingerprint.
    other_fingerprint = _v4_fingerprint(other_secret._key.pubkey())
    assert other_fingerprint == str(other_secret.fingerprint)
    assert other_fingerprint != recipient.fingerprint
    shared = _reference_shared_from_ciphertext(other_secret._key, pkesk.ct)
    other_info = _other_info(EllipticCurveOID.Curve25519, HashAlgorithm.SHA256,
                             SymmetricKeyAlgorithm.AES128, other_fingerprint)
    other_kek = _concat_kdf(shared, other_info, HashAlgorithm.SHA256, 16)
    with pytest.raises(InvalidUnwrap):
        aes_key_unwrap(other_kek, wrapped_before, default_backend())


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_final_unseal_verdict_is_pinned(name):
    vector = VECTORS[name]
    verdict = EXPECTED_UNSEAL[name]

    production_ok = bytes(vector['ciphertext_packet'].decrypt(vector['recipient'])) == _expected_unpadded_m(vector)
    reference_ok = _reference_unwrap(vector)['session_key'] == vector['session_key']

    try:
        vector['ciphertext_packet'].decrypt(_cross_key(vector['curve']))
        cross_key_rejected = False
    except (InvalidUnwrap, PGPDecryptionError, ValueError, TypeError):
        cross_key_rejected = True

    assert {'production': production_ok,
            'reference': reference_ok,
            'cross_key_rejected': cross_key_rejected} == verdict


def test_gnupg_message_final_unseal_verdict_is_pinned():
    vector = GPG_VECTOR
    production_ok = bytes(vector['pkesk'].ct.decrypt(vector['recipient'])) == _expected_unpadded_m({
        'session_alg': vector['session_alg'],
        'session_key': vector['session_key'],
    })
    reference_ok = _reference_unwrap({
        'recipient': vector['recipient'],
        'ciphertext_packet': vector['pkesk'].ct,
        'ciphertext': vector['ciphertext'],
        'curve': EllipticCurveOID.Curve25519,
        'hash_alg': HashAlgorithm.SHA256,
        'kek_alg': SymmetricKeyAlgorithm.AES128,
    })['session_key'] == vector['session_key']

    assert {'production': production_ok, 'reference': reference_ok,
            'cross_key_rejected': True} == EXPECTED_UNSEAL['gnupg_cv25519_message']


def test_reference_path_does_not_call_production_derive_key(monkeypatch):
    """Guard the independence claim: the reference vector construction must not delegate to ECKDF."""
    def forbidden(*args, **kwargs):  # pragma: no cover
        raise AssertionError('reference path called production ECKDF.derive_key')

    monkeypatch.setattr(ECKDF, 'derive_key', forbidden)

    vector = _make_vector(VECTORS['nist_p256_repo_leadzero_pad5']['recipient'],
                          EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256,
                          SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES128,
                          bytes(range(16)), _prime_ephemeral(EllipticCurveOID.NIST_P256,
                                                             0x107F6E5D431BB2A098),
                          5, REPO_P256_PRIMARY_FINGERPRINT)
    assert vector['kek'] == VECTORS['nist_p256_repo_leadzero_pad5']['kek']
    assert vector['m'] == VECTORS['nist_p256_repo_leadzero_pad5']['m']
    assert vector['ciphertext'] == VECTORS['nist_p256_repo_leadzero_pad5']['ciphertext']
    assert _reference_unwrap(vector)['session_key'] == bytes(range(16))
