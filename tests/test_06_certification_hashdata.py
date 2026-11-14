"""
Targeted differential tests for OpenPGP certification-signature digest
construction (RFC 4880 section 5.2.4, "Computing Signatures" -- see
.feedback/specs/rfc4880.txt).

Every expected hash preimage here is built independently: target-type prefix
octets (0x99 key / 0xB4 User ID / 0xD1 User Attribute), the two- and
four-octet length fields, the hashed-subpacket area and the six-octet V4
trailer are assembled from raw packet bytes parsed by this module.  PGPy's
own ``PGPSignature.hashdata``/``PGPKey.hashdata`` convenience logic is the
implementation *under test*, never the oracle, so a defect that makes
distinct target types share a signature domain cannot confirm itself.

Variant selection uses a fixed seed, so the bounded set of cases is
reproducible; each minimal mutation is wired back into the public
``certify``/``bind``/``verify`` API.
"""
import hashlib
import random
import struct
from types import SimpleNamespace

import pytest

from pgpy import PGPKey, PGPUID, PGPSignature
from pgpy.constants import HashAlgorithm, KeyFlags, PubKeyAlgorithm, SignatureType

pytestmark = pytest.mark.filterwarnings('ignore::UserWarning')

# fixed seed: bounded, reproducible variant generation
SEED = 0xF14880
UID_VARIANTS = 4

# pool of User IDs exercising distinct UTF-8 byte-length classes:
# pure ASCII, 2-byte, 3-byte and 4-byte sequences, and mixed forms
UID_POOL = [
    'Alice Example <alice@example.org>',
    'Björk Guðmundsdóttir <bjork@example.is>',
    '日本語 名前 <nihon@example.jp>',
    'Pompe 🎃 <pumpkin@example.org>',
    'Åsa Ström (åäö) <asa@example.se>',
    'Łukasz Żółć <lukasz@example.pl>',
    '김철수 <kim@example.kr>',
    'Müller 🎃🎃 日本 <mixed@example.org>',
]

CERT_SIGTYPES = {SignatureType.Generic_Cert, SignatureType.Persona_Cert,
                 SignatureType.Casual_Cert, SignatureType.Positive_Cert,
                 SignatureType.CertRevocation}


# ---------------------------------------------------------------------------
# independent preimage construction (the oracle; no PGPy hashdata logic)
# ---------------------------------------------------------------------------

def packet_body(raw):
    """Parse exactly one OpenPGP packet header (RFC 4880 section 4.2) and
    return the packet body."""
    first = raw[0]
    assert first & 0x80, 'not an OpenPGP packet'
    if first & 0x40:
        # new-format header: 1-, 2- or 5-octet definite lengths
        length_octet = raw[1]
        if length_octet < 192:
            hlen = 2
        elif length_octet <= 223:
            hlen = 3
        elif length_octet == 255:
            hlen = 5
        else:  # pragma: no cover
            raise AssertionError('partial body lengths are not emitted by PGPy')
    else:
        # old-format header: length type in the low two bits
        hlen = {0: 2, 1: 3, 2: 5}[first & 0x03]
    return bytes(raw[hlen:])


def key_domain(pgpkey):
    """0x99 || two-octet length || key packet body (RFC 4880 section 5.2.4)."""
    body = packet_body(bytes(pgpkey._key.pubkey()))
    return b'\x99' + struct.pack('>H', len(body)) + body


def uid_domain(pgpuid):
    """0xB4 || four-octet length || raw User ID octets (UTF-8)."""
    data = pgpuid._uid.uid.encode('utf-8')
    return b'\xb4' + struct.pack('>I', len(data)) + data


def ua_domain(pgpuid):
    """0xD1 || four-octet length || User Attribute packet body."""
    body = packet_body(bytes(pgpuid._uid))
    return b'\xd1' + struct.pack('>I', len(body)) + body


def v4_trailer(pgpsig):
    """version || sigtype || pubalg || hashalg || hashed-subpacket length and
    body, then 0x04 0xFF || four-octet length of the foregoing."""
    body = packet_body(bytes(pgpsig._signature))
    hlen = struct.unpack('>H', body[4:6])[0]
    head = body[:6 + hlen]
    return head + b'\x04\xff' + struct.pack('>I', len(head))


def digest_of(preimage, halg):
    return hashlib.new(halg.name.lower(), preimage).digest()


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module')
def cert_material():
    rng = random.Random(SEED)

    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)

    uids = []
    for name in rng.sample(UID_POOL, UID_VARIANTS):
        uid = PGPUID.new(name)
        key.add_uid(uid, usage={KeyFlags.Certify, KeyFlags.Sign},
                    hashes=[HashAlgorithm.SHA256])
        uids.append(uid)

    # a user attribute with deterministic pseudo-photo contents
    ua = PGPUID.new(bytearray(rng.getrandbits(8) for _ in range(48)))
    key.add_uid(ua, hashes=[HashAlgorithm.SHA256])

    # a signing-capable subkey, so a cross-signature (0x19) is also produced
    sub = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_subkey(sub, usage={KeyFlags.Sign})

    # an independent certifier, for third-party certifications/attestations
    third = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    third_uid = PGPUID.new('Third Party <third@example.org>')
    third.add_uid(third_uid, usage={KeyFlags.Certify}, hashes=[HashAlgorithm.SHA256])

    return SimpleNamespace(key=key, uids=uids, ua=ua, sub=sub, third=third)


@pytest.fixture(scope='module')
def binding_sig(cert_material):
    return next(s for s in cert_material.sub._signatures
                if s.type == SignatureType.Subkey_Binding)


# ---------------------------------------------------------------------------
# per-target-type differential preimage checks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('uid_idx', range(UID_VARIANTS))
def test_uid_certification_preimage(cert_material, uid_idx):
    uid = cert_material.uids[uid_idx]
    sig = uid.selfsig
    assert sig.type in CERT_SIGTYPES

    uid_bytes = uid._uid.uid.encode('utf-8')
    # the authenticated length is the UTF-8 *byte* count, never the character count
    assert uid_domain(uid)[1:5] == struct.pack('>I', len(uid_bytes))

    expected = key_domain(cert_material.key) + uid_domain(uid) + v4_trailer(sig)

    # differential check: production hashdata must equal the independent preimage
    assert sig.hashdata(uid) == expected
    # the signed hash2 left-justified octets must match the independent digest
    assert bytes(sig._signature.hash2) == digest_of(expected, sig.hash_algorithm)[:2]
    # and the whole thing must hold up through the public verify path
    assert cert_material.key.verify(uid, sig)


def test_user_attribute_certification_preimage(cert_material):
    ua = cert_material.ua
    sig = ua.selfsig
    assert sig.type in CERT_SIGTYPES

    expected = key_domain(cert_material.key) + ua_domain(ua) + v4_trailer(sig)

    assert sig.hashdata(ua) == expected
    assert bytes(sig._signature.hash2) == digest_of(expected, sig.hash_algorithm)[:2]
    assert cert_material.key.verify(ua, sig)


def test_subkey_binding_preimage(cert_material, binding_sig):
    expected = (key_domain(cert_material.key) + key_domain(cert_material.sub)
                + v4_trailer(binding_sig))

    assert binding_sig.hashdata(cert_material.sub) == expected
    assert bytes(binding_sig._signature.hash2) == digest_of(expected, binding_sig.hash_algorithm)[:2]
    assert cert_material.key.verify(cert_material.sub, binding_sig)


def test_primary_key_binding_preimage(cert_material):
    # minimal public-API path to a primary key binding signature (0x19)
    pkb = cert_material.sub.bind(cert_material.key)
    assert pkb.type == SignatureType.PrimaryKey_Binding

    expected = (key_domain(cert_material.key) + key_domain(cert_material.sub)
                + v4_trailer(pkb))

    assert pkb.hashdata(cert_material.key) == expected
    assert bytes(pkb._signature.hash2) == digest_of(expected, pkb.hash_algorithm)[:2]
    assert cert_material.key.verify(cert_material.key, pkb)


def test_attestation_preimage(cert_material):
    uid = cert_material.uids[0]
    # a third-party certification to be attested to
    tp_sig = cert_material.third.certify(uid, SignatureType.Generic_Cert)
    uid |= tp_sig

    att = cert_material.key.certify(uid, SignatureType.Attestation,
                                    attested_certifications=[tp_sig])
    assert att.type == SignatureType.Attestation

    # RFC 4880 does not define type 0x16; PGPy's attestation domain covers
    # only the signature trailer (no key or User ID material is mixed in).
    expected = v4_trailer(att)
    assert att.hashdata(uid) == expected

    # domain separation: the attestation over a User ID must not collide with
    # a certification over the same User ID (the sigtype octet in the hashed
    # trailer separates them)
    assert digest_of(expected, att.hash_algorithm) != digest_of(uid.selfsig.hashdata(uid), att.hash_algorithm)

    assert cert_material.key.verify(uid, att)
    assert att.attests_to(tp_sig)


# ---------------------------------------------------------------------------
# mutations that MUST change the digest (authenticated fields)
# ---------------------------------------------------------------------------

def test_binding_key_order_is_authenticated(cert_material, binding_sig):
    correct = (key_domain(cert_material.key) + key_domain(cert_material.sub)
               + v4_trailer(binding_sig))
    swapped = (key_domain(cert_material.sub) + key_domain(cert_material.key)
               + v4_trailer(binding_sig))

    # primary-before-subkey is the specified order; swapping must yield a
    # different preimage and a different digest
    assert binding_sig.hashdata(cert_material.sub) == correct
    assert swapped != correct
    assert digest_of(swapped, binding_sig.hash_algorithm) != digest_of(correct, binding_sig.hash_algorithm)


def test_unicode_uid_byte_length_governs_digest(cert_material):
    key = cert_material.key
    # equal character counts, different UTF-8 byte counts
    uid_wide = PGPUID.new('éééé <wide@example.org>')
    uid_narrow = PGPUID.new('eeee <narrow@example.org>')
    # single multibyte substitution at the same character position
    uid_subst = PGPUID.new('ééée <wide@example.org>')

    for uid in (uid_wide, uid_narrow, uid_subst):
        key.add_uid(uid, usage={KeyFlags.Certify}, hashes=[HashAlgorithm.SHA256])

    preimages = {uid._uid.uid: key_domain(key) + uid_domain(uid) + v4_trailer(uid.selfsig)
                 for uid in (uid_wide, uid_narrow, uid_subst)}

    wide_bytes = 'éééé <wide@example.org>'.encode('utf-8')
    assert uid_domain(uid_wide)[1:5] == struct.pack('>I', len(wide_bytes))
    assert len(wide_bytes) != len('éééé <wide@example.org>')

    # every byte-level difference must move the digest
    digests = {name: digest_of(pre, uid.selfsig.hash_algorithm)
               for name, pre in preimages.items()
               for uid in (uid_wide, uid_narrow, uid_subst) if uid._uid.uid == name}
    assert len(set(digests.values())) == 3

    # wire back through the public verify path
    for uid in (uid_wide, uid_narrow, uid_subst):
        assert uid.selfsig.hashdata(uid) == preimages[uid._uid.uid]
        assert key.verify(uid, uid.selfsig)


def test_hashed_subpacket_mutation_changes_digest_and_breaks_verify(cert_material):
    key, uid = cert_material.key, cert_material.uids[1]
    sig = key.certify(uid, SignatureType.Generic_Cert)

    before = sig.hashdata(uid)
    sig._signature.subpackets.addnew('NotationData', hashed=True, flags=0,
                                     name='tamper@example.org', value='authenticated')

    assert sig.hashdata(uid) != before
    # the hashed area is authenticated: mutating it invalidates the signature
    assert not key.verify(uid, sig)


# ---------------------------------------------------------------------------
# mutations that MUST NOT change the digest (explicitly unauthenticated)
# ---------------------------------------------------------------------------

def test_unhashed_subpacket_mutation_does_not_change_digest(cert_material):
    key, uid = cert_material.key, cert_material.uids[2]
    sig = key.certify(uid, SignatureType.Generic_Cert)

    before = sig.hashdata(uid)
    # the unhashed area is not covered by the signature per RFC 4880 section 5.2.4
    sig._signature.subpackets.addnew('NotationData', hashed=False, flags=0,
                                     name='note@example.org', value='not authenticated')

    assert sig.hashdata(uid) == before
    assert key.verify(uid, sig)


# ---------------------------------------------------------------------------
# domain separation: target-type prefixes must not be interchangeable
# ---------------------------------------------------------------------------

def test_target_type_domains_do_not_overlap(cert_material):
    uid = cert_material.uids[0]
    ua = cert_material.ua
    uid_bytes = uid._uid.uid.encode('utf-8')

    # the same payload octets under each target-type prefix
    as_uid = b'\xb4' + struct.pack('>I', len(uid_bytes)) + uid_bytes
    as_ua = b'\xd1' + struct.pack('>I', len(uid_bytes)) + uid_bytes
    as_key = b'\x99' + struct.pack('>H', len(uid_bytes)) + uid_bytes

    # all three domains must be pairwise distinct for identical content
    assert len({as_uid, as_ua, as_key}) == 3
    assert len({hashlib.sha256(d).digest() for d in (as_uid, as_ua, as_key)}) == 3

    # prefix-confused preimages must not reproduce the production hashdata
    key_part = key_domain(cert_material.key)
    trailer = v4_trailer(uid.selfsig)
    sig_confused = key_part + as_ua + trailer  # UID certified as User Attribute
    assert uid.selfsig.hashdata(uid) != sig_confused
    assert uid.selfsig.hashdata(uid) == key_part + as_uid + trailer

    ua_trailer = v4_trailer(ua.selfsig)
    assert ua.selfsig.hashdata(ua) != key_part + (
        b'\xb4' + struct.pack('>I', len(packet_body(bytes(ua._uid)))) + packet_body(bytes(ua._uid))) + ua_trailer


def test_prefix_confusion_defect_is_caught(cert_material, monkeypatch):
    """Simulate the deliberate defect: an implementation that swaps the User
    ID (0xB4) and User Attribute (0xD1) target-type prefixes.  Both the
    construction-level oracle and the public verify path must catch it."""
    key, uid, ua = cert_material.key, cert_material.uids[0], cert_material.ua
    original_hashdata = PGPSignature.hashdata

    def confused_hashdata(self, subject):
        data = bytearray(original_hashdata(self, subject))
        if self.type in CERT_SIGTYPES and isinstance(subject, PGPUID):
            # the certification prefix sits right after the 0x99 key block
            klen = struct.unpack('>H', bytes(data[1:3]))[0]
            pos = 3 + klen
            assert data[pos] in (0xB4, 0xD1)
            data[pos] ^= 0xB4 ^ 0xD1  # the defect: mixed-up target-type prefix
        return bytes(data)

    # construction level: the confused preimage cannot match the independent oracle
    uid_expected = key_domain(key) + uid_domain(uid) + v4_trailer(uid.selfsig)
    ua_expected = key_domain(key) + ua_domain(ua) + v4_trailer(ua.selfsig)
    assert confused_hashdata(uid.selfsig, uid) != uid_expected
    assert confused_hashdata(ua.selfsig, ua) != ua_expected

    # protocol level: verification under the confused domain must fail
    monkeypatch.setattr(PGPSignature, 'hashdata', confused_hashdata)
    assert not key.verify(uid, uid.selfsig)
    assert not key.verify(ua, ua.selfsig)
