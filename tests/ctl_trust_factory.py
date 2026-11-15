"""Self-contained PKI, Certificate Trust List and Authenticode signature factory.

The trust-constraint tests in ``test_ctl_trust_constraints.py`` exercise behaviour that
depends on the exact issuance time and EKU of certificates, and on the exact attribute
contents of a CTL. None of the shipped test data offers that level of control, so this
module generates everything on the fly.

Design notes
------------

* Keys are generated in pure Python (Miller-Rabin + RSA). The macOS ``oscrypto`` backend
  delegates key generation to the Keychain, which is unavailable in restricted
  environments, whereas loading already-generated DER keys and performing signing works
  everywhere.
* Only :mod:`asn1crypto` (ASN.1 structures) and :mod:`oscrypto` (RSA signing) are used,
  both of which are runtime dependencies of signify.
* CTL time attributes use the Windows ``FILETIME`` (count of 100-nanosecond intervals
  since 1601-01-01). :class:`signify.asn1.ctl.FileTime.set` multiplies by the wrong
  factor, so the raw value is packed here instead; :meth:`FileTime.native` decodes it
  correctly.
"""

from __future__ import annotations

import datetime
import hashlib
import math
import secrets
import struct
from dataclasses import dataclass

from asn1crypto import cms
from asn1crypto.algos import DigestAlgorithm
from asn1crypto.core import ObjectIdentifier
from asn1crypto.keys import (
    PublicKeyInfo,
    RSAPrivateKey,
    RSAPublicKey,
)
from asn1crypto.x509 import (
    BasicConstraints,
    ExtKeyUsageSyntax,
    KeyUsage,
    Name,
    TbsCertificate,
    Time,
    Validity,
    Certificate as Asn1Certificate,
)
from oscrypto import asymmetric

from signify import asn1 as _signify_asn1  # noqa: F401  (registers Microsoft OIDs)
from signify.asn1.ctl import (
    CertificateTrustList as Asn1CertificateTrustList,
    CTLString,
    FileTime,
    SubjectAttributeType,
    SubjectUsage,
    TrustedSubject,
    TrustedSubjects,
)
from signify.x509 import Certificate

# OID names used by the Authenticode / CTL structures.
OID_CTL_CONTENT = "1.3.6.1.4.1.311.10.1"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
OID_SPC_STATEMENT_TYPE = "1.3.6.1.4.1.311.2.1.11"
OID_SPC_SP_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12"
OID_SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15"
OID_SPC_COMMERCIAL = "1.3.6.1.4.1.311.2.1.22"

_SHA256_RSA = "sha256_rsa"
_RSA_BITS = 2048

# A fixed set of reference moments. All generated certificates are valid across the
# whole window, so the CTL time constraints - not ordinary certificate validity - are
# what determines the outcome.
WINDOW_START = datetime.datetime(2019, 1, 1, tzinfo=datetime.timezone.utc)
WINDOW_END = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
VERIFY_MOMENT = datetime.datetime(2021, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)


# --------------------------------------------------------------------------------------
# Low level DER helpers
# --------------------------------------------------------------------------------------
def _length_bytes(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length_bytes(len(content)) + content


def _filetime(value: datetime.datetime) -> FileTime:
    """Build a :class:`FileTime` holding the correct Windows FILETIME value."""
    ticks = int((value - FileTime._epoch).total_seconds() * 10_000_000)
    return FileTime.load(tlv(0x04, struct.pack("<Q", ticks)))


def _time(value: datetime.datetime) -> Time:
    """Build an x509 :class:`Time` choice (UTCTime before 2050)."""
    alternative = "utc_time" if value.year < 2050 else "general_time"
    return Time(name=alternative, value=value)


# --------------------------------------------------------------------------------------
# Pure Python RSA
# --------------------------------------------------------------------------------------
def _is_prime(number: int, rounds: int = 16) -> bool:
    if number < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if number % small == 0:
            return number == small
    d = number - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        base = secrets.randbelow(number - 3) + 2
        x = pow(base, d, number)
        if x in (1, number - 1):
            continue
        for _ in range(r - 1):
            x = x * x % number
            if x == number - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(candidate):
            return candidate


def generate_rsa_private_key(bits: int = _RSA_BITS) -> RSAPrivateKey:
    half = bits // 2
    public_exponent = 65537
    while True:
        p = _prime(half)
        q = _prime(half)
        if p == q:
            continue
        modulus = p * q
        if modulus.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(public_exponent, phi) != 1:
            continue
        private_exponent = pow(public_exponent, -1, phi)
        return RSAPrivateKey(
            {
                "version": 0,
                "modulus": modulus,
                "public_exponent": public_exponent,
                "private_exponent": private_exponent,
                "prime1": p,
                "prime2": q,
                "exponent1": private_exponent % (p - 1),
                "exponent2": private_exponent % (q - 1),
                "coefficient": pow(q, -1, p),
            }
        )


def _public_key_info(private_key: RSAPrivateKey) -> PublicKeyInfo:
    public_key = RSAPublicKey(
        {
            "modulus": private_key["modulus"].native,
            "public_exponent": private_key["public_exponent"].native,
        }
    )
    return PublicKeyInfo(
        {
            "algorithm": {"algorithm": "rsa"},
            "public_key": public_key,
        }
    )


# --------------------------------------------------------------------------------------
# Certificate generation
# --------------------------------------------------------------------------------------
@dataclass
class GeneratedCertificate:
    """A certificate together with the private key it was signed for."""

    certificate: Certificate
    private_key: object

    @property
    def subject(self) -> Name:
        return self.certificate.asn1.subject


def _build_certificate(
    *,
    subject_name: Name,
    subject_public_key: PublicKeyInfo,
    issuer_name: Name,
    issuer_key: object,
    serial_number: int,
    not_before: datetime.datetime,
    ca: bool,
    key_usage: set[str],
    extended_key_usages: list[str] | None,
) -> Asn1Certificate:
    extensions = [
        {
            "extn_id": "basic_constraints",
            "critical": True,
            "extn_value": BasicConstraints(
                {"ca": ca, "path_len_constraint": None}
            ),
        },
        {
            "extn_id": "key_usage",
            "critical": True,
            "extn_value": KeyUsage(set(key_usage)),
        },
    ]
    if extended_key_usages is not None:
        extensions.append(
            {
                "extn_id": "extended_key_usage",
                "critical": False,
                "extn_value": ExtKeyUsageSyntax(extended_key_usages),
            }
        )

    tbs = TbsCertificate(
        {
            "version": "v3",
            "serial_number": serial_number,
            "signature": {"algorithm": _SHA256_RSA},
            "issuer": issuer_name,
            "subject": subject_name,
            "validity": Validity(
                {"not_before": _time(not_before), "not_after": _time(WINDOW_END)}
            ),
            "subject_public_key_info": subject_public_key,
            "extensions": extensions,
        }
    )
    signature = asymmetric.rsa_pkcs1v15_sign(issuer_key, tbs.dump(), "sha256")
    return Asn1Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": {"algorithm": _SHA256_RSA},
            "signature_value": signature,
        }
    )


@dataclass
class TestPKI:
    """A three-level PKI: root -> intermediate -> code-signing leaf."""

    root: GeneratedCertificate
    intermediate: GeneratedCertificate
    leaf: GeneratedCertificate
    leaf_early: GeneratedCertificate


def build_pki() -> TestPKI:
    root_key_asn1 = generate_rsa_private_key()
    root_key = asymmetric.load_private_key(root_key_asn1.dump())
    root_name = Name.build({"common_name": "Signify CTL Test Root"})
    root_asn1 = _build_certificate(
        subject_name=root_name,
        subject_public_key=_public_key_info(root_key_asn1),
        issuer_name=root_name,
        issuer_key=root_key,
        serial_number=1,
        not_before=WINDOW_START,
        ca=True,
        key_usage={"key_cert_sign", "crl_sign"},
        extended_key_usages=None,
    )
    root = GeneratedCertificate(Certificate(root_asn1), root_key)

    intermediate_key_asn1 = generate_rsa_private_key()
    intermediate_key = asymmetric.load_private_key(intermediate_key_asn1.dump())
    intermediate_name = Name.build({"common_name": "Signify CTL Test Intermediate"})
    intermediate_asn1 = _build_certificate(
        subject_name=intermediate_name,
        subject_public_key=_public_key_info(intermediate_key_asn1),
        issuer_name=root_name,
        issuer_key=root_key,
        serial_number=2,
        not_before=WINDOW_START,
        ca=True,
        key_usage={"key_cert_sign", "crl_sign", "digital_signature"},
        extended_key_usages=None,
    )
    intermediate = GeneratedCertificate(
        Certificate(intermediate_asn1), intermediate_key
    )

    # A single leaf key backs two certificates that differ in issuance time and EKU.
    leaf_key_asn1 = generate_rsa_private_key()
    leaf_key = asymmetric.load_private_key(leaf_key_asn1.dump())
    leaf_public = _public_key_info(leaf_key_asn1)

    leaf_early_asn1 = _build_certificate(
        subject_name=Name.build({"common_name": "Signify Test Code Signer 2020"}),
        subject_public_key=leaf_public,
        issuer_name=intermediate_name,
        issuer_key=intermediate_key,
        serial_number=3,
        not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        ca=False,
        key_usage={"digital_signature"},
        extended_key_usages=["code_signing"],
    )
    leaf_asn1 = _build_certificate(
        subject_name=Name.build({"common_name": "Signify Test Code Signer 2022"}),
        subject_public_key=leaf_public,
        issuer_name=intermediate_name,
        issuer_key=intermediate_key,
        serial_number=4,
        not_before=datetime.datetime(2022, 1, 1, tzinfo=datetime.timezone.utc),
        ca=False,
        key_usage={"digital_signature"},
        extended_key_usages=["code_signing"],
    )
    return TestPKI(
        root=root,
        intermediate=intermediate,
        leaf=GeneratedCertificate(Certificate(leaf_asn1), leaf_key),
        leaf_early=GeneratedCertificate(Certificate(leaf_early_asn1), leaf_key),
    )


# --------------------------------------------------------------------------------------
# CTL construction
# --------------------------------------------------------------------------------------
@dataclass
class CTLConstraints:
    """The six trust-constraint fields of a single CTL subject.

    ``None`` means the attribute is absent; an empty list means the attribute is present
    but contains no EKUs. The distinction matters for the trust logic.
    """

    extended_key_usages: list[str] | None = None
    disallowed_filetime: datetime.datetime | None = None
    disallowed_extended_key_usages: list[str] | None = None
    not_before_filetime: datetime.datetime | None = None
    not_before_extended_key_usages: list[str] | None = None
    friendly_name: str = "Signify CTL Test Root"


def _ctl_attribute(type_name: str, set_inner_der: bytes) -> bytes:
    oid_value = next(
        oid for oid, name in SubjectAttributeType._map.items() if name == type_name
    )
    oid = ObjectIdentifier(oid_value).dump()
    return tlv(0x30, oid + tlv(0x31, set_inner_der))


def _eku_attribute(type_name: str, ekus: list[str]) -> bytes:
    # Real CTLs store OCTET STRING(ExtKeyUsageSyntax DER) inside the attribute SET.
    return _ctl_attribute(type_name, tlv(0x04, ExtKeyUsageSyntax(ekus).dump()))


def _filetime_attribute(type_name: str, moment: datetime.datetime) -> bytes:
    return _ctl_attribute(type_name, _filetime(moment).dump())


def _build_trusted_subject(
    root_identifier: bytes, constraints: CTLConstraints
) -> TrustedSubject:
    attributes: list[bytes] = [
        _ctl_attribute(
            "microsoft_ctl_friendly_name",
            CTLString(value=constraints.friendly_name).dump(),
        )
    ]
    if constraints.extended_key_usages is not None:
        attributes.append(
            _eku_attribute(
                "microsoft_ctl_enhkey_usage", constraints.extended_key_usages
            )
        )
    if constraints.disallowed_filetime is not None:
        attributes.append(
            _filetime_attribute(
                "microsoft_ctl_disallowed_filetime", constraints.disallowed_filetime
            )
        )
    if constraints.disallowed_extended_key_usages is not None:
        attributes.append(
            _eku_attribute(
                "microsoft_ctl_disallowed_enhkey_usage",
                constraints.disallowed_extended_key_usages,
            )
        )
    if constraints.not_before_filetime is not None:
        attributes.append(
            _filetime_attribute(
                "microsoft_ctl_not_before_filetime", constraints.not_before_filetime
            )
        )
    if constraints.not_before_extended_key_usages is not None:
        attributes.append(
            _eku_attribute(
                "microsoft_ctl_not_before_enhkey_usage",
                constraints.not_before_extended_key_usages,
            )
        )

    body = tlv(0x04, root_identifier) + tlv(0x31, b"".join(attributes))
    return TrustedSubject.load(tlv(0x30, body))


def _sign_content(
    *,
    content_oid: str,
    content_object,
    signer: GeneratedCertificate,
    digest_name: str = "sha256",
    extra_signed_attributes: list[cms.CMSAttribute] | None = None,
    additional_certificates: list[Certificate] | None = None,
) -> cms.ContentInfo:
    encapsulated = cms.ContentInfo(
        {
            "content_type": content_oid,
            "content": content_object,
        }
    )
    # The message digest covers the contents of the encapsulated structure (the raw
    # SEQUENCE body, without the explicit [0] outer tagging asn1crypto adds on dump).
    # SignedData.get_content_digest() hashes exactly ``content_asn1.contents`` during
    # verification, so the two must be byte-identical.
    digest = hashlib.new(digest_name, content_object.contents).digest()
    signed_attributes = cms.CMSAttributes(
        [
            cms.CMSAttribute(
                {"type": "content_type", "values": [content_oid]}
            ),
            cms.CMSAttribute(
                {"type": "message_digest", "values": [digest]}
            ),
            *(extra_signed_attributes or []),
        ]
    )
    signature = asymmetric.rsa_pkcs1v15_sign(
        signer.private_key, signed_attributes.dump(), digest_name
    )
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": {
                        # Per RFC 5652 the IssuerAndSerialNumber identifies the signer's
                        # own certificate: the issuing CA's name plus this serial.
                        "issuer": signer.certificate.asn1.issuer,
                        "serial_number": signer.certificate.serial_number,
                    }
                }
            ),
            "digest_algorithm": {"algorithm": digest_name},
            "signed_attrs": signed_attributes,
            "signature_algorithm": {"algorithm": _SHA256_RSA},
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [DigestAlgorithm({"algorithm": digest_name})],
            "encap_content_info": encapsulated,
            "certificates": [
                signer.certificate.asn1,
                *[cert.asn1 for cert in (additional_certificates or [])],
            ],
            "signer_infos": [signer_info],
        }
    )
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data})


def build_ctl(
    pki: TestPKI, constraints: CTLConstraints | list[CTLConstraints]
) -> bytes:
    """Build a DER-encoded, signed CTL rooted at ``pki.root``.

    The CTL is signed by the root itself (acting as the root-list signer), which is
    sufficient for the cryptographic self-verification the tests rely on.
    """
    if isinstance(constraints, CTLConstraints):
        constraints = [constraints]

    root_identifier = bytes.fromhex(pki.root.certificate.sha1_fingerprint)
    subjects = TrustedSubjects(
        [_build_trusted_subject(root_identifier, c) for c in constraints]
    )
    content = Asn1CertificateTrustList(
        {
            "subject_usage": SubjectUsage(["microsoft_root_list_signer"]),
            "sequence_number": 1,
            "ctl_this_update": _time(WINDOW_START),
            "subject_algorithm": {"algorithm": "sha1"},
            "trusted_subjects": subjects,
        }
    )
    envelope = _sign_content(
        content_oid=OID_CTL_CONTENT,
        content_object=content,
        signer=pki.root,
    )
    return envelope.dump()


# --------------------------------------------------------------------------------------
# Authenticode signature construction
# --------------------------------------------------------------------------------------
def _spc_indirect_data(content_digest: bytes, digest_name: str = "sha256"):
    from signify.asn1.spc import SpcAttributeTypeAndOptionalValue, SpcPeImageData
    from asn1crypto.algos import DigestInfo

    data = SpcAttributeTypeAndOptionalValue(
        {
            "type": OID_SPC_PE_IMAGE_DATA,
            "value": SpcPeImageData(
                {"file": {"file": {"unicode": "test-signed.bin"}}}
            ),
        }
    )
    from signify.asn1.spc import SpcIndirectDataContent

    return SpcIndirectDataContent(
        {
            "data": data,
            "message_digest": DigestInfo(
                {
                    "digest_algorithm": {"algorithm": digest_name},
                    "digest": content_digest,
                }
            ),
        }
    )


def build_authenticode_signature(
    pki: TestPKI, file_content: bytes, *, early: bool = False
) -> bytes:
    """Sign ``file_content`` with the code-signing leaf, returning a PKCS#7 blob.

    The blob is a regular Authenticode ``SpcIndirectDataContent`` SignedData, including
    the SPC statement type and SPC opus info authenticated attributes.
    """
    signer = pki.leaf_early if early else pki.leaf
    digest = hashlib.sha256(file_content).digest()
    indirect_data = _spc_indirect_data(digest)

    statement = cms.CMSAttribute(
        {
            "type": OID_SPC_STATEMENT_TYPE,
            "values": [[OID_SPC_COMMERCIAL]],
        }
    )
    opus = cms.CMSAttribute(
        {
            "type": OID_SPC_SP_OPUS_INFO,
            "values": [
                {
                    "program_name": {"unicode": "Signify CTL Test Program"},
                }
            ],
        }
    )
    envelope = _sign_content(
        content_oid=OID_SPC_INDIRECT_DATA,
        content_object=indirect_data,
        signer=signer,
        extra_signed_attributes=[statement, opus],
        additional_certificates=[pki.intermediate.certificate],
    )
    return envelope.dump()
