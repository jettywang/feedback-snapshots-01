"""Build Authenticode (PKCS#7 SignedData) fixtures without Windows tooling.

The structure mirrors the real layout: WIN_CERTIFICATE payload is a
ContentInfo/signedData whose encapsulated content is SpcIndirectDataContent,
whose digest is computed over the PE image with checksum, certificate
directory entry and the certificate table excluded.
"""

from __future__ import annotations

import datetime as dt
import hashlib

from Crypto.PublicKey import RSA

from . import crypto, der, verify

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
OID_SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_RSA = "1.2.840.113549.1.1.1"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_CN = "2.5.4.3"
OID_O = "2.5.4.10"
OID_OU = "2.5.4.11"
OID_EKU = "2.5.29.37"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
OID_CERTIFICATE = "1.2.840.113549.1.9.16.2.14"


def name(*pairs: tuple[str, str]) -> bytes:
    rdns = []
    for oid_value, value in pairs:
        rdns.append(der.set_of([der.sequence(der.oid(oid_value), der.bmp_string(value))]))
    return der.sequence(*rdns)


def build_certificate(
    *,
    subject: bytes,
    issuer: bytes,
    subject_key: RSA.RsaKey,
    issuer_key: RSA.RsaKey,
    serial: int,
    not_before: dt.datetime,
    not_after: dt.datetime,
    ca: bool,
    eku: list[str] | None = None,
    path_length: int | None = None,
) -> bytes:
    signature_algorithm = der.sequence(der.oid(OID_SHA256_RSA), der.null())
    spki = der.sequence(
        der.sequence(der.oid(OID_RSA), der.null()),
        der.bit_string(
            der.sequence(
                der.integer(subject_key.n),
                der.integer(subject_key.e),
            )
        ),
    )
    extensions = []
    constraints = [der.boolean(ca)]
    if path_length is not None:
        constraints.append(der.integer(path_length))
    extensions.append(der.sequence(der.oid(OID_BASIC_CONSTRAINTS), der.boolean(ca), der.octet_string(der.sequence(*constraints))))
    if eku:
        extensions.append(der.sequence(der.oid(OID_EKU), der.octet_string(der.sequence(*(der.oid(item) for item in eku)))))
    tbs = der.sequence(
        der.explicit(0, der.integer(2)),
        der.integer(serial),
        signature_algorithm,
        issuer,
        der.sequence(der.utc_time(not_before), der.utc_time(not_after)),
        subject,
        spki,
        der.explicit(3, der.sequence(*extensions)),
    )
    digest = hashlib.sha256(tbs).digest()
    signature = crypto.pkcs1_v15_sign(issuer_key, crypto.digest_info("sha256", digest))
    return der.sequence(tbs, signature_algorithm, der.bit_string(signature))


def build_pkcs7(
    *,
    image_digest: bytes,
    leaf_cert: bytes,
    leaf_key: RSA.RsaKey,
    extra_certs: list[bytes] = (),
    signing_time: dt.datetime | None = None,
    tamper_signed_attrs: bool = False,
    tamper_encap_digest: bool = False,
) -> bytes:
    spc_pe_image = der.sequence(
        der.sequence(der.oid(OID_SPC_PE_IMAGE_DATA), der.sequence(der.bit_string(b""))),
    )
    # SpcIndirectDataContent ::= SEQUENCE { data SpcAttributeTypeAndOptionalValue, messageDigest DigestInfo }
    digest_info = der.sequence(
        der.sequence(der.oid("2.16.840.1.101.3.4.2.1"), der.null()),
        der.octet_string(bytes(image_digest if not tamper_encap_digest else bytes(len(image_digest)))),
    )
    spc = der.sequence(
        der.sequence(der.oid(OID_SPC_PE_IMAGE_DATA), spc_pe_image),
        digest_info,
    )
    encap = der.sequence(der.oid(OID_SPC_INDIRECT_DATA), der.explicit(0, spc))
    signing_time = signing_time or dt.datetime(2025, 1, 2, 3, 4, 5)
    attributes = [
        der.sequence(der.oid(OID_CONTENT_TYPE), der.set_of([der.oid(OID_SPC_INDIRECT_DATA)])),
        der.sequence(der.oid(OID_SIGNING_TIME), der.set_of([der.utc_time(signing_time)])),
        der.sequence(
            der.oid(OID_MESSAGE_DIGEST),
            der.set_of([der.octet_string(hashlib.sha256(spc).digest())]),
        ),
    ]
    attrs_der = der.set_of(attributes)
    if tamper_signed_attrs:
        attrs_der = attrs_der[:-1] + bytes([attrs_der[-1] ^ 0x01])
    digest = hashlib.sha256(attrs_der).digest()
    signature = crypto.pkcs1_v15_sign(leaf_key, crypto.digest_info("sha256", digest))
    leaf = verify.parse_certificate(leaf_cert)
    signer_info = der.sequence(
        der.integer(1),
        der.sequence(leaf["issuer_raw"], der.integer(leaf["serial"])),
        der.sequence(der.oid("2.16.840.1.101.3.4.2.1"), der.null()),
        der.tlv(0xA0, der.content_of(attrs_der)),
        der.sequence(der.oid(OID_RSA), der.null()),
        der.octet_string(signature),
    )
    certificates = der.tlv(0xA0, leaf_cert + b"".join(extra_certs))
    signed_data = der.sequence(
        der.integer(1),
        der.set_of([der.sequence(der.oid("2.16.840.1.101.3.4.2.1"), der.null())]),
        encap,
        certificates,
        der.set_of([signer_info]),
    )
    return der.sequence(der.oid(OID_SIGNED_DATA), der.explicit(0, signed_data))


def sign_authenticode(
    image: bytes,
    *,
    leaf_cert: bytes,
    leaf_key: RSA.RsaKey,
    extra_certs: list[bytes] = (),
    hash_name: str = "sha256",
    tamper_image_digest: bool = False,
    tamper_signed_attrs: bool = False,
) -> bytes:
    digest, _, _ = verify.authenticode_digest(image, hash_name)
    if tamper_image_digest:
        digest = bytes([digest[0] ^ 0xFF]) + digest[1:]
    pkcs7 = build_pkcs7(
        image_digest=digest,
        leaf_cert=leaf_cert,
        leaf_key=leaf_key,
        extra_certs=list(extra_certs),
        tamper_signed_attrs=tamper_signed_attrs,
        tamper_encap_digest=False,
    )
    from . import pe_builder

    signed, _, _ = pe_builder.attach_certificate_table(image, pkcs7)
    return signed
