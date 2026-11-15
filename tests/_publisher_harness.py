"""Offline generation of certificates and Authenticode-signed PE files.

This harness is fully offline: it never reads the system keychain or the network.
Key generation and RSA signing use oscrypto's pure-ctypes OpenSSL backend
(:mod:`oscrypto._openssl.asymmetric`), because the default macOS backend needs a
keychain that is unavailable in restricted environments. Verification still goes
through the regular signify code path.

It exists to demonstrate publisher constraints based on leaf SubjectPublicKeyInfo
(SPKI) pins, including certificate renewal (same key) and genuine key rotation
(different key), independent of subject display names.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import struct

from asn1crypto import cms, x509
from asn1crypto.core import Void
from oscrypto._openssl import asymmetric as oa

from signify.asn1.spc import (
    SetOfSpcSpOpusInfo,
    SetOfSpcStatementType,
    SpcIndirectDataContent,
    SpcPeImageData,
    SpcSpOpusInfo,
    SpcStatementType,
)
from signify.x509 import Certificate

# OIDs used in Authenticode signatures.
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
OID_SPC_STATEMENT_TYPE = "1.3.6.1.4.1.311.2.1.11"
OID_SPC_SP_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12"
OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

_FILE_ALIGNMENT = 0x200
_SECTION_ALIGNMENT = 0x1000
_PE32_MAGIC = 0x10B
# Index of the security entry inside the optional-header data directory.
_SECURITY_DATA_DIR_INDEX = 4


def generate_rsa_key(bit_size: int = 2048):
    """Generates an RSA (public, private) key pair using the offline OpenSSL backend."""
    return oa.generate_pair("rsa", bit_size=bit_size)


def _validity(not_before: datetime.datetime, not_after: datetime.datetime):
    return {
        "not_before": x509.Time({"general_time": not_before}),
        "not_after": x509.Time({"general_time": not_after}),
    }


def build_certificate(
    subject_cn: str,
    issuer_cn: str,
    issuer_private_key,
    subject_public_key,
    *,
    serial: int,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    is_ca: bool = False,
    code_signing: bool = True,
) -> x509.Certificate:
    """Builds and SHA-256/RSA signs an X.509 certificate offline."""
    extensions = []
    if is_ca:
        extensions.append(
            x509.Extension(
                {
                    "extn_id": "basic_constraints",
                    "critical": True,
                    "extn_value": x509.BasicConstraints(
                        {"ca": True, "path_len_constraint": None}
                    ),
                }
            )
        )
        extensions.append(
            x509.Extension(
                {
                    "extn_id": "key_usage",
                    "critical": True,
                    "extn_value": x509.KeyUsage(
                        {"key_cert_sign", "crl_sign"}
                    ),
                }
            )
        )
    elif code_signing:
        extensions.append(
            x509.Extension(
                {
                    "extn_id": "extended_key_usage",
                    "critical": False,
                    "extn_value": x509.ExtKeyUsageSyntax([OID_CODE_SIGNING]),
                }
            )
        )

    tbs_kwargs = {
        "version": "v3",
        "serial_number": serial,
        "signature": {"algorithm": "sha256_rsa"},
        "issuer": x509.Name.build({"common_name": issuer_cn}),
        "validity": _validity(not_before, not_after),
        "subject": x509.Name.build({"common_name": subject_cn}),
        "subject_public_key_info": subject_public_key.asn1,
    }
    if extensions:
        tbs_kwargs["extensions"] = x509.Extensions(extensions)

    tbs = x509.TbsCertificate(tbs_kwargs)
    signature = oa.rsa_pkcs1v15_sign(issuer_private_key, tbs.dump(), "sha256")
    return x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature_value": signature,
        }
    )


@dataclasses.dataclass
class CertificateAuthority:
    certificate: Certificate
    private_key: object

    @property
    def spki_sha256(self) -> str:
        return self.certificate.spki_sha256_fingerprint


def create_root_ca(
    common_name: str = "Test Root CA",
    *,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
) -> CertificateAuthority:
    public_key, private_key = generate_rsa_key()
    raw = build_certificate(
        common_name,
        common_name,
        private_key,
        public_key,
        serial=1,
        not_before=not_before,
        not_after=not_after,
        is_ca=True,
    )
    return CertificateAuthority(Certificate(raw), private_key)


def issue_leaf(
    ca: CertificateAuthority,
    common_name: str,
    *,
    serial: int,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    issuer_common_name: str | None = None,
    public_key=None,
    private_key=None,
):
    """Issues a code-signing leaf. Reusing ``public_key``/``private_key`` across two
    leaves models a renewal that keeps the same key; generating a fresh pair models a
    genuine key rotation."""
    if public_key is None or private_key is None:
        public_key, private_key = generate_rsa_key()
    if issuer_common_name is None:
        issuer_common_name = next(
            ca.certificate.subject.get_components("CN")
        )
    raw = build_certificate(
        common_name,
        issuer_common_name,
        ca.private_key,
        public_key,
        serial=serial,
        not_before=not_before,
        not_after=not_after,
        is_ca=False,
    )
    return Certificate(raw), private_key


def build_minimal_pe() -> bytearray:
    """Builds a minimal, structurally valid PE32 file with one section and an empty
    security data directory. The Authenticode certificate table is appended later by
    :func:`sign_pe_file`; both it and the data-directory entry that points to it are
    excluded from the Authenticode hash.
    """
    # DOS header (64 bytes) plus a short DOS stub, so e_lfanew (at 0x3C) points beyond
    # the full DOS region and is never overwritten by the PE header.
    dos_header = bytearray(0x40)
    dos_header[0:2] = b"MZ"
    dos_stub = (
        b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21"
        b"This program cannot be run in DOS mode.\r\r\n$"
    )
    # Pad the DOS region up to the conventional 0x80-byte boundary.
    dos_region = bytearray(dos_header) + bytearray(dos_stub)
    if len(dos_region) < 0x80:
        dos_region.extend(b"\x00" * (0x80 - len(dos_region)))
    pe_offset = len(dos_region)
    struct.pack_into("<I", dos_region, 0x3C, pe_offset)

    # COFF file header (20 bytes). Machine i386, one section.
    size_of_optional_header = 0xE0  # PE32 optional header incl. 16 data dirs.
    file_header = struct.pack(
        "<HHIIIHH",
        0x14C,  # IMAGE_FILE_MACHINE_I386
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        size_of_optional_header,
        0x0102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    optional_header_size = size_of_optional_header
    number_of_rva_and_sizes = 16
    opt = bytearray(optional_header_size)
    struct.pack_into("<H", opt, 0, _PE32_MAGIC)
    opt[2] = 14  # MajorLinkerVersion
    opt[3] = 0  # MinorLinkerVersion
    struct.pack_into("<I", opt, 4, 0x200)  # SizeOfCode
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint (RVA)
    struct.pack_into("<I", opt, 20, _SECTION_ALIGNMENT)  # BaseOfCode
    struct.pack_into("<I", opt, 24, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 28, _SECTION_ALIGNMENT)  # SectionAlignment
    struct.pack_into("<I", opt, 32, _FILE_ALIGNMENT)  # FileAlignment
    struct.pack_into("<H", opt, 40, 4)  # MajorOperatingSystemVersion
    struct.pack_into("<H", opt, 42, 0)  # MinorOperatingSystemVersion
    struct.pack_into("<H", opt, 44, 4)  # MajorImageVersion
    struct.pack_into("<H", opt, 46, 0)  # MinorImageVersion
    struct.pack_into("<H", opt, 48, 4)  # MajorSubsystemVersion
    struct.pack_into("<H", opt, 50, 0)  # MinorSubsystemVersion
    struct.pack_into("<I", opt, 56, 0x10000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, _FILE_ALIGNMENT)  # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)  # Subsystem: WINDOWS_CUI
    struct.pack_into("<I", opt, 72, 0x100000)  # SizeOfStackReserve
    struct.pack_into("<I", opt, 76, 0x1000)  # SizeOfStackCommit
    struct.pack_into("<I", opt, 80, 0x100000)  # SizeOfHeapReserve
    struct.pack_into("<I", opt, 84, 0x1000)  # SizeOfHeapCommit
    struct.pack_into("<I", opt, 92, number_of_rva_and_sizes)  # NumberOfRvaAndSizes
    # Data directories start at offset 96; leave them all zero for now.
    data_dir_offset = 96

    coff_start = pe_offset + 4
    opt_offset = coff_start + len(file_header)
    section_table_offset = opt_offset + optional_header_size
    # One section header table entry (40 bytes).
    section_raw_offset = _FILE_ALIGNMENT
    section_raw_size = _FILE_ALIGNMENT
    section = bytearray(40)
    section[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", section, 8, _SECTION_ALIGNMENT)  # VirtualSize
    struct.pack_into("<I", section, 12, _SECTION_ALIGNMENT)  # VirtualAddress
    struct.pack_into("<I", section, 16, section_raw_size)  # SizeOfRawData
    struct.pack_into("<I", section, 20, section_raw_offset)  # PointerToRawData

    headers_size = section_table_offset + 40 - pe_offset
    headers = bytearray(headers_size)
    # All offsets below are relative to the start of ``headers`` (i.e. absolute file
    # offset minus pe_offset).
    headers[0:4] = b"PE\x00\x00"
    headers[4 : 4 + len(file_header)] = file_header
    opt_rel = 4 + len(file_header)
    headers[opt_rel : opt_rel + len(opt)] = opt
    section_rel = section_table_offset - pe_offset
    headers[section_rel : section_rel + 40] = section

    # Pad headers up to the file alignment, then append the section's raw data.
    blob = bytearray(dos_region) + headers
    if len(blob) < section_raw_offset:
        blob.extend(b"\x00" * (section_raw_offset - len(blob)))
    blob.extend(b"\xcc" * section_raw_size)

    return blob


def _pe_security_dir_file_offset(pe: bytes) -> int:
    pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]
    opt_offset = pe_offset + 4 + 20
    data_dir_offset = opt_offset + 96
    return data_dir_offset + _SECURITY_DATA_DIR_INDEX * 8


def _spc_indirect_data(authentihash: bytes) -> SpcIndirectDataContent:
    pe_image_data = SpcPeImageData(
        {
            "flags": {"include_resources"},
            "file": {"file": {"ascii": "<<<Obsolete>>>"}},
        }
    )
    return SpcIndirectDataContent(
        {
            "data": {
                "type": "microsoft_spc_pe_image_data",
                "value": pe_image_data,
            },
            "message_digest": {
                "digest_algorithm": {"algorithm": "sha256"},
                "digest": authentihash,
            },
        }
    )


def _signed_attributes(indirect_data_der: bytes, content_digest: bytes):
    return [
        cms.CMSAttribute(
            {
                "type": OID_CONTENT_TYPE,
                "values": [cms.ContentType(OID_SPC_INDIRECT_DATA)],
            }
        ),
        cms.CMSAttribute(
            {"type": OID_MESSAGE_DIGEST, "values": [cms.OctetString(content_digest)]}
        ),
        cms.CMSAttribute(
            {
                "type": OID_SPC_STATEMENT_TYPE,
                "values": SetOfSpcStatementType(
                    [SpcStatementType([OID_SPC_INDIRECT_DATA])]
                ),
            }
        ),
        cms.CMSAttribute(
            {
                "type": OID_SPC_SP_OPUS_INFO,
                "values": SetOfSpcSpOpusInfo(
                    [SpcSpOpusInfo({"program_name": None, "more_info": None})]
                ),
            }
        ),
    ]


def build_authenticode_signature(
    leaf: Certificate, leaf_private_key, chain_certs, authentihash: bytes
) -> bytes:
    """Builds an Authenticode PKCS#7 SignedData (ContentInfo) over the given file
    hash, signed by the leaf private key offline."""
    indirect_data = _spc_indirect_data(authentihash)
    indirect_der = indirect_data.dump()
    # signify (per RFC 5652) hashes the encapsulated content's octets, i.e. the
    # SEQUENCE payload without its tag and length, not the full DER encoding.
    content_digest = hashlib.sha256(indirect_data.contents).digest()

    signed_attrs = _signed_attributes(indirect_der, content_digest)
    # Re-encode the authenticated attributes with an explicit SET tag for signing,
    # mirroring SignerInfo._encode_attributes (RFC 5652 section 5.2).
    signed_attrs_set = cms.CMSAttributes(signed_attrs)
    explicit_set = type(signed_attrs_set)(contents=signed_attrs_set.contents)
    encoded_attrs = explicit_set.dump()

    encrypted_digest = oa.rsa_pkcs1v15_sign(
        leaf_private_key, encoded_attrs, "sha256"
    )

    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": {
                        "issuer": leaf.asn1.issuer,
                        "serial_number": leaf.serial_number,
                    }
                }
            ),
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": signed_attrs,
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": encrypted_digest,
        }
    )

    certificates = [leaf.asn1] + [cert.asn1 for cert in chain_certs]
    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [cms.DigestAlgorithm({"algorithm": "sha256"})],
            "encap_content_info": {
                "content_type": OID_SPC_INDIRECT_DATA,
                "content": indirect_data,
            },
            "certificates": certificates,
            "signer_infos": [signer_info],
        }
    )
    content_info = cms.ContentInfo(
        {"content_type": "signed_data", "content": signed_data}
    )
    return content_info.dump()


def append_win_certificate(pe: bytearray, signature_der: bytes) -> tuple[int, int]:
    """Appends a WIN_CERTIFICATE entry (revision 0x200, type 2 = PKCS#7) to the PE
    certificate table and points the security data directory at the start of the
    table. Multiple calls append additional entries, modelling a file carrying several
    (e.g. dual or competing) signatures.

    Returns the (offset, size) of the appended entry.
    """
    win_cert = (
        struct.pack("<IHH", 8 + len(signature_der), 0x0200, 0x0002) + signature_der
    )

    dir_offset = _pe_security_dir_file_offset(pe)
    table_start, _table_size = struct.unpack_from("<II", pe, dir_offset)

    # Entries are 8-byte aligned; pad the file before appending.
    if len(pe) % 8:
        pe.extend(b"\x00" * (8 - len(pe) % 8))

    if table_start == 0:
        # First entry: the table starts at the current (aligned) end of the file.
        table_start = len(pe)

    entry_offset = len(pe)
    pe.extend(win_cert)

    # The data directory covers the whole contiguous table, from its first entry to
    # the current end of file.
    struct.pack_into("<II", pe, dir_offset, table_start, len(pe) - table_start)
    return entry_offset, len(win_cert)


def sign_pe_file(
    pe: bytearray, leaf: Certificate, leaf_private_key, chain_certs
) -> bytes:
    """Appends an Authenticode signature (see :func:`append_win_certificate`) for the
    given leaf over the PE's current Authenticode hash.

    The file is hashed with the certificate table and the security data-directory
    entry excluded; signify's fingerprinter excludes exactly those ranges, so every
    embedded signature remains valid after further entries are appended.
    """
    from signify.authenticode.signed_file.pe import SignedPEFingerprinter

    # Hash the PE with its (empty or already-populated) certificate table excluded.
    import io

    fingerprinter = SignedPEFingerprinter(io.BytesIO(bytes(pe)))
    fingerprinter.add_signed_pe_hashers(hashlib.sha256)
    authentihash = fingerprinter.hashes()["authentihash"]["sha256"]

    signature_der = build_authenticode_signature(
        leaf, leaf_private_key, chain_certs, authentihash
    )
    append_win_certificate(pe, signature_der)
    return authentihash


def corrupt_last_signature(pe: bytearray) -> None:
    """Corrupts the encrypted (code) signature of the most recently appended
    WIN_CERTIFICATE entry, without touching the file content or any earlier entry.

    The result is a signature whose file digest and certificate chain are fine, but
    whose SignerInfo code signature no longer validates. It therefore fails full
    verification while a separate, intact signature in the same file still verifies -
    exactly the situation needed to prove a rejected signature cannot inherit publisher
    identity from a valid neighbouring chain.
    """
    from asn1crypto import cms

    dir_offset = _pe_security_dir_file_offset(pe)
    table_start, table_size = struct.unpack_from("<II", pe, dir_offset)
    table_end = table_start + table_size

    # Walk the WIN_CERTIFICATE entries to find the last one.
    position = table_start
    last_entry_start = None
    last_entry_length = None
    while position < table_end:
        length = struct.unpack_from("<I", pe, position)[0]
        last_entry_start = position
        last_entry_length = length
        position += length + (8 - length % 8) % 8

    # The WIN_CERTIFICATE header is 8 bytes, followed by the PKCS#7 ContentInfo.
    content_info_offset = last_entry_start + 8
    content_info_end = content_info_offset + (last_entry_length - 8)
    content_info = cms.ContentInfo.load(
        bytes(pe[content_info_offset:content_info_end])
    )
    signed_data = content_info["content"]
    signer_info = signed_data["signer_infos"][0]
    signature_value = signer_info["signature"]
    raw = bytearray(signature_value.native)
    raw[0] ^= 0xFF

    # Rebuild the SignerInfo from its existing field objects, substituting only the
    # signature octet string, so no native choice types need to round-trip.
    signer_info_fields = {
        "version": signer_info["version"].native,
        "sid": signer_info["sid"],
        "digest_algorithm": signer_info["digest_algorithm"],
        "signed_attrs": signer_info["signed_attrs"],
        "signature_algorithm": signer_info["signature_algorithm"],
        "signature": cms.OctetString(bytes(raw)),
    }
    unsigned_attrs = signer_info["unsigned_attrs"]
    if not isinstance(unsigned_attrs, Void):
        signer_info_fields["unsigned_attrs"] = unsigned_attrs
    rebuilt_signer_info = cms.SignerInfo(signer_info_fields)
    signed_data["signer_infos"] = cms.SignerInfos([rebuilt_signer_info])

    rebuilt = content_info.dump()
    new_win_cert = struct.pack("<IHH", 8 + len(rebuilt), 0x0200, 0x0002) + rebuilt

    # dwLength covers only the WIN_CERTIFICATE itself; the trailing alignment padding
    # is separate. Rebuilding preserves the DER length, so dwLength is unchanged and
    # the existing padding stays valid.
    if len(new_win_cert) != last_entry_length:
        raise RuntimeError(
            "Corrupted signature changed the WIN_CERTIFICATE entry length; this is"
            " not expected for an equal-length encrypted digest."
        )
    pe[
        last_entry_start : last_entry_start + last_entry_length
    ] = new_win_cert


def build_nested_authenticode_signature(
    outer_der: bytes,
    nested_leaf: Certificate,
    nested_private_key,
    chain_certs,
) -> bytes:
    """Wraps an existing Authenticode SignedData (``outer_der``) with a nested
    signature carried in the outer SignerInfo's ``microsoft_nested_signature``
    unauthenticated attribute.

    The nested signature is a fully independent SignedData: it has its own signer,
    its own certificate chain and its own IndirectData (over the same file hash). This
    lets a test prove the nested signer is constrained on its own leaf certificate and
    can never be satisfied by the outer signature's publisher.
    """
    outer_info = cms.ContentInfo.load(outer_der)
    outer_signed_data = outer_info["content"]
    outer_signer_info = outer_signed_data["signer_infos"][0]

    # The nested SignedData covers the same file hash; only its signer differs.
    nested_content_info = cms.ContentInfo.load(
        build_authenticode_signature(
            nested_leaf, nested_private_key, chain_certs,
            _authentihash_from_content_info(outer_der),
        )
    )

    nested_attr = cms.CMSAttribute(
        {
            "type": "microsoft_nested_signature",
            "values": cms.SetOfContentInfo([nested_content_info]),
        }
    )

    unsigned = outer_signer_info["unsigned_attrs"]
    if isinstance(unsigned, Void):
        new_unsigned = cms.CMSAttributes([nested_attr])
    else:
        new_unsigned = cms.CMSAttributes([*unsigned, nested_attr])

    rebuilt_signer_info_fields = {
        "version": outer_signer_info["version"].native,
        "sid": outer_signer_info["sid"],
        "digest_algorithm": outer_signer_info["digest_algorithm"],
        "signed_attrs": outer_signer_info["signed_attrs"],
        "signature_algorithm": outer_signer_info["signature_algorithm"],
        "signature": outer_signer_info["signature"],
        "unsigned_attrs": new_unsigned,
    }
    outer_signed_data["signer_infos"] = cms.SignerInfos(
        [cms.SignerInfo(rebuilt_signer_info_fields)]
    )
    return outer_info.dump()


def _authentihash_from_content_info(content_info_der: bytes) -> bytes:
    info = cms.ContentInfo.load(content_info_der)
    indirect = info["content"]["encap_content_info"]["content"]
    return indirect["message_digest"]["digest"].native


def sign_pe_file_nested(
    pe: bytearray,
    outer_leaf: Certificate,
    outer_private_key,
    nested_leaf: Certificate,
    nested_private_key,
    chain_certs,
) -> None:
    """Appends a single WIN_CERTIFICATE entry that contains an outer signature with a
    nested signature in its unauthenticated attributes."""
    import io

    from signify.authenticode.signed_file.pe import SignedPEFingerprinter

    fingerprinter = SignedPEFingerprinter(io.BytesIO(bytes(pe)))
    fingerprinter.add_signed_pe_hashers(hashlib.sha256)
    authentihash = fingerprinter.hashes()["authentihash"]["sha256"]

    outer_der = build_authenticode_signature(
        outer_leaf, outer_private_key, chain_certs, authentihash
    )
    wrapped_der = build_nested_authenticode_signature(
        outer_der, nested_leaf, nested_private_key, chain_certs
    )
    append_win_certificate(pe, wrapped_der)
