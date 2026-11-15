"""Helpers to build fully-signed, in-memory catalog (``.cat``) files for tests.

The regular test-suite catalogs are signed by real (Microsoft) certificates, which
cannot be generated offline. To be able to test *catalog content* behavior - member
lookups, ambiguous members, digest/algorithm consistency and explainable failures -
this module mints a self-signed certificate and signs a freshly constructed catalog
with it.

The macOS Security-framework backend of :mod:`oscrypto` requires a keychain that is
not available in restricted environments, so the ctypes-based OpenSSL backend
(``oscrypto._openssl.asymmetric``) is used directly. It returns the same
``asn1crypto`` key objects and is a pure in-process implementation.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass

from asn1crypto import cms, x509
from asn1crypto.algos import DigestAlgorithm, SignedDigestAlgorithm
from asn1crypto.core import OctetString
from oscrypto._openssl import asymmetric

from signify.asn1 import ctl as ctl_mod
from signify.asn1 import spc
from signify.x509 import Certificate, CertificateStore

# OIDs for the two catalog member identifier algorithms.
CATALOG_V1_OID = "microsoft_catalog_list_member"
CATALOG_V2_OID = "microsoft_catalog_list_member_v2"

CATALOG_MEMBER_GUID = "{DE351A42-8E59-11D0-8C47-00C04FC295EE}"


@dataclass(frozen=True)
class CatalogMemberSpec:
    """A member to embed in a generated catalog.

    :param digest: The file digest. This is used both as the member identifier
        (UTF-16 upper-case hex for v1, raw bytes for v2) and as the digest inside the
        :class:`~signify.authenticode.IndirectData`.
    :param display_name: The informational ``File`` name stored in the member's
        ``catalog_namevalue``. It is never used for membership matching.
    :param content_type: The Authenticode content type of the indirect data.
    :param digest_oid: The digest algorithm recorded in the indirect data.
    """

    digest: bytes
    display_name: str
    content_type: str = "microsoft_spc_cab_data"
    digest_oid: str = "sha1"


def _make_certificate() -> tuple[x509.Certificate, asymmetric.PrivateKey]:
    public_key, private_key = asymmetric.generate_pair("rsa", bit_size=2048)
    name = x509.Name.build({"common_name": "Signify Test Catalog Signer"})
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": 1,
            "signature": SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
            "issuer": name,
            "validity": {
                "not_before": x509.Time(
                    name="utc_time",
                    value=x509.UTCTime(
                        datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
                    ),
                ),
                "not_after": x509.Time(
                    name="general_time",
                    value=x509.GeneralizedTime(
                        datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
                    ),
                ),
            },
            "subject": name,
            "subject_public_key_info": public_key.asn1,
        }
    )
    signature = asymmetric.rsa_pkcs1v15_sign(private_key, tbs.dump(), "sha256")
    certificate = x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
            "signature_value": signature,
        }
    )
    return certificate, private_key


class CatalogTestSigner:
    """Holds a self-signed certificate and the matching trusted store, and signs
    catalogs built with :meth:`build_catalog`.
    """

    def __init__(self) -> None:
        self.certificate, self.private_key = _make_certificate()

    @property
    def trusted_store(self) -> CertificateStore:
        return CertificateStore([Certificate(self.certificate)], trusted=True)

    def _build_indirect_data(
        self, member: CatalogMemberSpec
    ) -> spc.SpcIndirectDataContent:
        if member.content_type == "microsoft_spc_pe_image_data":
            value = spc.SpcPeImageData(
                {
                    "flags": {"include_resources"},
                    "file": spc.SpcLink({"url": " "}),
                }
            )
        else:
            value = spc.SpcLink({"url": " "})
        return spc.SpcIndirectDataContent(
            {
                "data": {"type": member.content_type, "value": value},
                "message_digest": {
                    "digest_algorithm": {"algorithm": member.digest_oid},
                    "digest": member.digest,
                },
            }
        )

    def _member_identifier(self, member: CatalogMemberSpec, version: int) -> bytes:
        if version == 1:
            return (member.digest.hex().upper() + "\0").encode("utf-16-le")
        return member.digest

    def _build_subject(
        self, member: CatalogMemberSpec, version: int
    ) -> ctl_mod.TrustedSubject:
        indirect = self._build_indirect_data(member)
        attributes = [
            ctl_mod.SubjectAttribute(
                {
                    "type": "microsoft_spc_indirect_data_content",
                    "values": spc.SetOfSpcIndirectDataContent([indirect]),
                }
            )
        ]
        name_values = ctl_mod.NameValues(
            [
                ctl_mod.NameValue(
                    {
                        "refname": "File",
                        "typeaction": 65537,
                        "value": ctl_mod.CTLString(member.display_name + "\0"),
                    }
                )
            ]
        )
        attributes.append(
            ctl_mod.SubjectAttribute(
                {"type": "microsoft_cat_namevalue", "values": name_values}
            )
        )
        member_info = ctl_mod.SetOfMemberInfo(
            [ctl_mod.MemberInfo({"subguid": CATALOG_MEMBER_GUID, "certversion": 512})]
        )
        attributes.append(
            ctl_mod.SubjectAttribute(
                {"type": "microsoft_cat_memberinfo", "values": member_info}
            )
        )
        return ctl_mod.TrustedSubject(
            {
                "subject_identifier": ctl_mod.SubjectIdentifier(
                    self._member_identifier(member, version)
                ),
                "subject_attributes": ctl_mod.SubjectAttributes(attributes),
            }
        )

    def build_catalog(
        self,
        members: list[CatalogMemberSpec],
        *,
        version: int = 1,
        signature_hash: str = "sha256",
        subject_usage: tuple[str, ...] = ("microsoft_catalog_list",),
    ) -> bytes:
        """Constructs and signs a catalog containing the provided members.

        :param members: The members to include.
        :param version: ``1`` for ``microsoft_catalog_list_member`` (SHA-1) or ``2``
            for ``microsoft_catalog_list_member_v2`` (SHA-256).
        :param signature_hash: Hash used for the PKCS#7 signature.
        :param subject_usage: Overrides the CTL subject usage. Passing a non-catalog
            usage allows building a structurally-similar regular CTL.
        """
        member_oid = CATALOG_V1_OID if version == 1 else CATALOG_V2_OID
        subjects = ctl_mod.TrustedSubjects(
            [self._build_subject(member, version) for member in members]
        )
        ctl = ctl_mod.CertificateTrustList(
            {
                "version": "v1",
                "subject_usage": ctl_mod.SubjectUsage(list(subject_usage)),
                "ctl_this_update": x509.Time(
                    name="utc_time",
                    value=x509.UTCTime(
                        datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
                    ),
                ),
                "subject_algorithm": DigestAlgorithm({"algorithm": member_oid}),
                "trusted_subjects": subjects,
            }
        )

        # The message digest is over the encapsulated content (the DER of the CTL
        # itself), excluding the explicit [0] encapsulation tag and length.
        message_digest = hashlib.new(signature_hash, ctl.contents).digest()
        signed_attrs = cms.CMSAttributes(
            [
                cms.CMSAttribute(
                    {
                        "type": "content_type",
                        "values": cms.SetOfContentType(["microsoft_ctl"]),
                    }
                ),
                cms.CMSAttribute(
                    {
                        "type": "message_digest",
                        "values": cms.SetOfOctetString([OctetString(message_digest)]),
                    }
                ),
            ]
        )
        signature = asymmetric.rsa_pkcs1v15_sign(
            self.private_key, signed_attrs.dump(), signature_hash
        )
        signer_info = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": {
                            "issuer": self.certificate.issuer,
                            "serial_number": self.certificate.serial_number,
                        }
                    }
                ),
                "digest_algorithm": DigestAlgorithm({"algorithm": signature_hash}),
                "signed_attrs": signed_attrs,
                "signature_algorithm": SignedDigestAlgorithm(
                    {"algorithm": f"{signature_hash}_rsa"}
                ),
                "signature": signature,
            }
        )
        signed_data = cms.SignedData(
            {
                "version": "v1",
                "digest_algorithms": cms.DigestAlgorithms(
                    [DigestAlgorithm({"algorithm": signature_hash})]
                ),
                "encap_content_info": cms.ContentInfo(
                    {"content_type": "microsoft_ctl", "content": ctl}
                ),
                "certificates": cms.CertificateSet(
                    [cms.CertificateChoices({"certificate": self.certificate})]
                ),
                "signer_infos": cms.SignerInfos([signer_info]),
            }
        )
        content_info = cms.ContentInfo(
            {"content_type": "signed_data", "content": signed_data}
        )
        return content_info.dump()
