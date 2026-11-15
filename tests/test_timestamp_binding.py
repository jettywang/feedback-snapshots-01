"""Layer-by-layer tests for timestamp binding to Authenticode signatures.

The signing material in ``tests/test_data/timestamp_binding`` is generated locally
(RSA keys only), so these tests do not depend on network access or on the Microsoft
trust store. Two signatures are built from the same key and certificate: each one is
valid on its own, but their timestamp tokens prove different signature bytes.
"""

import datetime
import hashlib

import pytest
from asn1crypto import cms, core, tsp, x509
from oscrypto import asymmetric

import signify.asn1  # noqa: F401 - registers the Microsoft OIDs with asn1crypto
from signify.asn1 import spc
from signify.authenticode.signed_data import AuthenticodeSignature
from signify.x509 import Certificate, CertificateStore, VerificationContext
from tests._utils import data_path

UTC = datetime.timezone.utc

FIXTURES = data_path("timestamp_binding")


def _load_key(name):
    return asymmetric.load_private_key((FIXTURES / name).read_bytes())


def _time(value):
    return x509.Time(
        {"utc_time" if value.year < 2050 else "generalized_time": value.astimezone(UTC)}
    )


def _build_certificate(
    subject,
    issuer,
    public_key,
    signing_key,
    *,
    serial,
    not_before,
    not_after,
    ca=False,
    eku=None,
):
    extensions = [
        x509.Extension(
            {
                "extn_id": "basic_constraints",
                "critical": True,
                "extn_value": x509.BasicConstraints({"ca": ca}),
            }
        )
    ]
    if eku:
        extensions.append(
            x509.Extension(
                {
                    "extn_id": "extended_key_usage",
                    "critical": False,
                    "extn_value": x509.ExtKeyUsageSyntax(eku),
                }
            )
        )
    if not ca:
        extensions.append(
            x509.Extension(
                {
                    "extn_id": "key_usage",
                    "critical": True,
                    "extn_value": x509.KeyUsage({"digital_signature"}),
                }
            )
        )
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": serial,
            "signature": {"algorithm": "sha256_rsa"},
            "issuer": issuer,
            "validity": {
                "not_before": _time(not_before),
                "not_after": _time(not_after),
            },
            "subject": subject,
            "subject_public_key_info": public_key,
            "extensions": extensions,
        }
    )
    signature = asymmetric.rsa_pkcs1v15_sign(signing_key, tbs.dump(), "sha256")
    return x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature_value": signature,
        }
    )


class _PKI:
    def __init__(self):
        root_key = _load_key("root.pem")
        signer_key = _load_key("signer.pem")
        tsa_key = _load_key("tsa.pem")

        root_name = x509.Name.build({"common_name": "Local Root"})
        self.root = _build_certificate(
            root_name,
            root_name,
            root_key.public_key.asn1,
            root_key,
            serial=1,
            not_before=datetime.datetime(2010, 1, 1, tzinfo=UTC),
            not_after=datetime.datetime(2040, 1, 1, tzinfo=UTC),
            ca=True,
        )
        self.signer = _build_certificate(
            x509.Name.build({"common_name": "Local Signer"}),
            root_name,
            signer_key.public_key.asn1,
            root_key,
            serial=2,
            not_before=datetime.datetime(2015, 1, 1, tzinfo=UTC),
            not_after=datetime.datetime(2017, 1, 1, tzinfo=UTC),
            eku=["code_signing"],
        )
        self.tsa = _build_certificate(
            x509.Name.build({"common_name": "Local TSA"}),
            root_name,
            tsa_key.public_key.asn1,
            root_key,
            serial=3,
            not_before=datetime.datetime(2015, 1, 1, tzinfo=UTC),
            not_after=datetime.datetime(2020, 1, 1, tzinfo=UTC),
            eku=["time_stamping"],
        )
        self.not_a_tsa = _build_certificate(
            x509.Name.build({"common_name": "Not A TSA"}),
            root_name,
            tsa_key.public_key.asn1,
            root_key,
            serial=4,
            not_before=datetime.datetime(2015, 1, 1, tzinfo=UTC),
            not_after=datetime.datetime(2020, 1, 1, tzinfo=UTC),
            eku=["code_signing"],
        )
        self.signer_key = signer_key
        self.tsa_key = tsa_key
        self.store = CertificateStore(
            [Certificate.from_der(self.root.dump())], trusted=True
        )

    def signature(self, content: bytes, *extra_certificates) -> AuthenticodeSignature:
        indirect_data = spc.SpcIndirectDataContent(
            {
                "data": {
                    "type": "microsoft_spc_pe_image_data",
                    "value": spc.SpcPeImageData(
                        {
                            "file": spc.SpcLink(
                                {"file": spc.SpcString({"ascii": "local.bin"})}
                            )
                        }
                    ),
                },
                "message_digest": {
                    "digest_algorithm": {"algorithm": "sha256"},
                    "digest": hashlib.sha256(content).digest(),
                },
            }
        )
        attrs = cms.CMSAttributes(
            [
                cms.CMSAttribute(
                    {
                        "type": "content_type",
                        "values": ["microsoft_spc_indirect_data_content"],
                    }
                ),
                cms.CMSAttribute(
                    {
                        "type": "message_digest",
                        "values": [hashlib.sha256(indirect_data.contents).digest()],
                    }
                ),
            ]
        )
        signer_info = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": {
                            "issuer": self.signer.issuer,
                            "serial_number": self.signer.serial_number,
                        }
                    }
                ),
                "digest_algorithm": {"algorithm": "sha256"},
                "signed_attrs": attrs,
                "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                "signature": asymmetric.rsa_pkcs1v15_sign(
                    self.signer_key,
                    type(attrs)(contents=attrs.contents).dump(),
                    "sha256",
                ),
            }
        )
        signed_data = cms.SignedData(
            {
                "version": "v1",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {
                    "content_type": "microsoft_spc_indirect_data_content",
                    "content": indirect_data,
                },
                "certificates": [
                    x509.Certificate.load(c.dump())
                    for c in (self.signer, *extra_certificates)
                ],
                "signer_infos": [signer_info],
            }
        )
        return AuthenticodeSignature.from_envelope(
            cms.ContentInfo(
                {"content_type": "signed_data", "content": signed_data}
            ).dump()
        )

    def token(
        self,
        signature_bytes,
        *,
        certificate,
        key,
        gen_time,
        imprint="sha256",
        digest="sha256",
    ):
        tst_info = tsp.TSTInfo(
            {
                "version": "v1",
                "policy": "1.3.6.1.4.1.99999.1",
                "message_imprint": {
                    "hash_algorithm": {"algorithm": imprint},
                    "hashed_message": getattr(hashlib, imprint)(
                        signature_bytes
                    ).digest(),
                },
                "serial_number": 1,
                "gen_time": gen_time.astimezone(UTC),
                "tsa": {"directory_name": certificate.subject},
            }
        )
        attrs = cms.CMSAttributes(
            [
                cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
                cms.CMSAttribute(
                    {
                        "type": "message_digest",
                        "values": [getattr(hashlib, digest)(tst_info.dump()).digest()],
                    }
                ),
            ]
        )
        signer_info = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": {
                            "issuer": certificate.issuer,
                            "serial_number": certificate.serial_number,
                        }
                    }
                ),
                "digest_algorithm": {"algorithm": digest},
                "signed_attrs": attrs,
                "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                "signature": asymmetric.rsa_pkcs1v15_sign(
                    key, type(attrs)(contents=attrs.contents).dump(), digest
                ),
            }
        )
        signed_data = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [{"algorithm": digest}],
                "encap_content_info": {"content_type": "tst_info", "content": tst_info},
                "certificates": [x509.Certificate.load(certificate.dump())],
                "signer_infos": [signer_info],
            }
        )
        return cms.ContentInfo(
            {"content_type": "signed_data", "content": signed_data}
        )

    def countersignature(
        self,
        signature_bytes,
        *,
        certificate,
        key,
        signing_time,
        digest="sha256",
    ):
        """Build a legacy PKCS#7 countersignature (unauthenticated attribute)."""
        attrs = cms.CMSAttributes(
            [
                cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
                cms.CMSAttribute(
                    {
                        "type": "message_digest",
                        "values": [getattr(hashlib, digest)(signature_bytes).digest()],
                    }
                ),
                cms.CMSAttribute(
                    {
                        "type": "signing_time",
                        "values": [
                            cms.Time(
                                {"utc_time": signing_time.astimezone(UTC)}
                            )
                        ],
                    }
                ),
            ]
        )
        return cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": {
                            "issuer": certificate.issuer,
                            "serial_number": certificate.serial_number,
                        }
                    }
                ),
                "digest_algorithm": {"algorithm": digest},
                "signed_attrs": attrs,
                "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                "signature": asymmetric.rsa_pkcs1v15_sign(
                    key, type(attrs)(contents=attrs.contents).dump(), digest
                ),
            }
        )

    def resign(self, signature):
        """Recompute the outer signature over its (possibly modified) attributes."""
        signer_info = signature.asn1["signer_infos"][0]
        signer_info["signature"] = asymmetric.rsa_pkcs1v15_sign(
            self.signer_key,
            type(signer_info["signed_attrs"])(
                contents=signer_info["signed_attrs"].contents
            ).dump(),
            "sha256",
        )
        return AuthenticodeSignature.from_envelope(
            cms.ContentInfo(
                {"content_type": "signed_data", "content": signature.asn1}
            ).dump()
        )

    def attach(self, signature, attribute, values):
        signature.asn1["signer_infos"][0]["unsigned_attrs"] = cms.CMSAttributes(
            [cms.CMSAttribute({"type": attribute, "values": values})]
        )
        return AuthenticodeSignature.from_envelope(
            cms.ContentInfo(
                {"content_type": "signed_data", "content": signature.asn1}
            ).dump()
        )

    def verify(self, signature, content: bytes, *, timestamp, mode="strict"):
        context = VerificationContext(
            self.store,
            signature.certificates,
            extended_key_usages=["code_signing"],
            key_usages=["digital_signature"],
            optional_ku=True,
        )
        context.timestamp = timestamp
        return list(
            signature.verify(
                verification_context=context,
                trusted_certificate_store=self.store,
                expected_hash=hashlib.sha256(content).digest(),
                countersignature_mode=mode,
            )
        )


@pytest.fixture(scope="module")
def pki():
    return _PKI()


def _timestamped(pki, content, gen_time):
    signature = pki.signature(content)
    token = pki.token(
        signature.signer_info.encrypted_digest,
        certificate=pki.tsa,
        key=pki.tsa_key,
        gen_time=gen_time,
    )
    return pki.attach(signature, "microsoft_time_stamp_token", [token])


def test_timestamp_extends_expired_signer(pki):
    signature = _timestamped(pki, b"alpha", datetime.datetime(2016, 6, 1, tzinfo=UTC))

    assert signature.signer_info.countersigner is not None
    assert signature.signer_info.countersigner.signing_time == datetime.datetime(
        2016, 6, 1, tzinfo=UTC
    )
    # The signer certificate expired in 2017; the bound timestamp keeps this valid.
    chains = pki.verify(
        signature, b"alpha", timestamp=datetime.datetime(2025, 1, 1, tzinfo=UTC)
    )
    assert len(chains) == 1


def test_timestamp_from_other_signature_is_rejected(pki):
    source = pki.signature(b"beta")
    source_token = pki.token(
        source.signer_info.encrypted_digest,
        certificate=pki.tsa,
        key=pki.tsa_key,
        gen_time=datetime.datetime(2019, 6, 1, tzinfo=UTC),
    )
    target = pki.signature(b"alpha")
    swapped = pki.attach(
        target,
        "microsoft_time_stamp_token",
        [source_token],
    )

    # The swapped token is itself genuinely signed by the TSA and proves the
    # signature bytes of ``source`` ...
    token = swapped.signer_info.countersigner
    assert token.check_message_digest(source.signer_info.encrypted_digest)
    assert not token.check_message_digest(target.signer_info.encrypted_digest)

    with pytest.raises(Exception, match="encryptedDigest"):
        pki.verify(
            swapped, b"alpha", timestamp=datetime.datetime(2025, 1, 1, tzinfo=UTC)
        )


def test_timestamp_certificate_must_be_allowed_to_time_stamp(pki):
    signature = pki.signature(b"alpha")
    token = pki.token(
        signature.signer_info.encrypted_digest,
        certificate=pki.not_a_tsa,
        key=pki.tsa_key,
        gen_time=datetime.datetime(2016, 6, 1, tzinfo=UTC),
    )
    bound = pki.attach(signature, "microsoft_time_stamp_token", [token])
    assert bound.signer_info.countersigner.check_message_digest(
        bound.signer_info.encrypted_digest
    )

    with pytest.raises(Exception, match="time stamping"):
        pki.verify(bound, b"alpha", timestamp=datetime.datetime(2016, 7, 1, tzinfo=UTC))


def test_timestamp_verification_does_not_leak_into_next_signature(pki):
    timestamped = _timestamped(pki, b"alpha", datetime.datetime(2016, 6, 1, tzinfo=UTC))
    untimestamped = pki.signature(b"beta")

    context = VerificationContext(
        pki.store,
        timestamped.certificates,
        extended_key_usages=["code_signing"],
        key_usages=["digital_signature"],
        optional_ku=True,
    )
    # The current time is after the signer certificate expired.
    context.timestamp = datetime.datetime(2025, 1, 1, tzinfo=UTC)
    timestamped.verify(
        verification_context=context,
        trusted_certificate_store=pki.store,
        expected_hash=hashlib.sha256(b"alpha").digest(),
    )
    # Verification must not have changed the timestamp of the shared context.
    assert context.timestamp == datetime.datetime(2025, 1, 1, tzinfo=UTC)

    with pytest.raises(Exception, match="expired"):
        untimestamped.verify(
            verification_context=context,
            trusted_certificate_store=pki.store,
            expected_hash=hashlib.sha256(b"beta").digest(),
        )


def test_forged_tst_info_is_rejected(pki):
    signature = _timestamped(pki, b"alpha", datetime.datetime(2016, 6, 1, tzinfo=UTC))
    token = signature.asn1["signer_infos"][0]["unsigned_attrs"][0]["values"][0]
    tst_info = token["content"]["encap_content_info"]["content"]
    parsed = tsp.TSTInfo.load(tst_info.parsed.dump())
    parsed["gen_time"] = core.GeneralizedTime("20300101000000Z")
    tst_info = core.ParsableOctetString(parsed.dump())
    token["content"]["encap_content_info"]["content"] = tst_info

    forged = AuthenticodeSignature.from_envelope(
        cms.ContentInfo(
            {"content_type": "signed_data", "content": signature.asn1}
        ).dump()
    )
    assert forged.signer_info.countersigner.signing_time == datetime.datetime(
        2030, 1, 1, tzinfo=UTC
    )

    with pytest.raises(Exception):
        pki.verify(
            forged, b"alpha", timestamp=datetime.datetime(2025, 1, 1, tzinfo=UTC)
        )


def test_independent_signatures_are_valid_without_timestamps(pki):
    for content in (b"alpha", b"beta"):
        signature = pki.signature(content)
        assert signature.signer_info.countersigner is None
        with pytest.raises(Exception, match="expired"):
            pki.verify(
                signature,
                content,
                timestamp=datetime.datetime(2025, 1, 1, tzinfo=UTC),
            )


def test_permit_mode_does_not_use_unusable_timestamp(pki):
    """A bound timestamp whose TSA may not time-stamp must not extend validity.

    In ``permit`` mode countersignature errors are ignored, but the timestamp must
    not be applied to the outer signature either: the timestamp was never accepted.
    The outer signature is then checked at the caller's time, so it has expired.
    """
    signature = pki.signature(b"alpha")
    token = pki.token(
        signature.signer_info.encrypted_digest,
        certificate=pki.not_a_tsa,
        key=pki.tsa_key,
        gen_time=datetime.datetime(2016, 6, 1, tzinfo=UTC),
    )
    bound = pki.attach(signature, "microsoft_time_stamp_token", [token])
    assert bound.signer_info.countersigner.check_message_digest(
        bound.signer_info.encrypted_digest
    )

    with pytest.raises(Exception, match="expired"):
        pki.verify(
            bound,
            b"alpha",
            timestamp=datetime.datetime(2025, 1, 1, tzinfo=UTC),
            mode="permit",
        )


def test_permit_mode_shared_context_is_not_contaminated(pki):
    """A rejected timestamp must not set the outer signature's verification time.

    When the same context object is used for both the signature and its
    countersignature, setting the timestamp while checking the countersignature
    would otherwise leave it behind, and the outer (expired) signature would still
    validate in ``permit`` mode.
    """
    signature = pki.signature(b"alpha")
    token = pki.token(
        signature.signer_info.encrypted_digest,
        certificate=pki.not_a_tsa,
        key=pki.tsa_key,
        gen_time=datetime.datetime(2016, 6, 1, tzinfo=UTC),
    )
    bound = pki.attach(signature, "microsoft_time_stamp_token", [token])

    context = VerificationContext(
        pki.store,
        bound.certificates,
        extended_key_usages=["code_signing"],
        key_usages=["digital_signature"],
        optional_ku=True,
    )
    context.timestamp = datetime.datetime(2025, 1, 1, tzinfo=UTC)

    with pytest.raises(Exception, match="expired"):
        bound.verify(
            verification_context=context,
            cs_verification_context=context,
            trusted_certificate_store=pki.store,
            expected_hash=hashlib.sha256(b"alpha").digest(),
            countersignature_mode="permit",
        )
    assert context.timestamp == datetime.datetime(2025, 1, 1, tzinfo=UTC)


def test_legacy_countersignature_extends_expired_signer(pki):
    signature = pki.signature(b"alpha", pki.tsa)
    countersignature = pki.countersignature(
        signature.signer_info.encrypted_digest,
        certificate=pki.tsa,
        key=pki.tsa_key,
        signing_time=datetime.datetime(2016, 6, 1, tzinfo=UTC),
    )
    bound = pki.attach(signature, "counter_signature", [countersignature])

    assert bound.signer_info.countersigner is not None
    assert bound.signer_info.countersigner.check_message_digest(
        bound.signer_info.encrypted_digest
    )
    assert len(
        pki.verify(
            bound, b"alpha", timestamp=datetime.datetime(2025, 1, 1, tzinfo=UTC)
        )
    ) == 1


def test_legacy_countersignature_from_other_signature_is_rejected(pki):
    target = pki.signature(b"alpha", pki.tsa)
    source = pki.signature(b"beta", pki.tsa)
    countersignature = pki.countersignature(
        source.signer_info.encrypted_digest,
        certificate=pki.tsa,
        key=pki.tsa_key,
        signing_time=datetime.datetime(2019, 6, 1, tzinfo=UTC),
    )
    swapped = pki.attach(target, "counter_signature", [countersignature])

    assert swapped.signer_info.countersigner.check_message_digest(
        source.signer_info.encrypted_digest
    )
    with pytest.raises(Exception, match="encryptedDigest"):
        pki.verify(
            swapped, b"alpha", timestamp=datetime.datetime(2025, 1, 1, tzinfo=UTC)
        )


def test_resigned_outer_with_original_timestamp_is_rejected(pki):
    """Replace the signed content, re-sign the outer structure, and keep the token.

    The timestamp token is genuine and verifies on its own, but it proves the
    original signature bytes. Correctly re-signing the outer structure must not make
    that timestamp apply to the new signature bytes.
    """
    original = pki.signature(b"alpha")
    staled_digest = original.signer_info.encrypted_digest
    token = pki.token(
        staled_digest,
        certificate=pki.tsa,
        key=pki.tsa_key,
        gen_time=datetime.datetime(2016, 6, 1, tzinfo=UTC),
    )
    replacement = pki.signature(b"beta")

    # Replace the signed attributes with those of another valid signature and
    # correctly re-sign the outer structure with the original signer key.
    original.asn1["encap_content_info"] = replacement.asn1["encap_content_info"]
    original.asn1["signer_infos"][0]["signed_attrs"] = replacement.asn1[
        "signer_infos"
    ][0]["signed_attrs"]
    resigned = pki.resign(original)
    bound = pki.attach(resigned, "microsoft_time_stamp_token", [token])

    # The timestamp token itself is valid and binds to a real signature - just not
    # to the bytes in this (correctly re-signed) structure.
    token_object = bound.signer_info.countersigner
    assert token_object.check_message_digest(staled_digest)
    assert not token_object.check_message_digest(bound.signer_info.encrypted_digest)

    # The outer signature is genuinely valid as a signature ...
    signer_certificate = bound.certificates.find_certificate(
        issuer=bound.signer_info.issuer,
        serial_number=bound.signer_info.serial_number,
    )
    bound.signer_info._verify_issuer_signature(
        signer_certificate, VerificationContext(pki.store)
    )

    # ... but the timestamp proves different bytes, so it must be rejected.
    with pytest.raises(Exception, match="encryptedDigest"):
        pki.verify(bound, b"beta", timestamp=datetime.datetime(2025, 1, 1, tzinfo=UTC))


def test_legacy_countersignature_certificate_must_be_allowed_to_time_stamp(pki):
    signature = pki.signature(b"alpha", pki.not_a_tsa)
    countersignature = pki.countersignature(
        signature.signer_info.encrypted_digest,
        certificate=pki.not_a_tsa,
        key=pki.tsa_key,
        signing_time=datetime.datetime(2016, 6, 1, tzinfo=UTC),
    )
    bound = pki.attach(signature, "counter_signature", [countersignature])
    assert bound.signer_info.countersigner.check_message_digest(
        bound.signer_info.encrypted_digest
    )

    with pytest.raises(Exception, match="time stamping"):
        pki.verify(
            bound, b"alpha", timestamp=datetime.datetime(2016, 7, 1, tzinfo=UTC)
        )
