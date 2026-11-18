"""Offline regression tests for how stapled OCSP responses are reported.

A stapled OCSP response carries several independent facts, and each one is tracked (and
serialized to JSON) separately so they never get collapsed into a single "pass" status:

* the response was stapled and could be parsed (``ocsp_response``);
* the response's signature chains to a trust store (``ocsp_response_is_trusted``);
* the response is about the currently deployed leaf certificate (serial number match);
* the response is fresh at verification time (``this_update``/``next_update``).

Everything here runs offline: certificates and OCSP responses are generated locally, no
external OCSP responder is ever queried, and verification happens at a pinned time so the
machine's date cannot decide the outcome.
"""

import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import nassl._nassl
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, DNSName
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPResponderEncoding,
    OCSPResponseBuilder,
    OCSPResponseStatus,
    load_der_ocsp_response,
)

from sslyze.plugins.certificate_info._cert_chain_analyzer import (
    CertificateDeploymentAnalyzer,
    CertificateDeploymentAnalysisResult,
)
from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult
from sslyze.plugins.certificate_info.json_output import CertificateInfoScanResultAsJson
from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore

# Verification is pinned to a fixed point in time; every certificate below is valid from 2020 to 2050
# so that neither the pinned time nor the machine's date can change the outcome of the scenarios
_PINNED_VERIFICATION_TIME = datetime.datetime(2026, 6, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
_VALIDITY_NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
_VALIDITY_NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)

_HOSTNAME = "sec17-ocsp-evidence.example.com"

_LEAF_SERIAL = 3000
_OTHER_CERT_SERIAL = 3001
_REISSUED_LEAF_SERIAL = 3999


def _generate_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_certificate(
    common_name: str,
    issuer_name: x509.Name,
    issuer_key: RSAPrivateKey,
    subject_key: RSAPrivateKey,
    serial_number: int,
    is_ca: bool,
    san_hostname: Optional[str] = None,
    not_valid_after: datetime.datetime = _VALIDITY_NOT_AFTER,
) -> Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(_VALIDITY_NOT_BEFORE)
        .not_valid_after(not_valid_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    )
    subject_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    if issuer_name != subject_name:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if san_hostname:
        builder = builder.add_extension(x509.SubjectAlternativeName([DNSName(san_hostname)]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _as_pem(certificate: Certificate) -> str:
    return certificate.public_bytes(Encoding.PEM).decode("ascii")


def _build_ocsp_response_der(
    cert: Certificate,
    issuer: Certificate,
    signer_certificate: Certificate,
    signer_key: RSAPrivateKey,
    this_update: datetime.datetime,
    next_update: datetime.datetime,
    certificate_status: OCSPCertStatus = OCSPCertStatus.GOOD,
    extra_certificates: Optional[List[Certificate]] = None,
) -> bytes:
    builder = (
        OCSPResponseBuilder()
        .add_response(
            cert=cert,
            issuer=issuer,
            algorithm=hashes.SHA1(),
            cert_status=certificate_status,
            this_update=this_update,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(OCSPResponderEncoding.NAME, signer_certificate)
        .certificates([signer_certificate] + (extra_certificates or []))
    )
    return builder.sign(private_key=signer_key, algorithm=hashes.SHA256()).public_bytes(Encoding.DER)


class _OfflineOcspResponse:
    """Offline stand-in for ``nassl._nassl.OCSP_RESPONSE``, which can only be obtained from a live handshake.

    It exposes the same interface the analyzer relies on (``as_der_bytes``/``basic_verify``) and performs
    real verification locally at the pinned verification time: the response signature is checked with the
    responder's public key and the responder's certificate chain is walked to an anchor in the trust store.
    Mirroring OpenSSL's ``OCSP_basic_verify`` (what nassl calls), the freshness of this_update/next_update
    is NOT checked here.
    """

    def __init__(self, der_bytes: bytes) -> None:
        self._der_bytes = der_bytes

    def as_der_bytes(self) -> bytes:
        return self._der_bytes

    def basic_verify(self, trust_store_path: str) -> None:
        response = load_der_ocsp_response(self._der_bytes)
        if response.response_status != OCSPResponseStatus.SUCCESSFUL:
            raise nassl._nassl.OpenSSLError("certificate verify error: unsuccessful OCSP response")

        responder_certificate = None
        for certificate in response.certificates:
            if response.responder_name is not None and certificate.subject == response.responder_name:
                responder_certificate = certificate
                break
        if responder_certificate is None:
            raise nassl._nassl.OpenSSLError("certificate verify error: responder certificate not included")

        try:
            responder_certificate.public_key().verify(
                response.signature,
                response.tbs_response_bytes,
                padding.PKCS1v15(),
                response.signature_hash_algorithm,
            )
        except Exception as exc:
            raise nassl._nassl.OpenSSLError(f"certificate verify error: bad response signature: {exc}")

        anchors = x509.load_pem_x509_certificates(Path(trust_store_path).read_bytes())
        anchor_fingerprints = {anchor.fingerprint(hashes.SHA256()) for anchor in anchors}
        certificates_by_subject: Dict[x509.Name, List[Certificate]] = {}
        for certificate in list(response.certificates) + anchors:
            certificates_by_subject.setdefault(certificate.subject, []).append(certificate)

        current_certificate = responder_certificate
        for _ in range(8):
            validity = current_certificate
            if not (
                validity.not_valid_before_utc <= _PINNED_VERIFICATION_TIME <= validity.not_valid_after_utc
            ):
                raise nassl._nassl.OpenSSLError(
                    "certificate verify error: certificate not valid at the verification time"
                )
            if current_certificate.fingerprint(hashes.SHA256()) in anchor_fingerprints:
                return
            for issuer_candidate in certificates_by_subject.get(current_certificate.issuer, []):
                try:
                    current_certificate.verify_directly_issued_by(issuer_candidate)
                    current_certificate = issuer_candidate
                    break
                except Exception:
                    continue
            else:
                raise nassl._nassl.OpenSSLError(
                    "certificate verify error: unable to build a chain to a trusted anchor"
                )
        raise nassl._nassl.OpenSSLError("certificate verify error: certificate chain too long")


@dataclass(frozen=True)
class _OfflinePki:
    trust_store: TrustStore
    leaf_certificate: Certificate
    issuer_certificate: Certificate
    issuer_key: RSAPrivateKey
    chain_as_pem: List[str]
    other_certificate: Certificate
    reissued_leaf_certificate: Certificate
    rogue_issuer_certificate: Certificate
    rogue_issuer_key: RSAPrivateKey
    root_certificate: Certificate


@pytest.fixture(scope="module")
def offline_pki(tmp_path_factory: pytest.TempPathFactory) -> _OfflinePki:
    # Given a fully offline PKI: a root CA, an issuing CA and a leaf certificate for _HOSTNAME
    root_key = _generate_key()
    root_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "SEC17 Evidence Root CA")])
    root_certificate = _build_certificate(
        "SEC17 Evidence Root CA", root_name, root_key, root_key, serial_number=1000, is_ca=True
    )

    issuer_key = _generate_key()
    issuer_certificate = _build_certificate(
        "SEC17 Evidence Issuing CA", root_name, root_key, issuer_key, serial_number=2000, is_ca=True
    )

    leaf_key = _generate_key()
    leaf_certificate = _build_certificate(
        "SEC17 Leaf",
        issuer_certificate.subject,
        issuer_key,
        leaf_key,
        serial_number=_LEAF_SERIAL,
        is_ca=False,
        san_hostname=_HOSTNAME,
    )

    # A different certificate from the same issuer (different subject, key and serial)
    other_certificate = _build_certificate(
        "SEC17 Other Server",
        issuer_certificate.subject,
        issuer_key,
        _generate_key(),
        serial_number=_OTHER_CERT_SERIAL,
        is_ca=False,
        san_hostname="sec17-other.example.com",
    )

    # The "same" leaf re-issued with a different serial number
    reissued_leaf_certificate = _build_certificate(
        "SEC17 Leaf",
        issuer_certificate.subject,
        issuer_key,
        leaf_key,
        serial_number=_REISSUED_LEAF_SERIAL,
        is_ca=False,
        san_hostname=_HOSTNAME,
    )

    # A rogue CA using the exact same issuer name but its own key; its anchor is not trusted
    rogue_issuer_key = _generate_key()
    rogue_issuer_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "SEC17 Evidence Issuing CA")])
    rogue_issuer_certificate = _build_certificate(
        "SEC17 Evidence Issuing CA", rogue_issuer_name, rogue_issuer_key, rogue_issuer_key,
        serial_number=2000, is_ca=True,
    )

    trust_store_path = tmp_path_factory.mktemp("ocsp-evidence") / "trust_store.pem"
    trust_store_path.write_bytes(root_certificate.public_bytes(Encoding.PEM))
    trust_store = TrustStore(trust_store_path, "SEC17 Offline Store", "1.0")

    return _OfflinePki(
        trust_store=trust_store,
        leaf_certificate=leaf_certificate,
        issuer_certificate=issuer_certificate,
        issuer_key=issuer_key,
        chain_as_pem=[_as_pem(leaf_certificate), _as_pem(issuer_certificate)],
        other_certificate=other_certificate,
        reissued_leaf_certificate=reissued_leaf_certificate,
        rogue_issuer_certificate=rogue_issuer_certificate,
        rogue_issuer_key=rogue_issuer_key,
        root_certificate=root_certificate,
    )


def _good_response_der(pki: _OfflinePki, **kwargs: Any) -> bytes:
    kwargs.setdefault("cert", pki.leaf_certificate)
    kwargs.setdefault("this_update", _PINNED_VERIFICATION_TIME - datetime.timedelta(days=1))
    kwargs.setdefault("next_update", _PINNED_VERIFICATION_TIME + datetime.timedelta(days=6))
    return _build_ocsp_response_der(
        issuer=pki.issuer_certificate,
        signer_certificate=pki.issuer_certificate,
        signer_key=pki.issuer_key,
        extra_certificates=[pki.root_certificate],
        **kwargs,
    )


def _analyze(pki: _OfflinePki, ocsp_response: Optional[_OfflineOcspResponse]) -> CertificateDeploymentAnalysisResult:
    analyzer = CertificateDeploymentAnalyzer(
        server_subject=DNSName(_HOSTNAME),
        server_certificate_chain_as_pem=pki.chain_as_pem,
        server_ocsp_response=ocsp_response,
        trust_stores_for_validation=[pki.trust_store],
        validation_time=_PINNED_VERIFICATION_TIME,
    )
    return analyzer.perform()


def _deployment_as_json(analysis_result: CertificateDeploymentAnalysisResult) -> Dict[str, Any]:
    # Serialize through the real JSON output path, including a full JSON round-trip
    scan_result = CertificateInfoScanResult(
        hostname_used_for_server_name_indication=_HOSTNAME,
        certificate_deployments=[analysis_result],
        certificate_deployment_with_sni_disabled=None,
    )
    result_as_json = CertificateInfoScanResultAsJson.model_validate(scan_result)
    reparsed_result = CertificateInfoScanResultAsJson.model_validate_json(result_as_json.model_dump_json())
    return reparsed_result.certificate_deployments[0].model_dump()


class TestStapledOcspResponseEvidence:
    def test_good_response_each_fact_holds_independently(self, offline_pki: _OfflinePki) -> None:
        # Given a server stapling a valid, fresh OCSP response for the deployed leaf
        analysis_result = _analyze(offline_pki, _OfflineOcspResponse(_good_response_der(offline_pki)))

        # When analyzing the deployment, every fact is established
        assert analysis_result.ocsp_response is not None
        assert analysis_result.ocsp_response_is_trusted is True
        assert analysis_result.ocsp_response.serial_number == _LEAF_SERIAL

        # And each fact is serialized separately in the JSON output
        deployment = _deployment_as_json(analysis_result)
        ocsp_response_as_json = deployment["ocsp_response"]
        assert ocsp_response_as_json["response_status"] == "SUCCESSFUL"
        assert ocsp_response_as_json["certificate_status"] == "GOOD"
        assert deployment["ocsp_response_is_trusted"] is True

        # The response refers to the deployed leaf certificate
        leaf_as_json = deployment["received_certificate_chain"][0]
        assert ocsp_response_as_json["serial_number"] == leaf_as_json["serial_number"] == _LEAF_SERIAL

        # And it is fresh at the pinned verification time
        assert ocsp_response_as_json["this_update"] <= _PINNED_VERIFICATION_TIME
        assert ocsp_response_as_json["next_update"] >= _PINNED_VERIFICATION_TIME

    def test_response_with_wrong_serial_is_trusted_but_does_not_match_leaf(
        self, offline_pki: _OfflinePki
    ) -> None:
        # Given a correctly signed response that is about a different serial number than the deployed leaf
        response_der = _good_response_der(offline_pki, cert=offline_pki.reissued_leaf_certificate)
        analysis_result = _analyze(offline_pki, _OfflineOcspResponse(response_der))

        # The signature is still trusted: the trust flag does not certify that the response matches the leaf
        assert analysis_result.ocsp_response_is_trusted is True

        # And the serial number mismatch is visible as a separate fact in the JSON output
        deployment = _deployment_as_json(analysis_result)
        assert deployment["ocsp_response"]["serial_number"] == _REISSUED_LEAF_SERIAL
        assert deployment["received_certificate_chain"][0]["serial_number"] == _LEAF_SERIAL
        assert deployment["ocsp_response_is_trusted"] is True

    def test_response_for_another_certificate_with_valid_signature(self, offline_pki: _OfflinePki) -> None:
        # Given a response for a completely different certificate, validly signed by the real issuer
        # Counter-example: a valid signature does not imply the response is about the deployed leaf
        response_der = _good_response_der(offline_pki, cert=offline_pki.other_certificate)
        analysis_result = _analyze(offline_pki, _OfflineOcspResponse(response_der))

        assert analysis_result.ocsp_response_is_trusted is True

        deployment = _deployment_as_json(analysis_result)
        assert deployment["ocsp_response"]["serial_number"] == _OTHER_CERT_SERIAL
        assert deployment["received_certificate_chain"][0]["serial_number"] == _LEAF_SERIAL

    def test_response_signed_by_similar_issuer_is_not_trusted(self, offline_pki: _OfflinePki) -> None:
        # Given a response signed by a rogue CA reusing the real issuer's name, with an untrusted anchor
        response_der = _build_ocsp_response_der(
            cert=offline_pki.leaf_certificate,
            issuer=offline_pki.issuer_certificate,
            signer_certificate=offline_pki.rogue_issuer_certificate,
            signer_key=offline_pki.rogue_issuer_key,
            this_update=_PINNED_VERIFICATION_TIME - datetime.timedelta(days=1),
            next_update=_PINNED_VERIFICATION_TIME + datetime.timedelta(days=6),
        )
        analysis_result = _analyze(offline_pki, _OfflineOcspResponse(response_der))

        # The response could be parsed but its signature is not trusted
        assert analysis_result.ocsp_response is not None
        assert analysis_result.ocsp_response_is_trusted is False

        deployment = _deployment_as_json(analysis_result)
        assert deployment["ocsp_response"]["response_status"] == "SUCCESSFUL"
        assert deployment["ocsp_response_is_trusted"] is False

    def test_expired_response_trust_flag_does_not_cover_freshness(self, offline_pki: _OfflinePki) -> None:
        # Given a correctly signed response whose next_update is in the past at verification time
        response_der = _good_response_der(
            offline_pki,
            this_update=_PINNED_VERIFICATION_TIME - datetime.timedelta(days=10),
            next_update=_PINNED_VERIFICATION_TIME - datetime.timedelta(days=3),
        )
        analysis_result = _analyze(offline_pki, _OfflineOcspResponse(response_der))

        # Coverage limitation: the trust flag mirrors OpenSSL's OCSP_basic_verify, which does not
        # check freshness, so an expired response is still reported as trusted
        assert analysis_result.ocsp_response_is_trusted is True

        # Freshness is only available as separate evidence in the JSON output, for consumers to check
        deployment = _deployment_as_json(analysis_result)
        ocsp_response_as_json = deployment["ocsp_response"]
        assert ocsp_response_as_json["next_update"] < _PINNED_VERIFICATION_TIME
        assert ocsp_response_as_json["this_update"] < _PINNED_VERIFICATION_TIME
        assert deployment["ocsp_response_is_trusted"] is True

    def test_unknown_certificate_status_is_reported_as_unknown(self, offline_pki: _OfflinePki) -> None:
        # Given a correctly signed response with an "unknown" certificate status
        response_der = _good_response_der(offline_pki, certificate_status=OCSPCertStatus.UNKNOWN)
        analysis_result = _analyze(offline_pki, _OfflineOcspResponse(response_der))

        # The unknown status is reported as-is, not collapsed into good/revoked
        assert analysis_result.ocsp_response_is_trusted is True

        deployment = _deployment_as_json(analysis_result)
        ocsp_response_as_json = deployment["ocsp_response"]
        assert ocsp_response_as_json["response_status"] == "SUCCESSFUL"
        assert ocsp_response_as_json["certificate_status"] == "UNKNOWN"
        assert ocsp_response_as_json["revocation_time"] is None

    def test_missing_staple_is_not_reported_as_revoked(self, offline_pki: _OfflinePki) -> None:
        # Given a server that did not staple any OCSP response
        analysis_result = _analyze(offline_pki, None)

        # Both OCSP fields are empty; the absence of a response is not evidence about revocation
        assert analysis_result.ocsp_response is None
        assert analysis_result.ocsp_response_is_trusted is None

        deployment = _deployment_as_json(analysis_result)
        assert deployment["ocsp_response"] is None
        assert deployment["ocsp_response_is_trusted"] is None
        assert "REVOKED" not in CertificateInfoScanResultAsJson.model_validate(
            CertificateInfoScanResult(
                hostname_used_for_server_name_indication=_HOSTNAME,
                certificate_deployments=[analysis_result],
                certificate_deployment_with_sni_disabled=None,
            )
        ).model_dump_json()

    def test_untrusted_chain_leaves_dependent_ocsp_check_not_completed(
        self, offline_pki: _OfflinePki, tmp_path: Path
    ) -> None:
        # Given a server whose certificate chain cannot be built with the trust store
        untrusted_root_key = _generate_key()
        untrusted_root_name = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, "SEC17 Untrusted Root CA")]
        )
        untrusted_root = _build_certificate(
            "SEC17 Untrusted Root CA", untrusted_root_name, untrusted_root_key, untrusted_root_key,
            serial_number=5000, is_ca=True,
        )
        untrusted_leaf = _build_certificate(
            "SEC17 Untrusted Leaf",
            untrusted_root.subject,
            untrusted_root_key,
            _generate_key(),
            serial_number=5001,
            is_ca=False,
            san_hostname=_HOSTNAME,
        )
        # And a stapled response that would verify against the untrusted root
        response_der = _build_ocsp_response_der(
            cert=untrusted_leaf,
            issuer=untrusted_root,
            signer_certificate=untrusted_root,
            signer_key=untrusted_root_key,
            this_update=_PINNED_VERIFICATION_TIME - datetime.timedelta(days=1),
            next_update=_PINNED_VERIFICATION_TIME + datetime.timedelta(days=6),
        )
        analyzer = CertificateDeploymentAnalyzer(
            server_subject=DNSName(_HOSTNAME),
            server_certificate_chain_as_pem=[_as_pem(untrusted_leaf), _as_pem(untrusted_root)],
            server_ocsp_response=_OfflineOcspResponse(response_der),
            trust_stores_for_validation=[offline_pki.trust_store],
            validation_time=_PINNED_VERIFICATION_TIME,
        )
        analysis_result = analyzer.perform()

        # The chain could not be verified
        assert analysis_result.verified_certificate_chain is None
        for path_validation_result in analysis_result.path_validation_results:
            assert not path_validation_result.was_validation_successful

        # The response was still parsed, but the trust check depends on a verified chain,
        # so it is left not completed (None) instead of being marked True or False
        assert analysis_result.ocsp_response is not None
        assert analysis_result.ocsp_response.serial_number == 5001
        assert analysis_result.ocsp_response_is_trusted is None
        assert analysis_result.verified_chain_has_sha1_signature is None

        deployment = _deployment_as_json(analysis_result)
        assert deployment["ocsp_response"]["serial_number"] == 5001
        assert deployment["ocsp_response_is_trusted"] is None
        assert deployment["verified_certificate_chain"] is None

    def test_verification_time_is_pinned(self, offline_pki: _OfflinePki, mocker: Any) -> None:
        # Given a leaf certificate that already expired after the pinned verification time
        expired_leaf_key = _generate_key()
        expired_leaf = _build_certificate(
            "SEC17 Short-Lived Leaf",
            offline_pki.issuer_certificate.subject,
            offline_pki.issuer_key,
            expired_leaf_key,
            serial_number=3002,
            is_ca=False,
            san_hostname=_HOSTNAME,
            not_valid_after=datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc),
        )
        assert expired_leaf.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc), (
            "This test requires the machine date to be past the leaf's expiry to be meaningful"
        )
        verify_spy = mocker.spy(TrustStore, "verify_certificate_chain")

        # When analyzing the deployment with the pinned verification time
        analyzer = CertificateDeploymentAnalyzer(
            server_subject=DNSName(_HOSTNAME),
            server_certificate_chain_as_pem=[_as_pem(expired_leaf), _as_pem(offline_pki.issuer_certificate)],
            server_ocsp_response=None,
            trust_stores_for_validation=[offline_pki.trust_store],
            validation_time=_PINNED_VERIFICATION_TIME,
        )
        analysis_result = analyzer.perform()

        # The chain validates because the pinned time is used, not the machine's date
        assert analysis_result.verified_certificate_chain is not None
        assert verify_spy.call_args.kwargs["validation_time"] == _PINNED_VERIFICATION_TIME
