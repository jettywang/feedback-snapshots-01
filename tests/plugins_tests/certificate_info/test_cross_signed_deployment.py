from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import DNSName
from cryptography.x509.oid import NameOID

from sslyze.plugins.certificate_info._cert_chain_analyzer import (
    CertificateDeploymentAnalysisResult,
    CertificateDeploymentAnalyzer,
)
from sslyze.plugins.certificate_info._cli_connector import _CertificateInfoCliConnector
from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult
from sslyze.plugins.certificate_info.json_output import CertificateInfoScanResultAsJson
from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore

_NOW = datetime.now(timezone.utc)
_DAY = timedelta(days=1)


def _private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(
    subject: str,
    issuer: str,
    public_key,
    signer: rsa.RSAPrivateKey,
    not_valid_before: datetime,
    not_valid_after: datetime,
    algorithm: hashes.HashAlgorithm,
    is_ca: bool = False,
    san: str = "",
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=not is_ca,
                content_commitment=False,
                key_encipherment=not is_ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    return builder.sign(signer, algorithm)


def _as_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(Encoding.PEM).decode("ascii")


def _write_trust_store(path: Path, name: str, root: x509.Certificate) -> TrustStore:
    path.write_text(_as_pem(root))
    return TrustStore(path=path, name=name, version="offline")


class _CrossSignedFixture:
    """A cross-signed deployment generated entirely offline.

    The server sends: Leaf -> Intermediate -> "Offline Root B" (cross-signed by Offline Root A) -> Offline Root A.
    Offline Root B is cross-signed by Offline Root A, so:
    - Ecosystem A builds Leaf -> Intermediate -> cross-signed Root B -> Root A (SHA-384 cross-certificate, sent by the
      server, longer path);
    - Ecosystem B builds Leaf -> Intermediate -> self-signed Root B (SHA-256, different validity, not sent by the
      server);
    - Ecosystem C is an unrelated root and cannot build any path.
    """

    def __init__(self, tmp_path: Path) -> None:
        root_a_key = _private_key()
        root_b_key = _private_key()
        root_c_key = _private_key()
        intermediate_key = _private_key()

        self.root_a = _certificate(
            "Offline Root A",
            "Offline Root A",
            root_a_key.public_key(),
            root_a_key,
            _NOW - 2200 * _DAY,
            _NOW + 5000 * _DAY,
            hashes.SHA256(),
            is_ca=True,
        )
        self.root_b = _certificate(
            "Offline Root B",
            "Offline Root B",
            root_b_key.public_key(),
            root_b_key,
            _NOW - 2500 * _DAY,
            _NOW + 3000 * _DAY,
            hashes.SHA256(),
            is_ca=True,
        )
        self.root_c = _certificate(
            "Offline Root C",
            "Offline Root C",
            root_c_key.public_key(),
            root_c_key,
            _NOW - 2200 * _DAY,
            _NOW + 5000 * _DAY,
            hashes.SHA256(),
            is_ca=True,
        )
        # Same subject and key as Root B, but signed by Root A: this is the cross-signature
        self.cross_signed_root_b = _certificate(
            "Offline Root B",
            "Offline Root A",
            root_b_key.public_key(),
            root_a_key,
            _NOW - 1800 * _DAY,
            _NOW + 900 * _DAY,
            hashes.SHA384(),
            is_ca=True,
        )
        self.intermediate = _certificate(
            "Offline Intermediate",
            "Offline Root B",
            intermediate_key.public_key(),
            root_b_key,
            _NOW - 1500 * _DAY,
            _NOW + 2000 * _DAY,
            hashes.SHA256(),
            is_ca=True,
        )
        self.leaf = _certificate(
            "cross.example.com",
            "Offline Intermediate",
            intermediate_key.public_key(),
            intermediate_key,
            _NOW - 400 * _DAY,
            _NOW + 1000 * _DAY,
            hashes.SHA256(),
            san="cross.example.com",
        )

        # The server sends the leaf, the intermediate, the cross-signed Root B, and Root A
        self.server_sent_chain = [
            _as_pem(self.leaf),
            _as_pem(self.intermediate),
            _as_pem(self.cross_signed_root_b),
            _as_pem(self.root_a),
        ]

        self.store_a = _write_trust_store(tmp_path / "root_a.pem", "Ecosystem A", self.root_a)
        self.store_b = _write_trust_store(tmp_path / "root_b.pem", "Ecosystem B", self.root_b)
        self.store_c = _write_trust_store(tmp_path / "root_c.pem", "Ecosystem C", self.root_c)

    def analyze(self, stores: List[TrustStore]) -> CertificateDeploymentAnalysisResult:
        return CertificateDeploymentAnalyzer(
            server_subject=DNSName("cross.example.com"),
            server_certificate_chain_as_pem=self.server_sent_chain,
            server_ocsp_response=None,
            trust_stores_for_validation=stores,
        ).perform()


@pytest.fixture
def cross_signed_deployment(tmp_path: Path) -> _CrossSignedFixture:
    return _CrossSignedFixture(tmp_path)


def _results_by_name(
    deployment: CertificateDeploymentAnalysisResult,
) -> dict:
    return {result.trust_store.name: result for result in deployment.path_validation_results}


class TestCrossSignedDeploymentReport:
    def test_each_trust_store_keeps_its_own_built_path(self, cross_signed_deployment):
        deployment = cross_signed_deployment.analyze(
            [cross_signed_deployment.store_c, cross_signed_deployment.store_b, cross_signed_deployment.store_a]
        )
        results = _results_by_name(deployment)

        # Both small trust stores build a path, but they are different paths
        assert results["Ecosystem A"].was_validation_successful
        assert results["Ecosystem B"].was_validation_successful
        assert results["Ecosystem A"].verified_certificate_chain is not None
        assert results["Ecosystem B"].verified_certificate_chain is not None

        chain_a = results["Ecosystem A"].verified_certificate_chain
        chain_b = results["Ecosystem B"].verified_certificate_chain
        assert chain_a is not None and chain_b is not None
        assert chain_a[-1].subject == _name("Offline Root A")
        assert chain_b[-1].subject == _name("Offline Root B")
        assert chain_a[-1] != chain_b[-1]

        # The cross-certificate in each path has a different signature algorithm and validity period
        path_a_cross_signed_root = next(cert for cert in chain_a if cert.subject == _name("Offline Root B"))
        path_b_root = chain_b[-1]
        assert path_a_cross_signed_root.issuer == _name("Offline Root A")
        assert path_b_root.issuer == _name("Offline Root B")
        assert path_a_cross_signed_root.signature_hash_algorithm.name == "sha384"
        assert path_b_root.signature_hash_algorithm.name == "sha256"
        assert path_a_cross_signed_root.not_valid_after_utc != path_b_root.not_valid_after_utc
        assert len(chain_a) == 4
        assert len(chain_b) == 3

        # Per-store conclusions are derived from that store's own path
        assert results["Ecosystem A"].received_chain_contains_anchor_certificate is True
        assert results["Ecosystem B"].received_chain_contains_anchor_certificate is False
        assert results["Ecosystem A"].verified_chain_has_sha1_signature is False
        assert results["Ecosystem B"].verified_chain_has_sha1_signature is False
        assert results["Ecosystem A"].verified_chain_has_legacy_symantec_anchor is False
        assert results["Ecosystem B"].verified_chain_has_legacy_symantec_anchor is False

    def test_trust_store_without_a_path_keeps_conclusions_unknown(self, cross_signed_deployment):
        deployment = cross_signed_deployment.analyze(
            [cross_signed_deployment.store_a, cross_signed_deployment.store_b, cross_signed_deployment.store_c]
        )
        result_c = _results_by_name(deployment)["Ecosystem C"]

        assert not result_c.was_validation_successful
        assert result_c.verified_certificate_chain is None
        assert result_c.validation_error
        assert result_c.received_chain_contains_anchor_certificate is None
        assert result_c.verified_chain_has_sha1_signature is None
        assert result_c.verified_chain_has_legacy_symantec_anchor is None

    def test_result_order_and_convenience_fields_do_not_depend_on_store_order(self, cross_signed_deployment):
        forward = cross_signed_deployment.analyze(
            [cross_signed_deployment.store_a, cross_signed_deployment.store_b, cross_signed_deployment.store_c]
        )
        reversed_order = cross_signed_deployment.analyze(
            [cross_signed_deployment.store_c, cross_signed_deployment.store_b, cross_signed_deployment.store_a]
        )

        assert [result.trust_store.name for result in forward.path_validation_results] == [
            "Ecosystem A",
            "Ecosystem B",
            "Ecosystem C",
        ]
        assert [result.trust_store.name for result in reversed_order.path_validation_results] == [
            "Ecosystem A",
            "Ecosystem B",
            "Ecosystem C",
        ]

        def _facts(deployment: CertificateDeploymentAnalysisResult) -> dict:
            return {
                result.trust_store.name: (
                    result.was_validation_successful,
                    result.received_chain_contains_anchor_certificate,
                    result.verified_chain_has_sha1_signature,
                    result.verified_chain_has_legacy_symantec_anchor,
                    tuple(_as_pem(cert) for cert in (result.verified_certificate_chain or [])),
                    result.validation_error,
                )
                for result in deployment.path_validation_results
            }

        assert _facts(forward) == _facts(reversed_order)

        # The legacy convenience fields explicitly name the store whose path they describe
        assert forward.verified_certificate_chain_trust_store is forward.path_validation_results[0].trust_store
        assert (
            reversed_order.verified_certificate_chain_trust_store
            is reversed_order.path_validation_results[0].trust_store
        )
        assert forward.verified_certificate_chain_trust_store is not None
        assert forward.verified_certificate_chain_trust_store.name == "Ecosystem A"
        assert forward.received_chain_contains_anchor_certificate is True
        assert forward.verified_chain_has_sha1_signature is False
        assert reversed_order.received_chain_contains_anchor_certificate is True
        assert reversed_order.verified_chain_has_sha1_signature is False

    def test_convenience_fields_are_unknown_when_no_store_builds_a_path(self, cross_signed_deployment):
        deployment = cross_signed_deployment.analyze([cross_signed_deployment.store_c])

        assert deployment.verified_certificate_chain_trust_store is None
        assert deployment.verified_certificate_chain is None
        assert deployment.received_chain_contains_anchor_certificate is None
        assert deployment.verified_chain_has_sha1_signature is None
        assert deployment.verified_chain_has_legacy_symantec_anchor is None

    def test_cli_report_shows_server_sent_chain_and_each_built_path(self, cross_signed_deployment):
        deployment = cross_signed_deployment.analyze(
            [cross_signed_deployment.store_a, cross_signed_deployment.store_b, cross_signed_deployment.store_c]
        )

        output = "\n".join(
            _CertificateInfoCliConnector._cert_deployment_to_console_output(1, deployment, was_sni_disabled=False)
        )

        # The chain sent by the server is presented separately from locally built chains
        assert "Received Chain:" in output
        assert (
            "Received Chain:                    cross.example.com --> Offline Intermediate"
            " --> Offline Root B --> Offline Root A"
        ) in output
        assert "Built Path:                      cross.example.com --> Offline Intermediate" in output
        assert "Verified Chain (convenience):" in output
        assert "Built Path:" in output

        # Each store's own path and conclusions are present
        assert "Ecosystem A CA Store" in output
        assert "Ecosystem B CA Store" in output
        assert "Ecosystem C CA Store" in output
        assert "Offline Root B --> Offline Root A" in output
        assert "Anchor Sent:" in output
        assert "SHA1 Signature:" in output
        assert "Symantec Anchor:" in output
        assert "UNKNOWN - no path was built with this trust store" in output
        assert "Ecosystem A CA Store (offline)]" in output
        assert "Signature Algorithms:" in output
        assert "sha256 --> sha256 --> sha384 --> sha256" in output
        assert "sha256 --> sha256 --> sha256" in output
        assert "Anchor:                          Offline Root B (not after" in output

    def test_convenience_fields_are_unknown_in_cli_when_no_store_builds_a_path(self, cross_signed_deployment):
        deployment = cross_signed_deployment.analyze([cross_signed_deployment.store_c])

        output = "\n".join(
            _CertificateInfoCliConnector._cert_deployment_to_console_output(1, deployment, was_sni_disabled=False)
        )

        assert "UNKNOWN - no trust store built a path [built by none - no trust store built a path]" in output
        assert "UNKNOWN - no path was built with this trust store" in output

    def test_json_report_contains_per_store_paths_and_conclusions(self, cross_signed_deployment):
        deployment = cross_signed_deployment.analyze(
            [cross_signed_deployment.store_a, cross_signed_deployment.store_b, cross_signed_deployment.store_c]
        )
        scan_result = CertificateInfoScanResult(
            hostname_used_for_server_name_indication="cross.example.com",
            certificate_deployments=[deployment],
            certificate_deployment_with_sni_disabled=None,
        )

        result_as_json = CertificateInfoScanResultAsJson.model_validate(scan_result)
        as_dict = result_as_json.model_dump()

        deployment_as_dict = as_dict["certificate_deployments"][0]
        assert deployment_as_dict["verified_certificate_chain_trust_store"]["name"] == "Ecosystem A"
        assert [store["trust_store"]["name"] for store in deployment_as_dict["path_validation_results"]] == [
            "Ecosystem A",
            "Ecosystem B",
            "Ecosystem C",
        ]

        json_results = _results_by_name(deployment)
        serialized_results = {
            result["trust_store"]["name"]: result for result in deployment_as_dict["path_validation_results"]
        }
        assert serialized_results["Ecosystem A"]["received_chain_contains_anchor_certificate"] is True
        assert serialized_results["Ecosystem B"]["received_chain_contains_anchor_certificate"] is False
        assert serialized_results["Ecosystem C"]["received_chain_contains_anchor_certificate"] is None
        assert serialized_results["Ecosystem C"]["verified_chain_has_sha1_signature"] is None
        assert (
            serialized_results["Ecosystem A"]["verified_certificate_chain"][-1]["subject"]["rfc4514_string"]
            == "CN=Offline Root A"
        )
        assert (
            serialized_results["Ecosystem B"]["verified_certificate_chain"][-1]["subject"]["rfc4514_string"]
            == "CN=Offline Root B"
        )
        assert json_results["Ecosystem A"].was_validation_successful

        # The JSON output can be parsed again without losing the per-store facts
        reparsed = CertificateInfoScanResultAsJson.model_validate_json(result_as_json.model_dump_json())
        assert reparsed.certificate_deployments[0].verified_certificate_chain_trust_store is not None
        assert reparsed.certificate_deployments[0].verified_certificate_chain_trust_store.name == "Ecosystem A"
