"""Offline tests for how the Mozilla TLS configuration checker handles incomplete scans.

These tests build small scan result objects by hand so they do not need a live server. They cover the three
situations that matter:

* a fully completed, compliant scan;
* a fully completed scan with confirmed violations;
* an incomplete scan where some required checks did not run or returned an error.

The last case must never be reported as compliant just because a missing scan command yields an empty cipher suite
list or a default boolean value.
"""
import datetime
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sslyze import (
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerTlsProbingResult,
)
from sslyze.mozilla_tls_profile.console_output import tls_configuration_check_result_as_console_output
from sslyze.mozilla_tls_profile.json_output import TlsConfigurationCheckResultAsJson
from sslyze.mozilla_tls_profile.tls_config_checker import (
    INDETERMINATE_CRITERION_STATUSES,
    SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER,
    _CRITERION_DEPENDENCIES,
    MozillaTlsConfiguration,
    ServerScanResultIncomplete,
    TlsConfigurationCheckStatusEnum,
    TlsConfigurationEnum,
    check_server_against_tls_configuration,
)
from sslyze.plugins.certificate_info._cert_chain_analyzer import (
    CertificateDeploymentAnalysisResult,
    PathValidationResult,
)
from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore
from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.elliptic_curves_plugin import EllipticCurve, SupportedEllipticCurvesScanResult
from sslyze.plugins.ems_extension_plugin import EmsExtensionScanResult
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanResult
from sslyze.plugins.heartbleed_plugin import HeartbleedScanResult
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanResult
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import CipherSuiteAcceptedByServer
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuitesRepository
from sslyze.plugins.openssl_cipher_suites.implementation import CipherSuitesScanResult
from sslyze.plugins.robot.implementation import RobotScanResult, RobotScanResultEnum
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanResult
from sslyze.scanner.models import (
    AllScanCommandsAttempts,
    CertificateInfoScanAttempt,
    CipherSuitesScanAttempt,
    CompressionScanAttempt,
    EmsExtensionScanAttempt,
    FallbackScsvScanAttempt,
    HeartbleedScanAttempt,
    OpenSslCcsInjectionScanAttempt,
    RobotScanAttempt,
    ServerConnectivityStatusEnum,
    ServerScanResult,
    ServerScanStatusEnum,
    SupportedEllipticCurvesScanAttempt,
    SessionRenegotiationScanAttempt,
    get_scan_command_attempt_cls,
)
from sslyze.server_connectivity import ClientAuthRequirementEnum, TlsVersionEnum


INTERMEDIATE_TLS_1_2_CIPHER = "ECDHE-RSA-AES128-GCM-SHA256"
INTERMEDIATE_TLS_1_3_CIPHER = "TLS_AES_128_GCM_SHA256"
BAD_TLS_1_2_CIPHER = "AES128-SHA"  # Not in the "intermediate" profile's allowed ciphers


# --------------------------------------------------------------------------------------------------
# Small object builders
# --------------------------------------------------------------------------------------------------
def _build_rsa_leaf_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _build_trust_store(leaf_cert) -> "TrustStore":
    # A trust store containing the self-signed leaf cert so its own chain can be marked as verified
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as store_file:
        store_file.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
        store_path = Path(store_file.name)
    try:
        return TrustStore(path=store_path, name="Test", version="1.0")
    finally:
        # The certs are loaded into an in-memory X509 store at construction time, so the file is no longer needed
        store_path.unlink(missing_ok=True)


def _build_certificate_info_result(verified: bool = True) -> CertificateInfoScanResult:
    leaf_cert, _ = _build_rsa_leaf_certificate()
    path_validation_results = []
    if verified:
        trust_store = _build_trust_store(leaf_cert)
        path_validation_results = [
            PathValidationResult(
                trust_store=trust_store,
                verified_certificate_chain=[leaf_cert],
                validation_error=None,
            )
        ]

    cert_deployment = CertificateDeploymentAnalysisResult(
        received_certificate_chain=[leaf_cert],
        leaf_certificate_has_must_staple_extension=False,
        leaf_certificate_is_ev=False,
        leaf_certificate_signed_certificate_timestamps_count=None,
        received_chain_contains_anchor_certificate=None,
        received_chain_has_valid_order=True,
        path_validation_results=path_validation_results,
        verified_chain_has_sha1_signature=False,
        verified_chain_has_legacy_symantec_anchor=None,
        ocsp_response=None,
        ocsp_response_is_trusted=None,
    )

    return CertificateInfoScanResult(
        hostname_used_for_server_name_indication="example.com",
        certificate_deployments=[cert_deployment],
        certificate_deployment_with_sni_disabled=None,
    )


def _cipher_suite(tls_version: TlsVersionEnum, openssl_name: str):
    return CipherSuitesRepository.get_cipher_suite_with_openssl_name(tls_version, openssl_name)


def _cipher_suites_scan_result(tls_version: TlsVersionEnum, accepted_names: List[str]):
    accepted_cipher_suites = [
        CipherSuiteAcceptedByServer(cipher_suite=_cipher_suite(tls_version, name), ephemeral_key=None)
        for name in accepted_names
    ]
    return CipherSuitesScanResult(
        tls_version_used=tls_version,
        accepted_cipher_suites=accepted_cipher_suites,
        rejected_cipher_suites=[],
    )


def _attempt(scan_command: ScanCommand, status: ScanCommandAttemptStatusEnum, result=None):
    attempt_cls = get_scan_command_attempt_cls(scan_command)
    return attempt_cls(status=status, error_reason=None, error_trace=None, result=result)


def _not_scheduled_attempt(scan_command: ScanCommand):
    return _attempt(scan_command, ScanCommandAttemptStatusEnum.NOT_SCHEDULED)


def _empty_cipher_suite_attempts() -> Dict[str, CipherSuitesScanAttempt]:
    # Every SSL/TLS version scan ran successfully, but the server accepted none of the cipher suites. An empty
    # accepted list must NOT be interpreted as "no bad version/cipher" unless the scan really did run.
    scan_command_to_tls_version = {
        ScanCommand.SSL_2_0_CIPHER_SUITES: TlsVersionEnum.SSL_2_0,
        ScanCommand.SSL_3_0_CIPHER_SUITES: TlsVersionEnum.SSL_3_0,
        ScanCommand.TLS_1_0_CIPHER_SUITES: TlsVersionEnum.TLS_1_0,
        ScanCommand.TLS_1_1_CIPHER_SUITES: TlsVersionEnum.TLS_1_1,
        ScanCommand.TLS_1_2_CIPHER_SUITES: TlsVersionEnum.TLS_1_2,
        ScanCommand.TLS_1_3_CIPHER_SUITES: TlsVersionEnum.TLS_1_3,
    }
    cipher_attempts = {}
    for scan_command, tls_version in scan_command_to_tls_version.items():
        result = _cipher_suites_scan_result(tls_version, accepted_names=[])
        cipher_attempts[scan_command.value] = _attempt(scan_command, ScanCommandAttemptStatusEnum.COMPLETED, result)
    return cipher_attempts


def _build_all_scan_attempts(
    cipher_attempts: Optional[Dict[str, CipherSuitesScanAttempt]] = None,
    certificate_info_result: Optional[CertificateInfoScanResult] = None,
    vulnerability_values: Optional[Dict[str, bool]] = None,
    robot_result: RobotScanResultEnum = RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE,
    supported_curve_names: Optional[List[str]] = None,
) -> AllScanCommandsAttempts:
    attempts = {scan_command.value: _not_scheduled_attempt(scan_command) for scan_command in ScanCommand}

    # Cipher suite scans
    if cipher_attempts:
        attempts.update(cipher_attempts)

    # Certificate info
    if certificate_info_result is not None:
        attempts[ScanCommand.CERTIFICATE_INFO.value] = CertificateInfoScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=certificate_info_result,
        )

    # TLS curves
    curves_result = SupportedEllipticCurvesScanResult(
        supports_ecdh_key_exchange=True,
        supported_curves=[EllipticCurve(name=name, openssl_nid=0) for name in (supported_curve_names or [])],
        rejected_curves=[],
    )
    attempts[ScanCommand.ELLIPTIC_CURVES.value] = SupportedEllipticCurvesScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=curves_result,
    )

    # Vulnerability plugins; default values below describe a fully hardened server
    values = vulnerability_values or {}
    vulnerability_builders = {
        ScanCommand.TLS_COMPRESSION: (
            CompressionScanAttempt,
            CompressionScanResult,
            {"supports_compression": values.get("tls_compression", False)},
        ),
        ScanCommand.OPENSSL_CCS_INJECTION: (
            OpenSslCcsInjectionScanAttempt,
            OpenSslCcsInjectionScanResult,
            {"is_vulnerable_to_ccs_injection": values.get("openssl_ccs_injection", False)},
        ),
        ScanCommand.TLS_FALLBACK_SCSV: (
            FallbackScsvScanAttempt,
            FallbackScsvScanResult,
            {"supports_fallback_scsv": values.get("tls_fallback_scsv", True)},
        ),
        ScanCommand.HEARTBLEED: (
            HeartbleedScanAttempt,
            HeartbleedScanResult,
            {"is_vulnerable_to_heartbleed": values.get("heartbleed", False)},
        ),
        ScanCommand.SESSION_RENEGOTIATION: (
            SessionRenegotiationScanAttempt,
            SessionRenegotiationScanResult,
            {
                "supports_secure_renegotiation": values.get("session_renegotiation", True),
                "is_vulnerable_to_client_renegotiation_dos": False,
                "client_renegotiations_success_count": 0,
            },
        ),
        ScanCommand.TLS_EXTENDED_MASTER_SECRET: (
            EmsExtensionScanAttempt,
            EmsExtensionScanResult,
            {"supports_ems_extension": values.get("tls_extended_master_secret", True)},
        ),
    }
    for scan_command, (attempt_cls, result_cls, result_kwargs) in vulnerability_builders.items():
        attempts[scan_command.value] = attempt_cls(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=result_cls(**result_kwargs),
        )

    attempts[ScanCommand.ROBOT.value] = RobotScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=RobotScanResult(robot_result=robot_result),
    )

    return AllScanCommandsAttempts(**attempts)


def _build_server_scan_result(scan_attempts: AllScanCommandsAttempts) -> ServerScanResult:
    location = ServerNetworkLocation(hostname="example.com", port=443, ip_address="1.2.3.4")
    return ServerScanResult(
        uuid=uuid4(),
        server_location=location,
        network_configuration=ServerNetworkConfiguration.default_for_server_location(location),
        connectivity_status=ServerConnectivityStatusEnum.COMPLETED,
        connectivity_error_trace=None,
        connectivity_result=ServerTlsProbingResult(
            highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
            cipher_suite_supported="AES",
            client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
            supports_ecdh_key_exchange=True,
        ),
        scan_status=ServerScanStatusEnum.COMPLETED,
        scan_result=scan_attempts,
    )


def _intermediate_profile():
    return MozillaTlsConfiguration.get(TlsConfigurationEnum.MOZILLA_INTERMEDIATE)


def _compliant_cipher_attempts() -> Dict[str, CipherSuitesScanAttempt]:
    cipher_attempts = _empty_cipher_suite_attempts()
    tls_1_2_result = _cipher_suites_scan_result(
        TlsVersionEnum.TLS_1_2, accepted_names=[INTERMEDIATE_TLS_1_2_CIPHER]
    )
    tls_1_3_result = _cipher_suites_scan_result(
        TlsVersionEnum.TLS_1_3, accepted_names=[INTERMEDIATE_TLS_1_3_CIPHER]
    )
    cipher_attempts[ScanCommand.TLS_1_2_CIPHER_SUITES.value] = _attempt(
        ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommandAttemptStatusEnum.COMPLETED, tls_1_2_result
    )
    cipher_attempts[ScanCommand.TLS_1_3_CIPHER_SUITES.value] = _attempt(
        ScanCommand.TLS_1_3_CIPHER_SUITES, ScanCommandAttemptStatusEnum.COMPLETED, tls_1_3_result
    )
    return cipher_attempts


# --------------------------------------------------------------------------------------------------
# 1. Fully completed, compliant scan
# --------------------------------------------------------------------------------------------------
class TestFullyCompletedCompliantScan:
    def test_all_criteria_complete_and_compliant(self):
        # Given a fully completed scan of a server matching the "intermediate" Mozilla profile
        scan_attempts = _build_all_scan_attempts(
            cipher_attempts=_compliant_cipher_attempts(),
            certificate_info_result=_build_certificate_info_result(verified=True),
            supported_curve_names=["X25519"],
        )
        server_scan_result = _build_server_scan_result(scan_attempts)

        # When checking it against the profile
        check_result = check_server_against_tls_configuration(server_scan_result, _intermediate_profile())

        # Then every criterion was evaluated and is compliant
        assert check_result.overall_status == TlsConfigurationCheckStatusEnum.COMPLIANT
        assert check_result.is_compliant is True
        assert check_result.issues == {}
        assert check_result.indeterminate_criteria == []
        # One criterion per entry in the dependency table (19 criteria)
        assert len(check_result.criteria) == len(_CRITERION_DEPENDENCIES)
        assert all(criterion.status == TlsConfigurationCheckStatusEnum.COMPLIANT for criterion in check_result.criteria)

        # And every dependency is reported as COMPLETED
        for criterion in check_result.criteria:
            assert criterion.dependencies
            assert all(
                status == ScanCommandAttemptStatusEnum.COMPLETED for status in criterion.dependencies.values()
            )


# --------------------------------------------------------------------------------------------------
# 2. Fully completed scan with confirmed violations
# --------------------------------------------------------------------------------------------------
class TestFullyCompletedViolatingScan:
    def test_confirmed_violations_are_reported_as_not_compliant(self):
        # Given a fully completed scan where the server accepts a cipher outside the profile and is vulnerable to
        # TLS compression
        cipher_attempts = _compliant_cipher_attempts()
        tls_1_2_result = _cipher_suites_scan_result(
            TlsVersionEnum.TLS_1_2,
            accepted_names=[INTERMEDIATE_TLS_1_2_CIPHER, BAD_TLS_1_2_CIPHER],
        )
        cipher_attempts[ScanCommand.TLS_1_2_CIPHER_SUITES.value] = _attempt(
            ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommandAttemptStatusEnum.COMPLETED, tls_1_2_result
        )
        scan_attempts = _build_all_scan_attempts(
            cipher_attempts=cipher_attempts,
            certificate_info_result=_build_certificate_info_result(verified=True),
            vulnerability_values={"tls_compression": True},
            supported_curve_names=["X25519"],
        )
        server_scan_result = _build_server_scan_result(scan_attempts)

        # When checking it against the profile
        check_result = check_server_against_tls_configuration(server_scan_result, _intermediate_profile())

        # Then the check is fully decided but not compliant, and the violations are surfaced
        assert check_result.overall_status == TlsConfigurationCheckStatusEnum.NOT_COMPLIANT
        assert check_result.is_compliant is False
        assert check_result.indeterminate_criteria == []
        assert "ciphers" in check_result.issues
        assert "tls_vulnerability_compression" in check_result.issues
        # The issue message uses the IANA name of the offending cipher suite
        bad_cipher_iana_name = _cipher_suite(TlsVersionEnum.TLS_1_2, BAD_TLS_1_2_CIPHER).name
        assert bad_cipher_iana_name in check_result.issues["ciphers"]

        offending_criteria = {c.criterion_name: c for c in check_result.criteria if c.status
                              == TlsConfigurationCheckStatusEnum.NOT_COMPLIANT}
        assert set(offending_criteria) == {"ciphers", "tls_vulnerability_compression"}
        for criterion in check_result.criteria:
            if criterion.criterion_name not in offending_criteria:
                assert criterion.status == TlsConfigurationCheckStatusEnum.COMPLIANT

    def test_untrusted_certificate_is_a_confirmed_violation(self):
        # Given a fully completed scan whose certificate path cannot be validated
        scan_attempts = _build_all_scan_attempts(
            cipher_attempts=_compliant_cipher_attempts(),
            certificate_info_result=_build_certificate_info_result(verified=False),
            supported_curve_names=["X25519"],
        )
        server_scan_result = _build_server_scan_result(scan_attempts)

        # When checking it
        check_result = check_server_against_tls_configuration(server_scan_result, _intermediate_profile())

        # Then it is a confirmed (decidable) non-compliance, not an indeterminate result
        assert check_result.overall_status == TlsConfigurationCheckStatusEnum.NOT_COMPLIANT
        assert "certificate_path_validation" in check_result.issues


# --------------------------------------------------------------------------------------------------
# 3. Incomplete scan: required checks did not run or returned an error
# --------------------------------------------------------------------------------------------------
class TestIncompleteScan:
    def test_missing_scan_commands_are_not_run_not_compliant_and_do_not_abort_other_checks(self):
        # Given a scan where only the compression plugin ran (and detected a vulnerability); every other scan
        # command the checker needs was never scheduled
        scan_attempts = _build_all_scan_attempts(
            vulnerability_values={"tls_compression": True},
        )
        for scan_command in SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER - {ScanCommand.TLS_COMPRESSION}:
            scan_attempts.__dict__[scan_command.value] = _not_scheduled_attempt(scan_command)
        server_scan_result = _build_server_scan_result(scan_attempts)

        # When checking it against the profile
        check_result = check_server_against_tls_configuration(server_scan_result, _intermediate_profile())

        # Then the overall check cannot be decided
        assert check_result.overall_status == TlsConfigurationCheckStatusEnum.NOT_RUN
        assert check_result.is_compliant is False

        # But the confirmed compression violation is still surfaced
        compression_criterion = next(
            c for c in check_result.criteria if c.criterion_name == "tls_vulnerability_compression"
        )
        assert compression_criterion.status == TlsConfigurationCheckStatusEnum.NOT_COMPLIANT
        assert check_result.issues == {"tls_vulnerability_compression": compression_criterion.issue_description}

        # And every other criterion is NOT_RUN with its NOT_SCHEDULED dependency exposed (never silently compliant)
        for criterion in check_result.criteria:
            if criterion.criterion_name == "tls_vulnerability_compression":
                continue
            assert criterion.status == TlsConfigurationCheckStatusEnum.NOT_RUN
            assert ScanCommandAttemptStatusEnum.NOT_SCHEDULED in criterion.dependencies.values()

    def test_empty_cipher_lists_from_missing_scans_do_not_look_compliant(self):
        # This is the regression: previously a missing cipher scan could leave empty sets which the difference-based
        # checks treated as "no bad version/cipher", i.e. compliant.
        scan_attempts = _build_all_scan_attempts(
            certificate_info_result=_build_certificate_info_result(verified=True),
            supported_curve_names=["X25519"],
        )
        # Remove the cipher suite scans entirely to simulate them not being scheduled
        for scan_command in [
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
        ]:
            scan_attempts.__dict__[scan_command.value] = _not_scheduled_attempt(scan_command)
        server_scan_result = _build_server_scan_result(scan_attempts)

        check_result = check_server_against_tls_configuration(server_scan_result, _intermediate_profile())

        assert check_result.overall_status == TlsConfigurationCheckStatusEnum.NOT_RUN
        for criterion_name in ["tls_versions", "ciphers", "ciphersuites", "ecdh_param_size", "dh_param_size"]:
            criterion = next(c for c in check_result.criteria if c.criterion_name == criterion_name)
            assert criterion.status == TlsConfigurationCheckStatusEnum.NOT_RUN
            assert criterion.issue_description is None

    def test_default_booleans_from_missing_vulnerability_scans_do_not_look_compliant(self):
        # Given a fully scheduled scan except for the boolean vulnerability plugins, which are left NOT_SCHEDULED
        scan_attempts = _build_all_scan_attempts(
            cipher_attempts=_empty_cipher_suite_attempts(),
            certificate_info_result=_build_certificate_info_result(verified=True),
            supported_curve_names=["X25519"],
        )
        for scan_command in [
            ScanCommand.HEARTBLEED,
            ScanCommand.ROBOT,
            ScanCommand.OPENSSL_CCS_INJECTION,
            ScanCommand.TLS_FALLBACK_SCSV,
            ScanCommand.TLS_COMPRESSION,
            ScanCommand.SESSION_RENEGOTIATION,
            ScanCommand.TLS_EXTENDED_MASTER_SECRET,
        ]:
            scan_attempts.__dict__[scan_command.value] = _not_scheduled_attempt(scan_command)
        server_scan_result = _build_server_scan_result(scan_attempts)

        check_result = check_server_against_tls_configuration(server_scan_result, _intermediate_profile())

        assert check_result.overall_status == TlsConfigurationCheckStatusEnum.NOT_RUN
        for criterion in check_result.criteria:
            if criterion.criterion_name.startswith("tls_vulnerability_"):
                assert criterion.status == TlsConfigurationCheckStatusEnum.NOT_RUN

    def test_erroring_scan_command_is_distinguished_from_not_run(self):
        # Given a scan where one plugin returned an error while another was never scheduled
        scan_attempts = _build_all_scan_attempts(
            vulnerability_values={"tls_compression": True},
        )
        scan_attempts.__dict__[ScanCommand.HEARTBLEED.value] = _attempt(
            ScanCommand.HEARTBLEED, ScanCommandAttemptStatusEnum.ERROR
        )
        # The certificate plugin never ran, so its criteria must stay NOT_RUN
        scan_attempts.__dict__[ScanCommand.CERTIFICATE_INFO.value] = _not_scheduled_attempt(
            ScanCommand.CERTIFICATE_INFO
        )
        server_scan_result = _build_server_scan_result(scan_attempts)

        check_result = check_server_against_tls_configuration(server_scan_result, _intermediate_profile())

        # The error makes the overall check an ERROR, distinct from NOT_RUN
        assert check_result.overall_status == TlsConfigurationCheckStatusEnum.ERROR
        heartbleed_criterion = next(
            c for c in check_result.criteria if c.criterion_name == "tls_vulnerability_heartbleed"
        )
        assert heartbleed_criterion.status == TlsConfigurationCheckStatusEnum.ERROR
        assert heartbleed_criterion.dependencies[ScanCommand.HEARTBLEED] == ScanCommandAttemptStatusEnum.ERROR

        # A not-scheduled command keeps its own NOT_RUN status
        certificate_criterion = next(
            c for c in check_result.criteria if c.criterion_name == "certificate_path_validation"
        )
        assert certificate_criterion.status == TlsConfigurationCheckStatusEnum.NOT_RUN

        # The confirmed compression violation is still reported
        assert "tls_vulnerability_compression" in check_result.issues

    def test_not_completed_server_scan_raises_incomplete(self):
        # Given a server scan that never completed
        location = ServerNetworkLocation(hostname="example.com", port=443, ip_address="1.2.3.4")
        server_scan_result = ServerScanResult(
            uuid=uuid4(),
            server_location=location,
            network_configuration=ServerNetworkConfiguration.default_for_server_location(location),
            connectivity_status=ServerConnectivityStatusEnum.ERROR,
            connectivity_error_trace=None,
            connectivity_result=None,
            scan_status=ServerScanStatusEnum.ERROR_NO_CONNECTIVITY,
            scan_result=None,
        )

        # When checking it, the checker signals that it cannot run at all
        with pytest.raises(ServerScanResultIncomplete):
            check_server_against_tls_configuration(server_scan_result, _intermediate_profile())


# --------------------------------------------------------------------------------------------------
# 4. Consistency across the API, the JSON output and the console output
# --------------------------------------------------------------------------------------------------
class TestOutputConsistency:
    def _three_scenarios(self):
        compliant = _build_server_scan_result(
            _build_all_scan_attempts(
                cipher_attempts=_compliant_cipher_attempts(),
                certificate_info_result=_build_certificate_info_result(verified=True),
                supported_curve_names=["X25519"],
            )
        )

        violating = _build_server_scan_result(
            _build_all_scan_attempts(
                cipher_attempts=_compliant_cipher_attempts(),
                certificate_info_result=_build_certificate_info_result(verified=True),
                vulnerability_values={"tls_compression": True},
                supported_curve_names=["X25519"],
            )
        )

        incomplete_attempts = _build_all_scan_attempts(vulnerability_values={"tls_compression": True})
        for scan_command in SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER - {ScanCommand.TLS_COMPRESSION}:
            incomplete_attempts.__dict__[scan_command.value] = _not_scheduled_attempt(scan_command)
        incomplete = _build_server_scan_result(incomplete_attempts)
        return compliant, violating, incomplete

    def test_api_json_and_console_report_the_same_status(self):
        profile = _intermediate_profile()
        expected_overall = [
            TlsConfigurationCheckStatusEnum.COMPLIANT,
            TlsConfigurationCheckStatusEnum.NOT_COMPLIANT,
            TlsConfigurationCheckStatusEnum.NOT_RUN,
        ]

        for server_scan_result, expected_status in zip(self._three_scenarios(), expected_overall):
            # API
            check_result = check_server_against_tls_configuration(server_scan_result, profile)
            assert check_result.overall_status == expected_status

            # JSON
            json_model = TlsConfigurationCheckResultAsJson.model_validate(check_result)
            json_payload = json.loads(json_model.model_dump_json())
            assert json_payload["overall_status"] == expected_status.value
            assert json_payload["is_compliant"] == check_result.is_compliant
            # The JSON round-trips and keeps every criterion with its dependency statuses
            assert len(json_payload["criteria"]) == len(check_result.criteria)
            for json_criterion, criterion in zip(json_payload["criteria"], check_result.criteria):
                assert json_criterion["criterion_name"] == criterion.criterion_name
                assert json_criterion["status"] == criterion.status.value
                assert json_criterion["dependencies"] == {
                    scan_command.value: attempt_status.value
                    for scan_command, attempt_status in criterion.dependencies.items()
                }
            TlsConfigurationCheckResultAsJson.model_validate_json(json_model.model_dump_json())

            # Console
            console_lines = tls_configuration_check_result_as_console_output("example.com", check_result)
            console_text = "\n".join(console_lines)
            if expected_status == TlsConfigurationCheckStatusEnum.COMPLIANT:
                assert "OK - Compliant." in console_text
            elif expected_status == TlsConfigurationCheckStatusEnum.NOT_COMPLIANT:
                assert "FAILED - Not compliant." in console_text
            else:
                assert "ERROR" in console_text and "not run" in console_text

            # Confirmed violations appear in all three surfaces for the scenarios that have them
            for criterion_name, issue_description in check_result.issues.items():
                assert criterion_name in console_text
                assert issue_description in console_text
                assert any(
                    c["criterion_name"] == criterion_name and c["issue_description"] == issue_description
                    for c in json_payload["criteria"]
                )

    def test_incomplete_scenario_lists_every_missing_dependency_in_all_surfaces(self):
        _, _, incomplete = self._three_scenarios()
        check_result = check_server_against_tls_configuration(incomplete, _intermediate_profile())

        assert check_result.overall_status in INDETERMINATE_CRITERION_STATUSES
        missing_criteria = check_result.indeterminate_criteria
        assert missing_criteria

        json_payload = json.loads(
            TlsConfigurationCheckResultAsJson.model_validate(check_result).model_dump_json()
        )
        json_indeterminate = [c for c in json_payload["criteria"] if c["status"] in
                              {status.value for status in INDETERMINATE_CRITERION_STATUSES}]
        assert len(json_indeterminate) == len(missing_criteria)

        console_text = "\n".join(
            tls_configuration_check_result_as_console_output("example.com", check_result)
        )
        for criterion in missing_criteria:
            assert criterion.criterion_name in console_text
            for scan_command in criterion.dependencies:
                assert scan_command.value in console_text
