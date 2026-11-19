"""Cross-plugin contract tests for the scan-result JSON serialization chain.

These tests do not compare a model against a dump/reload of itself: doing so would reuse the very same
default-value logic and could therefore hide a serializer that turns unrun or unknown checks into negated
findings. Instead every test starts from real scan-result objects (the dataclasses returned by the plugins),
runs them through the formal output chain used by the CLI (``ServerScanResultAsJson`` ->
``model_dump_json`` -> ``SslyzeOutputAsJson.model_validate_json``), and then asserts on the observable
on-the-wire facts: which fields exist, what status they carry, what context they keep, and whether a consumer
reading the JSON back can still tell which checks actually ran.

The four observable states of a scan command are all covered:

* COMPLETED with a full result,
* COMPLETED with a partial result (some derived fields are legitimately ``None``),
* ERROR (the plugin raised; only error context is available),
* NOT_SCHEDULED (the check was never run; it must not look like a negated vulnerability).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from traceback import TracebackException
from typing import Dict, Optional
from uuid import uuid4

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

from sslyze import (
    CertificateInfoScanResult,
    CertificateDeploymentAnalysisResult,
    ClientAuthRequirementEnum,
    CompressionScanResult,
    CipherSuite,
    CipherSuitesScanResult,
    EarlyDataScanResult,
    EmsExtensionScanResult,
    FallbackScsvScanResult,
    HeartbleedScanResult,
    HttpHeadersScanResult,
    OpenSslCcsInjectionScanResult,
    PathValidationResult,
    RobotScanResult,
    RobotScanResultEnum,
    ScanCommandAttemptStatusEnum,
    ScanCommandErrorReasonEnum,
    ServerConnectivityStatusEnum,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerScanResult,
    ServerScanStatusEnum,
    SessionRenegotiationScanResult,
    SupportedEllipticCurvesScanResult,
    EllipticCurve,
    TlsVersionEnum,
)
from sslyze.json.json_output import SslyzeOutputAsJson, ServerScanResultAsJson
from sslyze.plugins.openssl_cipher_suites.implementation import (
    CipherSuiteAcceptedByServer,
    CipherSuiteRejectedByServer,
)
from sslyze.scanner.models import (
    AllScanCommandsAttempts,
    CertificateInfoScanAttempt,
    CipherSuitesScanAttempt,
    CompressionScanAttempt,
    EarlyDataScanAttempt,
    EmsExtensionScanAttempt,
    FallbackScsvScanAttempt,
    HeartbleedScanAttempt,
    HttpHeadersScanAttempt,
    OpenSslCcsInjectionScanAttempt,
    RobotScanAttempt,
    SessionRenegotiationScanAttempt,
    SessionResumptionSupportScanAttempt,
    SupportedEllipticCurvesScanAttempt,
)
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
from sslyze.server_connectivity import ServerTlsProbingResult
from sslyze.plugins.session_resumption.implementation import (
    SessionResumptionSupportScanResult,
    TlsResumptionSupportEnum,
)


# --------------------------------------------------------------------------------------------------
# Helpers to build REAL result objects (the same dataclasses the plugins return), no network involved
# --------------------------------------------------------------------------------------------------

def _traceback_exception() -> TracebackException:
    try:
        raise RuntimeError("boom: a plugin blew up")
    except RuntimeError as exc:
        return TracebackException.from_exception(exc)


def _server_scan_result(all_attempts: AllScanCommandsAttempts) -> ServerScanResult:
    location = ServerNetworkLocation(hostname="contract.test", port=443, ip_address="203.0.113.7")
    return ServerScanResult(
        uuid=uuid4(),
        server_location=location,
        network_configuration=ServerNetworkConfiguration.default_for_server_location(location),
        connectivity_status=ServerConnectivityStatusEnum.COMPLETED,
        connectivity_error_trace=None,
        connectivity_result=ServerTlsProbingResult(
            highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
            cipher_suite_supported="AES256-GCM-SHA384",
            client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
            supports_ecdh_key_exchange=True,
        ),
        scan_status=ServerScanStatusEnum.COMPLETED,
        scan_result=all_attempts,
    )


def _not_scheduled(attempt_cls) -> ScanCommandAttempt:
    return attempt_cls(
        status=ScanCommandAttemptStatusEnum.NOT_SCHEDULED,
        error_reason=None,
        error_trace=None,
        result=None,
    )


def _errored(attempt_cls) -> ScanCommandAttempt:
    return attempt_cls(
        status=ScanCommandAttemptStatusEnum.ERROR,
        error_reason=ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE,
        error_trace=_traceback_exception(),
        result=None,
    )


def _build_all_attempts(overrides: Optional[Dict[str, ScanCommandAttempt]] = None) -> AllScanCommandsAttempts:
    """Build an AllScanCommandsAttempts where every non-overridden command is NOT_SCHEDULED."""
    attempts: Dict[str, ScanCommandAttempt] = {
        "certificate_info": _not_scheduled(CertificateInfoScanAttempt),
        "ssl_2_0_cipher_suites": _not_scheduled(CipherSuitesScanAttempt),
        "ssl_3_0_cipher_suites": _not_scheduled(CipherSuitesScanAttempt),
        "tls_1_0_cipher_suites": _not_scheduled(CipherSuitesScanAttempt),
        "tls_1_1_cipher_suites": _not_scheduled(CipherSuitesScanAttempt),
        "tls_1_2_cipher_suites": _not_scheduled(CipherSuitesScanAttempt),
        "tls_1_3_cipher_suites": _not_scheduled(CipherSuitesScanAttempt),
        "tls_compression": _not_scheduled(CompressionScanAttempt),
        "tls_1_3_early_data": _not_scheduled(EarlyDataScanAttempt),
        "openssl_ccs_injection": _not_scheduled(OpenSslCcsInjectionScanAttempt),
        "tls_fallback_scsv": _not_scheduled(FallbackScsvScanAttempt),
        "heartbleed": _not_scheduled(HeartbleedScanAttempt),
        "robot": _not_scheduled(RobotScanAttempt),
        "session_renegotiation": _not_scheduled(SessionRenegotiationScanAttempt),
        "session_resumption": _not_scheduled(SessionResumptionSupportScanAttempt),
        "elliptic_curves": _not_scheduled(SupportedEllipticCurvesScanAttempt),
        "http_headers": _not_scheduled(HttpHeadersScanAttempt),
        "tls_extended_master_secret": _not_scheduled(EmsExtensionScanAttempt),
    }
    if overrides:
        attempts.update(overrides)
    return AllScanCommandsAttempts(**attempts)


def _serialize_through_output_chain(server_scan_result: ServerScanResult):
    """The exact chain run by sslyze.__main__ to produce and read back the JSON report."""
    json_model = SslyzeOutputAsJson(
        server_scan_results=[ServerScanResultAsJson.model_validate(server_scan_result)],
        invalid_server_strings=[],
        date_scans_started=datetime.now(timezone.utc),
        date_scans_completed=datetime.now(timezone.utc),
    )
    json_as_str = json_model.model_dump_json()
    # Round-trip through plain json.loads so assertions observe the wire format, not pydantic defaults.
    return json.loads(json_as_str), SslyzeOutputAsJson.model_validate_json(json_as_str)


# --------------------------------------------------------------------------------------------------
# Real plugin result objects used as fixtures
# --------------------------------------------------------------------------------------------------

def _heartbleed_not_vulnerable_attempt() -> HeartbleedScanAttempt:
    return HeartbleedScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=HeartbleedScanResult(is_vulnerable_to_heartbleed=False),
    )


def _heartbleed_vulnerable_attempt() -> HeartbleedScanAttempt:
    return HeartbleedScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=HeartbleedScanResult(is_vulnerable_to_heartbleed=True),
    )


def _cipher_suites_attempt(tls_version: TlsVersionEnum, is_supported: bool) -> CipherSuitesScanAttempt:
    accepted = (
        [
            CipherSuiteAcceptedByServer(
                cipher_suite=CipherSuite(
                    name="TLS_RSA_WITH_AES_256_GCM_SHA384",
                    is_anonymous=False,
                    key_size=256,
                    openssl_name="AES256-GCM-SHA384",
                ),
                ephemeral_key=None,
            )
        ]
        if is_supported
        else []
    )
    rejected = (
        []
        if is_supported
        else [
            CipherSuiteRejectedByServer(
                cipher_suite=CipherSuite(
                    name="TLS_RSA_WITH_AES_128_CBC_SHA",
                    is_anonymous=False,
                    key_size=128,
                    openssl_name="AES128-SHA",
                ),
                error_message="TLS Alert: handshake failure",
            )
        ]
    )
    return CipherSuitesScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=CipherSuitesScanResult(
            tls_version_used=tls_version,
            accepted_cipher_suites=accepted,
            rejected_cipher_suites=rejected,
        ),
    )


def _certificate_info_attempt() -> CertificateInfoScanAttempt:
    """A partial cert result: several derived booleans are legitimately None (chain could not be verified)."""
    cert_path = Path(__file__).parent.parent / "certificates" / "github.com.pem"
    leaf_cert = load_pem_x509_certificate(cert_path.read_bytes(), default_backend())
    deployment = CertificateDeploymentAnalysisResult(
        received_certificate_chain=[leaf_cert],
        leaf_certificate_has_must_staple_extension=False,
        leaf_certificate_is_ev=True,
        # None: OpenSSL too old to parse SCTs
        leaf_certificate_signed_certificate_timestamps_count=None,
        # None: the verified chain could not be built
        received_chain_contains_anchor_certificate=None,
        received_chain_has_valid_order=None,
        path_validation_results=[
            PathValidationResult(
                trust_store=_FakeTrustStore(),
                verified_certificate_chain=None,
                validation_error="unable to get local issuer certificate",
            )
        ],
        verified_chain_has_sha1_signature=None,
        verified_chain_has_legacy_symantec_anchor=None,
        ocsp_response=None,
        ocsp_response_is_trusted=None,
    )
    result = CertificateInfoScanResult(
        hostname_used_for_server_name_indication="contract.test",
        certificate_deployments=[deployment],
        # None: the SNI-disabled handshake failed, so no deployment is available
        certificate_deployment_with_sni_disabled=None,
    )
    return CertificateInfoScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=result,
    )


class _FakeTrustStore:
    """Minimal stand-in for TrustStore: only the attributes serialized by _TrustStoreAsJson are needed."""

    path = Path("/nonexistent/trust-store.pem")
    name = "Fake Trust Store"
    version = "0.0.0"
    ev_oids = None


def _elliptic_curves_unsupported_attempt() -> SupportedEllipticCurvesScanAttempt:
    """The server does not do ECDH: the curve lists were never populated, so they stay None."""
    return SupportedEllipticCurvesScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=SupportedEllipticCurvesScanResult(
            supports_ecdh_key_exchange=False,
            supported_curves=None,
            rejected_curves=None,
        ),
    )


def _elliptic_curves_supported_attempt() -> SupportedEllipticCurvesScanAttempt:
    return SupportedEllipticCurvesScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=SupportedEllipticCurvesScanResult(
            supports_ecdh_key_exchange=True,
            supported_curves=[EllipticCurve(name="prime256v1", openssl_nid=415)],
            rejected_curves=[],
        ),
    )


def _robot_attempt(robot_result: RobotScanResultEnum) -> RobotScanAttempt:
    return RobotScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=RobotScanResult(robot_result=robot_result),
    )


def _full_successful_attempts() -> Dict[str, ScanCommandAttempt]:
    return {
        "certificate_info": _certificate_info_attempt(),
        "ssl_2_0_cipher_suites": _cipher_suites_attempt(TlsVersionEnum.SSL_2_0, is_supported=False),
        "ssl_3_0_cipher_suites": _cipher_suites_attempt(TlsVersionEnum.SSL_3_0, is_supported=False),
        "tls_1_0_cipher_suites": _cipher_suites_attempt(TlsVersionEnum.TLS_1_0, is_supported=False),
        "tls_1_1_cipher_suites": _cipher_suites_attempt(TlsVersionEnum.TLS_1_1, is_supported=False),
        "tls_1_2_cipher_suites": _cipher_suites_attempt(TlsVersionEnum.TLS_1_2, is_supported=True),
        "tls_1_3_cipher_suites": _cipher_suites_attempt(TlsVersionEnum.TLS_1_3, is_supported=True),
        "tls_compression": CompressionScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=CompressionScanResult(supports_compression=False),
        ),
        "tls_1_3_early_data": EarlyDataScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=EarlyDataScanResult(supports_early_data=False),
        ),
        "openssl_ccs_injection": OpenSslCcsInjectionScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=OpenSslCcsInjectionScanResult(is_vulnerable_to_ccs_injection=False),
        ),
        "tls_fallback_scsv": FallbackScsvScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=FallbackScsvScanResult(supports_fallback_scsv=True),
        ),
        "heartbleed": _heartbleed_not_vulnerable_attempt(),
        "robot": _robot_attempt(RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE),
        "session_renegotiation": SessionRenegotiationScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=SessionRenegotiationScanResult(
                supports_secure_renegotiation=True,
                is_vulnerable_to_client_renegotiation_dos=False,
                client_renegotiations_success_count=0,
            ),
        ),
        "session_resumption": SessionResumptionSupportScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=SessionResumptionSupportScanResult(
                session_id_resumption_result=TlsResumptionSupportEnum.FULLY_SUPPORTED,
                session_id_attempted_resumptions_count=5,
                session_id_successful_resumptions_count=5,
                tls_ticket_resumption_result=TlsResumptionSupportEnum.PARTIALLY_SUPPORTED,
                tls_ticket_attempted_resumptions_count=5,
                tls_ticket_successful_resumptions_count=2,
            ),
        ),
        "elliptic_curves": _elliptic_curves_supported_attempt(),
        "http_headers": HttpHeadersScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=HttpHeadersScanResult(
                http_request_sent="GET / HTTP/1.1",
                http_error_trace=None,
                http_path_redirected_to=None,
                strict_transport_security_header=None,
            ),
        ),
        "tls_extended_master_secret": EmsExtensionScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=EmsExtensionScanResult(supports_ems_extension=True),
        ),
    }


# --------------------------------------------------------------------------------------------------
# 1. NOT_SCHEDULED: an unrun check must not be represented as a negated vulnerability
# --------------------------------------------------------------------------------------------------

class TestNotScheduledChecksAreNotNegatedFindings:
    def test_only_one_command_scheduled_is_distinguishable_on_the_wire(self):
        # Given a server scan where only the Heartbleed check was actually run (and returned not vulnerable)
        server_scan_result = _server_scan_result(
            _build_all_attempts({"heartbleed": _heartbleed_not_vulnerable_attempt()})
        )

        # When going through the formal JSON output chain
        wire_json, parsed_model = _serialize_through_output_chain(server_scan_result)
        scan_result = wire_json["server_scan_results"][0]["scan_result"]

        # Then every one of the 18 scan commands is present as a field
        assert set(scan_result.keys()) == set(AllScanCommandsAttempts.__dataclass_fields__.keys())

        # And the command that ran is COMPLETED with its actual result
        assert scan_result["heartbleed"]["status"] == "COMPLETED"
        assert scan_result["heartbleed"]["result"] == {"is_vulnerable_to_heartbleed": False}
        assert scan_result["heartbleed"]["error_reason"] is None
        assert scan_result["heartbleed"]["error_trace"] is None

        # And every command that did NOT run keeps an explicit NOT_SCHEDULED status ...
        not_scheduled_commands = [name for name in scan_result if name != "heartbleed"]
        assert len(not_scheduled_commands) == 17
        for command_name in not_scheduled_commands:
            attempt = scan_result[command_name]
            assert attempt["status"] == "NOT_SCHEDULED"
            # ... with no result object: an unrun check cannot claim a (negated) boolean finding
            assert attempt["result"] is None
            assert attempt["error_reason"] is None
            assert attempt["error_trace"] is None

        # And reading the JSON back still answers "which checks ran?": exactly one COMPLETED attempt
        parsed_attempts = parsed_model.server_scan_results[0].scan_result
        completed = [
            name
            for name, attempt in parsed_attempts
            if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        ]
        assert completed == ["heartbleed"]
        not_scheduled = [
            name
            for name, attempt in parsed_attempts
            if attempt.status == ScanCommandAttemptStatusEnum.NOT_SCHEDULED
        ]
        assert set(not_scheduled) == set(not_scheduled_commands)

    def test_not_scheduled_attempt_has_no_vulnerability_boolean_anywhere(self):
        # Given a fully unscheduled robot check
        server_scan_result = _server_scan_result(_build_all_attempts())

        # When serialized
        wire_json, _ = _serialize_through_output_chain(server_scan_result)
        robot_attempt = wire_json["server_scan_results"][0]["scan_result"]["robot"]

        # Then the wire object contains no robot_result value that could be misread as "not vulnerable"
        assert robot_attempt == {
            "status": "NOT_SCHEDULED",
            "error_reason": None,
            "error_trace": None,
            "result": None,
        }
        assert "robot_result" not in json.dumps(robot_attempt)


# --------------------------------------------------------------------------------------------------
# 2. ERROR: a plugin exception is observable with its context and never becomes a clean negative
# --------------------------------------------------------------------------------------------------

class TestErroredChecksKeepErrorContext:
    def test_errored_attempt_serializes_status_reason_and_trace_without_result(self):
        # Given a Heartbleed check that crashed inside the plugin
        errored_attempt = _errored(HeartbleedScanAttempt)
        server_scan_result = _server_scan_result(
            _build_all_attempts({"heartbleed": errored_attempt})
        )

        # When serialized through the output chain
        wire_json, parsed_model = _serialize_through_output_chain(server_scan_result)
        heartbleed_attempt = wire_json["server_scan_results"][0]["scan_result"]["heartbleed"]

        # Then the failure is fully observable on the wire
        assert heartbleed_attempt["status"] == "ERROR"
        assert heartbleed_attempt["error_reason"] == "CONNECTIVITY_ISSUE"
        assert heartbleed_attempt["result"] is None
        # The TracebackException was stringified through the same conversion as the CLI path
        assert "RuntimeError" in heartbleed_attempt["error_trace"]
        assert "boom: a plugin blew up" in heartbleed_attempt["error_trace"]

        # And the raw text must not contain a heartbleed verdict: a crash is not a negative result
        assert "is_vulnerable_to_heartbleed" not in json.dumps(heartbleed_attempt)

        # And reading it back preserves the error state and its context
        parsed_attempt = parsed_model.server_scan_results[0].scan_result.heartbleed
        assert parsed_attempt.status == ScanCommandAttemptStatusEnum.ERROR
        assert parsed_attempt.error_reason == ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE
        assert parsed_attempt.result is None
        assert "RuntimeError" in parsed_attempt.error_trace

    def test_errored_and_not_scheduled_checks_are_never_confused_with_each_other(self):
        # Given one crashed command, one completed command, everything else unscheduled
        server_scan_result = _server_scan_result(
            _build_all_attempts(
                {
                    "heartbleed": _errored(HeartbleedScanAttempt),
                    "robot": _robot_attempt(RobotScanResultEnum.VULNERABLE_WEAK_ORACLE),
                }
            )
        )

        # When serialized and read back
        wire_json, parsed_model = _serialize_through_output_chain(server_scan_result)
        scan_result = wire_json["server_scan_results"][0]["scan_result"]

        # Then the three states remain disjoint
        assert scan_result["heartbleed"]["status"] == "ERROR"
        assert scan_result["heartbleed"]["result"] is None
        assert scan_result["robot"]["status"] == "COMPLETED"
        assert scan_result["robot"]["result"]["robot_result"] == "VULNERABLE_WEAK_ORACLE"
        assert scan_result["tls_compression"]["status"] == "NOT_SCHEDULED"
        assert scan_result["tls_compression"]["result"] is None

        statuses = {name: attempt.status for name, attempt in parsed_model.server_scan_results[0].scan_result}
        assert statuses["heartbleed"] == ScanCommandAttemptStatusEnum.ERROR
        assert statuses["robot"] == ScanCommandAttemptStatusEnum.COMPLETED
        assert statuses["tls_compression"] == ScanCommandAttemptStatusEnum.NOT_SCHEDULED


# --------------------------------------------------------------------------------------------------
# 3. PARTIAL results: legitimate None derived fields must survive as JSON null, never become false
# --------------------------------------------------------------------------------------------------

class TestPartialResultsKeepNoneAsJsonNull:
    def test_certificate_derived_unknown_fields_are_null_not_false(self):
        # Given a completed certificate_info scan whose verified chain could not be built, so several derived
        # booleans/counts are legitimately None
        server_scan_result = _server_scan_result(
            _build_all_attempts({"certificate_info": _certificate_info_attempt()})
        )

        # When serialized
        wire_json, parsed_model = _serialize_through_output_chain(server_scan_result)
        deployment = wire_json["server_scan_results"][0]["scan_result"]["certificate_info"]["result"][
            "certificate_deployments"
        ][0]

        # Then fields that were actually computed keep their real values ...
        assert deployment["leaf_certificate_has_must_staple_extension"] is False
        assert deployment["leaf_certificate_is_ev"] is True
        assert deployment["path_validation_results"][0]["was_validation_successful"] is False
        assert deployment["path_validation_results"][0]["validation_error"] is not None

        # ... while every "not available" derived field is an explicit JSON null, never false/0
        assert deployment["leaf_certificate_signed_certificate_timestamps_count"] is None
        assert deployment["received_chain_contains_anchor_certificate"] is None
        assert deployment["received_chain_has_valid_order"] is None
        assert deployment["verified_chain_has_sha1_signature"] is None
        assert deployment["verified_chain_has_legacy_symantec_anchor"] is None
        assert deployment["ocsp_response"] is None
        assert deployment["ocsp_response_is_trusted"] is None

        # And the optional SNI-disabled deployment, which was never produced, is null too
        cert_result = wire_json["server_scan_results"][0]["scan_result"]["certificate_info"]["result"]
        assert cert_result["certificate_deployment_with_sni_disabled"] is None
        assert cert_result["hostname_used_for_server_name_indication"] == "contract.test"

        # And the parsed-back model still carries None (not False) for those unknowns
        parsed_deployment = (
            parsed_model.server_scan_results[0]
            .scan_result.certificate_info.result.certificate_deployments[0]
        )
        assert parsed_deployment.verified_chain_has_sha1_signature is None
        assert parsed_deployment.received_chain_has_valid_order is None
        assert parsed_deployment.ocsp_response_is_trusted is None
        assert (
            parsed_model.server_scan_results[0]
            .scan_result.certificate_info.result.certificate_deployment_with_sni_disabled
            is None
        )

    def test_elliptic_curves_unsupported_keeps_curve_lists_null(self):
        # Given a server that does not support ECDH at all: the curve checks were never applicable
        server_scan_result = _server_scan_result(
            _build_all_attempts({"elliptic_curves": _elliptic_curves_unsupported_attempt()})
        )

        # When serialized
        wire_json, parsed_model = _serialize_through_output_chain(server_scan_result)
        curves = wire_json["server_scan_results"][0]["scan_result"]["elliptic_curves"]["result"]

        # Then the boolean answer is real, but the unpopulated lists are null rather than empty/denied lists
        assert curves["supports_ecdh_key_exchange"] is False
        assert curves["supported_curves"] is None
        assert curves["rejected_curves"] is None

        parsed_result = parsed_model.server_scan_results[0].scan_result.elliptic_curves.result
        assert parsed_result.supported_curves is None
        assert parsed_result.rejected_curves is None

    def test_a_none_coerced_to_false_variant_is_rejected(self):
        # Guard against a serializer variant that would force None -> false/[]: build the legitimate partial
        # report, then apply exactly that coercion to the on-the-wire JSON. The contract asserts this output
        # is invalid, i.e. such a variant could not pass these tests.
        server_scan_result = _server_scan_result(
            _build_all_attempts(
                {
                    "certificate_info": _certificate_info_attempt(),
                    "elliptic_curves": _elliptic_curves_unsupported_attempt(),
                }
            )
        )
        json_model = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.model_validate(server_scan_result)],
            invalid_server_strings=[],
            date_scans_started=datetime.now(timezone.utc),
            date_scans_completed=datetime.now(timezone.utc),
        )
        wire = json.loads(json_model.model_dump_json())

        # Simulate the buggy variant: recursively turn JSON null into false for booleans, and [] for lists
        def coerce_nulls(node):
            if isinstance(node, dict):
                return {key: coerce_nulls(value) for key, value in node.items()}
            if isinstance(node, list):
                return [coerce_nulls(item) for item in node]
            if node is None:
                return False
            return node

        corrupted = coerce_nulls(wire)
        cert_deployment = corrupted["server_scan_results"][0]["scan_result"]["certificate_info"]["result"][
            "certificate_deployments"
        ][0]

        # The corrupted variant fabricates negative findings out of unknowns ...
        assert cert_deployment["verified_chain_has_sha1_signature"] is False
        assert cert_deployment["ocsp_response_is_trusted"] is False
        curves = corrupted["server_scan_results"][0]["scan_result"]["elliptic_curves"]["result"]
        assert curves["supported_curves"] is False

        # ... and the contract explicitly rejects it: those fields must be null in the genuine report
        genuine = wire["server_scan_results"][0]["scan_result"]
        assert (
            genuine["certificate_info"]["result"]["certificate_deployments"][0][
                "verified_chain_has_sha1_signature"
            ]
            is None
        )
        assert (
            genuine["certificate_info"]["result"]["certificate_deployments"][0]["ocsp_response_is_trusted"]
            is None
        )
        assert genuine["elliptic_curves"]["result"]["supported_curves"] is None
        # And unscheduled attempts must keep a null result rather than being turned into a false value
        assert genuine["heartbleed"]["result"] is None


# --------------------------------------------------------------------------------------------------
# 4. TLS version results: supported vs unsupported versions stay distinguishable
# --------------------------------------------------------------------------------------------------

class TestTlsVersionResultsRemainDistinguishable:
    def test_supported_and_unsupported_tls_versions_keep_their_facts(self):
        # Given a server supporting TLS 1.2/1.3 but not SSL 3.0
        server_scan_result = _server_scan_result(
            _build_all_attempts(
                {
                    "tls_1_2_cipher_suites": _cipher_suites_attempt(TlsVersionEnum.TLS_1_2, True),
                    "tls_1_3_cipher_suites": _cipher_suites_attempt(TlsVersionEnum.TLS_1_3, True),
                    "ssl_3_0_cipher_suites": _cipher_suites_attempt(TlsVersionEnum.SSL_3_0, False),
                }
            )
        )

        # When serialized
        wire_json, parsed_model = _serialize_through_output_chain(server_scan_result)
        scan_result = wire_json["server_scan_results"][0]["scan_result"]

        # Then the supported versions expose accepted ciphers and a true support flag
        tls_1_2 = scan_result["tls_1_2_cipher_suites"]["result"]
        assert tls_1_2["tls_version_used"] == "TLS_1_2"
        assert tls_1_2["is_tls_version_supported"] is True
        assert len(tls_1_2["accepted_cipher_suites"]) == 1
        assert tls_1_2["accepted_cipher_suites"][0]["ephemeral_key"] is None
        assert tls_1_2["rejected_cipher_suites"] == []

        # And the unsupported version is still a COMPLETED check (it ran!) with an explicit false flag and
        # rejection context - it must not be conflated with NOT_SCHEDULED
        ssl_3 = scan_result["ssl_3_0_cipher_suites"]["result"]
        assert scan_result["ssl_3_0_cipher_suites"]["status"] == "COMPLETED"
        assert ssl_3["tls_version_used"] == "SSL_3_0"
        assert ssl_3["is_tls_version_supported"] is False
        assert ssl_3["accepted_cipher_suites"] == []
        assert len(ssl_3["rejected_cipher_suites"]) == 1
        assert ssl_3["rejected_cipher_suites"][0]["error_message"] == "TLS Alert: handshake failure"

        # And a version never tested stays NOT_SCHEDULED with no result at all
        assert scan_result["tls_1_0_cipher_suites"]["status"] == "NOT_SCHEDULED"
        assert scan_result["tls_1_0_cipher_suites"]["result"] is None

        # And reading back preserves the three different states
        parsed_attempts = parsed_model.server_scan_results[0].scan_result
        assert parsed_attempts.tls_1_2_cipher_suites.result.is_tls_version_supported is True
        assert parsed_attempts.ssl_3_0_cipher_suites.result.is_tls_version_supported is False
        assert (
            parsed_attempts.tls_1_0_cipher_suites.status
            == ScanCommandAttemptStatusEnum.NOT_SCHEDULED
        )
        assert parsed_attempts.tls_1_0_cipher_suites.result is None


# --------------------------------------------------------------------------------------------------
# 5. A legitimate full report keeps its usable, documented on-disk format
# --------------------------------------------------------------------------------------------------

class TestCompleteReportKeepsDocumentedFormat:
    def test_full_report_round_trips_with_all_fields_and_values(self):
        # Given a scan where every applicable command completed with real results
        server_scan_result = _server_scan_result(_build_all_attempts(_full_successful_attempts()))

        # When going through the exact CLI output chain (including indentation style)
        json_model = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.model_validate(server_scan_result)],
            invalid_server_strings=[],
            date_scans_started=datetime.now(timezone.utc),
            date_scans_completed=datetime.now(timezone.utc),
        )
        json_as_str = json_model.model_dump_json(indent=2)
        parsed = SslyzeOutputAsJson.model_validate_json(json_as_str)
        wire = json.loads(json_as_str)

        # Then the root envelope keeps its documented shape
        assert set(wire.keys()) == {
            "invalid_server_strings",
            "server_scan_results",
            "date_scans_started",
            "date_scans_completed",
            "sslyze_version",
            "sslyze_url",
        }
        assert wire["invalid_server_strings"] == []
        assert len(wire["server_scan_results"]) == 1

        # And every scheduled attempt is COMPLETED and carries its result (the report is still usable)
        scan_result = wire["server_scan_results"][0]["scan_result"]
        for command_name, attempt in scan_result.items():
            assert attempt["status"] == "COMPLETED", command_name
            assert attempt["error_reason"] is None
            assert attempt["error_trace"] is None
            assert attempt["result"] is not None

        # And representative facts survive the round trip with their original values
        assert scan_result["heartbleed"]["result"]["is_vulnerable_to_heartbleed"] is False
        assert scan_result["tls_fallback_scsv"]["result"]["supports_fallback_scsv"] is True
        assert scan_result["robot"]["result"]["robot_result"] == "NOT_VULNERABLE_NO_ORACLE"
        assert (
            scan_result["session_resumption"]["result"]["session_id_resumption_result"]
            == "FULLY_SUPPORTED"
        )
        assert (
            scan_result["session_resumption"]["result"]["tls_ticket_resumption_result"]
            == "PARTIALLY_SUPPORTED"
        )
        assert scan_result["tls_1_2_cipher_suites"]["result"]["is_tls_version_supported"] is True

        # And the parsed model is fully populated (pydantic did not need defaults or drop fields)
        parsed_scan = parsed.server_scan_results[0].scan_result
        assert parsed_scan.heartbleed.result.is_vulnerable_to_heartbleed is False
        assert parsed_scan.tls_fallback_scsv.result.supports_fallback_scsv is True
        assert (
            parsed_scan.session_resumption.result.session_id_successful_resumptions_count == 5
        )
        assert parsed_scan.elliptic_curves.result.supported_curves[0].name == "prime256v1"

    def test_full_report_is_accepted_by_the_forbid_extra_models(self):
        # The JSON models use extra="forbid"; a well-formed report must validate cleanly, proving the
        # contract does not require any rename or removal of existing fields.
        server_scan_result = _server_scan_result(_build_all_attempts(_full_successful_attempts()))
        json_model = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.model_validate(server_scan_result)],
            invalid_server_strings=[],
            date_scans_started=datetime.now(timezone.utc),
            date_scans_completed=datetime.now(timezone.utc),
        )
        parsed = SslyzeOutputAsJson.model_validate_json(json_model.model_dump_json())
        assert parsed.sslyze_version
        assert parsed.server_scan_results[0].scan_status == ServerScanStatusEnum.COMPLETED
        assert (
            parsed.server_scan_results[0].connectivity_status
            == ServerConnectivityStatusEnum.COMPLETED
        )
        assert parsed.server_scan_results[0].connectivity_result.cipher_suite_supported == (
            "AES256-GCM-SHA384"
        )

    @pytest.mark.parametrize(
        "command_name",
        sorted(AllScanCommandsAttempts.__dataclass_fields__.keys()),
    )
    def test_every_plugin_attempt_uses_the_common_status_contract(self, command_name):
        # Cross-plugin invariant: every scan command, regardless of plugin, serializes the same three
        # context fields plus a status drawn from the shared enum.
        server_scan_result = _server_scan_result(_build_all_attempts())
        wire_json, _ = _serialize_through_output_chain(server_scan_result)
        attempt = wire_json["server_scan_results"][0]["scan_result"][command_name]

        assert set(attempt.keys()) == {"status", "error_reason", "error_trace", "result"}
        assert attempt["status"] in {status.value for status in ScanCommandAttemptStatusEnum}
        assert attempt["status"] == "NOT_SCHEDULED"
        assert attempt["error_reason"] is None
        assert attempt["error_trace"] is None
        assert attempt["result"] is None
