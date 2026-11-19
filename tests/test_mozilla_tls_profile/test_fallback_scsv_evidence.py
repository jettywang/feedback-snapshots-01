"""Offline checks that the Mozilla checker only flags SCSV weakness on positive evidence."""

from unittest.mock import Mock

from sslyze.mozilla_tls_profile.tls_config_checker import _check_tls_vulnerabilities
from sslyze.plugins.fallback_scsv_plugin import (
    FallbackScsvConclusionEnum,
    FallbackScsvHandshakeObservation,
    FallbackScsvHandshakeOutcomeEnum,
    FallbackScsvInconclusiveReasonEnum,
    FallbackScsvScanResult,
)
from sslyze.server_connectivity import TlsVersionEnum


def _scan_result_with_fallback(fallback_result: FallbackScsvScanResult) -> Mock:
    scan_result = Mock()
    scan_result.tls_compression.result.supports_compression = False
    scan_result.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection = False
    scan_result.tls_fallback_scsv.result = fallback_result
    scan_result.heartbleed.result.is_vulnerable_to_heartbleed = False
    scan_result.robot.result.robot_result = None
    scan_result.session_renegotiation.result.supports_secure_renegotiation = True
    scan_result.tls_extended_master_secret.result.supports_ems_extension = True
    return scan_result


def _fallback_result(conclusion: FallbackScsvConclusionEnum) -> FallbackScsvScanResult:
    return FallbackScsvScanResult(
        conclusion=conclusion,
        supports_fallback_scsv=True
        if conclusion == FallbackScsvConclusionEnum.SUPPORTED
        else (False if conclusion == FallbackScsvConclusionEnum.NOT_SUPPORTED else None),
        inconclusive_reason=(
            None
            if conclusion != FallbackScsvConclusionEnum.INCONCLUSIVE
            else FallbackScsvInconclusiveReasonEnum.DOWNGRADE_TIMED_OUT
        ),
        baseline_observation=FallbackScsvHandshakeObservation(
            tls_version_attempted=TlsVersionEnum.TLS_1_1,
            scsv_enabled=False,
            outcome=FallbackScsvHandshakeOutcomeEnum.COMPLETED,
            negotiated_tls_version=TlsVersionEnum.TLS_1_1,
            alert_or_error=None,
        ),
        downgrade_observation=FallbackScsvHandshakeObservation(
            tls_version_attempted=TlsVersionEnum.TLS_1_1,
            scsv_enabled=True,
            outcome=FallbackScsvHandshakeOutcomeEnum.TIMED_OUT,
            negotiated_tls_version=None,
            alert_or_error="Connection to server timed out during the TLS handshake",
        ),
    )


def test_not_supported_is_reported_as_vulnerability() -> None:
    issues = _check_tls_vulnerabilities(
        _scan_result_with_fallback(_fallback_result(FallbackScsvConclusionEnum.NOT_SUPPORTED))
    )
    assert "tls_vulnerability_fallback_scsv" in issues


def test_supported_is_not_reported() -> None:
    issues = _check_tls_vulnerabilities(
        _scan_result_with_fallback(_fallback_result(FallbackScsvConclusionEnum.SUPPORTED))
    )
    assert "tls_vulnerability_fallback_scsv" not in issues


def test_inconclusive_is_not_reported_as_vulnerability() -> None:
    # Missing evidence (here a timeout) must not be turned into a definitive vulnerability finding
    issues = _check_tls_vulnerabilities(
        _scan_result_with_fallback(_fallback_result(FallbackScsvConclusionEnum.INCONCLUSIVE))
    )
    assert "tls_vulnerability_fallback_scsv" not in issues
