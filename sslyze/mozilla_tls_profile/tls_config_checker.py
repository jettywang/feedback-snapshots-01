import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional, Set, Dict, List, Callable

import pydantic
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, DhEphemeralKeyInfo

from sslyze import (
    ServerScanResult,
    ServerScanStatusEnum,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    CertificateInfoScanResult,
    AllScanCommandsAttempts,
    CipherSuitesScanResult,
    RobotScanResultEnum,
    SupportedEllipticCurvesScanResult,
)
from sslyze.plugins.http_headers_plugin import HttpHeadersScanResult


class _MozillaCiphersAsJson(pydantic.BaseModel):
    caddy: Set[str]
    go: Set[str]
    iana: Set[str]
    openssl: Set[str]


# ANSI X9.62 name (used by the Mozilla TLS profiles) -> SECG name
# Based on https://www.rfc-editor.org/rfc/rfc8422.html#appendix-A
_MOZILLA_CURVE_NAME_TO_SECG_CURVE_NAME = {
    "prime256v1": "secp256r1",
    "prime192v1": "secp192r1",
}


def _convert_mozilla_curve_name_to_secg_name(mozilla_curves: Set[str]) -> Set[str]:
    # Some curves use the ANSI X9.62 name in the Mozilla TLS profiles; convert the names to SECG names
    mozilla_curves_secg_names = set()
    for curve_name in mozilla_curves:
        try:
            final_curve_name = _MOZILLA_CURVE_NAME_TO_SECG_CURVE_NAME[curve_name]
        except KeyError:
            final_curve_name = curve_name
        mozilla_curves_secg_names.add(final_curve_name)

    return mozilla_curves_secg_names


class TlsConfigurationAsJson(pydantic.BaseModel):
    certificate_curves: Annotated[Set[str], pydantic.AfterValidator(_convert_mozilla_curve_name_to_secg_name)]
    certificate_signatures: Set[str]
    certificate_types: Set[str]
    ciphersuites: Set[str]
    ciphers: _MozillaCiphersAsJson
    dh_param_size: Optional[int]
    ecdh_param_size: int
    hsts_min_age: int
    maximum_certificate_lifespan: int
    ocsp_staple: bool
    recommended_certificate_lifespan: int
    rsa_key_size: Optional[int]
    server_preferred_order: bool
    tls_curves: Annotated[Set[str], pydantic.AfterValidator(_convert_mozilla_curve_name_to_secg_name)]
    tls_versions: Set[str]


class _AllMozillaTlsConfigurationsAsJson(pydantic.BaseModel):
    modern: TlsConfigurationAsJson
    intermediate: TlsConfigurationAsJson
    old: TlsConfigurationAsJson


class _MozillaTlsProfileAsJson(pydantic.BaseModel):
    version: float
    href: str
    configurations: _AllMozillaTlsConfigurationsAsJson


class TlsConfigurationEnum(str, Enum):
    MOZILLA_MODERN = "modern"
    MOZILLA_INTERMEDIATE = "intermediate"
    MOZILLA_OLD = "old"
    CUSTOM = "custom"


class TlsConfigurationCheckStatusEnum(str, Enum):
    """The status of a single compliance criterion, or of the compliance check as a whole.

    COMPLIANT: the criterion was evaluated and no issue was detected.
    NOT_COMPLIANT: the criterion was evaluated and an issue was detected; the issue description is available in
        ``TlsConfigurationCriterionCheckResult.issue_description``.
    NOT_RUN: the scan command(s) the criterion depends on were not scheduled or did not run, so the criterion could
        not be evaluated. This must never be treated as "compliant": an empty cipher suite list or a default boolean
        value coming from a missing scan result is not evidence of compliance.
    ERROR: the scan command(s) the criterion depends on returned an error, so the criterion could not be evaluated.
    """

    COMPLIANT = "COMPLIANT"
    NOT_COMPLIANT = "NOT_COMPLIANT"
    NOT_RUN = "NOT_RUN"
    ERROR = "ERROR"


# The statuses that mean the criterion could not actually be evaluated
INDETERMINATE_CRITERION_STATUSES = {
    TlsConfigurationCheckStatusEnum.NOT_RUN,
    TlsConfigurationCheckStatusEnum.ERROR,
}


@dataclass(frozen=True)
class TlsConfigurationCriterionCheckResult:
    """The result of checking the server against a single criterion of the TLS configuration.

    Attributes:
        criterion_name: The criterion that was checked; matches the issue keys historically returned by the checker
            (``tls_versions``, ``ciphers``, ``certificate_path_validation``, etc.).
        status: Whether the criterion is compliant, not compliant, or could not be evaluated.
        issue_description: A human-readable description of the detected issue; ``None`` if no issue was detected or if
            the criterion could not be evaluated.
        dependencies: The scan commands the criterion depends on and the status of each one of them. The distinction
            between NOT_SCHEDULED ("not run") and ERROR is preserved.
    """

    criterion_name: str
    status: TlsConfigurationCheckStatusEnum
    issue_description: Optional[str]
    dependencies: Dict[ScanCommand, ScanCommandAttemptStatusEnum]


@dataclass(frozen=True)
class TlsConfigurationCheckResult:
    """The result of checking a server against a TLS configuration.

    Confirmed violations are always surfaced through the criteria whose dependencies completed successfully, even when
    the check as a whole cannot be decided. ``overall_status`` is therefore independent of the individual criteria:
    it is COMPLIANT or NOT_COMPLIANT only when every criterion could be evaluated, and NOT_RUN/ERROR otherwise.

    Attributes:
        overall_status: Whether the server can be deemed compliant, not compliant, or whether the check is
            indeterminate because some required scan commands did not run or returned an error.
        criteria: The result of each criterion of the TLS configuration, including the scan commands it depends on.
    """

    overall_status: TlsConfigurationCheckStatusEnum
    criteria: List[TlsConfigurationCriterionCheckResult]

    @property
    def is_compliant(self) -> bool:
        """True only if the check is fully decided and every criterion is compliant."""
        return self.overall_status == TlsConfigurationCheckStatusEnum.COMPLIANT

    @property
    def indeterminate_criteria(self) -> List[TlsConfigurationCriterionCheckResult]:
        """The criteria that could not be evaluated because their dependencies did not run or returned an error."""
        return [criterion for criterion in self.criteria if criterion.status in INDETERMINATE_CRITERION_STATUSES]

    @property
    def issues(self) -> Dict[str, str]:
        """The criteria that were actually evaluated and found not compliant, keyed by criterion name."""
        return {
            criterion.criterion_name: criterion.issue_description
            for criterion in self.criteria
            if criterion.status == TlsConfigurationCheckStatusEnum.NOT_COMPLIANT and criterion.issue_description
        }


class ServerScanResultIncomplete(Exception):
    """Raised when the server scan itself was not completed and the compliance check cannot run at all."""


SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER: Set[ScanCommand] = {
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.HEARTBLEED,
    ScanCommand.ROBOT,
    ScanCommand.OPENSSL_CCS_INJECTION,
    ScanCommand.TLS_FALLBACK_SCSV,
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.SESSION_RENEGOTIATION,
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.ELLIPTIC_CURVES,
    ScanCommand.TLS_EXTENDED_MASTER_SECRET,
    # ScanCommand.HTTP_HEADERS,  # Disabled for now; see below
}


# The scan commands each criterion depends on. Every criterion declares at least one dependency so that a missing
# scan command can never silently look like a successful check (e.g. an empty accepted cipher suite list, or a
# boolean defaulting to False).
_CRITERION_DEPENDENCIES: Dict[str, Set[ScanCommand]] = {
    "certificate_path_validation": {ScanCommand.CERTIFICATE_INFO},
    "certificate_curves": {ScanCommand.CERTIFICATE_INFO},
    "rsa_key_size": {ScanCommand.CERTIFICATE_INFO},
    "certificate_types": {ScanCommand.CERTIFICATE_INFO},
    "certificate_signatures": {ScanCommand.CERTIFICATE_INFO},
    "maximum_certificate_lifespan": {ScanCommand.CERTIFICATE_INFO},
    "tls_versions": {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
    },
    "ciphersuites": {ScanCommand.TLS_1_3_CIPHER_SUITES},
    "ciphers": {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
    },
    "ecdh_param_size": {
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
    },
    "dh_param_size": {
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
    },
    "tls_curves": {ScanCommand.ELLIPTIC_CURVES},
    "tls_vulnerability_compression": {ScanCommand.TLS_COMPRESSION},
    "tls_vulnerability_ccs_injection": {ScanCommand.OPENSSL_CCS_INJECTION},
    "tls_vulnerability_fallback_scsv": {ScanCommand.TLS_FALLBACK_SCSV},
    "tls_vulnerability_heartbleed": {ScanCommand.HEARTBLEED},
    "tls_vulnerability_robot": {ScanCommand.ROBOT},
    "tls_vulnerability_renegotiation": {ScanCommand.SESSION_RENEGOTIATION},
    "tls_vulnerability_extended_master_secret": {ScanCommand.TLS_EXTENDED_MASTER_SECRET},
}


class MozillaTlsConfiguration:
    _JSON_PROFILE_PATH = Path(__file__).parent.absolute() / "5.7.json"

    @classmethod
    def get(cls, tls_configuration_enum: TlsConfigurationEnum) -> TlsConfigurationAsJson:
        json_profile_as_str = cls._JSON_PROFILE_PATH.read_text()
        parsed_profile = _MozillaTlsProfileAsJson(**json.loads(json_profile_as_str))
        tls_config = getattr(parsed_profile.configurations, tls_configuration_enum.value)
        return tls_config


def check_server_against_tls_configuration(
    server_scan_result: ServerScanResult,
    tls_config_to_check_against: TlsConfigurationAsJson,
) -> TlsConfigurationCheckResult:
    """Check a server scan result against a TLS configuration and return the outcome as a structured result.

    The check never raises to signal a compliance outcome anymore. Instead:

    * criteria whose dependencies completed are evaluated and reported as COMPLIANT or NOT_COMPLIANT; confirmed
      violations are always surfaced, even if the overall check ends up being indeterminate;
    * criteria whose dependencies did not run (NOT_SCHEDULED) or returned an error are reported as NOT_RUN or ERROR
      respectively, along with the status of each dependency, instead of being mistaken for a passing check;
    * ``overall_status`` is COMPLIANT/NOT_COMPLIANT only when every criterion could be evaluated, and NOT_RUN/ERROR
      otherwise.
    """
    # The scan itself has to be completed; without this there is nothing to check
    if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
        raise ServerScanResultIncomplete("The server scan was not completed.")
    assert server_scan_result.scan_result

    # Collect the status of every scan command the checker needs, preserving the difference between "not run"
    # (NOT_SCHEDULED) and "error"
    dependencies_status: Dict[ScanCommand, ScanCommandAttemptStatusEnum] = {}
    for scan_command in SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER:
        scan_cmd_attempt = getattr(server_scan_result.scan_result, scan_command.value)
        dependencies_status[scan_command] = scan_cmd_attempt.status

    # Evaluate every criterion independently; a missing dependency only skips that criterion, it does not abort the
    # whole check nor get interpreted as compliance
    criteria_results: List[TlsConfigurationCriterionCheckResult] = []
    for criterion_name, criterion_dependencies in _CRITERION_DEPENDENCIES.items():
        criterion_dependencies_status = {
            scan_command: dependencies_status[scan_command] for scan_command in criterion_dependencies
        }
        criterion_status = _criterion_status_from_dependencies(criterion_dependencies_status)
        issue_description: Optional[str] = None

        if criterion_status == TlsConfigurationCheckStatusEnum.COMPLIANT:
            issue_description = _CRITERION_CHECKERS[criterion_name](
                server_scan_result.scan_result, tls_config_to_check_against
            )
            if issue_description:
                criterion_status = TlsConfigurationCheckStatusEnum.NOT_COMPLIANT

        criteria_results.append(
            TlsConfigurationCriterionCheckResult(
                criterion_name=criterion_name,
                status=criterion_status,
                issue_description=issue_description,
                dependencies=criterion_dependencies_status,
            )
        )

    overall_status = _compute_overall_status(criteria_results)
    return TlsConfigurationCheckResult(overall_status=overall_status, criteria=criteria_results)


def _criterion_status_from_dependencies(
    dependencies_status: Dict[ScanCommand, ScanCommandAttemptStatusEnum],
) -> TlsConfigurationCheckStatusEnum:
    # An error on any dependency takes precedence: the criterion could not be evaluated because a plugin failed
    if ScanCommandAttemptStatusEnum.ERROR in dependencies_status.values():
        return TlsConfigurationCheckStatusEnum.ERROR
    # The criterion can only be evaluated if every dependency actually completed
    if all(status == ScanCommandAttemptStatusEnum.COMPLETED for status in dependencies_status.values()):
        return TlsConfigurationCheckStatusEnum.COMPLIANT
    # Some dependencies were never scheduled ("not run")
    return TlsConfigurationCheckStatusEnum.NOT_RUN


def _compute_overall_status(
    criteria_results: List[TlsConfigurationCriterionCheckResult],
) -> TlsConfigurationCheckStatusEnum:
    # The overall outcome is independent of the individual criteria: it is decidable only when every criterion could
    # be evaluated. Unknowns are neither counted as compliant nor as not compliant.
    if any(criterion.status == TlsConfigurationCheckStatusEnum.ERROR for criterion in criteria_results):
        return TlsConfigurationCheckStatusEnum.ERROR
    if any(criterion.status == TlsConfigurationCheckStatusEnum.NOT_RUN for criterion in criteria_results):
        return TlsConfigurationCheckStatusEnum.NOT_RUN
    if any(criterion.status == TlsConfigurationCheckStatusEnum.NOT_COMPLIANT for criterion in criteria_results):
        return TlsConfigurationCheckStatusEnum.NOT_COMPLIANT
    return TlsConfigurationCheckStatusEnum.COMPLIANT


@dataclass(frozen=True)
class _ParsedTlsVersionsAndCiphers:
    tls_versions_supported: Set[str]
    cipher_suites_supported: Set[str]
    tls_1_3_cipher_suites_supported: Set[str]
    curves_supported: Set[str]
    smallest_ecdh_param_size: int
    smallest_dh_param_size: int


def _parse_tls_versions_and_ciphers(scan_result: AllScanCommandsAttempts) -> _ParsedTlsVersionsAndCiphers:
    tls_versions_supported = set()
    cipher_suites_supported = set()
    tls_1_3_cipher_suites_supported = set()
    curves_supported = set()
    smallest_ecdh_param_size = 100000
    smallest_dh_param_size = 100000
    for field_name, tls_version_name in [
        ("ssl_2_0_cipher_suites", "SSLv2"),
        ("ssl_3_0_cipher_suites", "SSLv3"),
        ("tls_1_0_cipher_suites", "TLSv1"),
        ("tls_1_1_cipher_suites", "TLSv1.1"),
        ("tls_1_2_cipher_suites", "TLSv1.2"),
        ("tls_1_3_cipher_suites", "TLSv1.3"),
    ]:
        tls_scan_result: CipherSuitesScanResult = getattr(scan_result, field_name).result
        if tls_scan_result.is_tls_version_supported:
            tls_versions_supported.add(tls_version_name)
            for accepted_cipher_suite in tls_scan_result.accepted_cipher_suites:
                if tls_version_name == "TLSv1.3":
                    tls_1_3_cipher_suites_supported.add(accepted_cipher_suite.cipher_suite.name)
                else:
                    cipher_suites_supported.add(accepted_cipher_suite.cipher_suite.name)

                ephemeral_key = accepted_cipher_suite.ephemeral_key
                if isinstance(ephemeral_key, EcDhEphemeralKeyInfo):
                    curves_supported.add(ephemeral_key.curve_name)
                    actual_key_size = ephemeral_key.size + 3  # OpenSSL returns 253 instead of 255 for the secret key
                    smallest_ecdh_param_size = min([smallest_ecdh_param_size, actual_key_size])

                elif isinstance(ephemeral_key, DhEphemeralKeyInfo):
                    smallest_dh_param_size = min([smallest_dh_param_size, ephemeral_key.size])

    return _ParsedTlsVersionsAndCiphers(
        tls_versions_supported=tls_versions_supported,
        cipher_suites_supported=cipher_suites_supported,
        tls_1_3_cipher_suites_supported=tls_1_3_cipher_suites_supported,
        curves_supported=curves_supported,
        smallest_ecdh_param_size=smallest_ecdh_param_size,
        smallest_dh_param_size=smallest_dh_param_size,
    )


def _check_tls_versions(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    parsed_results = _parse_tls_versions_and_ciphers(scan_result)
    tls_versions_difference = parsed_results.tls_versions_supported - tls_config.tls_versions
    if tls_versions_difference:
        return f"TLS versions {tls_versions_difference} are supported, but should be rejected."
    return None


def _check_tls_1_3_cipher_suites(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    parsed_results = _parse_tls_versions_and_ciphers(scan_result)
    tls_1_3_cipher_suites_difference = parsed_results.tls_1_3_cipher_suites_supported - tls_config.ciphersuites
    if tls_1_3_cipher_suites_difference:
        return (
            f"TLS 1.3 cipher suites {tls_1_3_cipher_suites_difference} are supported, but should be rejected."
        )
    return None


def _check_cipher_suites(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    parsed_results = _parse_tls_versions_and_ciphers(scan_result)
    cipher_suites_difference = parsed_results.cipher_suites_supported - tls_config.ciphers.iana
    if cipher_suites_difference:
        return f"Cipher suites {cipher_suites_difference} are supported, but should be rejected."
    return None


def _check_ecdh_param_size(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    parsed_results = _parse_tls_versions_and_ciphers(scan_result)
    if tls_config.ecdh_param_size and parsed_results.smallest_ecdh_param_size < tls_config.ecdh_param_size:
        return (
            f"ECDH parameter size is {parsed_results.smallest_ecdh_param_size},"
            f" should be superior or equal to {tls_config.ecdh_param_size}."
        )
    return None


def _check_dh_param_size(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    parsed_results = _parse_tls_versions_and_ciphers(scan_result)
    if tls_config.dh_param_size and parsed_results.smallest_dh_param_size < tls_config.dh_param_size:
        return (
            f"DH parameter size is {parsed_results.smallest_dh_param_size},"
            f" should be superior or equal to {tls_config.dh_param_size}."
        )
    return None


def _check_tls_curves(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    tls_curves_result: SupportedEllipticCurvesScanResult = scan_result.elliptic_curves.result
    if tls_curves_result.supported_curves:
        supported_curves = {curve.name for curve in tls_curves_result.supported_curves}
    else:
        supported_curves = set()

    tls_curves_difference = supported_curves - tls_config.tls_curves
    if tls_curves_difference:
        return f"TLS curves {tls_curves_difference} are supported, but should be rejected."
    return None


def _check_tls_vulnerability_compression(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    if scan_result.tls_compression.result.supports_compression:
        return "Server is vulnerable to TLS compression attacks."
    return None


def _check_tls_vulnerability_ccs_injection(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    if scan_result.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection:
        return "Server is vulnerable to the OpenSSL CCS injection attack."
    return None


def _check_tls_vulnerability_fallback_scsv(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    if not scan_result.tls_fallback_scsv.result.supports_fallback_scsv:
        return (
            "Server is vulnerable to TLS downgrade attacks because it does not support the TLS_FALLBACK_SCSV mechanism."
        )
    return None


def _check_tls_vulnerability_heartbleed(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    if scan_result.heartbleed.result.is_vulnerable_to_heartbleed:
        return "Server is vulnerable to the OpenSSL Heartbleed attack."
    return None


def _check_tls_vulnerability_robot(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    if scan_result.robot.result.robot_result == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
        return "Server is vulnerable to the ROBOT attack."
    return None


def _check_tls_vulnerability_renegotiation(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    if not scan_result.session_renegotiation.result.supports_secure_renegotiation:
        return "Server is vulnerable to the insecure renegotiation attack."
    return None


def _check_tls_vulnerability_extended_master_secret(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    if not scan_result.tls_extended_master_secret.result.supports_ems_extension:
        return "Server does not support the Extended Master Secret TLS extension."
    return None


def _check_certificate_path_validation(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    cert_info_result: CertificateInfoScanResult = scan_result.certificate_info.result
    for cert_deployment in cert_info_result.certificate_deployments:
        leaf_cert = cert_deployment.received_certificate_chain[0]
        if not cert_deployment.verified_certificate_chain:
            return f"Certificate path validation failed for {leaf_cert.subject.rfc4514_string()}."
    return None


def _check_certificate_curves(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    cert_info_result = scan_result.certificate_info.result
    for cert_deployment in cert_info_result.certificate_deployments:
        leaf_cert = cert_deployment.received_certificate_chain[0]
        public_key = leaf_cert.public_key()
        if (
            isinstance(public_key, EllipticCurvePublicKey)
            and public_key.curve.name not in tls_config.certificate_curves
        ):
            return (
                f"Certificate curve is {public_key.curve.name},"
                f" should be one of {tls_config.certificate_curves}."
            )
    return None


def _check_rsa_key_size(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    cert_info_result = scan_result.certificate_info.result
    for cert_deployment in cert_info_result.certificate_deployments:
        leaf_cert = cert_deployment.received_certificate_chain[0]
        public_key = leaf_cert.public_key()
        if isinstance(public_key, RSAPublicKey):
            if tls_config.rsa_key_size and public_key.key_size < tls_config.rsa_key_size:
                return (
                    f"RSA key size is {public_key.key_size},"
                    f" minimum allowed is {tls_config.rsa_key_size}."
                )
    return None


def _check_certificate_types(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    cert_info_result = scan_result.certificate_info.result
    deployed_key_algorithms = set()
    for cert_deployment in cert_info_result.certificate_deployments:
        leaf_cert = cert_deployment.received_certificate_chain[0]
        public_key = leaf_cert.public_key()
        if isinstance(public_key, EllipticCurvePublicKey):
            deployed_key_algorithms.add("ecdsa")
        elif isinstance(public_key, RSAPublicKey):
            deployed_key_algorithms.add("rsa")
        else:
            deployed_key_algorithms.add(public_key.__class__.__name__)

    # At least one of the Mozilla cert types should have been detected in the server's cert deployments
    if not any(key_algorithm in deployed_key_algorithms for key_algorithm in tls_config.certificate_types):
        return (
            f"Deployed certificate types are {deployed_key_algorithms},"
            f" should have at least one of {tls_config.certificate_types}."
        )
    return None


def _check_certificate_signatures(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    cert_info_result = scan_result.certificate_info.result
    deployed_signature_algorithms = set()
    for cert_deployment in cert_info_result.certificate_deployments:
        leaf_cert = cert_deployment.received_certificate_chain[0]
        deployed_signature_algorithms.add(leaf_cert.signature_algorithm_oid._name)  # type: ignore

    if not any(sig_algorithm in deployed_signature_algorithms for sig_algorithm in tls_config.certificate_signatures):
        return (
            f"Deployed certificate signatures are {deployed_signature_algorithms},"
            f" should have at least one of {tls_config.certificate_signatures}."
        )
    return None


def _check_maximum_certificate_lifespan(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> Optional[str]:
    cert_info_result = scan_result.certificate_info.result
    for cert_deployment in cert_info_result.certificate_deployments:
        leaf_cert = cert_deployment.received_certificate_chain[0]
        leaf_cert_lifespan = leaf_cert.not_valid_after_utc - leaf_cert.not_valid_before_utc
        if leaf_cert_lifespan.days > tls_config.maximum_certificate_lifespan:
            return (
                f"Certificate life span is {leaf_cert_lifespan.days} days,"
                f" should be less than {tls_config.maximum_certificate_lifespan}."
            )
    return None


# Maps each criterion name to the function able to evaluate it. Every function returns the issue description as a
# string, or None when the criterion is compliant. The functions are only called when all their dependencies
# completed, so their scan command results are guaranteed to be set.
_CRITERION_CHECKERS: Dict[str, Callable[[AllScanCommandsAttempts, TlsConfigurationAsJson], Optional[str]]] = {
    "certificate_path_validation": _check_certificate_path_validation,
    "certificate_curves": _check_certificate_curves,
    "rsa_key_size": _check_rsa_key_size,
    "certificate_types": _check_certificate_types,
    "certificate_signatures": _check_certificate_signatures,
    "maximum_certificate_lifespan": _check_maximum_certificate_lifespan,
    "tls_versions": _check_tls_versions,
    "ciphersuites": _check_tls_1_3_cipher_suites,
    "ciphers": _check_cipher_suites,
    "ecdh_param_size": _check_ecdh_param_size,
    "dh_param_size": _check_dh_param_size,
    "tls_curves": _check_tls_curves,
    "tls_vulnerability_compression": _check_tls_vulnerability_compression,
    "tls_vulnerability_ccs_injection": _check_tls_vulnerability_ccs_injection,
    "tls_vulnerability_fallback_scsv": _check_tls_vulnerability_fallback_scsv,
    "tls_vulnerability_heartbleed": _check_tls_vulnerability_heartbleed,
    "tls_vulnerability_robot": _check_tls_vulnerability_robot,
    "tls_vulnerability_renegotiation": _check_tls_vulnerability_renegotiation,
    "tls_vulnerability_extended_master_secret": _check_tls_vulnerability_extended_master_secret,
}


def _check_http_headers(
    http_headers_result: HttpHeadersScanResult,
    tls_config: TlsConfigurationAsJson,
) -> Dict[str, str]:
    issues_with_http_headers = {}

    if not http_headers_result.strict_transport_security_header:
        issues_with_http_headers["hsts_min_age"] = "HSTS header is missing."

    elif not http_headers_result.strict_transport_security_header.max_age:
        issues_with_http_headers["hsts_min_age"] = "HSTS max-age directive is missing."

    else:
        if http_headers_result.strict_transport_security_header.max_age < tls_config.hsts_min_age:
            issues_with_http_headers["hsts_min_age"] = (
                f"HSTS max-age is {http_headers_result.strict_transport_security_header.max_age},"
                f" should be superior or equal to {tls_config.hsts_min_age}."
            )

    return issues_with_http_headers
