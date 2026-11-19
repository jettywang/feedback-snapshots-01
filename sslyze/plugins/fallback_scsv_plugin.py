from dataclasses import dataclass
from enum import Enum, unique
from typing import List, Optional

from nassl import _nassl

from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid, StrFromEnumValueName
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanCommandExtraArgument,
    ScanJob,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
    ScanJobResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum
from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut, ConnectionToServerFailed

_INAPPROPRIATE_FALLBACK_ALERT = "inappropriate fallback"
_PROTOCOL_VERSION_ALERTS = ("tlsv1 alert protocol version", "TLS alert: protocol version")


@unique
class FallbackScsvHandshakeOutcomeEnum(str, Enum):
    """What happened during a single handshake performed for the TLS_FALLBACK_SCSV test.

    Attributes:
        COMPLETED: The handshake completed and the negotiated protocol version is known.
        REJECTED_INAPPROPRIATE_FALLBACK: The server returned the specific "inappropriate fallback" alert (RFC 7507).
        REJECTED_OTHER_ALERT: The server rejected the handshake with an alert other than "inappropriate fallback".
        TIMED_OUT: The TCP connection was established but the TLS handshake timed out.
        CONNECTION_INTERRUPTED: The transport (TCP/TLS) connection failed or was closed by the peer.
        NOT_ATTEMPTED: No handshake was attempted (for example no lower TLS version is available to test).
    """

    COMPLETED = "COMPLETED"
    REJECTED_INAPPROPRIATE_FALLBACK = "REJECTED_INAPPROPRIATE_FALLBACK"
    REJECTED_OTHER_ALERT = "REJECTED_OTHER_ALERT"
    TIMED_OUT = "TIMED_OUT"
    CONNECTION_INTERRUPTED = "CONNECTION_INTERRUPTED"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


@unique
class FallbackScsvConclusionEnum(str, Enum):
    """The conclusion of the TLS_FALLBACK_SCSV test, based only on evidence actually collected.

    Attributes:
        SUPPORTED: Positive evidence proves the server implements TLS_FALLBACK_SCSV (RFC 7507).
        NOT_SUPPORTED: Positive evidence proves the server does not implement TLS_FALLBACK_SCSV.
        INCONCLUSIVE: The available evidence does not allow proving either outcome.
    """

    SUPPORTED = "SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@unique
class FallbackScsvInconclusiveReasonEnum(str, Enum):
    """Why a TLS_FALLBACK_SCSV test ended up being inconclusive.

    Attributes:
        NO_LOWER_TLS_VERSION_AVAILABLE: The highest supported version has no lower version to downgrade to.
        BASELINE_HANDSHAKE_TIMED_OUT: The baseline handshake at the downgrade version timed out.
        BASELINE_CONNECTION_INTERRUPTED: The baseline connection failed before a TLS conclusion could be reached.
        LOWER_VERSION_NOT_SUPPORTED: The server does not support the TLS version the downgrade attempt would use,
            so the downgrade premise (a server that accepts an older version without SCSV) cannot be established.
        BASELINE_REJECTED: The baseline handshake was rejected with an alert that is not a protocol-version alert,
            so the downgrade premise cannot be established.
        DOWNGRADE_TIMED_OUT: The SCSV downgrade attempt timed out instead of returning an alert.
        DOWNGRADE_CONNECTION_INTERRUPTED: The SCSV downgrade attempt's transport was interrupted without an alert.
        DOWNGRADE_REJECTED_WITH_OTHER_ALERT: The SCSV downgrade attempt was rejected, but not with the specific
            "inappropriate fallback" alert, so SCSV enforcement cannot be proven.
        UNEXPECTED_BASELINE_OUTCOME: The baseline handshake produced an outcome that cannot be interpreted.
    """

    NO_LOWER_TLS_VERSION_AVAILABLE = "NO_LOWER_TLS_VERSION_AVAILABLE"
    BASELINE_HANDSHAKE_TIMED_OUT = "BASELINE_HANDSHAKE_TIMED_OUT"
    BASELINE_CONNECTION_INTERRUPTED = "BASELINE_CONNECTION_INTERRUPTED"
    LOWER_VERSION_NOT_SUPPORTED = "LOWER_VERSION_NOT_SUPPORTED"
    BASELINE_REJECTED = "BASELINE_REJECTED"
    DOWNGRADE_TIMED_OUT = "DOWNGRADE_TIMED_OUT"
    DOWNGRADE_CONNECTION_INTERRUPTED = "DOWNGRADE_CONNECTION_INTERRUPTED"
    DOWNGRADE_REJECTED_WITH_OTHER_ALERT = "DOWNGRADE_REJECTED_WITH_OTHER_ALERT"
    UNEXPECTED_BASELINE_OUTCOME = "UNEXPECTED_BASELINE_OUTCOME"


@dataclass(frozen=True)
class FallbackScsvHandshakeObservation:
    """The evidence collected from one handshake performed for the TLS_FALLBACK_SCSV test.

    Attributes:
        tls_version_attempted: The TLS version the client was configured to negotiate.
        scsv_enabled: Whether TLS_FALLBACK_SCSV was enabled in the client hello.
        outcome: What actually happened during the handshake.
        negotiated_tls_version: The protocol version actually negotiated, only known when the handshake completed.
        alert_or_error: The raw alert/error message returned by the server or transport layer, when available.
    """

    tls_version_attempted: TlsVersionEnum
    scsv_enabled: bool
    outcome: FallbackScsvHandshakeOutcomeEnum
    negotiated_tls_version: Optional[TlsVersionEnum]
    alert_or_error: Optional[str]


@dataclass(frozen=True)
class FallbackScsvScanResult(ScanCommandResult):
    """The result of testing a server for the TLS_FALLBACK_SCSV mechanism (RFC 7507).

    Attributes:
        conclusion: The evidence-based conclusion of the test; see FallbackScsvConclusionEnum.
        supports_fallback_scsv: True/False only when the conclusion is backed by positive evidence, None when the
            collected evidence is insufficient to prove either outcome.
        inconclusive_reason: Why the test is inconclusive; None when a definitive conclusion was reached.
        baseline_observation: Evidence from the baseline handshake (lower TLS version, SCSV disabled).
        downgrade_observation: Evidence from the downgrade attempt (same TLS version, SCSV enabled).
    """

    conclusion: FallbackScsvConclusionEnum
    supports_fallback_scsv: Optional[bool]
    inconclusive_reason: Optional[FallbackScsvInconclusiveReasonEnum]
    baseline_observation: FallbackScsvHandshakeObservation
    downgrade_observation: FallbackScsvHandshakeObservation


class FallbackScsvHandshakeObservationAsJson(BaseModelWithOrmModeAndForbid):
    tls_version_attempted: StrFromEnumValueName
    scsv_enabled: bool
    outcome: FallbackScsvHandshakeOutcomeEnum
    negotiated_tls_version: Optional[StrFromEnumValueName]
    alert_or_error: Optional[str]


class FallbackScsvScanResultAsJson(BaseModelWithOrmModeAndForbid):
    conclusion: FallbackScsvConclusionEnum
    supports_fallback_scsv: Optional[bool]
    inconclusive_reason: Optional[FallbackScsvInconclusiveReasonEnum]
    baseline_observation: FallbackScsvHandshakeObservationAsJson
    downgrade_observation: FallbackScsvHandshakeObservationAsJson


class FallbackScsvScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[FallbackScsvScanResultAsJson]


def _tls_version_to_display_name(tls_version: TlsVersionEnum) -> str:
    # TlsVersionEnum.TLS_1_1 -> "TLS 1.1"; TlsVersionEnum.SSL_3_0 -> "SSL 3.0"
    protocol, major, minor = tls_version.name.split("_")
    return f"{protocol} {major}.{minor}"


class _FallbackScsvCliConnector(ScanCommandCliConnector[FallbackScsvScanResult, None]):
    _cli_option = "fallback"
    _cli_description = "Test a server for the TLS_FALLBACK_SCSV mechanism to prevent downgrade attacks."

    @classmethod
    def result_to_console_output(cls, result: FallbackScsvScanResult) -> List[str]:
        result_as_txt = [cls._format_title("Downgrade Attacks")]

        if result.conclusion == FallbackScsvConclusionEnum.SUPPORTED:
            downgrade_txt = "OK - Supported"
        elif result.conclusion == FallbackScsvConclusionEnum.NOT_SUPPORTED:
            downgrade_txt = "VULNERABLE - Signaling cipher suite not supported"
        else:
            assert result.inconclusive_reason
            downgrade_txt = (
                f"UNKNOWN - Could not determine TLS_FALLBACK_SCSV support ({result.inconclusive_reason.value})"
            )
        result_as_txt.append(cls._format_field("TLS_FALLBACK_SCSV:", downgrade_txt))

        for observation in [result.baseline_observation, result.downgrade_observation]:
            result_as_txt.append(cls._format_observation(observation))

        return result_as_txt

    @classmethod
    def _format_observation(cls, observation: FallbackScsvHandshakeObservation) -> str:
        scsv_txt = "SCSV enabled" if observation.scsv_enabled else "SCSV disabled"
        attempted_txt = _tls_version_to_display_name(observation.tls_version_attempted)
        detail_txt = f"{attempted_txt}, {scsv_txt}, outcome: {observation.outcome.value}"
        if observation.negotiated_tls_version is not None:
            negotiated_txt = _tls_version_to_display_name(observation.negotiated_tls_version)
            detail_txt += f", negotiated: {negotiated_txt}"
        if observation.alert_or_error:
            detail_txt += f', alert/error: "{observation.alert_or_error}"'
        return cls._format_field("", detail_txt)


class FallbackScsvImplementation(ScanCommandImplementation[FallbackScsvScanResult, None]):
    """Test a server for the TLS_FALLBACK_SCSV mechanism to prevent downgrade attacks."""

    cli_connector_cls = _FallbackScsvCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        # TLS 1.3 cannot be downgraded through the SCSV mechanism, so the test version is capped at TLS 1.2
        highest_version = server_info.tls_probing_result.highest_tls_version_supported
        if highest_version.value >= TlsVersionEnum.TLS_1_3.value:
            baseline_tls_version = TlsVersionEnum.TLS_1_2
        else:
            baseline_tls_version = highest_version

        # The downgrade is tested on the version immediately below the highest one the server is known to support
        if baseline_tls_version.value > TlsVersionEnum.TLS_1_0.value:
            downgrade_tls_version: Optional[TlsVersionEnum] = TlsVersionEnum(baseline_tls_version.value - 1)
        else:
            # Nothing below TLS 1.0 can be tested through the legacy client; the premise cannot be established
            downgrade_tls_version = None

        if downgrade_tls_version is None:
            return [
                ScanJob(
                    function_to_call=_skipped_observation_job,
                    function_arguments=[server_info, baseline_tls_version],
                )
            ]

        return [
            ScanJob(
                function_to_call=_perform_handshake,
                function_arguments=[server_info, downgrade_tls_version, False],
            ),
            ScanJob(
                function_to_call=_perform_handshake,
                function_arguments=[server_info, downgrade_tls_version, True],
            ),
        ]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> FallbackScsvScanResult:
        if len(scan_job_results) not in [1, 2]:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        if len(scan_job_results) == 1:
            skipped_observation = scan_job_results[0].get_result()
            return _build_result(
                baseline_observation=skipped_observation,
                downgrade_observation=skipped_observation,
            )

        baseline_observation = scan_job_results[0].get_result()
        downgrade_observation = scan_job_results[1].get_result()
        return _build_result(
            baseline_observation=baseline_observation,
            downgrade_observation=downgrade_observation,
        )


def _skipped_observation_job(
    server_info: ServerConnectivityInfo, tls_version: TlsVersionEnum
) -> FallbackScsvHandshakeObservation:
    return FallbackScsvHandshakeObservation(
        tls_version_attempted=tls_version,
        scsv_enabled=False,
        outcome=FallbackScsvHandshakeOutcomeEnum.NOT_ATTEMPTED,
        negotiated_tls_version=None,
        alert_or_error=None,
    )


def _perform_handshake(
    server_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, enable_scsv: bool
) -> FallbackScsvHandshakeObservation:
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version,
        # Only the legacy client has enable_fallback_scsv()
        should_use_legacy_openssl=True,
    )

    if enable_scsv:
        ssl_connection.ssl_client.enable_fallback_scsv()

    outcome = FallbackScsvHandshakeOutcomeEnum.CONNECTION_INTERRUPTED
    alert_or_error: Optional[str] = None
    negotiated_tls_version: Optional[TlsVersionEnum] = None
    try:
        # Perform the SSL handshake
        ssl_connection.connect()
        outcome = FallbackScsvHandshakeOutcomeEnum.COMPLETED
        # The client is pinned to tls_version so a completed handshake means the server negotiated that version
        negotiated_tls_version = tls_version

    except _nassl.OpenSSLError as e:
        alert_or_error = str(e.args[0]) if e.args else str(e)
        if _INAPPROPRIATE_FALLBACK_ALERT in alert_or_error:
            outcome = FallbackScsvHandshakeOutcomeEnum.REJECTED_INAPPROPRIATE_FALLBACK
        else:
            outcome = FallbackScsvHandshakeOutcomeEnum.REJECTED_OTHER_ALERT

    except ServerRejectedTlsHandshake as e:
        alert_or_error = e.error_message
        outcome = FallbackScsvHandshakeOutcomeEnum.REJECTED_OTHER_ALERT

    except TlsHandshakeTimedOut as e:
        alert_or_error = e.error_message
        outcome = FallbackScsvHandshakeOutcomeEnum.TIMED_OUT

    except ConnectionToServerFailed as e:
        # A plain transport failure (TCP reset, connection closed mid-handshake, proxy failure, ...) is evidence of
        # nothing regarding SCSV support; record it instead of turning it into a definitive security conclusion
        alert_or_error = e.error_message
        outcome = FallbackScsvHandshakeOutcomeEnum.CONNECTION_INTERRUPTED

    finally:
        ssl_connection.close()

    return FallbackScsvHandshakeObservation(
        tls_version_attempted=tls_version,
        scsv_enabled=enable_scsv,
        outcome=outcome,
        negotiated_tls_version=negotiated_tls_version,
        alert_or_error=alert_or_error,
    )


def _build_result(
    baseline_observation: FallbackScsvHandshakeObservation,
    downgrade_observation: FallbackScsvHandshakeObservation,
) -> FallbackScsvScanResult:
    # First establish the downgrade premise: the server must actually accept the lower TLS version without SCSV
    if baseline_observation.outcome == FallbackScsvHandshakeOutcomeEnum.NOT_ATTEMPTED:
        return _inconclusive_result(
            baseline_observation,
            downgrade_observation,
            FallbackScsvInconclusiveReasonEnum.NO_LOWER_TLS_VERSION_AVAILABLE,
        )

    if baseline_observation.outcome == FallbackScsvHandshakeOutcomeEnum.TIMED_OUT:
        return _inconclusive_result(
            baseline_observation,
            downgrade_observation,
            FallbackScsvInconclusiveReasonEnum.BASELINE_HANDSHAKE_TIMED_OUT,
        )

    if baseline_observation.outcome == FallbackScsvHandshakeOutcomeEnum.CONNECTION_INTERRUPTED:
        return _inconclusive_result(
            baseline_observation,
            downgrade_observation,
            FallbackScsvInconclusiveReasonEnum.BASELINE_CONNECTION_INTERRUPTED,
        )

    if baseline_observation.outcome == FallbackScsvHandshakeOutcomeEnum.REJECTED_OTHER_ALERT:
        # The server does not support the lower TLS version (or rejects it for another reason); the SCSV downgrade
        # premise can therefore not be established
        alert_text = baseline_observation.alert_or_error or ""
        if any(alert_signature in alert_text for alert_signature in _PROTOCOL_VERSION_ALERTS):
            reason = FallbackScsvInconclusiveReasonEnum.LOWER_VERSION_NOT_SUPPORTED
        else:
            reason = FallbackScsvInconclusiveReasonEnum.BASELINE_REJECTED
        return _inconclusive_result(baseline_observation, downgrade_observation, reason)

    if baseline_observation.outcome != FallbackScsvHandshakeOutcomeEnum.COMPLETED:
        return _inconclusive_result(
            baseline_observation,
            downgrade_observation,
            FallbackScsvInconclusiveReasonEnum.UNEXPECTED_BASELINE_OUTCOME,
        )

    # The downgrade premise is proven: the same lower version works without SCSV. Interpret the SCSV attempt.
    if downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.REJECTED_INAPPROPRIATE_FALLBACK:
        # The specific RFC 7507 alert is positive evidence that the server enforces SCSV
        conclusion = FallbackScsvConclusionEnum.SUPPORTED
        return FallbackScsvScanResult(
            conclusion=conclusion,
            supports_fallback_scsv=True,
            inconclusive_reason=None,
            baseline_observation=baseline_observation,
            downgrade_observation=downgrade_observation,
        )

    if downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.COMPLETED:
        # The server negotiated the downgraded version even though SCSV was signaled: positive evidence of no
        # protection
        conclusion = FallbackScsvConclusionEnum.NOT_SUPPORTED
        return FallbackScsvScanResult(
            conclusion=conclusion,
            supports_fallback_scsv=False,
            inconclusive_reason=None,
            baseline_observation=baseline_observation,
            downgrade_observation=downgrade_observation,
        )

    if downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.TIMED_OUT:
        reason = FallbackScsvInconclusiveReasonEnum.DOWNGRADE_TIMED_OUT
    elif downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.CONNECTION_INTERRUPTED:
        reason = FallbackScsvInconclusiveReasonEnum.DOWNGRADE_CONNECTION_INTERRUPTED
    elif downgrade_observation.outcome == FallbackScsvHandshakeOutcomeEnum.REJECTED_OTHER_ALERT:
        reason = FallbackScsvInconclusiveReasonEnum.DOWNGRADE_REJECTED_WITH_OTHER_ALERT
    else:
        # Only NOT_ATTEMPTED can reach here (all other outcomes were handled above); the two observations
        # are then inconsistent with each other
        reason = FallbackScsvInconclusiveReasonEnum.UNEXPECTED_BASELINE_OUTCOME

    return _inconclusive_result(baseline_observation, downgrade_observation, reason)


def _inconclusive_result(
    baseline_observation: FallbackScsvHandshakeObservation,
    downgrade_observation: FallbackScsvHandshakeObservation,
    reason: FallbackScsvInconclusiveReasonEnum,
) -> FallbackScsvScanResult:
    return FallbackScsvScanResult(
        conclusion=FallbackScsvConclusionEnum.INCONCLUSIVE,
        supports_fallback_scsv=None,
        inconclusive_reason=reason,
        baseline_observation=baseline_observation,
        downgrade_observation=downgrade_observation,
    )
