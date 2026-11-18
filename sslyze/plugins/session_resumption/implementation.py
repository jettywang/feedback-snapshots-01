from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple, Union

from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanCommandExtraArgument,
    ScanJob,
    ScanCommandCliConnector,
    OptParseCliOption,
    ScanJobResult,
)
from sslyze.plugins.session_resumption._resumption_with_id import (
    resume_with_session_id,
    _ScanJobResultEnum,
    TlsResumptionSupportEnum,
    ServerOnlySupportsTls13,
    ResumptionAttemptEvidence,
    ResumptionAttemptOutcomeEnum,
    ResumptionMechanismEnum,
)
from sslyze.plugins.session_resumption._resumption_with_ticket import resume_with_tls_ticket
from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class SessionResumptionSupportExtraArgument(ScanCommandExtraArgument):
    """Additional configuration for running the SESSION_RESUMPTION scan command.

    Attributes:
        number_of_resumptions_to_attempt: The number of session resumptions (both with Session IDs and TLS
            Tickets) that SSLyze should attempt. The default value is 5, but a higher value such as 100 can be used to
            get a more accurate measure of how often session resumption succeeds or fails with the server.
    """

    number_of_resumptions_to_attempt: int


@dataclass(frozen=True)
class SessionResumptionSupportScanResult(ScanCommandResult):
    """The result of testing a server for TLS 1.2 session resumption support, using Session IDs and TLS tickets.

    Attributes:
        session_id_resumption_result: The overall result of session ID resumption testing.
        session_id_attempted_resumptions_count: The total number of session ID resumptions that were attempted.
        session_id_successful_resumptions_count: The number of session ID resumptions that were successful.
        tls_ticket_resumption_result: The overall result of TLS ticket resumption testing.
        tls_ticket_attempted_resumptions_count: The total number of TLS ticket resumptions that were attempted.
        tls_ticket_successful_resumptions_count: The number of TLS ticket resumptions that were successful.
        session_id_attempts: The auditable evidence for each session ID resumption attempt, in completion order.
        tls_ticket_attempts: The auditable evidence for each TLS ticket resumption attempt, in completion order.

    """

    session_id_resumption_result: TlsResumptionSupportEnum
    session_id_attempted_resumptions_count: int
    session_id_successful_resumptions_count: int

    tls_ticket_resumption_result: TlsResumptionSupportEnum
    tls_ticket_attempted_resumptions_count: int
    tls_ticket_successful_resumptions_count: int

    session_id_attempts: Tuple[ResumptionAttemptEvidence, ...] = ()
    tls_ticket_attempts: Tuple[ResumptionAttemptEvidence, ...] = ()


def _resumption_result_to_console_output(
    resumption_result: TlsResumptionSupportEnum,
    successful_resumptions_count: int,
    attempted_resumptions_count: int,
) -> str:
    if resumption_result == TlsResumptionSupportEnum.FULLY_SUPPORTED:
        resumption_support_txt = "OK - Supported"
    elif resumption_result == TlsResumptionSupportEnum.PARTIALLY_SUPPORTED:
        resumption_support_txt = "PARTIALLY SUPPORTED"
    elif resumption_result == TlsResumptionSupportEnum.NOT_SUPPORTED:
        resumption_support_txt = "NOT SUPPORTED"
    else:
        raise ValueError(f"Unexpected value: {resumption_result}")

    resum_rate_txt = (
        f"({successful_resumptions_count} successful resumptions" f" out of {attempted_resumptions_count} attempts)"
    )

    return f"{resumption_support_txt} {resum_rate_txt}"


def _resumption_attempt_to_console_output(attempt_index: int, attempt: ResumptionAttemptEvidence) -> str:
    target_txt = f"{attempt.server_hostname}:{attempt.server_port}"
    connection_config_txt = f"SNI: {attempt.tls_server_name_indication}, {attempt.tls_version_used.name}"

    if attempt.outcome == ResumptionAttemptOutcomeEnum.RESUMED:
        outcome_txt = "RESUMED - the server resumed the initial session"
    elif attempt.outcome == ResumptionAttemptOutcomeEnum.FULL_REHANDSHAKE:
        outcome_txt = "NOT RESUMED - the server performed a full handshake instead"
    elif attempt.outcome == ResumptionAttemptOutcomeEnum.NO_SESSION_ASSIGNED:
        outcome_txt = "NOT RESUMED - the server did not assign a session ID or TLS ticket"
    elif attempt.outcome == ResumptionAttemptOutcomeEnum.INITIAL_HANDSHAKE_FAILED:
        outcome_txt = f"INCOMPLETE - the initial handshake failed ({attempt.error_message})"
    elif attempt.outcome == ResumptionAttemptOutcomeEnum.RESUMPTION_HANDSHAKE_FAILED:
        outcome_txt = f"INCOMPLETE - the resumption handshake failed ({attempt.error_message})"
    else:
        raise ValueError(f"Unexpected value: {attempt.outcome}")

    fingerprints_txt = ""
    if attempt.initial_session_fingerprint:
        fingerprints_txt = f" [initial session sha256: {attempt.initial_session_fingerprint[:16]}..."
        if attempt.resumed_session_fingerprint:
            fingerprints_txt += f", resumed session sha256: {attempt.resumed_session_fingerprint[:16]}..."
        fingerprints_txt += "]"

    return f"        #{attempt_index} {target_txt} ({connection_config_txt}): {outcome_txt}{fingerprints_txt}"


class _SessionResumptionSupportCliConnector(
    ScanCommandCliConnector[SessionResumptionSupportScanResult, SessionResumptionSupportExtraArgument]
):
    _cli_option = "resum"
    _cli_description = "Test a server for TLS 1.2 session resumption support using session IDs and TLS tickets."

    @classmethod
    def get_cli_options(cls) -> List[OptParseCliOption]:
        scan_command_option = super().get_cli_options()
        scan_command_option.append(
            OptParseCliOption(
                option="resum_attempts",
                help="To be used with --resum. Number of session resumptions (both with Session IDs and TLS Tickets)"
                " that SSLyze should attempt."
                " The default value is 5, but a higher value such as 100 can be used to get a more accurate"
                " measure of how often session resumption succeeds or fails with the server.",
                action="store",
            )
        )
        return scan_command_option

    @classmethod
    def find_cli_options_in_command_line(
        cls, parsed_command_line: Dict[str, Union[None, bool, str]]
    ) -> Tuple[bool, Optional[SessionResumptionSupportExtraArgument]]:
        # Check if --resum was used
        is_scan_cmd_enabled, _ = super().find_cli_options_in_command_line(parsed_command_line)

        # Check if --resum_attempts was used
        extra_arguments = None
        try:
            resum_attempts = parsed_command_line["resum_attempts"]
            if resum_attempts:
                try:
                    resum_attempts_as_int = int(resum_attempts)
                    extra_arguments = SessionResumptionSupportExtraArgument(
                        number_of_resumptions_to_attempt=resum_attempts_as_int
                    )
                except ValueError:
                    raise ValueError(f'Supplied value for --resum_attempts is not an integer: "{resum_attempts}"')
        except KeyError:
            pass

        return is_scan_cmd_enabled, extra_arguments

    @classmethod
    def result_to_console_output(cls, result: SessionResumptionSupportScanResult) -> List[str]:
        result_as_txt = [cls._format_title("TLS 1.2 Session Resumption Support")]

        # Resumption with session IDs
        if result.session_id_resumption_result == TlsResumptionSupportEnum.SERVER_IS_TLS_1_3_ONLY:
            session_id_support_txt = "OK - Server only supports TLS 1.3 which doesn't support Session IDs"
        else:
            session_id_support_txt = _resumption_result_to_console_output(
                result.session_id_resumption_result,
                result.session_id_successful_resumptions_count,
                result.session_id_attempted_resumptions_count,
            )
        result_as_txt.append(f"      With Session IDs: {session_id_support_txt}.")

        # Resumption with TLS tickets
        if result.tls_ticket_resumption_result == TlsResumptionSupportEnum.SERVER_IS_TLS_1_3_ONLY:
            tls_ticket_support_txt = "OK - Server only supports TLS 1.3 which doesn't support TLS tickets"
        else:
            tls_ticket_support_txt = _resumption_result_to_console_output(
                result.tls_ticket_resumption_result,
                result.tls_ticket_successful_resumptions_count,
                result.tls_ticket_attempted_resumptions_count,
            )
        result_as_txt.append(f"      With TLS Tickets: {tls_ticket_support_txt}.")

        # Per-attempt evidence, so each attempt's target, TLS configuration and outcome can be audited individually
        if result.session_id_attempts:
            result_as_txt.append("      Session ID resumption attempts:")
            for attempt_index, attempt in enumerate(result.session_id_attempts, start=1):
                result_as_txt.append(_resumption_attempt_to_console_output(attempt_index, attempt))
        if result.tls_ticket_attempts:
            result_as_txt.append("      TLS ticket resumption attempts:")
            for attempt_index, attempt in enumerate(result.tls_ticket_attempts, start=1):
                result_as_txt.append(_resumption_attempt_to_console_output(attempt_index, attempt))

        return result_as_txt


def _process_resumption_attempt_results(
    resumption_attempts: List[ResumptionAttemptEvidence],
) -> Tuple[TlsResumptionSupportEnum, int, int]:
    total_attempts_count = len(resumption_attempts)
    successful_attempts_count = 0
    for attempt in resumption_attempts:
        if attempt.outcome == ResumptionAttemptOutcomeEnum.RESUMED:
            successful_attempts_count += 1

    if successful_attempts_count == 0:
        result = TlsResumptionSupportEnum.NOT_SUPPORTED
    elif successful_attempts_count == total_attempts_count:
        result = TlsResumptionSupportEnum.FULLY_SUPPORTED
    else:
        result = TlsResumptionSupportEnum.PARTIALLY_SUPPORTED

    return result, successful_attempts_count, total_attempts_count


class SessionResumptionSupportImplementation(
    ScanCommandImplementation[SessionResumptionSupportScanResult, SessionResumptionSupportExtraArgument]
):
    """Test a server for session resumption support using session IDs and TLS tickets."""

    cli_connector_cls = _SessionResumptionSupportCliConnector

    _DEFAULT_RESUMPTION_ATTEMPTS = 5

    @classmethod
    def scan_jobs_for_scan_command(
        cls,
        server_info: ServerConnectivityInfo,
        extra_arguments: Optional[SessionResumptionSupportExtraArgument] = None,
    ) -> List[ScanJob]:
        if extra_arguments:
            number_of_resumption_attempts = extra_arguments.number_of_resumptions_to_attempt
        else:
            number_of_resumption_attempts = cls._DEFAULT_RESUMPTION_ATTEMPTS

        # Test Session ID support
        session_id_scan_jobs = [
            ScanJob(function_to_call=resume_with_session_id, function_arguments=[server_info])
            for _ in range(number_of_resumption_attempts)
        ]

        # Test TLS tickets support
        tls_ticket_scan_jobs = [
            ScanJob(function_to_call=resume_with_tls_ticket, function_arguments=[server_info])
            for _ in range(number_of_resumption_attempts)
        ]

        return session_id_scan_jobs + tls_ticket_scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> SessionResumptionSupportScanResult:
        if len(scan_job_results) == 0:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        # Sort TLS ticket VS session ID results; each job returns its own self-contained evidence record, so
        # attribution to a target never depends on the order in which the jobs completed
        results_dict: Dict[_ScanJobResultEnum, List[ResumptionAttemptEvidence]] = {
            _ScanJobResultEnum.SESSION_ID_RESUMPTION: [],
            _ScanJobResultEnum.TLS_TICKET_RESUMPTION: [],
        }
        for job in scan_job_results:
            try:
                result_enum, attempt_evidence = job.get_result()
                results_dict[result_enum].append(attempt_evidence)
            except ServerOnlySupportsTls13:
                # If the server only supports TLS 1.3, none of the resumption mechanisms in this plugin are supported
                # by the server
                return SessionResumptionSupportScanResult(
                    session_id_resumption_result=TlsResumptionSupportEnum.SERVER_IS_TLS_1_3_ONLY,
                    session_id_attempted_resumptions_count=0,
                    session_id_successful_resumptions_count=0,
                    tls_ticket_resumption_result=TlsResumptionSupportEnum.SERVER_IS_TLS_1_3_ONLY,
                    tls_ticket_attempted_resumptions_count=0,
                    tls_ticket_successful_resumptions_count=0,
                )

        # Process session IDs resumption results
        session_id_result, session_id_successful_count, session_id_total_count = _process_resumption_attempt_results(
            results_dict[_ScanJobResultEnum.SESSION_ID_RESUMPTION]
        )

        # Process the TLS tickets resumption results
        tls_ticket_result, tls_ticket_successful_count, tls_ticket_total_count = _process_resumption_attempt_results(
            results_dict[_ScanJobResultEnum.TLS_TICKET_RESUMPTION]
        )

        # All done
        return SessionResumptionSupportScanResult(
            session_id_resumption_result=session_id_result,
            session_id_attempted_resumptions_count=session_id_total_count,
            session_id_successful_resumptions_count=session_id_successful_count,
            tls_ticket_resumption_result=tls_ticket_result,
            tls_ticket_attempted_resumptions_count=tls_ticket_total_count,
            tls_ticket_successful_resumptions_count=tls_ticket_successful_count,
            session_id_attempts=tuple(results_dict[_ScanJobResultEnum.SESSION_ID_RESUMPTION]),
            tls_ticket_attempts=tuple(results_dict[_ScanJobResultEnum.TLS_TICKET_RESUMPTION]),
        )
