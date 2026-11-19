"""Deterministic tests of how scan command failures are classified into ScanCommandErrorReasonEnum.

These tests do not open any network connection: a fake plugin raises a specific exception from its scan job and
the assertions verify that the scanner attributes the failure to the right cause (client certificate needed,
client certificate rejected, connectivity issue, or an SSLyze bug) instead of reusing the failure of another
plugin or masking a client-auth problem as "TLS not supported".
"""

from dataclasses import dataclass
from typing import List, Optional
from unittest import mock
from nassl.ssl_client import ClientCertificateRequested

from sslyze import (
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    ScanCommandErrorReasonEnum,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerTlsProbingResult,
)
from sslyze.errors import (
    ServerRejectedClientCertificate,
    ServerRejectedTlsHandshake,
    ServerRequestedClientAuthentication,
    TlsHandshakeTimedOut,
)
from sslyze.plugins.plugin_base import (
    ScanCommandExtraArgument,
    ScanCommandImplementation,
    ScanCommandResult,
    ScanJob,
    ScanJobResult,
)
from sslyze.plugins.scan_commands import ScanCommandsRepository
from sslyze.scanner._mass_scanner import _generate_result_for_completed_server_scan, _OngoingServerScan
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
from sslyze.server_connectivity import ClientAuthRequirementEnum, TlsVersionEnum


@dataclass(frozen=True)
class _FakeScanResult(ScanCommandResult):
    ok: bool = True


class _PluginThatRaises(ScanCommandImplementation):
    raised_exception: Optional[Exception] = None

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        return [ScanJob(function_to_call=cls._raise_configured_exception, function_arguments=[])]

    @classmethod
    def _raise_configured_exception(cls):
        exception = cls.raised_exception
        if exception is None:
            raise RuntimeError("Test plugin was not configured with an exception to raise")
        raise exception

    @classmethod
    def result_for_completed_scan_jobs(cls, server_info, scan_job_results: List[ScanJobResult]) -> ScanCommandResult:
        for job_result in scan_job_results:
            job_result.get_result()
        return _FakeScanResult()


def _plugin_that_raises(exception: Exception):
    class _ConfiguredFailingPlugin(_PluginThatRaises):
        raised_exception = exception

    return _ConfiguredFailingPlugin


class _SucceedingPlugin(ScanCommandImplementation):
    @classmethod
    def scan_jobs_for_scan_command(cls, server_info, extra_arguments: Optional[ScanCommandExtraArgument] = None):
        return [ScanJob(function_to_call=lambda: True, function_arguments=[])]

    @classmethod
    def result_for_completed_scan_jobs(cls, server_info, scan_job_results: List[ScanJobResult]) -> ScanCommandResult:
        scan_job_results[0].get_result()
        return _FakeScanResult()


def _server_location():
    return ServerNetworkLocation(hostname="localhost", port=8443, ip_address="127.0.0.1")


def _probing_result(client_auth=ClientAuthRequirementEnum.DISABLED):
    return ServerTlsProbingResult(
        highest_tls_version_supported=TlsVersionEnum.TLS_1_3,
        cipher_suite_supported="TLS_AES_256_GCM_SHA384",
        client_auth_requirement=client_auth,
        supports_ecdh_key_exchange=True,
    )


def _run_scanner_with_exception(exception: Exception):
    server_location = _server_location()
    network_config = ServerNetworkConfiguration(tls_server_name_indication="localhost")
    scan_request = ServerScanRequest(
        server_location=server_location,
        network_configuration=network_config,
        scan_commands={ScanCommand.CERTIFICATE_INFO},
    )
    probing_result = _probing_result()

    _PluginThatRaises.raised_exception = exception
    with mock.patch.object(ScanCommandsRepository, "get_implementation_cls", return_value=_PluginThatRaises):
        ongoing_scan = _OngoingServerScan(
            server_scan_request=scan_request,
            server_connectivity_result=probing_result,
            assigned_queue=mock.Mock(),
            scan_command_errors_during_queuing={},
            queued_scan_jobs_count=1,
            completed_scan_jobs=[],
        )
        # Queue + execute the single job the same way the worker thread would
        jobs_per_cmd, queuing_errors = _queue_jobs(scan_request, probing_result)
        assert not queuing_errors
        job = jobs_per_cmd[ScanCommand.CERTIFICATE_INFO][0]
        function_to_call, function_arguments = job.function_to_call, job.function_arguments
        try:
            return_value = function_to_call(*function_arguments)
            job_exception = None
        except Exception as e:  # mirrored from JobsWorkerThread.run()
            return_value, job_exception = None, e

        from sslyze.scanner._jobs_worker_thread import CompletedScanJob

        ongoing_scan.completed_scan_jobs.append(
            CompletedScanJob(
                parent_server_scan_request_uuid=scan_request.uuid,
                for_scan_command=ScanCommand.CERTIFICATE_INFO,
                return_value=return_value,
                exception=job_exception,
            )
        )
        return _generate_result_for_completed_server_scan(ongoing_scan)


def _queue_jobs(scan_request, probing_result):
    from sslyze.scanner._mass_scanner import _generate_scan_jobs_for_server_scan

    return _generate_scan_jobs_for_server_scan(
        server_scan_request=scan_request, server_connectivity_result=probing_result
    )


def _certificate_info_attempt(server_scan_result) -> ScanCommandAttempt:
    return server_scan_result.scan_result.certificate_info


class TestScanCommandErrorClassification:
    def test_client_certificate_requested_is_client_certificate_needed(self):
        # Given a plugin job whose handshake is interrupted by a CertificateRequest
        exception = ClientCertificateRequested(ca_list=["CN=Some CA"])

        # When generating the scan result
        result = _run_scanner_with_exception(exception)

        # Then the failure is attributed to a missing client certificate, not a connectivity issue
        attempt = _certificate_info_attempt(result)
        assert attempt.status == ScanCommandAttemptStatusEnum.ERROR
        assert attempt.error_reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED
        assert attempt.result is None
        assert attempt.error_trace is not None

    def test_client_auth_handshake_error_is_client_certificate_needed(self):
        # Given the typed error for a server requesting client authentication
        exception = ServerRequestedClientAuthentication(
            server_location=_server_location(),
            network_configuration=ServerNetworkConfiguration(tls_server_name_indication="localhost"),
            error_message="The server requested a client certificate but none was supplied",
        )

        result = _run_scanner_with_exception(exception)

        attempt = _certificate_info_attempt(result)
        assert attempt.error_reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED

    def test_rejected_client_certificate_is_distinct_reason(self):
        # Given a caller that did supply a client certificate but the server rejected it
        exception = ServerRejectedClientCertificate(
            server_location=_server_location(),
            network_configuration=ServerNetworkConfiguration(tls_server_name_indication="localhost"),
            error_message="TLS alert: bad client certificate",
        )

        result = _run_scanner_with_exception(exception)

        attempt = _certificate_info_attempt(result)
        assert attempt.error_reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_REJECTED

    def test_plain_handshake_failure_remains_connectivity_issue(self):
        # Given a regular handshake rejection unrelated to client authentication
        exception = ServerRejectedTlsHandshake(
            server_location=_server_location(),
            network_configuration=ServerNetworkConfiguration(tls_server_name_indication="localhost"),
            error_message="TLS alert: handshake failure",
        )

        result = _run_scanner_with_exception(exception)

        attempt = _certificate_info_attempt(result)
        assert attempt.error_reason == ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE

    def test_handshake_timeout_remains_connectivity_issue(self):
        exception = TlsHandshakeTimedOut(
            server_location=_server_location(),
            network_configuration=ServerNetworkConfiguration(tls_server_name_indication="localhost"),
            error_message="Connection to server timed out during the TLS handshake",
        )

        result = _run_scanner_with_exception(exception)

        attempt = _certificate_info_attempt(result)
        assert attempt.error_reason == ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE

    def test_unexpected_error_remains_bug_in_sslyze(self):
        # Given an exception that is not part of the known handshake/client-auth taxonomy
        result = _run_scanner_with_exception(KeyError("unexpected"))

        attempt = _certificate_info_attempt(result)
        assert attempt.error_reason == ScanCommandErrorReasonEnum.BUG_IN_SSLYZE

    def test_client_auth_failure_of_one_plugin_does_not_poison_another(self):
        # Given two scan commands where only the first one fails on client authentication
        server_location = _server_location()
        network_config = ServerNetworkConfiguration(tls_server_name_indication="localhost")
        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=network_config,
            scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.TLS_COMPRESSION},
        )
        probing_result = _probing_result(client_auth=ClientAuthRequirementEnum.REQUIRED)

        class _FailingPlugin(_PluginThatRaises):
            raised_exception = ClientCertificateRequested(ca_list=[])

        implementations = {
            ScanCommand.CERTIFICATE_INFO: _FailingPlugin,
            ScanCommand.TLS_COMPRESSION: _SucceedingPlugin,
        }
        with mock.patch.object(
            ScanCommandsRepository,
            "get_implementation_cls",
            side_effect=lambda scan_cmd: implementations[scan_cmd],
        ):
            jobs_per_cmd, queuing_errors = _queue_jobs(scan_request, probing_result)
            assert not queuing_errors

            from sslyze.scanner._jobs_worker_thread import CompletedScanJob

            completed_jobs = []
            for scan_cmd, jobs in jobs_per_cmd.items():
                for job in jobs:
                    try:
                        return_value = job.function_to_call(*job.function_arguments)
                        exception = None
                    except Exception as e:
                        return_value, exception = None, e
                    completed_jobs.append(
                        CompletedScanJob(
                            parent_server_scan_request_uuid=scan_request.uuid,
                            for_scan_command=scan_cmd,
                            return_value=return_value,
                            exception=exception,
                        )
                    )

            ongoing_scan = _OngoingServerScan(
                server_scan_request=scan_request,
                server_connectivity_result=probing_result,
                assigned_queue=mock.Mock(),
                scan_command_errors_during_queuing={},
                queued_scan_jobs_count=len(completed_jobs),
                completed_scan_jobs=completed_jobs,
            )
            result = _generate_result_for_completed_server_scan(ongoing_scan)

        # The command blocked by client auth reports the precise reason...
        assert result.scan_result.certificate_info.error_reason == (
            ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED
        )
        # ...while the independent command is still completed instead of inheriting the failure
        assert result.scan_result.tls_compression.status == ScanCommandAttemptStatusEnum.COMPLETED


class TestOptionalClientAuthIsNotReportedAsNoTls:
    """End-to-end guard for the headline bug: a server with *optional* client authentication must be reported as
    reachable (COMPLETED) and never aggregated as ERROR_NO_CONNECTIVITY / "TLS not supported".
    """

    def test_optional_client_auth_server_completes_full_scan(self):
        from sslyze.scanner import _mass_connectivity_tester
        from sslyze import Scanner, ServerScanStatusEnum, ServerConnectivityStatusEnum

        server_location = _server_location()
        network_config = ServerNetworkConfiguration(tls_server_name_indication="localhost")
        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=network_config,
            scan_commands={ScanCommand.TLS_COMPRESSION},
        )
        # Connectivity probing succeeds and detects OPTIONAL client authentication (TLS is fully supported)
        probing_result = _probing_result(client_auth=ClientAuthRequirementEnum.OPTIONAL)

        completed_with_optional_auth = []

        class _RecordingSucceedingPlugin(_SucceedingPlugin):
            @classmethod
            def scan_jobs_for_scan_command(cls, server_info, extra_arguments=None):
                # Record the effective ignore-client-auth choice the scanner handed to the plugin
                completed_with_optional_auth.append(
                    server_info.tls_probing_result.client_auth_requirement
                )
                return super().scan_jobs_for_scan_command(server_info, extra_arguments)

        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=probing_result
        ), mock.patch.object(
            ScanCommandsRepository,
            "get_implementation_cls",
            return_value=_RecordingSucceedingPlugin,
        ):
            scanner = Scanner()
            scanner.queue_scans([scan_request])
            results = list(scanner.get_results())

        assert len(results) == 1
        server_scan_result = results[0]

        # The server is reachable and TLS is supported - not "no connectivity"
        assert server_scan_result.connectivity_status == ServerConnectivityStatusEnum.COMPLETED
        assert server_scan_result.scan_status == ServerScanStatusEnum.COMPLETED
        assert server_scan_result.connectivity_result.client_auth_requirement == (
            ClientAuthRequirementEnum.OPTIONAL
        )

        # The plugin actually ran (it was not blocked by a re-used connectivity failure)
        assert completed_with_optional_auth == [ClientAuthRequirementEnum.OPTIONAL]
        attempt = server_scan_result.scan_result.tls_compression
        assert attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        assert attempt.error_reason is None

    def test_required_client_auth_server_still_reachable_but_plugin_blocked(self):
        from sslyze.scanner import _mass_connectivity_tester
        from sslyze import Scanner, ServerScanStatusEnum, ServerConnectivityStatusEnum

        server_location = _server_location()
        network_config = ServerNetworkConfiguration(tls_server_name_indication="localhost")
        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=network_config,
            scan_commands={ScanCommand.CERTIFICATE_INFO},
        )
        # Connectivity probing succeeds; the server REQUIRES a client certificate
        probing_result = _probing_result(client_auth=ClientAuthRequirementEnum.REQUIRED)

        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=probing_result
        ), mock.patch.object(
            ScanCommandsRepository,
            "get_implementation_cls",
            return_value=_plugin_that_raises(ClientCertificateRequested(ca_list=[])),
        ):
            scanner = Scanner()
            scanner.queue_scans([scan_request])
            results = list(scanner.get_results())

        server_scan_result = results[0]
        # The server IS reachable (TLS works); only the scan command is blocked by the missing certificate
        assert server_scan_result.connectivity_status == ServerConnectivityStatusEnum.COMPLETED
        assert server_scan_result.scan_status == ServerScanStatusEnum.COMPLETED
        attempt = server_scan_result.scan_result.certificate_info
        assert attempt.status == ScanCommandAttemptStatusEnum.ERROR
        assert attempt.error_reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED
