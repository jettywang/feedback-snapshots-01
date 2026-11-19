from typing import Dict, List, Union
from unittest import mock

from sslyze.plugins.openssl_cipher_suites._scan_coordinator import (
    CipherSuiteScanCell,
    CipherSuiteScanCoordinator,
)
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    CipherSuiteAcceptedByServer,
    CipherSuiteRejectedByServer,
    CipherSuiteTransportError,
    CipherSuiteNotCapable,
    CipherSuiteScanStatusEnum,
    OpenSslBackendEnum,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite, CipherSuitesRepository
from sslyze.plugins.openssl_cipher_suites.implementation import Tlsv13ScanImplementation
from sslyze.plugins.plugin_base import ScanJobResult
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerConnectivityInfo,
    ServerTlsProbingResult,
    TlsVersionEnum,
)
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation
from tests.plugins_tests.openssl_cipher_suites.test_scan_coordinator import (
    ScriptedConnectionTester,
    _timeout,
)


def _server_info() -> ServerConnectivityInfo:
    server_location = ServerNetworkLocation(hostname="localhost", port=443, ip_address="127.0.0.1")
    return ServerConnectivityInfo(
        server_location=server_location,
        network_configuration=ServerNetworkConfiguration(tls_server_name_indication="localhost"),
        tls_probing_result=ServerTlsProbingResult(
            highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
            cipher_suite_supported="AES",
            client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
            supports_ecdh_key_exchange=True,
        ),
    )


def _run_scan(implementation_cls, tester) -> "object":
    """Drive scan_jobs_for_scan_command() + result_for_completed_scan_jobs() with a scripted tester."""
    server_info = _server_info()
    with mock.patch(
        "sslyze.plugins.openssl_cipher_suites.implementation.CipherSuiteScanCoordinator"
    ) as coordinator_cls:
        tls_version = implementation_cls._tls_version
        real_coordinator = CipherSuiteScanCoordinator(tls_version=tls_version, connection_tester=tester)
        coordinator_cls.return_value = real_coordinator
        jobs = implementation_cls.scan_jobs_for_scan_command(server_info)
        job_results: List[ScanJobResult] = []
        for job in jobs:
            cell = job.function_to_call(*job.function_arguments)
            job_results.append(ScanJobResult(_return_value=cell, _exception=None))
        result = implementation_cls.result_for_completed_scan_jobs(server_info, job_results)
    return result


class TestResultAggregation:
    def test_full_support_matrix_is_aggregated_once_per_cell(self):
        # Given a TLS 1.3 server that accepts every TLS 1.3 cipher suite
        suites = list(CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_3))
        scripted = {
            suite.openssl_name: [CipherSuiteAcceptedByServer(cipher_suite=suite, ephemeral_key=None)]
            for suite in suites
        }
        tester = ScriptedConnectionTester(scripted)

        # When running the scan
        result = _run_scan(Tlsv13ScanImplementation, tester)

        # Then every cipher suite appears exactly once in the accepted list and nowhere else
        assert len(result.accepted_cipher_suites) == len(suites)
        assert not result.rejected_cipher_suites
        assert not result.errored_cipher_suites
        assert result.is_complete is True
        # And the number of connections proves no full re-run happened: one connection per cell
        assert result.total_connection_attempts == len(suites)

    def test_one_timeout_then_success_does_not_inflate_the_matrix(self):
        # Given a TLS 1.3 matrix where one suite times out once and succeeds on the retry
        suites = list(CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_3))
        flaky = suites[0]
        scripted: Dict[str, List[Union[CipherSuiteAcceptedByServer, CipherSuiteTransportError]]] = {}
        for suite in suites:
            if suite.openssl_name == flaky.openssl_name:
                scripted[suite.openssl_name] = [
                    _timeout(suite),
                    CipherSuiteAcceptedByServer(cipher_suite=suite, ephemeral_key=None),
                ]
            else:
                scripted[suite.openssl_name] = [CipherSuiteAcceptedByServer(cipher_suite=suite, ephemeral_key=None)]
        tester = ScriptedConnectionTester(scripted)

        result = _run_scan(Tlsv13ScanImplementation, tester)

        # The flaky suite is accepted once (not duplicated, not rejected, not left errored)
        assert len(result.accepted_cipher_suites) == len(suites)
        accepted_names = [entry.cipher_suite.openssl_name for entry in result.accepted_cipher_suites]
        assert accepted_names.count(flaky.openssl_name) == 1
        assert not result.errored_cipher_suites
        assert result.is_complete is True
        # Only one extra connection was made (the retry); the whole matrix was not re-run
        assert result.total_connection_attempts == len(suites) + 1

    def test_persistent_error_cell_is_reported_as_incomplete_not_rejected(self):
        suites = list(CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_3))
        broken = suites[0]
        scripted = {}
        for suite in suites:
            if suite.openssl_name == broken.openssl_name:
                scripted[suite.openssl_name] = [_timeout(suite), _timeout(suite)]
            else:
                scripted[suite.openssl_name] = [CipherSuiteAcceptedByServer(cipher_suite=suite, ephemeral_key=None)]
        tester = ScriptedConnectionTester(scripted)

        result = _run_scan(Tlsv13ScanImplementation, tester)

        # The broken cell is surfaced as an error and keeps the matrix flagged as incomplete
        assert len(result.accepted_cipher_suites) == len(suites) - 1
        assert len(result.errored_cipher_suites) == 1
        assert result.errored_cipher_suites[0].cipher_suite.openssl_name == broken.openssl_name
        assert not result.rejected_cipher_suites
        assert result.is_complete is False
        assert result.incomplete_cipher_suites == result.errored_cipher_suites
        # The broken cell used its retry budget (2 connections), every other cell used one
        assert result.total_connection_attempts == len(suites) + 1

    def test_explicit_rejections_are_separate_from_transport_errors(self):
        suites = list(CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_3))
        rejected_suite = suites[0]
        broken_suite = suites[1]
        rejection = CipherSuiteRejectedByServer(
            cipher_suite=rejected_suite, error_message="TLS alert: handshake failure"
        )
        scripted = {}
        for suite in suites:
            if suite.openssl_name == rejected_suite.openssl_name:
                scripted[suite.openssl_name] = [rejection]
            elif suite.openssl_name == broken_suite.openssl_name:
                scripted[suite.openssl_name] = [_timeout(suite), _timeout(suite)]
            else:
                scripted[suite.openssl_name] = [CipherSuiteAcceptedByServer(cipher_suite=suite, ephemeral_key=None)]
        tester = ScriptedConnectionTester(scripted)

        result = _run_scan(Tlsv13ScanImplementation, tester)

        assert [e.cipher_suite.openssl_name for e in result.rejected_cipher_suites] == [rejected_suite.openssl_name]
        assert [e.cipher_suite.openssl_name for e in result.errored_cipher_suites] == [broken_suite.openssl_name]
        assert len(result.accepted_cipher_suites) == len(suites) - 2
        assert result.is_complete is False
        # The rejected cell was only tried once; the errored cell was retried once
        assert result.total_connection_attempts == len(suites) + 1

    def test_duplicate_cells_in_job_results_are_deduplicated(self):
        # If the same cell somehow comes back twice, aggregation must count it once
        suites = list(CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_3))
        duplicated_suite = suites[0]
        job_results = [
            ScanJobResult(
                _return_value=CipherSuiteScanCell(
                    key=_key_for(other),
                    cipher_suite=other,
                    status=CipherSuiteScanStatusEnum.ACCEPTED,
                    connection_attempts=1,
                    ephemeral_key=None,
                ),
                _exception=None,
            )
            for other in suites
        ]
        # Replace the last entry with a second result for the same cell as the first entry
        job_results[-1] = ScanJobResult(
            _return_value=CipherSuiteScanCell(
                key=_key_for(duplicated_suite),
                cipher_suite=duplicated_suite,
                status=CipherSuiteScanStatusEnum.ACCEPTED,
                connection_attempts=1,
                ephemeral_key=None,
            ),
            _exception=None,
        )

        result = Tlsv13ScanImplementation.result_for_completed_scan_jobs(_server_info(), job_results)

        # The duplicated cell is counted once, and the cell whose job was replaced is simply absent
        assert len(result.accepted_cipher_suites) == len(suites) - 1
        accepted_names = [entry.cipher_suite.openssl_name for entry in result.accepted_cipher_suites]
        assert accepted_names.count(duplicated_suite.openssl_name) == 1
        assert result.total_connection_attempts == len(suites) - 1

    def test_not_capable_cells_open_no_connection_and_are_listed_separately(self):
        suites = list(CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_3))
        incapable = suites[0]
        job_results = []
        for suite in suites:
            if suite.openssl_name == incapable.openssl_name:
                job_results.append(
                    ScanJobResult(
                        _return_value=CipherSuiteScanCell(
                            key=_key_for(suite),
                            cipher_suite=suite,
                            status=CipherSuiteScanStatusEnum.NOT_CAPABLE,
                            connection_attempts=0,
                            error_message="Set a cipher that is not supported by nassl",
                        ),
                        _exception=None,
                    )
                )
            else:
                job_results.append(
                    ScanJobResult(
                        _return_value=CipherSuiteScanCell(
                            key=_key_for(suite),
                            cipher_suite=suite,
                            status=CipherSuiteScanStatusEnum.ACCEPTED,
                            connection_attempts=1,
                            ephemeral_key=None,
                        ),
                        _exception=None,
                    )
                )

        result = Tlsv13ScanImplementation.result_for_completed_scan_jobs(_server_info(), job_results)

        assert len(result.not_capable_cipher_suites) == 1
        assert isinstance(result.not_capable_cipher_suites[0], CipherSuiteNotCapable)
        assert len(result.accepted_cipher_suites) == len(suites) - 1
        # Not-capable cells contribute zero connections, so the total only counts the attempted cells
        assert result.total_connection_attempts == len(suites) - 1
        # Not-capable is a definitive outcome, not an incomplete/transport cell
        assert result.is_complete is True


def _key_for(suite: CipherSuite):
    from sslyze.plugins.openssl_cipher_suites._scan_coordinator import CipherSuiteAttemptKey

    return CipherSuiteAttemptKey(
        tls_version=TlsVersionEnum.TLS_1_3,
        backend=OpenSslBackendEnum.MODERN,
        openssl_cipher_name=suite.openssl_name,
    )
