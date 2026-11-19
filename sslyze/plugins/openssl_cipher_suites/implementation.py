from operator import attrgetter

from dataclasses import dataclass, field

from sslyze.plugins.openssl_cipher_suites._cli_connector import _CipherSuitesCliConnector
from sslyze.plugins.openssl_cipher_suites._scan_coordinator import (
    CipherSuiteAttemptKey,
    CipherSuiteScanCell,
    CipherSuiteScanCoordinator,
)
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    CipherSuiteAcceptedByServer,
    CipherSuiteRejectedByServer,
    CipherSuiteTransportError,
    CipherSuiteNotCapable,
    CipherSuiteScanStatusEnum,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuitesRepository
from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandResult,
    ScanJob,
    ScanCommandExtraArgument,
    ScanCommandWrongUsageError,
    ScanJobResult,
)
from typing import ClassVar, Optional
from typing import List, Dict

from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


@dataclass(frozen=True)
class CipherSuitesScanResult(ScanCommandResult):
    """The result of testing a server for cipher suites with a specific version of SSL/TLS.

    Attributes:
        tls_version_used: The SSL/TLS version used to connect to the server.
        accepted_cipher_suites: Cipher suites the server negotiated successfully.
        rejected_cipher_suites: Cipher suites the server explicitly refused to negotiate.
        errored_cipher_suites: Cipher suites whose probe could not complete because of a transport failure (timeout,
            reset, ...). These cells are NOT rejections: the server never gave a clear answer and the matrix is
            incomplete as long as this list is not empty.
        not_capable_cipher_suites: Cipher suites SSLyze/OpenSSL cannot attempt for this TLS version; no connection
            was made for them.
        total_connection_attempts: The number of TCP/TLS connections actually opened to the server to produce this
            result. Retries only add connections for the affected cells, so this is usually well below the number of
            cells when no retry was needed.
    """

    tls_version_used: TlsVersionEnum
    accepted_cipher_suites: List[CipherSuiteAcceptedByServer]
    rejected_cipher_suites: List[CipherSuiteRejectedByServer]
    errored_cipher_suites: List[CipherSuiteTransportError] = field(default_factory=list)
    not_capable_cipher_suites: List[CipherSuiteNotCapable] = field(default_factory=list)
    total_connection_attempts: int = 0

    @property
    def is_tls_version_supported(self) -> bool:
        """Is the SSL/TLS version used to connect the server supported by it?"""
        return True if self.accepted_cipher_suites else False

    @property
    def is_complete(self) -> bool:
        """True only if every cell of the support matrix got a definitive accepted/rejected answer."""
        return not self.errored_cipher_suites

    @property
    def incomplete_cipher_suites(self) -> List[CipherSuiteTransportError]:
        """Alias for the cells that remain untested because of a transport failure."""
        return self.errored_cipher_suites


class _Sslv20CliConnector(_CipherSuitesCliConnector):
    _cli_option = "sslv2"
    _cli_description = "Test a server for SSL 2.0 support."
    _title_in_output = "SSL 2.0 Cipher Suites"


class _Sslv30CliConnector(_CipherSuitesCliConnector):
    _cli_option = "sslv3"
    _cli_description = "Test a server for SSL 3.0 support."
    _title_in_output = "SSL 3.0 Cipher Suites"


class _Tlsv10CliConnector(_CipherSuitesCliConnector):
    _cli_option = "tlsv1"
    _cli_description = "Test a server for TLS 1.0 support."
    _title_in_output = "TLS 1.0 Cipher Suites"


class _Tlsv11CliConnector(_CipherSuitesCliConnector):
    _cli_option = "tlsv1_1"
    _cli_description = "Test a server for TLS 1.1 support."
    _title_in_output = "TLS 1.1 Cipher Suites"


class _Tlsv12CliConnector(_CipherSuitesCliConnector):
    _cli_option = "tlsv1_2"
    _cli_description = "Test a server for TLS 1.2 support."
    _title_in_output = "TLS 1.2 Cipher Suites"


class _Tlsv13CliConnector(_CipherSuitesCliConnector):
    _cli_option = "tlsv1_3"
    _cli_description = "Test a server for TLS 1.3 support."
    _title_in_output = "TLS 1.3 Cipher Suites"


class _CipherSuitesScanImplementation(ScanCommandImplementation[CipherSuitesScanResult, None]):
    # The SSL version corresponding to the scan command
    _tls_version: ClassVar[TlsVersionEnum]

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        # One coordinator per scan command records every attempt per (TLS version, backend, cipher suite) cell and
        # performs the retries; the same coordinator is shared by all the jobs of this scan command
        coordinator = CipherSuiteScanCoordinator(tls_version=cls._tls_version)

        # Run one job per cipher suite to test for
        all_cipher_suites_to_test = CipherSuitesRepository.get_all_cipher_suites(cls._tls_version)
        scan_jobs = [
            ScanJob(
                function_to_call=coordinator.scan_cipher_suite,
                function_arguments=[server_info, cipher_suite],
            )
            for cipher_suite in all_cipher_suites_to_test
        ]
        return scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> CipherSuitesScanResult:
        expected_scan_jobs_count = len(CipherSuitesRepository.get_all_cipher_suites(cls._tls_version))
        if len(scan_job_results) != expected_scan_jobs_count:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        # Index cells by their identity so that a job completing more than once (retry/re-dispatch) can never be
        # counted twice
        cells_by_key: Dict[CipherSuiteAttemptKey, CipherSuiteScanCell] = {}
        for completed_job in scan_job_results:
            cell = completed_job.get_result()
            if not isinstance(cell, CipherSuiteScanCell):
                raise ValueError("Should never happen")
            cells_by_key.setdefault(cell.key, cell)

        accepted_cipher_suites: List[CipherSuiteAcceptedByServer] = []
        rejected_cipher_suites: List[CipherSuiteRejectedByServer] = []
        errored_cipher_suites: List[CipherSuiteTransportError] = []
        not_capable_cipher_suites: List[CipherSuiteNotCapable] = []
        total_connection_attempts = 0

        for cell in cells_by_key.values():
            total_connection_attempts += cell.connection_attempts
            if cell.status == CipherSuiteScanStatusEnum.ACCEPTED:
                accepted_cipher_suites.append(
                    CipherSuiteAcceptedByServer(cipher_suite=cell.cipher_suite, ephemeral_key=cell.ephemeral_key)
                )
            elif cell.status == CipherSuiteScanStatusEnum.REJECTED:
                rejected_cipher_suites.append(
                    CipherSuiteRejectedByServer(
                        cipher_suite=cell.cipher_suite,
                        error_message=cell.error_message if cell.error_message is not None else "",
                    )
                )
            elif cell.status == CipherSuiteScanStatusEnum.TRANSPORT_ERROR:
                errored_cipher_suites.append(
                    CipherSuiteTransportError(
                        cipher_suite=cell.cipher_suite,
                        error_message=cell.error_message if cell.error_message is not None else "",
                    )
                )
            elif cell.status == CipherSuiteScanStatusEnum.NOT_CAPABLE:
                not_capable_cipher_suites.append(
                    CipherSuiteNotCapable(
                        cipher_suite=cell.cipher_suite,
                        reason=cell.error_message if cell.error_message is not None else "",
                    )
                )
            else:
                raise ValueError("Should never happen")

        # Sort all the lists
        accepted_cipher_suites.sort(key=attrgetter("cipher_suite.name"), reverse=True)
        rejected_cipher_suites.sort(key=attrgetter("cipher_suite.name"), reverse=True)
        errored_cipher_suites.sort(key=attrgetter("cipher_suite.name"), reverse=True)
        not_capable_cipher_suites.sort(key=attrgetter("cipher_suite.name"), reverse=True)

        # Generate the results
        return CipherSuitesScanResult(
            tls_version_used=cls._tls_version,
            accepted_cipher_suites=accepted_cipher_suites,
            rejected_cipher_suites=rejected_cipher_suites,
            errored_cipher_suites=errored_cipher_suites,
            not_capable_cipher_suites=not_capable_cipher_suites,
            total_connection_attempts=total_connection_attempts,
        )


class Sslv20ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for SSL 2.0 support."""

    cli_connector_cls = _Sslv20CliConnector
    _tls_version = TlsVersionEnum.SSL_2_0


class Sslv30ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for SSL 3.0 support."""

    cli_connector_cls = _Sslv30CliConnector
    _tls_version = TlsVersionEnum.SSL_3_0


class Tlsv10ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for TLS 1.0 support."""

    cli_connector_cls = _Tlsv10CliConnector
    _tls_version = TlsVersionEnum.TLS_1_0


class Tlsv11ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for TLS 1.1 support."""

    cli_connector_cls = _Tlsv11CliConnector
    _tls_version = TlsVersionEnum.TLS_1_1


class Tlsv12ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for TLS 1.2 support."""

    cli_connector_cls = _Tlsv12CliConnector
    _tls_version = TlsVersionEnum.TLS_1_2


class Tlsv13ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for TLS 1.3 support."""

    cli_connector_cls = _Tlsv13CliConnector
    _tls_version = TlsVersionEnum.TLS_1_3
