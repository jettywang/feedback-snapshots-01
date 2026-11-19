import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Union

from nassl.ephemeral_key_info import EphemeralKeyInfo

from sslyze.connection_helpers.tls_connection import NoCiphersAvailableBugInSSlyze
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    CipherSuiteAcceptedByServer,
    CipherSuiteRejectedByServer,
    CipherSuiteTransportError,
    CipherSuiteScanStatusEnum,
    OpenSslBackendEnum,
    connect_with_cipher_suite,
    get_openssl_backend_for_cipher_suite,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


# One retry by default: a single transient timeout gets a second chance without re-running the whole scan
DEFAULT_MAX_TRANSPORT_RETRIES = 1


@dataclass(frozen=True)
class CipherSuiteAttemptKey:
    """Uniquely identifies one cell of the support matrix: TLS version + actual OpenSSL backend + cipher suite."""

    tls_version: TlsVersionEnum
    backend: OpenSslBackendEnum
    openssl_cipher_name: str


@dataclass(frozen=True)
class CipherSuiteScanCell:
    """The recorded state of one support-matrix cell, including how many actual connections it took."""

    key: CipherSuiteAttemptKey
    cipher_suite: CipherSuite
    status: CipherSuiteScanStatusEnum
    connection_attempts: int
    ephemeral_key: Optional[EphemeralKeyInfo] = None
    error_message: Optional[str] = None


CipherSuiteConnectionTester = Callable[
    [ServerConnectivityInfo, TlsVersionEnum, CipherSuite],
    Union[CipherSuiteAcceptedByServer, CipherSuiteRejectedByServer, CipherSuiteTransportError],
]


class CipherSuiteScanCoordinator:
    """Runs and records cipher suite probe jobs for one TLS version.

    Attempts are tracked per (TLS version, OpenSSL backend, cipher suite) cell. Only transport failures are retried,
    and only for the affected cell: accepted/rejected/not-capable cells never trigger another connection. All state
    is guarded by a lock so worker threads may complete jobs in any order without duplicate or missing cells.
    """

    def __init__(
        self,
        tls_version: TlsVersionEnum,
        max_transport_retries: int = DEFAULT_MAX_TRANSPORT_RETRIES,
        connection_tester: Optional[CipherSuiteConnectionTester] = None,
    ) -> None:
        self._tls_version = tls_version
        self._max_attempts_per_cell = 1 + max_transport_retries
        self._connection_tester: CipherSuiteConnectionTester = connection_tester or connect_with_cipher_suite
        self._lock = threading.Lock()
        self._cells: Dict[CipherSuiteAttemptKey, CipherSuiteScanCell] = {}
        self._total_connection_attempts = 0

    @property
    def total_connection_attempts(self) -> int:
        with self._lock:
            return self._total_connection_attempts

    def get_cell(self, key: CipherSuiteAttemptKey) -> Optional[CipherSuiteScanCell]:
        with self._lock:
            return self._cells.get(key)

    def iter_cells(self) -> tuple[CipherSuiteScanCell, ...]:
        with self._lock:
            return tuple(self._cells.values())

    def scan_cipher_suite(
        self, server_connectivity_info: ServerConnectivityInfo, cipher_suite: CipherSuite
    ) -> CipherSuiteScanCell:
        backend = get_openssl_backend_for_cipher_suite(self._tls_version, cipher_suite)
        key = CipherSuiteAttemptKey(
            tls_version=self._tls_version,
            backend=backend,
            openssl_cipher_name=cipher_suite.openssl_name,
        )

        # Never open a second connection for a cell that was already completed (idempotent job scheduling)
        with self._lock:
            cached_cell = self._cells.get(key)
            if cached_cell is not None:
                return cached_cell

        connection_attempts = 0
        last_outcome: Optional[
            Union[CipherSuiteAcceptedByServer, CipherSuiteRejectedByServer, CipherSuiteTransportError]
        ] = None
        for _ in range(self._max_attempts_per_cell):
            try:
                outcome = self._connection_tester(server_connectivity_info, self._tls_version, cipher_suite)
            except NoCiphersAvailableBugInSSlyze as e:
                # OpenSSL cannot attempt this cipher suite/TLS version combination: no network connection was made
                return self._store_cell(
                    CipherSuiteScanCell(
                        key=key,
                        cipher_suite=cipher_suite,
                        status=CipherSuiteScanStatusEnum.NOT_CAPABLE,
                        connection_attempts=0,
                        error_message=str(e),
                    )
                )

            connection_attempts += 1
            with self._lock:
                self._total_connection_attempts += 1
            last_outcome = outcome

            # Only transport failures may be retried; acceptances and explicit rejections are terminal
            if not isinstance(outcome, CipherSuiteTransportError):
                break

        assert last_outcome is not None
        return self._store_cell(self._build_cell_from_outcome(key, cipher_suite, last_outcome, connection_attempts))

    @staticmethod
    def _build_cell_from_outcome(
        key: CipherSuiteAttemptKey,
        cipher_suite: CipherSuite,
        outcome: Union[CipherSuiteAcceptedByServer, CipherSuiteRejectedByServer, CipherSuiteTransportError],
        connection_attempts: int,
    ) -> CipherSuiteScanCell:
        if isinstance(outcome, CipherSuiteAcceptedByServer):
            return CipherSuiteScanCell(
                key=key,
                cipher_suite=cipher_suite,
                status=CipherSuiteScanStatusEnum.ACCEPTED,
                connection_attempts=connection_attempts,
                ephemeral_key=outcome.ephemeral_key,
            )
        if isinstance(outcome, CipherSuiteRejectedByServer):
            return CipherSuiteScanCell(
                key=key,
                cipher_suite=cipher_suite,
                status=CipherSuiteScanStatusEnum.REJECTED,
                connection_attempts=connection_attempts,
                error_message=outcome.error_message,
            )
        return CipherSuiteScanCell(
            key=key,
            cipher_suite=cipher_suite,
            status=CipherSuiteScanStatusEnum.TRANSPORT_ERROR,
            connection_attempts=connection_attempts,
            error_message=outcome.error_message,
        )

    def _store_cell(self, cell: CipherSuiteScanCell) -> CipherSuiteScanCell:
        with self._lock:
            # Another thread may have completed the same cell meanwhile; keep the first recorded result
            already_recorded = self._cells.get(cell.key)
            if already_recorded is not None:
                return already_recorded
            self._cells[cell.key] = cell
            return cell
