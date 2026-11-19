import threading
from typing import Dict, List, Union
from unittest import mock

from sslyze.connection_helpers.tls_connection import NoCiphersAvailableBugInSSlyze
from sslyze.errors import TlsHandshakeTimedOut, ServerRejectedTlsHandshake
from nassl.ssl_client import SslClient
from sslyze.plugins.openssl_cipher_suites._scan_coordinator import (
    CipherSuiteAttemptKey,
    CipherSuiteScanCoordinator,
)
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    CipherSuiteAcceptedByServer,
    CipherSuiteRejectedByServer,
    CipherSuiteTransportError,
    CipherSuiteScanStatusEnum,
    OpenSslBackendEnum,
    connect_with_cipher_suite,
    get_openssl_backend_for_cipher_suite,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite, CipherSuitesRepository
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerConnectivityInfo,
    ServerTlsProbingResult,
    TlsVersionEnum,
)
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation


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


def _cipher_suite(openssl_name: str = "AES128-SHA", rfc_name: str = "TLS_RSA_WITH_AES_128_CBC_SHA") -> CipherSuite:
    return CipherSuite(name=rfc_name, is_anonymous=False, key_size=128, openssl_name=openssl_name)


def _tls_13_suite() -> CipherSuite:
    return next(
        suite
        for suite in CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_3)
        if suite.openssl_name == "TLS_AES_128_GCM_SHA256"
    )


def _timeout(cipher_suite: CipherSuite) -> CipherSuiteTransportError:
    server_info = _server_info()
    err = TlsHandshakeTimedOut(
        server_location=server_info.server_location,
        network_configuration=server_info.network_configuration,
        error_message="Connection to server timed out during the TLS handshake",
    )
    return CipherSuiteTransportError(cipher_suite=cipher_suite, error_message=err.error_message)


def _rejection(cipher_suite: CipherSuite) -> CipherSuiteRejectedByServer:
    server_info = _server_info()
    err = ServerRejectedTlsHandshake(
        server_location=server_info.server_location,
        network_configuration=server_info.network_configuration,
        error_message="TLS alert: handshake failure",
    )
    return CipherSuiteRejectedByServer(cipher_suite=cipher_suite, error_message=err.error_message)


class ScriptedConnectionTester:
    """Test double for connect_with_cipher_suite that returns scripted outcomes and counts connections."""

    def __init__(self, scripted: Dict[str, List[Union[CipherSuiteAcceptedByServer, CipherSuiteTransportError]]]):
        self._scripted = {name: list(outcomes) for name, outcomes in scripted.items()}
        self.calls_per_suite: Dict[str, int] = {}
        self._lock = threading.Lock()

    def __call__(self, server_info, tls_version, cipher_suite):
        with self._lock:
            self.calls_per_suite[cipher_suite.openssl_name] = self.calls_per_suite.get(cipher_suite.openssl_name, 0) + 1
            outcomes = self._scripted[cipher_suite.openssl_name]
        if len(outcomes) == 1:
            return outcomes[0]
        return outcomes.pop(0)


class TestCipherSuiteBackendSelection:
    def test_tls_13_always_uses_modern_backend(self):
        # TLS 1.3 cipher suites can only be tested with the modern OpenSSL and its dedicated ciphersuites API
        suite = _tls_13_suite()
        assert get_openssl_backend_for_cipher_suite(TlsVersionEnum.TLS_1_3, suite) == OpenSslBackendEnum.MODERN

    def test_legacy_tls_versions_always_use_legacy_backend(self):
        suite = _cipher_suite()
        for tls_version in [
            TlsVersionEnum.SSL_2_0,
            TlsVersionEnum.SSL_3_0,
            TlsVersionEnum.TLS_1_0,
            TlsVersionEnum.TLS_1_1,
        ]:
            assert get_openssl_backend_for_cipher_suite(tls_version, suite) == OpenSslBackendEnum.LEGACY

    def test_tls_12_backend_depends_on_the_cipher_suite(self):
        # TLS 1.2 is split between the legacy and modern OpenSSL depending on each cipher suite
        modern_only_suite = next(
            suite
            for suite in CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_2)
            if suite.openssl_name == "ECDHE-RSA-CHACHA20-POLY1305"
        )
        legacy_suite = next(
            suite
            for suite in CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_2)
            if suite.openssl_name == "AES128-SHA"
        )
        assert (
            get_openssl_backend_for_cipher_suite(TlsVersionEnum.TLS_1_2, modern_only_suite) == OpenSslBackendEnum.MODERN
        )
        assert get_openssl_backend_for_cipher_suite(TlsVersionEnum.TLS_1_2, legacy_suite) == OpenSslBackendEnum.LEGACY


class TestCipherSuiteScanCoordinatorRetry:
    def test_timeout_then_success_is_retried_and_recorded_as_accepted(self):
        # Given a cipher suite whose first connection times out but whose retry succeeds
        cipher_suite = _cipher_suite()
        accepted = CipherSuiteAcceptedByServer(cipher_suite=cipher_suite, ephemeral_key=None)
        tester = ScriptedConnectionTester({cipher_suite.openssl_name: [_timeout(cipher_suite), accepted]})
        coordinator = CipherSuiteScanCoordinator(
            tls_version=TlsVersionEnum.TLS_1_2, max_transport_retries=1, connection_tester=tester
        )

        # When running the job
        cell = coordinator.scan_cipher_suite(_server_info(), cipher_suite)

        # Then the cell is accepted (not rejected) and exactly two connections were made (1 initial + 1 retry)
        assert cell.status == CipherSuiteScanStatusEnum.ACCEPTED
        assert cell.connection_attempts == 2
        assert tester.calls_per_suite[cipher_suite.openssl_name] == 2
        assert coordinator.total_connection_attempts == 2

    def test_persistent_transport_failure_is_left_untested_not_rejected(self):
        # Given a cipher suite whose connection always times out
        cipher_suite = _cipher_suite()
        tester = ScriptedConnectionTester({cipher_suite.openssl_name: [_timeout(cipher_suite), _timeout(cipher_suite)]})
        coordinator = CipherSuiteScanCoordinator(
            tls_version=TlsVersionEnum.TLS_1_2, max_transport_retries=1, connection_tester=tester
        )

        # When running the job
        cell = coordinator.scan_cipher_suite(_server_info(), cipher_suite)

        # Then the cell is a TRANSPORT_ERROR (untested), never a rejection, and the retry budget was used
        assert cell.status == CipherSuiteScanStatusEnum.TRANSPORT_ERROR
        assert cell.connection_attempts == 2
        assert tester.calls_per_suite[cipher_suite.openssl_name] == 2

    def test_explicit_rejection_is_not_retried(self):
        # Given a server that explicitly rejects a cipher suite
        cipher_suite = _cipher_suite()
        tester = ScriptedConnectionTester({cipher_suite.openssl_name: [_rejection(cipher_suite)]})
        coordinator = CipherSuiteScanCoordinator(
            tls_version=TlsVersionEnum.TLS_1_2, max_transport_retries=1, connection_tester=tester
        )

        # When running the job
        cell = coordinator.scan_cipher_suite(_server_info(), cipher_suite)

        # Then it is recorded as rejected and only one connection was opened
        assert cell.status == CipherSuiteScanStatusEnum.REJECTED
        assert cell.connection_attempts == 1
        assert tester.calls_per_suite[cipher_suite.openssl_name] == 1

    def test_accepted_is_not_retried(self):
        cipher_suite = _cipher_suite()
        accepted = CipherSuiteAcceptedByServer(cipher_suite=cipher_suite, ephemeral_key=None)
        tester = ScriptedConnectionTester({cipher_suite.openssl_name: [accepted]})
        coordinator = CipherSuiteScanCoordinator(
            tls_version=TlsVersionEnum.TLS_1_2, max_transport_retries=1, connection_tester=tester
        )

        cell = coordinator.scan_cipher_suite(_server_info(), cipher_suite)

        assert cell.status == CipherSuiteScanStatusEnum.ACCEPTED
        assert cell.connection_attempts == 1
        assert tester.calls_per_suite[cipher_suite.openssl_name] == 1

    def test_not_capable_opens_no_connection(self):
        # Given an OpenSSL that cannot attempt the cipher suite/TLS version combination
        cipher_suite = _cipher_suite()

        def tester_that_raises(server_info, tls_version, suite):
            raise NoCiphersAvailableBugInSSlyze("Set a cipher that is not supported by nassl")

        coordinator = CipherSuiteScanCoordinator(
            tls_version=TlsVersionEnum.TLS_1_2, max_transport_retries=1, connection_tester=tester_that_raises
        )

        cell = coordinator.scan_cipher_suite(_server_info(), cipher_suite)

        assert cell.status == CipherSuiteScanStatusEnum.NOT_CAPABLE
        assert cell.connection_attempts == 0
        assert coordinator.total_connection_attempts == 0

    def test_cells_are_keyed_by_tls_version_backend_and_cipher(self):
        cipher_suite = _cipher_suite()
        accepted = CipherSuiteAcceptedByServer(cipher_suite=cipher_suite, ephemeral_key=None)
        tester = ScriptedConnectionTester({cipher_suite.openssl_name: [accepted]})
        coordinator = CipherSuiteScanCoordinator(tls_version=TlsVersionEnum.TLS_1_2, connection_tester=tester)

        cell = coordinator.scan_cipher_suite(_server_info(), cipher_suite)

        assert cell.key == CipherSuiteAttemptKey(
            tls_version=TlsVersionEnum.TLS_1_2,
            backend=OpenSslBackendEnum.LEGACY,
            openssl_cipher_name=cipher_suite.openssl_name,
        )

    def test_duplicate_job_for_same_cell_does_not_open_a_second_connection(self):
        cipher_suite = _cipher_suite()
        accepted = CipherSuiteAcceptedByServer(cipher_suite=cipher_suite, ephemeral_key=None)
        tester = ScriptedConnectionTester({cipher_suite.openssl_name: [accepted]})
        coordinator = CipherSuiteScanCoordinator(tls_version=TlsVersionEnum.TLS_1_2, connection_tester=tester)

        first_cell = coordinator.scan_cipher_suite(_server_info(), cipher_suite)
        second_cell = coordinator.scan_cipher_suite(_server_info(), cipher_suite)

        assert first_cell is second_cell
        assert tester.calls_per_suite[cipher_suite.openssl_name] == 1
        assert coordinator.total_connection_attempts == 1


class TestCoordinatorConcurrentOutOfOrderCompletion:
    def test_out_of_order_completion_builds_the_full_matrix_without_double_counting(self):
        # Given the full set of TLS 1.3 cipher suites and a server that accepts them all
        tls_version = TlsVersionEnum.TLS_1_3
        suites = list(CipherSuitesRepository.get_all_cipher_suites(tls_version))
        scripted = {
            suite.openssl_name: [CipherSuiteAcceptedByServer(cipher_suite=suite, ephemeral_key=None)]
            for suite in suites
        }
        tester = ScriptedConnectionTester(scripted)
        coordinator = CipherSuiteScanCoordinator(tls_version=tls_version, connection_tester=tester)
        server_info = _server_info()

        # When the jobs run concurrently (workers complete cells in an arbitrary order)
        errors: List[Exception] = []

        def _run(suite: CipherSuite) -> None:
            try:
                coordinator.scan_cipher_suite(server_info, suite)
            except Exception as e:  # pragma: no cover - surfaced via the errors list
                errors.append(e)

        threads = [threading.Thread(target=_run, args=(suite,)) for suite in suites]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        # Then every cell of the support matrix is present exactly once
        cells = coordinator.iter_cells()
        assert len(cells) == len(suites)
        assert {cell.key.openssl_cipher_name for cell in cells} == {suite.openssl_name for suite in suites}
        # And exactly one connection per cell: no cell was run twice
        assert coordinator.total_connection_attempts == len(suites)
        assert all(cell.status == CipherSuiteScanStatusEnum.ACCEPTED for cell in cells)

    def test_retry_only_reruns_the_failing_cell_not_the_whole_matrix(self):
        # Given a matrix where a single cell times out once then succeeds, while all others succeed immediately
        tls_version = TlsVersionEnum.TLS_1_3
        suites = list(CipherSuitesRepository.get_all_cipher_suites(tls_version))
        flaky_suite = suites[0]
        scripted = {}
        for suite in suites:
            if suite.openssl_name == flaky_suite.openssl_name:
                scripted[suite.openssl_name] = [
                    _timeout(suite),
                    CipherSuiteAcceptedByServer(cipher_suite=suite, ephemeral_key=None),
                ]
            else:
                scripted[suite.openssl_name] = [CipherSuiteAcceptedByServer(cipher_suite=suite, ephemeral_key=None)]
        tester = ScriptedConnectionTester(scripted)
        coordinator = CipherSuiteScanCoordinator(
            tls_version=tls_version, max_transport_retries=1, connection_tester=tester
        )
        server_info = _server_info()

        for suite in suites:
            coordinator.scan_cipher_suite(server_info, suite)

        # Then every cell is accepted and only the flaky cell paid for an extra connection
        cells = {cell.key.openssl_cipher_name: cell for cell in coordinator.iter_cells()}
        assert all(cell.status == CipherSuiteScanStatusEnum.ACCEPTED for cell in cells.values())
        assert cells[flaky_suite.openssl_name].connection_attempts == 2
        assert sum(tester.calls_per_suite.values()) == len(suites) + 1
        assert coordinator.total_connection_attempts == len(suites) + 1


class _FakeConnection:
    """Minimal stand-in for SslConnection whose connect() can raise scripted errors."""

    def __init__(self, connect_error):
        from nassl.ssl_client import OpenSslVersionEnum

        self.ssl_client = SslClient(ssl_version=OpenSslVersionEnum.TLSV1_2)
        self._connect_error = connect_error
        self.closed = False

    def connect(self):
        raise self._connect_error

    def close(self):
        self.closed = True


class TestConnectWithCipherSuiteClassification:
    def test_timeout_is_returned_as_transport_error_not_rejection(self):
        # Given a connection whose TLS handshake times out
        cipher_suite = _cipher_suite()
        server_info = _server_info()
        timeout_error = TlsHandshakeTimedOut(
            server_location=server_info.server_location,
            network_configuration=server_info.network_configuration,
            error_message="Connection to server timed out during the TLS handshake",
        )
        fake_connection = _FakeConnection(connect_error=timeout_error)

        with mock.patch.object(
            ServerConnectivityInfo, "get_preconfigured_tls_connection", return_value=fake_connection
        ):
            # When testing the cipher suite
            outcome = connect_with_cipher_suite(server_info, TlsVersionEnum.TLS_1_2, cipher_suite)

        # Then it is classified as a transport error and not as a server rejection
        assert isinstance(outcome, CipherSuiteTransportError)
        assert not isinstance(outcome, CipherSuiteRejectedByServer)
        assert fake_connection.closed is True

    def test_handshake_rejection_is_returned_as_rejected(self):
        cipher_suite = _cipher_suite()
        server_info = _server_info()
        rejection_error = ServerRejectedTlsHandshake(
            server_location=server_info.server_location,
            network_configuration=server_info.network_configuration,
            error_message="TLS alert: handshake failure",
        )
        fake_connection = _FakeConnection(connect_error=rejection_error)

        with mock.patch.object(
            ServerConnectivityInfo, "get_preconfigured_tls_connection", return_value=fake_connection
        ):
            outcome = connect_with_cipher_suite(server_info, TlsVersionEnum.TLS_1_2, cipher_suite)

        assert isinstance(outcome, CipherSuiteRejectedByServer)
        assert fake_connection.closed is True
