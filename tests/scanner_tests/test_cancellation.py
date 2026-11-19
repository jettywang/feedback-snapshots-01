"""Deterministic tests for controlled cancellation of mass TLS scans.

All interleavings are arranged with threading.Event/threading.Barrier stubs; no test opens a network connection, sends
external traffic, or relies on a random sleep.
"""

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from unittest import mock
from uuid import UUID

import pytest

from sslyze import (
    Scanner,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    ServerConnectivityStatusEnum,
    ServerNetworkLocation,
    ServerNetworkConfiguration,
    ServerScanRequest,
    ServerScanResultAsJson,
    ServerScanStatusEnum,
    ServerTlsProbingResult,
    SslyzeOutputAsJson,
)
from sslyze.connection_helpers import tls_connection
from sslyze.errors import ConnectionToServerFailed, ScanCancelledError
from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandResult,
    ScanJob,
)
from sslyze.plugins.scan_commands import ScanCommandsRepository
from sslyze.scanner import _mass_connectivity_tester
from sslyze.scanner._scan_cancellation import ScanCancellation, job_cancellation_context
from sslyze.scanner.scanner_observer import ScannerObserver
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum, ClientAuthRequirementEnum
from tests.factories import ServerScanRequestFactory

_ALL_COMMANDS = list(ScanCommand)


class _Result(ScanCommandResult):
    def __init__(self, evidence: str) -> None:
        self.evidence = evidence


class _RecordingObserver(ScannerObserver):
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.terminal_events: List[UUID] = []
        self.error_events: List[UUID] = []
        self.completed_events: List[UUID] = []
        self.cancelled_connectivity_events: List[UUID] = []
        self.all_completed_calls = 0

    def server_connectivity_test_error(self, server_scan_request, connectivity_error):
        with self.lock:
            self.error_events.append(server_scan_request.uuid)

    def server_connectivity_test_completed(self, server_scan_request, connectivity_result):
        with self.lock:
            self.completed_events.append(server_scan_request.uuid)

    def server_connectivity_test_cancelled(self, server_scan_request):
        with self.lock:
            self.cancelled_connectivity_events.append(server_scan_request.uuid)

    def server_scan_completed(self, server_scan_result):
        with self.lock:
            self.terminal_events.append(server_scan_result.uuid)

    def all_server_scans_completed(self):
        with self.lock:
            self.all_completed_calls += 1


def _wait(event: threading.Event, what: str) -> None:
    assert event.wait(5), f"Timed out waiting for {what}"


def _result_attempts(server_scan_result) -> Dict[str, Any]:
    assert server_scan_result.scan_result is not None
    return {scan_cmd.value: getattr(server_scan_result.scan_result, scan_cmd.value) for scan_cmd in ScanCommand}


class _FakeSocket:
    """Minimal socket double: closing it wakes up a fake blocking handshake."""

    def __init__(self) -> None:
        self.closed_event = threading.Event()
        self.shutdown_calls = 0
        self.close_calls = 0
        self.send = mock.Mock()

    def shutdown(self, how: int) -> None:
        self.shutdown_calls += 1
        self.closed_event.set()

    def close(self) -> None:
        self.close_calls += 1
        self.closed_event.set()


_fake_sockets_created: List[_FakeSocket] = []


def _open_fake_socket(server_location, network_timeout) -> _FakeSocket:
    """Socket factory used to replace tls_connection._open_socket; each connection gets its own fake socket."""
    fake_socket = _FakeSocket()
    _fake_sockets_created.append(fake_socket)
    return fake_socket


class _HandshakeJobImplementation(ScanCommandImplementation[_Result, None]):
    """A plugin whose single job performs a TLS handshake that blocks until the scan is cancelled."""

    started_event = threading.Event()
    socket_holder: Dict[str, _FakeSocket] = {}

    @classmethod
    def scan_jobs_for_scan_command(cls, server_info, extra_arguments=None):
        return [ScanJob(function_to_call=cls._handshake_job, function_arguments=[server_info])]

    @staticmethod
    def _handshake_job(server_info: ServerConnectivityInfo) -> str:
        assert server_info.tls_probing_result
        ssl_connection = tls_connection.SslConnection(
            server_location=server_info.server_location,
            network_configuration=server_info.network_configuration,
            tls_version=TlsVersionEnum.TLS_1_2,
            should_ignore_client_auth=True,
        )

        def blocking_do_handshake() -> None:
            _HandshakeJobImplementation.started_event.set()
            # Wait on the socket that SslConnection registered with the cancellation, so that the cancellation's
            # shutdown() is what unblocks the handshake.
            registered_socket = _fake_sockets_created[-1]
            _HandshakeJobImplementation.socket_holder["socket"] = registered_socket
            registered_socket.closed_event.wait(5)
            raise OSError("Nassl SSL handshake failed")

        ssl_connection.ssl_client.do_handshake = blocking_do_handshake  # type: ignore[method-assign]
        try:
            ssl_connection.connect(should_retry_connection=False)
        finally:
            ssl_connection.close()
        return "should-not-be-used"

    @classmethod
    def result_for_completed_scan_jobs(cls, server_info, scan_job_results):
        return _Result(evidence="handshake-evidence")


class _FastJobImplementation(ScanCommandImplementation[_Result, None]):
    """A plugin whose job completes immediately and produces evidence."""

    job_ran_event = threading.Event()

    @classmethod
    def scan_jobs_for_scan_command(cls, server_info, extra_arguments=None):
        return [ScanJob(function_to_call=cls._job, function_arguments=["evidence"])]

    @staticmethod
    def _job(evidence: str) -> str:
        _FastJobImplementation.job_ran_event.set()
        return evidence

    @classmethod
    def result_for_completed_scan_jobs(cls, server_info, scan_job_results):
        return _Result(evidence=scan_job_results[0].get_result())


def _connectivity_result() -> ServerTlsProbingResult:
    return ServerTlsProbingResult(
        highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
        cipher_suite_supported="AES",
        client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
        supports_ecdh_key_exchange=True,
    )


def _request(scan_commands: Set[ScanCommand]) -> ServerScanRequest:
    return ServerScanRequestFactory.create(scan_commands=scan_commands)


def _consume_in_background(scanner: Scanner, results: List[Any], finished: threading.Event) -> threading.Thread:
    def consume() -> None:
        try:
            for result in scanner.get_results():
                results.append(result)
        finally:
            finished.set()

    thread = threading.Thread(target=consume, daemon=False)
    thread.start()
    return thread


class TestCancellationDuringConnectivityProbing:
    def test_cancelled_probe_is_not_a_connectivity_error(self):
        # Given three servers and a connectivity prober that blocks on the first one
        oracle = _request({ScanCommand.CERTIFICATE_INFO})
        left_behind = [_request({ScanCommand.CERTIFICATE_INFO}) for _ in range(2)]
        all_requests = [oracle, *left_behind]
        probe_started = threading.Event()
        probe_release = threading.Event()
        probe_call_count = [0]

        def blocking_probe(server_location, network_configuration):
            probe_call_count[0] += 1
            probe_started.set()
            probe_release.wait(5)
            # The probe finishes after the cancellation and reports a failure; it must still not be reported as the
            # server rejecting the connection.
            raise ConnectionToServerFailed(
                server_location=server_location,
                network_configuration=network_configuration,
                error_message="probe returned late after cancel",
            )

        observer = _RecordingObserver()
        results: List[Any] = []
        finished = threading.Event()

        with mock.patch.object(_mass_connectivity_tester, "check_connectivity_to_server", side_effect=blocking_probe):
            scanner = Scanner(concurrent_server_scans_limit=1, observers=[observer])
            scanner.queue_scans(all_requests)
            consumer = _consume_in_background(scanner, results, finished)

            # When the probe is in progress and the caller stops the scan
            _wait(probe_started, "connectivity probe to start")
            scanner.cancel_scans()
            probe_release.set()
            _wait(finished, "the consumer to finish")
            consumer.join(5)

        # Then every request got exactly one terminal result, with its original UUID
        assert not consumer.is_alive()
        assert [result.uuid for result in results] and {result.uuid for result in results} == {
            request.uuid for request in all_requests
        }
        assert len(results) == len(all_requests)

        # And the cancellation was never reported as a server rejection
        for result in results:
            assert result.connectivity_status == ServerConnectivityStatusEnum.CANCELLED
            assert result.scan_status == ServerScanStatusEnum.CANCELLED
            assert result.connectivity_error_trace is None
            attempts = _result_attempts(result)
            assert attempts[ScanCommand.CERTIFICATE_INFO.value].status == ScanCommandAttemptStatusEnum.CANCELLED
            assert attempts[ScanCommand.CERTIFICATE_INFO.value].error_reason is None
            assert attempts[ScanCommand.ROBOT.value].status == ScanCommandAttemptStatusEnum.NOT_SCHEDULED

        # And observers saw one cancellation and one terminal notification per request, and no error notification
        assert observer.error_events == []
        assert sorted(observer.terminal_events) == sorted(request.uuid for request in all_requests)
        assert sorted(observer.cancelled_connectivity_events) == sorted(request.uuid for request in all_requests)
        assert observer.all_completed_calls == 1
        assert probe_call_count[0] >= 1

        # And no scan command was started for any server; the generator only finished after joining every thread
        assert not consumer.is_alive()
        assert scanner._cancellation.pending_jobs_count == 0
        assert scanner._cancellation.open_connections_count == 0


class TestCancellationWithQueuedAndRunningJobs:
    def test_completed_evidence_is_kept_and_unfinished_checks_are_cancelled(self):
        # Given one server whose scan has a quick command that completes and a command that blocks in a TLS handshake
        scan_request = _request({ScanCommand.CERTIFICATE_INFO, ScanCommand.ROBOT})
        _FastJobImplementation.job_ran_event.clear()
        _HandshakeJobImplementation.started_event.clear()

        def implementation_for(scan_cmd: ScanCommand):
            if scan_cmd == ScanCommand.CERTIFICATE_INFO:
                return _FastJobImplementation
            return _HandshakeJobImplementation

        _fake_sockets_created.clear()
        observer = _RecordingObserver()
        results: List[Any] = []
        finished = threading.Event()

        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=_connectivity_result()
        ), mock.patch.object(
            ScanCommandsRepository, "get_implementation_cls", side_effect=implementation_for
        ), mock.patch.object(tls_connection, "_open_socket", side_effect=_open_fake_socket):
            scanner = Scanner(concurrent_server_scans_limit=1, observers=[observer])
            scanner.queue_scans([scan_request])
            consumer = _consume_in_background(scanner, results, finished)

            # Wait until the quick job produced its evidence and the other job is blocked inside its TLS handshake
            _wait(_FastJobImplementation.job_ran_event, "the quick scan job to complete")
            _wait(_HandshakeJobImplementation.started_event, "the TLS handshake to start")
            # And until the quick job's result has been settled (only the handshake job is still pending)
            assert scanner._cancellation.wait_until_pending_jobs_at_most(1, 5)

            # When the caller stops the scan while the handshake is in progress
            scanner.cancel_scans()
            _wait(finished, "the consumer to finish")
            consumer.join(5)

        # Then the server got one result, tagged with its own UUID
        assert len(results) == 1
        server_scan_result = results[0]
        assert server_scan_result.uuid == scan_request.uuid
        assert server_scan_result.scan_status == ServerScanStatusEnum.CANCELLED

        attempts = _result_attempts(server_scan_result)
        # The command that completed before the cancellation kept its evidence
        certificate_attempt = attempts[ScanCommand.CERTIFICATE_INFO.value]
        assert certificate_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        assert certificate_attempt.result.evidence == "evidence"

        # The command that was cut short is CANCELLED, not a server rejection or an SSLyze bug
        robot_attempt = attempts[ScanCommand.ROBOT.value]
        assert robot_attempt.status == ScanCommandAttemptStatusEnum.CANCELLED
        assert robot_attempt.error_reason is None
        assert robot_attempt.error_trace is None
        assert robot_attempt.result is None

        # The unrequested commands remain NOT_SCHEDULED
        assert attempts[ScanCommand.HEARTBLEED.value].status == ScanCommandAttemptStatusEnum.NOT_SCHEDULED

        # And the handshake socket was shut down and closed, with nothing left registered
        fake_socket = _HandshakeJobImplementation.socket_holder["socket"]
        assert fake_socket.shutdown_calls >= 1
        assert fake_socket.close_calls >= 1
        assert scanner._cancellation.open_connections_count == 0
        assert scanner._cancellation.pending_jobs_count == 0

        # And observers were notified exactly once for this server
        assert observer.terminal_events == [scan_request.uuid]
        assert observer.all_completed_calls == 1
        assert observer.error_events == []
        # And the generator only finished after joining every worker thread
        assert not consumer.is_alive()


class TestCancellationWithQueuedJobs:
    def test_queued_job_never_starts_and_is_reported_cancelled(self):
        # Given a scan command with two jobs; with a single worker, the second job stays queued
        scan_request = _request({ScanCommand.CERTIFICATE_INFO})
        queued_job_function_calls: List[str] = []
        running_job_started = threading.Event()
        release_running_job = threading.Event()

        class _TwoJobsImplementation(ScanCommandImplementation[_Result, None]):
            @classmethod
            def scan_jobs_for_scan_command(cls, server_info, extra_arguments=None):
                return [
                    ScanJob(function_to_call=cls._running_job, function_arguments=[]),
                    ScanJob(function_to_call=cls._queued_job, function_arguments=[]),
                ]

            @staticmethod
            def _running_job() -> str:
                running_job_started.set()
                release_running_job.wait(5)
                return "running-evidence"

            @staticmethod
            def _queued_job() -> str:
                queued_job_function_calls.append("ran")
                return "queued-evidence"

            @classmethod
            def result_for_completed_scan_jobs(cls, server_info, scan_job_results):
                return _Result(evidence="|".join(job.get_result() for job in scan_job_results))

        observer = _RecordingObserver()
        results: List[Any] = []
        finished = threading.Event()

        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=_connectivity_result()
        ), mock.patch.object(ScanCommandsRepository, "get_implementation_cls", return_value=_TwoJobsImplementation):
            scanner = Scanner(
                concurrent_server_scans_limit=1, per_server_concurrent_connections_limit=1, observers=[observer]
            )
            scanner.queue_scans([scan_request])
            consumer = _consume_in_background(scanner, results, finished)
            _wait(running_job_started, "the first job to start")

            # When the scan is cancelled while one job is running and the other one is still queued
            scanner.cancel_scans()
            release_running_job.set()
            _wait(finished, "the consumer to finish")
            consumer.join(5)

        # Then the queued job never ran
        assert queued_job_function_calls == []

        # And the server has exactly one result, with the scan command reported as CANCELLED rather than an error
        assert len(results) == 1
        server_scan_result = results[0]
        assert server_scan_result.uuid == scan_request.uuid
        attempt = _result_attempts(server_scan_result)[ScanCommand.CERTIFICATE_INFO.value]
        assert attempt.status == ScanCommandAttemptStatusEnum.CANCELLED
        assert attempt.error_reason is None
        assert attempt.error_trace is None
        assert attempt.result is None

        # And everything was accounted for and joined
        assert scanner._cancellation.pending_jobs_count == 0
        assert scanner._cancellation.open_connections_count == 0
        assert observer.terminal_events == [scan_request.uuid]
        assert observer.all_completed_calls == 1
        assert not consumer.is_alive()


class TestHandshakeCancellation:
    def test_handshake_aborted_by_cancel_raises_scan_cancelled(self):
        # Given an SslConnection whose handshake blocks until its socket is closed
        cancellation = ScanCancellation()
        job_token = UUID(int=1)
        assert cancellation.register_job(job_token)
        fake_socket = _FakeSocket()
        outcome: List[BaseException] = []
        handshake_started = threading.Event()

        def connect_in_job() -> None:
            ssl_connection = tls_connection.SslConnection(
                server_location=ServerNetworkLocation(hostname="example.test", port=443, ip_address="10.0.0.10"),
                network_configuration=ServerNetworkConfiguration(tls_server_name_indication="example.test"),
                tls_version=TlsVersionEnum.TLS_1_2,
                should_ignore_client_auth=True,
            )

            def blocking_do_handshake() -> None:
                handshake_started.set()
                fake_socket.closed_event.wait(5)
                raise OSError("Nassl SSL handshake failed")

            ssl_connection.ssl_client.do_handshake = blocking_do_handshake  # type: ignore[method-assign]
            try:
                with job_cancellation_context(cancellation, job_token):
                    ssl_connection.connect(should_retry_connection=False)
            except BaseException as e:  # noqa: BLE001 - we want to inspect whatever comes out
                outcome.append(e)
            finally:
                ssl_connection.close()

        with mock.patch.object(tls_connection, "_open_socket", return_value=fake_socket):
            worker = threading.Thread(target=connect_in_job)
            worker.start()
            _wait(handshake_started, "the handshake to block")
            assert cancellation.open_connections_count == 1

            # When the scan is cancelled
            assert cancellation.cancel() is True
            worker.join(5)

        # Then the handshake returned promptly with a cancellation, not a server rejection
        assert not worker.is_alive()
        assert len(outcome) == 1
        assert isinstance(outcome[0], ScanCancelledError)
        assert not isinstance(outcome[0], ConnectionToServerFailed)
        # And the socket was closed and is no longer tracked
        assert fake_socket.shutdown_calls >= 1
        assert cancellation.open_connections_count == 0


class TestCompletionVersusCancellationOwnership:
    def test_settlement_that_happens_first_wins(self):
        # Given a job that settles before the scan is cancelled
        cancellation = ScanCancellation()
        job_token = UUID(int=2)
        assert cancellation.register_job(job_token)
        assert cancellation.settle_job_completed(job_token) is True

        # When the scan gets cancelled afterwards
        assert cancellation.cancel() is True

        # Then the completion owned the terminal state
        assert not cancellation.is_job_cancelled(job_token)

    def test_cancellation_that_happens_first_discards_late_result(self):
        # Given a job that is still pending
        cancellation = ScanCancellation()
        job_token = UUID(int=3)
        assert cancellation.register_job(job_token)

        # When the scan is cancelled and the job then tries to settle with its late result
        assert cancellation.cancel() is True
        assert cancellation.settle_job_completed(job_token) is False

        # Then the late result is discarded and the job is owned by the cancellation; it is no longer pending
        assert cancellation.is_job_cancelled(job_token)
        assert cancellation.pending_jobs_count == 0

        # And a second cancellation is a no-op that does not flip any ownership
        assert cancellation.cancel() is False

    def test_worker_racing_cancel_has_exactly_one_terminal_state(self):
        # Given a job blocked at a barrier, with a result ready to be settled
        scan_request = _request({ScanCommand.CERTIFICATE_INFO})
        rendezvous = threading.Barrier(2, timeout=5)
        job_returned = threading.Event()

        class _RacingJobImplementation(ScanCommandImplementation[_Result, None]):
            @classmethod
            def scan_jobs_for_scan_command(cls, server_info, extra_arguments=None):
                return [ScanJob(function_to_call=cls._job, function_arguments=[])]

            @staticmethod
            def _job() -> str:
                job_returned.set()
                # Rendezvous with the test thread before returning the result
                rendezvous.wait()
                return "late-evidence"

            @classmethod
            def result_for_completed_scan_jobs(cls, server_info, scan_job_results):
                return _Result(evidence=scan_job_results[0].get_result())

        observer = _RecordingObserver()
        results: List[Any] = []
        finished = threading.Event()

        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=_connectivity_result()
        ), mock.patch.object(ScanCommandsRepository, "get_implementation_cls", return_value=_RacingJobImplementation):
            scanner = Scanner(concurrent_server_scans_limit=1, observers=[observer])
            scanner.queue_scans([scan_request])
            consumer = _consume_in_background(scanner, results, finished)
            _wait(job_returned, "the job to be ready to return")

            # When the caller cancels while the job is about to produce its result
            scanner.cancel_scans()
            try:
                rendezvous.wait(5)
            except threading.BrokenBarrierError:
                pytest.fail("The job never reached the rendezvous")
            _wait(finished, "the consumer to finish")
            consumer.join(5)

        # Then the request has exactly one terminal state: CANCELLED, with no partial evidence
        assert len(results) == 1
        server_scan_result = results[0]
        assert server_scan_result.uuid == scan_request.uuid
        assert server_scan_result.scan_status == ServerScanStatusEnum.CANCELLED
        attempt = _result_attempts(server_scan_result)[ScanCommand.CERTIFICATE_INFO.value]
        assert attempt.status == ScanCommandAttemptStatusEnum.CANCELLED
        assert attempt.result is None
        assert "late-evidence" not in repr(server_scan_result.scan_result)
        assert observer.terminal_events == [scan_request.uuid]

        # And no result was emitted twice
        assert scanner._cancellation.pending_jobs_count == 0
        assert scanner._cancellation.open_connections_count == 0


class TestLateResultAttribution:
    def test_late_result_never_attaches_to_another_server(self):
        # Given two servers; the first one's job returns a distinctive value only after the scan is cancelled
        first = _request({ScanCommand.CERTIFICATE_INFO})
        second = _request({ScanCommand.CERTIFICATE_INFO})
        job_started = threading.Event()
        job_release = threading.Event()

        class _LateImplementation(ScanCommandImplementation[_Result, None]):
            @classmethod
            def scan_jobs_for_scan_command(cls, server_info, extra_arguments=None):
                return [ScanJob(function_to_call=cls._job, function_arguments=[server_info])]

            @staticmethod
            def _job(server_info: ServerConnectivityInfo) -> str:
                hostname = server_info.server_location.hostname
                if hostname == first.server_location.hostname:
                    job_started.set()
                    job_release.wait(5)
                    return "late-evidence-for-first"
                return "evidence-for-second"

            @classmethod
            def result_for_completed_scan_jobs(cls, server_info, scan_job_results):
                return _Result(evidence=scan_job_results[0].get_result())

        observer = _RecordingObserver()
        results: List[Any] = []
        finished = threading.Event()

        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=_connectivity_result()
        ), mock.patch.object(ScanCommandsRepository, "get_implementation_cls", return_value=_LateImplementation):
            scanner = Scanner(concurrent_server_scans_limit=1, observers=[observer])
            scanner.queue_scans([first, second])
            consumer = _consume_in_background(scanner, results, finished)
            _wait(job_started, "the first server's job to start")

            # When the scan is cancelled and the first server's job returns afterwards
            scanner.cancel_scans()
            job_release.set()
            _wait(finished, "the consumer to finish")
            consumer.join(5)

        # Then both requests have their own terminal result; the late value is nowhere to be found
        assert len(results) == 2
        by_uuid = {result.uuid: result for result in results}
        assert set(by_uuid) == {first.uuid, second.uuid}
        for server_scan_result in results:
            assert server_scan_result.scan_status == ServerScanStatusEnum.CANCELLED
            attempt = _result_attempts(server_scan_result)[ScanCommand.CERTIFICATE_INFO.value]
            assert attempt.status == ScanCommandAttemptStatusEnum.CANCELLED
            assert attempt.result is None
        assert "late-evidence-for-first" not in repr([result.scan_result for result in results])

        # And the observer was notified once per request
        assert sorted(observer.terminal_events) == sorted([first.uuid, second.uuid])
        assert observer.all_completed_calls == 1


class TestConsumerStopsReceiving:
    def test_abandoning_results_does_not_leave_threads_blocked(self):
        # Given a batch of scans in progress
        all_requests = [_request({ScanCommand.CERTIFICATE_INFO}) for _ in range(10)]
        consumers_finished = threading.Event()

        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=_connectivity_result()
        ), mock.patch.object(ScanCommandsRepository, "get_implementation_cls", return_value=_FastJobImplementation):
            scanner = Scanner(concurrent_server_scans_limit=2)
            scanner.queue_scans(all_requests)
            results_iterator = scanner.get_results()

            # When the caller reads one result and stops
            first_result = next(results_iterator)
            assert first_result.uuid in {request.uuid for request in all_requests}

            def close_iterator() -> None:
                results_iterator.close()
                consumers_finished.set()

            closer = threading.Thread(target=close_iterator)
            closer.start()
            _wait(consumers_finished, "the generator to close")
            closer.join(5)

        # Then closing drove the pipeline to a clean shutdown instead of leaving a blocked join
        assert not closer.is_alive()
        assert scanner.is_cancelled


class TestCancelledResultSerialization:
    def test_cancelled_result_round_trips_through_json(self):
        # Given a scan that was cancelled during its connectivity test
        scan_request = _request({ScanCommand.CERTIFICATE_INFO})

        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=_connectivity_result()
        ), mock.patch.object(ScanCommandsRepository, "get_implementation_cls", return_value=_FastJobImplementation):
            scanner = Scanner()
            scanner.queue_scans([scan_request])
            scanner.cancel_scans()
            results = list(scanner.get_results())

        # When serializing it to JSON and back
        assert len(results) == 1
        as_json = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.model_validate(results[0])],
            invalid_server_strings=[],
            date_scans_started=datetime.now(timezone.utc),
            date_scans_completed=datetime.now(timezone.utc),
        )
        json_output_as_str = as_json.model_dump_json()

        # Then the cancelled statuses are preserved and the evidence is kept
        assert '"CANCELLED"' in json_output_as_str
        parsed_output = SslyzeOutputAsJson.model_validate_json(json_output_as_str)
        parsed_result = parsed_output.server_scan_results[0]
        assert str(parsed_result.uuid) == str(scan_request.uuid)
        assert parsed_result.scan_status == ServerScanStatusEnum.CANCELLED
        assert parsed_result.connectivity_status == ServerConnectivityStatusEnum.CANCELLED


class TestNormalScanUnaffectedByCancellationSupport:
    def test_scan_without_cancellation_still_completes(self):
        # Given a normally reachable server
        scan_request = _request({ScanCommand.CERTIFICATE_INFO})
        FastImplementation = type(
            "FastImplementation",
            (_FastJobImplementation,),
            {"job_ran_event": threading.Event()},
        )
        observer = _RecordingObserver()
        results: List[Any] = []

        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=_connectivity_result()
        ), mock.patch.object(ScanCommandsRepository, "get_implementation_cls", return_value=FastImplementation):
            scanner = Scanner(observers=[observer])
            scanner.queue_scans([scan_request])
            results = list(scanner.get_results())

        # Then the scan completed and was never marked as cancelled
        assert len(results) == 1
        assert results[0].uuid == scan_request.uuid
        assert results[0].scan_status == ServerScanStatusEnum.COMPLETED
        assert results[0].scan_result.certificate_info.status == ScanCommandAttemptStatusEnum.COMPLETED
        assert observer.terminal_events == [scan_request.uuid]
        assert observer.all_completed_calls == 1
