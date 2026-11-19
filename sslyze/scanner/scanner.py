import queue
from dataclasses import fields
from traceback import TracebackException
from typing import List, Optional, Generator, Sequence

from sslyze import ServerTlsProbingResult
from sslyze.errors import ConnectionToServerFailed
from sslyze.scanner._mass_connectivity_tester import MassConnectivityTester
from sslyze.scanner._mass_scanner import (
    MassScannerProducerThread,
    NoMoreServerScanRequestsSentinel,
    ServerScanRequestsQueueType,
    ServerScanResultsQueueType,
)
from sslyze.scanner._scan_cancellation import ScanCancellation
from sslyze.scanner.models import (
    ServerScanRequest,
    ServerScanResult,
    ServerConnectivityStatusEnum,
    ServerScanStatusEnum,
    AllScanCommandsAttempts,
    get_scan_command_attempt_cls,
)
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum


from sslyze.scanner.scanner_observer import ScannerObserver


class Scanner:
    def __init__(
        self,
        per_server_concurrent_connections_limit: Optional[int] = None,
        concurrent_server_scans_limit: Optional[int] = None,
        observers: Optional[Sequence[ScannerObserver]] = None,
    ):
        self._observers: Sequence[ScannerObserver]
        if observers is None:
            self._observers = []
        else:
            self._observers = observers

        # Setup default values
        if per_server_concurrent_connections_limit is None:
            final_per_server_concurrent_connections_limit = 5
        else:
            final_per_server_concurrent_connections_limit = per_server_concurrent_connections_limit
        self._per_server_concurrent_connections_count = final_per_server_concurrent_connections_limit

        if concurrent_server_scans_limit is None:
            final_concurrent_server_scans_limit = 10
        else:
            final_concurrent_server_scans_limit = concurrent_server_scans_limit
        self._concurrent_server_scans_count = final_concurrent_server_scans_limit

        # Shared by connectivity testing and all the job workers; calling cancel() on it stops the scan and closes
        # the connections of jobs that have not completed yet.
        self._cancellation = ScanCancellation()
        self._connectivity_tester = MassConnectivityTester(
            self._concurrent_server_scans_count, cancellation=self._cancellation
        )
        self._results_iterator_was_created = False

    def queue_scans(self, server_scan_requests: List[ServerScanRequest]) -> None:
        if self._has_started_work:
            raise ValueError("Already submitted scan requests")

        if not server_scan_requests:
            raise ValueError("Submitted emtpy list of server_scan_requests")

        # Start with connectivity testing
        self._connectivity_tester.start_work(server_scan_requests)

    @property
    def _has_started_work(self) -> bool:
        return self._connectivity_tester.has_started_work

    def cancel_scans(self) -> None:
        """Stop the scans as soon as possible.

        No new connectivity tests or scan jobs are started. Connections of TLS handshakes that are currently in
        progress get closed so that workers can shut down. The results of jobs that completed before the cancellation
        are kept: every request still yields one ServerScanResult, whose scan_status is CANCELLED (or COMPLETED if it
        had already finished) and whose scan commands that could not finish are marked as CANCELLED.

        Calling this method more than once is safe.
        """
        self._cancellation.cancel()

    @property
    def is_cancelled(self) -> bool:
        return self._cancellation.is_cancelled

    def get_results(self) -> Generator[ServerScanResult, None, None]:
        if not self._has_started_work:
            raise ValueError("No scan requests have been submitted")
        if self._results_iterator_was_created:
            raise ValueError("get_results() can only be called once")
        self._results_iterator_was_created = True

        # Setup the queues for running and completing the scans
        server_scan_requests_queue: ServerScanRequestsQueueType = queue.Queue()
        server_scan_results_queue: ServerScanResultsQueueType = queue.Queue()

        # Requests for which connectivity testing was cancelled get a terminal result without starting any scan
        all_cancelled_requests: List[ServerScanRequest] = []

        def server_connectivity_test_completed_callback(
            server_scan_request: ServerScanRequest, connectivity_result: ServerTlsProbingResult
        ) -> None:
            for inner_observer in self._observers:
                inner_observer.server_connectivity_test_completed(server_scan_request, connectivity_result)

            # Since the server is reachable, queue the actual scan commands
            server_scan_requests_queue.put((server_scan_request, connectivity_result))

        def server_connectivity_test_error_callback(
            server_scan_request: ServerScanRequest, connectivity_error: ConnectionToServerFailed
        ) -> None:
            for inner_observer in self._observers:
                inner_observer.server_connectivity_test_error(server_scan_request, connectivity_error)

            # Since the server is not reachable, there is nothing else to do
            server_scan_results_queue.put(
                ServerScanResult(
                    uuid=server_scan_request.uuid,
                    server_location=server_scan_request.server_location,
                    network_configuration=server_scan_request.network_configuration,
                    connectivity_status=ServerConnectivityStatusEnum.ERROR,
                    connectivity_error_trace=TracebackException.from_exception(connectivity_error),
                    connectivity_result=None,
                    scan_status=ServerScanStatusEnum.ERROR_NO_CONNECTIVITY,
                    scan_result=None,
                )
            )

        def server_connectivity_test_cancelled_callback(server_scan_request: ServerScanRequest) -> None:
            # Not a connectivity error: the caller stopped the scan
            for inner_observer in self._observers:
                inner_observer.server_connectivity_test_cancelled(server_scan_request)
            all_cancelled_requests.append(server_scan_request)

        # Initialize the MassScanner for running scan commands
        mass_scanner_thread = MassScannerProducerThread(
            concurrent_server_scans_count=self._concurrent_server_scans_count,
            per_server_concurrent_connections_count=self._per_server_concurrent_connections_count,
            server_scan_requests_queue_in=server_scan_requests_queue,
            server_scan_results_queue_out=server_scan_results_queue,
            cancellation=self._cancellation,
        )
        mass_scanner_thread.start()

        # Wait until all connectivity testing has been completed
        self._connectivity_tester.wait_until_all_work_was_processed(
            server_connectivity_test_completed_callback=server_connectivity_test_completed_callback,
            server_connectivity_test_error_callback=server_connectivity_test_error_callback,
            server_connectivity_test_cancelled_callback=server_connectivity_test_cancelled_callback,
        )

        # Notify the MassScanner that all the scan requests have been queued
        server_scan_requests_queue.put(NoMoreServerScanRequestsSentinel())

        # Wait for all scans to finish
        has_received_all_results = False
        try:
            while True:
                server_scan_result = server_scan_results_queue.get(block=True)
                server_scan_results_queue.task_done()
                if isinstance(server_scan_result, NoMoreServerScanRequestsSentinel):
                    # All scans have been completed
                    has_received_all_results = True
                    break

                # Notify observers and yield the completed scan
                for observer in self._observers:
                    observer.server_scan_completed(server_scan_result)

                yield server_scan_result

            # Requests whose connectivity test was cancelled never reached the MassScanner; give them a terminal
            # result so that the caller can account for every submitted request.
            all_cancelled_results = [
                _generate_result_for_cancelled_connectivity(cancelled_request)
                for cancelled_request in all_cancelled_requests
            ]
            for cancelled_result in all_cancelled_results:
                for observer in self._observers:
                    observer.server_scan_completed(cancelled_result)
                yield cancelled_result
        finally:
            # Always drive the pipeline to a clean shutdown. If the consumer abandons the generator early, the
            # producer may be waiting for results to be acknowledged, so cancellation is requested and the results
            # queue is drained until the producer signals that it is done. This guarantees no blocked join().
            if not has_received_all_results:
                self._cancellation.cancel()
                while True:
                    leftover_result = server_scan_results_queue.get(block=True)
                    server_scan_results_queue.task_done()
                    if isinstance(leftover_result, NoMoreServerScanRequestsSentinel):
                        break

            server_scan_requests_queue.join()
            mass_scanner_thread.join()
            self._connectivity_tester.join_workers()

            for observer in self._observers:
                observer.all_server_scans_completed()


def _generate_result_for_cancelled_connectivity(server_scan_request: ServerScanRequest) -> ServerScanResult:
    """Build the result of a request that was cancelled before its connectivity could be tested."""
    all_scan_command_attempts = {}
    for cls_field in fields(AllScanCommandsAttempts):
        scan_cmd = ScanCommand(cls_field.name)
        scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)
        if scan_cmd in server_scan_request.scan_commands:
            # Requested but never run because the caller cancelled the scan
            status = ScanCommandAttemptStatusEnum.CANCELLED
        else:
            status = ScanCommandAttemptStatusEnum.NOT_SCHEDULED
        all_scan_command_attempts[scan_cmd] = scan_command_attempt_cls(
            status=status,
            error_reason=None,
            error_trace=None,
            result=None,
        )

    scan_result = AllScanCommandsAttempts(
        **{scan_cmd.value: scan_cmd_attempt for scan_cmd, scan_cmd_attempt in all_scan_command_attempts.items()}  # type: ignore
    )
    return ServerScanResult(
        uuid=server_scan_request.uuid,
        server_location=server_scan_request.server_location,
        network_configuration=server_scan_request.network_configuration,
        connectivity_status=ServerConnectivityStatusEnum.CANCELLED,
        connectivity_error_trace=None,
        connectivity_result=None,
        scan_status=ServerScanStatusEnum.CANCELLED,
        scan_result=scan_result,
    )
