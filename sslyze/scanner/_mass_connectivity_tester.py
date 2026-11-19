import queue
import threading
from typing import Optional, Tuple, Union, List, Callable
from uuid import uuid4

from sslyze import ServerScanRequest, ServerTlsProbingResult
from sslyze.errors import ConnectionToServerFailed, ScanCancelledError
from sslyze.scanner._scan_cancellation import ScanCancellation, job_cancellation_context
from sslyze.server_connectivity import check_connectivity_to_server

try:
    # Python 3.10+
    from typing import TypeAlias  # type: ignore
except ImportError:
    # Python 3.9 and before
    from typing_extensions import TypeAlias  # type: ignore


_ServerConnectivityTestingResult = Union[ServerTlsProbingResult, ConnectionToServerFailed]


ServerConnectivityTestCompletedCallback = Callable[[ServerScanRequest, ServerTlsProbingResult], None]
ServerConnectivityTestErrorCallback = Callable[[ServerScanRequest, ConnectionToServerFailed], None]
ServerConnectivityTestCancelledCallback = Callable[[ServerScanRequest], None]


class _NoMoreWorkSentinel:
    pass


_ScanRequestsQueueType: TypeAlias = "queue.Queue[Union[_NoMoreWorkSentinel, ServerScanRequest]]"
_ResultsQueueType: TypeAlias = (
    "queue.Queue[Union[_NoMoreWorkSentinel, Tuple[ServerScanRequest, _ServerConnectivityTestingResult]]]"
)


class MassConnectivityTester:
    """Wrapper around check_connectivity_to_server() for concurrent/mass testing."""

    def __init__(
        self,
        concurrent_server_scans_count: int,
        cancellation: Optional[ScanCancellation] = None,
    ) -> None:
        if concurrent_server_scans_count < 1:
            raise ValueError()

        self._cancellation = cancellation if cancellation is not None else ScanCancellation()
        # Requests that were cancelled are reported through this queue so that the caller can still account for
        # every request it submitted, without being told the server rejected anything.
        self._cancelled_requests_queue: "queue.Queue[ServerScanRequest]" = queue.Queue()
        self._scan_requests_queue: _ScanRequestsQueueType = queue.Queue()
        self._results_queue: _ResultsQueueType = queue.Queue()
        self._all_worker_threads = [
            _ConnectivityTesterThread(
                scan_requests_queue_in=self._scan_requests_queue,
                results_queue_out=self._results_queue,
                cancellation=self._cancellation,
                cancelled_requests_queue=self._cancelled_requests_queue,
            )
            for _ in range(concurrent_server_scans_count)
        ]
        self.has_started_work = False

    @property
    def cancellation(self) -> ScanCancellation:
        return self._cancellation

    def start_work(self, server_scan_requests: List[ServerScanRequest]) -> None:
        assert not self.has_started_work
        self.has_started_work = True

        # Start the threads
        for worker_thread in self._all_worker_threads:
            worker_thread.start()

        # Queue the work
        for request in server_scan_requests:
            self._scan_requests_queue.put(request)

        # Notify workers when all work as been completed
        for _ in self._all_worker_threads:
            self._scan_requests_queue.put(_NoMoreWorkSentinel())

    def wait_until_all_work_was_processed(
        self,
        server_connectivity_test_completed_callback: ServerConnectivityTestCompletedCallback,
        server_connectivity_test_error_callback: ServerConnectivityTestErrorCallback,
        server_connectivity_test_cancelled_callback: Optional[ServerConnectivityTestCancelledCallback] = None,
    ) -> None:
        shutdown_workers_count = 0
        while shutdown_workers_count < len(self._all_worker_threads):
            result = self._results_queue.get(block=True)

            if isinstance(result, _NoMoreWorkSentinel):
                shutdown_workers_count += 1
            else:
                scan_request, connectivity_result = result
                if isinstance(connectivity_result, ConnectionToServerFailed):
                    server_connectivity_test_error_callback(scan_request, connectivity_result)
                elif isinstance(connectivity_result, ServerTlsProbingResult):
                    server_connectivity_test_completed_callback(scan_request, connectivity_result)
                else:
                    raise TypeError()

            self._results_queue.task_done()

        # Report every remaining request as cancelled; no scan will be performed for it
        while not self._cancelled_requests_queue.empty():
            cancelled_request = self._cancelled_requests_queue.get(block=False)
            self._cancelled_requests_queue.task_done()
            if server_connectivity_test_cancelled_callback is not None:
                server_connectivity_test_cancelled_callback(cancelled_request)

        self.join_workers()

        # All done - shut everything down cleanly
        self._scan_requests_queue.join()
        self._results_queue.join()
        self._cancelled_requests_queue.join()

    def join_workers(self) -> None:
        """Wait until every connectivity worker thread has terminated."""
        for worker_thread in self._all_worker_threads:
            worker_thread.join()


class _ConnectivityTesterThread(threading.Thread):
    def __init__(
        self,
        scan_requests_queue_in: _ScanRequestsQueueType,
        results_queue_out: _ResultsQueueType,
        cancellation: Optional[ScanCancellation] = None,
        cancelled_requests_queue: Optional["queue.Queue[ServerScanRequest]"] = None,
    ):
        super().__init__()
        self._scan_requests_queue_in = scan_requests_queue_in
        self._results_queue_out = results_queue_out
        self._cancellation = cancellation if cancellation is not None else ScanCancellation()
        # Exposed so the parent can collect cancelled requests; defaults to a private queue for standalone use.
        self.cancelled_requests_queue: "queue.Queue[ServerScanRequest]" = (
            cancelled_requests_queue if cancelled_requests_queue is not None else queue.Queue()
        )
        self.daemon = True  # Shutdown the thread if the program is exiting early (ie. ctrl+c)

    def run(self) -> None:
        while True:
            scan_request = self._scan_requests_queue_in.get(block=True)

            # If there are no more jobs to complete, notify the parent and shutdown the thread
            if isinstance(scan_request, _NoMoreWorkSentinel):
                self._results_queue_out.put(_NoMoreWorkSentinel())
                self._scan_requests_queue_in.task_done()
                return

            try:
                self._process_request(scan_request)
            finally:
                self._scan_requests_queue_in.task_done()

    def _process_request(self, scan_request: ServerScanRequest) -> None:
        if self._cancellation.is_cancelled:
            self._report_request_cancelled(scan_request)
            return

        job_token = uuid4()
        if not self._cancellation.register_job(job_token):
            self._report_request_cancelled(scan_request)
            return

        try:
            with job_cancellation_context(self._cancellation, job_token):
                tls_probing_result = check_connectivity_to_server(
                    server_location=scan_request.server_location,
                    network_configuration=scan_request.network_configuration,
                )
        except ScanCancelledError:
            self._cancellation.close_connections_for_job(job_token)
            self._report_request_cancelled(scan_request)
            return
        except ConnectionToServerFailed as connectivity_error:
            # First-wins: if the cancellation claimed this job, the failure (which may have been caused by our own
            # socket shutdown) is discarded. A cancellation is never reported as the server rejecting a connection.
            if not self._cancellation.settle_job_completed(job_token):
                self._cancellation.close_connections_for_job(job_token)
                self._report_request_cancelled(scan_request)
                return
            self._cancellation.close_connections_for_job(job_token)
            self._results_queue_out.put((scan_request, connectivity_error))
            return
        except Exception:
            if self._cancellation.is_job_cancelled(job_token):
                # Same rule for unexpected low-level errors triggered by closing the socket: not a server rejection
                self._cancellation.close_connections_for_job(job_token)
                self._report_request_cancelled(scan_request)
                return
            raise

        if not self._cancellation.settle_job_completed(job_token):
            # The cancellation won the race; a late successful probe must not start scans for this request.
            self._cancellation.close_connections_for_job(job_token)
            self._report_request_cancelled(scan_request)
            return

        self._cancellation.close_connections_for_job(job_token)
        self._results_queue_out.put((scan_request, tls_probing_result))

    def _report_request_cancelled(self, scan_request: ServerScanRequest) -> None:
        self.cancelled_requests_queue.put(scan_request)
