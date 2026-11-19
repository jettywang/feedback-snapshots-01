import threading
from dataclasses import dataclass, fields
import queue
from traceback import TracebackException
from typing import Dict, List, Optional, Set, Tuple, Union
from uuid import UUID

from nassl.ssl_client import ClientCertificateRequested

from sslyze import ServerTlsProbingResult, ScanCommandAttemptStatusEnum, ScanCommandErrorReasonEnum
from sslyze.errors import (
    ConnectionToServerTimedOut,
    TlsHandshakeTimedOut,
    ServerRejectedTlsHandshake,
    ScanCancelledError,
)
from sslyze.plugins.plugin_base import ScanCommandWrongUsageError, ScanJob, ScanJobResult
from sslyze.plugins.scan_commands import ScanCommandsRepository, ScanCommand
from sslyze.scanner._jobs_worker_thread import (
    WorkerThreadNoMoreJobsSentinel,
    CompletedScanJob,
    QueuedScanJob,
    JobsWorkerThread,
    WorkerQueueType,
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
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
from sslyze.server_connectivity import ServerConnectivityInfo

from typing import TypeAlias


# How long the producer waits before re-checking for completed jobs; it also wakes up immediately on cancellation.
_PRODUCER_POLL_INTERVAL_SECONDS = 0.2


@dataclass
class _OngoingServerScan:
    server_scan_request: ServerScanRequest
    server_connectivity_result: ServerTlsProbingResult
    assigned_queue: queue.Queue
    scan_command_errors_during_queuing: Dict[ScanCommand, ScanCommandAttempt]
    # Which scan commands were requested; used to mark the ones that never ran as CANCELLED when the caller stops the
    # scan.
    requested_scan_commands: Set[ScanCommand]
    queued_scan_jobs_count: int
    # Number of jobs each scan command would need to produce a result; used to detect commands that were cut short by
    # a cancellation.
    expected_scan_jobs_count_per_scan_cmd: Dict[ScanCommand, int]
    completed_scan_jobs: List[CompletedScanJob]  # Populated as the scan is getting completed

    @property
    def is_completed(self) -> bool:
        return self.queued_scan_jobs_count == len(self.completed_scan_jobs)


class NoMoreServerScanRequestsSentinel:
    pass


ServerScanRequestsQueueType: TypeAlias = (
    "queue.Queue[Union[NoMoreServerScanRequestsSentinel, Tuple[ServerScanRequest, ServerTlsProbingResult]]]"
)
ServerScanResultsQueueType: TypeAlias = "queue.Queue[Union[NoMoreServerScanRequestsSentinel, ServerScanResult]]"


class MassScannerProducerThread(threading.Thread):
    """Thread to continuously process more scans and the corresponding jobs as previous ones get completed.

    The goal is to reduce memory usage, by only generating objects related to a single server scan (ScanJob, etc.) when
    the scan is ongoing, instead of generating all objects for all scans at the very beginning.
    The previous implementation used ThreadPoolExecutor and took a lot memory because it did just that:
    https://github.com/nabla-c0d3/sslyze/issues/511

    When the supplied ScanCancellation gets cancelled, no new server scan is admitted. Scans that were already
    admitted are drained so that the jobs that completed before the cancellation keep their evidence; their jobs that
    never started are discarded and their remaining scan commands are marked as CANCELLED.
    """

    def __init__(
        self,
        concurrent_server_scans_count: int,
        per_server_concurrent_connections_count: int,
        server_scan_requests_queue_in: ServerScanRequestsQueueType,
        server_scan_results_queue_out: ServerScanResultsQueueType,
        cancellation: Optional[ScanCancellation] = None,
    ):
        super().__init__()
        self._server_scan_results_queue_out = server_scan_results_queue_out
        self._server_scan_requests_queue_in = server_scan_requests_queue_in
        self._cancellation = cancellation if cancellation is not None else ScanCancellation()
        # Set once the cancellation is observed; used to stop admitting new server scans while still draining the
        # scans that were already admitted.
        self._has_stopped_admitting_new_scans = False
        self.daemon = True  # Shutdown the thread if the program is exiting early (ie. ctrl+c)

        # Create internal threads and queues for dispatching jobs
        self._completed_jobs_queue: queue.Queue[CompletedScanJob] = queue.Queue()
        self._all_worker_queues: List[WorkerQueueType] = [queue.Queue() for _ in range(concurrent_server_scans_count)]
        self._worker_threads_per_queues_count = per_server_concurrent_connections_count
        self._all_worker_threads = []
        for worker_queue in self._all_worker_queues:
            self._all_worker_threads.extend(
                [
                    JobsWorkerThread(
                        jobs_queue_in=worker_queue,
                        completed_jobs_queue_out=self._completed_jobs_queue,
                        cancellation=self._cancellation,
                    )
                    for _ in range(self._worker_threads_per_queues_count)
                ]
            )
        for worker_thread in self._all_worker_threads:
            worker_thread.start()

    @property
    def cancellation(self) -> ScanCancellation:
        return self._cancellation

    def _wait_for_work(self) -> None:
        # Wait for jobs to complete, but wake up immediately if the scan gets cancelled
        self._cancellation.wait(_PRODUCER_POLL_INTERVAL_SECONDS)

    def _should_stop_admitting_new_scans(self) -> bool:
        if not self._has_stopped_admitting_new_scans and self._cancellation.is_cancelled:
            self._has_stopped_admitting_new_scans = True
        return self._has_stopped_admitting_new_scans

    def run(self) -> None:
        all_ongoing_server_scans: Dict[UUID, _OngoingServerScan] = {}

        # Start the first batch of scans; dispatch one server scan per available queue
        has_retrieved_all_server_scan_requests = False
        for worker_queue in self._all_worker_queues:
            entry_in_queue = self._server_scan_requests_queue_in.get(block=True)
            if isinstance(entry_in_queue, NoMoreServerScanRequestsSentinel):
                has_retrieved_all_server_scan_requests = True
                self._server_scan_requests_queue_in.task_done()
                break

            server_scan_request, server_connectivity_result = entry_in_queue
            next_queued_server_scan = _queue_server_scan(
                server_scan_request=server_scan_request,
                server_connectivity_result=server_connectivity_result,
                assigned_worker_queue=worker_queue,
                cancellation=self._cancellation,
            )
            all_ongoing_server_scans[server_scan_request.uuid] = next_queued_server_scan
            self._server_scan_requests_queue_in.task_done()

        # Main loop for checking if a server scan was completed and queuing the next scan
        while all_ongoing_server_scans:
            # Wait for some jobs to complete
            self._wait_for_work()

            # Retrieve and store completed jobs; a job whose parent scan is not tracked anymore (should never happen)
            # is dropped rather than corrupting another scan.
            while not self._completed_jobs_queue.empty():
                completed_job = self._completed_jobs_queue.get(block=False)
                parent_server_scan = all_ongoing_server_scans.get(completed_job.parent_server_scan_request_uuid)
                if parent_server_scan is not None:
                    parent_server_scan.completed_scan_jobs.append(completed_job)
                self._completed_jobs_queue.task_done()

            # Check if any server scan has been fully completed
            all_completed_server_scans = []
            for ongoing_server_scan in all_ongoing_server_scans.values():
                if ongoing_server_scan.is_completed:
                    all_completed_server_scans.append(ongoing_server_scan)

            # For fully completed scans, send back the results
            for completed_server_scan in all_completed_server_scans:
                del all_ongoing_server_scans[completed_server_scan.server_scan_request.uuid]
                server_scan_result = _generate_result_for_completed_server_scan(
                    completed_scan=completed_server_scan,
                    was_cancelled=self._should_stop_admitting_new_scans(),
                )
                self._server_scan_results_queue_out.put(server_scan_result)

                # After sending the result, start the next server scan on the same queue
                if has_retrieved_all_server_scan_requests or self._should_stop_admitting_new_scans():
                    # But do nothing if all the scans have already been queued, or if the scan was cancelled
                    continue

                entry_in_queue = self._server_scan_requests_queue_in.get(block=True)
                if isinstance(entry_in_queue, NoMoreServerScanRequestsSentinel):
                    # No more server scans
                    has_retrieved_all_server_scan_requests = True
                    self._server_scan_requests_queue_in.task_done()
                else:
                    server_scan_request, server_connectivity_result = entry_in_queue
                    next_queued_server_scan = _queue_server_scan(
                        server_scan_request=server_scan_request,
                        server_connectivity_result=server_connectivity_result,
                        assigned_worker_queue=completed_server_scan.assigned_queue,
                        cancellation=self._cancellation,
                    )
                    all_ongoing_server_scans[server_scan_request.uuid] = next_queued_server_scan
                    self._server_scan_requests_queue_in.task_done()

        # If we get here there are no more ongoing server scans; we are all done
        # If the scan was cancelled, requests that were queued for admission but never admitted still need one
        # terminal result each: their connectivity test may have completed, but no scan command was run. When the
        # NoMore sentinel was already consumed, there is nothing left to drain.
        if not has_retrieved_all_server_scan_requests:
            self._drain_unadmitted_requests()

        # Shutdown the worker queue and threads
        self._completed_jobs_queue.join()
        for worker_queue in self._all_worker_queues:
            for _ in range(self._worker_threads_per_queues_count):
                worker_queue.put(WorkerThreadNoMoreJobsSentinel())
        for worker_queue in self._all_worker_queues:
            worker_queue.join()

        for worker_thread in self._all_worker_threads:
            worker_thread.join()

        self._server_scan_results_queue_out.put(NoMoreServerScanRequestsSentinel())

    def _drain_unadmitted_requests(self) -> None:
        while True:
            entry_in_queue = self._server_scan_requests_queue_in.get(block=True)
            self._server_scan_requests_queue_in.task_done()
            if isinstance(entry_in_queue, NoMoreServerScanRequestsSentinel):
                return
            server_scan_request, server_connectivity_result = entry_in_queue
            self._server_scan_results_queue_out.put(
                _generate_result_for_cancelled_server_scan(
                    server_scan_request=server_scan_request,
                    server_connectivity_result=server_connectivity_result,
                )
            )


def _queue_server_scan(
    server_scan_request: ServerScanRequest,
    server_connectivity_result: ServerTlsProbingResult,
    assigned_worker_queue: WorkerQueueType,
    cancellation: Optional[ScanCancellation] = None,
) -> _OngoingServerScan:
    # Queue all the underlying jobs for this server scan
    all_scan_jobs_per_scan_cmd, scan_command_errors_during_queuing = _generate_scan_jobs_for_server_scan(
        server_scan_request=server_scan_request,
        server_connectivity_result=server_connectivity_result,
    )
    total_job_counts = 0
    expected_scan_jobs_count_per_scan_cmd = {
        scan_cmd: len(all_jobs) for scan_cmd, all_jobs in all_scan_jobs_per_scan_cmd.items()
    }
    is_cancelled = cancellation is not None and cancellation.is_cancelled
    for scan_cmd, all_jobs in all_scan_jobs_per_scan_cmd.items():
        for job in all_jobs:
            if is_cancelled:
                # Do not queue work after the cancellation; the job is accounted for and will be reported as
                # CANCELLED by _generate_result_for_completed_server_scan().
                continue
            assigned_worker_queue.put(
                QueuedScanJob(
                    parent_server_scan_request_uuid=server_scan_request.uuid,
                    for_scan_command=scan_cmd,
                    function_to_call=job.function_to_call,
                    function_arguments=job.function_arguments,
                )
            )
            total_job_counts += 1

    # Return information about the server scan that was just queued
    queued_server_scan = _OngoingServerScan(
        server_scan_request=server_scan_request,
        server_connectivity_result=server_connectivity_result,
        assigned_queue=assigned_worker_queue,
        scan_command_errors_during_queuing=scan_command_errors_during_queuing,
        requested_scan_commands=set(server_scan_request.scan_commands),
        queued_scan_jobs_count=total_job_counts,
        expected_scan_jobs_count_per_scan_cmd=expected_scan_jobs_count_per_scan_cmd,
        completed_scan_jobs=[],
    )
    return queued_server_scan


def _generate_scan_jobs_for_server_scan(
    server_scan_request: ServerScanRequest,
    server_connectivity_result: ServerTlsProbingResult,
) -> Tuple[Dict[ScanCommand, List[ScanJob]], Dict[ScanCommand, ScanCommandAttempt]]:
    all_scan_jobs_per_scan_cmd: Dict[ScanCommand, List[ScanJob]] = {}
    scan_command_errors_during_queuing: Dict[ScanCommand, ScanCommandAttempt] = {}
    for scan_cmd in server_scan_request.scan_commands:
        implementation_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd)
        scan_cmd_extra_args = getattr(server_scan_request.scan_commands_extra_arguments, scan_cmd, None)

        try:
            jobs_for_scan_cmd = implementation_cls.scan_jobs_for_scan_command(
                server_info=ServerConnectivityInfo(
                    server_location=server_scan_request.server_location,
                    network_configuration=server_scan_request.network_configuration,
                    tls_probing_result=server_connectivity_result,
                ),
                extra_arguments=scan_cmd_extra_args,
            )
            all_scan_jobs_per_scan_cmd[scan_cmd] = jobs_for_scan_cmd

        # Process exceptions and instantly "complete" the scan command if the call to create the jobs failed
        except ScanCommandWrongUsageError as e:
            scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)
            errored_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.WRONG_USAGE,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )
            scan_command_errors_during_queuing[scan_cmd] = errored_attempt
        except Exception as e:
            scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)
            errored_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )
            scan_command_errors_during_queuing[scan_cmd] = errored_attempt

    return all_scan_jobs_per_scan_cmd, scan_command_errors_during_queuing


def _generate_cancelled_attempt(scan_cmd: ScanCommand) -> ScanCommandAttempt:
    scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)
    return scan_command_attempt_cls(
        status=ScanCommandAttemptStatusEnum.CANCELLED,
        error_reason=None,
        error_trace=None,
        result=None,
    )


def _generate_result_for_cancelled_server_scan(
    server_scan_request: ServerScanRequest,
    server_connectivity_result: ServerTlsProbingResult,
) -> ServerScanResult:
    """Build the result of a request whose connectivity test succeeded, but which never got admitted for scanning."""
    completed_scan = _OngoingServerScan(
        server_scan_request=server_scan_request,
        server_connectivity_result=server_connectivity_result,
        assigned_queue=queue.Queue(),
        scan_command_errors_during_queuing={},
        requested_scan_commands=set(server_scan_request.scan_commands),
        queued_scan_jobs_count=0,
        expected_scan_jobs_count_per_scan_cmd={scan_cmd: 1 for scan_cmd in server_scan_request.scan_commands},
        completed_scan_jobs=[],
    )
    return _generate_result_for_completed_server_scan(completed_scan=completed_scan, was_cancelled=True)


def _generate_result_for_completed_server_scan(
    completed_scan: _OngoingServerScan,
    was_cancelled: bool = False,
) -> ServerScanResult:
    all_scan_command_attempts: Dict[ScanCommand, ScanCommandAttempt] = {}

    # Group all the completed jobs per scan command; jobs claimed by the cancellation are accounted for but never
    # used as evidence.
    scan_cmd_to_completed_jobs: Dict[ScanCommand, List[CompletedScanJob]] = {
        scan_cmd: [] for scan_cmd in completed_scan.server_scan_request.scan_commands
    }
    for completed_job in completed_scan.completed_scan_jobs:
        if completed_job.was_cancelled:
            continue
        scan_cmd_to_completed_jobs[completed_job.for_scan_command].append(completed_job)

    # A scan command can only produce a result if all of its jobs produced one; when the scan was cancelled, the
    # scan commands that did not get all of their jobs are reported as CANCELLED instead of ERROR.
    if was_cancelled:
        # Jobs for commands that never got all their results are reported as CANCELLED even if no job terminal was
        # produced (for example, work that was never admitted to a worker queue).
        for scan_cmd in completed_scan.requested_scan_commands:
            expected_jobs_count = completed_scan.expected_scan_jobs_count_per_scan_cmd.get(scan_cmd, 0)
            if len(scan_cmd_to_completed_jobs.get(scan_cmd, [])) < expected_jobs_count:
                all_scan_command_attempts[scan_cmd] = _generate_cancelled_attempt(scan_cmd)

    for scan_cmd, completed_scan_jobs in scan_cmd_to_completed_jobs.items():
        if scan_cmd in all_scan_command_attempts:
            # Already reported as CANCELLED
            continue
        scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)

        expected_jobs_count = completed_scan.expected_scan_jobs_count_per_scan_cmd.get(scan_cmd, 0)
        if was_cancelled and len(completed_scan_jobs) < expected_jobs_count:
            all_scan_command_attempts[scan_cmd] = _generate_cancelled_attempt(scan_cmd)
            continue

        # Pass the completed scan jobs to the corresponding plugin implementation to generate a result
        scan_job_results_for_plugin = [
            ScanJobResult(_return_value=job.return_value, _exception=job.exception) for job in completed_scan_jobs
        ]
        plugin_implementation_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd)
        try:
            scan_cmd_result = plugin_implementation_cls.result_for_completed_scan_jobs(
                server_info=ServerConnectivityInfo(
                    server_location=completed_scan.server_scan_request.server_location,
                    network_configuration=completed_scan.server_scan_request.network_configuration,
                    tls_probing_result=completed_scan.server_connectivity_result,
                ),
                scan_job_results=scan_job_results_for_plugin,
            )
            scan_cmd_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.COMPLETED,
                error_reason=None,
                error_trace=None,
                result=scan_cmd_result,
            )

        # Process exceptions that may have been raised while the jobs were being completed
        except ScanCancelledError:
            # Never report a cancellation as a server rejection or an SSLyze error
            scan_cmd_attempt = _generate_cancelled_attempt(scan_cmd)
        except ClientCertificateRequested as e:
            scan_cmd_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )
        except (ConnectionToServerTimedOut, TlsHandshakeTimedOut, ServerRejectedTlsHandshake) as e:
            scan_cmd_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )
        except Exception as e:
            scan_cmd_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )

        all_scan_command_attempts[scan_cmd] = scan_cmd_attempt

    # Add scan command attempts that failed when queuing them
    all_scan_command_attempts.update(completed_scan.scan_command_errors_during_queuing)

    # Add remaining scan commands as NOT_SCHEDULED, or CANCELLED if the caller cancelled the scan
    for cls_field in fields(AllScanCommandsAttempts):
        if cls_field.name not in all_scan_command_attempts:
            scan_cmd = ScanCommand(cls_field.name)
            if was_cancelled and scan_cmd in completed_scan.requested_scan_commands:
                # This scan command was requested but the cancellation prevented it from completing
                all_scan_command_attempts[scan_cmd] = _generate_cancelled_attempt(scan_cmd)
            else:
                scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)
                all_scan_command_attempts[scan_cmd] = scan_command_attempt_cls(
                    status=ScanCommandAttemptStatusEnum.NOT_SCHEDULED,
                    error_reason=None,
                    error_trace=None,
                    result=None,
                )

    # Generate the final scan_result object
    scan_cmd_str_to_scan_cmd_result = {
        scan_cmd.value: scan_cmd_result for scan_cmd, scan_cmd_result in all_scan_command_attempts.items()
    }
    scan_result = AllScanCommandsAttempts(**scan_cmd_str_to_scan_cmd_result)  # type: ignore

    # Cancellation vs. completion: if every requested scan command reached a terminal, non-cancelled state, the
    # scan had actually completed before the cancellation and is reported as such (first-wins).
    scan_status = ServerScanStatusEnum.COMPLETED
    if was_cancelled:
        scan_status = ServerScanStatusEnum.CANCELLED
        for requested_scan_cmd in completed_scan.requested_scan_commands:
            requested_attempt = all_scan_command_attempts.get(requested_scan_cmd)
            if requested_attempt is None or requested_attempt.status == ScanCommandAttemptStatusEnum.CANCELLED:
                break
        else:
            scan_status = ServerScanStatusEnum.COMPLETED

    # Lastly, return the fully completed server scan
    server_scan_result = ServerScanResult(
        uuid=completed_scan.server_scan_request.uuid,
        server_location=completed_scan.server_scan_request.server_location,
        network_configuration=completed_scan.server_scan_request.network_configuration,
        connectivity_status=ServerConnectivityStatusEnum.COMPLETED,
        connectivity_error_trace=None,
        connectivity_result=completed_scan.server_connectivity_result,
        scan_status=scan_status,
        scan_result=scan_result,
    )
    return server_scan_result
