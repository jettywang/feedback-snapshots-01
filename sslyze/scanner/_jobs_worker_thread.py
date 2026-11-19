import threading
from dataclasses import dataclass, field
import queue
from typing import Optional, Any, Callable, Sequence, Union
from uuid import UUID, uuid4

from sslyze.errors import ScanCancelledError
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner._scan_cancellation import ScanCancellation, job_cancellation_context


from typing import TypeAlias


@dataclass(frozen=True)
class CompletedScanJob:
    parent_server_scan_request_uuid: UUID
    for_scan_command: ScanCommand

    return_value: Optional[Any]
    exception: Optional[Exception]

    # True when the job was claimed by the cancellation; the job still gets a terminal state for accounting, but its
    # return value/exception is never used as evidence.
    was_cancelled: bool = False


@dataclass(frozen=True)
class QueuedScanJob:
    parent_server_scan_request_uuid: UUID
    for_scan_command: ScanCommand

    function_to_call: Callable
    function_arguments: Sequence[Any]

    # Unique ID used to decide who owns this job's terminal state when a cancellation races with its completion
    job_token: UUID = field(default_factory=uuid4)


class WorkerThreadNoMoreJobsSentinel:
    pass


WorkerQueueType: TypeAlias = "queue.Queue[Union[WorkerThreadNoMoreJobsSentinel, QueuedScanJob]]"


class JobsWorkerThread(threading.Thread):
    def __init__(
        self,
        jobs_queue_in: WorkerQueueType,
        completed_jobs_queue_out: "queue.Queue[CompletedScanJob]",
        cancellation: Optional[ScanCancellation] = None,
    ):
        super().__init__()
        self._jobs_queue_in = jobs_queue_in
        self._completed_jobs_queue_out = completed_jobs_queue_out
        self._cancellation = cancellation
        self.daemon = True  # Shutdown the thread if the program is exiting early (ie. ctrl+c)

    def run(self) -> None:
        while True:
            job_to_complete = self._jobs_queue_in.get(block=True)
            if isinstance(job_to_complete, WorkerThreadNoMoreJobsSentinel):
                self._jobs_queue_in.task_done()
                # No more jobs to complete - shutdown the thread
                break

            try:
                self._run_job(job_to_complete)
            finally:
                self._jobs_queue_in.task_done()

    def _report_cancelled_job(self, job_to_complete: QueuedScanJob) -> None:
        self._completed_jobs_queue_out.put(
            CompletedScanJob(
                parent_server_scan_request_uuid=job_to_complete.parent_server_scan_request_uuid,
                for_scan_command=job_to_complete.for_scan_command,
                return_value=None,
                exception=None,
                was_cancelled=True,
            )
        )

    def _run_job(self, job_to_complete: QueuedScanJob) -> None:
        cancellation = self._cancellation
        if cancellation is not None and not cancellation.register_job(job_to_complete.job_token):
            # The scan was cancelled before this job started; it must not run. Its terminal state is still reported
            # so that the parent scan can be accounted for and converge.
            self._report_cancelled_job(job_to_complete)
            return

        return_value: Optional[Any] = None
        exception: Optional[Exception] = None
        try:
            if cancellation is None:
                return_value = job_to_complete.function_to_call(*job_to_complete.function_arguments)
            else:
                with job_cancellation_context(cancellation, job_to_complete.job_token):
                    return_value = job_to_complete.function_to_call(*job_to_complete.function_arguments)
        except ScanCancelledError as e:
            # Either the scan was cancelled while this job was running, or a connection got closed under it.
            # This is not an error from the server; the job has no result.
            exception = e
        except Exception as e:
            exception = e

        if cancellation is not None:
            # First-wins: if cancel() already claimed this job, the result is discarded and the job is reported as
            # CANCELLED; a late result is never attached to another target.
            was_result_accepted = cancellation.settle_job_completed(job_to_complete.job_token)
            # Ensure any socket still owned by this job is closed before we report it as terminal
            cancellation.close_connections_for_job(job_to_complete.job_token)
            if not was_result_accepted:
                self._report_cancelled_job(job_to_complete)
                return

        if isinstance(exception, ScanCancelledError):
            # A cancellation that got registered after the job started; it is never an ERROR nor a server rejection
            self._report_cancelled_job(job_to_complete)
            return

        self._completed_jobs_queue_out.put(
            CompletedScanJob(
                parent_server_scan_request_uuid=job_to_complete.parent_server_scan_request_uuid,
                for_scan_command=job_to_complete.for_scan_command,
                return_value=return_value,
                exception=exception,
            )
        )
