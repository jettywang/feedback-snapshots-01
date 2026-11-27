"""Operator-gated recovery of quarantined failed jobs.

Jobs stranded by misconfigured workers are placed into in-memory quarantine
records. Each record is a plain-data forensic snapshot of the failure (job ID,
origin queue, function name, exception info) kept even after the job itself is
released. On-call staff can inspect record metadata, and only records that have
been explicitly approved may be released back onto a queue.

Release is gated on a local re-verification that never executes the job's
function: the job must still be fetchable and deserializable (readable), and
its function name (purpose) and origin queue must still match the approved
record.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .exceptions import (
    DeserializationError,
    NoSuchJobError,
    RecoveryError,
    RecoveryNotApprovedError,
    RecoveryVerificationError,
)
from .job import Job
from .registry import FailedJobRegistry
from .serializers import resolve_serializer
from .utils import now

if TYPE_CHECKING:
    from redis import Redis

    from .serializers import Serializer


class QuarantineState(enum.Enum):
    """Lifecycle of a quarantined failure record."""

    QUARANTINED = 'quarantined'
    APPROVED = 'approved'
    RELEASED = 'released'
    REJECTED = 'rejected'


@dataclass
class QuarantineRecord:
    """Plain-data snapshot of a failed job, kept for forensics and gated recovery.

    The record is never deleted: releasing the job transitions the state to
    ``RELEASED`` while the original failure metadata (notably ``exc_info``)
    stays available for audit.
    """

    job_id: str
    queue_name: str
    func_name: str
    exc_info: str
    state: QuarantineState = QuarantineState.QUARANTINED
    quarantined_at: datetime | None = None
    note: str = ''
    approved_by: str | None = None
    approved_at: datetime | None = None
    released_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        """Returns the operator-facing metadata view of this record."""
        return {
            'job_id': self.job_id,
            'queue_name': self.queue_name,
            'func_name': self.func_name,
            'exc_info': self.exc_info,
            'state': self.state.value,
            'quarantined_at': self.quarantined_at.isoformat() if self.quarantined_at else None,
            'note': self.note,
            'approved_by': self.approved_by,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'released_at': self.released_at.isoformat() if self.released_at else None,
        }


class RecoveryManager:
    """In-memory quarantine store and approval gate for recovering failed jobs.

    Records live only in this process; the Redis-side failure data stays in the
    ``FailedJobRegistry`` until a record is approved and released.
    """

    def __init__(self, connection: Redis, serializer: Serializer | str | None = None):
        self.connection = connection
        self.serializer = resolve_serializer(serializer)
        self._records: dict[str, QuarantineRecord] = {}

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, job_id: str) -> bool:
        return job_id in self._records

    def quarantine(self, job_or_id: Job | str, note: str = '') -> QuarantineRecord:
        """Snapshots a failed job into an in-memory quarantine record.

        Reads the job back from Redis (forcing deserialization of its payload)
        so unreadable jobs are caught at intake. The original failure data in
        Redis is left untouched.

        Args:
            job_or_id (Union[Job, str]): The failed Job or its ID.
            note (str, optional): Free-form operator note. Defaults to ''.

        Returns:
            QuarantineRecord: The freshly quarantined record.
        """
        if isinstance(job_or_id, Job):
            job = job_or_id
        else:
            job = Job.fetch(job_or_id, connection=self.connection, serializer=self.serializer)
        latest = job.latest_result()
        record = QuarantineRecord(
            job_id=job.id,
            queue_name=job.origin or '',
            func_name=job.func_name or '',
            exc_info=(latest.exc_string or '') if latest else '',
            quarantined_at=now(),
            note=note,
        )
        self._records[job.id] = record
        return record

    def inspect(self, job_id: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        """Returns quarantine metadata for on-call review.

        Args:
            job_id (Optional[str]): When given, the metadata of that single record;
                otherwise a list of all records' metadata.

        Raises:
            RecoveryError: If no record exists for ``job_id``.
        """
        if job_id is None:
            return [record.as_dict() for record in self._records.values()]
        return self._require(job_id).as_dict()

    def approve(self, job_id: str, approved_by: str) -> QuarantineRecord:
        """Marks a quarantined record as approved for recovery.

        Args:
            job_id (str): The quarantined job ID.
            approved_by (str): Identifier of the approving operator.

        Raises:
            RecoveryError: If the record is not in ``QUARANTINED`` state.
        """
        record = self._require(job_id)
        if record.state is not QuarantineState.QUARANTINED:
            raise RecoveryError(f'Cannot approve job {job_id!r} in state {record.state.value!r}')
        record.state = QuarantineState.APPROVED
        record.approved_by = approved_by
        record.approved_at = now()
        return record

    def reject(self, job_id: str, note: str = '') -> QuarantineRecord:
        """Marks a quarantined record as rejected; it can never be released."""
        record = self._require(job_id)
        if record.state is QuarantineState.RELEASED:
            raise RecoveryError(f'Cannot reject job {job_id!r}: already released')
        record.state = QuarantineState.REJECTED
        if note:
            record.note = note
        return record

    def verify(self, job_id: str) -> Job:
        """Re-verifies an approved record against the live job without running it.

        Checks that the job is still fetchable and deserializable, and that its
        function name (purpose) and origin queue still match the approved record.
        The job's function is never imported for execution or called here.

        Raises:
            RecoveryNotApprovedError: If the record has not been approved.
            RecoveryVerificationError: If any local check fails.

        Returns:
            Job: The verified job, ready to be requeued.
        """
        record = self._require(job_id)
        if record.state is not QuarantineState.APPROVED:
            raise RecoveryNotApprovedError(f'Job {job_id!r} is not approved for recovery (state: {record.state.value})')
        try:
            job = Job.fetch(record.job_id, connection=self.connection, serializer=self.serializer)
        except NoSuchJobError as e:
            raise RecoveryVerificationError(f'Job {record.job_id!r} is no longer readable') from e
        try:
            func_name = job.func_name
        except DeserializationError as e:
            raise RecoveryVerificationError(f'Job {record.job_id!r} payload cannot be deserialized') from e
        if func_name != record.func_name:
            raise RecoveryVerificationError(
                f'Job {record.job_id!r} purpose mismatch: expected {record.func_name!r}, found {func_name!r}'
            )
        if (job.origin or '') != record.queue_name:
            raise RecoveryVerificationError(
                f'Job {record.job_id!r} queue mismatch: expected {record.queue_name!r}, found {job.origin!r}'
            )
        return job

    def recover(self, job_id: str, at_front: bool = False) -> Job:
        """Releases an approved, verified job back onto its origin queue.

        The job is requeued from the ``FailedJobRegistry``; the quarantine
        record transitions to ``RELEASED`` and keeps the original failure
        metadata for forensics.

        Args:
            job_id (str): The quarantined job ID.
            at_front (bool, optional): Requeue at the front of the queue. Defaults to False.

        Returns:
            Job: The requeued job.
        """
        job = self.verify(job_id)
        registry = FailedJobRegistry(job.origin, connection=self.connection, serializer=self.serializer)
        job = registry.requeue(job, at_front=at_front)
        record = self._require(job_id)
        record.state = QuarantineState.RELEASED
        record.released_at = now()
        return job

    def _require(self, job_id: str) -> QuarantineRecord:
        try:
            return self._records[job_id]
        except KeyError:
            raise RecoveryError(f'No quarantine record for job {job_id!r}') from None
