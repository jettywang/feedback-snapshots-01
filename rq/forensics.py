from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from redis import Redis

from .defaults import (
    DEFAULT_FORENSIC_SUMMARY_LIMIT,
    FORMAT_KEY_PREFIX,
)
from .utils import as_text, current_timestamp, now

if TYPE_CHECKING:
    from redis.client import Pipeline

    from .executions import Execution
    from .job import Job

FORENSIC_RECEIPTS_KEY_TEMPLATE = FORMAT_KEY_PREFIX + ':receipts:{0}'
FORENSIC_RECEIPT_KEY_TEMPLATE = FORMAT_KEY_PREFIX + ':receipt:{0}:{1}'

# Outcomes and cleanup states are plain strings so they survive as evidence even
# if the enum that produced them changes later.
ACTIVE = 'active'
SUCCESSFUL = 'successful'
FAILED = 'failed'
RETRIED = 'retried'
MAX_RETRIES_EXCEEDED = 'max_retries_exceeded'
STOPPED = 'stopped'
ABANDONED = 'abandoned'

CLEANUP_ACTIVE = 'active'
CLEANUP_CLEANED = 'cleaned'
CLEANUP_JOB_DELETED = 'job_deleted'


class ForensicSettings:
    """Resolved, opt-in forensic settings for one job execution.

    A job-level `forensic_ttl` overrides the worker's. `None` or `0` on both
    means receipts are not recorded; `-1` keeps them without a TTL.
    """

    __slots__ = ('ttl', 'summary_limit')

    def __init__(self, ttl: int | None, summary_limit: int):
        self.ttl = ttl
        self.summary_limit = summary_limit

    @classmethod
    def for_job(cls, job: Job, worker: Any = None) -> ForensicSettings | None:
        ttl = job.forensic_ttl
        if ttl is None and worker is not None:
            ttl = getattr(worker, 'forensic_ttl', None)
        if ttl is None or ttl == 0:
            return None
        limit = job.forensic_summary_limit
        if limit is None:
            limit = getattr(worker, 'forensic_summary_limit', DEFAULT_FORENSIC_SUMMARY_LIMIT)
        return cls(ttl=int(ttl), summary_limit=max(int(limit), 0))


def _timestamp(value: datetime | None) -> float | None:
    return value.timestamp() if value is not None else None


def _datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _as_bool(value: Any) -> bool:
    return bool(int(value)) if value not in (None, '', b'') else False


def _result_summary(return_value: Any, limit: int) -> str | None:
    """A deliberately small, config-gated representation of a business result.

    The raw return value is never persisted in a receipt. A limit of 0 keeps
    only the `result_recorded` flag.
    """
    if limit <= 0:
        return None
    try:
        text = repr(return_value)
    except Exception:
        text = f'<{type(return_value).__name__}>'
    if len(text) > limit:
        return text[:limit] + '...'
    return text


class ExecutionReceipt:
    """Evidence for one execution attempt of a job.

    A receipt records only identity, timing, cleanup and retry facts (plus an
    optional configured result summary). It deliberately never stores the
    full business result, and its retention is independent from `result_ttl`.
    """

    def __init__(
        self,
        execution_id: str,
        job_id: str,
        connection: Redis,
        *,
        worker_name: str = '',
        started_at: datetime | None = None,
        ended_at: datetime | None = None,
        outcome: str = ACTIVE,
        cleanup_status: str = CLEANUP_ACTIVE,
        cleaned_at: datetime | None = None,
        attempt: int = 1,
        retried: bool = False,
        retries_left: int | None = None,
        number_of_retries: int | None = None,
        result_recorded: bool = False,
        result_type: str | None = None,
        result_ttl: int | None = None,
        result_expires_at: datetime | None = None,
        result_summary: str | None = None,
        expires_at: datetime | None = None,
    ):
        self.execution_id = execution_id
        self.job_id = job_id
        self.connection = connection
        self.worker_name = worker_name
        self.started_at = started_at
        self.ended_at = ended_at
        self.outcome = outcome
        self.cleanup_status = cleanup_status
        self.cleaned_at = cleaned_at
        self.attempt = attempt
        self.retried = retried
        self.retries_left = retries_left
        self.number_of_retries = number_of_retries
        self.result_recorded = result_recorded
        self.result_type = result_type
        self.result_ttl = result_ttl
        self.result_expires_at = result_expires_at
        self.result_summary = result_summary
        self.expires_at = expires_at
        self.result_present: bool | None = None

    @property
    def id(self) -> str:
        return self.execution_id

    @property
    def has_result(self) -> bool:
        """Whether a result existed when the receipt was last written."""
        return self.result_recorded

    @property
    def has_content(self) -> bool:
        """Whether a result for this execution is still in the result stream."""
        return bool(self.result_present)

    @property
    def is_cleaned(self) -> bool:
        return self.cleanup_status in (CLEANUP_CLEANED, CLEANUP_JOB_DELETED)

    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}(job_id={self.job_id!r}, execution_id={self.execution_id!r}, '
            f'worker_name={self.worker_name!r}, outcome={self.outcome!r}, cleanup={self.cleanup_status!r})'
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ExecutionReceipt) and self.job_id == other.job_id and self.id == other.id

    def __hash__(self) -> int:
        return hash((self.job_id, self.id))

    @property
    def key(self) -> str:
        return FORENSIC_RECEIPT_KEY_TEMPLATE.format(self.job_id, self.execution_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            'execution_id': self.execution_id,
            'job_id': self.job_id,
            'worker_name': self.worker_name,
            'started_at': _timestamp(self.started_at),
            'ended_at': _timestamp(self.ended_at),
            'outcome': self.outcome,
            'cleanup_status': self.cleanup_status,
            'cleaned_at': _timestamp(self.cleaned_at),
            'attempt': self.attempt,
            'retried': int(self.retried),
            'retries_left': self.retries_left,
            'number_of_retries': self.number_of_retries,
            'result_recorded': int(self.result_recorded),
            'result_type': self.result_type or '',
            'result_ttl': self.result_ttl,
            'result_expires_at': _timestamp(self.result_expires_at),
            'result_summary': self.result_summary or '',
            'expires_at': _timestamp(self.expires_at),
        }

    @classmethod
    def from_dict(cls, job_id: str, data: dict, connection: Redis) -> ExecutionReceipt:
        data = {as_text(k): v for k, v in data.items()}
        return cls(
            execution_id=as_text(data.get('execution_id', b'')),
            job_id=as_text(data.get('job_id', job_id.encode())) or job_id,
            connection=connection,
            worker_name=as_text(data.get('worker_name', b'')),
            started_at=_datetime(data.get('started_at')),
            ended_at=_datetime(data.get('ended_at')),
            outcome=as_text(data.get('outcome', ACTIVE.encode())),
            cleanup_status=as_text(data.get('cleanup_status', CLEANUP_ACTIVE.encode())),
            cleaned_at=_datetime(data.get('cleaned_at')),
            attempt=int(data.get('attempt') or 1),
            retried=_as_bool(data.get('retried')),
            retries_left=int(data['retries_left']) if data.get('retries_left') not in (None, b'') else None,
            number_of_retries=(
                int(data['number_of_retries']) if data.get('number_of_retries') not in (None, b'') else None
            ),
            result_recorded=_as_bool(data.get('result_recorded')),
            result_type=as_text(data.get('result_type', b'')) or None,
            result_ttl=int(data['result_ttl']) if data.get('result_ttl') not in (None, b'') else None,
            result_expires_at=_datetime(data.get('result_expires_at')),
            result_summary=as_text(data.get('result_summary', b'')) or None,
            expires_at=_datetime(data.get('expires_at')),
        )


class ForensicTimeline:
    """The opt-in forensic timeline for one job.

    Receipts live in their own Redis keys scored by an independent expiry
    deadline, so expired result streams, deleted execution hashes and retries
    cannot remove the archived evidence.
    """

    key_template = FORENSIC_RECEIPTS_KEY_TEMPLATE

    def __init__(self, job_id: str, connection: Redis):
        self.job_id = job_id
        self.connection = connection
        self.key = self.key_template.format(job_id)

    @classmethod
    def for_job(cls, job: Job) -> ForensicTimeline:
        return cls(job.id, connection=job.connection)

    def __len__(self) -> int:
        self.cleanup()
        return int(self.connection.zcard(self.key))

    def receipt_key(self, execution_id: str) -> str:
        return FORENSIC_RECEIPT_KEY_TEMPLATE.format(self.job_id, execution_id)

    def _score(self, ttl: int) -> float | str:
        return float('inf') if ttl < 0 else current_timestamp() + ttl

    def _expires_at(self, ttl: int) -> datetime | None:
        return None if ttl < 0 else now() + timedelta(seconds=ttl)

    def cleanup(self, timestamp: float | None = None) -> int:
        """Drop receipt entries whose independent forensic TTL has elapsed."""
        score = timestamp if timestamp is not None else current_timestamp()
        expired = self.connection.zrangebyscore(self.key, 0, score)
        if not expired:
            return 0
        with self.connection.pipeline() as pipeline:
            for execution_id in expired:
                pipeline.delete(self.receipt_key(as_text(execution_id)))
            pipeline.zremrangebyscore(self.key, 0, score)
            pipeline.execute()
        return len(expired)

    def record_start(
        self,
        execution: Execution,
        job: Job,
        settings: ForensicSettings,
        pipeline: Pipeline,
        *,
        attempt: int | None = None,
    ) -> ExecutionReceipt:
        """Queue the initial receipt for an execution attempt.

        `attempt` lets callers stamp the true attempt number (for example the
        job's retry counter) instead of relying on the current receipt count.
        """
        if attempt is None:
            # A retry/repeat counter is the trustworthy attempt number when the
            # job carries one. Otherwise the receipt count gives a stable
            # ordinal within this job's timeline.
            attempt = int(self.connection.zcard(self.key)) + 1
            counter = job.number_of_retries
            if counter:
                attempt = counter + 1
        receipt = ExecutionReceipt(
            execution_id=execution.id,
            job_id=job.id,
            connection=self.connection,
            worker_name=execution.worker_name,
            started_at=execution.created_at,
            attempt=attempt,
            retries_left=job.retries_left,
            number_of_retries=job.number_of_retries,
            expires_at=self._expires_at(settings.ttl),
        )
        self._write(receipt, settings.ttl, pipeline)
        return receipt

    def _register(
        self,
        execution_id: str,
        settings: ForensicSettings,
        pipeline: Pipeline,
        *,
        score: float | str | None = None,
    ) -> None:
        connection = pipeline if pipeline is not None else self.connection
        connection.zadd(self.key, {execution_id: score if score is not None else self._score(settings.ttl)})
        if settings.ttl < 0:
            connection.persist(self.key)
            connection.persist(self.receipt_key(execution_id))
        else:
            connection.expire(self.key, settings.ttl)
            connection.expire(self.receipt_key(execution_id), settings.ttl)

    def record_outcome(
        self,
        execution: Execution,
        job: Job,
        settings: ForensicSettings,
        outcome: str,
        *,
        retried: bool = False,
        result_recorded: bool = False,
        result_type: str | None = None,
        result_ttl: int | None = None,
        result_expires_at: datetime | None = None,
        return_value: Any | None = None,
        pipeline: Pipeline,
        ended_at: datetime | None = None,
        attempt: int | None = None,
    ) -> ExecutionReceipt:
        """Queue the terminal facts for an execution attempt.

        Only outcome fields are written here, so the receipt hash created at
        the start of the attempt (including its attempt number) is preserved
        even though this runs in the same Redis transaction.
        """
        ended = ended_at if ended_at is not None else job.ended_at or now()
        summary = _result_summary(return_value, settings.summary_limit) if result_recorded else None
        receipt_expires_at = self._expires_at(settings.ttl)
        connection = pipeline if pipeline is not None else self.connection
        connection.hset(
            self.receipt_key(execution.id),
            mapping={
                'execution_id': execution.id,
                'job_id': job.id,
                'worker_name': execution.worker_name,
                'started_at': execution.created_at.timestamp(),
                'ended_at': ended.timestamp(),
                'outcome': outcome,
                'retried': int(retried),
                'result_recorded': int(result_recorded),
                'result_type': result_type or '',
                'result_summary': summary or '',
            }
            | ({'attempt': attempt} if attempt is not None else {})
            | (
                {'retries_left': job.retries_left}
                if job.retries_left is not None
                else {}
            )
            | (
                {'number_of_retries': job.number_of_retries}
                if job.number_of_retries is not None
                else {}
            )
            | (
                {'result_ttl': result_ttl}
                if result_ttl is not None
                else {}
            )
            | (
                {'result_expires_at': result_expires_at.timestamp()}
                if result_expires_at is not None
                else {}
            )
            | (
                {'expires_at': receipt_expires_at.timestamp()}
                if receipt_expires_at is not None
                else {}
            ),
        )
        # Register the attempt even when no start record was written (for
        # example, a worker method invoked directly in a test).
        self._register(execution.id, settings, pipeline)
        return ExecutionReceipt(
            execution_id=execution.id,
            job_id=job.id,
            connection=self.connection,
            worker_name=execution.worker_name,
            started_at=execution.created_at,
            ended_at=ended,
            outcome=outcome,
            retried=retried,
            retries_left=job.retries_left,
            number_of_retries=job.number_of_retries,
            result_recorded=result_recorded,
            result_type=result_type,
            result_ttl=result_ttl,
            result_expires_at=result_expires_at,
            result_summary=summary,
            expires_at=receipt_expires_at,
            attempt=attempt if attempt is not None else 1,
        )

    def record_cleanup(self, execution: Execution, pipeline: Pipeline) -> None:
        """Queue a cleanup fact for an execution without deleting its receipt.

        Only the cleanup fields are written, so outcome fields queued earlier
        in the same transaction are not clobbered.
        """
        connection = pipeline if pipeline is not None else self.connection
        cleaned_at = now()
        connection.hset(
            self.receipt_key(execution.id),
            mapping={
                'execution_id': execution.id,
                'job_id': execution.job_id or self.job_id,
                'worker_name': execution.worker_name,
                'cleanup_status': CLEANUP_CLEANED,
                'cleaned_at': cleaned_at.timestamp(),
            },
        )

    def record_cleanup_if_exists(self, execution: Execution, pipeline: Pipeline) -> None:
        """Record cleanup only for executions that already have a receipt.

        A receipt already marked `job_deleted` keeps that stronger status.
        This is called through the execution's own pipeline, so it checks the
        score set rather than reading the not-yet-visible hash.
        """
        if not self.connection.zscore(self.key, execution.id):
            return
        current = as_text(self.connection.hget(self.receipt_key(execution.id), 'cleanup_status') or b'')
        if current == CLEANUP_JOB_DELETED:
            return
        self.record_cleanup(execution, pipeline)

    def mark_job_deleted(self, pipeline: Pipeline | None = None, *, ttl: int | None = None) -> None:
        """Mark receipts that were still active when the job hash was deleted.

        Only the cleanup fields are written. Terminal outcome fields queued
        earlier in the same transaction (for example a `result_ttl=0` job
        deleted right after success) must survive. When `ttl` is given, the
        independent receipt TTL is refreshed to it; otherwise the existing TTL
        is left untouched.
        """
        connection = pipeline if pipeline is not None else self.connection
        cleaned_at = now()
        for receipt in self.get_receipts():
            if receipt.cleanup_status == CLEANUP_JOB_DELETED:
                continue
            connection.hset(
                receipt.key,
                mapping={
                    'cleanup_status': CLEANUP_JOB_DELETED,
                    'cleaned_at': cleaned_at.timestamp(),
                },
            )
            if ttl is not None:
                connection.expire(receipt.key, ttl)

    def mark_active_abandoned(self, pipeline: Pipeline | None = None) -> None:
        """Mark every open attempt of this job as abandoned."""
        connection = pipeline if pipeline is not None else self.connection
        for receipt in self.get_receipts():
            if receipt.outcome == ACTIVE:
                connection.hset(
                    receipt.key,
                    mapping={
                        'outcome': ABANDONED,
                        'ended_at': (receipt.ended_at or now()).timestamp(),
                    },
                )

    def _write(
        self,
        receipt: ExecutionReceipt,
        ttl: int,
        pipeline: Pipeline | None,
        *,
        set_expiry: bool = True,
    ) -> None:
        connection = pipeline if pipeline is not None else self.connection
        data = {key: value for key, value in receipt.to_dict().items() if value is not None}
        connection.hset(receipt.key, mapping=data)
        if set_expiry:
            connection.zadd(self.key, {receipt.id: self._score(ttl)})
            if ttl < 0:
                connection.persist(self.key)
                connection.persist(receipt.key)
            else:
                connection.expire(self.key, ttl)
                connection.expire(receipt.key, ttl)
        elif ttl >= 0:
            # Refresh the key's TTL only when the caller is not extending it.
            connection.expire(receipt.key, ttl)

    def get_receipt(self, execution_id: str, pipeline: Pipeline | None = None) -> ExecutionReceipt | None:
        if pipeline is not None:
            # Callers inside a transaction have not yet committed their start
            # write, so they must pass the receipt fields explicitly. Reading
            # Redis here is intentionally avoided because it would observe the
            # pre-transaction state.
            return None
        data = self.connection.hgetall(self.receipt_key(execution_id))
        if not data:
            return None
        return ExecutionReceipt.from_dict(self.job_id, data, self.connection)

    def get_receipts(self, cleanup: bool = True) -> list[ExecutionReceipt]:
        if cleanup:
            self.cleanup()
        execution_ids = [as_text(value) for value in self.connection.zrange(self.key, 0, -1)]
        if not execution_ids:
            return []
        with self.connection.pipeline() as pipeline:
            for execution_id in execution_ids:
                pipeline.hgetall(self.receipt_key(execution_id))
            raw_receipts = pipeline.execute()
        receipts = []
        for execution_id, data in zip(execution_ids, raw_receipts):
            if not data:
                self.connection.zrem(self.key, execution_id)
                continue
            receipts.append(ExecutionReceipt.from_dict(self.job_id, data, self.connection))
        self._mark_result_presence(receipts)
        receipts.sort(key=lambda receipt: (receipt.started_at or now(), receipt.attempt))
        return receipts

    def _mark_result_presence(self, receipts: list[ExecutionReceipt]) -> None:
        from .results import Result

        result_execution_ids = set(Result.execution_ids(self.job_id, self.connection))
        for receipt in receipts:
            if not receipt.result_recorded:
                receipt.result_present = False
            elif receipt.result_expires_at is None:
                # No expiry was recorded (for example, a receipt written before
                # this field existed). Presence is then whatever Redis still holds.
                receipt.result_present = receipt.execution_id in result_execution_ids
            else:
                # The configured result TTL is the authority once the result's
                # stream can be swept independently of when this is read.
                receipt.result_present = (
                    receipt.execution_id in result_execution_ids and now() <= receipt.result_expires_at
                )

    def reconcile(self) -> dict[str, Any]:
        """Cross-check receipts against the residual result stream.

        Returns a dict with receipts and result execution IDs that have no
        receipt, making both sides independently inspectable.
        """
        from .results import Result

        receipts = self.get_receipts()
        known = {receipt.execution_id for receipt in receipts}
        result_ids = Result.execution_ids(self.job_id, self.connection)
        unmatched = [execution_id for execution_id in result_ids if execution_id not in known]
        return {
            'job_id': self.job_id,
            'receipts': receipts,
            'unmatched_result_execution_ids': unmatched,
        }


def result_expiry(result_ttl: int | None) -> datetime | None:
    """Deadline of the result produced for a ttl, mirroring Redis' expire.

    `None` for a ttl of -1 (never expires) and for ttl 0 (deleted immediately),
    so a receipt can state when the result it refers to should be gone.
    """
    if result_ttl is None or result_ttl <= 0:
        return None
    return now() + timedelta(seconds=result_ttl)


def forensic_settings(job: Job, worker: Any = None) -> ForensicSettings | None:
    """Resolve the opt-in forensic settings for a job and an optional worker."""
    return ForensicSettings.for_job(job, worker)
