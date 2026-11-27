"""Optional runtime admission for recovered and repeating schedules.

A schedule can be registered here before it is allowed to enqueue work.  Schedulers
consult the *current* rule on every decision, so a retirement that happens after a
scheduler was started still applies to a later takeover.  Decisions are recorded in
Redis and distinguish:

* ``stopped``: the schedule was retired and must not emit new work;
* ``completed``: the occurrence was already emitted/adjudicated, so replaying it
  during recovery must not enqueue it again;
* ``review``: the policy cannot decide safely (missing or stale registration) and a
  human must resolve it.

Jobs that have already started are never rewritten.  The admission check runs
before execution, so a job already in progress keeps its ``started`` status and its
execution record.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

from redis.exceptions import WatchError

from .defaults import RQ_KEY_PREFIX
from .exceptions import AdmissionRuleConflict
from .job import JobStatus
from .utils import as_text, current_timestamp, utcformat, utcparse

if TYPE_CHECKING:
    from redis import Redis

    from .cron import CronJob
    from .job import Job


ADMISSION_RULES_KEY = RQ_KEY_PREFIX + ':admission:rules'
ADMISSION_OCCURRENCES_KEY = RQ_KEY_PREFIX + ':admission:occurrences'
ADMISSION_RECORDS_KEY = RQ_KEY_PREFIX + ':admission:records'
ADMISSION_HELD_KEY = RQ_KEY_PREFIX + ':admission:held:{0}'
ADMISSION_HELD_META_KEY = RQ_KEY_PREFIX + ':admission:held-meta:{0}'

DEFAULT_ADMISSION_RECORD_LIMIT = 10000
DEFAULT_ADMISSION_RECORD_TTL = 90 * 24 * 3600
DEFAULT_ADMISSION_OCCURRENCE_TTL = 30 * 24 * 3600


class AdmissionState(str, Enum):
    """Registered state of a schedule."""

    ACTIVE = 'active'
    STOPPED = 'stopped'


class AdmissionResult(str, Enum):
    """Outcome of applying the admission policy to one occurrence/job."""

    ADMIT = 'admit'
    STOPPED = 'stopped'
    COMPLETED = 'completed'
    IN_PROGRESS = 'in_progress'
    REVIEW = 'review'


@dataclass(frozen=True)
class AdmissionRule:
    """A registered admission rule for a schedule identity."""

    key: str
    state: AdmissionState
    revision: int
    reason: str = ''
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'key': self.key,
            'state': self.state.value,
            'revision': self.revision,
            'reason': self.reason,
            'updated_at': utcformat(self.updated_at or datetime.now(timezone.utc)),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdmissionRule:
        return cls(
            key=data['key'],
            state=AdmissionState(data['state']),
            revision=int(data['revision']),
            reason=data.get('reason', ''),
            updated_at=utcparse(data['updated_at']) if data.get('updated_at') else None,
        )


@dataclass(frozen=True)
class AdmissionDecision:
    """A decision returned to a scheduler or worker."""

    result: AdmissionResult
    schedule_key: str
    reason: str = ''
    job_id: str | None = None
    occurrence: str | None = None
    rule_revision: int | None = None
    scheduled_revision: int | None = None

    @property
    def admitted(self) -> bool:
        return self.result is AdmissionResult.ADMIT


@dataclass(frozen=True)
class AdmissionOccurrence:
    """A claimed occurrence, used to make recovery idempotent."""

    schedule_key: str
    occurrence: str
    result: str
    job_id: str | None = None
    rule_revision: int | None = None
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'schedule_key': self.schedule_key,
            'occurrence': self.occurrence,
            'result': self.result,
            'job_id': self.job_id,
            'rule_revision': self.rule_revision,
            'updated_at': utcformat(self.updated_at or datetime.now(timezone.utc)),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdmissionOccurrence:
        return cls(
            schedule_key=data['schedule_key'],
            occurrence=data['occurrence'],
            result=data['result'],
            job_id=data.get('job_id'),
            rule_revision=data.get('rule_revision'),
            updated_at=utcparse(data['updated_at']) if data.get('updated_at') else None,
        )


class AdmissionPolicy:
    """Redis-backed rules and decision records for schedule recovery.

    The policy is optional: passing ``None`` to a scheduler or worker leaves the
    existing recovery behaviour unchanged.  When enabled without any registered
    rules, work is admitted by default so existing jobs keep running.  Set
    ``require_registration=True`` to hold unregistered schedules for review.
    """

    def __init__(
        self,
        connection: Redis,
        *,
        require_registration: bool = False,
        record_admitted: bool = False,
        record_limit: int = DEFAULT_ADMISSION_RECORD_LIMIT,
        record_ttl: int = DEFAULT_ADMISSION_RECORD_TTL,
        occurrence_ttl: int = DEFAULT_ADMISSION_OCCURRENCE_TTL,
    ):
        self.connection = connection
        self.require_registration = require_registration
        self.record_admitted = record_admitted
        self.record_limit = max(1, int(record_limit))
        self.record_ttl = record_ttl
        self.occurrence_ttl = occurrence_ttl

    def export_options(self) -> dict[str, Any]:
        """Return picklable policy options, excluding the Redis connection.

        Used when a worker process forks/spawns: Redis clients are not picklable.
        """
        return {
            'require_registration': self.require_registration,
            'record_admitted': self.record_admitted,
            'record_limit': self.record_limit,
            'record_ttl': self.record_ttl,
            'occurrence_ttl': self.occurrence_ttl,
        }

    def for_connection(self, connection: Redis) -> AdmissionPolicy:
        """Return an equivalent policy bound to another connection."""
        return AdmissionPolicy(connection, **self.export_options())

    # ------------------------------------------------------------------
    # Rule registration
    # ------------------------------------------------------------------
    def get_rule(self, schedule_key: str) -> AdmissionRule | None:
        raw = self.connection.hget(ADMISSION_RULES_KEY, schedule_key)
        if not raw:
            return None
        return AdmissionRule.from_dict(json.loads(as_text(raw)))

    def set_rule(
        self,
        schedule_key: str,
        state: AdmissionState | str,
        *,
        reason: str = '',
        expected_revision: int | None = None,
    ) -> AdmissionRule:
        """Register or update a rule, incrementing its revision.

        ``expected_revision`` makes the update conditional: if another process
        changed the rule first, :class:`AdmissionRuleConflict` is raised.
        """
        state = AdmissionState(state)
        with self.connection.pipeline() as pipeline:
            while True:
                try:
                    pipeline.watch(ADMISSION_RULES_KEY)
                    raw = pipeline.hget(ADMISSION_RULES_KEY, schedule_key)
                    existing = AdmissionRule.from_dict(json.loads(as_text(raw))) if raw else None
                    if expected_revision is not None and (existing is None or existing.revision != expected_revision):
                        raise AdmissionRuleConflict(
                            f"Admission rule '{schedule_key}' is not at revision {expected_revision}"
                        )
                    rule = AdmissionRule(
                        key=schedule_key,
                        state=state,
                        revision=(existing.revision + 1) if existing else 1,
                        reason=reason,
                        updated_at=datetime.now(timezone.utc),
                    )
                    pipeline.multi()
                    pipeline.hset(ADMISSION_RULES_KEY, schedule_key, json.dumps(rule.to_dict()))
                    pipeline.execute()
                    return rule
                except WatchError:
                    continue

    def stop(self, schedule_key: str, *, reason: str = '', expected_revision: int | None = None) -> AdmissionRule:
        """Retire a schedule so recovery no longer emits it."""
        return self.set_rule(schedule_key, AdmissionState.STOPPED, reason=reason, expected_revision=expected_revision)

    def admit(self, schedule_key: str, *, reason: str = '', expected_revision: int | None = None) -> AdmissionRule:
        """Return a schedule to service."""
        return self.set_rule(schedule_key, AdmissionState.ACTIVE, reason=reason, expected_revision=expected_revision)

    # ------------------------------------------------------------------
    # Identity helpers
    # ------------------------------------------------------------------
    @staticmethod
    def cron_key(cron_job: CronJob) -> str:
        """Stable identity of a logical cron job (``name`` may group jobs)."""
        return f'cron:{cron_job.name}'

    @staticmethod
    def job_key(job: Job) -> str:
        """Identity of a timed/repeating job.

        Jobs may carry ``meta['admission_key']`` to share a rule with a schedule
        (for example a cron job); otherwise the job ID is the identity.  Repeating
        jobs keep their job ID, so their rule survives across repetitions.
        """
        meta = job.meta if isinstance(job.meta, dict) else {}
        key = meta.get('admission_key')
        return str(key) if key else f'job:{job.id}'

    @staticmethod
    def scheduled_revision(job: Job) -> int | None:
        meta = job.meta if isinstance(job.meta, dict) else {}
        value = meta.get('admission_revision')
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    # ------------------------------------------------------------------
    # Occurrence claims
    # ------------------------------------------------------------------
    @staticmethod
    def _occurrence_field(schedule_key: str, occurrence: str) -> str:
        return f'{schedule_key}|{occurrence}'

    def get_occurrence(self, schedule_key: str, occurrence: str) -> AdmissionOccurrence | None:
        raw = self.connection.hget(ADMISSION_OCCURRENCES_KEY, self._occurrence_field(schedule_key, occurrence))
        if not raw:
            return None
        return AdmissionOccurrence.from_dict(json.loads(as_text(raw)))

    def claim_occurrence(
        self,
        schedule_key: str,
        occurrence: str,
        *,
        job_id: str | None = None,
        result: str = 'reserved',
        rule_revision: int | None = None,
    ) -> bool:
        """Atomically claim an occurrence.  Returns False if another scheduler did."""
        claim = AdmissionOccurrence(
            schedule_key=schedule_key,
            occurrence=occurrence,
            result=result,
            job_id=job_id,
            rule_revision=rule_revision,
            updated_at=datetime.now(timezone.utc),
        )
        field = self._occurrence_field(schedule_key, occurrence)
        added = bool(self.connection.hsetnx(ADMISSION_OCCURRENCES_KEY, field, json.dumps(claim.to_dict())))
        if added and self.occurrence_ttl:
            self.connection.expire(ADMISSION_OCCURRENCES_KEY, self.occurrence_ttl)
        return added

    def update_occurrence(
        self,
        schedule_key: str,
        occurrence: str,
        *,
        job_id: str | None = None,
        result: str = 'enqueued',
        rule_revision: int | None = None,
        expected_job_id: str | None = None,
    ) -> bool:
        """Update a claim, optionally only if it still holds ``expected_job_id``."""
        field = self._occurrence_field(schedule_key, occurrence)
        with self.connection.pipeline() as pipeline:
            while True:
                try:
                    pipeline.watch(ADMISSION_OCCURRENCES_KEY)
                    raw = pipeline.hget(ADMISSION_OCCURRENCES_KEY, field)
                    if not raw:
                        raise AdmissionRuleConflict(f"Occurrence '{occurrence}' is no longer claimed")
                    existing = AdmissionOccurrence.from_dict(json.loads(as_text(raw)))
                    if expected_job_id is not None and existing.job_id != expected_job_id:
                        return False
                    claim = AdmissionOccurrence(
                        schedule_key=schedule_key,
                        occurrence=occurrence,
                        result=result,
                        job_id=job_id if job_id is not None else existing.job_id,
                        rule_revision=rule_revision if rule_revision is not None else existing.rule_revision,
                        updated_at=datetime.now(timezone.utc),
                    )
                    pipeline.multi()
                    pipeline.hset(ADMISSION_OCCURRENCES_KEY, field, json.dumps(claim.to_dict()))
                    pipeline.execute()
                    return True
                except WatchError:
                    continue

    def release_occurrence(self, schedule_key: str, occurrence: str, *, expected_job_id: str | None = None) -> bool:
        """Release a reservation after an enqueue failed."""
        field = self._occurrence_field(schedule_key, occurrence)
        with self.connection.pipeline() as pipeline:
            while True:
                try:
                    pipeline.watch(ADMISSION_OCCURRENCES_KEY)
                    raw = pipeline.hget(ADMISSION_OCCURRENCES_KEY, field)
                    if not raw:
                        return False
                    existing = AdmissionOccurrence.from_dict(json.loads(as_text(raw)))
                    if expected_job_id is not None and existing.job_id != expected_job_id:
                        return False
                    pipeline.multi()
                    pipeline.hdel(ADMISSION_OCCURRENCES_KEY, field)
                    pipeline.execute()
                    return True
                except WatchError:
                    continue

    # ------------------------------------------------------------------
    # Decisions
    # ------------------------------------------------------------------
    def _evaluate_rule(
        self, schedule_key: str, scheduled_revision: int | None = None
    ) -> tuple[AdmissionResult, AdmissionRule | None, str]:
        rule = self.get_rule(schedule_key)
        if rule is None:
            if self.require_registration:
                return AdmissionResult.REVIEW, None, 'no registered rule for schedule'
            return AdmissionResult.ADMIT, None, 'no admission rule'
        if rule.state is AdmissionState.STOPPED:
            return AdmissionResult.STOPPED, rule, rule.reason or 'schedule is stopped'
        if scheduled_revision is not None and scheduled_revision > rule.revision:
            return (
                AdmissionResult.REVIEW,
                rule,
                f'scheduled revision {scheduled_revision} is newer than registered revision {rule.revision}',
            )
        return AdmissionResult.ADMIT, rule, ''

    def evaluate_cron(self, cron_job: CronJob, occurrence: str) -> AdmissionDecision:
        """Decide whether a due cron occurrence may be emitted.

        The current rule takes precedence over replay deduplication: a schedule
        retired after an earlier occurrence was emitted must not stay active just
        because that earlier occurrence is already in the ledger.
        """
        schedule_key = self.cron_key(cron_job)
        result, rule, reason = self._evaluate_rule(schedule_key)
        decision = AdmissionDecision(
            result=result,
            schedule_key=schedule_key,
            occurrence=occurrence,
            rule_revision=rule.revision if rule else None,
            reason=reason,
        )
        if result is AdmissionResult.STOPPED:
            # Make the retired occurrence terminal so a later reactivation does not
            # backfill work that was missed while the schedule was stopped.
            self.claim_occurrence(
                schedule_key, occurrence, result=AdmissionResult.STOPPED.value, rule_revision=decision.rule_revision
            )
            self._record(decision)
            return decision

        existing = self.get_occurrence(schedule_key, occurrence)
        if existing is not None:
            decision = AdmissionDecision(
                result=AdmissionResult.COMPLETED,
                schedule_key=schedule_key,
                occurrence=occurrence,
                job_id=existing.job_id,
                rule_revision=existing.rule_revision,
                scheduled_revision=decision.scheduled_revision,
                reason=f'occurrence already adjudicated as {existing.result}',
            )

        self._record(decision)
        return decision

    def evaluate_scheduled_job(self, job: Job, *, queue_name: str | None = None) -> AdmissionDecision:
        """Decide whether a job left in ``ScheduledJobRegistry`` may be recovered."""
        schedule_key = self.job_key(job)
        status = job.get_status(refresh=True)
        if status in (JobStatus.STARTED, JobStatus.FINISHED, JobStatus.FAILED, JobStatus.STOPPED, JobStatus.CANCELED):
            result = AdmissionResult.IN_PROGRESS if status is JobStatus.STARTED else AdmissionResult.COMPLETED
            decision = AdmissionDecision(
                result=result,
                schedule_key=schedule_key,
                job_id=job.id,
                reason=f'job is already {status.value}; left unchanged',
            )
            self._record(decision)
            return decision

        result, rule, reason = self._evaluate_rule(schedule_key, self.scheduled_revision(job))
        decision = AdmissionDecision(
            result=result,
            schedule_key=schedule_key,
            occurrence=job.id,
            job_id=job.id,
            rule_revision=rule.revision if rule else None,
            scheduled_revision=self.scheduled_revision(job),
            reason=reason,
        )
        if result is AdmissionResult.STOPPED:
            # The current rule wins over an older adjudication, so a retirement
            # recorded after the job was enqueued still applies on recovery.
            self.claim_occurrence(
                schedule_key,
                job.id,
                job_id=job.id,
                result=AdmissionResult.STOPPED.value,
                rule_revision=decision.rule_revision,
            )
            self._record(decision)
            return decision

        existing = self.get_occurrence(schedule_key, job.id)
        if existing is not None:
            decision = AdmissionDecision(
                result=AdmissionResult.COMPLETED,
                schedule_key=schedule_key,
                occurrence=job.id,
                job_id=job.id,
                rule_revision=existing.rule_revision,
                reason=f'job occurrence already adjudicated as {existing.result}',
            )

        self._record(decision)
        return decision

    def check_worker_job(self, job: Job) -> AdmissionDecision:
        """Decide whether a dequeued job may start executing.

        This runs before the worker starts the job, so a job already ``started``
        elsewhere is reported and left untouched.
        """
        schedule_key = self.job_key(job)
        status = job.get_status(refresh=True)
        if status is JobStatus.STARTED:
            decision = AdmissionDecision(
                result=AdmissionResult.IN_PROGRESS,
                schedule_key=schedule_key,
                job_id=job.id,
                reason='job already started; execution state preserved',
            )
            self._record(decision)
            return decision
        if status in (JobStatus.FINISHED, JobStatus.FAILED, JobStatus.STOPPED, JobStatus.CANCELED):
            decision = AdmissionDecision(
                result=AdmissionResult.COMPLETED,
                schedule_key=schedule_key,
                job_id=job.id,
                reason=f'job is already {status.value}',
            )
            self._record(decision)
            return decision

        result, rule, reason = self._evaluate_rule(schedule_key, self.scheduled_revision(job))
        decision = AdmissionDecision(
            result=result,
            schedule_key=schedule_key,
            job_id=job.id,
            rule_revision=rule.revision if rule else None,
            scheduled_revision=self.scheduled_revision(job),
            reason=reason,
        )
        if result is AdmissionResult.ADMIT:
            if self.record_admitted:
                self._record(decision)
        else:
            self._record(decision)
        return decision

    def check_repeat(self, job: Job, occurrence: str) -> AdmissionDecision:
        """Decide whether a completed job may schedule its next repetition."""
        schedule_key = self.job_key(job)
        existing = self.get_occurrence(schedule_key, occurrence)
        if existing is not None:
            return AdmissionDecision(
                result=AdmissionResult.COMPLETED,
                schedule_key=schedule_key,
                occurrence=occurrence,
                job_id=existing.job_id,
                rule_revision=existing.rule_revision,
                reason=f'repeat occurrence already adjudicated as {existing.result}',
            )

        result, rule, reason = self._evaluate_rule(schedule_key, self.scheduled_revision(job))
        decision = AdmissionDecision(
            result=result,
            schedule_key=schedule_key,
            occurrence=occurrence,
            job_id=job.id,
            rule_revision=rule.revision if rule else None,
            scheduled_revision=self.scheduled_revision(job),
            reason=reason,
        )
        if result is AdmissionResult.STOPPED:
            self.claim_occurrence(
                schedule_key,
                occurrence,
                job_id=job.id,
                result=AdmissionResult.STOPPED.value,
                rule_revision=decision.rule_revision,
            )
        self._record(decision)
        return decision

    # ------------------------------------------------------------------
    # Held jobs and records
    # ------------------------------------------------------------------
    @staticmethod
    def _held_key(queue_name: str) -> str:
        return ADMISSION_HELD_KEY.format(queue_name)

    @staticmethod
    def _held_meta_key(queue_name: str) -> str:
        return ADMISSION_HELD_META_KEY.format(queue_name)

    def hold_job(
        self,
        job: Job,
        queue_name: str,
        *,
        score: float | None = None,
        reason: str = '',
        decision: AdmissionDecision | None = None,
    ) -> None:
        """Move a not-yet-emitted job out of recovery while preserving its schedule.

        The job hash and status are not changed.  Its original scheduled score is
        kept in a per-queue sorted set so the original schedule record remains
        inspectable.
        """
        score = current_timestamp() if score is None else score
        record_key = job.key
        with self.connection.pipeline() as pipeline:
            pipeline.zadd(self._held_key(queue_name), {job.id: score})
            pipeline.hset(
                self._held_meta_key(queue_name),
                job.id,
                json.dumps(
                    {
                        'job_id': job.id,
                        'queue': queue_name,
                        'job_key': record_key,
                        'score': score,
                        'reason': reason,
                        'decision': decision.result.value if decision else None,
                        'schedule_key': decision.schedule_key if decision else self.job_key(job),
                        'rule_revision': decision.rule_revision if decision else None,
                    }
                ),
            )
            pipeline.execute()

    def held_job_ids(self, queue_name: str) -> list[str]:
        return [as_text(job_id) for job_id in self.connection.zrange(self._held_key(queue_name), 0, -1)]

    def held_job_scores(self, queue_name: str) -> dict[str, float]:
        return {
            as_text(job_id): score
            for job_id, score in self.connection.zrange(self._held_key(queue_name), 0, -1, withscores=True)
        }

    def held_job_meta(self, queue_name: str, job_id: str) -> dict[str, Any] | None:
        raw = self.connection.hget(self._held_meta_key(queue_name), job_id)
        return json.loads(as_text(raw)) if raw else None

    def release_held_job(self, queue_name: str, job_id: str) -> bool:
        """Remove a held job so an operator can requeue it deliberately."""
        removed = bool(self.connection.zrem(self._held_key(queue_name), job_id))
        self.connection.hdel(self._held_meta_key(queue_name), job_id)
        return removed

    def record(self, decision: AdmissionDecision, **extra: Any) -> None:
        self._record(decision, **extra)

    def _record(self, decision: AdmissionDecision, **extra: Any) -> None:
        payload = {
            'result': decision.result.value,
            'schedule_key': decision.schedule_key,
            'job_id': decision.job_id,
            'occurrence': decision.occurrence,
            'rule_revision': decision.rule_revision,
            'scheduled_revision': decision.scheduled_revision,
            'reason': decision.reason,
            'recorded_at': utcformat(datetime.now(timezone.utc)),
        }
        payload.update(extra)
        with self.connection.pipeline() as pipeline:
            pipeline.lpush(ADMISSION_RECORDS_KEY, json.dumps(payload))
            pipeline.ltrim(ADMISSION_RECORDS_KEY, 0, self.record_limit - 1)
            if self.record_ttl:
                pipeline.expire(ADMISSION_RECORDS_KEY, self.record_ttl)
            pipeline.execute()

    def records(
        self,
        *,
        schedule_key: str | None = None,
        result: AdmissionResult | str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return decision records, newest first, optionally filtered."""
        result_value = result.value if isinstance(result, AdmissionResult) else result
        raw_records = self.connection.lrange(ADMISSION_RECORDS_KEY, 0, -1)
        records: list[dict[str, Any]] = []
        for raw in raw_records:
            record = json.loads(as_text(raw))
            if schedule_key is not None and record.get('schedule_key') != schedule_key:
                continue
            if result_value is not None and record.get('result') != result_value:
                continue
            records.append(record)
            if limit is not None and len(records) >= limit:
                break
        return records
