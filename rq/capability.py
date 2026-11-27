"""Capability checking for restricted jobs.

A *capability* names a restricted action a job wants to perform (e.g. ``"reports:generate"``).
A caller that was approved for a scope attaches a *capability proof* when enqueueing the job.
The proof is persisted with the job, so it survives scheduling, automatic retries and
dependency deferral, and is verified by the worker right before the job function runs.

Jobs enqueued before this mechanism existed carry no proof. How those legacy jobs are
treated is configurable via the checker's ``legacy_policy`` (``"allow"`` or ``"deny"``).
"""

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from redis import Redis

from .defaults import RQ_KEY_PREFIX
from .exceptions import CapabilityDenied
from .utils import now, utcformat

if TYPE_CHECKING:
    from .job import Job

LEGACY_POLICIES = ('allow', 'deny')


@dataclass
class CapabilityReceipt:
    """A record of a capability decision made right before a job would start.

    Denied receipts are persisted to Redis so operators can audit rejections.
    """

    job_id: str
    capability: str | None
    decision: str  # 'allowed' or 'denied'
    reason: str
    worker_name: str | None
    created_at: str


def receipt_key(job_id: str) -> str:
    """Redis key of the hash storing the capability receipt for a job."""
    return f'{RQ_KEY_PREFIX}:capability:receipt:{job_id}'


def denials_key() -> str:
    """Redis key of the list holding the IDs of all jobs denied by capability checks."""
    return f'{RQ_KEY_PREFIX}:capability:denials'


def record_denial(connection: Redis, job: 'Job', reason: str, worker_name: str | None = None) -> CapabilityReceipt:
    """Persists a denial receipt for ``job`` and returns it.

    The receipt is stored as a hash at ``rq:capability:receipt:<job_id>`` and the job ID
    is appended to the ``rq:capability:denials`` list for auditing.
    """
    receipt = CapabilityReceipt(
        job_id=job.id,
        capability=job.capability,
        decision='denied',
        reason=reason,
        worker_name=worker_name,
        created_at=utcformat(now()),
    )
    mapping = {key: value for key, value in asdict(receipt).items() if value is not None}
    with connection.pipeline() as pipeline:
        pipeline.hset(receipt_key(job.id), mapping=mapping)
        pipeline.rpush(denials_key(), job.id)
        pipeline.execute()
    return receipt


class CapabilityChecker:
    """Base class for capability checkers. Pass an instance (or any callable accepting a
    job and raising :class:`rq.exceptions.CapabilityDenied`) as ``capability_checker``
    when creating a worker.

    Args:
        legacy_policy (str, optional): How to treat jobs that carry no capability proof
            (e.g. jobs enqueued before capabilities were used). Either ``"allow"``
            (run them, the default) or ``"deny"`` (reject them).
        record_allowed (bool, optional): Also persist a receipt for approved jobs.
            Defaults to False; denials are always recorded.
    """

    def __init__(self, legacy_policy: str = 'allow', record_allowed: bool = False):
        if legacy_policy not in LEGACY_POLICIES:
            raise ValueError(f'legacy_policy must be one of {LEGACY_POLICIES}, got {legacy_policy!r}')
        self.legacy_policy = legacy_policy
        self.record_allowed = record_allowed

    def verify(self, job: 'Job') -> None:
        """Raises :class:`CapabilityDenied` if the job may not start. Implemented by subclasses."""
        raise NotImplementedError

    def check(self, job: 'Job', connection: Redis, worker_name: str | None = None) -> CapabilityReceipt:
        """Verifies the job, records the decision and returns the receipt.

        Raises:
            CapabilityDenied: If the job may not start. The denial receipt is persisted
                before the exception propagates.
        """
        try:
            self.verify(job)
        except CapabilityDenied as exc:
            receipt = record_denial(connection, job, str(exc), worker_name=worker_name)
            raise
        receipt = CapabilityReceipt(
            job_id=job.id,
            capability=job.capability,
            decision='allowed',
            reason='',
            worker_name=worker_name,
            created_at=utcformat(now()),
        )
        if self.record_allowed:
            mapping = {key: value for key, value in asdict(receipt).items() if value is not None}
            connection.hset(receipt_key(job.id), mapping=mapping)
        return receipt


class ScopeCapabilityChecker(CapabilityChecker):
    """Approves a job when its required capability is covered by the caller-approved scope.

    The proof attached at enqueue time is a space-separated scope string, e.g.
    ``"reports:read reports:generate"``. A job whose ``capability`` is not part of that
    scope is denied. Jobs without any capability requirement are legacy jobs and are
    handled according to ``legacy_policy``.
    """

    def verify(self, job: 'Job') -> None:
        capability = job.capability
        proof = job.capability_proof
        if capability is None:
            if self.legacy_policy == 'deny':
                raise CapabilityDenied(f'Job {job.id} carries no capability proof and legacy_policy is "deny"')
            return
        granted = set(proof.split()) if proof else set()
        if capability not in granted:
            raise CapabilityDenied(
                f'Job {job.id} requires capability {capability!r} which is not covered '
                f'by the caller-approved scope {proof!r}'
            )
