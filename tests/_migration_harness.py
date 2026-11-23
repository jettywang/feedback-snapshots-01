# SPDX-License-Identifier: MIT

"""
Test-only reference model for password-digest migration decisions.

The production migration code is about to be replaced, so these helpers pin
down the contract the replacement has to honor without duplicating it.  The
regression suite builds synthetic digests with Argon2's local interface,
judges the same digest on two workers whose defaults differ locally, and
audits a deliberately wrong "any difference is an upgrade" stand-in.

Nothing here is imported by :mod:`argon2` itself.
"""

from __future__ import annotations

import base64
import json

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from argon2 import Parameters, PasswordHasher, Type, extract_parameters
from argon2.low_level import hash_secret


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "migration"


class Action(Enum):
    """
    What a worker should do with a stored digest.
    """

    KEEP = "keep"
    UPGRADE = "upgrade"
    DEFER = "defer"


def meets_target(candidate: Parameters, target: Parameters) -> bool:
    """
    Return whether *candidate* is at least as strong as *target* on every
    relevant axis.

    Equality with a worker's defaults is irrelevant: a digest can differ from
    the defaults and still be compliant, and it can match the defaults while
    still falling short of the target.
    """
    return (
        candidate.type == target.type
        and candidate.version >= target.version
        and candidate.salt_len >= target.salt_len
        and candidate.hash_len >= target.hash_len
        and candidate.time_cost >= target.time_cost
        and candidate.memory_cost >= target.memory_cost
        and candidate.parallelism >= target.parallelism
    )


def _downgraded(before: Parameters, after: Parameters) -> bool:
    """
    Return whether *after* is numerically weaker than *before* on any axis.

    The Argon2 variant is judged by :func:`meets_target` instead, because a
    variant change is a policy question rather than a numeric downgrade.
    """
    return (
        after.version < before.version
        or after.salt_len < before.salt_len
        or after.hash_len < before.hash_len
        or after.time_cost < before.time_cost
        or after.memory_cost < before.memory_cost
        or after.parallelism < before.parallelism
    )


@dataclass(frozen=True)
class WorkerConfig:
    """
    One worker's defaults and the strongest parameters it can produce.

    ``defaults`` is what the worker makes without explicit parameters.
    ``capacity`` is separate because "what my defaults are" and "what I can
    generate" are different questions during a migration.  A worker can
    always *verify* a digest it could not have produced.
    """

    name: str
    defaults: Parameters
    capacity: Parameters

    def new_hasher(self) -> PasswordHasher:
        """
        Return a hasher using this worker's defaults.
        """
        return PasswordHasher.from_parameters(self.defaults)

    def would_rehash(self, digest: str) -> bool:
        """
        Return the naive answer of the existing exact-match API.
        """
        return self.new_hasher().check_needs_rehash(digest)

    def can_produce(self, params: Parameters) -> bool:
        """
        Return whether this worker can produce *params*.
        """
        return meets_target(self.capacity, params)


@dataclass(frozen=True)
class Sample:
    """
    A synthetic stored digest plus everything needed to recreate it.

    ``migration_salt`` is a fixed replacement salt so migrated output can be
    compared against checked-in vectors.  A real migration must generate a
    fresh random salt instead.
    """

    sample_id: str
    password: bytes
    salt: bytes
    parameters: Parameters
    digest: str
    migration_salt: bytes

    @classmethod
    def create(
        cls,
        sample_id: str,
        password: bytes,
        salt: bytes,
        parameters: Parameters,
        migration_salt: bytes,
    ) -> Sample:
        """
        Build a deterministic sample with Argon2's local encoded-hash API.
        """
        digest = hash_secret(
            password,
            salt,
            parameters.time_cost,
            parameters.memory_cost,
            parameters.parallelism,
            parameters.hash_len,
            parameters.type,
            parameters.version,
        ).decode("ascii")

        return cls(
            sample_id, password, salt, parameters, digest, migration_salt
        )


class ReferencePolicy:
    """
    The expected policy: never downgrade and never rewrite compliant data.

    A weaker digest is upgraded only on a worker that can produce the target;
    otherwise it waits for a more capable worker.
    """

    __slots__ = ["target"]

    def __init__(self, target: Parameters):
        self.target = target

    def decide(self, before: Parameters, worker: WorkerConfig) -> Action:
        """
        Decide what should happen to *before* on *worker*.
        """
        if meets_target(before, self.target):
            return Action.KEEP

        if worker.can_produce(self.target):
            return Action.UPGRADE

        return Action.DEFER

    def rehash_parameters(self, worker: WorkerConfig) -> Parameters:
        """
        Return the parameters for a permitted upgrade.
        """
        return self.target


class CheckNeedsRehashUpgrades:
    """
    Deliberately wrong stand-in for acceptance testing.

    This is exactly ``check_needs_rehash()`` used as migration authorization:
    every difference from the running worker's defaults becomes an upgrade,
    and the replacement is written with those defaults.  That can lower a
    digest that already complies, and it can rewrite data that merely differs
    from the defaults.
    """

    __slots__ = ["target"]

    def __init__(self, target: Parameters):
        self.target = target

    def decide(self, before: Parameters, worker: WorkerConfig) -> Action:
        """
        Return ``UPGRADE`` for any digest that differs from the defaults.
        """
        if before != worker.defaults:
            return Action.UPGRADE

        return Action.KEEP

    def rehash_parameters(self, worker: WorkerConfig) -> Parameters:
        """
        Return the worker's defaults, even if they are weaker.
        """
        return worker.defaults


@dataclass(frozen=True)
class MigrationResult:
    """
    Observable outcome of judging and possibly migrating one digest.
    """

    sample_id: str
    worker: str
    verified: bool
    action: Action
    before: Parameters
    after: Parameters | None
    digest_before: str
    digest_after: str | None
    compliant: bool
    differs_from_worker_default: bool
    matches_target: bool

    @property
    def difference_is_default_only(self) -> bool:
        """
        Whether the digest is exactly the target but differs from this
        worker's defaults.

        This is the case a naive ``check_needs_rehash()`` call misreads: it
        reports an update is needed although the digest is already compliant.
        """
        return self.matches_target and self.differs_from_worker_default

    def as_row(self) -> dict[str, object]:
        """
        Return a stable, JSON-friendly record for independent review.

        Digests are included so a reviewer can re-verify them with the local
        interface; the cleartext password is never part of the row.
        """
        return {
            "sample_id": self.sample_id,
            "worker": self.worker,
            "verified": self.verified,
            "action": self.action.value,
            "compliant": self.compliant,
            "differs_from_worker_default": (self.differs_from_worker_default),
            "default_only_difference": self.difference_is_default_only,
            "digest_before": self.digest_before,
            "digest_after": self.digest_after,
        }


def migrate(
    sample: Sample,
    worker: WorkerConfig,
    policy: ReferencePolicy | CheckNeedsRehashUpgrades,
) -> MigrationResult:
    """
    Verify *sample* and apply *policy* on *worker*.

    Upgrades use :attr:`Sample.migration_salt` and the policy's replacement
    parameters, both through Argon2's local hashing interface, so the result
    is reproducible and can be checked against a fixed vector.
    """
    verifier = worker.new_hasher()
    verified = verifier.verify(sample.digest, sample.password)

    before = extract_parameters(sample.digest)
    action = policy.decide(before, worker)

    after: Parameters | None = None
    digest_after: str | None = None
    if action is Action.UPGRADE:
        params = policy.rehash_parameters(worker)
        digest_after = hash_secret(
            sample.password,
            sample.migration_salt,
            params.time_cost,
            params.memory_cost,
            params.parallelism,
            params.hash_len,
            params.type,
            params.version,
        ).decode("ascii")
        after = extract_parameters(digest_after)

    return MigrationResult(
        sample_id=sample.sample_id,
        worker=worker.name,
        verified=verified,
        action=action,
        before=before,
        after=after,
        digest_before=sample.digest,
        digest_after=digest_after,
        compliant=meets_target(before, policy.target),
        differs_from_worker_default=before != worker.defaults,
        matches_target=before == policy.target,
    )


def migrate_all(
    samples: tuple[Sample, ...],
    worker: WorkerConfig,
    policy: ReferencePolicy | CheckNeedsRehashUpgrades,
) -> tuple[MigrationResult, ...]:
    """
    Apply *policy* to *samples* in exactly the given order.
    """
    return tuple(migrate(sample, worker, policy) for sample in samples)


def acknowledge_migration(result: MigrationResult) -> str:
    """
    Return the digest to store after a migration decision.

    ``KEEP`` and ``DEFER`` deliberately return the original digest, so a
    deferred record cannot be silently replaced by this worker.
    """
    if result.action is Action.UPGRADE:
        if result.digest_after is None:
            msg = f"upgrade for {result.sample_id!r} produced no digest"
            raise AssertionError(msg)
        return result.digest_after

    return result.digest_before


@dataclass(frozen=True)
class Violation:
    """
    One digest whose migration change is not acceptable.
    """

    sample_id: str
    worker: str
    reason: str
    digest_after: str | None
    before: Parameters
    after: Parameters | None


def audit(
    results: tuple[MigrationResult, ...], target: Parameters
) -> tuple[Violation, ...]:
    """
    Return every non-compliant change in *results*, preserving input order.

    A change is unacceptable if it rewrites a digest that already met the
    target, lowers any parameter, or claims an upgrade that still falls short
    of the target.
    """
    violations = []

    for result in results:
        if not result.verified:
            violations.append(
                Violation(
                    result.sample_id,
                    result.worker,
                    "digest did not verify",
                    result.digest_after,
                    result.before,
                    result.after,
                )
            )
            continue

        if result.action is not Action.UPGRADE:
            if result.digest_after is not None:
                violations.append(
                    Violation(
                        result.sample_id,
                        result.worker,
                        "non-upgrade produced a digest",
                        result.digest_after,
                        result.before,
                        result.after,
                    )
                )
            continue

        if result.after is None:
            violations.append(
                Violation(
                    result.sample_id,
                    result.worker,
                    "upgrade produced no digest",
                    None,
                    result.before,
                    None,
                )
            )
        elif _downgraded(result.before, result.after):
            violations.append(
                Violation(
                    result.sample_id,
                    result.worker,
                    "downgrade",
                    result.digest_after,
                    result.before,
                    result.after,
                )
            )
        elif meets_target(result.before, target):
            violations.append(
                Violation(
                    result.sample_id,
                    result.worker,
                    "rewrote a compliant digest",
                    result.digest_after,
                    result.before,
                    result.after,
                )
            )
        elif not meets_target(result.after, target):
            violations.append(
                Violation(
                    result.sample_id,
                    result.worker,
                    "still below target",
                    result.digest_after,
                    result.before,
                    result.after,
                )
            )

    return tuple(violations)


_TYPE_BY_NAME = {"d": Type.D, "i": Type.I, "id": Type.ID}


def parameters_from_dict(data: dict[str, object]) -> Parameters:
    """
    Build :class:`~argon2.Parameters` from a JSON fixture entry.
    """
    return Parameters(
        type=_TYPE_BY_NAME[str(data["type"])],
        version=int(data["version"]),  # type: ignore[arg-type]
        salt_len=int(data["salt_len"]),  # type: ignore[arg-type]
        hash_len=int(data["hash_len"]),  # type: ignore[arg-type]
        time_cost=int(data["time_cost"]),  # type: ignore[arg-type]
        memory_cost=int(data["memory_cost"]),  # type: ignore[arg-type]
        parallelism=int(data["parallelism"]),  # type: ignore[arg-type]
    )


def load_worker(name: str) -> WorkerConfig:
    """
    Load a worker configuration by fixture name.
    """
    data = json.loads((FIXTURE_DIR / f"worker-{name}.json").read_text())

    return WorkerConfig(
        name=str(data["name"]),
        defaults=parameters_from_dict(data["defaults"]),  # type: ignore[arg-type]
        capacity=parameters_from_dict(data["capacity"]),  # type: ignore[arg-type]
    )


def load_samples() -> dict[str, Sample]:
    """
    Load all synthetic samples, keyed by sample ID.
    """
    entries = json.loads((FIXTURE_DIR / "samples.json").read_text())

    samples = {}
    for data in entries:  # type: ignore[union-attr]
        samples[str(data["sample_id"])] = Sample.create(
            sample_id=str(data["sample_id"]),
            password=str(data["password_utf8"]).encode(),
            salt=base64.b64decode(str(data["salt_b64"])),
            parameters=parameters_from_dict(data["parameters"]),  # type: ignore[arg-type]
            migration_salt=base64.b64decode(str(data["migration_salt_b64"])),
        )

    return samples


def load_read_order() -> tuple[str, ...]:
    """
    Return the fixed reading order shared by all workers.
    """
    return tuple(json.loads((FIXTURE_DIR / "read-order.json").read_text()))


def load_expected() -> dict[str, dict[str, str]]:
    """
    Return the pinned digest and migrated digest for each sample.
    """
    entries = json.loads((FIXTURE_DIR / "samples.json").read_text())

    return {
        str(data["sample_id"]): {
            "digest": str(data["digest"]),
            "migrated_target_digest": (
                str(data["migrated_target_digest"])
                if "migrated_target_digest" in data
                else None
            ),
        }
        for data in entries  # type: ignore[union-attr]
    }


def load_expected_decisions() -> tuple[dict[str, object], ...]:
    """
    Return the pinned decision table for both workers.
    """
    return tuple(
        json.loads((FIXTURE_DIR / "expected-decisions.json").read_text())
    )
