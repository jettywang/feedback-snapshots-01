# SPDX-License-Identifier: MIT

"""
Regression tests for refusing to downgrade password digests.

The production migration code is about to be replaced.  These tests pin the
decision contract with synthetic, low-cost digests: the same stored record is
judged on two workers whose defaults differ only locally, and the actual
migrated output is checked against independent local vectors.
"""

import pytest

from argon2 import Parameters, Type, extract_parameters, profiles
from argon2.low_level import verify_secret

from ._migration_harness import (
    Action,
    CheckNeedsRehashUpgrades,
    ReferencePolicy,
    acknowledge_migration,
    audit,
    load_expected,
    load_expected_decisions,
    load_read_order,
    load_samples,
    load_worker,
    meets_target,
    migrate,
    migrate_all,
)


TARGET = Parameters(
    type=Type.ID,
    version=19,
    salt_len=16,
    hash_len=8,
    time_cost=2,
    memory_cost=64,
    parallelism=4,
)

# (sample_id, primary action, edge action, compliant with the target)
EXPECTED_DECISIONS = [
    ("compliant-at-target", Action.KEEP, Action.KEEP, True),
    ("legacy-v18-argon2i", Action.UPGRADE, Action.DEFER, False),
    ("matches-edge-defaults", Action.UPGRADE, Action.DEFER, False),
    ("stronger-than-target", Action.KEEP, Action.KEEP, True),
    ("needs-cost-upgrade", Action.UPGRADE, Action.DEFER, False),
    ("short-salt", Action.UPGRADE, Action.DEFER, False),
]


@pytest.fixture(scope="module")
def workers():
    """
    The two locally different worker configurations.
    """
    return load_worker("primary"), load_worker("edge")


@pytest.fixture(scope="module")
def samples():
    """
    Synthetic samples, keyed by ID.
    """
    return load_samples()


@pytest.fixture(scope="module")
def read_order():
    """
    The fixed reading order shared by both workers.
    """
    return load_read_order()


class TestWorkerConfigs:
    def test_configs_differ_only_locally(self, workers, samples):
        """
        The two worker configs are identical except for parallelism.
        """
        primary, edge = workers

        assert primary.name == "primary"
        assert edge.name == "edge"
        assert primary.defaults == TARGET
        assert primary.capacity == TARGET
        assert edge.capacity == edge.defaults
        assert edge.defaults == Parameters(
            type=Type.ID,
            version=19,
            salt_len=16,
            hash_len=8,
            time_cost=2,
            memory_cost=64,
            parallelism=1,
        )

        fields = (
            "type",
            "version",
            "salt_len",
            "hash_len",
            "time_cost",
            "memory_cost",
            "parallelism",
        )

        assert {
            field
            for field in fields
            if getattr(primary.defaults, field)
            != getattr(edge.defaults, field)
        } == {"parallelism"}

        assert {
            field
            for field in fields
            if getattr(primary.capacity, field)
            != getattr(edge.capacity, field)
        } == {"parallelism"}

        # The capable worker can produce the target; the single-threaded
        # worker can only verify it.
        assert primary.can_produce(TARGET)
        assert not edge.can_produce(TARGET)
        assert edge.new_hasher().verify(
            samples["compliant-at-target"].digest,
            samples["compliant-at-target"].password,
        )

    def test_configs_are_cheap_and_legal(self, workers):
        """
        Every synthetic configuration is accepted by the real local API.
        """
        for worker in workers:
            for params in (worker.defaults, worker.capacity):
                assert params.memory_cost <= 64
                assert params.time_cost <= 3
                assert params.parallelism <= 4
                assert params.type is Type.ID
                assert params.version == 19

                # Constructing a PasswordHasher is the platform validation.
                worker.new_hasher()

    def test_read_order_is_fixed_and_complete(self, read_order, samples):
        """
        The pinned reading order covers every sample exactly once.
        """
        assert read_order == (
            "compliant-at-target",
            "legacy-v18-argon2i",
            "matches-edge-defaults",
            "stronger-than-target",
            "needs-cost-upgrade",
            "short-salt",
        )
        assert set(read_order) == set(samples)
        assert len(read_order) == len(set(read_order))


class TestSampleLegality:
    def test_every_sample_verifies_on_both_workers(
        self, workers, samples, read_order
    ):
        """
        All samples are legal, low-cost digests that each worker can verify.
        """
        for worker in workers:
            for sample_id in read_order:
                sample = samples[sample_id]

                assert worker.new_hasher().verify(
                    sample.digest, sample.password
                )

    def test_samples_match_checked_in_vectors(self, samples):
        """
        Regenerating each sample reproduces the checked-in digest.
        """
        expected = load_expected()

        for sample_id, sample in samples.items():
            assert sample.digest == expected[sample_id]["digest"]

            assert verify_secret(
                sample.digest.encode(),
                sample.password,
                sample.parameters.type,
            )

    def test_samples_are_below_or_at_target(self, samples, read_order):
        """
        A sample either meets the target or is below it, never ambiguous.
        """
        for sample_id in read_order:
            before = extract_parameters(samples[sample_id].digest)
            compliant = meets_target(before, TARGET)

            if sample_id in {
                "compliant-at-target",
                "stronger-than-target",
            }:
                assert compliant
            else:
                assert not compliant


class TestSameRecordDifferentWorkers:
    def test_decisions_are_worker_specific(self, workers, samples, read_order):
        """
        The same record gets the same verification but a different migration
        decision when a worker's local defaults differ.
        """
        primary, edge = workers
        policy = ReferencePolicy(TARGET)

        for (
            sample_id,
            primary_action,
            edge_action,
            compliant,
        ) in EXPECTED_DECISIONS:
            sample = samples[sample_id]

            primary_result = migrate(sample, primary, policy)
            edge_result = migrate(sample, edge, policy)

            assert primary_result.verified is True
            assert edge_result.verified is True
            assert primary_result.before == edge_result.before
            assert primary_result.compliant is compliant
            assert edge_result.compliant is compliant

            assert primary_result.action is primary_action
            assert edge_result.action is edge_action

    def test_incapable_worker_defers_instead_of_downgrading(
        self, workers, samples
    ):
        """
        A worker that cannot produce the target leaves a weaker digest alone.
        """
        _, edge = workers
        sample = samples["needs-cost-upgrade"]

        result = migrate(sample, edge, ReferencePolicy(TARGET))

        assert result.action is Action.DEFER
        assert result.digest_after is None
        assert result.after is None
        assert result.digest_before == sample.digest

        # The deferred record is acknowledged unchanged, so this worker
        # cannot silently replace it with weaker parameters.
        assert acknowledge_migration(result) == sample.digest

    def test_compliant_record_is_kept_on_every_worker(self, workers, samples):
        """
        A compliant digest is never rewritten, even where it differs from the
        worker's defaults.
        """
        policy = ReferencePolicy(TARGET)

        for worker in workers:
            for sample_id in ("compliant-at-target", "stronger-than-target"):
                result = migrate(samples[sample_id], worker, policy)

                assert result.action is Action.KEEP
                assert result.digest_after is None
                assert result.compliant is True

    def test_default_only_difference_is_not_an_upgrade_signal(
        self, workers, samples
    ):
        """
        ``check_needs_rehash()`` is true here, yet no migration is allowed.

        On the edge worker, an at-target digest differs from the defaults in
        parallelism.  That difference must not be read as a reason to rewrite.
        """
        primary, edge = workers

        at_target = samples["compliant-at-target"]
        stronger = samples["stronger-than-target"]

        assert edge.would_rehash(at_target.digest) is True
        assert primary.would_rehash(stronger.digest) is True

        # Exactly the target, judged where the defaults differ: the only
        # difference is the worker's local default.
        edge_result = migrate(at_target, edge, ReferencePolicy(TARGET))

        assert edge_result.action is Action.KEEP
        assert edge_result.matches_target is True
        assert edge_result.differs_from_worker_default is True
        assert edge_result.difference_is_default_only is True
        assert edge_result.digest_after is None

        # Also compliant, but varies from the target in strength rather than
        # merely from a worker default: it is still kept, never downgraded.
        stronger_result = migrate(stronger, primary, ReferencePolicy(TARGET))

        assert stronger_result.action is Action.KEEP
        assert stronger_result.compliant is True
        assert stronger_result.matches_target is False
        assert stronger_result.difference_is_default_only is False
        assert stronger_result.digest_after is None

        # The primary worker's defaults are the target, so an at-target
        # digest does not differ there -- but it is still compliant.
        primary_result = migrate(at_target, primary, ReferencePolicy(TARGET))

        assert primary_result.action is Action.KEEP
        assert primary_result.compliant is True
        assert primary_result.differs_from_worker_default is False

    def test_default_match_can_still_need_upgrade(self, workers, samples):
        """
        Matching a worker's defaults is not compliance with the target.

        The edge worker's defaults equal this digest, so the naive API says
        no rehash is needed; the target still requires more parallelism, so
        the record must be deferred rather than kept as final.
        """
        _, edge = workers
        sample = samples["matches-edge-defaults"]

        assert edge.would_rehash(sample.digest) is False

        result = migrate(sample, edge, ReferencePolicy(TARGET))

        assert result.action is Action.DEFER
        assert result.compliant is False
        assert result.differs_from_worker_default is False


class TestMigrationOutput:
    def test_migrated_output_matches_independent_vectors(
        self, workers, samples
    ):
        """
        Upgrades are reproducible and equal the checked-in vectors, which can
        be re-verified directly with the low-level interface.
        """
        expected = load_expected()
        primary, edge = workers
        policy = ReferencePolicy(TARGET)

        for sample_id in (
            "legacy-v18-argon2i",
            "needs-cost-upgrade",
            "short-salt",
        ):
            sample = samples[sample_id]
            result = migrate(sample, primary, policy)

            assert result.action is Action.UPGRADE
            assert (
                result.digest_after
                == expected[sample_id]["migrated_target_digest"]
            )
            assert result.after == TARGET

            assert verify_secret(
                result.digest_after.encode(),
                sample.password,
                Type.ID,
            )

            # The single-threaded worker must not emit a weaker replacement.
            deferred = migrate(sample, edge, policy)
            assert deferred.action is Action.DEFER
            assert deferred.digest_after is None

    def test_upgrade_replaces_salt(self, samples):
        """
        Migration does not reuse the old salt: the encoded salt changes.
        """
        sample = samples["needs-cost-upgrade"]

        assert sample.migration_salt != sample.salt
        assert len(sample.migration_salt) == TARGET.salt_len

    def test_audit_accepts_reference_policy(
        self, workers, samples, read_order
    ):
        """
        The reference policy produces no unacceptable change on any worker.
        """
        ordered = tuple(samples[sample_id] for sample_id in read_order)

        for worker in workers:
            results = migrate_all(ordered, worker, ReferencePolicy(TARGET))

            assert [r.sample_id for r in results] == list(read_order)
            assert audit(results, TARGET) == ()

    def test_review_rows_match_pinned_decision_table(
        self, workers, samples, read_order
    ):
        """
        The published decision table equals what the reference policy does.
        """
        ordered = tuple(samples[sample_id] for sample_id in read_order)
        rows = []

        for worker in workers:
            rows.extend(
                result.as_row()
                for result in migrate_all(
                    ordered, worker, ReferencePolicy(TARGET)
                )
            )

        assert rows == list(load_expected_decisions())

    def test_review_rows_never_contain_the_password(
        self, workers, samples, read_order
    ):
        """
        Rows expose digests for independent review, but no cleartext.
        """
        ordered = tuple(samples[sample_id] for sample_id in read_order)

        for worker in workers:
            for result in migrate_all(
                ordered, worker, ReferencePolicy(TARGET)
            ):
                row = result.as_row()

                assert set(row) == {
                    "sample_id",
                    "worker",
                    "verified",
                    "action",
                    "compliant",
                    "differs_from_worker_default",
                    "default_only_difference",
                    "digest_before",
                    "digest_after",
                }
                assert samples[result.sample_id].password.decode() not in str(
                    row
                )


class TestRejectDanglingUpgrade:
    def test_any_difference_policy_is_rejected_on_primary(
        self, workers, samples, read_order
    ):
        """
        The wrong stand-in lowers a stronger-than-target digest on the
        primary worker; acceptance names that digest.
        """
        primary, _ = workers
        ordered = tuple(samples[sample_id] for sample_id in read_order)

        results = migrate_all(
            ordered, primary, CheckNeedsRehashUpgrades(TARGET)
        )
        violations = audit(results, TARGET)

        assert [v.sample_id for v in violations] == ["stronger-than-target"]
        assert violations[0].reason == "downgrade"
        assert violations[0].worker == "primary"
        assert violations[0].after == TARGET

    def test_any_difference_policy_is_rejected_on_edge(
        self, workers, samples, read_order
    ):
        """
        On the edge worker the wrong stand-in rewrites a compliant digest and
        emits still-non-compliant replacements; acceptance names each one.
        """
        _, edge = workers
        ordered = tuple(samples[sample_id] for sample_id in read_order)

        results = migrate_all(ordered, edge, CheckNeedsRehashUpgrades(TARGET))
        violations = audit(results, TARGET)

        assert [(v.sample_id, v.reason) for v in violations] == [
            ("compliant-at-target", "downgrade"),
            ("legacy-v18-argon2i", "still below target"),
            ("stronger-than-target", "downgrade"),
            ("needs-cost-upgrade", "still below target"),
            ("short-salt", "downgrade"),
        ]

        # Every reported digest is the actual replacement that was written.
        for violation in violations:
            result = next(
                r for r in results if r.sample_id == violation.sample_id
            )
            assert violation.digest_after == result.digest_after

    def test_wrong_policy_reports_the_digest_that_changed(
        self, workers, samples
    ):
        """
        Acceptance output points at the exact digests, not just a boolean.
        """
        _, edge = workers
        policy = CheckNeedsRehashUpgrades(TARGET)

        rewrite = migrate(samples["compliant-at-target"], edge, policy)
        violation = audit((rewrite,), TARGET)[0]

        assert violation.reason == "downgrade"
        assert violation.digest_after == rewrite.digest_after
        assert violation.digest_after != rewrite.digest_before


def test_target_is_cheaper_than_the_installed_default():
    """
    The synthetic target is a legal but cheaper stand-in for the real default.
    """
    default = profiles.get_default_parameters()

    assert TARGET.memory_cost < default.memory_cost
    assert TARGET.time_cost <= default.time_cost
    assert TARGET.parallelism <= default.parallelism
    assert TARGET.salt_len <= default.salt_len
    assert TARGET.hash_len <= default.hash_len


def test_fixture_salts_match_declared_lengths(samples):
    """
    Every fixture salt decodes to the length recorded in its parameters.
    """
    for sample in samples.values():
        assert len(sample.salt) == sample.parameters.salt_len
        assert len(sample.migration_salt) == 16
