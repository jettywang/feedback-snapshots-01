# SPDX-License-Identifier: MIT

import dataclasses

from unittest import mock

import pytest

from argon2 import (
    GroupFailureReason,
    GroupStatus,
    ImportGroup,
    InMemoryCommitStore,
    ItemStatus,
    MigrationItem,
    PasswordHasher,
    digest_fingerprint,
    extract_parameters,
    import_groups,
    profiles,
)
from argon2.exceptions import (
    HashingError,
    MigrationStorageError,
    VerifyMismatchError,
)


class RecordingHandle:
    """
    Synthetic short-lived password handle that records its access window.

    The cleartext is only exposed between open() and close(); read() outside
    that window raises, proving the migrator never keeps access alive.
    """

    def __init__(self, password: str | bytes, label: str = "h") -> None:
        self._password = password
        self.label = label
        self.opened = 0
        self.closed = 0
        self.reads = 0
        self._open = False

    def open(self) -> None:
        assert not self._open, "handle opened twice without close"
        self._open = True
        self.opened += 1

    def read(self) -> str | bytes:
        if not self._open:
            msg = "password is only available while the handle is open"
            raise RuntimeError(msg)
        self.reads += 1
        return self._password

    def close(self) -> None:
        assert self._open, "close without open"
        self._open = False
        self.closed += 1


class ExplodingHandle:
    """Handle whose password material cannot be produced."""

    def __init__(self) -> None:
        self.closed = False

    def open(self) -> None:
        msg = "vault entry unavailable"
        raise RuntimeError(msg)

    def read(self) -> str | bytes:
        msg = "never opened"
        raise RuntimeError(msg)

    def close(self) -> None:
        self.closed = True


def _group(group_id, profile, pairs):
    items = tuple(
        MigrationItem(key=key, handle=handle) for key, handle in pairs
    )
    return ImportGroup(group_id=group_id, profile=profile, items=items)


@pytest.fixture()
def two_groups():
    profile_a = profiles.CHEAPEST
    profile_b = dataclasses.replace(profile_a, hash_len=8)
    handles_a = [
        RecordingHandle("s3cret-alpha", "a0"),
        RecordingHandle("s3cret-alpha-2", "a1"),
    ]
    handles_b = [
        RecordingHandle("s3cret-bravo", "b0"),
        RecordingHandle("s3cret-bravo-2", "b1"),
    ]
    group_a = _group(
        "release-a",
        profile_a,
        [("acct-1", handles_a[0]), ("acct-2", handles_a[1])],
    )
    group_b = _group(
        "release-b",
        profile_b,
        [("acct-3", handles_b[0]), ("acct-4", handles_b[1])],
    )
    return group_a, group_b, handles_a, handles_b, profile_b


def _verify_against_store(keys_passwords, store):
    hasher = PasswordHasher()
    outcomes = {}
    for key, password in keys_passwords:
        digest = store.get_digest(key)
        assert digest is not None
        outcomes[key] = hasher.verify(digest, password)
    return outcomes


class TestHappyPath:
    def test_groups_commit_and_digests_verify(self, two_groups):
        group_a, group_b, handles_a, handles_b, _ = two_groups
        store = InMemoryCommitStore()

        result = import_groups([group_a, group_b], store)

        assert result.all_committed is True
        assert [g.group_id for g in result.groups] == [
            "release-a",
            "release-b",
        ]
        for group in result.groups:
            assert group.status is GroupStatus.COMMITTED
            assert group.failure is None
            assert group.uncommitted_keys == ()
            assert len(group.committed_keys) == 2
            for item in group.items:
                assert item.status is ItemStatus.COMMITTED
                assert item.digest_verified is True
                assert item.digest_fingerprint is not None
                assert not item.digest_fingerprint.startswith("$argon2")

        # Every digest landed and verifies against its own password.
        outcomes = _verify_against_store(
            [
                ("acct-1", "s3cret-alpha"),
                ("acct-2", "s3cret-alpha-2"),
                ("acct-3", "s3cret-bravo"),
                ("acct-4", "s3cret-bravo-2"),
            ],
            store,
        )
        assert all(outcomes.values())

        # Handle access is strictly scoped: open once, read >= once, closed.
        for handle in [*handles_a, *handles_b]:
            assert handle.opened == 1
            assert handle.closed == 1
            assert handle.reads >= 1

    def test_distinct_profiles_are_used(self, two_groups):
        group_a, group_b, _, _, profile_b = two_groups
        store = InMemoryCommitStore()

        import_groups([group_a, group_b], store)

        digest_b = store.get_digest("acct-3")

        assert extract_parameters(digest_b).hash_len == profile_b.hash_len
        assert (
            extract_parameters(store.get_digest("acct-1")).hash_len
            == profiles.CHEAPEST.hash_len
        )


class TestStorageFailureAndRecovery:
    def test_backend_error_rolls_group_back_other_group_lands(
        self, two_groups
    ):
        group_a, group_b, handles_a, handles_b, _ = two_groups
        store = InMemoryCommitStore()

        # Fail the first group's commit, after both digests were produced.
        store.fail_next_commit = True
        first = import_groups([group_a, group_b], store)

        result_a, result_b = first.groups

        # Group A: fully uncommitted, marked as a transient storage failure.
        assert result_a.status is GroupStatus.UNCOMMITTED
        assert result_a.failure is not None
        assert result_a.failure.reason is GroupFailureReason.STORAGE
        assert set(result_a.uncommitted_keys) == {"acct-1", "acct-2"}
        assert all(
            item.status is ItemStatus.UNCOMMITTED
            and item.digest_fingerprint is None
            for item in result_a.items
        )

        # Group B is isolated and lands normally.
        assert result_b.status is GroupStatus.COMMITTED
        assert result_b.failure is None
        assert set(result_b.committed_keys) == {"acct-3", "acct-4"}

        # The failed group wrote nothing; no stale digest to verify.
        assert store.get_digest("acct-1") is None
        assert store.get_digest("acct-2") is None
        assert store.group_id_for("acct-3") == "release-b"

        # Handles were still closed even though the backend failed, and the
        # migrator never needed to manage the cleartext itself.
        for handle in handles_a:
            assert handle.opened == 1
            assert handle.closed == 1
        for handle in handles_b:
            assert handle.opened == 1
            assert handle.closed == 1

        # Recover: re-run the same batch with the (still short-lived)
        # handles. Group B is detected as already committed and skipped.
        recovery = import_groups([group_a, group_b], store)
        rec_a, rec_b = recovery.groups

        assert rec_a.status is GroupStatus.COMMITTED
        assert rec_b.status is GroupStatus.COMMITTED
        assert all(
            item.status is ItemStatus.ALREADY_COMMITTED for item in rec_b.items
        )
        # Skipped accounts never had their handles touched again.
        for handle in handles_b:
            assert handle.opened == 1
            assert handle.closed == 1
            assert handle.reads == 1
        for handle in handles_a:
            assert handle.opened == 2
            assert handle.closed == 2

        # Now every account verifies, including group A's new digests.
        outcomes = _verify_against_store(
            [
                ("acct-1", "s3cret-alpha"),
                ("acct-2", "s3cret-alpha-2"),
                ("acct-3", "s3cret-bravo"),
                ("acct-4", "s3cret-bravo-2"),
            ],
            store,
        )
        assert all(outcomes.values())
        # Group A landed under its own approved group id.
        assert store.group_id_for("acct-1") == "release-a"

    def test_reprocessing_is_idempotent(self, two_groups):
        group_a, group_b, handles_a, handles_b, _ = two_groups
        store = InMemoryCommitStore()

        import_groups([group_a, group_b], store)
        first_digests = {
            key: store.get_digest(key)
            for key in ("acct-1", "acct-2", "acct-3", "acct-4")
        }
        second = import_groups([group_a, group_b], store)

        # No new effective records: digests are byte-identical and every
        # account is reported as already committed.
        for key, digest in first_digests.items():
            assert store.get_digest(key) == digest
        for group in second.groups:
            assert group.status is GroupStatus.COMMITTED
            assert all(
                item.status is ItemStatus.ALREADY_COMMITTED
                for item in group.items
            )
            # A skipped pass produces no new digest material at all.
            assert all(item.digest_fingerprint is None for item in group.items)
        for handle in [*handles_a, *handles_b]:
            assert handle.opened == 1  # second pass skipped the handle

    def test_stage_failure_after_one_digest_rolls_whole_group(self):
        handles = [RecordingHandle("pw-1"), RecordingHandle("pw-2")]
        group = _group(
            "g",
            profiles.CHEAPEST,
            [("k1", handles[0]), ("k2", handles[1])],
        )
        store = InMemoryCommitStore()
        store.fail_next_stage = True  # blows up on the very first stage

        result = import_groups([group], store)
        (group_result,) = result.groups

        assert group_result.status is GroupStatus.UNCOMMITTED
        assert group_result.failure.reason is GroupFailureReason.STORAGE
        assert store.get_digest("k1") is None
        assert store.get_digest("k2") is None
        # The handle that was opened is still closed in the failure path;
        # the second account was never reached so its handle stays untouched.
        assert handles[0].opened == 1
        assert handles[0].closed == 1
        assert handles[1].opened == 0
        assert handles[1].closed == 0


class TestGroupIsolation:
    def test_handle_failure_only_affects_its_group(self, two_groups):
        group_a, group_b, _, handles_b, _ = two_groups
        bad_handle = ExplodingHandle()
        broken_group = _group(
            "broken", profiles.CHEAPEST, [("acct-x", bad_handle)]
        )
        store = InMemoryCommitStore()

        result = import_groups([broken_group, group_b], store)
        broken, healthy = result.groups

        assert broken.status is GroupStatus.UNCOMMITTED
        assert broken.failure.reason is GroupFailureReason.HANDLE
        assert healthy.status is GroupStatus.COMMITTED
        assert store.get_digest("acct-x") is None
        assert store.get_digest("acct-3") is not None
        for handle in handles_b:
            assert handle.opened == 1
            assert handle.closed == 1

    def test_calculation_failure_only_affects_its_group(self, two_groups):
        group_a, group_b, _, handles_b, _ = two_groups
        calc_group = _group(
            "calc",
            profiles.CHEAPEST,
            [("acct-y", RecordingHandle("pw-y"))],
        )
        store = InMemoryCommitStore()
        real_hash = PasswordHasher.hash

        def faulting_hash(self, password, *, salt=None):
            if self._parameters.hash_len == profiles.CHEAPEST.hash_len:
                raise HashingError("ARGON2_MEMORY_ALLOCATOR_ERROR")
            return real_hash(self, password, salt=salt)

        with mock.patch.object(PasswordHasher, "hash", faulting_hash):
            result = import_groups([calc_group, group_b], store)

        calc_result, healthy = result.groups

        # The Argon2 computation failure rolls its own group back...
        assert calc_result.status is GroupStatus.UNCOMMITTED
        assert calc_result.failure.reason is (GroupFailureReason.CALCULATION)
        assert "ARGON2" in calc_result.failure.detail
        assert store.get_digest("acct-y") is None

        # ...while the other group (a different approved profile) still
        # commits and remains verifiable.
        assert healthy.status is GroupStatus.COMMITTED
        assert PasswordHasher().verify(
            store.get_digest("acct-3"), "s3cret-bravo"
        )
        for handle in handles_b:
            assert handle.opened == 1
            assert handle.closed == 1

    def test_verification_failure_rolls_group_back(self):
        handle = RecordingHandle("pw")
        group = _group("verify", profiles.CHEAPEST, [("acct-v", handle)])
        store = InMemoryCommitStore()

        with mock.patch.object(
            PasswordHasher,
            "verify",
            side_effect=VerifyMismatchError("does not match"),
        ):
            result = import_groups([group], store)

        (gr,) = result.groups
        assert gr.status is GroupStatus.UNCOMMITTED
        assert gr.failure.reason is GroupFailureReason.VERIFICATION
        assert store.get_digest("acct-v") is None
        assert handle.closed == 1


class TestDiagnostics:
    def test_failure_detail_has_no_password_or_full_digest(self, two_groups):
        group_a, _, handles_a, _, _ = two_groups
        store = InMemoryCommitStore()
        store.fail_next_commit = True

        (result_a,) = import_groups([group_a], store).groups
        detail = result_a.failure.detail

        assert "s3cret" not in detail
        assert "$argon2" not in detail
        assert "MigrationStorageError" in detail

    def test_fingerprint_is_stable_and_non_reversible(self):
        digest = PasswordHasher.from_parameters(profiles.CHEAPEST).hash(
            "hunter2"
        )
        fp1 = digest_fingerprint(digest)
        fp2 = digest_fingerprint(digest.encode())

        assert fp1 == fp2
        assert fp1.startswith("fp_")
        assert digest not in fp1
        assert "hunter2" not in fp1
        assert len(fp1) == len("fp_") + 16


def test_old_registration_remains_verifiable_after_rollback():
    """
    A rolled-back rehash must leave the previous digest fully usable.
    """
    old_hasher = PasswordHasher.from_parameters(profiles.CHEAPEST)
    old_digest = old_hasher.hash("original-password")

    store = InMemoryCommitStore()
    tx = store.begin("seed")
    tx.stage("acct", old_digest, "seed")
    tx.commit()

    handle = RecordingHandle("new-password")
    group = _group("rehash", profiles.CHEAPEST, [("acct", handle)])
    store.fail_next_commit = True
    (failed,) = import_groups([group], store).groups

    assert failed.status is GroupStatus.UNCOMMITTED
    # Old registration is untouched and still verifies the old password.
    assert store.get_digest("acct") == old_digest
    assert store.group_id_for("acct") == "seed"
    assert old_hasher.verify(old_digest, "original-password")
    with pytest.raises(VerifyMismatchError):
        old_hasher.verify(old_digest, "new-password")


def test_migration_storage_error_is_public():
    with pytest.raises(MigrationStorageError):
        raise MigrationStorageError("boom")
