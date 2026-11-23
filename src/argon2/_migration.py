# SPDX-License-Identifier: MIT

"""
Transactional, group-scoped bulk import of rehashed password digests.

This module lets an account migrator turn a *batch* of approved rehash
requests into Argon2 digests without taking ownership of the cleartext
passwords and without leaving a group half-applied:

* The caller supplies short-lived :class:`PasswordHandle` objects that expose
  a cleartext password only while the group is being processed.
* The caller supplies a :class:`CommitStore` whose transactions own the
  durable write.  A group is either fully committed or fully rolled back.
* A failure while processing one group never affects the other groups in
  the batch.
* Re-running a batch never produces a second set of effective records:
  accounts that already landed under a group id are detected through the
  store and skipped before their handles are opened.

The regular :class:`~argon2.PasswordHasher` one-at-a-time API is unaffected
and remains the right choice outside of batch migration.
"""

from __future__ import annotations

import hashlib

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from ._password_hasher import PasswordHasher
from ._utils import Parameters
from .exceptions import (
    HashingError,
    InvalidHashError,
    MigrationStorageError,
    VerificationError,
)


# ---------------------------------------------------------------------------
# Status enums and result records
# ---------------------------------------------------------------------------


class GroupStatus(str, Enum):
    """
    Outcome of processing one migration group.
    """

    COMMITTED = "committed"
    UNCOMMITTED = "uncommitted"


class ItemStatus(str, Enum):
    """
    Outcome of processing one account within a group.
    """

    COMMITTED = "committed"
    ALREADY_COMMITTED = "already_committed"
    UNCOMMITTED = "uncommitted"


class GroupFailureReason(str, Enum):
    """
    Machine-readable category of a group failure.

    Only :attr:`STORAGE` is considered transient; the migrator never retries
    a group on its own and never touches the cleartext lifecycle itself.
    """

    HANDLE = "handle"
    FORMAT = "format"
    CALCULATION = "calculation"
    VERIFICATION = "verification"
    STORAGE = "storage"


@dataclass(frozen=True, slots=True)
class GroupFailure:
    """
    Why a group was rolled back.

    The *detail* string is safe for logs: it never contains a cleartext
    password or a complete digest.  Use :func:`digest_fingerprint` if you
    need to correlate a digest in your own diagnostics.
    """

    reason: GroupFailureReason
    detail: str


@dataclass(frozen=True, slots=True)
class ItemResult:
    """
    Per-account outcome within a processed group.

    *digest_fingerprint* is ``None`` unless a brand-new digest was actually
    committed for the account.  The full digest lives only in the commit
    store, never in these results.
    """

    key: str
    status: ItemStatus
    digest_fingerprint: str | None = None
    digest_verified: bool | None = None


@dataclass(frozen=True, slots=True)
class GroupResult:
    """
    Outcome of processing one :class:`ImportGroup`.

    Full digests are deliberately absent: they remain solely in the
    :class:`CommitStore`.  Results expose only non-reversible fingerprints,
    so they are safe to log and ship to diagnostics.
    """

    group_id: str
    status: GroupStatus
    items: tuple[ItemResult, ...] = ()
    failure: GroupFailure | None = None

    @property
    def uncommitted_keys(self) -> tuple[str, ...]:
        """
        Keys whose approved digest has not landed yet and must be retried.
        """
        return tuple(
            item.key
            for item in self.items
            if item.status is ItemStatus.UNCOMMITTED
        )

    @property
    def committed_keys(self) -> tuple[str, ...]:
        """
        Keys whose digest is now effective under this group.
        """
        return tuple(
            item.key
            for item in self.items
            if item.status
            in (ItemStatus.COMMITTED, ItemStatus.ALREADY_COMMITTED)
        )


@dataclass(frozen=True, slots=True)
class BatchResult:
    """
    Aggregate outcome of :func:`import_groups`.
    """

    groups: tuple[GroupResult, ...]

    @property
    def all_committed(self) -> bool:
        """
        Whether every group in the batch landed (or was already landed).
        """
        return all(
            group.status is GroupStatus.COMMITTED for group in self.groups
        )

    def group(self, group_id: str) -> GroupResult:
        """
        Return the result for *group_id*.

        Raises:
            KeyError: If the batch did not contain *group_id*.
        """
        for group in self.groups:
            if group.group_id == group_id:
                return group
        msg = f"Unknown group id: {group_id!r}"
        raise KeyError(msg)


# ---------------------------------------------------------------------------
# Input contracts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MigrationItem:
    """
    One approved rehash request.

    Args:
        key: Stable, non-secret account identifier used by the store.
        handle: Short-lived handle for the account's cleartext password.
    """

    key: str
    handle: PasswordHandle


@dataclass(frozen=True, slots=True)
class ImportGroup:
    """
    A release group that must land atomically.

    Every group may use its own approved *profile*; the resulting hasher is
    cached per distinct parameter set for the duration of the batch.
    """

    group_id: str
    profile: Parameters
    items: tuple[MigrationItem, ...]


@runtime_checkable
class PasswordHandle(Protocol):
    """
    Short-lived, caller-owned accessor for one cleartext password.

    The migrator calls :meth:`open` at most once, immediately before it needs
    the password, and :meth:`close` exactly once when the account has been
    processed -- even if hashing or the backend fails.  Between those two
    calls :meth:`read` returns the cleartext password as ``str`` or
    ``bytes``; afterwards it must not.

    Implementations own the cleartext lifecycle (for example an unlocked
    vault entry or a pinned buffer).  The migrator never persists, logs, or
    closes over the returned value beyond the single hashing call.
    """

    def open(self) -> None:
        """
        Make :meth:`read` available for this handle.
        """

    def read(self) -> str | bytes:
        """
        Return the cleartext password while the handle is open.
        """

    def close(self) -> None:
        """
        Release the cleartext material and make :meth:`read` unavailable.
        """


class MigrationTransaction(Protocol):
    """
    One atomic write of a single migration group.

    All staging happens against an isolated, private view.  Nothing is
    visible outside the transaction until :meth:`commit` succeeds;
    :meth:`rollback` (or dropping the object without committing) discards
    every staged write.
    """

    def is_committed(self, key: str, group_id: str) -> bool:
        """
        Whether *key* already carries a digest landed under *group_id*.

        A truthful result makes re-running a batch idempotent.
        """

    def stage(self, key: str, digest: str, group_id: str) -> None:
        """
        Record the new *digest* for *key* inside this transaction.

        Raises:
            argon2.exceptions.MigrationStorageError: On a transient
                backend failure.
        """

    def commit(self) -> None:
        """
        Make every staged write durable and visible.

        Raises:
            argon2.exceptions.MigrationStorageError: On a transient
                backend failure; the transaction is then considered rolled
                back.
        """

    def rollback(self) -> None:
        """
        Discard every staged write without touching the live store.
        """


class CommitStore(Protocol):
    """
    Caller-supplied, transactional storage for password digests.

    A store hands out one :class:`MigrationTransaction` per group and keeps
    the previously registered digest available until a transaction commits,
    so a rolled-back group leaves the old registration fully verifiable.
    """

    def begin(self, group_id: str) -> MigrationTransaction:
        """
        Open a fresh transaction for *group_id*.
        """


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def digest_fingerprint(digest: str | bytes) -> str:
    """
    Return a short, non-reversible fingerprint of an encoded *digest*.

    Fingerprints let operators correlate digest records in logs without ever
    exposing the full digest (which is usable for offline guessing).  The
    same digest always maps to the same fingerprint within a library
    version.
    """
    if isinstance(digest, str):
        digest = digest.encode("ascii")
    return "fp_" + hashlib.blake2b(digest, digest_size=8).hexdigest()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def _failure(exc: Exception, reason: GroupFailureReason) -> GroupFailure:
    detail = f"{type(exc).__name__}: {exc}".rstrip(": ")
    return GroupFailure(reason=reason, detail=detail)


def _import_group(
    group: ImportGroup,
    store: CommitStore,
    hashers: dict[int, PasswordHasher],
    verify: bool,
) -> GroupResult:
    profile = group.profile
    hasher = hashers.get(id(profile))
    if hasher is None:
        hasher = PasswordHasher.from_parameters(profile)
        hashers[id(profile)] = hasher

    transaction = store.begin(group.group_id)
    results: list[ItemResult] = []
    try:
        try:
            for item in group.items:
                if transaction.is_committed(item.key, group.group_id):
                    results.append(
                        ItemResult(
                            key=item.key,
                            status=ItemStatus.ALREADY_COMMITTED,
                        )
                    )
                    continue

                item.handle.open()
                try:
                    password = item.handle.read()
                    digest = hasher.hash(password)
                    if verify:
                        hasher.verify(digest, password)
                    transaction.stage(item.key, digest, group.group_id)
                finally:
                    # The cleartext lifetime ends here, even when hashing,
                    # verification, or staging fails.
                    item.handle.close()

                results.append(
                    ItemResult(
                        key=item.key,
                        status=ItemStatus.COMMITTED,
                        digest_fingerprint=digest_fingerprint(digest),
                        digest_verified=True if verify else None,
                    )
                )

            transaction.commit()
        except MigrationStorageError as exc:
            transaction.rollback()
            return GroupResult(
                group_id=group.group_id,
                status=GroupStatus.UNCOMMITTED,
                items=tuple(
                    ItemResult(
                        key=item.key,
                        status=ItemStatus.UNCOMMITTED,
                    )
                    for item in group.items
                ),
                failure=_failure(exc, GroupFailureReason.STORAGE),
            )
        except Exception as exc:  # noqa: BLE001 - isolated per group
            transaction.rollback()
            reason = _classify(exc)
            return GroupResult(
                group_id=group.group_id,
                status=GroupStatus.UNCOMMITTED,
                items=tuple(
                    ItemResult(
                        key=item.key,
                        status=ItemStatus.UNCOMMITTED,
                    )
                    for item in group.items
                ),
                failure=_failure(exc, reason),
            )
    except MigrationStorageError as exc:
        # Rolling back itself hit the backend; the transaction is already
        # abandoned.  Report without leaking any secret material.
        return GroupResult(
            group_id=group.group_id,
            status=GroupStatus.UNCOMMITTED,
            items=tuple(
                ItemResult(key=item.key, status=ItemStatus.UNCOMMITTED)
                for item in group.items
            ),
            failure=_failure(exc, GroupFailureReason.STORAGE),
        )

    return GroupResult(
        group_id=group.group_id,
        status=GroupStatus.COMMITTED,
        items=tuple(results),
    )


def _classify(exc: Exception) -> GroupFailureReason:
    # Order matters: VerificationError is a subtype of Argon2Error only.
    if isinstance(exc, VerificationError):
        return GroupFailureReason.VERIFICATION
    if isinstance(exc, InvalidHashError):
        return GroupFailureReason.FORMAT
    if isinstance(exc, TypeError | ValueError | UnicodeError):
        return GroupFailureReason.FORMAT
    if isinstance(exc, HashingError):
        return GroupFailureReason.CALCULATION
    return GroupFailureReason.HANDLE


def import_groups(
    groups: list[ImportGroup] | tuple[ImportGroup, ...],
    store: CommitStore,
    *,
    verify: bool = True,
) -> BatchResult:
    """
    Import a batch of approved rehash groups.

    Each group is processed in its own store transaction and is isolated
    from the others: a malformed handle, an Argon2 computation failure, or a
    transient storage error rolls back that group only.  Storage failures
    are reported as :data:`GroupFailureReason.STORAGE` and leave the old
    registrations untouched, so the same batch can simply be run again with
    fresh handles.

    Args:
        groups: Release groups to process.  Each group carries its own
            approved Argon2 profile.
        store: Caller-owned transactional digest storage.
        verify:
            When true (the default), every freshly produced digest is
            immediately verified against its handle before staging.

    Returns:
        A :class:`BatchResult` describing the true commit state of every
        group and account, with fingerprints rather than full digests.
    """
    hashers: dict[int, PasswordHasher] = {}
    results = [
        _import_group(group, store, hashers, verify) for group in groups
    ]
    return BatchResult(groups=tuple(results))


# ---------------------------------------------------------------------------
# In-memory reference implementation
# ---------------------------------------------------------------------------


class _InMemoryTransaction:
    """
    Copy-on-write transaction used by :class:`InMemoryCommitStore`.

    Reads always observe the last committed state; writes are buffered in a
    private map and only merged into the store on commit.
    """

    __slots__ = ("_group_id", "_store", "_staged", "_closed")

    def __init__(self, store: InMemoryCommitStore, group_id: str) -> None:
        self._store = store
        self._group_id = group_id
        self._staged: dict[str, str] = {}
        self._closed = False

    def is_committed(self, key: str, group_id: str) -> bool:
        return self._store.is_committed(key, group_id)

    def stage(self, key: str, digest: str, group_id: str) -> None:
        if group_id != self._group_id:
            msg = "group id does not match the open transaction"
            raise MigrationStorageError(msg)
        if self._closed:
            msg = "transaction is closed"
            raise MigrationStorageError(msg)
        if self._store.fail_next_stage:
            self._store.fail_next_stage = False
            msg = "simulated transient staging failure"
            raise MigrationStorageError(msg)
        self._staged[key] = digest

    def commit(self) -> None:
        if self._closed:
            msg = "transaction is closed"
            raise MigrationStorageError(msg)
        if self._store.fail_next_commit:
            self._store.fail_next_commit = False
            self._closed = True
            self._staged = {}
            msg = "simulated transient commit failure"
            raise MigrationStorageError(msg)
        for key, digest in self._staged.items():
            self._store._apply(key, digest, self._group_id)
        self._closed = True
        self._staged = {}

    def rollback(self) -> None:
        self._staged = {}
        self._closed = True


class InMemoryCommitStore:
    """
    Transactional, in-memory :class:`CommitStore` for tests and adapters.

    It keeps, per account key, the currently effective digest plus the group
    id that landed it.  Transactions are copy-on-write: rolling back leaves
    the previously registered digest -- including its ability to be
    verified -- completely untouched.

    The two ``fail_next_*`` flags exist solely to exercise transient
    backend failures; production stores would raise
    :class:`~argon2.exceptions.MigrationStorageError` from real I/O errors.
    """

    __slots__ = (
        "_digests",
        "_group_ids",
        "fail_next_commit",
        "fail_next_stage",
    )

    def __init__(self) -> None:
        self._digests: dict[str, str] = {}
        self._group_ids: dict[str, str] = {}
        self.fail_next_commit = False
        self.fail_next_stage = False

    def begin(self, group_id: str) -> MigrationTransaction:
        return _InMemoryTransaction(self, group_id)

    def is_committed(self, key: str, group_id: str) -> bool:
        return self._group_ids.get(key) == group_id

    def get_digest(self, key: str) -> str | None:
        """
        Return the currently effective digest for *key*, if any.
        """
        return self._digests.get(key)

    def group_id_for(self, key: str) -> str | None:
        """
        Return the group id that last landed *key*, if any.
        """
        return self._group_ids.get(key)

    def _apply(self, key: str, digest: str, group_id: str) -> None:
        self._digests[key] = digest
        self._group_ids[key] = group_id
