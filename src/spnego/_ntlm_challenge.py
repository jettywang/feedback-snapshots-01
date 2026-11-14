# Copyright: (c) 2026, pyspnego contributors
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Replay-safe NTLMv2 challenge state.

The NTLM acceptor in :mod:`spnego._ntlm` can be used by request handlers that
only see a single token at a time.  A stateless handler creates a new acceptor
for every request, so the CHALLENGE it sends and the AUTHENTICATE it later
receives need to be correlated through a store rather than through instance
attributes.

This module provides the pluggable pieces for that:

* :class:`NTLMClock` with :class:`SystemClock` and :class:`FixedClock`
  implementations.  A fixed clock makes expiry deterministic and avoids tests
  or callers having to sleep.
* :class:`NTLMChallengeStore`, the interface used by the acceptor.
* :class:`InMemoryNTLMChallengeStore`, a thread-safe implementation whose
  transition log can be snapshotted and restored.  Restoring a snapshot
  releases reservations that were in progress when the previous process
  stopped.
* :class:`NTLMChallengeState` and :class:`NTLMChallengeTransition`, immutable
  records of the state and of every transition applied to it.

Expiry is always based on the store's ``issued_at``/``expires_at`` values.  The
timestamp sent in the NTLMv2 client challenge is authenticated data, but it is
never used to extend the lifetime of a server challenge.
"""

import abc
import base64
import dataclasses
import datetime
import enum
import threading
import typing

from spnego.exceptions import (
    NTLMChallengeBusyError,
    NTLMChallengeExpiredError,
    NTLMChallengeMismatchError,
    NTLMChallengeNotFoundError,
    NTLMChallengeReplayError,
)

__all__ = [
    "FixedClock",
    "FixedNTLMClock",
    "InMemoryNTLMChallengeStore",
    "MemoryNTLMChallengeStore",
    "NTLMChallengeState",
    "NTLMChallengeStatus",
    "NTLMChallengeStore",
    "NTLMChallengeTransition",
    "NTLMClock",
    "SystemClock",
    "SystemNTLMClock",
]

_UTC = datetime.timezone.utc


def _to_utc(value: datetime.datetime) -> datetime.datetime:
    """Normalize a datetime to an aware UTC datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=_UTC)
    return value.astimezone(_UTC)


class NTLMChallengeStatus(str, enum.Enum):
    """The lifecycle status of a server challenge."""

    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"
    expired = "expired"


class NTLMClock(typing.Protocol):
    """Clock interface used by the NTLM acceptor and challenge store."""

    def now(self) -> datetime.datetime:
        """Return the current time as a timezone aware datetime."""
        ...  # pragma: no cover


class SystemClock:
    """A clock backed by the system's wall clock in UTC."""

    def now(self) -> datetime.datetime:
        return datetime.datetime.now(_UTC)


class FixedClock:
    """A deterministic clock for tests and simulations.

    Args:
        now: The initial time.  Naive datetimes are treated as UTC.

    The clock does not move on its own.  Call :meth:`advance` or :meth:`set`
    to move it.  This is intentionally the only way time moves when using this
    clock so expiry tests never need to sleep.
    """

    def __init__(self, now: datetime.datetime) -> None:
        self._lock = threading.Lock()
        self._now = _to_utc(now)

    def now(self) -> datetime.datetime:
        with self._lock:
            return self._now

    def set(self, now: datetime.datetime) -> None:
        """Set the current time."""
        with self._lock:
            self._now = _to_utc(now)

    def advance(self, delta: typing.Union[float, int, datetime.timedelta]) -> datetime.datetime:
        """Advance the clock and return the new time."""
        if isinstance(delta, datetime.timedelta):
            offset = delta
        else:
            offset = datetime.timedelta(seconds=float(delta))

        with self._lock:
            self._now += offset
            return self._now


# Convenient names for discoverability.  The shorter names are the documented
# API but the NTLM prefixed aliases avoid collisions for callers that import
# several providers into the same namespace.
SystemNTLMClock = SystemClock
FixedNTLMClock = FixedClock


@dataclasses.dataclass(frozen=True)
class NTLMChallengeState:
    """The server-side state associated with one NTLM CHALLENGE message.

    Attributes:
        challenge_id: Opaque identifier placed in the CHALLENGE TargetInfo and
            echoed by the initiator.  It is what allows a completely new
            acceptor instance to find the original challenge.
        server_challenge: The 8 byte random nonce sent in the CHALLENGE.
        negotiate_message: The exact NEGOTIATE token received by the acceptor.
            It is needed to validate the Authenticate MIC.
        challenge_message: The exact CHALLENGE token sent by the acceptor.
        flags: The flags negotiated in the CHALLENGE.
        target_info: The packed TargetInfo sent in the CHALLENGE.
        issued_at: The time the server issued the challenge.
        expires_at: The time the challenge stops being usable.  This is
            computed once from ``issued_at`` and never changed by retries or
            by the client supplied timestamp.
        status: The current lifecycle status.
        principal: The authenticated identity once status is ``completed``.
        attempts: The number of reservations made for this challenge.
    """

    challenge_id: str
    server_challenge: bytes
    negotiate_message: bytes
    challenge_message: bytes
    flags: int
    target_info: bytes
    issued_at: datetime.datetime
    expires_at: datetime.datetime
    status: NTLMChallengeStatus = NTLMChallengeStatus.pending
    principal: typing.Optional[str] = None
    attempts: int = 0

    @property
    def identifier(self) -> str:
        """Alias for :attr:`challenge_id`."""
        return self.challenge_id

    @property
    def expired(self) -> bool:
        """Whether the stored status is expired."""
        return self.status == NTLMChallengeStatus.expired

    @property
    def consumed(self) -> bool:
        """Whether the challenge was successfully authenticated once."""
        return self.status == NTLMChallengeStatus.completed

    def is_expired(self, now: datetime.datetime) -> bool:
        """Whether the challenge has reached its expiry time."""
        return _to_utc(now) >= self.expires_at

    def remaining(self, now: datetime.datetime) -> datetime.timedelta:
        """The time remaining before expiry, clamped at zero."""
        remaining = self.expires_at - _to_utc(now)
        return remaining if remaining > datetime.timedelta(0) else datetime.timedelta(0)


@dataclasses.dataclass(frozen=True)
class NTLMChallengeTransition:
    """One recorded transition of a challenge state."""

    challenge_id: str
    action: str
    at: datetime.datetime
    previous_status: typing.Optional[NTLMChallengeStatus]
    status: NTLMChallengeStatus
    principal: typing.Optional[str] = None
    detail: typing.Optional[str] = None


class NTLMChallengeStore(abc.ABC):
    """Interface for the replay-safe NTLM challenge state store.

    The acceptor reserves a challenge before it validates the password or
    response.  Reserving is atomic: only one acceptor may hold the reservation
    for a challenge at a time.  The reservation is released if validation
    fails so a legitimate retry can still use the same challenge, but the
    original ``expires_at`` is never moved.  A successful validation calls
    :meth:`complete` and permanently marks the challenge as consumed.
    """

    @abc.abstractmethod
    def issue(self, state: NTLMChallengeState) -> None:
        """Persist a newly issued challenge."""

    @abc.abstractmethod
    def reserve(self, challenge_id: str, *, now: datetime.datetime) -> NTLMChallengeState:
        """Atomically reserve a pending, unexpired challenge.

        Raises:
            NTLMChallengeNotFoundError: No state exists for the identifier.
            NTLMChallengeExpiredError: The challenge is past ``expires_at``.
            NTLMChallengeReplayError: The challenge was already completed.
            NTLMChallengeBusyError: Another acceptor holds the reservation.
        """

    @abc.abstractmethod
    def release(
        self,
        challenge_id: str,
        *,
        now: datetime.datetime,
        principal: typing.Optional[str] = None,
        reason: typing.Optional[str] = None,
    ) -> NTLMChallengeState:
        """Release a reservation after validation failed.

        Releasing only affects the specified challenge.  Other challenges are
        left untouched and keep their original expiry.
        """

    @abc.abstractmethod
    def complete(
        self,
        challenge_id: str,
        *,
        principal: str,
        now: datetime.datetime,
    ) -> NTLMChallengeState:
        """Permanently consume a reserved challenge and record the identity."""

    @abc.abstractmethod
    def reject(
        self,
        challenge_id: str,
        *,
        now: datetime.datetime,
        reason: str,
    ) -> None:
        """Record a rejected attempt without changing the challenge state.

        Used when the acceptor rejects a token before taking a reservation,
        for example because the response is bound to a different challenge.
        """

    @abc.abstractmethod
    def get(
        self,
        challenge_id: str,
        *,
        now: typing.Optional[datetime.datetime] = None,
    ) -> typing.Optional[NTLMChallengeState]:
        """Return a challenge state, optionally expiring it first."""

    @abc.abstractmethod
    def active(self, *, now: datetime.datetime) -> typing.List[NTLMChallengeState]:
        """Return unexpired, incomplete challenges, expiring stale entries."""

    @property
    @abc.abstractmethod
    def transitions(self) -> typing.Tuple[NTLMChallengeTransition, ...]:
        """The recorded state transitions in chronological order."""

    @property
    def history(self) -> typing.Tuple[NTLMChallengeTransition, ...]:
        """Alias for :attr:`transitions`."""
        return self.transitions

    @property
    def states(self) -> typing.Tuple[NTLMChallengeState, ...]:
        """A snapshot of all challenge states currently known to the store."""
        raise NotImplementedError


    def snapshot(self) -> typing.Dict[str, typing.Any]:
        """Return a serializable snapshot of the store."""
        raise NotImplementedError

    @classmethod
    def restore(
        cls,
        snapshot: typing.Dict[str, typing.Any],
        *,
        now: typing.Optional[datetime.datetime] = None,
    ) -> "NTLMChallengeStore":
        """Restore a store from :meth:`snapshot` output.

        Args:
            snapshot: The mapping returned by :meth:`snapshot`.
            now: The time to record for the restore transition.  Defaults to
                the system clock.
        """
        raise NotImplementedError


class InMemoryNTLMChallengeStore(NTLMChallengeStore):
    """Thread-safe in-memory challenge store.

    A single instance can be shared by acceptor instances in different request
    handlers or threads.  The store deliberately holds no reference to an
    acceptor context; all state needed to validate a later AUTHENTICATE token
    is in :class:`NTLMChallengeState`.
    """

    _SCHEMA_VERSION = 1

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._states: typing.Dict[str, NTLMChallengeState] = {}
        self._transitions: typing.List[NTLMChallengeTransition] = []

    @property
    def transitions(self) -> typing.Tuple[NTLMChallengeTransition, ...]:
        with self._lock:
            return tuple(self._transitions)

    @property
    def states(self) -> typing.Tuple[NTLMChallengeState, ...]:
        """A snapshot of all challenge states currently known to the store."""
        with self._lock:
            return tuple(self._states.values())

    def issue(self, state: NTLMChallengeState) -> None:
        if not state.challenge_id:
            raise ValueError("NTLM challenge state must have a challenge_id")

        now = state.issued_at
        with self._lock:
            if state.challenge_id in self._states:
                raise ValueError("NTLM challenge %s has already been issued" % state.challenge_id)

            stored = dataclasses.replace(
                state,
                issued_at=_to_utc(state.issued_at),
                expires_at=_to_utc(state.expires_at),
                status=NTLMChallengeStatus.pending,
                principal=None,
            )
            self._states[stored.challenge_id] = stored
            self._record(stored, "issued", now, None, stored.status)

    def reserve(self, challenge_id: str, *, now: datetime.datetime) -> NTLMChallengeState:
        now = _to_utc(now)
        with self._lock:
            state = self._states.get(challenge_id)
            if state is None:
                raise NTLMChallengeNotFoundError(
                    context_msg="NTLM challenge %s was not found or is no longer active" % challenge_id
                )

            state = self._expire_locked(state, now)

            if state.status == NTLMChallengeStatus.completed:
                self._record(state, "rejected", now, state.status, state.status, detail="already consumed")
                raise NTLMChallengeReplayError(
                    context_msg="NTLM challenge %s has already been consumed" % challenge_id
                )

            if state.status == NTLMChallengeStatus.expired:
                self._record(state, "rejected", now, state.status, state.status, detail="expired")
                raise NTLMChallengeExpiredError(context_msg="NTLM challenge %s has expired" % challenge_id)

            if state.status == NTLMChallengeStatus.in_progress:
                self._record(state, "rejected", now, state.status, state.status, detail="already reserved")
                raise NTLMChallengeBusyError(
                    context_msg="NTLM challenge %s is already being validated" % challenge_id
                )

            reserved = dataclasses.replace(
                state,
                status=NTLMChallengeStatus.in_progress,
                attempts=state.attempts + 1,
            )
            self._states[challenge_id] = reserved
            self._record(reserved, "reserved", now, state.status, reserved.status)
            return reserved

    def release(
        self,
        challenge_id: str,
        *,
        now: datetime.datetime,
        principal: typing.Optional[str] = None,
        reason: typing.Optional[str] = None,
    ) -> NTLMChallengeState:
        now = _to_utc(now)
        with self._lock:
            state = self._states.get(challenge_id)
            if state is None:
                raise NTLMChallengeNotFoundError(
                    context_msg="NTLM challenge %s was not found or is no longer active" % challenge_id
                )

            if state.status != NTLMChallengeStatus.in_progress:
                # A release is only meaningful while a reservation is held.  A
                # completed or expired challenge is never made reusable.
                return state

            released = dataclasses.replace(state, status=NTLMChallengeStatus.pending)
            self._states[challenge_id] = released
            self._record(released, "released", now, state.status, released.status, principal, reason)
            return released

    def complete(
        self,
        challenge_id: str,
        *,
        principal: str,
        now: datetime.datetime,
    ) -> NTLMChallengeState:
        now = _to_utc(now)
        with self._lock:
            state = self._states.get(challenge_id)
            if state is None:
                raise NTLMChallengeNotFoundError(
                    context_msg="NTLM challenge %s was not found or is no longer active" % challenge_id
                )

            if state.status == NTLMChallengeStatus.completed:
                self._record(state, "rejected", now, state.status, state.status, detail="already consumed")
                raise NTLMChallengeReplayError(
                    context_msg="NTLM challenge %s has already been consumed" % challenge_id
                )

            if state.status == NTLMChallengeStatus.expired or state.is_expired(now):
                expired = dataclasses.replace(state, status=NTLMChallengeStatus.expired)
                self._states[challenge_id] = expired
                self._record(expired, "expired", now, state.status, expired.status)
                raise NTLMChallengeExpiredError(context_msg="NTLM challenge %s has expired" % challenge_id)

            if state.status != NTLMChallengeStatus.in_progress:
                raise NTLMChallengeMismatchError(
                    context_msg="NTLM challenge %s was not reserved before completion" % challenge_id
                )

            completed = dataclasses.replace(
                state,
                status=NTLMChallengeStatus.completed,
                principal=principal,
            )
            self._states[challenge_id] = completed
            self._record(completed, "completed", now, state.status, completed.status, principal)
            return completed

    def reject(
        self,
        challenge_id: str,
        *,
        now: datetime.datetime,
        reason: str,
    ) -> None:
        now = _to_utc(now)
        with self._lock:
            state = self._states.get(challenge_id)
            if state is not None:
                self._record(state, "rejected", now, state.status, state.status, detail=reason)

    def get(
        self,
        challenge_id: str,
        *,
        now: typing.Optional[datetime.datetime] = None,
    ) -> typing.Optional[NTLMChallengeState]:
        with self._lock:
            state = self._states.get(challenge_id)
            if state is not None and now is not None:
                state = self._expire_locked(state, _to_utc(now))
            return state

    def active(self, *, now: datetime.datetime) -> typing.List[NTLMChallengeState]:
        now = _to_utc(now)
        with self._lock:
            for challenge_id, state in list(self._states.items()):
                state = self._expire_locked(state, now)
                self._states[challenge_id] = state

            return [
                state
                for state in self._states.values()
                if state.status in (NTLMChallengeStatus.pending, NTLMChallengeStatus.in_progress)
            ]

    def snapshot(self) -> typing.Dict[str, typing.Any]:
        """Return a JSON serializable snapshot of the store."""
        with self._lock:
            states = [self._serialize_state(state) for state in self._states.values()]
            transitions = [self._serialize_transition(transition) for transition in self._transitions]

        return {
            "schema_version": self._SCHEMA_VERSION,
            "states": states,
            "transitions": transitions,
        }

    @classmethod
    def restore(
        cls,
        snapshot: typing.Dict[str, typing.Any],
        *,
        now: typing.Optional[datetime.datetime] = None,
    ) -> "InMemoryNTLMChallengeStore":
        """Rebuild a store from :meth:`snapshot`.

        In-flight reservations cannot belong to the new process, so any state
        that was ``in_progress`` when the snapshot was taken is restored as
        ``pending``.  This is the process recovery path for a request handler
        that was restarted between the CHALLENGE and AUTHENTICATE requests.
        """
        version = snapshot.get("schema_version")
        if version != cls._SCHEMA_VERSION:
            raise ValueError("Unsupported NTLM challenge store snapshot version %r" % (version,))

        store = cls()
        restored_at = _to_utc(now) if now is not None else SystemClock().now()

        with store._lock:
            # Historical transitions first so the restored transitions are
            # appended in chronological order.
            for raw_transition in snapshot.get("transitions", []):
                store._transitions.append(store._deserialize_transition(raw_transition))

            for raw_state in snapshot.get("states", []):
                state = store._deserialize_state(raw_state)
                if state.status == NTLMChallengeStatus.in_progress:
                    restored = dataclasses.replace(state, status=NTLMChallengeStatus.pending)
                    detail = "in-progress reservation released on restore"
                else:
                    restored = state
                    detail = None

                store._states[restored.challenge_id] = restored
                store._record(
                    restored,
                    "restored",
                    restored_at,
                    state.status,
                    restored.status,
                    restored.principal,
                    detail,
                )

        return store

    def _expire_locked(self, state: NTLMChallengeState, now: datetime.datetime) -> NTLMChallengeState:
        if state.status in (NTLMChallengeStatus.pending, NTLMChallengeStatus.in_progress) and state.is_expired(now):
            expired = dataclasses.replace(state, status=NTLMChallengeStatus.expired)
            self._states[state.challenge_id] = expired
            self._record(expired, "expired", now, state.status, expired.status)
            return expired

        return state

    def _record(
        self,
        state: NTLMChallengeState,
        action: str,
        at: datetime.datetime,
        previous_status: typing.Optional[NTLMChallengeStatus],
        status: NTLMChallengeStatus,
        principal: typing.Optional[str] = None,
        detail: typing.Optional[str] = None,
    ) -> None:
        self._transitions.append(
            NTLMChallengeTransition(
                challenge_id=state.challenge_id,
                action=action,
                at=_to_utc(at),
                previous_status=previous_status,
                status=status,
                principal=principal,
                detail=detail,
            )
        )

    @staticmethod
    def _serialize_state(state: NTLMChallengeState) -> typing.Dict[str, typing.Any]:
        return {
            "challenge_id": state.challenge_id,
            "server_challenge": base64.b64encode(state.server_challenge).decode("ascii"),
            "negotiate_message": base64.b64encode(state.negotiate_message).decode("ascii"),
            "challenge_message": base64.b64encode(state.challenge_message).decode("ascii"),
            "flags": state.flags,
            "target_info": base64.b64encode(state.target_info).decode("ascii"),
            "issued_at": state.issued_at.isoformat(),
            "expires_at": state.expires_at.isoformat(),
            "status": state.status.value,
            "principal": state.principal,
            "attempts": state.attempts,
        }

    @staticmethod
    def _deserialize_state(data: typing.Dict[str, typing.Any]) -> NTLMChallengeState:
        return NTLMChallengeState(
            challenge_id=data["challenge_id"],
            server_challenge=base64.b64decode(data["server_challenge"]),
            negotiate_message=base64.b64decode(data["negotiate_message"]),
            challenge_message=base64.b64decode(data["challenge_message"]),
            flags=int(data["flags"]),
            target_info=base64.b64decode(data["target_info"]),
            issued_at=_to_utc(datetime.datetime.fromisoformat(data["issued_at"])),
            expires_at=_to_utc(datetime.datetime.fromisoformat(data["expires_at"])),
            status=NTLMChallengeStatus(data["status"]),
            principal=data.get("principal"),
            attempts=int(data.get("attempts", 0)),
        )

    @staticmethod
    def _serialize_transition(transition: NTLMChallengeTransition) -> typing.Dict[str, typing.Any]:
        return {
            "challenge_id": transition.challenge_id,
            "action": transition.action,
            "at": transition.at.isoformat(),
            "previous_status": transition.previous_status.value if transition.previous_status else None,
            "status": transition.status.value,
            "principal": transition.principal,
            "detail": transition.detail,
        }

    @staticmethod
    def _deserialize_transition(data: typing.Dict[str, typing.Any]) -> NTLMChallengeTransition:
        previous = data.get("previous_status")
        return NTLMChallengeTransition(
            challenge_id=data["challenge_id"],
            action=data["action"],
            at=_to_utc(datetime.datetime.fromisoformat(data["at"])),
            previous_status=NTLMChallengeStatus(previous) if previous else None,
            status=NTLMChallengeStatus(data["status"]),
            principal=data.get("principal"),
            detail=data.get("detail"),
        )


MemoryNTLMChallengeStore = InMemoryNTLMChallengeStore
