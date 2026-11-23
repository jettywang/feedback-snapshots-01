# SPDX-License-Identifier: MIT

"""
Runtime management of self-checked Argon2 parameter profiles.

On startup the active Argon2 backend may only support a subset of the
configured parameter profiles.  The classes in this module make the runtime
adopt nothing but a verification plan that has been probed against the
backend in use:

#. A candidate :class:`~argon2.Parameters` profile is probed by running a
   complete hash-and-verify round-trip through the backend.
#. Only a successful probe is promoted to the active, confirmed plan.
#. A failed re-probe leaves the previously confirmed plan untouched and is
   recorded as a failed state instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Protocol, runtime_checkable

from ._utils import Parameters, validate_params_for_platform
from .exceptions import ProfileNotVerifiedError
from .low_level import Type, hash_secret, verify_secret
from .profiles import get_default_parameters


# A fixed probe salt is fine: it never protects a real password.
_PROBE_SALT = b"argon2-runtime-profile-probe-salt"
_PROBE_PASSWORD = b"argon2-runtime-profile-probe-password"


class ProfileStatus(str, Enum):
    """
    Lifecycle states of a runtime verification plan.

    Attributes:
        UNINITIALIZED:
            No profile has been probed yet.

        VERIFIED:
            The active profile passed a backend self-check and is the
            confirmed plan used by the runtime.

        FAILED:
            The last probe failed.  If a plan had been confirmed earlier, it
            stays active and is still used; otherwise there is no active
            plan.
    """

    UNINITIALIZED = "uninitialized"
    VERIFIED = "verified"
    FAILED = "failed"


@dataclass(frozen=True)
class VerificationResult:
    """
    Outcome of probing one candidate profile against a backend.

    The object is immutable so it can be shared safely between threads.

    Attributes:
        parameters: The profile that was probed.

        status: Whether the probe was verified or failed.

        applied:
            Whether the probe replaced the previously active plan.  A failed
            probe is never applied; a successful probe is only applied when it
            targets the plan currently being switched to.

        error:
            The error message of a failed probe, or `None` on success.

        active_parameters:
            The confirmed plan that remains active after the probe, or
            `None` if no plan is confirmed yet.
    """

    __slots__ = (
        "active_parameters",
        "applied",
        "error",
        "parameters",
        "status",
    )

    parameters: Parameters
    status: ProfileStatus
    applied: bool
    error: str | None
    active_parameters: Parameters | None


@runtime_checkable
class BackendCapability(Protocol):
    """
    Backend operations required to self-check a parameter profile.

    The two methods mirror the low-level Argon2 bindings, which makes it
    possible to substitute test doubles for the real backend.
    """

    def hash_secret(
        self,
        secret: bytes,
        salt: bytes,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        hash_len: int,
        type: Type,
    ) -> bytes:
        """
        Hash *secret* and return an encoded hash.
        """

    def verify_secret(
        self, hash: bytes, secret: bytes, type: Type
    ) -> bool:
        """
        Verify *secret* against the encoded *hash*.
        """


class DefaultBackend:
    """
    Backend capability backed by the installed Argon2 CFFI bindings.
    """

    __slots__ = ()

    def hash_secret(
        self,
        secret: bytes,
        salt: bytes,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        hash_len: int,
        type: Type,
    ) -> bytes:
        """
        Hash *secret* through the installed Argon2 bindings.
        """
        return hash_secret(
            secret=secret,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=type,
        )

    def verify_secret(
        self, hash: bytes, secret: bytes, type: Type
    ) -> bool:
        """
        Verify *secret* through the installed Argon2 bindings.
        """
        return verify_secret(hash, secret, type)


class ProfileManager:
    """
    Track and switch the runtime's self-checked verification plan.

    Explicit profiles and the running environment's default profile are both
    supported.  A plan becomes active only after a successful backend
    self-check; a failed check preserves the previously confirmed plan, while
    an in-flight probe only ever touches its own candidate configuration.

    Args:
        backend:
            Backend used for the self-checks.  Defaults to the installed
            Argon2 bindings and may be replaced by a capability double in
            tests.

    .. versionadded:: 26.1.0
    """

    __slots__ = ("_active", "_backend", "_error", "_lock", "_status")

    def __init__(self, backend: BackendCapability | None = None) -> None:
        """
        Start in the uninitialized state, using *backend* for self-checks.
        """
        self._backend: BackendCapability = backend or DefaultBackend()
        self._status = ProfileStatus.UNINITIALIZED
        self._active: Parameters | None = None
        self._error: str | None = None
        self._lock = RLock()

    @property
    def status(self) -> ProfileStatus:
        """
        Current lifecycle state of the runtime plan.
        """
        return self._status

    @property
    def last_error(self) -> str | None:
        """
        Error message of the last failed probe, or `None`.
        """
        return self._error

    @property
    def is_verified(self) -> bool:
        """
        Whether a confirmed plan is currently active.
        """
        return self._status is ProfileStatus.VERIFIED

    @property
    def active_parameters(self) -> Parameters:
        """
        The confirmed plan that the runtime is allowed to use.

        Raises:
            argon2.exceptions.ProfileNotVerifiedError:
                If no profile has been self-checked successfully yet.
        """
        if self._active is None:
            msg = (
                "No Argon2 profile has been verified for the current "
                "backend; call initialize() or switch_to() first."
            )
            raise ProfileNotVerifiedError(msg)

        return self._active

    def initialize(
        self, parameters: Parameters | None = None
    ) -> VerificationResult:
        """
        Probe the initial plan and adopt it if the backend supports it.

        Args:
            parameters:
                Explicit profile to verify.  When `None`, the running
                environment's default profile is selected.

        Returns:
            The result of the self-check.  On failure with no confirmed plan
            in place, the manager enters the failed state without raising.
        """
        candidate = parameters or get_default_parameters()

        return self._probe(candidate, adopt=True, record_state=True)

    def switch_to(self, parameters: Parameters) -> VerificationResult:
        """
        Self-check *parameters* and only then make it the active plan.

        Args:
            parameters: The explicit profile to verify and switch to.

        Returns:
            The result of the self-check.  If the probe fails, the previously
            confirmed plan remains active.
        """
        return self._probe(parameters, adopt=True, record_state=True)

    def probe(self, parameters: Parameters) -> VerificationResult:
        """
        Self-check *parameters* without changing the active plan.

        This lets the runtime evaluate a candidate while requests keep using
        the confirmed plan.

        Args:
            parameters: The candidate profile to verify.

        Returns:
            The result of the self-check.  ``applied`` is always `False` and
            the active plan -- including its status -- is left untouched.
        """
        return self._probe(parameters, adopt=False, record_state=False)

    def _probe(
        self, candidate: Parameters, *, adopt: bool, record_state: bool
    ) -> VerificationResult:
        """
        Run one hash-and-verify self-check for *candidate*.

        *adopt* controls whether a successful probe becomes the active plan
        and *record_state* whether the manager's status/error are updated on
        failure.
        """
        validate_params_for_platform(candidate)

        try:
            encoded = self._backend.hash_secret(
                secret=_PROBE_PASSWORD,
                salt=_PROBE_SALT,
                time_cost=candidate.time_cost,
                memory_cost=candidate.memory_cost,
                parallelism=candidate.parallelism,
                hash_len=candidate.hash_len,
                type=candidate.type,
            )
            self._backend.verify_secret(
                encoded, _PROBE_PASSWORD, candidate.type
            )
        except Exception as exc:  # noqa: BLE001
            error = str(exc) or exc.__class__.__name__
            with self._lock:
                # A failed probe never replaces the confirmed plan.
                if record_state:
                    self._error = error
                    if self._active is None:
                        self._status = ProfileStatus.FAILED

                return VerificationResult(
                    parameters=candidate,
                    status=ProfileStatus.FAILED,
                    applied=False,
                    error=error,
                    active_parameters=self._active,
                )

        with self._lock:
            if adopt:
                self._active = candidate
                self._status = ProfileStatus.VERIFIED
                self._error = None

            return VerificationResult(
                parameters=candidate,
                status=ProfileStatus.VERIFIED,
                applied=adopt,
                error=None,
                active_parameters=self._active,
            )
