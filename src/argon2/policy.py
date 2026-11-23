# SPDX-License-Identifier: MIT

"""
An explicit, versioned policy for moving password hashes between platforms
with different capabilities.

The same password service may run on more than one platform -- for example a
regular server and a WebAssembly (WASM) edge worker.  Both platforms must keep
verifying the hashes they receive from each other, but they do not necessarily
share the same parameter limits (WASM, for instance, only supports
``parallelism=1``).

This module separates three concerns that are otherwise easy to conflate:

* The *target* parameters that the application declares as its goal.
* The *platform capabilities* of the worker that is currently executing.
* The *policy version* that recorded why a hash looks the way it does, so a
  later worker can confirm locally that a migration decision was legitimate.

A :class:`DigestPolicy` never downgrades parameters and never rewrites a hash
that already satisfies its target on the current platform.
"""

from __future__ import annotations

import dataclasses

from enum import Enum

from ._utils import Parameters, extract_parameters
from .exceptions import UnsupportedParametersError


__all__ = [
    "DigestDecision",
    "DigestPolicy",
    "MigrationDecision",
    "PlatformCapabilities",
    "PolicyPasswordHasher",
    "SERVER_PLATFORM",
    "WASM_PLATFORM",
]


class DigestDecision(Enum):
    """
    What a worker should do with a verified password hash.

    Attributes:
        KEEP:
            The hash already satisfies the policy on this platform; it must
            not be rewritten.

        UPGRADE:
            The hash is below the application target and the current platform
            can produce the target parameters; it may be rehashed now.

        DEFER:
            The hash is below the application target, but the current platform
            cannot produce the target parameters.  The record waits for a more
            capable worker instead of being rewritten to weaker parameters.
    """

    KEEP = "keep"
    UPGRADE = "upgrade"
    DEFER = "defer"


@dataclasses.dataclass(frozen=True)
class MigrationDecision:
    """
    The outcome of evaluating one encoded hash against a policy.

    Attributes:
        action: Whether to keep, upgrade, or defer the hash.

        reason:
            A short, stable, human-readable explanation that can be confirmed
            locally without consulting the platform that made the decision.

        current: Parameters extracted from the evaluated hash.

        target: The parameters the application is aiming for.

        policy_version:
            Version of the :class:`DigestPolicy` that produced this decision.
    """

    action: DigestDecision
    reason: str
    current: Parameters
    target: Parameters
    policy_version: str

    @property
    def needs_rehash(self) -> bool:
        """
        Whether the caller should rehash the password right now.
        """
        return self.action is DigestDecision.UPGRADE


@dataclasses.dataclass(frozen=True)
class PlatformCapabilities:
    """
    What a worker platform can do.

    This is a capability *description*, not a live probe: tests and demos can
    substitute synthetic platforms without monkey-patching ``sys.platform``.

    Attributes:
        name: Human-readable platform identifier.

        max_parallelism:
            Maximum ``parallelism`` the platform can hash with.  WebAssembly
            only supports a single thread, so its value is ``1``.

        max_memory_cost:
            Maximum ``memory_cost`` in kibibytes the platform can afford, or
            ``None`` if there is no additional memory limit.
    """

    name: str
    max_parallelism: int = 1
    max_memory_cost: int | None = None

    def supports(self, params: Parameters) -> bool:
        """
        Return whether *params* can be produced on this platform.
        """
        if params.parallelism > self.max_parallelism:
            return False
        if (
            self.max_memory_cost is not None
            and params.memory_cost > self.max_memory_cost
        ):
            return False
        return True

    def validate(self, params: Parameters) -> None:
        """
        Raise :class:`~argon2.exceptions.UnsupportedParametersError` if
        *params* exceed this platform's capabilities.
        """
        if params.parallelism > self.max_parallelism:
            msg = (
                f"Platform '{self.name}' supports parallelism up to "
                f"{self.max_parallelism}, got {params.parallelism}."
            )
            raise UnsupportedParametersError(msg)
        if (
            self.max_memory_cost is not None
            and params.memory_cost > self.max_memory_cost
        ):
            msg = (
                f"Platform '{self.name}' supports memory_cost up to "
                f"{self.max_memory_cost} KiB, got {params.memory_cost} KiB."
            )
            raise UnsupportedParametersError(msg)


#: Capabilities of a regular server process.
SERVER_PLATFORM = PlatformCapabilities(
    name="server", max_parallelism=4, max_memory_cost=None
)

#: Capabilities of a single-threaded WebAssembly worker.
WASM_PLATFORM = PlatformCapabilities(
    name="wasm", max_parallelism=1, max_memory_cost=None
)


class DigestPolicy:
    """
    An explicit, versioned cross-platform digest policy.

    The *target* parameters are declared by the application and stay fixed as
    the service moves between platforms.  Each running process additionally
    reports the :class:`PlatformCapabilities` of its current worker.

    The policy only ever *raises* parameters towards the target.  It never
    downgrades, and a hash that already meets the target is never rewritten --
    even on a less capable platform that could not have produced it.  Such a
    platform still verifies the hash; it simply defers the migration.

    Args:
        target: Parameters the application wants all hashes to reach.

        platform: Capabilities of the currently executing worker.

        version:
            Policy version.  Bump it whenever the target or the decision rules
            change, so historical migration reasons stay auditable locally.

    The *target* is the application's declaration and is accepted as-is even
    when the current platform cannot produce it: that mismatch is exactly what
    turns an upgrade into a DEFER rather than an error at construction time.

    .. versionadded:: 25.2.0
    """

    __slots__ = ["platform", "target", "version"]

    def __init__(
        self,
        target: Parameters,
        platform: PlatformCapabilities,
        version: str = "2026.1",
    ):
        self.target = target
        self.platform = platform
        self.version = version

    def effective_parameters(self) -> Parameters:
        """
        The parameters a new hash gets on *this* platform.

        They equal the application target when the platform supports it, and
        otherwise the strongest parameters the platform can produce without
        changing the target's hash type and output lengths.
        """
        if self.platform.supports(self.target):
            return self.target

        return dataclasses.replace(
            self.target,
            parallelism=min(
                self.target.parallelism, self.platform.max_parallelism
            ),
            memory_cost=(
                min(self.target.memory_cost, self.platform.max_memory_cost)
                if self.platform.max_memory_cost is not None
                else self.target.memory_cost
            ),
        )

    def evaluate(self, hash: str) -> MigrationDecision:
        """
        Decide what should happen to an existing *hash*.

        Verification itself is intentionally not performed here: a decision is
        cheap and side-effect free, while verification requires the cleartext
        password.  Use :meth:`PolicyPasswordHasher.verify_and_plan` for the
        combined login flow.

        Args:
            hash: An encoded Argon2 password hash.

        Returns:
            A :class:`MigrationDecision` whose ``reason`` explains the outcome
            in terms that can be confirmed without the originating platform.
        """
        current = extract_parameters(hash)

        if current == self.target:
            return MigrationDecision(
                DigestDecision.KEEP,
                "hash already matches the application target",
                current,
                self.target,
                self.version,
            )

        if not self._is_below_target(current):
            return MigrationDecision(
                DigestDecision.KEEP,
                "hash differs from the target but is not weaker; "
                "policies never downgrade parameters",
                current,
                self.target,
                self.version,
            )

        if self.platform.supports(self.target):
            return MigrationDecision(
                DigestDecision.UPGRADE,
                "hash is below the target and this platform can produce it",
                current,
                self.target,
                self.version,
            )

        return MigrationDecision(
            DigestDecision.DEFER,
            "hash is below the target but this platform cannot produce the "
            "target parameters; waiting for a more capable worker",
            current,
            self.target,
            self.version,
        )

    def _is_below_target(self, params: Parameters) -> bool:
        """
        Return whether *params* are strictly weaker than the target.

        Every security-relevant dimension must be at least as strong as the
        target for a hash to count as compliant.
        """
        return (
            params.type is not self.target.type
            or params.version < self.target.version
            or params.hash_len < self.target.hash_len
            or params.salt_len < self.target.salt_len
            or params.time_cost < self.target.time_cost
            or params.memory_cost < self.target.memory_cost
            or params.parallelism < self.target.parallelism
        )


class PolicyPasswordHasher:
    """
    A :class:`~argon2.PasswordHasher`-style wrapper driven by a
    :class:`DigestPolicy`.

    New hashes use the policy's :meth:`~DigestPolicy.effective_parameters` for
    the current platform.  Verification works for any Argon2 hash regardless
    of where it was produced, so hashes keep flowing between platforms.

    Args:
        policy: The cross-platform policy to enforce.

        encoding: Encoding used when string passwords are supplied.
    """

    __slots__ = ["_hasher", "policy"]

    def __init__(self, policy: DigestPolicy, encoding: str = "utf-8"):
        from ._password_hasher import PasswordHasher

        effective = policy.effective_parameters()
        self.policy = policy
        self._hasher = PasswordHasher(
            time_cost=effective.time_cost,
            memory_cost=effective.memory_cost,
            parallelism=effective.parallelism,
            hash_len=effective.hash_len,
            salt_len=effective.salt_len,
            encoding=encoding,
            type=effective.type,
        )

    @property
    def encoding(self) -> str:
        return self._hasher.encoding

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        """
        Hash *password* with the current platform's effective parameters.
        """
        return self._hasher.hash(password, salt=salt)

    def verify(self, hash: str | bytes, password: str | bytes) -> bool:
        """
        Verify *password* against *hash* on any platform.

        A hash produced by a more capable platform remains verifiable here;
        platform limits only govern what this worker may *produce*.
        """
        return self._hasher.verify(hash, password)

    def verify_and_plan(
        self, hash: str | bytes, password: str | bytes
    ) -> tuple[bool, MigrationDecision]:
        """
        Verify a login and plan the migration in one step.

        Args:
            hash: The stored encoded hash.

            password: The supplied cleartext password.

        Returns:
            ``(True, decision)`` on success, where *decision* says whether to
            keep, upgrade, or defer the record.  On failure a verification
            exception is raised and no decision is returned.
        """
        self.verify(hash, password)
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        return True, self.policy.evaluate(hash)

    def rehash_if_allowed(
        self, hash: str | bytes, password: str | bytes
    ) -> str | None:
        """
        Return a fresh hash when the policy allows an upgrade, else ``None``.

        DEFER decisions leave the stored record untouched: this platform is
        not the right worker for that migration.
        """
        _, decision = self.verify_and_plan(hash, password)
        if decision.action is DigestDecision.UPGRADE:
            return self.policy_platform_hash(password)
        return None

    def policy_platform_hash(
        self, password: str | bytes, *, salt: bytes | None = None
    ) -> str:
        """
        Hash *password* with the full application target.

        Only call this after the policy has decided on an UPGRADE; it raises
        :class:`~argon2.exceptions.UnsupportedParametersError` on a platform
        that cannot meet the target, which is exactly what turns an intended
        upgrade into a DEFER instead of a silent downgrade.
        """
        from ._password_hasher import PasswordHasher

        target = self.policy.target
        self.policy.platform.validate(target)
        target_hasher = PasswordHasher(
            time_cost=target.time_cost,
            memory_cost=target.memory_cost,
            parallelism=target.parallelism,
            hash_len=target.hash_len,
            salt_len=target.salt_len,
            encoding=self.encoding,
            type=target.type,
        )
        return target_hasher.hash(password, salt=salt)
