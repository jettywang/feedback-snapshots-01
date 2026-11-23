# SPDX-License-Identifier: MIT

import dataclasses

from unittest import mock

import pytest

from argon2 import ProfileManager, ProfileStatus, VerificationResult, profiles
from argon2._runtime import BackendCapability, DefaultBackend
from argon2.exceptions import (
    HashingError,
    ProfileNotVerifiedError,
    UnsupportedParametersError,
    VerifyMismatchError,
)
from argon2.low_level import Type, hash_secret, verify_secret


class WorkingBackend:
    """
    Capability double whose hash/verify round-trips always succeed.

    It delegates to the real low-level bindings but records every probed
    configuration so tests can observe which plan a request used.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

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
        self.calls.append(
            {
                "time_cost": time_cost,
                "memory_cost": memory_cost,
                "parallelism": parallelism,
                "hash_len": hash_len,
                "type": type,
            }
        )

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
        return verify_secret(hash, secret, type)


class FailingBackend:
    """
    Capability double that fails self-checks in a configurable stage.

    ``hash`` fails while producing the hash, ``verify`` produces a hash but
    rejects it during verification, and ``both`` fails either way.
    """

    def __init__(self, stage: str = "hash") -> None:
        if stage not in ("hash", "verify", "both"):
            msg = f"unknown failure stage: {stage!r}"
            raise ValueError(msg)

        self.stage = stage
        self.hash_calls: list[dict[str, object]] = []
        self.verify_calls: list[dict[str, object]] = []

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
        self.hash_calls.append(
            {"memory_cost": memory_cost, "parallelism": parallelism}
        )

        if self.stage in ("hash", "both"):
            raise HashingError("simulated backend outage")

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
        self.verify_calls.append({"type": type})

        if self.stage in ("verify", "both"):
            raise VerifyMismatchError("simulated verification failure")

        return verify_secret(hash, secret, type)


class TestBackendDoubles:
    def test_working_backend_satisfies_capability_protocol(self):
        """
        The working double is a BackendCapability and uses the real backend.
        """
        backend = WorkingBackend()

        assert isinstance(backend, BackendCapability)

        result = ProfileManager(backend).initialize(profiles.CHEAPEST)

        assert result.status is ProfileStatus.VERIFIED
        assert backend.calls[-1]["memory_cost"] == profiles.CHEAPEST.memory_cost

    @pytest.mark.parametrize("stage", ["hash", "verify", "both"])
    def test_failing_backend_reports_a_failed_probe(self, stage):
        """
        Both failing stages turn into a FAILED result with the error kept.
        """
        manager = ProfileManager(FailingBackend(stage=stage))

        result = manager.initialize(profiles.CHEAPEST)

        assert result.status is ProfileStatus.FAILED
        assert result.applied is False
        assert result.error is not None
        assert result.active_parameters is None
        assert manager.status is ProfileStatus.FAILED
        assert manager.is_verified is False

    def test_unknown_failure_stage_is_rejected(self):
        """
        Only the documented failure stages are accepted.
        """
        with pytest.raises(ValueError, match="unknown failure stage"):
            FailingBackend(stage="nope")


class TestProfileManager:
    def test_default_backend_is_the_real_bindings(self):
        """
        Without an explicit double, the manager talks to the CFFI bindings.
        """
        assert isinstance(ProfileManager()._backend, DefaultBackend)

    def test_starts_uninitialized_without_active_plan(self):
        """
        Before the first self-check there is no confirmed plan.
        """
        manager = ProfileManager(WorkingBackend())

        assert manager.status is ProfileStatus.UNINITIALIZED
        assert manager.is_verified is False
        assert manager.last_error is None

        with pytest.raises(ProfileNotVerifiedError, match="No Argon2 profile"):
            manager.active_parameters

    def test_first_initialization_adopts_env_default_profile(self):
        """
        initialize() without arguments verifies the environment default.
        """
        backend = WorkingBackend()
        manager = ProfileManager(backend)

        result = manager.initialize()

        expected = profiles.get_default_parameters()
        assert result.status is ProfileStatus.VERIFIED
        assert result.applied is True
        assert result.error is None
        assert result.parameters == expected
        assert result.active_parameters == expected
        assert manager.status is ProfileStatus.VERIFIED
        assert manager.is_verified is True
        assert manager.active_parameters == expected
        assert manager.last_error is None
        assert backend.calls[-1]["memory_cost"] == expected.memory_cost

    def test_first_initialization_accepts_explicit_profile(self):
        """
        An explicit profile is probed using its own configuration.
        """
        backend = WorkingBackend()
        manager = ProfileManager(backend)

        result = manager.initialize(profiles.CHEAPEST)

        assert result.status is ProfileStatus.VERIFIED
        assert result.applied is True
        assert result.parameters == profiles.CHEAPEST
        assert manager.active_parameters == profiles.CHEAPEST
        assert backend.calls[-1]["parallelism"] == profiles.CHEAPEST.parallelism

    def test_first_initialization_failure_enters_failed_state(self):
        """
        With no prior plan, a failed init leaves the manager in FAILED state.
        """
        manager = ProfileManager(FailingBackend())

        result = manager.initialize(profiles.CHEAPEST)

        assert result.status is ProfileStatus.FAILED
        assert result.applied is False
        assert result.error == "simulated backend outage"
        assert manager.status is ProfileStatus.FAILED
        assert manager.is_verified is False
        with pytest.raises(ProfileNotVerifiedError):
            manager.active_parameters

    def test_failed_switch_keeps_the_confirmed_plan(self):
        """
        A mid-life failed verification preserves the old confirmed plan.
        """
        good_backend = WorkingBackend()
        manager = ProfileManager(good_backend)
        first = manager.initialize(profiles.CHEAPEST)

        assert first.status is ProfileStatus.VERIFIED

        failing_backend = FailingBackend(stage="verify")
        manager._backend = failing_backend
        new_candidate = dataclasses.replace(
            profiles.CHEAPEST, memory_cost=16
        )

        result = manager.switch_to(new_candidate)

        assert result.status is ProfileStatus.FAILED
        assert result.applied is False
        assert result.parameters == new_candidate
        assert result.active_parameters == profiles.CHEAPEST
        # The failed request probed its own candidate configuration.
        assert failing_backend.verify_calls
        # The runtime keeps serving with the old confirmed plan.
        assert manager.status is ProfileStatus.VERIFIED
        assert manager.is_verified is True
        assert manager.active_parameters == profiles.CHEAPEST
        assert manager.last_error == "simulated verification failure"

    def test_approved_switch_promotes_the_new_plan(self):
        """
        A successful re-check swaps the active plan to the new profile.
        """
        manager = ProfileManager(WorkingBackend())
        manager.initialize(profiles.CHEAPEST)

        new_candidate = dataclasses.replace(
            profiles.CHEAPEST, memory_cost=16
        )
        result = manager.switch_to(new_candidate)

        assert result.status is ProfileStatus.VERIFIED
        assert result.applied is True
        assert result.error is None
        assert result.parameters == new_candidate
        assert result.active_parameters == new_candidate
        assert manager.status is ProfileStatus.VERIFIED
        assert manager.active_parameters == new_candidate
        assert manager.last_error is None

    def test_recovery_after_failed_switch(self):
        """
        A later approved switch clears the recorded failure state.
        """
        manager = ProfileManager(WorkingBackend())
        manager.initialize(profiles.CHEAPEST)

        manager._backend = FailingBackend()
        failed = manager.switch_to(
            dataclasses.replace(profiles.CHEAPEST, memory_cost=16)
        )
        assert failed.status is ProfileStatus.FAILED
        assert manager.last_error is not None

        manager._backend = WorkingBackend()
        recovered = manager.switch_to(
            dataclasses.replace(profiles.CHEAPEST, memory_cost=32)
        )

        assert recovered.status is ProfileStatus.VERIFIED
        assert recovered.applied is True
        assert manager.active_parameters.memory_cost == 32
        assert manager.last_error is None

    def test_trial_probe_never_touches_the_active_plan(self):
        """
        probe() evaluates a candidate with its own config but stays read-only.
        """
        backend = WorkingBackend()
        manager = ProfileManager(backend)
        manager.initialize(profiles.CHEAPEST)

        candidate = dataclasses.replace(
            profiles.CHEAPEST, memory_cost=64
        )
        result = manager.probe(candidate)

        assert isinstance(result, VerificationResult)
        assert result.status is ProfileStatus.VERIFIED
        assert result.applied is False
        assert result.parameters == candidate
        assert result.active_parameters == profiles.CHEAPEST
        # The candidate's own configuration reached the backend.
        assert backend.calls[-1]["memory_cost"] == 64
        # The confirmed plan and its status are unchanged.
        assert manager.status is ProfileStatus.VERIFIED
        assert manager.active_parameters == profiles.CHEAPEST

    def test_failed_trial_probe_leaves_state_untouched(self):
        """
        A failing probe() neither records an error nor changes the status.
        """
        manager = ProfileManager(WorkingBackend())
        manager.initialize(profiles.CHEAPEST)

        manager._backend = FailingBackend()
        result = manager.probe(
            dataclasses.replace(profiles.CHEAPEST, memory_cost=64)
        )

        assert result.status is ProfileStatus.FAILED
        assert result.applied is False
        assert manager.status is ProfileStatus.VERIFIED
        assert manager.last_error is None
        assert manager.active_parameters == profiles.CHEAPEST

    def test_failed_trial_probe_before_init_keeps_uninitialized(self):
        """
        A read-only probe on a fresh manager does not flip it to FAILED.
        """
        manager = ProfileManager(FailingBackend())

        result = manager.probe(profiles.CHEAPEST)

        assert result.status is ProfileStatus.FAILED
        assert manager.status is ProfileStatus.UNINITIALIZED
        assert manager.last_error is None

    def test_unsupported_candidate_is_rejected_before_backend_call(self):
        """
        Platform validation runs before the backend is ever touched.
        """
        backend = FailingBackend()
        manager = ProfileManager(backend)
        invalid = dataclasses.replace(profiles.CHEAPEST, parallelism=2)

        with mock.patch("sys.platform", "emscripten"):
            with pytest.raises(
                UnsupportedParametersError,
                match="In WebAssembly environments `parallelism` must be 1",
            ):
                manager.initialize(invalid)

        assert backend.hash_calls == []
        assert manager.status is ProfileStatus.UNINITIALIZED
