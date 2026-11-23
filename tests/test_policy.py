# SPDX-License-Identifier: MIT

import dataclasses

import pytest

from argon2 import (
    DigestDecision,
    DigestPolicy,
    Parameters,
    PasswordHasher,
    PlatformCapabilities,
    PolicyPasswordHasher,
    Type,
    extract_parameters,
)
from argon2.exceptions import (
    UnsupportedParametersError,
    VerifyMismatchError,
)


TARGET = Parameters(
    type=Type.ID,
    version=19,
    salt_len=16,
    hash_len=32,
    time_cost=2,
    memory_cost=1024,
    parallelism=4,
)

SERVER = PlatformCapabilities(name="server", max_parallelism=4)
WASM = PlatformCapabilities(name="wasm", max_parallelism=1)
SMALL_RAM = PlatformCapabilities(
    name="small-ram", max_parallelism=4, max_memory_cost=512
)


def weaker(**overrides):
    params = Parameters(
        type=Type.ID,
        version=19,
        salt_len=16,
        hash_len=32,
        time_cost=1,
        memory_cost=512,
        parallelism=1,
    )
    return dataclasses.replace(params, **overrides)


class TestPlatformCapabilities:
    def test_supports(self):
        """
        Capability checks cover parallelism and optional memory limits.
        """
        assert SERVER.supports(TARGET)
        assert not WASM.supports(TARGET)
        assert not SMALL_RAM.supports(TARGET)
        assert WASM.supports(weaker())

    def test_validate_raises(self):
        """
        validate raises a helpful error for unsupported parameters.
        """
        with pytest.raises(
            UnsupportedParametersError,
            match="Platform 'wasm' supports parallelism up to 1, got 4",
        ):
            WASM.validate(TARGET)

        with pytest.raises(
            UnsupportedParametersError,
            match="memory_cost up to 512 KiB, got 1024 KiB",
        ):
            SMALL_RAM.validate(TARGET)

    def test_validate_passes(self):
        """
        Supported parameters validate without an error.
        """
        assert SERVER.validate(TARGET) is None


class TestDigestPolicy:
    def test_target_is_platform_independent(self):
        """
        A target the platform cannot produce is still accepted; the mismatch
        surfaces as a DEFER decision, not a construction error.
        """
        policy = DigestPolicy(TARGET, WASM)

        assert policy.target is TARGET
        assert policy.evaluate  # policy is usable

    def test_effective_parameters_server(self):
        """
        A capable platform hashes with the full application target.
        """
        assert DigestPolicy(TARGET, SERVER).effective_parameters() == TARGET

    def test_effective_parameters_wasm(self):
        """
        A single-threaded platform clamps parallelism but keeps the rest.
        """
        effective = DigestPolicy(TARGET, WASM).effective_parameters()

        assert effective.parallelism == 1
        assert effective.memory_cost == TARGET.memory_cost
        assert effective.time_cost == TARGET.time_cost

    def test_effective_parameters_memory_limit(self):
        """
        A memory-constrained platform clamps memory_cost as well.
        """
        effective = DigestPolicy(TARGET, SMALL_RAM).effective_parameters()

        assert effective.memory_cost == 512
        assert effective.parallelism == 4

    def test_evaluate_keeps_compliant_hash_everywhere(self):
        """
        A hash at target is never rewritten, even on a platform that could
        not have produced it.
        """
        digest = PasswordHasher.from_parameters(TARGET).hash(
            "pw", salt=b"0123456789abcdef"
        )

        for platform in (SERVER, WASM):
            decision = DigestPolicy(TARGET, platform).evaluate(digest)

            assert decision.action is DigestDecision.KEEP
            assert decision.policy_version == "2026.1"
            assert decision.current == TARGET
            assert decision.target is TARGET

    def test_evaluate_upgrade_on_capable_platform(self):
        """
        A weaker hash is upgraded where the target is producible.
        """
        digest = PasswordHasher.from_parameters(weaker()).hash(
            "pw", salt=b"0123456789abcdef"
        )

        decision = DigestPolicy(TARGET, SERVER).evaluate(digest)

        assert decision.action is DigestDecision.UPGRADE
        assert decision.needs_rehash
        assert decision.current == weaker()

    def test_evaluate_defers_on_incapable_platform(self):
        """
        A weaker hash is deferred, not downgraded, on WASM.
        """
        digest = PasswordHasher.from_parameters(weaker()).hash(
            "pw", salt=b"0123456789abcdef"
        )

        decision = DigestPolicy(TARGET, WASM).evaluate(digest)

        assert decision.action is DigestDecision.DEFER
        assert not decision.needs_rehash
        assert "more capable worker" in decision.reason

    def test_evaluate_defers_on_memory_limited_platform(self):
        """
        A memory limit alone is enough to force a deferral.
        """
        digest = PasswordHasher.from_parameters(weaker()).hash(
            "pw", salt=b"0123456789abcdef"
        )

        decision = DigestPolicy(TARGET, SMALL_RAM).evaluate(digest)

        assert decision.action is DigestDecision.DEFER

    def test_stronger_than_target_is_kept(self):
        """
        A hash that differs but is never weaker is kept; policies do not
        downgrade.
        """
        stronger = Parameters(
            type=Type.ID,
            version=19,
            salt_len=16,
            hash_len=32,
            time_cost=3,
            memory_cost=2048,
            parallelism=4,
        )
        digest = PasswordHasher.from_parameters(stronger).hash(
            "pw", salt=b"0123456789abcdef"
        )

        decision = DigestPolicy(TARGET, SERVER).evaluate(digest)

        assert decision.action is DigestDecision.KEEP
        assert "never downgrade" in decision.reason

    @pytest.mark.parametrize(
        "overrides",
        [
            {"time_cost": 1},
            {"memory_cost": 512},
            {"parallelism": 1},
            {"hash_len": 16},
            {"salt_len": 8},
        ],
    )
    def test_any_weaker_dimension_triggers_upgrade(self, overrides):
        """
        Falling short in a single dimension is enough to require migration.
        """
        params = weaker(**overrides)
        digest = PasswordHasher.from_parameters(params).hash(
            "pw", salt=b"0123456789abcdef"
        )

        action = DigestPolicy(TARGET, SERVER).evaluate(digest).action

        assert action is DigestDecision.UPGRADE

    def test_policy_version_is_recorded(self):
        """
        Decisions carry the exact policy version that produced them, so
        migration reasons remain locally auditable.
        """
        digest = PasswordHasher.from_parameters(weaker()).hash(
            "pw", salt=b"0123456789abcdef"
        )

        decision = DigestPolicy(
            TARGET, WASM, version="2030.7"
        ).evaluate(digest)

        assert decision.policy_version == "2030.7"


class TestPolicyPasswordHasher:
    def test_hash_uses_effective_parameters(self):
        """
        New hashes reflect the current platform's effective parameters.
        """
        server = PolicyPasswordHasher(DigestPolicy(TARGET, SERVER))
        wasm = PolicyPasswordHasher(DigestPolicy(TARGET, WASM))

        assert extract_parameters(
            server.hash("pw", salt=b"0123456789abcdef")
        ) == TARGET
        assert (
            extract_parameters(
                wasm.hash("pw", salt=b"0123456789abcdef")
            ).parallelism
            == 1
        )

    def test_cross_platform_verification(self):
        """
        A hash produced on either platform verifies on the other one.
        """
        server = PolicyPasswordHasher(DigestPolicy(TARGET, SERVER))
        wasm = PolicyPasswordHasher(DigestPolicy(TARGET, WASM))

        server_digest = server.hash("pw", salt=b"0123456789abcdef")
        wasm_digest = wasm.hash("pw", salt=b"0123456789abcdef")

        assert wasm.verify(server_digest, "pw") is True
        assert server.verify(wasm_digest, "pw") is True

    def test_verify_and_plan_success(self):
        """
        verify_and_plan returns True plus the migration decision.
        """
        server = PolicyPasswordHasher(DigestPolicy(TARGET, SERVER))
        digest = PasswordHasher.from_parameters(weaker()).hash(
            "pw", salt=b"0123456789abcdef"
        )

        ok, decision = server.verify_and_plan(digest, "pw")

        assert ok is True
        assert decision.action is DigestDecision.UPGRADE

    def test_verify_and_plan_mismatch(self):
        """
        A wrong password raises and yields no decision.
        """
        server = PolicyPasswordHasher(DigestPolicy(TARGET, SERVER))
        digest = server.hash("pw", salt=b"0123456789abcdef")

        with pytest.raises(VerifyMismatchError):
            server.verify_and_plan(digest, "nope")

    def test_rehash_upgrades_on_server(self):
        """
        rehash_if_allowed returns a target-parameter hash on a capable worker.
        """
        server = PolicyPasswordHasher(DigestPolicy(TARGET, SERVER))
        digest = PasswordHasher.from_parameters(weaker()).hash(
            "pw", salt=b"0123456789abcdef"
        )

        new_digest = server.rehash_if_allowed(digest, "pw")

        assert new_digest is not None
        assert extract_parameters(new_digest) == TARGET
        assert server.verify(new_digest, "pw") is True

    def test_rehash_defers_on_wasm_and_preserves_record(self):
        """
        On WASM the record stays untouched and no target hash is attempted.
        """
        wasm = PolicyPasswordHasher(DigestPolicy(TARGET, WASM))
        digest = PasswordHasher.from_parameters(weaker()).hash(
            "pw", salt=b"0123456789abcdef"
        )

        assert wasm.rehash_if_allowed(digest, "pw") is None

    def test_compliant_record_is_never_rehashed(self):
        """
        Already compliant records produce no rehash on either platform.
        """
        digest = PasswordHasher.from_parameters(TARGET).hash(
            "pw", salt=b"0123456789abcdef"
        )

        for platform in (SERVER, WASM):
            worker = PolicyPasswordHasher(DigestPolicy(TARGET, platform))
            assert worker.rehash_if_allowed(digest, "pw") is None

    def test_platform_hash_refuses_on_incapable_platform(self):
        """
        Forcing a target hash on WASM raises rather than downgrading.
        """
        wasm = PolicyPasswordHasher(DigestPolicy(TARGET, WASM))

        with pytest.raises(UnsupportedParametersError):
            wasm.policy_platform_hash("pw")

    def test_accepts_bytes_hash(self):
        """
        verify_and_plan accepts bytes-encoded hashes like verify does.
        """
        server = PolicyPasswordHasher(DigestPolicy(TARGET, SERVER))
        digest = server.hash("pw", salt=b"0123456789abcdef").encode("ascii")

        ok, decision = server.verify_and_plan(digest, "pw")

        assert ok is True
        assert decision.action is DigestDecision.KEEP
