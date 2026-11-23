# SPDX-License-Identifier: MIT

import dataclasses

import pytest

from argon2 import (
    DEFAULT_VERIFICATION_POLICY,
    HashFormat,
    PasswordHasher,
    Type,
    VerificationOutcome,
    VerificationPolicy,
    VerificationReport,
    inspect_hash,
)
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from argon2.low_level import hash_secret

from .test_utils import VALID_HASH, VALID_HASH_V18


# A synthetic account with one secret stored in both record generations.
PASSWORD = "synthetic-account-password"  # noqa: S105


@pytest.fixture(scope="module")
def hasher():
    return PasswordHasher(
        time_cost=1,
        memory_cost=8,
        parallelism=1,
        hash_len=16,
        salt_len=16,
        type=Type.ID,
    )


@pytest.fixture(scope="module")
def modern_hash(hasher):
    return hasher.hash(PASSWORD)


@pytest.fixture(scope="module")
def legacy_hash():
    # Real pre-1.3 record: no explicit version field (five $-parts).
    encoded = hash_secret(
        PASSWORD.encode(),
        b"saltsalt",
        time_cost=1,
        memory_cost=8,
        parallelism=1,
        hash_len=16,
        type=Type.I,
        version=16,
    ).decode("ascii")
    return encoded.replace("$v=16", "")


class TestInspectHash:
    def test_modern_record_is_fully_explicit(self):
        inspection = inspect_hash(VALID_HASH)

        assert inspection.hash_format is HashFormat.MODERN
        assert inspection.inferred_parameters == {}

    def test_legacy_record_marks_inferred_version(self):
        inspection = inspect_hash(VALID_HASH_V18)

        assert inspection.hash_format is HashFormat.LEGACY_1_2
        assert inspection.parameters.version == 18
        assert inspection.inferred_parameters == {"version": 18}

    @pytest.mark.parametrize(
        "hash",
        [
            "",
            "tiger",
            "abc" + VALID_HASH,
            VALID_HASH.replace("p=4", "p=four"),
            VALID_HASH.replace(",p=4", ""),
        ],
    )
    def test_uninterpretable_text_raises(self, hash):
        with pytest.raises(InvalidHashError):
            inspect_hash(hash)

    def test_report_contains_no_material(self, modern_hash, legacy_hash):
        report = PasswordHasher().verify_with_report(modern_hash, PASSWORD)

        rendered = repr(report)
        assert PASSWORD not in rendered
        # Neither the salt nor the digest section may leak into the receipt.
        payload = modern_hash.rsplit("$", 2)
        assert payload[1] not in rendered
        assert payload[2] not in rendered

        legacy_report = PasswordHasher().verify_with_report(
            legacy_hash, PASSWORD
        )
        assert PASSWORD not in repr(legacy_report)


class TestVerificationPolicy:
    def test_default_window_covers_both_generations(self):
        assert DEFAULT_VERIFICATION_POLICY.accepted_versions == frozenset(
            {18, 19}
        )
        assert DEFAULT_VERIFICATION_POLICY.accepted_formats == frozenset(
            HashFormat
        )
        assert DEFAULT_VERIFICATION_POLICY.accepted_types is None

    def test_empty_window_is_rejected(self):
        with pytest.raises(ValueError, match="accepted_versions"):
            VerificationPolicy(accepted_versions=frozenset())

    def test_default_formats_cover_both_generations(self):
        policy = VerificationPolicy(accepted_versions=frozenset({19}))

        assert policy.accepted_formats == frozenset(HashFormat)

    def test_empty_format_window_is_rejected(self):
        with pytest.raises(ValueError, match="accepted_formats"):
            VerificationPolicy(accepted_formats=frozenset())

    def test_type_window(self):
        policy = VerificationPolicy(
            accepted_versions=frozenset({19}),
            accepted_types=frozenset({Type.ID}),
        )

        assert policy.accepts(inspect_hash(VALID_HASH))
        assert not policy.accepts(inspect_hash(VALID_HASH_V18))


class TestVerifyWithReport:
    def test_both_generations_verify_under_default_policy(
        self, hasher, modern_hash, legacy_hash
    ):
        for record in (modern_hash, legacy_hash):
            report = hasher.verify_with_report(
                record, PASSWORD, DEFAULT_VERIFICATION_POLICY
            )

            assert report.outcome is VerificationOutcome.VERIFIED
            assert report.accepted is True
            assert report.reason

    def test_legacy_receipt_documents_inference(self, hasher, legacy_hash):
        report = hasher.verify_with_report(legacy_hash, PASSWORD)

        assert report.hash_format is HashFormat.LEGACY_1_2
        assert report.parameters is not None
        assert report.parameters.version == 18
        assert report.inferred_parameters == {"version": 18}
        # The old Argon2i v1.2 record does not match the current Argon2id
        # parameters, so migration is requested despite the match.
        assert report.needs_rehash is True

    def test_modern_receipt_needs_no_rehash(self, hasher, modern_hash):
        report = hasher.verify_with_report(modern_hash, PASSWORD)

        assert report.hash_format is HashFormat.MODERN
        assert report.inferred_parameters == {}
        assert report.needs_rehash is False

    def test_password_mismatch_is_distinct(self, hasher, modern_hash):
        report = hasher.verify_with_report(modern_hash, "wrong password")

        assert report.outcome is VerificationOutcome.PASSWORD_MISMATCH
        assert report.accepted is True
        assert report.inspection is not None

    def test_format_not_applicable_is_distinct(self, hasher):
        report = hasher.verify_with_report("tiger", PASSWORD)

        assert report.outcome is VerificationOutcome.FORMAT_NOT_APPLICABLE
        assert report.inspection is None
        assert report.accepted is None
        assert report.needs_rehash is None

    def test_uninterpretable_parameters_are_distinct(self, hasher):
        broken = VALID_HASH.replace("p=4", "p=four")

        report = hasher.verify_with_report(broken, PASSWORD)

        assert report.outcome is VerificationOutcome.PARAMETERS_UNINTERPRETABLE
        assert report.inspection is None

    def test_tightened_window_rejects_legacy_but_keeps_modern(
        self, hasher, modern_hash, legacy_hash
    ):
        tight = VerificationPolicy(
            accepted_versions=frozenset({19}),
            accepted_formats=frozenset({HashFormat.MODERN}),
        )

        legacy_report = hasher.verify_with_report(legacy_hash, PASSWORD, tight)
        assert (
            legacy_report.outcome
            is VerificationOutcome.PARAMETERS_UNINTERPRETABLE
        )
        assert legacy_report.accepted is False
        # Parsing evidence survives even when the window rejects the record.
        assert legacy_report.hash_format is HashFormat.LEGACY_1_2

        modern_report = hasher.verify_with_report(modern_hash, PASSWORD, tight)
        assert modern_report.outcome is VerificationOutcome.VERIFIED
        assert modern_report.accepted is True

    def test_bytes_hash_and_password(self, hasher, modern_hash):
        report = hasher.verify_with_report(
            modern_hash.encode("ascii"), PASSWORD.encode()
        )

        assert report.outcome is VerificationOutcome.VERIFIED

    def test_low_level_decoding_failure_is_reported_not_raised(self, hasher):
        # Structurally parseable text whose payload the library cannot decode.
        broken = "$argon2id$v=19$m=8,t=1,p=1$!!!not-base64!!!$GpZ3sK"
        assert inspect_hash(broken)  # grammar is fine

        report = hasher.verify_with_report(broken, PASSWORD)

        assert report.outcome is VerificationOutcome.VERIFICATION_ERROR
        assert report.low_level_error is not None

    def test_reports_are_immutable(self, hasher, modern_hash):
        report = hasher.verify_with_report(modern_hash, PASSWORD)

        with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
            report.outcome = VerificationOutcome.PASSWORD_MISMATCH

    def test_report_is_a_verification_report(self, hasher, modern_hash):
        assert isinstance(
            hasher.verify_with_report(modern_hash, PASSWORD),
            VerificationReport,
        )


class TestLowLevelCrossCheck:
    """
    The high-level receipt must agree with low_level.verify_secret whenever
    the low-level call is reachable.
    """

    def test_match_agrees_for_both_generations(
        self, hasher, modern_hash, legacy_hash
    ):
        for record in (modern_hash, legacy_hash):
            report = hasher.verify_with_report(record, PASSWORD)
            low_level = low_verify(record, PASSWORD)

            assert report.outcome is VerificationOutcome.VERIFIED
            assert low_level is True

    def test_mismatch_agrees_for_both_generations(
        self, hasher, modern_hash, legacy_hash
    ):
        for record in (modern_hash, legacy_hash):
            report = hasher.verify_with_report(record, "wrong secret")
            low_level = low_verify(record, "wrong secret")

            assert report.outcome is VerificationOutcome.PASSWORD_MISMATCH
            assert low_level == "mismatch"

    def test_undecodable_payload_agrees(self, hasher):
        broken = "$argon2id$v=19$m=8,t=1,p=1$!!!not-base64!!!$GpZ3sK"

        report = hasher.verify_with_report(broken, PASSWORD)
        low_level = low_verify(broken, PASSWORD)

        assert report.outcome is VerificationOutcome.VERIFICATION_ERROR
        assert low_level == "error"
        assert report.low_level_error is not None

    def test_report_blocks_calls_the_low_level_cannot_reach(
        self, hasher, legacy_hash
    ):
        # The low level has no concept of a policy window: given the bytes it
        # would still verify the legacy record.  The report must reject it
        # first under a tightened policy.
        tight = VerificationPolicy(
            accepted_versions=frozenset({19}),
            accepted_formats=frozenset({HashFormat.MODERN}),
        )

        report = hasher.verify_with_report(legacy_hash, PASSWORD, tight)

        assert report.outcome is VerificationOutcome.PARAMETERS_UNINTERPRETABLE
        assert low_verify(legacy_hash, PASSWORD) is True


def low_verify(record: str, secret: str) -> bool | str:
    """
    Mirror the high-level decision using the low-level binding directly.
    """
    from argon2.low_level import Type as LowType
    from argon2.low_level import verify_secret

    header = {
        b"$argon2i$": LowType.I,
        b"$argon2d$": LowType.D,
        b"$argon2id": LowType.ID,
    }[record[:9].encode("ascii")]
    try:
        return verify_secret(record.encode("ascii"), secret.encode(), header)
    except VerifyMismatchError:
        return "mismatch"
    except VerificationError:
        return "error"


class TestVerifyContractUnchanged:
    def test_verify_still_returns_true(self, hasher, modern_hash):
        assert hasher.verify(modern_hash, PASSWORD) is True

    def test_verify_still_raises_mismatch(self, hasher, modern_hash):
        with pytest.raises(VerifyMismatchError):
            hasher.verify(modern_hash, "wrong password")

    def test_verify_still_raises_invalid_hash(self, hasher):
        with pytest.raises(InvalidHashError):
            hasher.verify("tiger", PASSWORD)

    def test_verify_still_raises_on_undecodable_payload(self, hasher):
        broken = "$argon2id$v=19$m=8,t=1,p=1$!!!not-base64!!!$GpZ3sK"
        with pytest.raises(VerificationError):
            hasher.verify(broken, PASSWORD)
