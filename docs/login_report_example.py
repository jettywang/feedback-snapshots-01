"""
Login receipt walkthrough for a password library holding two generations of
Argon2 records.

The same synthetic account is stored once as a legacy Argon2 v1.2 record and
once as a modern Argon2id record.  Both are read under the default migration
window, then again after the runtime policy is tightened to current records.

The output deliberately contains no password, no salt, and no full digest:
only structural metadata, parsing evidence, and outcome reasons are printed.
"""

from __future__ import annotations

from argon2 import (
    DEFAULT_VERIFICATION_POLICY,
    HashFormat,
    PasswordHasher,
    VerificationOutcome,
    VerificationPolicy,
)
from argon2.low_level import Type, hash_secret


# Cheap parameters keep the demo fast; they do not appear in the output.
hasher = PasswordHasher(
    time_cost=1,
    memory_cost=8,
    parallelism=1,
    hash_len=16,
    salt_len=16,
    type=Type.ID,
)

ACCOUNT_SECRET = "synthetic-account-secret"


def build_records() -> dict[str, str]:
    modern = hasher.hash(ACCOUNT_SECRET)

    # A historical pre-1.3 record has no explicit version field: five
    # $-separated parts instead of six.
    encoded = hash_secret(
        ACCOUNT_SECRET.encode(),
        b"demo-salt",
        time_cost=1,
        memory_cost=8,
        parallelism=1,
        hash_len=16,
        type=Type.I,
        version=16,
    ).decode("ascii")
    legacy = encoded.replace("$v=16", "")

    return {"legacy v1.2 record": legacy, "modern v1.3 record": modern}


def describe(label: str, report) -> None:
    format_name = (
        report.hash_format.value if report.hash_format else "unparseable"
    )
    inferred = (
        ", ".join(
            f"{name}={value}"
            for name, value in report.inferred_parameters.items()
        )
        or "none (all values read from the record text)"
    )

    print(f"- {label}")
    print(f"    outcome        : {report.outcome.value}")
    print(f"    reason         : {report.reason}")
    print(f"    record format  : {format_name}")
    print(f"    window accepts : {report.accepted}")
    print(f"    needs rehash   : {report.needs_rehash}")
    print(f"    inferred values: {inferred}")


def main() -> None:
    records = build_records()

    print("== Default migration window (legacy v1.2 + modern v1.3) ==")
    for label, record in records.items():
        describe(
            label,
            hasher.verify_with_report(record, ACCOUNT_SECRET),
        )

    tightened = VerificationPolicy(
        accepted_versions=frozenset({19}),
        accepted_formats=frozenset({HashFormat.MODERN}),
    )
    print("\n== Runtime policy replaced: modern v1.3 records only ==")
    for label, record in records.items():
        describe(
            label,
            hasher.verify_with_report(record, ACCOUNT_SECRET, tightened),
        )

    modern = records["modern v1.3 record"]
    print("\n== The three distinct failure reasons ==")

    not_argon2 = hasher.verify_with_report(
        "plain-text-not-an-argon2-record", ACCOUNT_SECRET
    )
    assert not_argon2.outcome is VerificationOutcome.FORMAT_NOT_APPLICABLE
    print(f"1. format not applicable : {not_argon2.reason}")

    unexplainable = hasher.verify_with_report(
        "$argon2id$v=19$m=8,t=1,p=four$c29tZXNhbHQ$GpZ3sK", ACCOUNT_SECRET
    )
    assert (
        unexplainable.outcome is VerificationOutcome.PARAMETERS_UNINTERPRETABLE
    )
    print(f"2. parameters unexplained: {unexplainable.reason}")

    mismatched = hasher.verify_with_report(modern, "a-different-secret")
    assert mismatched.outcome is VerificationOutcome.PASSWORD_MISMATCH
    print(f"3. secret mismatch       : {mismatched.reason}")

    print("\n== Legacy record under the tightened window (re-read) ==")
    describe(
        "legacy v1.2 record",
        hasher.verify_with_report(
            records["legacy v1.2 record"], ACCOUNT_SECRET, tightened
        ),
    )

    print("\n== Cross-check: low-level verify() contract is unchanged ==")
    assert hasher.verify(modern, ACCOUNT_SECRET) is True
    print("verify() still returns True on success and keeps raising its")
    print("original exceptions; verify_with_report() never does.")
    print(f"Default policy in effect: {DEFAULT_VERIFICATION_POLICY!r}")

    print("\n== Cross-check: receipt vs. low-level binding ==")
    for label, record in records.items():
        report = hasher.verify_with_report(record, ACCOUNT_SECRET)
        # The low level knows nothing about policy windows or parsing
        # evidence; it only confirms the cryptographic result.
        low_level_ok = hasher.verify(record, ACCOUNT_SECRET)
        agreement = (
            report.outcome is VerificationOutcome.VERIFIED
            and low_level_ok is True
        )
        print(
            f"- {label}: receipt={report.outcome.value}, "
            f"low-level match={low_level_ok}, agreement={agreement}"
        )


if __name__ == "__main__":
    main()
