import argon2


argon2.PasswordHasher.from_parameters(argon2.profiles.RFC_9106_HIGH_MEMORY)
ph = argon2.PasswordHasher()

ph.hash("pw")
ph.hash("pw", salt=b"salt")
ph.hash(b"pw")
ph.hash(b"pw", salt=b"salt")
ph.verify("hash", "pw")
ph.verify(b"hash", "pw")
ph.verify(b"hash", b"pw")
ph.verify("hash", b"pw")

if ph.check_needs_rehash("hash") is True:
    ...

report: argon2.VerificationReport = ph.verify_with_report("hash", "pw")
if report.outcome is argon2.VerificationOutcome.VERIFIED:
    reveal_type(report.outcome)
    reveal_type(report.accepted)
    reveal_type(report.needs_rehash)
    reveal_type(report.inferred_parameters)

inspection: argon2.HashInspection = argon2.inspect_hash("hash")
reveal_type(inspection.hash_format)
reveal_type(inspection.inferred_parameters)

policy: argon2.VerificationPolicy = argon2.VerificationPolicy(
    accepted_versions=frozenset({19}),
    accepted_formats=frozenset({argon2.HashFormat.MODERN}),
)
report = ph.verify_with_report(b"hash", b"pw", policy)

params: argon2.Parameters = argon2.profiles.get_default_parameters()
