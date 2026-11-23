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

params: argon2.Parameters = argon2.profiles.get_default_parameters()

platform = argon2.PlatformCapabilities(name="wasm", max_parallelism=1)
policy = argon2.DigestPolicy(params, platform, version="2026.1")
worker = argon2.PolicyPasswordHasher(policy)

effective: argon2.Parameters = policy.effective_parameters()
decision: argon2.MigrationDecision = policy.evaluate("hash")
action: argon2.DigestDecision = decision.action
if decision.needs_rehash:
    ...

ok: bool
ok, decision = worker.verify_and_plan("hash", "pw")
if ok:
    new_hash: str | None = worker.rehash_if_allowed("hash", "pw")
