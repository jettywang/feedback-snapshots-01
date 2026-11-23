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

limiter = argon2.VerificationLimiter(2)
limited = argon2.PasswordHasher(limiter=limiter)
limited.verify("hash", "pw", wait_timeout=1.0)
limited.verify("hash", "pw", cancel_event=None)
budget: argon2.VerificationBudget = limiter.snapshot()
task: argon2.VerificationTask = limited.start_verify("hash", "pw")
task.wait()
task.result(timeout=1.0)
task.cancel()
