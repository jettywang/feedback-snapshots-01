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

manager = argon2.ProfileManager()
init_result: argon2.VerificationResult = manager.initialize(params)
if init_result.status is argon2.ProfileStatus.VERIFIED:
    active: argon2.Parameters = manager.active_parameters
    switch_result: argon2.VerificationResult = manager.switch_to(active)
    trial_result: argon2.VerificationResult = manager.probe(active)
    if manager.is_verified and switch_result.applied and not trial_result.applied:
        ...
