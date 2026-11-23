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


class KeyRing(argon2.KeyProvider):
    def current_generation(self) -> int:
        return 1

    def key_for_generation(self, generation: int) -> bytes | None:
        return b"key" if generation == 1 else None


pph = argon2.PepperedPasswordHasher(KeyRing())
pph = argon2.PepperedPasswordHasher(KeyRing(), argon2.PasswordHasher())

peppered = pph.hash("pw")
receipt: argon2.PepperedVerification = pph.verify(peppered, "pw")
status: argon2.PepperStatus = receipt.status
needs_rehash: bool = receipt.needs_rehash
assert status is argon2.PepperStatus.CURRENT or needs_rehash

pph.check_needs_rehash(peppered)
pph.migrate(peppered, "pw")

