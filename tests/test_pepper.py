# SPDX-License-Identifier: MIT

import pytest

from argon2 import (
    PasswordHasher,
    PepperedPasswordHasher,
    PepperedVerification,
    PepperStatus,
    profiles,
)
from argon2.exceptions import (
    InvalidHashError,
    KeyMaterialUnavailableError,
    VerifyMismatchError,
)


class MemoryKeyProvider:
    """
    In-memory provider that can hold several generations and hide one.

    Both the keys and all passwords stay inside the test process.
    """

    def __init__(self, keys: dict[int, bytes], current: int):
        self.keys = keys
        self.current = current
        self.unavailable: set[int] = set()
        self.requests: list[int] = []

    def current_generation(self) -> int:
        return self.current

    def key_for_generation(self, generation: int) -> bytes | None:
        self.requests.append(generation)
        if generation in self.unavailable:
            return None
        return self.keys.get(generation)


def make_hasher(provider: MemoryKeyProvider) -> PepperedPasswordHasher:
    return PepperedPasswordHasher(
        provider, PasswordHasher.from_parameters(profiles.CHEAPEST)
    )


TWO_GENERATIONS = {0: b"generation-zero-key", 1: b"generation-one-key"}


class TestPepperedPasswordHasher:
    def test_hash_uses_current_generation_and_standard_argon2_inside(self):
        """
        New digests record the approved generation and contain an ordinary
        Argon2 digest.
        """
        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        ph = make_hasher(provider)

        digest = ph.hash("correct horse")

        assert digest.startswith("$argon2-cffi-pepper$v=1$g=1$")
        assert provider.requests == [1]

        # The inner part is still parseable by the regular API.
        inner = ph._parse(digest)[1]
        assert inner.startswith("$argon2id$")

    def test_roundtrip_current_generation(self):
        """
        A digest created for the current generation verifies without a
        migration receipt.
        """
        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        ph = make_hasher(provider)

        receipt = ph.verify(ph.hash("pw"), "pw")

        assert isinstance(receipt, PepperedVerification)
        assert receipt is not None
        assert receipt.generation == 1
        assert receipt.current_generation == 1
        assert PepperStatus.CURRENT is receipt.status
        assert receipt.needs_rehash is False

    def test_old_digest_still_verifies_after_rotation(self):
        """
        Records issued under the old generation remain verifiable as long as
        the provider still has that generation's key.
        """
        old_provider = MemoryKeyProvider(TWO_GENERATIONS, current=0)
        old_digest = make_hasher(old_provider).hash("pw")

        rotated_provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        receipt = make_hasher(rotated_provider).verify(old_digest, "pw")

        assert receipt.generation == 0
        assert receipt.current_generation == 1
        assert PepperStatus.ROTATED is receipt.status
        assert receipt.needs_rehash is True

    def test_old_digest_cannot_be_verified_with_new_key(self):
        """
        The recorded generation is authoritative; when only the current
        generation's key is available there is no fallback to it.
        """
        old_digest = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=0)
        ).hash("pw")

        only_current = MemoryKeyProvider({1: TWO_GENERATIONS[1]}, current=1)

        with pytest.raises(KeyMaterialUnavailableError):
            make_hasher(only_current).verify(old_digest, "pw")

    def test_missing_old_material_is_distinct_from_mismatch(self):
        """
        Temporarily unavailable old material raises a dedicated error, not a
        password mismatch and not an unpeppered fallback.
        """
        old_digest = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=0)
        ).hash("pw")

        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        provider.unavailable.add(0)
        ph = make_hasher(provider)

        with pytest.raises(KeyMaterialUnavailableError) as exc_info:
            ph.verify(old_digest, "pw")

        assert exc_info.value.generation == 0
        assert provider.requests == [0]

        with pytest.raises(KeyMaterialUnavailableError):
            ph.verify(old_digest, "wrong")

    def test_missing_current_material_prevents_new_registration(self):
        """
        New registrations only use the current generation, so missing current
        material prevents them instead of silently using another generation.
        """
        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        provider.unavailable.add(1)
        ph = make_hasher(provider)

        with pytest.raises(KeyMaterialUnavailableError) as exc_info:
            ph.hash("pw")

        assert exc_info.value.generation == 1
        assert provider.requests == [1]

    def test_wrong_password_raises_mismatch(self):
        """
        A bad password is a verification failure, not a key-material issue.
        """
        ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=1))

        with pytest.raises(VerifyMismatchError):
            ph.verify(ph.hash("pw"), "not-pw")

    def test_migrate_old_digest(self):
        """
        Approved migration verifies with the old generation, then writes only
        the current generation.
        """
        old_digest = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=0)
        ).hash("pw")

        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        ph = make_hasher(provider)

        migrated = ph.migrate(old_digest, "pw")

        assert migrated.startswith("$argon2-cffi-pepper$v=1$g=1$")
        assert migrated != old_digest
        assert provider.requests == [0, 1]

        receipt = ph.verify(migrated, "pw")
        assert PepperStatus.CURRENT is receipt.status
        assert receipt.needs_rehash is False

    def test_migrate_rejects_bad_password_without_writing(self):
        """
        Migration is not a blind rehash: a bad password raises and no new
        digest is produced.
        """
        old_digest = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=0)
        ).hash("pw")
        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        ph = make_hasher(provider)

        with pytest.raises(VerifyMismatchError):
            ph.migrate(old_digest, "wrong")

        assert provider.requests == [0]

    def test_migrate_missing_old_material(self):
        """
        Migration cannot silently skip verification when old material is
        unavailable.
        """
        old_digest = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=0)
        ).hash("pw")
        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        provider.unavailable.add(0)

        with pytest.raises(KeyMaterialUnavailableError):
            make_hasher(provider).migrate(old_digest, "pw")

    def test_migrate_missing_new_material(self):
        """
        Migration cannot write when the approved generation's material is
        unavailable, even if the old digest verified.
        """
        old_digest = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=0)
        ).hash("pw")
        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        provider.unavailable.add(1)

        with pytest.raises(KeyMaterialUnavailableError) as exc_info:
            make_hasher(provider).migrate(old_digest, "pw")

        assert exc_info.value.generation == 1
        assert provider.requests == [0, 1]

    def test_migrate_current_digest_is_noop(self):
        """
        A current digest is returned unchanged.
        """
        ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=1))
        digest = ph.hash("pw")

        assert ph.migrate(digest, "pw") == digest

    def test_future_generation_is_reported(self):
        """
        A digest from a newer generation is reported separately from a
        rotation and is verified with its recorded generation.
        """
        newer_digest = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=1)
        ).hash("pw")

        receipt = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=0)
        ).verify(newer_digest, "pw")

        assert receipt.generation == 1
        assert PepperStatus.FUTURE is receipt.status
        assert receipt.needs_rehash is True

    def test_migrate_refuses_future_generation(self):
        """
        A stale process must not downgrade a digest written by a newer
        generation.
        """
        newer_digest = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=1)
        ).hash("pw")
        ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=0))

        with pytest.raises(ValueError, match="Refusing to migrate"):
            ph.migrate(newer_digest, "pw")

    def test_check_needs_rehash_does_not_need_key_material(self):
        """
        The cheap rehash check inspects the envelope and Argon2 parameters
        without asking for key material.
        """
        old_digest = make_hasher(
            MemoryKeyProvider(TWO_GENERATIONS, current=0)
        ).hash("pw")
        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        provider.unavailable.add(0)

        assert make_hasher(provider).check_needs_rehash(old_digest) is True
        assert provider.requests == []

    def test_parameter_change_requires_rehash(self):
        """
        Argon2 parameter changes are reflected even within one generation.
        """
        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        digest = make_hasher(provider).hash("pw")

        stronger = PepperedPasswordHasher(
            provider, PasswordHasher(time_cost=2, memory_cost=8, parallelism=1)
        )

        receipt = stronger.verify(digest, "pw")
        assert receipt.needs_rehash is True

    def test_bytes_and_str(self):
        """
        Bytes and str work like the regular PasswordHasher and bytes digests
        can be verified.
        """
        ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=1))
        digest = ph.hash("pässword")

        assert ph.verify(digest.encode(), "pässword") is not None
        assert ph.verify(digest, "pässword".encode()) is not None

    def test_custom_salt(self):
        """
        A custom salt is passed through to the inner Argon2 digest.
        """
        ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=1))
        a = ph.hash("pw", salt=b"12345678")
        b = ph.hash("pw", salt=b"12345678")

        assert a == b

    def test_receipt_is_truthy(self):
        """
        Existing call sites that just check truthiness keep working.
        """
        ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=1))

        assert ph.verify(ph.hash("pw"), "pw")

    @pytest.mark.parametrize(
        "digest",
        [
            "",
            "tiger",
            "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQ$abc",
            "$argon2-cffi-pepper$v=1$g=x$YQ",
            "$argon2-cffi-pepper$v=1$g=1$!!!",
            "$argon2-cffi-pepper$v=2$g=1$YQ",
            b"\xff",
        ],
    )
    def test_invalid_digest(self, digest):
        """
        Malformed envelopes raise InvalidHashError instead of leaking parser
        details.
        """
        ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=1))

        with pytest.raises(InvalidHashError):
            ph.verify(digest, "pw")

        with pytest.raises(InvalidHashError):
            ph.check_needs_rehash(digest)

    def test_provider_misuse_is_reported(self):
        """
        Provider return types are validated.
        """
        provider = MemoryKeyProvider({1: b"key"}, current=True)

        with pytest.raises(TypeError):
            make_hasher(provider).hash("pw")

        provider = MemoryKeyProvider({1: "key"}, current=1)  # type: ignore[dict-item]

        with pytest.raises(TypeError):
            make_hasher(provider).hash("pw")

    def test_key_material_is_returned_empty(self):
        """
        An empty key is treated as unavailable, never used silently.
        """
        provider = MemoryKeyProvider({1: b""}, current=1)

        with pytest.raises(KeyMaterialUnavailableError):
            make_hasher(provider).hash("pw")

    def test_digest_does_not_contain_key_material(self):
        """
        The encoded digest only contains the generation, never the key or
        password.
        """
        ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=1))
        digest = ph.hash("unique-password-marker")

        for key in TWO_GENERATIONS.values():
            assert key.decode() not in digest
        assert "unique-password-marker" not in digest

    def test_never_persists_keys(self):
        """
        The hasher holds the provider, not a copy of the keys.
        """
        provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
        ph = make_hasher(provider)

        ph.hash("pw")

        assert not hasattr(ph, "keys")
        assert ph._key_provider is provider

    def test_underlying_hasher_is_exposed_read_only(self):
        """
        The Argon2 configuration is inspectable but not replaceable.
        """
        ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=1))

        assert ph.password_hasher is ph._hasher
        with pytest.raises(AttributeError):
            ph.password_hasher = PasswordHasher()


def test_pepper_and_argon2_are_not_interchangeable():
    """
    An unpeppered Argon2 digest must not be accepted by the peppered API and
    vice versa.
    """
    plain = PasswordHasher.from_parameters(profiles.CHEAPEST)
    ph = make_hasher(MemoryKeyProvider(TWO_GENERATIONS, current=1))

    with pytest.raises(InvalidHashError):
        ph.verify(plain.hash("pw"), "pw")

    with pytest.raises(InvalidHashError):
        plain.verify(ph.hash("pw"), "pw")


def test_key_provider_callback_is_used_per_operation():
    """
    Key material is fetched through the callback on each operation instead of
    being snapshotted at construction time.
    """
    old_digest = make_hasher(
        MemoryKeyProvider(TWO_GENERATIONS, current=0)
    ).hash("pw")
    provider = MemoryKeyProvider(TWO_GENERATIONS, current=0)
    ph = make_hasher(provider)

    provider.current = 1
    receipt = ph.verify(old_digest, "pw")

    assert PepperStatus.ROTATED is receipt.status
    assert provider.requests == [0]


def test_no_caching_between_verifications():
    """
    Each verification asks for the recorded generation's key again.
    """
    provider = MemoryKeyProvider(TWO_GENERATIONS, current=1)
    ph = make_hasher(provider)
    digest = ph.hash("pw")

    ph.verify(digest, "pw")
    ph.verify(digest, "pw")

    assert provider.requests == [1, 1, 1]


def test_mock_hmac_digest_changes_with_generation():
    """
    Generation is bound into the derived Argon2 input, so two generations
    with the same underlying bytes do not produce equivalent derivations.
    """
    provider = MemoryKeyProvider({0: b"same-key", 1: b"same-key"}, current=1)
    ph = make_hasher(provider)

    derived_0 = ph._derive("pw", 0, b"same-key")
    derived_1 = ph._derive("pw", 1, b"same-key")

    assert derived_0 != derived_1
    assert len(derived_0) == 32
