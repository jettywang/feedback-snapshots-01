# SPDX-License-Identifier: MIT

"""
Optional high-level password hashing with a key-provider-managed pepper.

The regular :class:`argon2.PasswordHasher` deliberately has no concept of
application secrets: its encoded hashes are self-contained.  This module adds a
separate entry point for applications that want to mix an additional secret
("pepper") into their password digests, while keeping the key material under
the control of the caller.

Key material is never stored by *argon2-cffi*.  Every operation asks the
caller-supplied :class:`KeyProvider` for the key of a specific generation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from ._password_hasher import PasswordHasher, _ensure_bytes
from .exceptions import InvalidHashError, KeyMaterialUnavailableError


_PEPPER_PREFIX = "$argon2-cffi-pepper$v=1$"
_PEPPER_DOMAIN = b"argon2-cffi-pepper-v1\x00"


class KeyProvider(Protocol):
    """
    Caller-held source of pepper keys and generations.

    Implementations usually wrap a KMS, a key ring, or a secrets manager.
    *argon2-cffi* keeps a reference to the provider, but never caches or
    persists the returned key material.

    The provider decides which generation is approved for new writes.  During
    a rotation, it must keep older generations available for verification
    until all records have been migrated.
    """

    def current_generation(self) -> int:
        """
        Return the key generation that is approved for new digests.

        New registrations only ever use this generation.
        """
        ...

    def key_for_generation(self, generation: int) -> bytes | None:
        """
        Return the key material for *generation*.

        Return `None` if the material is currently unavailable.  This is not a
        password mismatch and must not cause a fallback to another generation.
        """
        ...


class PepperStatus(Enum):
    """
    Relationship between a digest's generation and the approved generation.

    .. versionadded:: 25.2.0
    """

    CURRENT = "current"
    """
    The digest was issued with the currently approved generation.
    """

    ROTATED = "rotated"
    """
    The digest uses an older generation and must be migrated after a
    successful verification.
    """

    FUTURE = "future"
    """
    The digest uses a generation that is newer than the currently approved
    one.  This usually means that this process has stale configuration.
    Verification is still attempted with the recorded generation.
    """


@dataclass(frozen=True, slots=True)
class PepperedVerification:
    """
    Receipt returned by :meth:`PepperedPasswordHasher.verify`.

    A returned receipt means the password matched.  Mismatches raise
    :exc:`argon2.exceptions.VerifyMismatchError` as usual.  Missing key
    material raises :exc:`argon2.exceptions.KeyMaterialUnavailableError` and
    therefore never produces a receipt.

    Attributes:
        generation: The generation recorded in the digest.

        current_generation: The generation approved for new digests at
            verification time.

        status: Whether the digest uses the current, an older, or a newer
            generation.

        needs_rehash: `True` if the digest should be migrated -- either
            because its generation differs from the approved one, or because
            its Argon2 parameters changed.

    .. versionadded:: 25.2.0
    """

    generation: int
    current_generation: int
    status: PepperStatus
    needs_rehash: bool

    def __bool__(self) -> bool:
        """
        A receipt only exists for successful verifications.
        """
        return True


class PepperedPasswordHasher:
    r"""
    High-level password hasher with an application-managed pepper.

    This is an optional, separate entry point next to
    :class:`argon2.PasswordHasher`.  It hashes an HMAC-SHA256 of the password
    -- keyed by the pepper generation and domain-separated -- with regular
    Argon2, and wraps the resulting standard Argon2 hash in an envelope that
    records the key generation.

    Because the generation is part of the HMAC input, it is authenticated by
    the digest: changing the ``g=`` label in an envelope makes verification
    fail instead of silently using another generation's key.

    Existing digests are always verified with the generation recorded in
    their envelope.  :meth:`hash` and :meth:`migrate` only write the
    generation that :meth:`KeyProvider.current_generation` has approved.
    Rotating the provider therefore does *not* invalidate old users: they can
    still log in, get a :attr:`PepperStatus.ROTATED` receipt, and be migrated
    explicitly.

    Args:
        key_provider:
            Callback object that supplies keys by generation.  It must
            implement :class:`KeyProvider`.

        password_hasher:
            Optional :class:`argon2.PasswordHasher` that defines the Argon2
            parameters.  If `None`, the defaults are used.

    .. warning::

        If the key material for a digest's generation is lost, the digest
        cannot be verified.  Keep old generations available until all records
        have been migrated.  Never fall back to an unpeppered digest or to a
        different generation.

    .. versionadded:: 25.2.0
    """

    __slots__ = ("_hasher", "_key_provider")

    def __init__(
        self,
        key_provider: KeyProvider,
        password_hasher: PasswordHasher | None = None,
    ):
        self._key_provider = key_provider
        self._hasher = password_hasher or PasswordHasher()

    @property
    def password_hasher(self) -> PasswordHasher:
        """
        The underlying Argon2 hasher (read-only).
        """
        return self._hasher

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        """
        Hash *password* into a new digest for the current generation.

        Args:
            password: Password to hash.

            salt:
                If None, a random salt is securely created.

                .. danger::

                    You should **not** pass a salt unless you really know what
                    you are doing.

        Raises:
            argon2.exceptions.KeyMaterialUnavailableError:
                If the current generation's key material is unavailable.

            argon2.exceptions.HashingError:
                If hashing fails.

        Returns:
            A peppered, encoded digest that records its key generation.

        .. versionadded:: 25.2.0
        """
        generation = self._current_generation()
        key = self._key_for(generation)

        inner = self._hasher.hash(
            self._derive(password, generation, key), salt=salt
        )

        return (
            f"{_PEPPER_PREFIX}g={generation}$"
            f"{base64.b64encode(inner.encode('ascii')).decode('ascii')}"
        )

    def verify(
        self, hash: str | bytes, password: str | bytes
    ) -> PepperedVerification:
        """
        Verify *password* against a peppered *hash*.

        The key generation is read from the digest; the current approved
        generation is only used to classify the receipt.  No fallback to a
        different generation happens.

        Args:
            hash: A digest as returned by :meth:`hash`.

            password: The password to verify.

        Raises:
            argon2.exceptions.KeyMaterialUnavailableError:
                If the recorded generation's key material is unavailable.

            argon2.exceptions.VerifyMismatchError:
                If the password does not match.

            argon2.exceptions.InvalidHashError:
                If *hash* is not a valid peppered digest.

        Returns:
            A receipt describing whether the digest is current, older, or
            newer than the approved generation.

        .. versionadded:: 25.2.0
        """
        generation, inner = self._parse(hash)
        current_generation = self._current_generation()
        key = self._key_for(generation)

        self._hasher.verify(inner, self._derive(password, generation, key))

        if generation == current_generation:
            status = PepperStatus.CURRENT
        elif generation < current_generation:
            status = PepperStatus.ROTATED
        else:
            status = PepperStatus.FUTURE

        return PepperedVerification(
            generation=generation,
            current_generation=current_generation,
            status=status,
            needs_rehash=(
                generation != current_generation
                or self._hasher.check_needs_rehash(inner)
            ),
        )

    def check_needs_rehash(self, hash: str | bytes) -> bool:
        """
        Check whether *hash* should be migrated to the current generation.

        This does not need the recorded generation's key material.

        Args:
            hash: A digest as returned by :meth:`hash`.

        Returns:
            Whether *hash* uses another generation or different Argon2
            parameters than the current ones.

        Raises:
            argon2.exceptions.InvalidHashError:
                If *hash* is not a valid peppered digest.

        .. versionadded:: 25.2.0
        """
        generation, inner = self._parse(hash)

        return (
            generation != self._current_generation()
            or self._hasher.check_needs_rehash(inner)
        )

    def migrate(
        self,
        hash: str | bytes,
        password: str | bytes,
        *,
        salt: bytes | None = None,
    ) -> str:
        """
        Migrate *hash* to the current generation after verifying *password*.

        This is the explicit "approved migration" step: nothing is written
        unless the old digest verifies successfully.  Callers normally invoke
        it after a login when :attr:`PepperedVerification.needs_rehash` is
        `True`.

        If the digest is already current and its Argon2 parameters match, the
        original digest is returned unchanged.

        Digests from a newer generation are refused: a process with stale
        configuration must not downgrade a record written by a newer one.

        Args:
            hash: The existing digest.

            password: The password that was just verified.

            salt:
                Optional salt for the replacement digest.

        Raises:
            argon2.exceptions.KeyMaterialUnavailableError:
                If the old or the current generation's key material is
                unavailable.

            argon2.exceptions.VerifyMismatchError:
                If *password* does not match *hash*.

            argon2.exceptions.InvalidHashError:
                If *hash* is not a valid peppered digest.

            ValueError:
                If *hash* uses a newer generation than the approved one.

        Returns:
            A digest for the current generation.

        .. versionadded:: 25.2.0
        """
        receipt = self.verify(hash, password)

        if PepperStatus.FUTURE is receipt.status:
            msg = (
                "Refusing to migrate a digest from key generation "
                f"{receipt.generation}; the approved generation is only "
                f"{receipt.current_generation}."
            )
            raise ValueError(msg)

        if not receipt.needs_rehash:
            if isinstance(hash, bytes):
                return hash.decode("ascii")
            return hash

        return self.hash(password, salt=salt)

    def _current_generation(self) -> int:
        generation = self._key_provider.current_generation()

        if isinstance(generation, bool) or not isinstance(generation, int):
            msg = "'current_generation' must be an int"
            raise TypeError(msg)

        if generation < 0:
            msg = "'current_generation' must not be negative"
            raise ValueError(msg)

        return generation

    def _key_for(self, generation: int) -> bytes:
        key = self._key_provider.key_for_generation(generation)

        if key is None:
            raise KeyMaterialUnavailableError(generation)

        if not isinstance(key, bytes | bytearray | memoryview):
            msg = "'key_for_generation' must return bytes or None"
            raise TypeError(msg)

        key = bytes(key)

        if not key:
            raise KeyMaterialUnavailableError(generation)

        return key

    def _derive(
        self, password: str | bytes, generation: int, key: bytes
    ) -> bytes:
        material = _ensure_bytes(password, self._hasher.encoding)
        message = (
            _PEPPER_DOMAIN
            + str(generation).encode("ascii")
            + b"\x00"
            + material
        )

        return hmac.new(key, message, hashlib.sha256).digest()

    @staticmethod
    def _parse(hash: str | bytes) -> tuple[int, str]:
        if isinstance(hash, bytes):
            try:
                hash = hash.decode("ascii")
            except UnicodeDecodeError:
                raise InvalidHashError from None

        parts = hash.split("$")

        if (
            len(parts) != 5
            or parts[0] != ""
            or parts[1] != "argon2-cffi-pepper"
            or parts[2] != "v=1"
            or not parts[3].startswith("g=")
        ):
            raise InvalidHashError

        generation_text = parts[3][2:]
        if not generation_text.isascii() or not generation_text.isdigit():
            raise InvalidHashError

        try:
            generation = int(generation_text)
            inner = base64.b64decode(parts[4], validate=True).decode("ascii")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            raise InvalidHashError from None

        if generation < 0:
            raise InvalidHashError

        return generation, inner
