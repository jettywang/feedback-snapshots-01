# SPDX-License-Identifier: MIT

from __future__ import annotations


class Argon2Error(Exception):
    """
    Superclass of all argon2 exceptions.

    Never thrown directly.
    """


class VerificationError(Argon2Error):
    """
    Verification failed.

    You can find the original error message from Argon2 in ``args[0]``.
    """


class VerifyMismatchError(VerificationError):
    """
    The secret does not match the hash.

    Subclass of :exc:`argon2.exceptions.VerificationError`.

    .. versionadded:: 16.1.0
    """


class HashingError(Argon2Error):
    """
    Raised if hashing failed.

    You can find the original error message from Argon2 in ``args[0]``.
    """


class KeyMaterialUnavailableError(Argon2Error):
    """
    Key material for a password digest's key generation is unavailable.

    This is distinct from a password mismatch: the digest may be valid, but
    the caller's key provider cannot currently supply the generation that is
    recorded in it.  Never fall back to an unpeppered digest or to another
    generation in this situation.

    Attributes:
        generation: The key generation whose material is missing.

    .. versionadded:: 25.2.0
    """

    generation: int

    def __init__(self, generation: int):
        self.generation = generation
        super().__init__(
            f"No key material is available for key generation {generation}."
        )


class InvalidHashError(ValueError):
    """
    Raised if the hash is invalid before passing it to Argon2.

    .. versionadded:: 23.1.0
       As a replacement for :exc:`argon2.exceptions.InvalidHash`.
    """


class UnsupportedParametersError(ValueError):
    """
    Raised if the current platform does not support the parameters.

    For example, in WebAssembly parallelism must be set to 1.

    .. versionadded:: 25.1.0
    """


InvalidHash = InvalidHashError
"""
Deprecated alias for :class:`InvalidHashError`.

.. versionadded:: 18.2.0
.. deprecated:: 23.1.0
    Use :exc:`argon2.exceptions.InvalidHashError` instead.
"""
