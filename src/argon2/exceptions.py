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


class ProfileNotVerifiedError(Argon2Error):
    """
    Raised if no parameter profile has been self-checked successfully.

    The runtime only adopts a verification plan after it has been probed
    against the active backend.  If initialization or a profile switch fails
    and there is no previously confirmed plan to fall back to, the manager is
    in a failed state without any active profile.

    .. versionadded:: 26.1.0
    """


InvalidHash = InvalidHashError
"""
Deprecated alias for :class:`InvalidHashError`.

.. versionadded:: 18.2.0
.. deprecated:: 23.1.0
    Use :exc:`argon2.exceptions.InvalidHashError` instead.
"""
