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


class VerificationTimeout(Argon2Error, TimeoutError):  # noqa: N818
    """
    Waiting for a verification share or result timed out.

    The verification was not started if the timeout happened while waiting
    for a share.  If it happened while waiting for a result, the backend may
    still be running and keeps holding its share until it finishes.

    .. versionadded:: 25.2.0
    """

    def __init__(
        self,
        message: str = "Timed out waiting for the verification budget.",
    ) -> None:
        super().__init__(message)


class VerificationCancelled(Argon2Error):  # noqa: N818
    """
    A verification was abandoned before its backend started.

    No share of the budget was consumed.

    .. versionadded:: 25.2.0
    """

    def __init__(
        self,
        message: str = (
            "The verification was abandoned before the backend started."
        ),
    ) -> None:
        super().__init__(message)


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
