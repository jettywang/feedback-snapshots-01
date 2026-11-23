# SPDX-License-Identifier: MIT

"""
Verification receipts that separate cryptographic success from parsing
evidence and migration-policy decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ._utils import HashFormat, HashInspection, Parameters
from .low_level import Type


class VerificationOutcome(str, Enum):
    """
    Disposition of a verification receipt.

    The values intentionally distinguish three independent failure modes that
    a boolean "did the password match?" answer cannot separate:

    Attributes:
        VERIFIED:
            The password matched an accepted, fully explainable hash.

        FORMAT_NOT_APPLICABLE:
            The text is not an Argon2 hash the running policy accepts, so no
            verification was attempted.

        PARAMETERS_UNINTERPRETABLE:
            The text looks like an Argon2 hash but its parameters could not be
            parsed, or the parsed parameters fall outside the registered
            version window.

        PASSWORD_MISMATCH:
            The hash was accepted and fully parsed, but the supplied secret
            did not match it.

        VERIFICATION_ERROR:
            The low-level Argon2 library refused the hash for a reason other
            than a mismatch (for example a malformed payload it could not
            decode).

    .. versionadded:: 25.2.0
    """

    VERIFIED = "verified"
    FORMAT_NOT_APPLICABLE = "format_not_applicable"
    PARAMETERS_UNINTERPRETABLE = "parameters_uninterpretable"
    PASSWORD_MISMATCH = "password_mismatch"  # noqa: S105
    VERIFICATION_ERROR = "verification_error"


# Human-readable explanations for every outcome.  They deliberately mention
# only structural facts, never passwords, salts, or hash material.
_OUTCOME_REASONS = {
    VerificationOutcome.VERIFIED: "Password matched an accepted hash.",
    VerificationOutcome.FORMAT_NOT_APPLICABLE: (
        "The text is not an Argon2 hash accepted by the active policy; "
        "no verification was attempted."
    ),
    VerificationOutcome.PARAMETERS_UNINTERPRETABLE: (
        "The Argon2 parameters could not be parsed or fall outside the "
        "registered version window."
    ),
    VerificationOutcome.PASSWORD_MISMATCH: (
        "The hash was accepted and parsed, but the supplied secret "
        "did not match."
    ),
    VerificationOutcome.VERIFICATION_ERROR: (
        "The Argon2 library could not process the accepted hash."
    ),
}


@dataclass(frozen=True)
class VerificationPolicy:
    """
    Runtime policy describing which stored records a login service accepts.

    The policy only governs acceptance of stored hash records; it never
    changes how new passwords are hashed.

    Args:
        accepted_versions:
            Argon2 versions allowed on stored records.  Modern hashes state
            their version explicitly; legacy v1.2 records are understood as
            version 18.

        accepted_types:
            Argon2 variants allowed on stored records, or `None` to accept
            every variant the library can verify.

        accepted_formats:
            Hash encodings allowed on stored records.  Defaults to both the
            legacy v1.2 and the modern encoding.

    .. versionadded:: 25.2.0
    """

    accepted_versions: frozenset[int] = frozenset({18, 19})
    accepted_types: frozenset[Type] | None = None
    accepted_formats: frozenset[HashFormat] = frozenset(HashFormat)

    def __post_init__(self) -> None:
        if not self.accepted_versions:
            msg = "accepted_versions must contain at least one version"
            raise ValueError(msg)
        if not self.accepted_formats:
            msg = "accepted_formats must contain at least one format"
            raise ValueError(msg)
        if self.accepted_types is not None:
            object.__setattr__(
                self,
                "accepted_types",
                frozenset(self.accepted_types),
            )

    def accepts(self, inspection: HashInspection) -> bool:
        """
        Return whether the parsed record lies within the policy window.
        """
        params = inspection.parameters
        return (
            params.version in self.accepted_versions
            and inspection.hash_format in self.accepted_formats
            and (
                self.accepted_types is None
                or params.type in self.accepted_types
            )
        )


# Default registration window: both the legacy v1.2 convention (version 18)
# and the current v1.3 records (version 19) are accepted.
DEFAULT_VERIFICATION_POLICY = VerificationPolicy()


@dataclass(frozen=True)
class VerificationReport:
    """
    Structured receipt of a verification attempt.

    A receipt answers three independent questions:

    1. What did the low-level Argon2 verification conclude
       (:attr:`outcome`)?
    2. What could be read from the hash text (:attr:`inspection`,
       :attr:`inferred_parameters`)?
    3. Does the record fit the active migration window and should it be
       rehashed (:attr:`accepted`, :attr:`needs_rehash`)?

    Attributes:
        outcome: Disposition of the attempt.

        reason: Human-readable explanation of *outcome* that never contains
            password, salt, or hash material.

        inspection: Parsing evidence, or `None` if the text could not be
            parsed at all.

        accepted:
            Whether the record lies within the policy's version window.
            `None` when no record could be inspected.

        needs_rehash:
            Whether the record differs from the hasher's current parameters
            and should be rehashed at the next login.  `None` when no record
            could be inspected.

        low_level_error:
            Error message reported by the Argon2 library when verification
            failed for a non-mismatch reason, otherwise `None`.

    .. versionadded:: 25.2.0
    """

    outcome: VerificationOutcome
    reason: str
    inspection: HashInspection | None = None
    accepted: bool | None = None
    needs_rehash: bool | None = None
    low_level_error: str | None = None

    @property
    def parameters(self) -> Parameters | None:
        """
        Parsed parameters, or `None` if the text could not be parsed.
        """
        if self.inspection is None:
            return None
        return self.inspection.parameters

    @property
    def inferred_parameters(self) -> dict[str, int]:
        """
        Parameter values the library assumed per historical convention.
        """
        if self.inspection is None:
            return {}
        return dict(self.inspection.inferred_parameters)

    @property
    def hash_format(self) -> HashFormat | None:
        """
        Encoding generation of the record, or `None` if unparseable.
        """
        if self.inspection is None:
            return None
        return self.inspection.hash_format

    @classmethod
    def _build(
        cls,
        outcome: VerificationOutcome,
        inspection: HashInspection | None,
        *,
        accepted: bool | None = None,
        needs_rehash: bool | None = None,
        low_level_error: str | None = None,
        reason: str | None = None,
    ) -> VerificationReport:
        return cls(
            outcome=outcome,
            reason=reason or _OUTCOME_REASONS[outcome],
            inspection=inspection,
            accepted=accepted,
            needs_rehash=needs_rehash,
            low_level_error=low_level_error,
        )
