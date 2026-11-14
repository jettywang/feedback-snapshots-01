"""Authentication service that issues MFA discharge macaroons.

Every challenge record ties together four things: the subject, the operation
digest, the expiry instant, and the one-time caveat key used to sign the
discharge.  A caveat identifier is only a lookup key.  It is never treated as
evidence that MFA happened.

The service exposes two separate steps:

* ``verify_mfa`` decides whether this subject completed this challenge and,
  only on success, returns a one-time :class:`VerificationReceipt`.
* ``issue_discharge`` exchanges that receipt, once, for a discharge macaroon.
  It rechecks the operation, subject, expiry, and the restrictions actually
  present in the root macaroon.

Issuance is not authorization.  The business service still verifies the root
signature, the root-to-discharge binding, and every caveat.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Dict, Tuple

from pymacaroons import Macaroon

from .mfa import SimulatedMfaVerifier
from .model import Denied, Operation, new_token


@dataclass(frozen=True)
class ChallengeGrant:
    """Material the business service needs in order to add the caveat."""

    challenge_id: str
    caveat_key: str
    expires_at: int
    operation_digest: str


@dataclass(frozen=True)
class VerificationReceipt:
    """One-time proof that this subject completed this challenge.

    The receipt is returned only from a successful ``verify_mfa`` call.  It is
    bound to the challenge's subject and operation digest, not merely to the
    public challenge identifier.
    """

    token: str
    challenge_id: str
    user_id: str
    operation_digest: str
    expires_at: int


@dataclass(frozen=True)
class IssuedDischarge:
    """Audit record for one discharge macaroon the issuer actually signed."""

    challenge_id: str
    user_id: str
    operation_digest: str
    expires_at: int
    issued_at: int
    identifier: str
    signature: str
    caveats: Tuple[str, ...]


@dataclass
class _Challenge:
    challenge_id: str
    user_id: str
    operation_digest: str
    operation_summary: str
    caveat_key: str
    receipt_token: str
    expires_at: int
    status: str  # pending | verified | consumed | expired


class MfaDischargeService:
    """Issues discharges only after a matching MFA verification."""

    LOCATION = 'mfa.example.test'

    def __init__(
        self,
        *,
        clock,
        mfa: SimulatedMfaVerifier,
        location: str = LOCATION,
    ) -> None:
        self.clock = clock
        self.mfa = mfa
        self.location = location
        self._challenges: Dict[str, _Challenge] = {}
        self._issued: Tuple[IssuedDischarge, ...] = ()

    def start_challenge(
        self,
        *,
        user_id: str,
        operation: Operation,
        ttl_seconds: int = 300,
    ) -> ChallengeGrant:
        """Create a pending challenge and send the proof to ``user_id``."""
        if ttl_seconds <= 0:
            raise ValueError('ttl_seconds must be positive')
        challenge = _Challenge(
            challenge_id=new_token('mfa'),
            user_id=user_id,
            operation_digest=operation.digest(),
            operation_summary=operation.describe(),
            caveat_key=new_token('caveat-key'),
            receipt_token=new_token('receipt'),
            expires_at=self.clock.now() + ttl_seconds,
            status='pending',
        )
        self._challenges[challenge.challenge_id] = challenge
        self.mfa.send_challenge(challenge.challenge_id, user_id)
        return ChallengeGrant(
            challenge_id=challenge.challenge_id,
            caveat_key=challenge.caveat_key,
            expires_at=challenge.expires_at,
            operation_digest=challenge.operation_digest,
        )

    def verify_mfa(
        self,
        *,
        challenge_id: str,
        user_id: str,
        operation: Operation,
        proof: str,
    ) -> VerificationReceipt:
        """Confirm ``user_id`` completed this challenge for ``operation``."""
        challenge = self._require_challenge(challenge_id)
        self._ensure_unexpired(challenge)
        self._ensure_pending(challenge)
        self._ensure_subject(challenge, user_id)
        self._ensure_operation(challenge, operation)

        if not self.mfa.verify(challenge_id, user_id, proof):
            raise Denied('mfa_not_completed')
        challenge.status = 'verified'
        return VerificationReceipt(
            token=challenge.receipt_token,
            challenge_id=challenge.challenge_id,
            user_id=challenge.user_id,
            operation_digest=challenge.operation_digest,
            expires_at=challenge.expires_at,
        )

    def issue_discharge(
        self,
        *,
        root: Macaroon,
        receipt: VerificationReceipt,
    ) -> Macaroon:
        """Exchange a verification receipt, once, for a discharge macaroon."""
        if not isinstance(receipt, VerificationReceipt):
            raise Denied('invalid_receipt')
        challenge = self._require_challenge(receipt.challenge_id)
        if challenge.status == 'consumed':
            raise Denied('challenge_already_consumed')
        if challenge.status == 'expired':
            raise Denied('challenge_expired')
        if challenge.status != 'verified':
            raise Denied('mfa_not_verified')

        self._ensure_unexpired(challenge)
        self._ensure_receipt(challenge, receipt)
        self._ensure_root_binding(root, challenge)

        discharge = Macaroon(
            location=self.location,
            identifier=challenge.challenge_id,
            key=challenge.caveat_key,
        )
        discharge.add_first_party_caveat(
            'mfa-challenge = {}'.format(challenge.challenge_id)
        )
        discharge.add_first_party_caveat(
            'mfa-user = {}'.format(challenge.user_id)
        )
        discharge.add_first_party_caveat(
            'mfa-operation = {}'.format(challenge.operation_digest)
        )
        discharge.add_first_party_caveat(
            'mfa-expires = {}'.format(challenge.expires_at)
        )

        challenge.status = 'consumed'
        self._issued += (IssuedDischarge(
            challenge_id=challenge.challenge_id,
            user_id=challenge.user_id,
            operation_digest=challenge.operation_digest,
            expires_at=challenge.expires_at,
            issued_at=self.clock.now(),
            identifier=discharge.identifier,
            signature=discharge.signature,
            caveats=tuple(
                caveat.caveat_id for caveat in discharge.first_party_caveats()
            ),
        ),)
        return discharge

    @property
    def issued_discharges(self) -> Tuple[IssuedDischarge, ...]:
        """Every discharge this issuer actually signed, in order."""
        return self._issued

    def challenge_status(self, challenge_id: str) -> str:
        return self._require_challenge(challenge_id).status

    # -- internal checks -----------------------------------------------------

    def _require_challenge(self, challenge_id: str) -> _Challenge:
        challenge = self._challenges.get(challenge_id)
        if challenge is None:
            raise Denied('unknown_challenge')
        return challenge

    def _ensure_pending(self, challenge: _Challenge) -> None:
        if challenge.status == 'consumed':
            raise Denied('challenge_already_consumed')
        if challenge.status == 'verified':
            raise Denied('mfa_already_verified')
        if challenge.status == 'expired':
            raise Denied('challenge_expired')

    def _ensure_subject(self, challenge: _Challenge, user_id: str) -> None:
        if challenge.user_id != user_id:
            raise Denied(
                'wrong_subject',
                'challenge belongs to another user',
            )

    def _ensure_operation(
        self, challenge: _Challenge, operation: Operation,
    ) -> None:
        if challenge.operation_digest != operation.digest():
            raise Denied(
                'operation_changed',
                'challenge is bound to a different operation',
            )

    def _ensure_unexpired(self, challenge: _Challenge) -> None:
        if self.clock.now() >= challenge.expires_at:
            challenge.status = 'expired'
            raise Denied('challenge_expired')

    def _ensure_receipt(
        self, challenge: _Challenge, receipt: VerificationReceipt,
    ) -> None:
        """Bind the receipt to this exact challenge record.

        The token is the secret capability.  The accompanying fields are
        checked too, so a caller cannot relabel a valid receipt for another
        subject or operation even if they know the token.
        """
        if not hmac.compare_digest(receipt.token, challenge.receipt_token):
            raise Denied('invalid_receipt')
        if receipt.challenge_id != challenge.challenge_id:
            raise Denied('receipt_challenge_mismatch')
        if receipt.user_id != challenge.user_id:
            raise Denied('wrong_subject')
        if receipt.operation_digest != challenge.operation_digest:
            raise Denied('operation_changed')

    def _ensure_root_binding(
        self, root: Macaroon, challenge: _Challenge,
    ) -> None:
        matches = [
            caveat
            for caveat in root.third_party_caveats()
            if caveat.caveat_id == challenge.challenge_id
        ]
        if len(matches) != 1:
            raise Denied(
                'root_missing_challenge',
                'root does not carry exactly one matching challenge',
            )
        if matches[0].location != self.location:
            raise Denied(
                'caveat_location_mismatch',
                'caveat was not addressed to this service',
            )

        # These first-party values are public; the issuer uses them for
        # binding, while the business service remains responsible for
        # verifying the root signature and enforcing the same restrictions.
        self._require_root_predicate(
            root, 'user', challenge.user_id,
        )
        self._require_root_predicate(
            root, 'operation', challenge.operation_digest,
        )
        self._require_root_predicate(
            root, 'expires', str(challenge.expires_at),
        )

    @staticmethod
    def _require_root_predicate(
        root: Macaroon, name: str, expected: str,
    ) -> None:
        prefix = '{} = '.format(name)
        values = [
            caveat.caveat_id[len(prefix):]
            for caveat in root.first_party_caveats()
            if caveat.caveat_id.startswith(prefix)
        ]
        if len(values) != 1 or values[0] != expected:
            raise Denied(
                'root_restriction_mismatch',
                'root {} restriction does not match the challenge'.format(
                    name),
            )
