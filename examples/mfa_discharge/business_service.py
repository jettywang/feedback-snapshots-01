"""Business service that creates and enforces MFA-limited macaroons.

The business service is the relying party.  It owns the root signing key,
creates the restrictions, and verifies the root binding and every caveat
itself.  It never treats a call to the authentication service as a substitute
for local verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict

from pymacaroons import Macaroon, Verifier
from pymacaroons.exceptions import (
    MacaroonInvalidSignatureException,
    MacaroonUnmetCaveatException,
)

from .auth_service import MfaDischargeService
from .model import Denied, Operation, new_token


@dataclass(frozen=True)
class OperationRequest:
    """Handle returned when a sensitive operation starts."""

    request_id: str
    user_id: str
    operation: Operation
    challenge_id: str
    expires_at: int
    root: Macaroon


@dataclass(frozen=True)
class Approval:
    """Result of successful business-side verification."""

    request_id: str
    user_id: str
    operation: Operation
    challenge_id: str
    approved_at: int


@dataclass
class _PendingRequest:
    request: OperationRequest
    status: str = 'pending'  # pending | approved


class BusinessService:
    """Owns root macaroons and validates all restrictions locally."""

    LOCATION = 'business.example.test'
    ROOT_KEY = 'business-root-signing-key-not-for-production'

    def __init__(
        self,
        *,
        clock,
        auth_service: MfaDischargeService,
        location: str = LOCATION,
    ) -> None:
        self.clock = clock
        self.auth_service = auth_service
        self.location = location
        self._pending: Dict[str, _PendingRequest] = {}

    def begin(
        self,
        *,
        user_id: str,
        operation: Operation,
        ttl_seconds: int = 300,
    ) -> OperationRequest:
        """Create a root macaroon demanding MFA discharge for ``operation``."""
        grant = self.auth_service.start_challenge(
            user_id=user_id,
            operation=operation,
            ttl_seconds=ttl_seconds,
        )
        root = Macaroon(
            location=self.location,
            identifier='session:{}'.format(new_token('session')),
            key=self.ROOT_KEY,
        )
        root.add_first_party_caveat('user = {}'.format(user_id))
        root.add_first_party_caveat(
            'operation = {}'.format(operation.digest())
        )
        root.add_first_party_caveat(
            'expires = {}'.format(grant.expires_at)
        )
        root.add_third_party_caveat(
            self.auth_service.location,
            grant.caveat_key,
            grant.challenge_id,
        )
        request = OperationRequest(
            request_id=new_token('request'),
            user_id=user_id,
            operation=operation,
            challenge_id=grant.challenge_id,
            expires_at=grant.expires_at,
            root=root,
        )
        self._pending[request.request_id] = _PendingRequest(request=request)
        return request

    def complete(
        self, *, request_id: str, discharge: Macaroon,
    ) -> Approval:
        """Bind a discharge to the stored root and verify all restrictions.

        The caller supplies only the request handle and the discharge.  The
        user, operation, root macaroon, and expiry come from this service's
        own pending record, so a caller cannot re-aim an existing discharge.
        """
        pending = self._pending.get(request_id)
        if pending is None:
            raise Denied('unknown_request')
        if pending.status != 'pending':
            raise Denied('request_already_completed')

        request = pending.request
        if self.clock.now() >= request.expires_at:
            raise Denied('request_expired')
        if discharge.identifier != request.challenge_id:
            raise Denied(
                'discharge_challenge_mismatch',
                'discharge does not answer this request',
            )
        self._check_root_caveats(request)
        self.authorize(
            root=request.root,
            discharge=discharge,
            user_id=request.user_id,
            operation=request.operation,
            challenge_id=request.challenge_id,
        )
        pending.status = 'approved'
        return Approval(
            request_id=request.request_id,
            user_id=request.user_id,
            operation=request.operation,
            challenge_id=request.challenge_id,
            approved_at=self.clock.now(),
        )

    def authorize(
        self,
        *,
        root: Macaroon,
        discharge: Macaroon,
        user_id: str,
        operation: Operation,
        challenge_id: str,
    ) -> bool:
        """Verify the root binding and every restriction on both macaroons.

        ``root.prepare_for_request`` binds the discharge to this exact root
        signature.  First-party caveats are then checked against facts the
        business service knows independently: the authenticated user, the
        canonical operation digest, the challenge identifier, and the clock.
        """
        protected = root.prepare_for_request(discharge)
        verifier = Verifier(discharge_macaroons=[protected])
        verifier.satisfy_exact('user = {}'.format(user_id))
        verifier.satisfy_exact('operation = {}'.format(operation.digest()))
        verifier.satisfy_general(
            self._context_predicates(user_id, operation, challenge_id)
        )

        try:
            verifier.verify(root, self.ROOT_KEY)
        except MacaroonInvalidSignatureException:
            raise Denied(
                'invalid_signature',
                'root or discharge binding did not verify',
            )
        except MacaroonUnmetCaveatException:
            raise Denied(
                'unmet_caveat',
                'a macaroon restriction was not satisfied',
            )
        return True

    # -- internal checks -----------------------------------------------------

    def _check_root_caveats(self, request: OperationRequest) -> None:
        third_party = request.root.third_party_caveats()
        if len(third_party) != 1:
            raise Denied(
                'root_caveat_mismatch',
                'root must carry exactly one MFA caveat',
            )
        caveat = third_party[0]
        if caveat.caveat_id != request.challenge_id:
            raise Denied('root_caveat_mismatch')
        if caveat.location != self.auth_service.location:
            raise Denied('root_caveat_mismatch')

    def _context_predicates(
        self, user_id: str, operation: Operation, challenge_id: str,
    ) -> Callable[[str], bool]:
        operation_digest = operation.digest()

        def check(predicate: str) -> bool:
            if predicate.startswith('expires = '):
                return self._before_expiry(predicate)
            if predicate == 'mfa-user = {}'.format(user_id):
                return True
            if predicate == 'mfa-operation = {}'.format(operation_digest):
                return True
            if predicate == 'mfa-challenge = {}'.format(challenge_id):
                return True
            if predicate.startswith('mfa-expires = '):
                return self._before_expiry(predicate)
            return False

        return check

    def _before_expiry(self, predicate: str) -> bool:
        _, value = predicate.rsplit('= ', 1)
        try:
            expires_at = int(value)
        except ValueError:
            return False
        return self.clock.now() < expires_at
