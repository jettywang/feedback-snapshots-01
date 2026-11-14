"""Run a successful MFA discharge and the attacks the design must stop.

Run with::

    python -m examples.mfa_discharge.demo

The output lists each scenario and the issuer's signed-discharge audit log.
Each scenario uses its own clock, issuer, and business service so the audit
records show exactly which scenarios caused a discharge to be signed.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from pymacaroons import Macaroon

from .auth_service import MfaDischargeService, VerificationReceipt
from .business_service import BusinessService, OperationRequest
from .clock import ManualClock
from .mfa import SimulatedMfaVerifier
from .model import Denied, Operation


@dataclass(frozen=True)
class Step:
    """One observable outcome in the demo."""

    name: str
    outcome: str
    detail: str = ''


@dataclass(frozen=True)
class SignedDischarge:
    """Audit view of one discharge signature produced by an issuer."""

    scenario: str
    challenge_id: str
    user_id: str
    operation_digest: str
    issued_at: int
    expires_at: int
    signature: str


def transfer(amount: str = '250') -> Operation:
    return Operation(
        action='transfer',
        resource='account:alice',
        details=(('amount', amount), ('currency', 'USD')),
    )


class Scenario:
    """Fresh services, plus recording of the discharges they sign."""

    def __init__(self, name: str, signed: List[SignedDischarge]) -> None:
        self.name = name
        self.signed = signed
        self.clock = ManualClock()
        self.mfa = SimulatedMfaVerifier()
        self.auth = MfaDischargeService(clock=self.clock, mfa=self.mfa)
        self.business = BusinessService(
            clock=self.clock, auth_service=self.auth,
        )
        self._proofs: Dict[str, str] = {}
        self._receipts: Dict[str, VerificationReceipt] = {}

    def begin(self, *, user_id: str, operation: Operation,
              ttl_seconds: int = 300) -> OperationRequest:
        request = self.business.begin(
            user_id=user_id,
            operation=operation,
            ttl_seconds=ttl_seconds,
        )
        proof = self.mfa.read_code(user_id, request.challenge_id)
        if proof is not None:
            self._proofs[request.request_id] = proof
        return request

    def complete_mfa(self, request: OperationRequest) -> VerificationReceipt:
        proof = self._proofs.get(request.request_id)
        if proof is None:
            raise Denied('mfa_not_completed', 'no proof was issued')
        receipt = self.auth.verify_mfa(
            challenge_id=request.challenge_id,
            user_id=request.user_id,
            operation=request.operation,
            proof=proof,
        )
        self._receipts[request.request_id] = receipt
        return receipt

    def issue(self, request: OperationRequest, receipt=None):
        receipt = receipt or self._receipts[request.request_id]
        before = len(self.auth.issued_discharges)
        discharge = self.auth.issue_discharge(
            root=request.root,
            receipt=receipt,
        )
        for record in self.auth.issued_discharges[before:]:
            self.signed.append(SignedDischarge(
                scenario=self.name,
                challenge_id=record.challenge_id,
                user_id=record.user_id,
                operation_digest=record.operation_digest,
                issued_at=record.issued_at,
                expires_at=record.expires_at,
                signature=record.signature,
            ))
        return discharge


def _attacker_root(
    *,
    location: str,
    user_id: str,
    operation: Operation,
    expires_at: int,
    challenge_id: str,
    auth_location: str,
) -> Macaroon:
    """Build a root with the right public claims but an attacker key.

    The business service would reject this root on signature, but the issuer
    must also refuse to sign against restrictions that do not match its own
    challenge record.
    """
    root = Macaroon(
        location=location,
        identifier='forged-session',
        key='attacker-root-key',
    )
    root.add_first_party_caveat('user = {}'.format(user_id))
    root.add_first_party_caveat(
        'operation = {}'.format(operation.digest())
    )
    root.add_first_party_caveat('expires = {}'.format(expires_at))
    root.add_third_party_caveat(
        auth_location,
        'attacker-caveat-key',
        challenge_id,
    )
    return root


def _attempt(label: str, action: Callable[[], object],
             steps: List[Step]) -> None:
    try:
        action()
    except Denied as exc:
        steps.append(Step(label, 'denied:{}'.format(exc.reason), exc.detail))
        return
    steps.append(Step(label, 'allowed'))


def run_demo() -> Tuple[List[Step], List[SignedDischarge]]:
    """Return scenario outcomes and every discharge an issuer signed."""
    steps: List[Step] = []
    signed: List[SignedDischarge] = []

    # 1. Success.  The root restricts user and operation, MFA completes, the
    #    issuer signs a discharge, and the business service verifies all of it.
    success = Scenario('success', signed)
    request = success.begin(
        user_id='alice', operation=transfer(), ttl_seconds=120,
    )
    steps.append(Step(
        'challenge_created', 'pending',
        'expires_at={}'.format(request.expires_at),
    ))
    success.complete_mfa(request)
    discharge = success.issue(request)
    approval = success.business.complete(
        request_id=request.request_id, discharge=discharge,
    )
    steps.append(Step(
        'alice_approved', 'allowed',
        '{} by {}'.format(approval.operation.describe(), approval.user_id),
    ))

    # 2. Another user submits the same public challenge identifier, then
    #    relabels alice's receipt as mallory's and redeems it.
    cross_user = Scenario('cross_user', signed)
    victim = cross_user.begin(user_id='alice', operation=transfer('100'))
    _attempt(
        'cross_user_confirmation',
        lambda: cross_user.auth.verify_mfa(
            challenge_id=victim.challenge_id,
            user_id='mallory',
            operation=transfer('100'),
            proof=cross_user._proofs[victim.request_id],
        ),
        steps,
    )
    receipt = cross_user.complete_mfa(victim)
    relabelled = dataclasses.replace(receipt, user_id='mallory')
    mallory_root = _attacker_root(
        location=cross_user.business.location,
        user_id='mallory',
        operation=transfer('100'),
        expires_at=victim.expires_at,
        challenge_id=victim.challenge_id,
        auth_location=cross_user.auth.location,
    )
    _attempt(
        'cross_user_redemption',
        lambda: cross_user.auth.issue_discharge(
            root=mallory_root,
            receipt=relabelled,
        ),
        steps,
    )
    steps.append(Step(
        'issuer_signed_after_cross_user',
        'none' if not cross_user.auth.issued_discharges else 'unexpected',
    ))

    # 3. MFA verifies for one operation; the operation is then changed in
    #    both the root and the receipt before issuance.
    swap = Scenario('operation_swap', signed)
    request = swap.begin(user_id='alice', operation=transfer('100'))
    receipt = swap.complete_mfa(request)
    changed = transfer('900')
    forged_root = _attacker_root(
        location=swap.business.location,
        user_id='alice',
        operation=changed,
        expires_at=request.expires_at,
        challenge_id=request.challenge_id,
        auth_location=swap.auth.location,
    )
    relabelled = dataclasses.replace(
        receipt, operation_digest=changed.digest(),
    )
    _attempt(
        'operation_swapped_after_mfa',
        lambda: swap.auth.issue_discharge(
            root=forged_root,
            receipt=relabelled,
        ),
        steps,
    )

    # 4. Expiry is checked when the discharge is requested, not just when
    #    MFA completed.
    expired = Scenario('expiry', signed)
    request = expired.begin(
        user_id='alice', operation=transfer(), ttl_seconds=120,
    )
    receipt = expired.complete_mfa(request)
    expired.clock.advance(121)
    _attempt(
        'expired_before_issue',
        lambda: expired.auth.issue_discharge(
            root=request.root,
            receipt=receipt,
        ),
        steps,
    )

    # 5. Confirming or redeeming again after consumption cannot mint another
    #    discharge for the same challenge, even with the same receipt.
    replay = Scenario('replay', signed)
    request = replay.begin(user_id='alice', operation=transfer())
    receipt = replay.complete_mfa(request)
    first = replay.issue(request, receipt=receipt)
    replay.business.complete(request_id=request.request_id, discharge=first)
    _attempt(
        'repeat_confirmation_after_issue',
        lambda: replay.complete_mfa(request),
        steps,
    )
    _attempt(
        'repeat_issue_after_issue',
        lambda: replay.auth.issue_discharge(
            root=request.root, receipt=receipt,
        ),
        steps,
    )

    # 6. A discharge issued for request A is replayed against request B.
    #    The business service rejects the mismatch locally.
    biz_replay = Scenario('business_replay', signed)
    request_a = biz_replay.begin(user_id='alice', operation=transfer('10'))
    biz_replay.complete_mfa(request_a)
    discharge_a = biz_replay.issue(request_a)
    biz_replay.business.complete(
        request_id=request_a.request_id, discharge=discharge_a,
    )
    request_b = biz_replay.begin(user_id='alice', operation=transfer('1000'))
    _attempt(
        'cross_operation_replay',
        lambda: biz_replay.business.complete(
            request_id=request_b.request_id, discharge=discharge_a,
        ),
        steps,
    )
    steps.append(Step(
        'issuer_signed_for_replayed_request',
        'none' if not biz_replay.auth.issued_discharges[1:] else 'unexpected',
    ))

    # 7. A signed discharge is edited after issuance; the local signature
    #    check must reject it before policy is considered.
    tamper = Scenario('tamper', signed)
    request = tamper.begin(user_id='alice', operation=transfer())
    tamper.complete_mfa(request)
    discharge = tamper.issue(request)
    discharge.add_first_party_caveat('mfa-user = mallory')
    _attempt(
        'tampered_discharge',
        lambda: tamper.business.complete(
            request_id=request.request_id, discharge=discharge,
        ),
        steps,
    )

    return steps, signed


def main() -> None:
    steps, signed = run_demo()
    width = max(len(step.name) for step in steps)
    for step in steps:
        line = '{:<{width}}  {}'.format(
            step.name, step.outcome, width=width,
        )
        if step.detail:
            line = '{}  # {}'.format(line, step.detail)
        print(line)

    print('\nDischarges actually signed by the issuers: {}'.format(
        len(signed)))
    for record in signed:
        print(
            '- scenario={scenario} challenge={challenge} user={user}\n'
            '  issued_at={issued} expires_at={expires}\n'
            '  operation={operation}\n'
            '  signature={signature}'.format(
                scenario=record.scenario,
                challenge=record.challenge_id,
                user=record.user_id,
                issued=record.issued_at,
                expires=record.expires_at,
                operation=record.operation_digest,
                signature=record.signature,
            )
        )


if __name__ == '__main__':
    main()
