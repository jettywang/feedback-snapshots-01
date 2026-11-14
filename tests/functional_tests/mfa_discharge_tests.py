"""Tests for the local MFA discharge example.

The example lives in ``examples/mfa_discharge`` because it is a protocol
walkthrough, not a library feature.  These tests pin the properties the
walkthrough claims:

* only a completed, matching MFA verification yields a discharge;
* the receipt, subject, operation, challenge, and expiry are all bound;
* the business service still verifies the root signature and every caveat;
* a discharge is signed exactly once per challenge.
"""

import pytest

from pymacaroons import Macaroon

from examples.mfa_discharge import (
    BusinessService,
    Denied,
    ManualClock,
    MfaDischargeService,
    Operation,
    SimulatedMfaVerifier,
)


def _operation(amount='100'):
    return Operation(
        action='transfer',
        resource='account:alice',
        details=(('amount', amount), ('currency', 'USD')),
    )


class Harness(object):
    def __init__(self, ttl_seconds=300):
        self.clock = ManualClock()
        self.mfa = SimulatedMfaVerifier()
        self.auth = MfaDischargeService(clock=self.clock, mfa=self.mfa)
        self.business = BusinessService(
            clock=self.clock, auth_service=self.auth,
        )
        self.ttl_seconds = ttl_seconds
        self.proofs = {}

    def begin(self, user_id='alice', operation=None):
        operation = operation or _operation()
        request = self.business.begin(
            user_id=user_id,
            operation=operation,
            ttl_seconds=self.ttl_seconds,
        )
        self.proofs[request.request_id] = self.mfa.read_code(
            user_id, request.challenge_id,
        )
        return request

    def complete_mfa(self, request, user_id=None):
        return self.auth.verify_mfa(
            challenge_id=request.challenge_id,
            user_id=user_id or request.user_id,
            operation=request.operation,
            proof=self.proofs[request.request_id],
        )

    def issue(self, request):
        receipt = self.complete_mfa(request)
        return self.auth.issue_discharge(
            root=request.root, receipt=receipt,
        )

    def approve(self, request):
        discharge = self.issue(request)
        return self.business.complete(
            request_id=request.request_id, discharge=discharge,
        )


def _forged_root(*, auth_location, challenge_id, expires_at,
                 user_id='alice', operation=None):
    operation = operation or _operation()
    root = Macaroon(
        location='business.example.test',
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


def test_successful_discharge_and_business_verification():
    harness = Harness()
    request = harness.begin()
    approval = harness.approve(request)

    assert approval.request_id == request.request_id
    assert approval.user_id == 'alice'
    assert approval.operation == request.operation
    assert approval.challenge_id == request.challenge_id
    assert len(harness.auth.issued_discharges) == 1
    record = harness.auth.issued_discharges[0]
    assert record.challenge_id == request.challenge_id
    assert record.user_id == 'alice'
    assert record.operation_digest == request.operation.digest()
    assert record.expires_at == request.expires_at


def test_receipt_from_another_challenge_is_rejected():
    harness = Harness()
    other = harness.begin(user_id='bob')
    other_receipt = harness.complete_mfa(other)
    request = harness.begin()

    with pytest.raises(Denied) as denied:
        harness.auth.issue_discharge(
            root=request.root,
            receipt=other_receipt,
        )
    assert denied.value.reason in (
        'invalid_receipt', 'root_missing_challenge',
    )
    assert harness.auth.issued_discharges == ()


def test_bare_challenge_identifier_is_not_a_discharge():
    harness = Harness()
    request = harness.begin()
    forged = Macaroon(
        location=harness.auth.location,
        identifier=request.challenge_id,
        key='attacker-chosen-key',
    )
    for predicate in (
        'mfa-challenge = {}'.format(request.challenge_id),
        'mfa-user = {}'.format(request.user_id),
        'mfa-operation = {}'.format(request.operation.digest()),
        'mfa-expires = {}'.format(request.expires_at),
    ):
        forged.add_first_party_caveat(predicate)

    with pytest.raises(Denied) as denied:
        harness.business.complete(
            request_id=request.request_id,
            discharge=forged,
        )
    assert denied.value.reason == 'invalid_signature'
    assert harness.auth.issued_discharges == ()


def test_wrong_user_cannot_verify_with_another_users_proof():
    harness = Harness()
    request = harness.begin()
    alice_proof = harness.proofs[request.request_id]

    with pytest.raises(Denied) as verified:
        harness.auth.verify_mfa(
            challenge_id=request.challenge_id,
            user_id='mallory',
            operation=request.operation,
            proof=alice_proof,
        )
    assert verified.value.reason == 'wrong_subject'
    assert harness.auth.issued_discharges == ()


def test_another_user_cannot_redeem_alices_receipt():
    harness = Harness()
    victim = harness.begin()
    receipt = harness.complete_mfa(victim)

    forged = _forged_root(
        auth_location=harness.auth.location,
        challenge_id=victim.challenge_id,
        expires_at=victim.expires_at,
        user_id='mallory',
    )
    with pytest.raises(Denied) as denied:
        harness.auth.issue_discharge(root=forged, receipt=receipt)
    assert denied.value.reason == 'root_restriction_mismatch'
    assert harness.auth.issued_discharges == ()


def test_operation_change_after_mfa_is_rejected():
    harness = Harness()
    request = harness.begin(operation=_operation('100'))
    receipt = harness.complete_mfa(request)

    forged = _forged_root(
        auth_location=harness.auth.location,
        challenge_id=request.challenge_id,
        expires_at=request.expires_at,
        operation=_operation('900'),
    )
    with pytest.raises(Denied) as denied:
        harness.auth.issue_discharge(root=forged, receipt=receipt)
    assert denied.value.reason == 'root_restriction_mismatch'
    assert harness.auth.challenge_status(request.challenge_id) == 'verified'
    assert harness.auth.issued_discharges == ()


def test_expired_challenge_cannot_be_issued():
    harness = Harness(ttl_seconds=120)
    request = harness.begin()
    receipt = harness.complete_mfa(request)
    harness.clock.advance(120)

    with pytest.raises(Denied) as expired:
        harness.auth.issue_discharge(root=request.root, receipt=receipt)
    assert expired.value.reason == 'challenge_expired'
    assert harness.auth.issued_discharges == ()


def test_business_rejects_discharge_after_request_expiry():
    harness = Harness(ttl_seconds=120)
    request = harness.begin()
    receipt = harness.complete_mfa(request)
    discharge = harness.auth.issue_discharge(
        root=request.root, receipt=receipt,
    )
    harness.clock.advance(120)

    with pytest.raises(Denied) as expired:
        harness.business.complete(
            request_id=request.request_id,
            discharge=discharge,
        )
    assert expired.value.reason == 'request_expired'


def test_repeat_confirmation_and_issue_do_not_mint_second_discharge():
    harness = Harness()
    request = harness.begin()
    receipt = harness.complete_mfa(request)
    harness.auth.issue_discharge(root=request.root, receipt=receipt)

    with pytest.raises(Denied) as confirmation:
        harness.complete_mfa(request)
    assert confirmation.value.reason == 'challenge_already_consumed'

    with pytest.raises(Denied) as reissue:
        harness.auth.issue_discharge(root=request.root, receipt=receipt)
    assert reissue.value.reason == 'challenge_already_consumed'

    assert len(harness.auth.issued_discharges) == 1


def test_cross_operation_replay_is_rejected_by_business_service():
    harness = Harness()
    request_a = harness.begin(operation=_operation('10'))
    receipt_a = harness.complete_mfa(request_a)
    discharge_a = harness.auth.issue_discharge(
        root=request_a.root, receipt=receipt_a,
    )
    harness.business.complete(
        request_id=request_a.request_id, discharge=discharge_a,
    )

    request_b = harness.begin(operation=_operation('1000'))
    with pytest.raises(Denied) as replay:
        harness.business.complete(
            request_id=request_b.request_id,
            discharge=discharge_a,
        )
    assert replay.value.reason == 'discharge_challenge_mismatch'
    assert len(harness.auth.issued_discharges) == 1


def test_tampered_discharge_is_rejected():
    harness = Harness()
    request = harness.begin()
    discharge = harness.issue(request)
    discharge.add_first_party_caveat('mfa-user = mallory')

    with pytest.raises(Denied) as denied:
        harness.business.complete(
            request_id=request.request_id,
            discharge=discharge,
        )
    assert denied.value.reason == 'invalid_signature'
