import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.authorization_receipts import (
    ExpiredAuthorizationReceipt,
    InvalidAuthorizationReceipt,
)
from rest_framework.test import APIClient
from tests.approval_receipts.harness import (
    ApprovalDecision,
    ApprovalReceiptDemo,
    basic_auth_header,
)


class AuthorizationReceiptAcceptanceTests(TestCase):
    def setUp(self):
        self.demo = ApprovalReceiptDemo()
        self.user = self.demo.seed_user()
        self.race_task = self.demo.seed_task(
            "task-approved",
            operation="refund",
            object_type="order",
            object_id="order-1001",
        )
        self.revoke_task = self.demo.seed_task(
            "task-revoked-later",
            operation="capture",
            object_type="payment",
            object_id="payment-2002",
        )

    def test_api_responses_two_receipts_claims_once_commit_and_revocation(self):
        race_response = self.demo.dispatch(self.user, self.race_task.id)
        revoked_response = self.demo.dispatch(self.user, self.revoke_task.id)

        assert race_response.status_code == status.HTTP_202_ACCEPTED
        assert revoked_response.status_code == status.HTTP_202_ACCEPTED

        race_body = race_response.data
        revoked_body = revoked_response.data
        assert race_body["status"] == "accepted"
        assert race_body["task_id"] == self.race_task.id
        assert race_body["result_id"] == self.race_task.result_id
        assert revoked_body["task_id"] == self.revoke_task.id

        # Exactly two reviewable authorization receipts: one per API decision.
        receipts = self.demo.ledger.all()
        assert len(receipts) == 2
        race_receipt = self.demo.ledger.get(race_body["receipt"]["receipt_id"])
        revoked_receipt = self.demo.ledger.get(revoked_body["receipt"]["receipt_id"])
        assert race_receipt in receipts
        assert revoked_receipt in receipts

        for response_body, receipt in (
            (race_body, race_receipt),
            (revoked_body, revoked_receipt),
        ):
            assert response_body["receipt"]["token"] == receipt.token
            assert response_body["receipt"]["expires_at"] == receipt.expires_at.isoformat()
            assert receipt.subject_ref == f"user:{self.user.pk}"
            assert receipt.actor == self.user.username
            assert receipt.auth_scheme == "BasicAuthentication"
            assert receipt.expires_at > receipt.issued_at
            assert receipt.result_id == response_body["result_id"]
            assert self.demo.password not in str(receipt.public_dict())
            assert "password" not in receipt.public_dict(include_token=False)

        assert race_receipt.operation == "refund"
        assert race_receipt.object_type == "order"
        assert race_receipt.object_id == "order-1001"
        assert race_receipt.scope.attributes == {"task_id": self.race_task.id}
        assert race_receipt.approval_version == 1

        assert revoked_receipt.operation == "capture"
        assert revoked_receipt.object_type == "payment"
        assert revoked_receipt.object_id == "payment-2002"

        # The receipts were produced by DRF's permission path, including the
        # object-level current-approval check.
        object_checks = {
            entry["task_id"]: entry
            for entry in self.demo.permission_audit
            if entry["check"] == "has_object_permission"
        }
        assert object_checks[self.race_task.id]["allowed"] is True
        assert object_checks[self.revoke_task.id]["allowed"] is True
        assert any(entry["check"] == "has_permission" and entry["allowed"]
                   for entry in self.demo.permission_audit)

        # The API handed both tasks to the in-memory background queue.
        assert [(message.task_id, message.receipt_id) for message in self.demo.queue.messages] == [
            (self.race_task.id, race_receipt.receipt_id),
            (self.revoke_task.id, revoked_receipt.receipt_id),
        ]

        # Two workers are released into claim at the same time.  Both receive a
        # claim receipt, but the result idempotency guard allows one side effect.
        both_at_claim = threading.Barrier(2)

        def wait_for_peer():
            both_at_claim.wait(timeout=5)

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(
                self.demo.executor.execute,
                race_receipt.token,
                "worker-a",
                before_claim=wait_for_peer,
            )
            second = executor.submit(
                self.demo.executor.execute,
                race_receipt.token,
                "worker-b",
                before_claim=wait_for_peer,
            )
            outcomes = [first.result(timeout=10), second.result(timeout=10)]

        claims = self.demo.queue.claims_for(self.race_task.id)
        assert len(claims) == 2
        assert {claim.worker_id for claim in claims} == {"worker-a", "worker-b"}
        assert len({claim.claim_id for claim in claims}) == 2
        assert all(claim.authorization_receipt_id == race_receipt.receipt_id for claim in claims)
        assert all(claim.result_id == race_receipt.result_id for claim in claims)

        outcomes_by_claim = {outcome.claim_id: outcome for outcome in outcomes}
        assert set(outcomes_by_claim) == {claim.claim_id for claim in claims}
        assert {outcome.task_id for outcome in outcomes} == {self.race_task.id}
        assert {outcome.result_id for outcome in outcomes} == {self.race_task.result_id}
        assert {outcome.receipt_id for outcome in outcomes} == {race_receipt.receipt_id}

        submitted = [outcome for outcome in outcomes if outcome.committed]
        deduplicated = [outcome for outcome in outcomes if outcome.deduplicated]
        assert len(submitted) == 1
        assert len(deduplicated) == 1
        assert submitted[0].business_call is not None
        assert deduplicated[0].business_call == submitted[0].business_call

        assert len(self.demo.business.calls) == 1
        business_call = self.demo.business.calls[0]
        assert business_call.sequence == 1
        assert business_call.result_id == self.race_task.result_id
        assert business_call.task_id == self.race_task.id
        assert business_call.operation == "refund"
        assert business_call.object_type == "order"
        assert business_call.object_id == "order-1001"
        assert business_call.subject_ref == race_receipt.subject_ref
        assert business_call.worker_id == submitted[0].worker_id
        assert business_call.claim_id == submitted[0].claim_id

        # A second task is claimed first, then approval changes before the
        # protected business call starts.
        def revoke_after_claim(task, claim):
            self.demo.board.revoke(task.id, reason="approval_revoked")

        revoked_outcome = self.demo.executor.execute(
            revoked_receipt.token,
            "worker-c",
            after_claim=revoke_after_claim,
        )

        assert revoked_outcome.status == "rejected"
        assert revoked_outcome.reason == "approval_revoked"
        assert revoked_outcome.task_id == self.revoke_task.id
        assert revoked_outcome.result_id == self.revoke_task.result_id
        assert revoked_outcome.receipt_id == revoked_receipt.receipt_id

        rejection, = self.demo.executor.rejections
        assert rejection.claim_id == revoked_outcome.claim_id
        assert rejection.reason == "approval_revoked"
        assert rejection.approval_version == 2
        assert self.demo.board.get_decision(self.revoke_task.id).approved is False

        verification = self.demo.verify_api(revoked_receipt.token)
        assert verification.status_code == status.HTTP_200_OK
        assert verification.data["valid"] is True
        assert verification.data["receipt"]["receipt_id"] == revoked_receipt.receipt_id
        assert verification.data["current_approval"] == {
            "approved": False,
            "version": 2,
            "reason": "approval_revoked",
        }

        invalid_verification = self.demo.verify_api("not-a-receipt")
        assert invalid_verification.status_code == status.HTTP_400_BAD_REQUEST
        assert invalid_verification.data["valid"] is False
        assert invalid_verification.data["reason"] == "invalid_authorization_receipt"

        # The revocation path did not add a business call.
        assert len(self.demo.business.calls) == 1

        # The ordinary read remains a read-only identity/control path.
        final_read = self.demo.read(self.user, self.race_task.id)
        assert final_read.status_code == 200
        assert final_read.data["reader"] == self.user.username
        assert final_read.data["approved"] is True
        assert final_read.data["object"]["id"] == "order-1001"
        assert len(self.demo.ledger) == 2
        assert len(self.demo.queue.messages) == 2
        assert len(self.demo.business.calls) == 1

    @override_settings(ROOT_URLCONF="tests.approval_receipts.urls")
    def test_mounted_routes_dispatch_read_and_verify(self):
        from tests.approval_receipts.urls import demo as mounted_demo

        task = mounted_demo.seed_task("mounted-task")
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=basic_auth_header(self.user.username, mounted_demo.password)
        )

        dispatch_response = client.post(f"/approvals/{task.id}/dispatch/", format="json")
        read_response = client.get(f"/approvals/{task.id}/")
        verify_response = client.post(
            "/authorization-receipts/verify/",
            {"token": dispatch_response.data["receipt"]["token"]},
            format="json",
        )

        assert dispatch_response.status_code == status.HTTP_202_ACCEPTED
        assert read_response.status_code == status.HTTP_200_OK
        assert read_response.data["reader"] == self.user.username
        assert verify_response.status_code == status.HTTP_200_OK
        assert verify_response.data["valid"] is True
        assert verify_response.data["receipt"]["result_id"] == task.result_id

    def test_anonymous_dispatch_is_rejected_and_issues_no_receipt(self):
        response = self.demo.dispatch(task_id=self.race_task.id)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert len(self.demo.ledger) == 0
        assert self.demo.queue.messages == []

    def test_current_object_permission_denies_dispatch_without_receipt(self):
        denied_task = self.demo.seed_task("task-not-approved")
        self.demo.board.decisions[denied_task.id] = ApprovalDecision(
            approved=False,
            reason="pending_approval",
        )

        response = self.demo.dispatch(self.user, denied_task.id)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert len(self.demo.ledger) == 0
        assert self.demo.queue.messages == []
        object_check = next(
            entry for entry in self.demo.permission_audit
            if entry.get("task_id") == denied_task.id
            and entry["check"] == "has_object_permission"
        )
        assert object_check["allowed"] is False
        assert object_check["reason"] == "pending_approval"

    def test_revoked_attempt_does_not_poison_later_valid_retry(self):
        task = self.demo.seed_task("task-approval-flips")
        response = self.demo.dispatch(self.user, task.id)
        token = response.data["receipt"]["token"]

        def revoke_after_claim(task, claim):
            self.demo.board.revoke(task.id)

        denied = self.demo.executor.execute(
            token,
            "worker-revoked",
            after_claim=revoke_after_claim,
        )
        assert denied.rejected
        assert denied.reason == "approval_revoked"
        assert self.demo.business.calls == []

        self.demo.board.approve(task.id)
        accepted = self.demo.executor.execute(token, "worker-reapproved")
        repeated = self.demo.executor.execute(token, "worker-retry")

        assert accepted.committed
        assert repeated.deduplicated
        assert len(self.demo.business.calls) == 1
        assert accepted.business_call.approval_version == 3

    def test_expired_and_tampered_receipts_cannot_be_claimed(self):
        expired = self.demo.issuer.issue(
            subject_ref=f"user:{self.user.pk}",
            actor=self.user.username,
            operation="refund",
            object_type="order",
            object_id="order-1001",
            result_id="result-expired",
            ttl=-1,
        )

        with pytest.raises(ExpiredAuthorizationReceipt):
            self.demo.executor.execute(expired.token, "worker-expired")
        assert self.demo.queue.claim_receipts == []
        assert self.demo.business.calls == []

        valid = self.demo.dispatch(self.user, self.race_task.id)
        tampered_token = valid.data["receipt"]["token"] + "tampered"
        with pytest.raises(InvalidAuthorizationReceipt):
            self.demo.executor.execute(tampered_token, "worker-tampered")
        assert self.demo.queue.claims_for(self.race_task.id) == []
