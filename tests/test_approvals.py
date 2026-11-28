from datetime import timedelta
from decimal import Decimal

from django.contrib.auth.models import User
from django.test import TestCase, TransactionTestCase

from rest_framework_simplejwt.approvals import (
    ApprovalConflict,
    ApprovalIncomplete,
    ApprovalUnavailable,
    ApprovalUsageMismatch,
    commit_approval,
    inspect_approval,
    issue_approval,
    record_approval_result,
    withdraw_approval,
)
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import ApprovalGrant
from rest_framework_simplejwt.tokens import ApprovalToken, RefreshToken
from rest_framework_simplejwt.utils import aware_utcnow

from .approval_executors import Executor, PaymentBackend, race


def winner_result_of(outcomes):
    return next(
        o.outcome["result"] for o in outcomes if o.outcome["status"] == "committed"
    )


def payment(note: str = "paid"):
    return lambda grant: note


class TestApprovalToken(TestCase):
    def setUp(self):
        self.user = User.objects.create(username="cashier", password="pw")

    def test_approval_is_bound_to_operation_and_amount(self):
        approval = issue_approval(self.user, "payment-42", "10.00")

        self.assertEqual(approval.operation, "payment-42")
        self.assertEqual(approval.amount, Decimal("10.0000"))
        self.assertTrue(approval.is_live)
        self.assertFalse(approval.is_settled)

        payload = ApprovalToken(approval.token).payload
        self.assertEqual(payload[api_settings.TOKEN_TYPE_CLAIM], "approval")
        self.assertNotEqual(
            payload[api_settings.TOKEN_TYPE_CLAIM],
            api_settings.AUTH_TOKEN_CLASSES[0].token_type,
        )
        self.assertEqual(payload[ApprovalToken.operation_claim], "payment-42")
        self.assertEqual(payload[ApprovalToken.amount_claim], "10.0000")

    def test_approval_is_not_an_access_token(self):
        approval = issue_approval(self.user, "payment-42", "10.00")

        with self.assertRaises(TokenError):
            api_settings.AUTH_TOKEN_CLASSES[0](approval.token)

    def test_approval_does_not_authorize_a_different_operation(self):
        approval = issue_approval(self.user, "payment-42", "10.00")

        with self.assertRaises(ApprovalUsageMismatch):
            commit_approval(
                approval.token,
                operation="payment-43",
                amount="10.00",
                operation_runner=payment(),
            )

    def test_approval_does_not_authorize_a_different_amount(self):
        approval = issue_approval(self.user, "payment-42", "10.00")

        with self.assertRaises(ApprovalUsageMismatch):
            commit_approval(
                approval.token,
                operation="payment-42",
                amount="10.01",
                operation_runner=payment(),
            )

    def test_raw_token_id_is_not_a_bearer_credential(self):
        approval = issue_approval(self.user, "payment-42", "10.00")

        with self.assertRaises(ApprovalUnavailable):
            inspect_approval(approval.token_id)

    def test_forged_token_is_rejected(self):
        approval = issue_approval(self.user, "payment-42", "10.00")
        header, _, signature = approval.token.split(".")
        other = issue_approval(self.user, "payment-42", "10.00")

        with self.assertRaises(ApprovalUnavailable):
            inspect_approval(f"{other.token.split('.')[0]}.{header}.{signature}")

    def test_expired_approval_cannot_be_committed(self):
        approval = issue_approval(
            self.user, "payment-42", "10.00", lifetime=timedelta(seconds=-1)
        )

        with self.assertRaises(ApprovalUnavailable):
            commit_approval(
                approval.token,
                operation="payment-42",
                amount="10.00",
                operation_runner=payment(),
            )

    def test_approval_requires_persisted_user(self):
        anonymous = User(id=9999)

        with self.assertRaises(ApprovalUsageMismatch):
            issue_approval(anonymous, "payment-42", "10.00")


class TestApprovalLifecycle(TestCase):
    def setUp(self):
        self.user = User.objects.create(username="cashier", password="pw")

    def test_normal_commit_records_result_once(self):
        calls = []
        approval = issue_approval(self.user, "payment-42", "10.00")

        record = commit_approval(
            approval.token,
            operation="payment-42",
            amount="10.00",
            operation_runner=lambda grant: calls.append(grant.token_id) or "receipt-1",
        )

        self.assertTrue(record.executed)
        self.assertEqual(record.status, ApprovalGrant.CONSUMED)
        self.assertTrue(record.is_settled)
        self.assertEqual(record.result, "receipt-1")
        self.assertEqual(calls, [approval.token_id])

    def test_withdrawal_before_commit_blocks_payment(self):
        calls = []
        approval = issue_approval(self.user, "payment-42", "10.00")

        withdrawn = withdraw_approval(approval.token)
        self.assertEqual(withdrawn.status, ApprovalGrant.WITHDRAWN)

        with self.assertRaises(ApprovalUnavailable):
            commit_approval(
                approval.token,
                operation="payment-42",
                amount="10.00",
                operation_runner=lambda g: calls.append(g) or "paid",
            )

        self.assertEqual(calls, [])

    def test_withdraw_after_consumption_loses(self):
        approval = issue_approval(self.user, "payment-42", "10.00")
        commit_approval(
            approval.token,
            operation="payment-42",
            amount="10.00",
            operation_runner=payment("receipt-1"),
        )

        with self.assertRaises(ApprovalConflict):
            withdraw_approval(approval.token)

        settled = inspect_approval(approval.token)
        self.assertEqual(settled.status, ApprovalGrant.CONSUMED)
        self.assertEqual(settled.result, "receipt-1")
        self.assertTrue(settled.is_settled)

    def test_double_commit_only_runs_operation_once(self):
        calls = []
        approval = issue_approval(self.user, "payment-42", "10.00")

        first = commit_approval(
            approval.token,
            operation="payment-42",
            amount="10.00",
            operation_runner=lambda g: calls.append(1) or "receipt-1",
        )
        second = commit_approval(
            approval.token,
            operation="payment-42",
            amount="10.00",
            operation_runner=lambda g: calls.append(2) or "receipt-2",
        )

        self.assertEqual(calls, [1])
        self.assertTrue(first.executed)
        self.assertFalse(second.executed)
        self.assertEqual(first.result, "receipt-1")
        self.assertEqual(second.result, "receipt-1")

    def test_retry_without_recorded_result_needs_reconciliation(self):
        approval = issue_approval(self.user, "payment-42", "10.00")
        grant = ApprovalGrant.objects.get(token_id=approval.token_id)
        ApprovalGrant.objects.filter(pk=grant.pk).update(
            status=ApprovalGrant.CONSUMED,
            consumed_at=aware_utcnow(),
        )

        with self.assertRaises(ApprovalIncomplete):
            commit_approval(
                approval.token,
                operation="payment-42",
                amount="10.00",
                operation_runner=payment(),
            )

    def test_result_can_be_recorded_after_failed_finance_write(self):
        approval = issue_approval(self.user, "payment-42", "10.00")

        def runner(grant):
            raise RuntimeError("finance record write failed")

        with self.assertRaises(RuntimeError):
            commit_approval(
                approval.token,
                operation="payment-42",
                amount="10.00",
                operation_runner=runner,
            )

        consumed = inspect_approval(approval.token)
        self.assertEqual(consumed.status, ApprovalGrant.CONSUMED)
        self.assertFalse(consumed.is_settled)

        reconciled = record_approval_result(approval.token, "payment-1")
        self.assertTrue(reconciled.is_settled)
        self.assertEqual(reconciled.result, "payment-1")

    def test_record_result_refuses_non_consumed_approval(self):
        approval = issue_approval(self.user, "payment-42", "10.00")

        with self.assertRaises(ApprovalUnavailable):
            record_approval_result(approval.token, "payment-1")

        self.assertFalse(inspect_approval(approval.token).is_settled)

    def test_committed_result_survives_inspection(self):
        approval = issue_approval(self.user, "payment-42", "10.00")
        commit_approval(
            approval.token,
            operation="payment-42",
            amount="10.00",
            operation_runner=payment("receipt-9"),
        )

        self.assertEqual(inspect_approval(approval.token).result, "receipt-9")

    def test_expired_grant_cannot_be_withdrawn_into_history(self):
        approval = issue_approval(
            self.user, "payment-42", "10.00", lifetime=timedelta(seconds=-1)
        )

        with self.assertRaises(ApprovalUnavailable):
            withdraw_approval(approval.token)


class TestRefreshDoesNotIssueApproval(TestCase):
    def setUp(self):
        self.user = User.objects.create(username="cashier", password="pw")

    def test_refresh_token_cannot_mint_approval(self):
        refresh = RefreshToken.for_user(self.user)

        with self.assertRaises(TokenError):
            ApprovalToken(str(refresh))

        with self.assertRaises(TokenError):
            ApprovalToken(str(refresh.access_token))

        self.assertFalse(ApprovalGrant.objects.exists())

    def test_access_token_has_no_approval_claims(self):
        refresh = RefreshToken.for_user(self.user)
        access = refresh.access_token

        self.assertNotIn(ApprovalToken.operation_claim, access.payload)
        self.assertNotIn(ApprovalToken.amount_claim, access.payload)

    def test_refresh_does_not_revive_withdrawn_approval(self):
        approval = issue_approval(self.user, "payment-42", "10.00")
        withdraw_approval(approval.token)

        refresh = RefreshToken.for_user(self.user)
        access = refresh.access_token
        self.assertNotIn(ApprovalToken.operation_claim, access.payload)

        with self.assertRaises(ApprovalUnavailable):
            commit_approval(
                approval.token,
                operation="payment-42",
                amount="10.00",
                operation_runner=payment(),
            )


class TestExecutorRace(TransactionTestCase):
    """
    Two local executors hold the same legitimate approval.  These run against
    a real (non-wrapped) database transaction so the conditional claim is
    exercised the way concurrent workers would exercise it.
    """

    reset_sequences = True

    def setUp(self):
        self.user = User.objects.create(username="cashier", password="pw")
        self.backend = PaymentBackend()

    def _commit(self, approval, *, operation_runner):
        return commit_approval(
            approval,
            operation="payment-42",
            amount="10.00",
            operation_runner=operation_runner,
        )

    def test_only_one_executor_wins_the_race(self):
        approval = issue_approval(self.user, "payment-42", "10.00")
        left = Executor("left", self.backend)
        right = Executor("right", self.backend)

        outcomes = race(self._commit, approval.token, left, right)

        statuses = sorted(o.outcome["status"] for o in outcomes)

        # Exactly one executor actually ran the operation and charged once.
        self.assertEqual(self.backend.call_count, 1)
        self.assertEqual(statuses.count("committed"), 1, statuses)
        loser = next(o for o in outcomes if o.outcome["status"] != "committed")
        self.assertIn(
            loser.outcome["status"], {"replayed", "error", "contended"}, statuses
        )
        if loser.outcome["status"] == "replayed":
            # A retried loser may observe the winner's result but must not
            # have executed anything itself.
            self.assertTrue(loser.outcome["settled"])
            self.assertEqual(loser.outcome["result"], winner_result_of(outcomes))
        winner = next(o for o in outcomes if o.outcome["status"] == "committed")
        self.assertTrue(winner.outcome["settled"])

    def test_admin_withdraws_first_so_no_executor_pays(self):
        approval = issue_approval(self.user, "payment-42", "10.00")
        withdraw_approval(approval.token)

        left = Executor("left", self.backend)
        right = Executor("right", self.backend)
        outcomes = race(self._commit, approval.token, left, right)

        self.assertEqual(self.backend.call_count, 0)
        for executor in outcomes:
            self.assertIn(executor.outcome["status"], {"error", "contended"})
            if executor.outcome["status"] == "error":
                self.assertEqual(executor.outcome["error"], "ApprovalUnavailable")

        final = inspect_approval(approval.token)
        self.assertEqual(final.status, ApprovalGrant.WITHDRAWN)
        self.assertFalse(final.is_settled)

    def test_finance_write_failure_never_double_pays_on_retry(self):
        approval = issue_approval(self.user, "payment-42", "10.00")
        self.backend.fail_record = lambda attempt: attempt == 1

        winner = Executor("winner", self.backend)
        loser = Executor("loser", self.backend)
        race(self._commit, approval.token, winner, loser)

        self.assertEqual(self.backend.call_count, 1)
        self.assertFalse(inspect_approval(approval.token).is_settled)

        retry = Executor("retry", self.backend)
        retry.start(self._commit, approval.token)

        self.assertEqual(self.backend.call_count, 1)
        self.assertIn(
            retry.outcome["error"], {"ApprovalIncomplete", "ApprovalConflict"}
        )

        reconciled = record_approval_result(approval.token, "payment-1")
        self.assertTrue(reconciled.is_settled)
        self.assertEqual(self.backend.call_count, 1)
