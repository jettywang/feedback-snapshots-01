from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import TransactionTestCase
from rest_framework.test import APITestCase

from rest_framework_simplejwt.approvals import (
    ApprovalUnavailable,
    commit_approval,
    inspect_approval,
)
from rest_framework_simplejwt.serializers import (
    ApprovalCommitSerializer,
    ApprovalObtainSerializer,
)
from rest_framework_simplejwt.token_blacklist.models import ApprovalGrant
from rest_framework_simplejwt.tokens import RefreshToken

from .approval_executors import Executor, PaymentBackend, race


class ApprovalViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="cashier", password="correct-horse"
        )
        self.client.force_authenticate(self.user)

    def test_authenticated_step_up_obtains_an_approval(self):
        response = self.client.post(
            "/approval/obtain/", {"operation": "payment-42", "amount": "10.00"}
        )

        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["operation"], "payment-42")
        self.assertEqual(response.data["status"], "pending")
        self.assertEqual(response.data["amount"], "10.0000")
        self.assertFalse(response.data["settled"])
        self.assertTrue(inspect_approval(response.data["approval"]).is_live)

    def test_refresh_endpoint_does_not_return_an_approval(self):
        refresh = RefreshToken.for_user(self.user)

        response = self.client.post("/token/refresh/", {"refresh": str(refresh)})

        self.assertEqual(response.status_code, 200, response.data)
        self.assertNotIn("approval", response.data)
        self.assertNotIn("operation", response.data)
        self.assertFalse(ApprovalGrant.objects.exists())

    def test_refresh_token_is_not_accepted_as_an_approval(self):
        refresh = RefreshToken.for_user(self.user)

        with self.assertRaises(ApprovalUnavailable):
            inspect_approval(str(refresh))

    def test_unauthenticated_callers_cannot_obtain_approvals(self):
        self.client.force_authenticate(None)

        response = self.client.post(
            "/approval/obtain/", {"operation": "payment-42", "amount": "10.00"}
        )

        self.assertIn(response.status_code, (401, 403))

    def test_withdraw_then_commit_over_http(self):
        approval = self.client.post(
            "/approval/obtain/", {"operation": "payment-42", "amount": "10.00"}
        ).data["approval"]

        withdrawn = self.client.post("/approval/withdraw/", {"approval": approval})
        self.assertEqual(withdrawn.status_code, 200, withdrawn.data)
        self.assertEqual(withdrawn.data["status"], "withdrawn")

        with self.assertRaises(ApprovalUnavailable):
            commit_approval(
                approval,
                operation="payment-42",
                amount="10.00",
                operation_runner=lambda grant: "receipt",
            )

    def test_withdraw_after_commit_reports_conflict(self):
        approval = self.client.post(
            "/approval/obtain/", {"operation": "payment-42", "amount": "10.00"}
        ).data["approval"]
        commit_approval(
            approval,
            operation="payment-42",
            amount="10.00",
            operation_runner=lambda grant: "receipt-1",
        )

        response = self.client.post("/approval/withdraw/", {"approval": approval})

        self.assertEqual(response.status_code, 400, response.data)


class ApprovalCommitSerializerTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="cashier", password="pw")
        self.client.force_authenticate(self.user)
        self.approval = self.client.post(
            "/approval/obtain/", {"operation": "payment-42", "amount": "10.00"}
        ).data["approval"]

    def test_commit_serializer_runs_operation_and_reports_settled(self):
        calls = []
        serializer = ApprovalCommitSerializer(
            data={
                "approval": self.approval,
                "operation": "payment-42",
                "amount": "10.00",
            },
            context={"operation_runner": lambda g: calls.append(1) or "receipt"},
        )

        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(calls, [1])
        self.assertTrue(serializer.validated_data["settled"])
        self.assertEqual(serializer.validated_data["result"], "receipt")

    def test_commit_serializer_requires_a_runner(self):
        serializer = ApprovalCommitSerializer(
            data={
                "approval": self.approval,
                "operation": "payment-42",
                "amount": "10.00",
            },
            context={},
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("detail", serializer.errors)

    def test_commit_serializer_rejects_usage_mismatch(self):
        serializer = ApprovalCommitSerializer(
            data={
                "approval": self.approval,
                "operation": "payment-99",
                "amount": "10.00",
            },
            context={"operation_runner": lambda g: "receipt"},
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors["code"], ["usage_mismatch"])


class ApprovalCommitEndpointTests(APITestCase):
    """
    Exercises the same serializer/view path the HTTP commit endpoint uses,
    with the business hook supplied by configuration.
    """

    def setUp(self):
        from .utils import override_api_settings

        self.user = User.objects.create_user(username="cashier", password="pw")
        self.client.force_authenticate(self.user)
        self.calls = []
        self._override = override_api_settings(
            APPROVAL_OPERATION_RUNNER=lambda approval: (
                self.calls.append(approval.token_id) or "receipt-1"
            )
        )
        self._override.__enter__()
        self.addCleanup(self._override.__exit__, None, None, None)

    def test_commit_endpoint_executes_once_and_reports_settled(self):
        approval = self.client.post(
            "/approval/obtain/", {"operation": "payment-42", "amount": "10.00"}
        ).data["approval"]

        response = self.client.post(
            "/approval/commit/",
            {"approval": approval, "operation": "payment-42", "amount": "10.00"},
        )

        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data["settled"])
        self.assertEqual(response.data["result"], "receipt-1")
        self.assertEqual(self.calls, [inspect_approval(approval).token_id])

    def test_commit_endpoint_rejects_a_withdrawn_approval(self):
        approval = self.client.post(
            "/approval/obtain/", {"operation": "payment-42", "amount": "10.00"}
        ).data["approval"]
        self.client.post("/approval/withdraw/", {"approval": approval})

        response = self.client.post(
            "/approval/commit/",
            {"approval": approval, "operation": "payment-42", "amount": "10.00"},
        )

        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(self.calls, [])


class ApprovalSerializerRaceTests(TransactionTestCase):
    """
    Two executors each build their own commit serializer for the same
    approval, mirroring two HTTP workers, and race the winning claim.
    """

    reset_sequences = True

    def setUp(self):
        self.user = User.objects.create_user(username="cashier", password="pw")
        self.backend = PaymentBackend()

    def _commit(self, approval, *, operation_runner):
        serializer = ApprovalCommitSerializer(
            data={
                "approval": approval,
                "operation": "payment-42",
                "amount": "10.00",
            },
            context={"operation_runner": operation_runner},
        )
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data

    def test_two_serializer_executors_charge_once(self):
        requested = ApprovalObtainSerializer(
            data={"operation": "payment-42", "amount": "10.00"},
            context={"request": SimpleNamespace(user=self.user)},
        )
        self.assertTrue(requested.is_valid(), requested.errors)
        approval = requested.validated_data["approval"]

        left = Executor("left", self.backend)
        right = Executor("right", self.backend)
        race(self._commit, approval, left, right)

        statuses = sorted(o.outcome["status"] for o in (left, right))

        # Exactly one executor ran the payment; the other never charged.
        self.assertEqual(self.backend.call_count, 1)
        self.assertEqual(statuses.count("committed"), 1, statuses)

    def test_serializer_executors_after_admin_withdrawal_never_pay(self):
        requested = ApprovalObtainSerializer(
            data={"operation": "payment-42", "amount": "10.00"},
            context={"request": SimpleNamespace(user=self.user)},
        )
        self.assertTrue(requested.is_valid(), requested.errors)
        approval = requested.validated_data["approval"]

        from rest_framework_simplejwt.approvals import withdraw_approval

        withdraw_approval(approval)

        left = Executor("left", self.backend)
        right = Executor("right", self.backend)
        race(self._commit, approval, left, right)

        self.assertEqual(self.backend.call_count, 0)
        for executor in (left, right):
            self.assertEqual(executor.outcome["status"], "error")

    def test_serializer_finance_write_failure_is_not_repaid_on_retry(self):
        requested = ApprovalObtainSerializer(
            data={"operation": "payment-42", "amount": "10.00"},
            context={"request": SimpleNamespace(user=self.user)},
        )
        self.assertTrue(requested.is_valid(), requested.errors)
        approval = requested.validated_data["approval"]
        self.backend.fail_record = lambda attempt: attempt == 1

        winner = Executor("winner", self.backend)
        loser = Executor("loser", self.backend)
        race(self._commit, approval, winner, loser)

        self.assertEqual(self.backend.call_count, 1)

        retry = Executor("retry", self.backend)
        retry.start(self._commit, approval)

        # The retry must not charge again; it reports the incomplete grant.
        self.assertEqual(self.backend.call_count, 1)
        # The serializer reports approval failures as DRF validation errors;
        # what matters is that no second charge happened.
        self.assertEqual(retry.outcome["status"], "error")
        self.assertIn(retry.outcome["error"], {"ValidationError", "ApprovalConflict"})

        from rest_framework_simplejwt.approvals import (
            inspect_approval,
            record_approval_result,
        )

        self.assertFalse(inspect_approval(approval).is_settled)
        reconciled = record_approval_result(approval, "payment-1")
        self.assertTrue(reconciled.is_settled)
        self.assertEqual(self.backend.call_count, 1)
