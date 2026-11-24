"""Self-contained DRF approval-receipt scenario used by the acceptance test."""
from __future__ import annotations

import base64
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from django.http import Http404
from django.urls import path
from django.utils import timezone
from rest_framework import authentication, permissions, status
from rest_framework.authorization_receipts import (
    AuthorizationReceipt,
    AuthorizationReceiptError,
    AuthorizationReceiptIssuer,
    AuthorizationScope,
    InMemoryAuthorizationReceiptLedger,
)
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView


DEFAULT_PASSWORD = "synthetic-passphrase"


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {token}"


class ApprovalScenarioError(Exception):
    pass


class ApprovalNotFound(ApprovalScenarioError):
    pass


class ApprovalNoLongerValid(ApprovalScenarioError):
    def __init__(self, reason: str = "approval_revoked", version: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.version = version


@dataclass(frozen=True)
class ApprovalTask:
    id: str
    operation: str
    object_type: str
    object_id: str
    result_id: str

    def authorization_scope(self) -> AuthorizationScope:
        return AuthorizationScope(
            operation=self.operation,
            object_type=self.object_type,
            object_id=self.object_id,
            attributes={"task_id": self.id},
        )


@dataclass
class ApprovalDecision:
    approved: bool = True
    version: int = 1
    reason: str = "approved"
    decided_at: datetime = field(default_factory=timezone.now)


class ApprovalBoard:
    """Current approval state; revocation is visible to all workers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.tasks: dict[str, ApprovalTask] = {}
        self.decisions: dict[str, ApprovalDecision] = {}

    def add_task(
        self,
        task: ApprovalTask,
        decision: ApprovalDecision | None = None,
    ) -> ApprovalTask:
        with self._lock:
            self.tasks[task.id] = task
            self.decisions[task.id] = decision or ApprovalDecision()
            return task

    def get_task(self, task_id: str) -> ApprovalTask | None:
        return self.tasks.get(task_id)

    def get_decision(self, task_id: str) -> ApprovalDecision | None:
        return self.decisions.get(task_id)

    def revoke(self, task_id: str, reason: str = "approval_revoked") -> ApprovalDecision:
        with self._lock:
            current = self.decisions[task_id]
            decision = ApprovalDecision(
                approved=False,
                version=current.version + 1,
                reason=reason,
            )
            self.decisions[task_id] = decision
            return decision

    def approve(self, task_id: str, reason: str = "approved") -> ApprovalDecision:
        with self._lock:
            current = self.decisions[task_id]
            decision = ApprovalDecision(
                approved=True,
                version=current.version + 1,
                reason=reason,
            )
            self.decisions[task_id] = decision
            return decision

    def require_approved(self, task_id: str) -> ApprovalDecision:
        decision = self.get_decision(task_id)
        if decision is None:
            raise ApprovalNotFound(task_id)
        if not decision.approved:
            raise ApprovalNoLongerValid(decision.reason, decision.version)
        return decision


@dataclass
class QueueMessage:
    task_id: str
    receipt_id: str
    result_id: str
    enqueued_at: datetime


@dataclass
class ClaimReceipt:
    claim_id: str
    sequence: int
    task_id: str
    worker_id: str
    authorization_receipt_id: str
    result_id: str
    claimed_at: datetime
    status: str = "delivered"

    @property
    def id(self) -> str:
        return self.claim_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "sequence": self.sequence,
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "authorization_receipt_id": self.authorization_receipt_id,
            "result_id": self.result_id,
            "claimed_at": self.claimed_at.isoformat(),
            "status": self.status,
        }


class InMemoryTaskQueue:
    """At-least-once memory queue with reviewable delivery/claim receipts."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.messages: list[QueueMessage] = []
        self.claim_receipts: list[ClaimReceipt] = []

    def enqueue(self, task_id: str, receipt: AuthorizationReceipt) -> QueueMessage:
        message = QueueMessage(
            task_id=task_id,
            receipt_id=receipt.receipt_id,
            result_id=receipt.result_id,
            enqueued_at=timezone.now(),
        )
        with self._lock:
            self.messages.append(message)
        return message

    def claim(
        self,
        task_id: str,
        worker_id: str,
        receipt: AuthorizationReceipt,
    ) -> ClaimReceipt:
        with self._lock:
            claim = ClaimReceipt(
                claim_id=f"claim_{uuid.uuid4().hex}",
                sequence=len(self.claim_receipts) + 1,
                task_id=task_id,
                worker_id=worker_id,
                authorization_receipt_id=receipt.receipt_id,
                result_id=receipt.result_id,
                claimed_at=timezone.now(),
            )
            self.claim_receipts.append(claim)
            return claim

    def claims_for(self, task_id: str) -> list[ClaimReceipt]:
        return [claim for claim in self.claim_receipts if claim.task_id == task_id]


MemoryTaskQueue = InMemoryTaskQueue


@dataclass(frozen=True)
class BusinessSubmission:
    sequence: int
    result_id: str
    task_id: str
    operation: str
    object_type: str
    object_id: str
    subject_ref: str
    worker_id: str
    claim_id: str
    approval_version: str | int | None
    submitted_at: datetime


class RecordingBusinessService:
    """The protected side effect; tests assert this is invoked exactly once."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.calls: list[BusinessSubmission] = []

    def submit(
        self,
        *,
        task: ApprovalTask,
        receipt: AuthorizationReceipt,
        claim: ClaimReceipt,
        worker_id: str,
        decision: ApprovalDecision,
    ) -> BusinessSubmission:
        with self._lock:
            call = BusinessSubmission(
                sequence=len(self.calls) + 1,
                result_id=receipt.result_id,
                task_id=task.id,
                operation=task.operation,
                object_type=task.object_type,
                object_id=task.object_id,
                subject_ref=receipt.subject_ref,
                worker_id=worker_id,
                claim_id=claim.claim_id,
                approval_version=decision.version,
                submitted_at=timezone.now(),
            )
            self.calls.append(call)
            return call


@dataclass(frozen=True)
class GuardResult:
    value: BusinessSubmission
    created: bool


class IdempotentSubmissionGuard:
    """Runs the business callback once per result id across local threads.

    The lock covers the check, approval re-read inside ``operation``, and call so
    two workers cannot both observe an absent result and submit duplicate work.
    Exceptions are not memoized: a rejected attempt may be retried after the
    current approval decision changes.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._completed: dict[str, BusinessSubmission] = {}

    def run_once(self, result_id: str, operation: Callable[[], BusinessSubmission]) -> GuardResult:
        with self._lock:
            completed = self._completed.get(result_id)
            if completed is not None:
                return GuardResult(completed, created=False)

            value = operation()
            self._completed[result_id] = value
            return GuardResult(value, created=True)


@dataclass
class RejectionRecord:
    task_id: str
    result_id: str
    receipt_id: str
    claim_id: str
    worker_id: str
    reason: str
    detail: str
    rejected_at: datetime
    approval_version: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "result_id": self.result_id,
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "worker_id": self.worker_id,
            "reason": self.reason,
            "detail": self.detail,
            "rejected_at": self.rejected_at.isoformat(),
            "approval_version": self.approval_version,
        }


@dataclass
class ExecutionOutcome:
    status: str
    task_id: str
    result_id: str
    receipt_id: str
    claim_id: str
    worker_id: str
    business_call: BusinessSubmission | None = None
    rejection: RejectionRecord | None = None

    @property
    def committed(self) -> bool:
        return self.status == "submitted"

    @property
    def deduplicated(self) -> bool:
        return self.status == "deduplicated"

    @property
    def rejected(self) -> bool:
        return self.status == "rejected"

    @property
    def reason(self) -> str | None:
        return self.rejection.reason if self.rejection else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "task_id": self.task_id,
            "result_id": self.result_id,
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "worker_id": self.worker_id,
            "reason": self.reason,
            "business_call": self.business_call.__dict__ if self.business_call else None,
            "rejection": self.rejection.to_dict() if self.rejection else None,
        }


class InMemoryExecutor:
    """Verify receipt/scope, claim, re-read approval, then commit once."""

    def __init__(
        self,
        board: ApprovalBoard,
        queue: InMemoryTaskQueue,
        business: RecordingBusinessService,
        issuer: AuthorizationReceiptIssuer,
        guard: IdempotentSubmissionGuard | None = None,
    ) -> None:
        self.board = board
        self.queue = queue
        self.business = business
        self.issuer = issuer
        self.guard = guard or IdempotentSubmissionGuard()
        self.outcomes: list[ExecutionOutcome] = []
        self.rejections: list[RejectionRecord] = []

    def execute(
        self,
        token_or_receipt: str | AuthorizationReceipt,
        worker_id: str,
        *,
        before_claim: Callable[[], None] | None = None,
        after_claim: Callable[..., None] | None = None,
    ) -> ExecutionOutcome:
        receipt = self.issuer.verify(token_or_receipt)
        task = self.board.get_task(receipt.scope.attributes.get("task_id", ""))
        if task is None:
            raise ApprovalNotFound(receipt.scope.attributes.get("task_id"))

        # Re-verify against current domain object identifiers, not just claims.
        self.issuer.verify(receipt.token, expected_scope=task.authorization_scope())
        if receipt.result_id != task.result_id:
            raise ValueError("Receipt result identifier does not match the task")

        if before_claim is not None:
            before_claim()

        claim = self.queue.claim(task.id, worker_id, receipt)

        if after_claim is not None:
            after_claim(task=task, claim=claim)

        def commit_once() -> BusinessSubmission:
            # Current approval is read immediately before the protected call.
            decision = self.board.require_approved(task.id)
            claim.status = "committing"
            return self.business.submit(
                task=task,
                receipt=receipt,
                claim=claim,
                worker_id=worker_id,
                decision=decision,
            )

        try:
            guarded = self.guard.run_once(receipt.result_id, commit_once)
        except ApprovalNoLongerValid as exc:
            claim.status = "rejected"
            rejection = RejectionRecord(
                task_id=task.id,
                result_id=receipt.result_id,
                receipt_id=receipt.receipt_id,
                claim_id=claim.claim_id,
                worker_id=worker_id,
                reason=exc.reason,
                detail=str(exc),
                rejected_at=timezone.now(),
                approval_version=exc.version,
            )
            self.rejections.append(rejection)
            outcome = ExecutionOutcome(
                status="rejected",
                task_id=task.id,
                result_id=receipt.result_id,
                receipt_id=receipt.receipt_id,
                claim_id=claim.claim_id,
                worker_id=worker_id,
                rejection=rejection,
            )
            self.outcomes.append(outcome)
            return outcome

        claim.status = "completed"
        outcome = ExecutionOutcome(
            status="submitted" if guarded.created else "deduplicated",
            task_id=task.id,
            result_id=receipt.result_id,
            receipt_id=receipt.receipt_id,
            claim_id=claim.claim_id,
            worker_id=worker_id,
            business_call=guarded.value,
        )
        self.outcomes.append(outcome)
        return outcome


MemoryApprovalExecutor = InMemoryExecutor
MemoryExecutor = InMemoryExecutor


class DispatchApprovalPermission(permissions.BasePermission):
    """Authenticate through DRF and check current object-level approval."""

    message = "approval_dispatch_permission_denied"

    def __init__(self, board: ApprovalBoard, audit: list[dict[str, Any]]) -> None:
        self.board = board
        self.audit = audit

    def has_permission(self, request: Any, view: APIView) -> bool:
        user = getattr(request, "user", None)
        allowed = bool(user is not None and user.is_authenticated)
        self.audit.append({
            "check": "has_permission",
            "username": getattr(user, "username", None),
            "allowed": allowed,
            "method": request.method,
            "path": request.path,
        })
        return allowed

    def has_object_permission(self, request: Any, view: APIView, obj: ApprovalTask) -> bool:
        decision = self.board.get_decision(obj.id)
        allowed = bool(decision is not None and decision.approved)
        self.audit.append({
            "check": "has_object_permission",
            "username": getattr(request.user, "username", None),
            "task_id": obj.id,
            "allowed": allowed,
            "approval_version": decision.version if decision else None,
            "reason": decision.reason if decision else "missing_decision",
        })
        if not allowed and decision is not None:
            self.message = decision.reason
        return allowed


class ApprovalDispatchView(APIView):
    authentication_classes = [authentication.BasicAuthentication]
    board: ApprovalBoard | None = None
    issuer: AuthorizationReceiptIssuer | None = None
    queue: InMemoryTaskQueue | None = None
    audit: list[dict[str, Any]] | None = None

    def get_permissions(self):
        assert self.board is not None
        assert self.audit is not None
        return [DispatchApprovalPermission(self.board, self.audit)]

    def post(self, request: Any, task_id: str) -> Response:
        assert self.board is not None
        assert self.issuer is not None
        assert self.queue is not None

        task = self.board.get_task(task_id)
        if task is None:
            raise Http404(f"Unknown approval task: {task_id}")

        self.check_object_permissions(request, task)
        decision = self.board.require_approved(task.id)
        receipt = self.issuer.issue_for_request(
            request,
            operation=task.operation,
            object_type=task.object_type,
            object_id=task.object_id,
            result_id=task.result_id,
            scope_attributes={"task_id": task.id},
            decision="approved" if decision.approved else "denied",
            approval_version=decision.version,
        )
        self.queue.enqueue(task.id, receipt)

        return Response(
            {
                "status": "accepted",
                "task_id": task.id,
                "result_id": task.result_id,
                "queue": "memory",
                "receipt": receipt.public_dict(),
            },
            status=202,
        )


class ApprovalReadView(APIView):
    authentication_classes = [authentication.BasicAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    board: ApprovalBoard | None = None

    def get(self, request: Any, task_id: str) -> Response:
        assert self.board is not None
        task = self.board.get_task(task_id)
        if task is None:
            raise Http404(f"Unknown approval task: {task_id}")
        decision = self.board.require_approved(task.id)
        return Response({
            "task_id": task.id,
            "result_id": task.result_id,
            "operation": task.operation,
            "object": {
                "type": task.object_type,
                "id": task.object_id,
            },
            "approved": decision.approved,
            "approval_version": decision.version,
            "reader": request.user.username,
            "identity_source": "request.user",
        })


class ReceiptVerificationView(APIView):
    """Optional internal endpoint for workers to inspect a signed receipt."""

    authentication_classes: list[type] = []
    permission_classes = [permissions.AllowAny]
    issuer: AuthorizationReceiptIssuer | None = None
    board: ApprovalBoard | None = None

    def post(self, request: Any) -> Response:
        assert self.issuer is not None
        token = request.data.get("token") if hasattr(request, "data") else None
        if not token:
            return Response(
                {"valid": False, "reason": "missing_authorization_receipt"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            receipt = self.issuer.verify(token)
        except AuthorizationReceiptError as exc:
            return Response(
                {"valid": False, "reason": exc.reason, "detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        current_approval = None
        if self.board is not None:
            task = self.board.get_task(receipt.scope.attributes.get("task_id", ""))
            decision = self.board.get_decision(task.id) if task is not None else None
            if decision is not None:
                current_approval = {
                    "approved": decision.approved,
                    "version": decision.version,
                    "reason": decision.reason,
                }

        return Response({
            "valid": True,
            "receipt": receipt.public_dict(include_token=False),
            "current_approval": current_approval,
        })


class ApprovalReceiptDemo:
    """Convenience container and request factory for the full scenario."""

    def __init__(self, *, ttl: Any = None) -> None:
        self.board = ApprovalBoard()
        self.ledger = InMemoryAuthorizationReceiptLedger()
        self.issuer = AuthorizationReceiptIssuer(ttl=ttl or 300, ledger=self.ledger)
        self.queue = InMemoryTaskQueue()
        self.business = RecordingBusinessService()
        self.executor = InMemoryExecutor(
            board=self.board,
            queue=self.queue,
            business=self.business,
            issuer=self.issuer,
        )
        self.permission_audit: list[dict[str, Any]] = []
        self.factory = APIRequestFactory()
        self.password = DEFAULT_PASSWORD

    def seed_user(self, username: str = "receipt-approver", password: str | None = None):
        from django.contrib.auth.models import User

        raw_password = password or self.password
        user, _created = User.objects.get_or_create(
            username=username,
            defaults={"email": "", "is_active": True},
        )
        user.is_active = True
        user.set_password(raw_password)
        user.save()
        self.password = raw_password
        return user

    def seed_task(
        self,
        task_id: str = "task-001",
        *,
        operation: str = "approve",
        object_type: str = "approval_subject",
        object_id: str | None = None,
        result_id: str | None = None,
        approved: bool = True,
    ) -> ApprovalTask:
        task = ApprovalTask(
            id=task_id,
            operation=operation,
            object_type=object_type,
            object_id=object_id or f"object-{task_id}",
            result_id=result_id or f"result-{task_id}",
        )
        self.board.add_task(task, ApprovalDecision(approved=approved))
        return task

    def _authorization(
        self,
        user: Any | None,
        username: str | None,
        password: str | None,
        authorization: str | None,
    ) -> dict[str, str]:
        if authorization is not None:
            return {"HTTP_AUTHORIZATION": authorization}
        if user is not None:
            return {"HTTP_AUTHORIZATION": basic_auth_header(
                username or user.username,
                password or self.password,
            )}
        if username is not None:
            return {"HTTP_AUTHORIZATION": basic_auth_header(
                username,
                password or self.password,
            )}
        return {}

    def dispatch(
        self,
        user: Any | None = None,
        task_id: str = "task-001",
        *,
        username: str | None = None,
        password: str | None = None,
        authorization: str | None = None,
    ) -> Response:
        headers = self._authorization(user, username, password, authorization)
        request = self.factory.post(f"/approvals/{task_id}/dispatch/", {}, format="json", **headers)
        view = ApprovalDispatchView.as_view(
            board=self.board,
            issuer=self.issuer,
            queue=self.queue,
            audit=self.permission_audit,
        )
        response = view(request, task_id=task_id)
        response.render()
        return response

    def read(
        self,
        user: Any | None = None,
        task_id: str = "task-001",
        *,
        username: str | None = None,
        password: str | None = None,
        authorization: str | None = None,
    ) -> Response:
        headers = self._authorization(user, username, password, authorization)
        request = self.factory.get(f"/approvals/{task_id}/", **headers)
        view = ApprovalReadView.as_view(board=self.board)
        response = view(request, task_id=task_id)
        response.render()
        return response

    def verify_api(self, token: str) -> Response:
        request = self.factory.post(
            "/authorization-receipts/verify/",
            {"token": token},
            format="json",
        )
        view = ReceiptVerificationView.as_view(issuer=self.issuer, board=self.board)
        response = view(request)
        response.render()
        return response


def build_urlpatterns(demo: ApprovalReceiptDemo | None = None):
    demo = demo or ApprovalReceiptDemo()
    return [
        path(
            "approvals/<str:task_id>/",
            ApprovalReadView.as_view(board=demo.board),
            name="approval-read",
        ),
        path(
            "approvals/<str:task_id>/dispatch/",
            ApprovalDispatchView.as_view(
                board=demo.board,
                issuer=demo.issuer,
                queue=demo.queue,
                audit=demo.permission_audit,
            ),
            name="approval-dispatch",
        ),
        path(
            "authorization-receipts/verify/",
            ReceiptVerificationView.as_view(issuer=demo.issuer, board=demo.board),
            name="authorization-receipt-verify",
        ),
    ]
