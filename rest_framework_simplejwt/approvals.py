"""
Temporary, withdrawable approvals for business operations.

This module lets a service that already uses Simple JWT hand a business a
verifiable, short-lived approval for one concrete operation (for example a
single payment).  The approval is issued after an out-of-band step-up
confirmation and stays independent from ordinary access/refresh credentials:

* refreshing an access token never mints, extends or revives an approval;
* a live approval is bound to the exact operation identifier and amount it was
  issued for;
* withdrawing and consuming race with a clear winner, and the caller can always
  look up what happened to an approval it already used.

The authority for an approval is a database row; the value handed to business
code is a signed ``ApprovalToken`` whose ``jti`` points at that row.  The pair
means an approval can be checked at commit time without re-authenticating the
user, while an already finished operation can still be inspected afterwards.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

from django.conf import settings
from django.db import OperationalError, transaction
from django.utils.translation import gettext_lazy as _

from .exceptions import ExpiredTokenError, TokenError
from .settings import api_settings
from .token_blacklist.models import ApprovalGrant
from .utils import aware_utcnow, datetime_from_epoch

__all__ = [
    "Approval",
    "ApprovalConflict",
    "ApprovalError",
    "ApprovalIncomplete",
    "ApprovalUnavailable",
    "ApprovalUsageMismatch",
    "CommitOutcome",
    "commit_approval",
    "inspect_approval",
    "issue_approval",
    "record_approval_result",
    "withdraw_approval",
]


class ApprovalError(TokenError):
    """Base error for approval operations."""


class ApprovalUnavailable(ApprovalError):
    """The approval is unknown, expired, withdrawn or otherwise not usable."""


class ApprovalUsageMismatch(ApprovalError):
    """The approval does not authorize the operation/amount being committed."""


class ApprovalIncomplete(ApprovalError):
    """
    The approval was already consumed, but no business result was recorded.

    The winner may have paid and then failed while persisting its finance
    record.  Callers must reconcile that side effect themselves and, once
    verified, use :func:`record_approval_result`; they must never pay twice.
    """

    def __init__(self, message: str, grant: ApprovalGrant) -> None:
        super().__init__(message)
        self.grant = grant


class ApprovalConflict(ApprovalError):
    """A concurrent withdrawal/consumption already won."""

    def __init__(self, message: str, grant: ApprovalGrant) -> None:
        super().__init__(message)
        self.grant = grant


# Internal markers stored in ``ApprovalGrant.result``.  They are never exposed
# to callers: ``IN_PROGRESS`` means the winner has claimed the grant and is
# running the business action; ``FAILED`` means the action ran but its result
# could not be recorded and must be reconciled.
_RESULT_IN_PROGRESS = "\x00approval-in-progress"
_RESULT_FAILED = "\x00approval-result-failed"


@dataclass(frozen=True)
class CommitOutcome:
    """
    Result of one :func:`commit_approval` call.

    ``executed`` is true only for the executor that actually ran the business
    operation.  A retry of an approval whose result was already stored returns
    ``executed=False`` together with the original result, so a caller can
    verify what happened without mistaking the replay for a second success.
    """

    approval: Approval
    executed: bool

    def __getattr__(self, name: str) -> Any:
        # Convenience passthrough for status/result/settled access.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.approval, name)


@dataclass(frozen=True)
class Approval:
    """
    Read-only snapshot of an approval, safe to hand to business code.
    """

    token_id: str
    operation: str
    amount: Decimal
    status: str
    result: Optional[str]
    expires_at: datetime
    token: Optional[str] = None

    @property
    def is_live(self) -> bool:
        return self.status == ApprovalGrant.PENDING and self.expires_at > aware_utcnow()

    @property
    def is_settled(self) -> bool:
        """
        True only once the operation actually ran and its result was stored.

        A consumed grant alone is not a completed payment; this distinction
        keeps an authenticated/claimed request from being mistaken for a
        finished business action.
        """
        return (
            self.status == ApprovalGrant.CONSUMED
            and _clean_result(self.result) is not None
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "approval": self.token,
            "operation": self.operation,
            "amount": str(self.amount),
            "status": self.status,
            "result": self.result,
            "settled": self.is_settled,
        }

    def as_commit_dict(self, *, executed: bool) -> dict[str, Any]:
        """
        Commit response payload.

        ``executed`` is false when this call only replayed a previously
        stored result, so a caller never treats an already-completed approval
        as a fresh success.
        """
        data = self.as_dict()
        data["executed"] = executed
        return data


def _require_blacklist_app() -> None:
    if "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS:
        raise ApprovalError(
            _(
                "Approvals require the 'rest_framework_simplejwt.token_blacklist' "
                "app to be installed."
            )
        )


def _normalize_amount(amount: Any) -> Decimal:
    try:
        value = Decimal(str(amount))
    except (InvalidOperation, TypeError, ValueError) as e:
        raise ApprovalUsageMismatch(_("Approval amount is not a valid number")) from e

    if not value.is_finite() or value < 0:
        raise ApprovalUsageMismatch(_("Approval amount is out of range"))

    return value.quantize(Decimal("0.0001"))


def _clean_result(result: Optional[str]) -> Optional[str]:
    if result in (_RESULT_IN_PROGRESS, _RESULT_FAILED):
        return None
    return result


def _snapshot(grant: ApprovalGrant) -> Approval:
    return Approval(
        token_id=grant.token_id,
        operation=grant.operation,
        amount=grant.amount,
        status=grant.status,
        result=_clean_result(grant.result),
        expires_at=grant.expires_at,
        token=grant.token or None,
    )


def _coerce_token_string(value: Any) -> str:
    """
    Accepts either a full signed approval or a snapshot carrying its token.

    A snapshot's ``token_id`` alone is never accepted as a bearer credential;
    only the token string it contains is trusted.
    """
    if isinstance(value, Approval):
        if not value.token:
            raise ApprovalUnavailable(_("Approval not found"))
        return value.token
    if not isinstance(value, str) or not value:
        raise ApprovalUnavailable(_("Approval not found"))
    return value


def _resolve_grant(value: Any) -> ApprovalGrant:
    """
    Resolves a presented approval string to its authoritative database row.

    A valid, signed token is decoded and its ``jti`` is used to find the row.
    An expired token is matched by its exact stored string, which still lets a
    caller reconcile an operation that finished earlier without trusting a
    stale payload.  A bare token id is never a bearer credential.
    """
    source = _coerce_token_string(value)
    token_class = api_settings.APPROVAL_TOKEN_CLASS

    try:
        token_id = token_class(source)[api_settings.JTI_CLAIM]
    except ExpiredTokenError:
        grant = ApprovalGrant.objects.filter(token=source).first()
        if grant is None:
            raise ApprovalUnavailable(_("Approval is invalid")) from None
        return grant
    except TokenError as e:
        raise ApprovalUnavailable(_("Approval is invalid")) from e

    grant = ApprovalGrant.objects.filter(token_id=token_id).first()
    if grant is None:
        raise ApprovalUnavailable(_("Approval not found"))
    return grant


def issue_approval(user, operation: str, amount: Any, *, lifetime=None) -> Approval:
    """
    Issues a fresh approval for one operation and amount.

    The caller is expected to have completed whatever extra confirmation the
    business requires before calling this.  The returned object carries the
    ``token`` string that the business later presents to
    :func:`withdraw_approval`, :func:`commit_approval` or
    :func:`inspect_approval`.
    """
    _require_blacklist_app()

    operation = str(operation)
    if not operation:
        raise ApprovalUsageMismatch(_("Approval operation is required"))

    value = _normalize_amount(amount)

    user_id = getattr(user, api_settings.USER_ID_FIELD, None)
    state = getattr(user, "_state", None)
    if user_id is None or (state is not None and state.adding):
        raise ApprovalUsageMismatch(_("Approval requires a persisted user"))

    token_class = api_settings.APPROVAL_TOKEN_CLASS

    token = token_class.for_approval(user, operation, value)
    if lifetime is not None:
        token.set_exp(from_time=token.current_time, lifetime=lifetime)

    token_id = token[api_settings.JTI_CLAIM]
    encoded = str(token)

    grant = ApprovalGrant.objects.create(
        token_id=token_id,
        token=encoded,
        user=user if user_id is not None else None,
        operation=operation,
        amount=value,
        status=ApprovalGrant.PENDING,
        expires_at=datetime_from_epoch(token["exp"]),
    )
    return _snapshot(grant)


def inspect_approval(value: str) -> Approval:
    """
    Returns the recorded state of an approval.

    Consumed and withdrawn history is returned as-is so callers can reconcile
    a result from an earlier run instead of trusting a fresh authentication.
    """
    _require_blacklist_app()
    return _snapshot(_resolve_grant(value))


def withdraw_approval(value: str) -> Approval:
    """
    Withdraws a pending approval and returns its now-withdrawn snapshot.

    Raises :class:`ApprovalConflict` if it was consumed first and
    :class:`ApprovalUnavailable` if it is unknown; both leave the caller able
    to inspect the outcome.
    """
    _require_blacklist_app()

    source = _coerce_token_string(value)
    grant = _resolve_grant(source)

    now = aware_utcnow()
    with transaction.atomic():
        updated = ApprovalGrant.objects.filter(
            pk=grant.pk, status=ApprovalGrant.PENDING, expires_at__gt=now
        ).update(status=ApprovalGrant.WITHDRAWN, withdrawn_at=now)

    current = ApprovalGrant.objects.get(pk=grant.pk)
    if not updated:
        if current.status == ApprovalGrant.CONSUMED:
            raise ApprovalConflict(_("Approval was already consumed"), current)
        if current.status == ApprovalGrant.WITHDRAWN:
            raise ApprovalConflict(_("Approval was already withdrawn"), current)
        raise ApprovalUnavailable(_("Approval has expired"))

    return _snapshot(current)


def _check_usage(grant: ApprovalGrant, operation: str, value: Decimal) -> None:
    if grant.operation != operation:
        raise ApprovalUsageMismatch(_("Approval is not valid for this operation"))
    if grant.amount != value:
        raise ApprovalUsageMismatch(_("Approval is not valid for this amount"))


def _claim(grant: ApprovalGrant) -> None:
    """
    Flips a pending grant to consumed; exactly one caller can observe a change.

    The predicate and the write happen in one statement so a concurrent
    withdraw/claim on any backend resolves to a single winner instead of a
    lost-update read-then-write race.
    """
    now = aware_utcnow()
    claimed = ApprovalGrant.objects.filter(
        pk=grant.pk, status=ApprovalGrant.PENDING, expires_at__gt=now
    ).update(
        status=ApprovalGrant.CONSUMED,
        consumed_at=now,
        result=_RESULT_IN_PROGRESS,
    )
    if not claimed:
        current = ApprovalGrant.objects.get(pk=grant.pk)
        raise _loss_error(current)


def _loss_error(grant: ApprovalGrant) -> ApprovalError:
    if grant.status == ApprovalGrant.CONSUMED:
        return ApprovalConflict(_("Approval was already consumed"), grant)
    if grant.status == ApprovalGrant.WITHDRAWN:
        return ApprovalUnavailable(_("Approval has been withdrawn"))
    return ApprovalUnavailable(_("Approval has expired"))


def commit_approval(
    value: str,
    *,
    operation: str,
    amount: Any,
    operation_runner,
) -> CommitOutcome:
    """
    Consumes an approval and runs ``operation_runner`` exactly once.

    The approval is validated for the exact ``operation`` and ``amount`` and
    then claimed with a single conditional update, so a concurrent withdrawal
    (or a second executor holding the same approval) loses with
    :class:`ApprovalConflict` / :class:`ApprovalUnavailable`.

    ``operation_runner`` runs only for the winner and only after the claim is
    committed, so a failed business write can never be retried into a second
    charge.  Retrying an approval whose result was stored replays that result
    without invoking ``operation_runner`` again; retrying one that was consumed
    but never recorded raises :class:`ApprovalIncomplete` for the caller to
    reconcile.
    """
    _require_blacklist_app()

    operation = str(operation)
    value_amount = _normalize_amount(amount)
    _source = _coerce_token_string(value)
    grant = _resolve_grant(_source)

    _check_usage(grant, operation, value_amount)

    if grant.status == ApprovalGrant.CONSUMED:
        if grant.result == _RESULT_IN_PROGRESS:
            raise ApprovalConflict(_("Approval is being committed"), grant)
        if _clean_result(grant.result) is not None:
            return CommitOutcome(_snapshot(grant), executed=False)
        if grant.result == _RESULT_FAILED:
            raise ApprovalIncomplete(
                _("Approval ran but its result was not recorded"), grant
            )
        raise ApprovalIncomplete(_("Approval was consumed but not recorded"), grant)

    if grant.status == ApprovalGrant.WITHDRAWN:
        raise ApprovalUnavailable(_("Approval has been withdrawn"))

    if grant.expires_at <= aware_utcnow():
        raise ApprovalUnavailable(_("Approval has expired"))

    _claim(grant)

    try:
        result = operation_runner(_snapshot(grant))
    except Exception:
        _mark_result_failed(grant.pk)
        raise

    _store_result(grant.pk, result if isinstance(result, str) else str(result))
    return CommitOutcome(inspect_approval(_source), executed=True)


def _mark_result_failed(pk: int, attempts: int = 5) -> None:
    """
    Durably records that the winning executor ran but could not store a result.

    This must not be best-effort: if the marker were lost, the grant would stay
    "in progress" forever and later reconciliation could not proceed.  The DB
    write is retried through transient lock contention.
    """
    for attempt in range(1, attempts + 1):
        try:
            ApprovalGrant.objects.filter(pk=pk).update(result=_RESULT_FAILED)
            return
        except OperationalError:
            if attempt == attempts:
                raise
            time.sleep(0.01 * attempt)


def _store_result(pk: int, text: str, attempts: int = 5) -> None:
    for attempt in range(1, attempts + 1):
        try:
            ApprovalGrant.objects.filter(pk=pk).update(result=text)
            return
        except OperationalError:
            if attempt == attempts:
                raise
            time.sleep(0.01 * attempt)


def record_approval_result(value: str, result: Any) -> Approval:
    """
    Stores the business result for an already-consumed approval.

    This is the reconciliation path for a payment that succeeded while its
    finance record failed to write: it records the known result without
    running the operation again.  It refuses withdrawn or still-pending
    approvals so it cannot be used to manufacture authority.
    """
    _require_blacklist_app()

    source = _coerce_token_string(value)
    grant = _resolve_grant(source)
    text = result if isinstance(result, str) else str(result)

    current = ApprovalGrant.objects.get(pk=grant.pk)
    if current.status != ApprovalGrant.CONSUMED:
        raise ApprovalUnavailable(_("Approval has not been consumed"))
    if current.result == _RESULT_IN_PROGRESS:
        raise ApprovalConflict(_("Approval is being committed"), current)

    _store_result(current.pk, text)
    return inspect_approval(source)
