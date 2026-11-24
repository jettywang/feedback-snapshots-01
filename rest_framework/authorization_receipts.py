"""Optional authorization receipts for work that continues outside a request.

A receipt is issued only after DRF authentication and permission checks have
run.  It deliberately contains a non-secret subject reference rather than the
request's credentials or ``request.auth`` material.  The signed token lets a
worker verify integrity and expiry; the ledger gives applications a reviewable
record of the issued scope and result identifier.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Mapping
from uuid import uuid4

from django.core import signing
from django.utils import timezone


RECEIPT_SALT = "rest_framework.authorization-receipt.v1"
DEFAULT_RECEIPT_TTL = timedelta(minutes=5)

__all__ = [
    "AuthorizationReceipt",
    "AuthorizationReceiptError",
    "AuthorizationReceiptIssuer",
    "AuthorizationReceiptService",
    "AuthorizationReceiptVerifier",
    "AuthorizationScope",
    "ExpiredAuthorizationReceipt",
    "InMemoryAuthorizationReceiptLedger",
    "InvalidAuthorizationReceipt",
    "ReceiptIdentityError",
    "ReceiptIssuer",
    "ReceiptLedger",
    "ReceiptScopeMismatch",
    "ReceiptVerifier",
    "actor_identifier_for_user",
    "subject_reference_for_user",
]


class AuthorizationReceiptError(Exception):
    """Base class for receipt verification failures."""

    reason = "invalid_authorization_receipt"


class ReceiptIdentityError(AuthorizationReceiptError):
    reason = "unauthenticated_receipt_identity"


class InvalidAuthorizationReceipt(AuthorizationReceiptError):
    reason = "invalid_authorization_receipt"


class ExpiredAuthorizationReceipt(AuthorizationReceiptError):
    reason = "expired_authorization_receipt"


class ReceiptScopeMismatch(AuthorizationReceiptError):
    reason = "authorization_scope_mismatch"


def subject_reference_for_user(user: Any) -> str:
    """Return the stable, non-credential identifier stored in a receipt."""
    if user is None or not getattr(user, "is_authenticated", False):
        raise ReceiptIdentityError("An authenticated request user is required.")

    primary_key = getattr(user, "pk", None)
    if primary_key is None:
        primary_key = getattr(user, "id", None)
    if primary_key is not None:
        return f"user:{primary_key}"

    username = getattr(user, "username", None)
    if callable(username):
        username = username()
    if not username and hasattr(user, "get_username"):
        username = user.get_username()
    if username:
        return f"username:{username}"

    raise ReceiptIdentityError("Authenticated user has no disclosable identifier.")


def actor_identifier_for_user(user: Any) -> str | None:
    """Return a human-reviewable account identifier without reading credentials."""
    username = getattr(user, "username", None)
    if username is not None and not isinstance(username, str):
        username = str(username)
    if not username and hasattr(user, "get_username"):
        username = user.get_username()
    return username or None


@dataclass(frozen=True)
class AuthorizationScope:
    """Operation and object boundary authorized by the originating request."""

    operation: str
    object_type: str
    object_id: str
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", dict(self.attributes))

    def matches(
        self,
        expected: "AuthorizationScope | Mapping[str, Any] | None" = None,
        **kwargs: Any,
    ) -> bool:
        if expected is not None:
            if isinstance(expected, AuthorizationScope):
                values = {
                    "operation": expected.operation,
                    "object_type": expected.object_type,
                    "object_id": expected.object_id,
                }
                attributes = expected.attributes
            elif isinstance(expected, Mapping):
                values = {
                    key: expected.get(key)
                    for key in ("operation", "object_type", "object_id")
                    if key in expected
                }
                attributes = expected.get("attributes") or {}
            else:
                raise TypeError("expected scope must be an AuthorizationScope or mapping")
        else:
            values = {}
            attributes = {}

        values.update(kwargs)
        for key, expected_value in values.items():
            if expected_value is not None and getattr(self, key) != expected_value:
                return False

        for key, expected_value in dict(attributes).items():
            if self.attributes.get(key) != expected_value:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class AuthorizationReceipt:
    """Verifiable identity, scope, lifetime and idempotent result reference."""

    receipt_id: str
    subject_ref: str
    scope: AuthorizationScope
    result_id: str
    issued_at: datetime
    expires_at: datetime
    token: str = ""
    actor: str | None = None
    decision: str = "approved"
    approval_version: str | int | None = None
    auth_scheme: str | None = None

    @property
    def id(self) -> str:
        return self.receipt_id

    @property
    def operation(self) -> str:
        return self.scope.operation

    @property
    def object_type(self) -> str:
        return self.scope.object_type

    @property
    def object_id(self) -> str:
        return self.scope.object_id

    @property
    def idempotency_key(self) -> str:
        return self.result_id

    def is_expired_at(self, moment: datetime | None = None) -> bool:
        moment = moment or timezone.now()
        return moment >= self.expires_at

    def public_dict(self, *, include_token: bool = True) -> dict[str, Any]:
        ttl_seconds = int((self.expires_at - self.issued_at).total_seconds())
        data: dict[str, Any] = {
            "id": self.receipt_id,
            "receipt_id": self.receipt_id,
            "jti": self.receipt_id,
            "subject_ref": self.subject_ref,
            "actor": self.actor,
            "identity": {
                "subject_ref": self.subject_ref,
                "actor": self.actor,
                "auth_scheme": self.auth_scheme,
            },
            "operation": self.operation,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "scope": self.scope.to_dict(),
            "result_id": self.result_id,
            "idempotency_key": self.result_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ttl_seconds": ttl_seconds,
            "decision": self.decision,
            "approval_version": self.approval_version,
            "authorization": {
                "decision": self.decision,
                "approval_version": self.approval_version,
            },
            "auth_scheme": self.auth_scheme,
        }
        if include_token and self.token:
            data["token"] = self.token
        return data

    to_dict = public_dict


class InMemoryAuthorizationReceiptLedger:
    """Thread-safe reviewable receipt ledger for single-process workers."""

    def __init__(self) -> None:
        self._receipts: dict[str, AuthorizationReceipt] = {}
        self._lock = threading.RLock()

    def add(self, receipt: AuthorizationReceipt) -> AuthorizationReceipt:
        with self._lock:
            if receipt.receipt_id in self._receipts:
                raise ValueError(f"Receipt already exists: {receipt.receipt_id}")
            self._receipts[receipt.receipt_id] = receipt
            return receipt

    def get(self, receipt_id: str) -> AuthorizationReceipt:
        return self._receipts[receipt_id]

    def all(self) -> tuple[AuthorizationReceipt, ...]:
        with self._lock:
            return tuple(self._receipts.values())

    def __len__(self) -> int:
        return len(self._receipts)


ReceiptLedger = InMemoryAuthorizationReceiptLedger


class AuthorizationReceiptIssuer:
    """Issue signed receipts from an authenticated DRF request."""

    salt = RECEIPT_SALT

    def __init__(
        self,
        *,
        ttl: timedelta | int | float = DEFAULT_RECEIPT_TTL,
        ledger: InMemoryAuthorizationReceiptLedger | None = None,
        signer_key: str | None = None,
        clock: Any = timezone.now,
        subject_resolver: Any = None,
    ) -> None:
        self.ttl = self._coerce_ttl(ttl)
        self.ledger = ledger if ledger is not None else InMemoryAuthorizationReceiptLedger()
        self.signer_key = signer_key
        self.clock = clock
        self.subject_resolver = subject_resolver or subject_reference_for_user

    @staticmethod
    def _coerce_ttl(ttl: timedelta | int | float) -> timedelta:
        if isinstance(ttl, timedelta):
            return ttl
        return timedelta(seconds=ttl)

    def issue_for_request(self, request: Any, **kwargs: Any) -> AuthorizationReceipt:
        user = getattr(request, "user", None)
        subject_ref = self.subject_resolver(user)
        actor = actor_identifier_for_user(user)

        authenticator = None
        try:
            authenticator = request.successful_authenticator
        except Exception:  # pragma: no cover - defensive for non-DRF request doubles
            authenticator = None
        auth_scheme = type(authenticator).__name__ if authenticator is not None else None

        return self.issue(
            subject_ref=subject_ref,
            actor=actor,
            auth_scheme=auth_scheme,
            **kwargs,
        )

    def issue(
        self,
        *,
        operation: str,
        object_type: str,
        object_id: str,
        result_id: str,
        subject_ref: str,
        scope_attributes: Mapping[str, Any] | None = None,
        attributes: Mapping[str, Any] | None = None,
        actor: str | None = None,
        decision: str = "approved",
        approval_version: str | int | None = None,
        auth_scheme: str | None = None,
        ttl: timedelta | int | float | None = None,
        issued_at: datetime | None = None,
    ) -> AuthorizationReceipt:
        moment = issued_at or self.clock()
        lifetime = self._coerce_ttl(ttl) if ttl is not None else self.ttl
        expires_at = moment + lifetime
        receipt_id = f"rcpt_{uuid4().hex}"
        merged_attributes = dict(scope_attributes or {})
        merged_attributes.update(attributes or {})
        scope = AuthorizationScope(
            operation=operation,
            object_type=object_type,
            object_id=str(object_id),
            attributes=merged_attributes,
        )

        payload = {
            "v": 1,
            "jti": receipt_id,
            "sub": subject_ref,
            "actor": actor,
            "op": operation,
            "obj_type": object_type,
            "obj_id": str(object_id),
            "attrs": dict(scope.attributes),
            "rid": result_id,
            "iat": moment.isoformat(),
            "exp": expires_at.isoformat(),
            "decision": decision,
            "apv": approval_version,
            "auth": auth_scheme,
        }
        token = signing.dumps(payload, key=self.signer_key, salt=self.salt)
        receipt = AuthorizationReceipt(
            receipt_id=receipt_id,
            subject_ref=subject_ref,
            actor=actor,
            scope=scope,
            result_id=result_id,
            issued_at=moment,
            expires_at=expires_at,
            token=token,
            decision=decision,
            approval_version=approval_version,
            auth_scheme=auth_scheme,
        )
        self.ledger.add(receipt)
        return receipt

    def verify(
        self,
        token_or_receipt: str | AuthorizationReceipt,
        *,
        expected_scope: AuthorizationScope | Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> AuthorizationReceipt:
        if isinstance(token_or_receipt, AuthorizationReceipt):
            token = token_or_receipt.token
        else:
            token = token_or_receipt

        try:
            payload = signing.loads(token, key=self.signer_key, salt=self.salt)
        except signing.BadSignature as exc:
            raise InvalidAuthorizationReceipt("Receipt signature is invalid.") from exc

        try:
            scope = AuthorizationScope(
                operation=payload["op"],
                object_type=payload["obj_type"],
                object_id=payload["obj_id"],
                attributes=payload.get("attrs", {}),
            )
            issued_at = datetime.fromisoformat(payload["iat"])
            expires_at = datetime.fromisoformat(payload["exp"])
            receipt = AuthorizationReceipt(
                receipt_id=payload["jti"],
                subject_ref=payload["sub"],
                actor=payload.get("actor"),
                scope=scope,
                result_id=payload["rid"],
                issued_at=issued_at,
                expires_at=expires_at,
                token=token,
                decision=payload.get("decision", "approved"),
                approval_version=payload.get("apv"),
                auth_scheme=payload.get("auth"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidAuthorizationReceipt("Receipt claims are malformed.") from exc

        moment = now or self.clock()
        if receipt.is_expired_at(moment):
            raise ExpiredAuthorizationReceipt("Authorization receipt has expired.")

        if expected_scope is not None and not scope.matches(expected_scope):
            raise ReceiptScopeMismatch(
                f"Receipt scope {scope.to_dict()} does not match {expected_scope!r}."
            )

        return receipt


AuthorizationReceiptService = AuthorizationReceiptIssuer
AuthorizationReceiptVerifier = AuthorizationReceiptIssuer
ReceiptIssuer = AuthorizationReceiptIssuer
ReceiptVerifier = AuthorizationReceiptIssuer
