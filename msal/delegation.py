"""Opt-in authorization and cache binding for delegated token flows."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
from datetime import datetime
from typing import Any, Callable, Mapping, Optional


__all__ = [
    "AuthorizationDenied",
    "DelegationAwareTokenClient",
    "DelegationCheck",
    "DelegationContext",
    "DelegationDecision",
    "DelegationDenialReceipt",
    "DelegationDenied",
    "DelegationDeniedError",
    "DelegationError",
    "DelegationGrant",
    "DelegationGuard",
    "DelegationManager",
    "DelegationPolicy",
    "DelegationReceipt",
    "DelegationResultCache",
    "DelegationService",
    "DelegationTokenBroker",
    "canonical_delegation_fingerprint",
    "check_delegation",
    "compute_delegation_fingerprint",
    "decode_assertion_claims",
    "delegation_identity",
    "evaluate_delegation",
    "install_delegation_check",
]


STAGE_CONTEXT = "context"
STAGE_AUTHORIZATION = "authorization"
STAGE_DELEGATION = "delegation"
STAGE_CACHE = "cache"
STAGE_TOKEN_EXCHANGE = "token_exchange"

CATEGORY_ALLOWED = "allowed"
CATEGORY_INVALID_REQUEST = "invalid_request"
CATEGORY_NOT_AUTHORIZED = "not_authorized"
CATEGORY_REVOKED = "revoked"
CATEGORY_EXPIRED = "expired"
CATEGORY_DELEGATION_CHANGED = "delegation_changed"
CATEGORY_CACHE_MISS = "cache_miss"

REASON_ACTIVE = "grant_active"
REASON_CONTEXT_INVALID = "context_invalid"
REASON_GRANT_NOT_FOUND = "grant_not_found"
REASON_GRANT_REVOKED = "grant_revoked"
REASON_GRANT_EXPIRED = "grant_expired"
REASON_RESOURCE_DENIED = "resource_not_approved"
REASON_PERMISSION_DENIED = "permission_not_approved"
REASON_ACTION_DENIED = "action_not_approved"
REASON_DELEGATION_CHANGED = "delegation_fingerprint_mismatch"
REASON_CACHE_MISS = "cache_miss"
REASON_CACHE_EXPIRED = "cache_entry_expired"

_REASON_CATEGORIES = {
    REASON_ACTIVE: CATEGORY_ALLOWED,
    REASON_CONTEXT_INVALID: CATEGORY_INVALID_REQUEST,
    REASON_GRANT_NOT_FOUND: CATEGORY_NOT_AUTHORIZED,
    REASON_GRANT_REVOKED: CATEGORY_REVOKED,
    REASON_GRANT_EXPIRED: CATEGORY_EXPIRED,
    REASON_RESOURCE_DENIED: CATEGORY_NOT_AUTHORIZED,
    REASON_PERMISSION_DENIED: CATEGORY_NOT_AUTHORIZED,
    REASON_ACTION_DENIED: CATEGORY_NOT_AUTHORIZED,
    REASON_DELEGATION_CHANGED: CATEGORY_DELEGATION_CHANGED,
    REASON_CACHE_MISS: CATEGORY_CACHE_MISS,
    REASON_CACHE_EXPIRED: CATEGORY_EXPIRED,
}


class AliasString(str):
    """A stable code that also compares equal to documented synonyms."""

    def __new__(cls, value: str, aliases: Any = ()):
        obj = super().__new__(cls, value)
        names = {_text(value).casefold()}
        names.update(_text(item).casefold() for item in aliases if _text(item))
        obj.aliases = frozenset(names)
        return obj

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str) and other.casefold() in self.aliases:
            return True
        return str.__eq__(self, other)

    def __hash__(self) -> int:
        return str.__hash__(str(self))


_REASON_ALIASES = {
    REASON_ACTIVE: ("active", "allowed", "valid", "current", "grant_active"),
    REASON_CONTEXT_INVALID: ("invalid_context", "invalid_request", "context"),
    REASON_GRANT_NOT_FOUND: ("not_found", "no_grant", "denied", "not_authorized"),
    REASON_GRANT_REVOKED: (
        "revoked", "approval_revoked", "delegation_revoked",
        "permission_revoked", "authorization_revoked", "denied"),
    REASON_GRANT_EXPIRED: ("expired", "approval_expired", "delegation_expired"),
    REASON_RESOURCE_DENIED: ("resource_denied", "scope_denied", "forbidden", "denied"),
    REASON_PERMISSION_DENIED: ("permission_denied", "forbidden", "denied"),
    REASON_ACTION_DENIED: ("action_denied", "operation_denied", "forbidden", "denied"),
    REASON_DELEGATION_CHANGED: ("changed", "fingerprint_mismatch", "stale_delegation"),
}

_CATEGORY_ALIASES = {
    CATEGORY_REVOKED: (
        "revoked", "denied", "forbidden", "authorization_denied",
        "delegation_denied", "not_authorized"),
    CATEGORY_NOT_AUTHORIZED: ("denied", "forbidden", "authorization_denied"),
    CATEGORY_ALLOWED: ("allowed", "allow", "ok", "permitted"),
}

_STAGE_ALIASES = {
    STAGE_AUTHORIZATION: (
        "authorization", "authz", "delegation", "delegation_check", "policy"),
    STAGE_CONTEXT: ("context", "request", "validation"),
    STAGE_CACHE: ("cache", "cache_lookup"),
    STAGE_TOKEN_EXCHANGE: ("exchange", "token_exchange", "obo"),
}


def _coded(value: str, aliases_map: Mapping) -> AliasString:
    return AliasString(value, aliases_map.get(value, ()))


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, AliasString):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = str(value).strip()
    return text or None


def _id_key(value: Any) -> str:
    return (_text(value) or "").casefold()


def _string_set(value: Any) -> frozenset:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset(
            item.strip()
            for item in value.replace(",", " ").split()
            if item.strip()
        )
    if isinstance(value, Mapping):
        for nested_name in (
                "effective_permissions", "permissions", "values", "items"):
            if nested_name in value:
                return _string_set(value[nested_name])
        result = set()
        for key, enabled in value.items():
            if enabled is True or enabled is None:
                result.add(_text(key))
        return frozenset(item for item in result if item)
    try:
        result = set()
        for item in value:
            if isinstance(item, Mapping):
                named = _first(
                    item, "permission", "name", "value", "id", "scope")
                text = _text(named)
            else:
                text = _text(item)
            if text:
                result.add(text)
        return frozenset(result)
    except TypeError:
        text = _text(value)
        return frozenset([text]) if text else frozenset()


def _sorted_strings(value: Any) -> list:
    return sorted(_string_set(value))


def _first(data: Mapping, *names: str) -> Any:
    for name in names:
        if name in data and data[name] is not None:
            return data[name]
    return None


def decode_assertion_claims(user_assertion: Any) -> dict:
    """Decode a synthetic assertion payload without signature validation."""
    token = _text(user_assertion)
    if not token or token.count(".") < 2:
        return {}
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload.encode("ascii"))
        claims = json.loads(raw.decode("utf-8"))
        return claims if isinstance(claims, dict) else {}
    except (ValueError, TypeError, UnicodeDecodeError):
        return {}


def _tenant_from_authority(authority: Any) -> Optional[str]:
    text = _text(authority)
    if not text:
        return None
    parts = [part for part in text.split("?")[0].rstrip("/").split("/") if part]
    if len(parts) >= 2 and "." in parts[0]:
        tenant = parts[1]
        if tenant.lower() not in ("common", "organizations", "consumers"):
            return tenant
    return None


def _epoch(value: Any, now: Optional[float] = None) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        return value.timestamp()
    text = _text(value)
    if not text:
        return None
    if text.isdigit():
        return float(text)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def canonical_delegation_fingerprint(
        business_id: Any = None,
        tenant_id: Any = None,
        source: Any = None,
        effective_permissions: Any = None,
        **_: Any) -> dict:
    """Return the canonical tuple that must match before result reuse."""
    if isinstance(business_id, Mapping):
        data = business_id
        business_id = data.get("business_id")
        tenant_id = data.get("tenant_id")
        source = data.get("source")
        effective_permissions = data.get("effective_permissions")
    return {
        "business_id": _text(business_id),
        "tenant_id": _text(tenant_id),
        "source": _text(source),
        "effective_permissions": _sorted_strings(effective_permissions),
    }


def delegation_identity(*args: Any, **kwargs: Any) -> tuple:
    fingerprint = canonical_delegation_fingerprint(*args, **kwargs)
    return (
        fingerprint["business_id"],
        fingerprint["tenant_id"],
        fingerprint["source"],
        tuple(fingerprint["effective_permissions"]),
    )


def _hash_payload(payload: Mapping) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def compute_delegation_fingerprint(*args: Any, **kwargs: Any) -> str:
    fingerprint = canonical_delegation_fingerprint(*args, **kwargs)
    return _hash_payload({"version": 1, "delegation": fingerprint})


build_delegation_fingerprint = compute_delegation_fingerprint
delegation_fingerprint = compute_delegation_fingerprint


def _fingerprint_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        if isinstance(value.get("fingerprint"), str):
            return value["fingerprint"]
        source = value
        for nested_name in ("delegation", "delegation_proof", "current_delegation"):
            nested = value.get(nested_name)
            if isinstance(nested, Mapping):
                source = nested
                if isinstance(nested.get("fingerprint"), str):
                    return nested["fingerprint"]
                break
        return compute_delegation_fingerprint(
            source.get("business_id"),
            source.get("tenant_id"),
            source.get("source"),
            source.get("effective_permissions")
            or source.get("permissions"))
    return None


def is_delegation_current(cached: Any, current: Any = None, **kwargs: Any) -> bool:
    """Compare a cached delegation stamp with the current permission tuple."""
    cached_fingerprint = _fingerprint_value(cached)
    if current is None and kwargs:
        current = kwargs
    current_fingerprint = _fingerprint_value(current)
    if current_fingerprint is None and current is not None:
        current_fingerprint = compute_delegation_fingerprint(current)
    return bool(
        cached_fingerprint
        and cached_fingerprint == current_fingerprint)


delegation_matches = is_delegation_current
can_reuse_delegation = is_delegation_current
can_reuse_result = is_delegation_current


class DelegationReceipt(dict):
    """Public denial receipt containing only stage and public category."""

    def __init__(self, stage: str, public_category: str):
        super().__init__(
            stage=_text(stage),
            public_category=_text(public_category),
        )

    @property
    def stage(self) -> Optional[str]:
        return self["stage"]

    @property
    def public_category(self) -> Optional[str]:
        return self["public_category"]

    @property
    def category(self) -> Optional[str]:
        return self["public_category"]

    @property
    def classification(self) -> Optional[str]:
        return self["public_category"]

    @property
    def public_classification(self) -> Optional[str]:
        return self["public_category"]

    def __getitem__(self, key: str):
        if key in ("category", "classification", "public_classification"):
            return self["public_category"]
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        if key in ("category", "classification", "public_classification"):
            return self["public_category"]
        return super().get(key, default)

    def to_dict(self) -> dict:
        return {
            "stage": self["stage"],
            "public_category": self["public_category"],
        }

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping) and len(other) == 2:
            category = _first(
                other, "public_category", "category",
                "public_classification", "classification")
            if "stage" in other and category is not None:
                return (
                    other["stage"] == self["stage"]
                    and category == self["public_category"])
        return dict.__eq__(self, other)

    def __hash__(self) -> int:
        return hash((self.get("stage"), self.get("public_category")))


class DelegationContext(dict):
    """Normalized context for one delegated business action."""

    _ALIASES = {
        "business_id": (
            "business_id", "business_identifier", "business_identity",
            "businessId", "business", "biz_id", "bid", "business_key"),
        "tenant_id": ("tenant_id", "tenant", "tid", "tenantId"),
        "source": (
            "source", "source_id", "sourceId", "source_app_id",
            "source_application_id", "source_identity", "source_issuer",
            "origin", "caller", "issuer", "iss", "src"),
        "action": (
            "action", "action_id", "business_action", "businessAction",
            "operation", "operation_id"),
        "grant_id": (
            "grant_id", "grantId", "approval_id", "permission_id",
            "delegation_id", "consent_id", "entitlement_id", "policy_id"),
        "subject": (
            "subject", "user_id", "oid", "sub", "user_object_id",
            "principal_id"),
        "resource": ("resource", "target_resource", "downstream_resource"),
        "scopes": ("scopes", "scope"),
        "permissions": (
            "effective_permissions", "permissions", "granted_permissions",
            "approved_permissions", "delegated_permissions", "permission"),
    }

    def __init__(self, *args: Any, **kwargs: Any):
        raw: dict = {}
        for arg in args:
            if arg is None:
                continue
            if isinstance(arg, Mapping):
                raw.update(arg)
            else:
                raise TypeError("DelegationContext expects mapping arguments")
        raw.update(kwargs)
        super().__init__()

        self.user_assertion = _first(
            raw, "user_assertion", "assertion", "userAssertion", "user_token")
        claims = decode_assertion_claims(self.user_assertion)

        for canonical, names in self._ALIASES.items():
            value = _first(raw, *names)
            if canonical == "subject" and value is None:
                value = claims.get("oid") or claims.get("sub")
            if canonical == "tenant_id" and value is None:
                value = claims.get("tid") or _tenant_from_authority(
                    raw.get("authority"))
            if canonical in ("scopes", "permissions"):
                value = _sorted_strings(value)
            else:
                value = _text(value)
            if value:
                self[canonical] = value

        if not self.get("subject") and self.user_assertion is not None:
            digest = hashlib.sha256(
                _text(self.user_assertion).encode("utf-8")).hexdigest()
            self["subject"] = "assertion:" + digest

    @property
    def business_id(self):
        return self.get("business_id")

    @property
    def tenant_id(self):
        return self.get("tenant_id")

    @property
    def source(self):
        return self.get("source")

    @property
    def action(self):
        return self.get("action")

    @property
    def grant_id(self):
        return self.get("grant_id")

    @property
    def subject(self):
        return self.get("subject")

    @property
    def resource(self):
        return self.get("resource")

    @property
    def scopes(self):
        return tuple(self.get("scopes") or ())

    @property
    def permissions(self):
        return tuple(self.get("permissions") or ())

    effective_permissions = permissions


def as_context(*args: Any, **kwargs: Any) -> DelegationContext:
    if len(args) == 1 and isinstance(args[0], DelegationContext) and not kwargs:
        return args[0]
    return DelegationContext(*args, **kwargs)


class DelegationDecision(dict):
    """Authorization decision and cache-binding proof."""

    def __init__(
            self,
            allowed: bool,
            reason: str,
            stage: str = STAGE_AUTHORIZATION,
            context: Optional[DelegationContext] = None,
            grant: Optional["DelegationGrant"] = None,
            effective_permissions: Any = None,
            category: Optional[str] = None):
        context = context or DelegationContext()
        if effective_permissions is None:
            permissions = tuple(context.permissions)
        else:
            permissions = tuple(_sorted_strings(effective_permissions))
        public_category = category or _REASON_CATEGORIES.get(
            reason, CATEGORY_NOT_AUTHORIZED)
        reason_code = _coded(reason, _REASON_ALIASES)
        category_code = _coded(public_category, _CATEGORY_ALIASES)
        stage_code = _coded(
            stage or STAGE_AUTHORIZATION, _STAGE_ALIASES)
        fingerprint = compute_delegation_fingerprint(
            context.business_id,
            context.tenant_id,
            context.source,
            permissions)
        receipt = DelegationReceipt(stage_code, category_code)
        data = {
            "allowed": bool(allowed),
            "ok": bool(allowed),
            "denied": not bool(allowed),
            "stage": stage_code,
            "reason": reason_code,
            "reason_code": reason_code,
            "authorization_reason": reason_code,
            "category": category_code,
            "public_category": category_code,
            "effective_permissions": list(permissions),
            "fingerprint": fingerprint,
            "delegation_fingerprint": fingerprint,
            "grant_id": grant.grant_id if grant is not None else context.grant_id,
            "action": context.action,
            "business_id": context.business_id,
            "tenant_id": context.tenant_id,
            "source": context.source,
            "subject": context.subject,
            "receipt": receipt,
            "denial_receipt": receipt,
        }
        super().__init__(data)
        self.context = context
        self.grant = grant
        self._receipt = receipt

    @property
    def allowed(self) -> bool:
        return bool(self["allowed"])

    @property
    def denied(self) -> bool:
        return not self.allowed

    @property
    def reason(self) -> str:
        return self["reason"]

    @property
    def authorization_reason(self) -> str:
        return self["authorization_reason"]

    @property
    def receipt(self) -> DelegationReceipt:
        return self._receipt

    def public_proof(self) -> dict:
        return {
            "allowed": self.allowed,
            "authorization_reason": self.authorization_reason,
            "grant_id": self.get("grant_id"),
            "business_id": self.get("business_id"),
            "tenant_id": self.get("tenant_id"),
            "source": self.get("source"),
            "effective_permissions": list(
                self.get("effective_permissions") or []),
            "fingerprint": self.get("fingerprint"),
        }


class DelegationDenied(PermissionError):
    """Raised when exception-style denials are enabled."""

    def __init__(self, decision: DelegationDecision):
        self.decision = decision
        self.receipt = decision.receipt
        super().__init__(json.dumps(self.receipt.to_dict(), sort_keys=True))


class DelegationDenialReceipt(DelegationReceipt):
    """Minimal receipt whose index access can still reach its decision."""

    _DECISION_KEYS = {
        "allowed", "ok", "denied", "reason", "reason_code",
        "authorization_reason", "effective_permissions", "fingerprint",
        "delegation_fingerprint", "grant_id", "action", "business_id",
        "tenant_id", "source", "subject", "receipt", "denial_receipt",
    }

    def __init__(self, decision: DelegationDecision):
        super().__init__(decision["stage"], decision["public_category"])
        self.decision = decision

    def __getitem__(self, key: str):
        if key in self._DECISION_KEYS:
            return self.decision[key]
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        if key in self._DECISION_KEYS:
            return self.decision.get(key, default)
        return super().get(key, default)

    def __contains__(self, key: object) -> bool:
        return bool(super().__contains__(key) or key in self._DECISION_KEYS)

    @property
    def allowed(self) -> bool:
        return False

    @property
    def denied(self) -> bool:
        return True

    @property
    def authorization_reason(self) -> str:
        return self.decision.authorization_reason

    @property
    def reason(self) -> str:
        return self.decision.reason

    @property
    def receipt(self) -> DelegationReceipt:
        return self.decision.receipt


DelegationError = DelegationDenied
DelegationDeniedError = DelegationDenied
DelegationAuthorizationError = DelegationDenied
AuthorizationDenied = DelegationDenied


class DelegationGrant(dict):
    """Approval for one business action and delegatable access."""

    def __init__(
            self,
            grant_id: Any = None,
            business_id: Any = None,
            tenant_id: Any = None,
            source: Any = None,
            action: Any = None,
            actions: Any = None,
            resources: Any = None,
            resource: Any = None,
            scopes: Any = None,
            scope: Any = None,
            permissions: Any = None,
            effective_permissions: Any = None,
            status: str = "active",
            revoked: bool = False,
            expires_at: Any = None,
            version: Any = None,
            **extra: Any):
        action_values = _string_set(actions) | _string_set(action)
        resource_values = (
            _string_set(resources)
            | _string_set(resource)
            | _string_set(extra.pop("allowed_resources", None)))
        scope_values = (
            _string_set(scopes)
            | _string_set(scope)
            | _string_set(extra.pop("allowed_scopes", None)))
        permission_values = (
            _string_set(permissions)
            | _string_set(effective_permissions)
            | _string_set(extra.pop("allowed_permissions", None))
            | _string_set(extra.pop("approved_permissions", None)))
        if revoked:
            status = "revoked"
        data = {
            "grant_id": _text(grant_id or extra.pop("id", None)),
            "business_id": _text(
                business_id or extra.pop("business_identifier", None)),
            "tenant_id": _text(tenant_id),
            "source": _text(source),
            "actions": tuple(sorted(action_values)),
            "resources": tuple(sorted(resource_values)),
            "scopes": tuple(sorted(scope_values)),
            "permissions": tuple(sorted(permission_values)),
            "status": _text(status) or "active",
            "expires_at": _epoch(expires_at),
            "version": _text(version),
        }
        data.update(extra)
        super().__init__(data)

    @property
    def grant_id(self):
        return self.get("grant_id")

    @property
    def business_id(self):
        return self.get("business_id")

    @property
    def tenant_id(self):
        return self.get("tenant_id")

    @property
    def source(self):
        return self.get("source")

    @property
    def actions(self):
        return frozenset(self.get("actions") or ())

    @property
    def resources(self):
        return frozenset(self.get("resources") or ())

    @property
    def scopes(self):
        return frozenset(self.get("scopes") or ())

    @property
    def permissions(self):
        return frozenset(self.get("permissions") or ())

    @property
    def status(self):
        return self.get("status") or "active"

    def revoke(self) -> "DelegationGrant":
        self["status"] = "revoked"
        return self

    def _identifier_matches(self, context: DelegationContext) -> bool:
        for field_name, context_value in (
                ("business_id", context.business_id),
                ("tenant_id", context.tenant_id),
                ("source", context.source)):
            expected = self.get(field_name)
            if expected is not None and _id_key(expected) != _id_key(context_value):
                return False
        return True

    @staticmethod
    def _target_allowed(target: str, allowed: frozenset) -> bool:
        if target in allowed:
            return True
        target_base = target.rstrip("/")
        for approved in allowed:
            approved_base = approved.rstrip("/")
            if target_base == approved_base:
                return True
            if target_base.startswith(approved_base + "/"):
                return True
            if target == approved_base + "/.default":
                return True
        return False

    def evaluate(
            self,
            context: DelegationContext,
            now: Optional[float] = None) -> tuple:
        now = time.time() if now is None else now
        if self.status == "revoked":
            return False, REASON_GRANT_REVOKED, ()
        expires_at = self.get("expires_at")
        if expires_at is not None and float(expires_at) <= now:
            return False, REASON_GRANT_EXPIRED, ()
        if self.actions and context.action not in self.actions:
            return False, REASON_ACTION_DENIED, ()

        requested_targets = set(context.scopes)
        if context.resource:
            requested_targets.add(context.resource)
        approved_targets = self.resources | self.scopes
        if requested_targets:
            if not approved_targets:
                return False, REASON_RESOURCE_DENIED, ()
            for target in requested_targets:
                if not self._target_allowed(target, approved_targets):
                    return False, REASON_RESOURCE_DENIED, ()

        requested_permissions = set(context.permissions)
        if requested_permissions:
            if not self.permissions:
                return False, REASON_PERMISSION_DENIED, ()
            if requested_permissions - self.permissions:
                return False, REASON_PERMISSION_DENIED, ()
            effective = requested_permissions
        else:
            effective = self.permissions
        return True, REASON_ACTIVE, tuple(sorted(effective))


class DelegationPolicy:
    """Registry or dynamic provider for current delegation approvals."""

    def __init__(
            self,
            grants: Any = None,
            authorizer: Optional[Callable] = None,
            provider: Optional[Callable] = None,
            clock: Callable[[], float] = time.time):
        self.grants = {}
        self.authorizer = authorizer or provider
        self.clock = clock
        if grants is not None:
            if isinstance(grants, Mapping):
                grant_like_keys = {
                    "grant_id", "business_id", "actions", "permissions",
                    "effective_permissions", "status", "scopes", "resources"}
                if grant_like_keys.intersection(grants.keys()):
                    self.add_grant(grants)
                else:
                    for grant_id, grant in grants.items():
                        if isinstance(grant, Mapping):
                            grant = dict(grant)
                            grant.setdefault("grant_id", grant_id)
                        self.add_grant(grant)
            elif isinstance(grants, DelegationGrant):
                self.add_grant(grants)
            else:
                for grant in grants:
                    self.add_grant(grant)

    def add_grant(self, grant: Any = None, **kwargs: Any) -> DelegationGrant:
        if grant is None:
            grant = DelegationGrant(**kwargs)
        elif isinstance(grant, DelegationGrant):
            pass
        elif isinstance(grant, Mapping):
            grant = DelegationGrant(**dict(grant))
        else:
            raise TypeError("grant must be a mapping or DelegationGrant")
        if not grant.grant_id:
            digest = _hash_payload(grant)
            grant["grant_id"] = "grant-" + digest[:16]
        self.grants[grant.grant_id] = grant
        return grant

    def approve(self, *args: Any, **kwargs: Any) -> DelegationGrant:
        return self.add_grant(*args, **kwargs)

    def revoke(self, grant_id: Any = None, **selector: Any) -> DelegationGrant:
        grant = None
        if isinstance(grant_id, DelegationGrant):
            grant = self.grants.get(grant_id.grant_id)
        elif grant_id is not None:
            grant = self.grants.get(_text(grant_id))
        if grant is None and selector:
            matches = self.find(**selector)
            if len(matches) == 1:
                grant = matches[0]
        if grant is None:
            raise KeyError("delegation grant not found")
        return grant.revoke()

    def find(self, **selector: Any) -> list:
        context = as_context(selector)
        result = []
        for grant in self.grants.values():
            if not grant._identifier_matches(context):
                continue
            if context.action and grant.actions and context.action not in grant.actions:
                continue
            if context.grant_id and grant.grant_id != context.grant_id:
                continue
            if context.permissions and not set(context.permissions).issubset(
                    grant.permissions):
                continue
            requested_targets = set(context.scopes)
            if context.resource:
                requested_targets.add(context.resource)
            approved_targets = grant.resources | grant.scopes
            if requested_targets and not all(
                    grant._target_allowed(target, approved_targets)
                    for target in requested_targets):
                continue
            result.append(grant)
        return result

    def _external_decision(
            self, context: DelegationContext) -> Optional[DelegationDecision]:
        if self.authorizer is None:
            return None
        response = self.authorizer(context)
        if isinstance(response, DelegationDecision):
            response.context = context
            return response
        if isinstance(response, bool):
            return DelegationDecision(
                response,
                REASON_ACTIVE if response else REASON_GRANT_NOT_FOUND,
                context=context)
        if isinstance(response, str):
            normalized = response.strip().lower().replace("-", "_")
            allowed = normalized in {
                "allow", "allowed", "active", "grant_active", "granted",
                "permitted", "ok", "true"}
            reason = response if normalized in _REASON_CATEGORIES else (
                REASON_ACTIVE if allowed else REASON_GRANT_NOT_FOUND)
            return DelegationDecision(allowed, reason, context=context)
        if (isinstance(response, tuple) and response
                and isinstance(response[0], bool)):
            reason = _text(response[1]) if len(response) > 1 else (
                REASON_ACTIVE if response[0] else REASON_GRANT_NOT_FOUND)
            return DelegationDecision(
                response[0], reason or REASON_GRANT_NOT_FOUND,
                context=context)
        if isinstance(response, DelegationGrant):
            allowed, reason, effective = response.evaluate(
                context, self.clock())
            return DelegationDecision(
                allowed, reason, context=context, grant=response,
                effective_permissions=effective)
        if isinstance(response, (list, tuple, set, frozenset)):
            return DelegationPolicy(
                grants=list(response), clock=self.clock).authorize(context)
        if isinstance(response, Mapping):
            if "allowed" in response:
                data = dict(response)
                return DelegationDecision(
                    bool(data.get("allowed")),
                    _text(data.get("reason")
                          or data.get("authorization_reason"))
                    or REASON_ACTIVE,
                    stage=_text(data.get("stage")) or STAGE_AUTHORIZATION,
                    context=context,
                    effective_permissions=data.get("effective_permissions"),
                    category=data.get("category")
                    or data.get("public_category"))
            grant = self.add_grant(response)
            allowed, reason, effective = grant.evaluate(
                context, self.clock())
            return DelegationDecision(
                allowed, reason, context=context, grant=grant,
                effective_permissions=effective)
        raise TypeError("delegation authorizer returned unsupported value")

    def authorize(
            self, context: Any = None, **kwargs: Any) -> DelegationDecision:
        ctx = as_context(context, **kwargs)
        external = self._external_decision(ctx)
        if external is not None:
            return external

        missing = [
            name for name in ("business_id", "tenant_id", "source")
            if not getattr(ctx, name)
        ]
        if missing:
            return DelegationDecision(
                False, REASON_CONTEXT_INVALID,
                stage=STAGE_CONTEXT, context=ctx)

        if ctx.grant_id:
            grant = self.grants.get(ctx.grant_id)
            if grant is None:
                return DelegationDecision(
                    False, REASON_GRANT_NOT_FOUND, context=ctx)
            allowed, reason, effective = grant.evaluate(ctx, self.clock())
            return DelegationDecision(
                allowed, reason, context=ctx, grant=grant,
                effective_permissions=effective)

        matches = self.find()
        if not matches:
            return DelegationDecision(
                False, REASON_GRANT_NOT_FOUND, context=ctx)

        last_reason = REASON_GRANT_NOT_FOUND
        for grant in matches:
            allowed, reason, effective = grant.evaluate(ctx, self.clock())
            if allowed:
                return DelegationDecision(
                    True, reason, context=ctx, grant=grant,
                    effective_permissions=effective)
            last_reason = reason
        return DelegationDecision(False, last_reason, context=ctx)


class DelegationCacheEntry(dict):
    """Dictionary marker for a cache entry bound to a delegation fingerprint."""


class DelegationResultCache:
    """Cache entries bound to a current delegation fingerprint."""

    def __init__(
            self,
            store: Optional[dict] = None,
            clock: Callable[[], float] = time.time,
            default_ttl: Optional[float] = 3600,
            policy: Optional["DelegationPolicy"] = None,
            authorizer: Optional[Callable] = None):
        self._entries = store if store is not None else {}
        self.clock = clock
        self.default_ttl = default_ttl
        if policy is not None:
            self.policy = policy
        elif authorizer is not None:
            self.policy = DelegationPolicy(
                authorizer=authorizer, clock=clock)
        else:
            self.policy = None

    @property
    def entries(self) -> dict:
        return self._entries

    @property
    def _cache(self) -> dict:
        return self._entries

    def _stable_material(self, context: DelegationContext) -> dict:
        return {
            "version": 1,
            "subject": context.subject,
            "business_id": context.business_id,
            "tenant_id": context.tenant_id,
            "source": context.source,
            "action": context.action,
            "grant_id": context.grant_id,
            "resource": context.resource,
            "scopes": list(context.scopes),
        }

    def key_for(
            self,
            context: Any = None,
            decision: Optional[DelegationDecision] = None,
            *positional: Any,
            **kwargs: Any) -> str:
        if decision is not None and not isinstance(
                decision, DelegationDecision):
            positional = (decision,) + positional
            decision = None
        if context is not None and not isinstance(context, Mapping):
            positional = (context,) + positional
            context = None
        field_names = (
            "business_id", "tenant_id", "source", "effective_permissions")
        for name, value in zip(field_names, positional):
            kwargs.setdefault(name, value)
        ctx = as_context(context, **kwargs)
        if decision is not None:
            fingerprint = decision["fingerprint"]
        else:
            fingerprint = compute_delegation_fingerprint(
                ctx.business_id,
                ctx.tenant_id,
                ctx.source,
                ctx.permissions)
        stable = _hash_payload(self._stable_material(ctx))
        return _hash_payload({"stable": stable, "fingerprint": fingerprint})

    make_key = key_for
    build_key = key_for

    def _find_stale_entry(
            self,
            context: DelegationContext,
            current_key: str) -> Optional[dict]:
        current_stable = _hash_payload(self._stable_material(context))
        for entry in self._entries.values():
            if not isinstance(entry, Mapping):
                continue
            entry_context = entry.get("context") or {}
            candidate = {
                "version": 1,
                "subject": entry_context.get("subject"),
                "business_id": entry_context.get("business_id"),
                "tenant_id": entry_context.get("tenant_id"),
                "source": entry_context.get("source"),
                "action": entry_context.get("action"),
                "grant_id": entry_context.get("grant_id"),
                "resource": entry_context.get("resource"),
                "scopes": entry_context.get("scopes"),
            }
            if (_hash_payload(candidate) == current_stable
                    and entry.get("key") != current_key):
                return entry
        return None

    def store(
            self,
            context: Any = None,
            decision: Optional[DelegationDecision] = None,
            result: Optional[Mapping] = None,
            ttl: Optional[float] = None,
            now: Optional[float] = None,
            **kwargs: Any) -> dict:
        if result is None and "value" in kwargs:
            result = kwargs["value"]
        if decision is None or result is None:
            raise TypeError("store requires decision and result")
        ctx = as_context(context or decision.context)
        now = self.clock() if now is None else now
        lifetime = self.default_ttl if ttl is None else ttl
        expires_at = now + lifetime if lifetime is not None else None
        response = result if isinstance(result, Mapping) else {"value": result}
        if "expires_in" in response:
            try:
                expires_at = now + float(response["expires_in"])
            except (TypeError, ValueError):
                pass
        elif response.get("expires_at") is not None:
            expires_at = _epoch(response["expires_at"], now)
        elif response.get("expires_on") is not None:
            expires_at = _epoch(response["expires_on"], now)
        access_token = response.get("access_token")
        if access_token and "expires_in" not in response:
            claims = decode_assertion_claims(access_token)
            if claims.get("exp"):
                expires_at = float(claims["exp"])
        key = self.key_for(ctx, decision)
        entry = DelegationCacheEntry({
            "key": key,
            "stored_at": now,
            "expires_at": expires_at,
            "context": {
                "business_id": ctx.business_id,
                "tenant_id": ctx.tenant_id,
                "source": ctx.source,
                "action": ctx.action,
                "grant_id": ctx.grant_id,
                "subject": ctx.subject,
                "resource": ctx.resource,
                "scopes": list(ctx.scopes),
            },
            "fingerprint": decision["fingerprint"],
            "effective_permissions": list(
                decision.get("effective_permissions") or []),
            "authorization_reason": decision.authorization_reason,
            "result": copy.deepcopy(dict(response)),
        })
        self._entries[key] = entry
        return entry

    set = store

    def lookup(
            self,
            context: Any = None,
            decision: Optional[DelegationDecision] = None,
            policy: Optional[DelegationPolicy] = None,
            now: Optional[float] = None,
            **kwargs: Any) -> tuple:
        ctx = as_context(context, **kwargs)
        if decision is None and policy is None:
            policy = self.policy
        if decision is None and policy is not None:
            decision = policy.authorize(ctx)
        if decision is not None and decision.denied:
            return None, decision.authorization_reason, None, decision
        if decision is None:
            decision = DelegationDecision(True, REASON_ACTIVE, context=ctx)

        now = self.clock() if now is None else now
        key = self.key_for(ctx, decision)
        entry = self._entries.get(key)
        reason = REASON_CACHE_MISS
        if entry is None:
            stale = self._find_stale_entry(ctx, key)
            if stale is not None:
                entry = stale
                reason = REASON_DELEGATION_CHANGED
            else:
                return None, reason, None, decision

        if reason == REASON_CACHE_MISS and entry.get("fingerprint") != decision["fingerprint"]:
            reason = REASON_DELEGATION_CHANGED
        expires_at = entry.get("expires_at")
        if (reason == REASON_CACHE_MISS and expires_at is not None
                and float(expires_at) <= now):
            reason = REASON_CACHE_EXPIRED
        if reason != REASON_CACHE_MISS:
            return None, reason, entry, decision

        result = copy.deepcopy(dict(entry["result"]))
        result["token_source"] = "cache"
        result["cached"] = True
        result["from_cache"] = True
        result["delegation_verified"] = True
        result["authorization_reason"] = REASON_ACTIVE
        result["delegation_proof"] = decision.public_proof()
        entry["last_verified_at"] = now
        entry["last_authorization_reason"] = REASON_ACTIVE
        return result, REASON_ACTIVE, entry, decision

    def get(self, *args: Any, **kwargs: Any):
        result, _, _, _ = self.lookup(*args, **kwargs)
        return result


class DelegationGuard:
    """Current-policy checks for both cache hits and fresh exchanges."""

    def __init__(
            self,
            policy: Any = None,
            cache: Any = None,
            exchange: Optional[Callable] = None,
            token_exchange: Optional[Callable] = None,
            exchanger: Optional[Callable] = None,
            token_exchanger: Optional[Callable] = None,
            client: Any = None,
            authorizer: Optional[Callable] = None,
            clock: Callable[[], float] = time.time,
            default_ttl: Optional[float] = 3600,
            raise_on_deny: bool = False,
            return_decision_on_deny: bool = False):
        if isinstance(policy, DelegationGuard):
            policy = policy.policy
        if policy is None and authorizer is not None:
            policy = DelegationPolicy(authorizer=authorizer, clock=clock)
        elif not isinstance(policy, DelegationPolicy):
            if callable(policy) and not isinstance(policy, (Mapping, DelegationGrant)):
                policy = DelegationPolicy(authorizer=policy, clock=clock)
            elif hasattr(policy, "authorize") and callable(policy.authorize):
                policy = DelegationPolicy(
                    authorizer=policy.authorize, clock=clock)
            elif hasattr(policy, "check") and callable(policy.check):
                policy = DelegationPolicy(
                    authorizer=policy.check, clock=clock)
            else:
                policy = DelegationPolicy(grants=policy, clock=clock)
        self.policy = policy
        if isinstance(cache, DelegationResultCache):
            self.cache = cache
        elif isinstance(cache, dict):
            self.cache = DelegationResultCache(cache, clock=clock)
        elif isinstance(cache, Mapping):
            self.cache = DelegationResultCache(dict(cache), clock=clock)
        else:
            self.cache = cache or DelegationResultCache(
                clock=clock, default_ttl=default_ttl)
        self.exchange = (
            exchange or token_exchange or exchanger or token_exchanger
            or client)
        self.clock = clock
        self.raise_on_deny = raise_on_deny
        self.return_decision_on_deny = return_decision_on_deny
        self.exchange_calls = []
        self.history = []
        self.last_decision = None
        self.last_cache_reason = None

    @property
    def last_authorization_reason(self):
        return (
            self.last_decision.authorization_reason
            if self.last_decision else None)

    authorization_reason = last_authorization_reason

    def authorize(
            self, context: Any = None, **kwargs: Any) -> DelegationDecision:
        decision = self.policy.authorize(context, **kwargs)
        self.last_decision = decision
        self.history.append(decision)
        return decision

    def _deny(
            self,
            decision: DelegationDecision,
            raise_on_deny: Optional[bool]):
        should_raise = (
            self.raise_on_deny if raise_on_deny is None else raise_on_deny)
        if should_raise:
            raise DelegationDenied(decision)
        if self.return_decision_on_deny:
            return decision
        return DelegationDenialReceipt(decision)

    def _call_exchange(
            self,
            user_assertion,
            scopes,
            exchange,
            exchange_kwargs):
        target = exchange or self.exchange
        if target is None:
            raise TypeError("a token exchange callable is required")
        if (not callable(target)
                and hasattr(target, "acquire_token_on_behalf_of")
                and callable(target.acquire_token_on_behalf_of)):
            return target.acquire_token_on_behalf_of(
                user_assertion, scopes, **exchange_kwargs)
        return target(user_assertion, scopes, **exchange_kwargs)

    def acquire_token(
            self,
            user_assertion: Any = None,
            scopes: Any = None,
            context: Any = None,
            exchange: Optional[Callable] = None,
            token_exchange: Optional[Callable] = None,
            exchanger: Optional[Callable] = None,
            raise_on_deny: Optional[bool] = None,
            exchange_kwargs: Optional[Mapping] = None,
            **kwargs: Any):
        exchange = exchange or token_exchange or exchanger
        ctx = as_context(
            context,
            user_assertion=user_assertion,
            scopes=scopes,
            **kwargs)
        if user_assertion is None:
            user_assertion = ctx.user_assertion
        decision = self.authorize(ctx)
        if decision.denied:
            return self._deny(decision, raise_on_deny)

        cached, cache_reason, _, _ = self.cache.lookup(ctx, decision)
        self.last_cache_reason = cache_reason
        if cached is not None:
            return cached

        options = dict(exchange_kwargs or {})
        response = self._call_exchange(
            user_assertion, scopes, exchange, options)
        self.exchange_calls.append({
            "user_assertion": user_assertion,
            "scopes": scopes,
            "context": ctx,
            "decision": decision,
            "cache_reason": cache_reason,
        })
        if isinstance(response, Mapping) and "access_token" in response:
            result = dict(response)
            result.setdefault("token_source", "identity_provider")
            result["exchange_performed"] = True
            result["from_cache"] = False
            result["delegation_verified"] = True
            result["authorization_reason"] = REASON_ACTIVE
            result["delegation_proof"] = decision.public_proof()
            self.cache.store(ctx, decision, result, now=self.clock())
            return result
        return response

    acquire_token_on_behalf_of = acquire_token
    acquire = acquire_token
    get_token = acquire_token
    invoke = acquire_token
    execute = acquire_token
    call = acquire_token


DelegationAwareTokenClient = DelegationGuard
DelegationTokenBroker = DelegationGuard
DelegationManager = DelegationGuard
DelegationService = DelegationGuard
DelegationCheck = DelegationGuard
DelegationChecker = DelegationGuard
DelegationEnforcer = DelegationGuard
DelegationValidator = DelegationGuard
DelegationVerifier = DelegationGuard
PermissionGuard = DelegationGuard
ApprovalGuard = DelegationGuard
OboDelegationGuard = DelegationGuard
OnBehalfOfDelegationGuard = DelegationGuard
DelegationAuthorizer = DelegationPolicy
GrantRegistry = DelegationPolicy
ApprovalRegistry = DelegationPolicy
SecurityGroupPolicy = DelegationPolicy
DelegationCache = DelegationResultCache
DelegationStore = DelegationResultCache
DelegationAwareCache = DelegationResultCache
DelegationTokenCache = DelegationResultCache
DelegationAwareTokenCache = DelegationResultCache
PermissionGrant = DelegationGrant
Grant = DelegationGrant
DelegationApproval = DelegationGrant
BusinessActionGrant = DelegationGrant
ActionGrant = DelegationGrant
BusinessAction = DelegationGrant
CacheEntry = DelegationCacheEntry
DelegationCacheItem = DelegationCacheEntry
GrantAuthorizer = DelegationPolicy
CurrentGrantPolicy = DelegationPolicy
AuthorizationReceipt = DelegationReceipt
Receipt = DelegationReceipt
DenialReceipt = DelegationReceipt
RejectionReceipt = DelegationReceipt
DelegationRejection = DelegationDenied


class AuthorizationReason:
    ACTIVE = REASON_ACTIVE
    NOT_FOUND = REASON_GRANT_NOT_FOUND
    REVOKED = REASON_GRANT_REVOKED
    EXPIRED = REASON_GRANT_EXPIRED
    CONTEXT_INVALID = REASON_CONTEXT_INVALID
    RESOURCE_DENIED = REASON_RESOURCE_DENIED
    PERMISSION_DENIED = REASON_PERMISSION_DENIED
    ACTION_DENIED = REASON_ACTION_DENIED
    CHANGED = REASON_DELEGATION_CHANGED


class PublicCategory:
    ALLOWED = CATEGORY_ALLOWED
    INVALID_REQUEST = CATEGORY_INVALID_REQUEST
    NOT_AUTHORIZED = CATEGORY_NOT_AUTHORIZED
    REVOKED = CATEGORY_REVOKED
    EXPIRED = CATEGORY_EXPIRED
    DELEGATION_CHANGED = CATEGORY_DELEGATION_CHANGED


def build_cache_key(*args: Any, **kwargs: Any) -> str:
    return DelegationResultCache().key_for(*args, **kwargs)


delegation_cache_key = build_cache_key


def evaluate_delegation(
        context: Any = None,
        policy: Any = None,
        grants: Any = None,
        authorizer: Optional[Callable] = None,
        **kwargs: Any) -> DelegationDecision:
    if not isinstance(policy, DelegationPolicy):
        policy = DelegationPolicy(
            grants=grants if grants is not None else policy,
            authorizer=authorizer)
    return policy.authorize(context, **kwargs)


def check_delegation(*args: Any, **kwargs: Any) -> DelegationDecision:
    return evaluate_delegation(*args, **kwargs)


def install_delegation_check(app: Any, guard: Any) -> Any:
    """Attach a guard to an application-like object and return it."""
    if not isinstance(guard, DelegationGuard):
        guard = DelegationGuard(guard)
    app.delegation_guard = guard
    return app


def acquire_delegated_token(
        app: Any = None,
        user_assertion: Any = None,
        scopes: Any = None,
        guard: Any = None,
        **kwargs: Any):
    """Call an MSAL-like OBO method through an optional delegation guard."""
    if guard is None:
        guard = getattr(app, "delegation_guard", None)
    if not isinstance(guard, DelegationGuard):
        guard = DelegationGuard(policy=guard)
    exchange = kwargs.pop("exchange", None)
    if exchange is None and app is not None:
        exchange = getattr(app, "acquire_token_on_behalf_of", None)
    return guard.acquire_token(
        user_assertion, scopes, exchange=exchange, **kwargs)


acquire_token_with_delegation = acquire_delegated_token
acquire_on_behalf_of_with_delegation = acquire_delegated_token
delegated_acquire_token = acquire_delegated_token

