"""Approval-gated revocation plans for dynamic credentials.

Vault's lease revocation endpoints are intentionally blunt: a prefix revocation
can remove every credential under a mount, and ``revoke-force`` can do so even
when the backend reports errors.  This module keeps the dangerous part behind a
small, inspectable plan that must be approved before any revocation request is
sent.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import math
import re
import uuid
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

import requests

from hvac import exceptions, utils
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin

DEFAULT_PLAN_TTL = 15 * 60
_DURATION_RE = re.compile(r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[smh]?)\s*$", re.IGNORECASE)


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _as_utc(value: _dt.datetime) -> _dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def _parse_ttl(ttl: Any) -> _dt.timedelta:
    """Convert an hvac-style TTL (seconds or ``15m``/``2h``) to a timedelta."""
    if isinstance(ttl, _dt.timedelta):
        if ttl < _dt.timedelta(0):
            raise exceptions.ParamValidationError("ttl must not be negative")
        return ttl

    if isinstance(ttl, bool):
        raise exceptions.ParamValidationError("ttl must be a number, duration string, or timedelta")

    if isinstance(ttl, (int, float)):
        if not math.isfinite(ttl) or ttl < 0:
            raise exceptions.ParamValidationError("ttl must be a finite, non-negative value")
        return _dt.timedelta(seconds=float(ttl))

    if isinstance(ttl, str):
        match = _DURATION_RE.match(ttl)
        if not match:
            raise exceptions.ParamValidationError(
                "ttl must be a number of seconds or a duration such as '30s', '15m', or '2h'"
            )
        value = float(match.group("value"))
        unit = (match.group("unit") or "s").lower()
        multiplier = {"s": 1, "m": 60, "h": 3600}[unit]
        return _dt.timedelta(seconds=value * multiplier)

    raise exceptions.ParamValidationError("ttl must be a number, duration string, or timedelta")


def _normalize_namespace(namespace: Optional[str]) -> str:
    if namespace is None:
        return ""
    return str(namespace).strip().strip("/")


def _display_namespace(namespace: str) -> str:
    return namespace or "root"


def _normalize_targets(values: Optional[Iterable[str]], name: str) -> Tuple[str, ...]:
    if values is None:
        return ()

    if isinstance(values, str):
        values = (values,)

    normalized = []
    seen = set()
    for value in values:
        if not isinstance(value, str):
            raise exceptions.ParamValidationError(f"{name} must contain strings")
        value = value.strip().strip("/")
        if not value:
            raise exceptions.ParamValidationError(f"{name} must not contain an empty value")
        if value not in seen:
            seen.add(value)
            normalized.append(value)
    return tuple(sorted(normalized))


def _error_text(exc: BaseException) -> str:
    if getattr(exc, "args", None):
        return str(exc.args[0])
    return str(exc)


@dataclasses.dataclass(frozen=True)
class Approval:
    """A named sign-off bound to one exact plan fingerprint."""

    approver: str
    approved_at: _dt.datetime
    fingerprint: str
    approval_id: str = dataclasses.field(default_factory=lambda: uuid.uuid4().hex)
    note: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.approver or not self.approver.strip():
            raise exceptions.ParamValidationError("approver must not be empty")
        object.__setattr__(self, "approved_at", _as_utc(self.approved_at))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "approver": self.approver,
            "approved_at": self.approved_at.isoformat(),
            "fingerprint": self.fingerprint,
            "note": self.note,
        }


@dataclasses.dataclass(frozen=True)
class RevocationPlan:
    """An inspectable, approval-gated set of lease revocation targets."""

    plan_id: str
    namespace: str
    lease_ids: Tuple[str, ...]
    prefixes: Tuple[str, ...]
    force: bool
    scope: Tuple[str, ...]
    created_at: _dt.datetime
    expires_at: _dt.datetime
    fingerprint: str
    approval: Optional[Approval] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "namespace", _normalize_namespace(self.namespace))
        object.__setattr__(self, "created_at", _as_utc(self.created_at))
        object.__setattr__(self, "expires_at", _as_utc(self.expires_at))
        if self.approval is not None and self.approval.fingerprint != self.fingerprint:
            raise exceptions.ParamValidationError(
                "approval does not match the plan fingerprint"
            )

    @property
    def approved(self) -> bool:
        return self.approval is not None

    @property
    def mode(self) -> str:
        if self.force and self.prefixes and self.lease_ids:
            return "force+lease"
        if self.force:
            return "force"
        if self.prefixes and self.lease_ids:
            return "prefix+lease"
        if self.prefixes:
            return "prefix"
        return "lease"

    def is_expired(self, now: Optional[_dt.datetime] = None) -> bool:
        now = _as_utc(now or _utcnow())
        return now >= self.expires_at

    def summary(self, now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
        """Return the facts an approver or on-call operator must check."""
        now = _as_utc(now or _utcnow())
        data = {
            "plan_id": self.plan_id,
            "namespace": _display_namespace(self.namespace),
            "namespace_header": self.namespace or None,
            "mode": self.mode,
            "force": self.force,
            "dangerous": self.force,
            "prefixes": list(self.prefixes),
            "lease_ids": list(self.lease_ids),
            "scope": list(self.scope),
            "scope_count": len(self.scope),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "expires_in_seconds": max(0, int((self.expires_at - now).total_seconds())),
            "expired": self.is_expired(now),
            "approved": self.approved,
            "approval": self.approval.to_dict() if self.approval else None,
            "fingerprint": self.fingerprint,
        }
        if self.force:
            data["warning"] = (
                "force revocation ignores backend errors and is explicitly selected; "
                "confirm the namespace and prefix scope before approval"
            )
        return data

    def describe(self) -> str:
        lines = [
            f"Revocation plan {self.plan_id}",
            f"  namespace: {_display_namespace(self.namespace)}",
            f"  mode: {self.mode}{' (DANGEROUS FORCE)' if self.force else ''}",
            f"  prefixes: {', '.join(self.prefixes) if self.prefixes else '(none)'}",
            f"  lease IDs: {', '.join(self.lease_ids) if self.lease_ids else '(none)'}",
            f"  observed scope ({len(self.scope)}):",
        ]
        if self.scope:
            lines.extend(f"    - {item}" for item in self.scope)
        else:
            lines.append("    (no leases listed; the prefix itself is the revocable range)")
        lines.extend(
            [
                f"  created_at: {self.created_at.isoformat()}",
                f"  expires_at: {self.expires_at.isoformat()}",
                f"  approved: {self.approved}",
            ]
        )
        if self.approval:
            lines.append(
                f"  approved_by: {self.approval.approver} at {self.approval.approved_at.isoformat()}"
            )
            if self.approval.note:
                lines.append(f"  approval_note: {self.approval.note}")
        lines.append(f"  fingerprint: {self.fingerprint}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return self.summary()

    def __str__(self) -> str:
        return self.describe()


@dataclasses.dataclass(frozen=True)
class RevocationResult:
    target: str
    kind: str
    endpoint: str
    status: str
    http_status: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "endpoint": self.endpoint,
            "status": self.status,
            "http_status": self.http_status,
            "error": self.error,
        }


@dataclasses.dataclass(frozen=True)
class RevocationReceipt:
    plan_id: str
    namespace: str
    force: bool
    fingerprint: str
    state: str
    started_at: _dt.datetime
    finished_at: _dt.datetime
    results: Tuple[RevocationResult, ...]

    @property
    def ok(self) -> bool:
        return self.state == "succeeded"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "namespace": _display_namespace(self.namespace),
            "force": self.force,
            "fingerprint": self.fingerprint,
            "state": self.state,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "results": [result.to_dict() for result in self.results],
        }


class Revocation(SystemBackendMixin):
    """Approval-gated revocation plans for dynamic credentials.

    A plan is created with a read-only scope snapshot, approved explicitly, and
    then executed.  Execution refuses to send any revocation request when the
    plan is unapproved, expired, approved for another namespace, or its observed
    scope has changed since approval.
    """

    def create_plan(
        self,
        lease_ids: Optional[Iterable[str]] = None,
        prefixes: Optional[Iterable[str]] = None,
        *,
        force: bool = False,
        ttl: Any = DEFAULT_PLAN_TTL,
        now: Optional[_dt.datetime] = None,
    ) -> RevocationPlan:
        """Create an inspectable plan without revoking anything.

        The plan captures the client's actual namespace, the requested lease IDs
        and prefixes, and a read-only snapshot of leases visible under each
        prefix.  No ``sys/leases/revoke*`` endpoint is called here.

        :param lease_ids: Exact lease IDs to revoke.
        :param prefixes: Lease prefixes whose matching leases should be revoked.
        :param force: Explicitly select ``sys/leases/revoke-force`` for prefixes.
            This is dangerous and defaults to ``False``.
        :param ttl: How long the plan may be executed, in seconds or as a
            duration such as ``15m``.  Defaults to 15 minutes.
        :param now: Optional clock injection for tests.
        :return: The unapproved plan.
        :rtype: RevocationPlan
        """
        if not isinstance(force, bool):
            raise exceptions.ParamValidationError("force must be an explicit bool")

        lease_ids = _normalize_targets(lease_ids, "lease_ids")
        prefixes = _normalize_targets(prefixes, "prefixes")

        if not lease_ids and not prefixes:
            raise exceptions.ParamValidationError(
                "a revocation plan requires at least one lease_id or prefix"
            )
        if force and not prefixes:
            raise exceptions.ParamValidationError(
                "force revocation applies to prefixes; provide at least one prefix"
            )

        created_at = _as_utc(now or _utcnow())
        expires_at = created_at + _parse_ttl(ttl)
        namespace = _normalize_namespace(self._adapter.namespace)
        try:
            scope = self._collect_scope(prefixes)
        except exceptions.VaultError as exc:
            raise exceptions.RevocationPlanError(
                "unable to determine the revocable scope for the requested prefixes; "
                "no plan was created",
            ) from exc
        plan_id = uuid.uuid4().hex

        fingerprint = self._fingerprint(
            plan_id=plan_id,
            namespace=namespace,
            lease_ids=lease_ids,
            prefixes=prefixes,
            force=force,
            scope=scope,
            created_at=created_at,
            expires_at=expires_at,
        )

        return RevocationPlan(
            plan_id=plan_id,
            namespace=namespace,
            lease_ids=lease_ids,
            prefixes=prefixes,
            force=force,
            scope=scope,
            created_at=created_at,
            expires_at=expires_at,
            fingerprint=fingerprint,
        )

    def approve_plan(
        self,
        plan: RevocationPlan,
        approver: str,
        *,
        note: Optional[str] = None,
        now: Optional[_dt.datetime] = None,
        approval_id: Optional[str] = None,
    ) -> RevocationPlan:
        """Sign off one exact plan and return an approved copy.

        The approval is bound to the plan fingerprint.  Re-approving an already
        approved plan is rejected so the audit trail has one named sign-off per
        plan.
        """
        self._validate_plan(plan)
        if not isinstance(approver, str) or not approver.strip():
            raise exceptions.ParamValidationError("approver must not be empty")
        if self._recompute_fingerprint(plan) != plan.fingerprint:
            raise exceptions.RevocationPlanError(
                f"revocation plan {plan.plan_id} failed its integrity check; approval was not recorded",
                plan=plan,
            )
        if plan.approval is not None:
            raise exceptions.RevocationPlanError(
                "revocation plan is already approved; create a new plan for a new scope"
            )

        actual_namespace = _normalize_namespace(self._adapter.namespace)
        if actual_namespace != plan.namespace:
            raise exceptions.RevocationPlanNamespaceChanged(
                f"revocation plan {plan.plan_id} was created for namespace "
                f"{_display_namespace(plan.namespace)}, but the client is using "
                f"{_display_namespace(actual_namespace)}; no approval was recorded",
                plan=plan,
                planned_namespace=plan.namespace,
                actual_namespace=actual_namespace,
            )

        approved_at = _as_utc(now or _utcnow())
        if plan.is_expired(approved_at):
            raise exceptions.RevocationPlanExpired(
                f"revocation plan {plan.plan_id} expired at {plan.expires_at.isoformat()}; "
                "no revocation request was sent",
                plan=plan,
            )

        try:
            current_scope = self._collect_scope(plan.prefixes)
        except exceptions.VaultError as exc:
            raise exceptions.RevocationPlanError(
                f"unable to verify the current scope for revocation plan {plan.plan_id}; "
                "approval was not recorded",
                plan=plan,
            ) from exc
        if current_scope != plan.scope:
            added = tuple(sorted(set(current_scope) - set(plan.scope)))
            removed = tuple(sorted(set(plan.scope) - set(current_scope)))
            raise exceptions.RevocationPlanScopeChanged(
                f"revocation plan {plan.plan_id} scope changed before approval "
                f"(added={list(added)}, removed={list(removed)}); approval was not recorded",
                plan=plan,
                added=added,
                removed=removed,
            )

        approval = Approval(
            approver=str(approver),
            approved_at=approved_at,
            fingerprint=plan.fingerprint,
            approval_id=approval_id or uuid.uuid4().hex,
            note=note,
        )
        return dataclasses.replace(plan, approval=approval)

    def execute_plan(
        self,
        plan: RevocationPlan,
        *,
        now: Optional[_dt.datetime] = None,
    ) -> RevocationReceipt:
        """Execute an approved plan, or fail closed before revocation.

        The following checks happen before the first revocation request:
        approval present and matching the fingerprint, plan not expired,
        actual adapter namespace matches the approved namespace, and the
        observed prefix scope is unchanged.

        A transport failure is reported as an unknown outcome.  The request is
        not retried because the server may already have applied it.
        """
        self._validate_plan(plan)
        executed_at = _as_utc(now or _utcnow())

        if plan.approval is None:
            raise exceptions.RevocationPlanNotApproved(
                f"revocation plan {plan.plan_id} is not approved; no revocation request was sent",
                plan=plan,
            )
        if plan.approval.fingerprint != plan.fingerprint:
            raise exceptions.RevocationPlanNotApproved(
                f"revocation plan {plan.plan_id} approval does not match its fingerprint; "
                "no revocation request was sent",
                plan=plan,
            )
        if self._recompute_fingerprint(plan) != plan.fingerprint:
            raise exceptions.RevocationPlanError(
                f"revocation plan {plan.plan_id} failed its integrity check; "
                "no revocation request was sent",
                plan=plan,
            )
        if plan.is_expired(executed_at):
            raise exceptions.RevocationPlanExpired(
                f"revocation plan {plan.plan_id} expired at {plan.expires_at.isoformat()}; "
                "no revocation request was sent",
                plan=plan,
            )

        actual_namespace = _normalize_namespace(self._adapter.namespace)
        if actual_namespace != plan.namespace:
            raise exceptions.RevocationPlanNamespaceChanged(
                f"revocation plan {plan.plan_id} was approved for namespace "
                f"{_display_namespace(plan.namespace)}, but the client is using "
                f"{_display_namespace(actual_namespace)}; no revocation request was sent",
                plan=plan,
                planned_namespace=plan.namespace,
                actual_namespace=actual_namespace,
            )

        try:
            current_scope = self._collect_scope(plan.prefixes)
        except exceptions.VaultError as exc:
            raise exceptions.RevocationPlanError(
                f"unable to verify the current scope for revocation plan {plan.plan_id}; "
                "no revocation request was sent",
                plan=plan,
            ) from exc
        if current_scope != plan.scope:
            added = tuple(sorted(set(current_scope) - set(plan.scope)))
            removed = tuple(sorted(set(plan.scope) - set(current_scope)))
            raise exceptions.RevocationPlanScopeChanged(
                f"revocation plan {plan.plan_id} scope changed since approval "
                f"(added={list(added)}, removed={list(removed)}); "
                "no revocation request was sent",
                plan=plan,
                added=added,
                removed=removed,
            )

        results = []
        for lease_id in plan.lease_ids:
            result = self._revoke_lease(lease_id)
            results.append(result)
            self._raise_for_bad_outcome(plan, results, lease_id, result, executed_at)

        for prefix in plan.prefixes:
            result = self._revoke_prefix(prefix, force=plan.force)
            results.append(result)
            self._raise_for_bad_outcome(plan, results, prefix, result, executed_at)

        return self._receipt(plan, results, "succeeded", executed_at)

    def _raise_for_bad_outcome(
        self,
        plan: RevocationPlan,
        results: Sequence[RevocationResult],
        target: str,
        result: RevocationResult,
        executed_at: _dt.datetime,
    ) -> None:
        if result.status == "unknown":
            receipt = self._receipt(plan, results, "unknown", executed_at)
            raise exceptions.RevocationOutcomeUnknown(
                self._unknown_message(plan, target, result.error),
                plan=plan,
                receipt=receipt,
                verification_steps=self.verification_steps(plan),
            )
        if result.status != "revoked":
            revoked_count = sum(1 for item in results if item.status == "revoked")
            state = "partial" if revoked_count else "failed"
            receipt = self._receipt(plan, results, state, executed_at)
            raise exceptions.RevocationFailed(
                f"revocation plan {plan.plan_id} stopped with state {state}; "
                f"Vault rejected {target!r} and no further targets were sent",
                plan=plan,
                receipt=receipt,
            )

    def readback(self, plan: RevocationPlan) -> Dict[str, Any]:
        """Read the current namespace and observed scope without revoking.

        This is the read-only evidence helper to use after an unknown outcome
        or before retrying.  ``changed`` is true when the visible lease set no
        longer matches the approved snapshot.  Exact lease IDs are also looked
        up individually so an operator can distinguish "still present" from
        "already gone" and from "cannot verify".
        """
        self._validate_plan(plan)
        actual_namespace = _normalize_namespace(self._adapter.namespace)
        result = {
            "plan_id": plan.plan_id,
            "namespace": _display_namespace(actual_namespace),
            "planned_namespace": _display_namespace(plan.namespace),
            "namespace_changed": actual_namespace != plan.namespace,
            "prefixes": list(plan.prefixes),
            "lease_ids": list(plan.lease_ids),
            "approved_scope": list(plan.scope),
            "approved": plan.approved,
            "expired": plan.is_expired(),
            "fingerprint": plan.fingerprint,
        }

        try:
            current_scope = self._collect_scope(plan.prefixes)
        except exceptions.VaultError as exc:
            result.update(
                current_scope=None,
                scope_error=_error_text(exc),
                added=[],
                removed=[],
                changed=None,
            )
        else:
            added = tuple(sorted(set(current_scope) - set(plan.scope)))
            removed = tuple(sorted(set(plan.scope) - set(current_scope)))
            result.update(
                current_scope=list(current_scope),
                added=list(added),
                removed=list(removed),
                changed=bool(added or removed),
            )

        result["lease_states"] = {
            lease_id: self._read_lease_state(lease_id)
            for lease_id in plan.lease_ids
        }
        return result

    def _read_lease_state(self, lease_id: str) -> str:
        try:
            response = self._adapter.put(
                url="/v1/sys/leases/lookup", json={"lease_id": lease_id}
            )
        except exceptions.InvalidPath:
            return "missing"
        except requests.exceptions.RequestException as exc:
            return f"unknown: {_error_text(exc)}"
        except exceptions.VaultError as exc:
            return f"unknown: {_error_text(exc)}"

        status_code = getattr(response, "status_code", None)
        if isinstance(response, dict) or status_code in (None, 200):
            return "present"
        if status_code == 404:
            return "missing"
        return f"unknown: HTTP {status_code}"

    def verification_steps(self, plan: RevocationPlan) -> Tuple[str, ...]:
        """Return the checks an on-call operator should perform."""
        return (
            "Do not retry automatically: the request may already have been applied.",
            f"Run client.sys.revocation.readback(plan) for namespace {_display_namespace(plan.namespace)} "
            f"and prefixes {list(plan.prefixes)}; compare the returned current scope with the approved scope.",
            "Check the Vault audit device for sys/leases/revoke, sys/leases/revoke-prefix, or "
            "sys/leases/revoke-force entries at the request time.",
            "Check the target secrets engine or credential store for the affected credential; "
            "readback.lease_states reports present/missing/unknown for exact lease IDs. A missing "
            "credential supports revocation, but a missing audit entry alone is not proof that nothing happened.",
            "If the scope is unchanged and no revocation audit entry exists, create a new plan and obtain a "
            "new approval before retrying.",
        )

    def _validate_plan(self, plan: RevocationPlan) -> None:
        if not isinstance(plan, RevocationPlan):
            raise exceptions.ParamValidationError("plan must be a RevocationPlan")

    def _receipt(
        self,
        plan: RevocationPlan,
        results: Sequence[RevocationResult],
        state: str,
        started_at: _dt.datetime,
    ) -> RevocationReceipt:
        return RevocationReceipt(
            plan_id=plan.plan_id,
            namespace=plan.namespace,
            force=plan.force,
            fingerprint=plan.fingerprint,
            state=state,
            started_at=started_at,
            finished_at=_utcnow(),
            results=tuple(results),
        )

    def _unknown_message(
        self, plan: RevocationPlan, target: str, error: Optional[str]
    ) -> str:
        detail = f": {error}" if error else ""
        return (
            f"revocation outcome is unknown for {target!r} "
            f"in namespace {_display_namespace(plan.namespace)}{detail}; the request was not retried"
        )

    def _recompute_fingerprint(self, plan: RevocationPlan) -> str:
        return self._fingerprint(
            plan_id=plan.plan_id,
            namespace=_normalize_namespace(plan.namespace),
            lease_ids=plan.lease_ids,
            prefixes=plan.prefixes,
            force=plan.force,
            scope=plan.scope,
            created_at=plan.created_at,
            expires_at=plan.expires_at,
        )

    def _fingerprint(
        self,
        *,
        plan_id: str,
        namespace: str,
        lease_ids: Sequence[str],
        prefixes: Sequence[str],
        force: bool,
        scope: Sequence[str],
        created_at: _dt.datetime,
        expires_at: _dt.datetime,
    ) -> str:
        payload = {
            "plan_id": plan_id,
            "namespace": namespace,
            "lease_ids": list(lease_ids),
            "prefixes": list(prefixes),
            "force": force,
            "scope": list(scope),
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _collect_scope(self, prefixes: Sequence[str]) -> Tuple[str, ...]:
        entries = set()
        for prefix in prefixes:
            self._walk_prefix(prefix, entries, depth=0)
        return tuple(sorted(entries))

    def _walk_prefix(self, prefix: str, entries: set, *, depth: int) -> None:
        if depth > 8:
            return
        for key in self._list_prefix(prefix):
            if key.endswith("/"):
                self._walk_prefix(
                    self._full_lease_id(prefix, key).rstrip("/"),
                    entries,
                    depth=depth + 1,
                )
            else:
                entries.add(self._full_lease_id(prefix, key))

    def _list_prefix(self, prefix: str) -> Tuple[str, ...]:
        api_path = utils.format_url("/v1/sys/leases/lookup/{prefix}", prefix=prefix)
        try:
            response = self._adapter.list(url=api_path)
        except exceptions.InvalidPath:
            return ()
        return self._extract_keys(response)

    @staticmethod
    def _extract_keys(response: Any) -> Tuple[str, ...]:
        payload = response
        if not isinstance(payload, dict) and hasattr(payload, "json"):
            try:
                payload = payload.json()
            except ValueError:
                return ()
        if not isinstance(payload, dict):
            return ()
        data = payload.get("data") or {}
        keys = data.get("keys") or []
        return tuple(str(key) for key in keys)

    @staticmethod
    def _full_lease_id(prefix: str, key: str) -> str:
        prefix = prefix.strip("/")
        key = str(key).strip().strip("/")
        if not key:
            return prefix
        if key == prefix or key.startswith(prefix + "/"):
            return key.rstrip("/")
        return f"{prefix}/{key}".rstrip("/")

    def _revoke_lease(self, lease_id: str) -> RevocationResult:
        api_path = "/v1/sys/leases/revoke"
        try:
            response = self._adapter.put(url=api_path, json={"lease_id": lease_id})
        except requests.exceptions.RequestException as exc:
            return RevocationResult(
                target=lease_id,
                kind="lease",
                endpoint=api_path,
                status="unknown",
                error=_error_text(exc),
            )
        except exceptions.VaultError as exc:
            return self._result_from_vault_error(lease_id, "lease", api_path, exc)
        return self._result_from_response(lease_id, "lease", api_path, response)

    def _revoke_prefix(self, prefix: str, *, force: bool) -> RevocationResult:
        endpoint = "revoke-force" if force else "revoke-prefix"
        api_path = utils.format_url(
            f"/v1/sys/leases/{endpoint}/{{prefix}}", prefix=prefix
        )
        try:
            response = self._adapter.put(url=api_path, json={"prefix": prefix})
        except requests.exceptions.RequestException as exc:
            return RevocationResult(
                target=prefix,
                kind="prefix",
                endpoint=api_path,
                status="unknown",
                error=_error_text(exc),
            )
        except exceptions.VaultError as exc:
            return self._result_from_vault_error(prefix, "prefix", api_path, exc)
        return self._result_from_response(prefix, "prefix", api_path, response)

    @staticmethod
    def _result_from_vault_error(
        target: str, kind: str, endpoint: str, exc: exceptions.VaultError
    ) -> RevocationResult:
        uncertain = isinstance(
            exc,
            (
                exceptions.InternalServerError,
                exceptions.BadGateway,
                exceptions.VaultDown,
                exceptions.UnexpectedError,
            ),
        )
        return RevocationResult(
            target=target,
            kind=kind,
            endpoint=endpoint,
            status="unknown" if uncertain else "rejected",
            error=_error_text(exc),
        )

    @staticmethod
    def _result_from_response(
        target: str, kind: str, endpoint: str, response: Any
    ) -> RevocationResult:
        if isinstance(response, dict):
            if response.get("errors"):
                return RevocationResult(
                    target=target,
                    kind=kind,
                    endpoint=endpoint,
                    status="rejected",
                    http_status=200,
                    error=", ".join(str(item) for item in response["errors"]),
                )
            return RevocationResult(
                target=target,
                kind=kind,
                endpoint=endpoint,
                status="revoked",
                http_status=200,
            )
        status_code = getattr(response, "status_code", None)
        if status_code is None:
            return RevocationResult(
                target=target,
                kind=kind,
                endpoint=endpoint,
                status="revoked",
            )
        if 200 <= status_code < 300:
            return RevocationResult(
                target=target,
                kind=kind,
                endpoint=endpoint,
                status="revoked",
                http_status=status_code,
            )
        if 400 <= status_code < 500:
            return RevocationResult(
                target=target,
                kind=kind,
                endpoint=endpoint,
                status="rejected",
                http_status=status_code,
                error=getattr(response, "text", None),
            )
        return RevocationResult(
            target=target,
            kind=kind,
            endpoint=endpoint,
            status="unknown",
            http_status=status_code,
            error=getattr(response, "text", None),
        )
