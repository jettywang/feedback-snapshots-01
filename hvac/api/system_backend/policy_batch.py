"""Batch change interface for Vault ACL policies.

The endpoints under ``/sys/policy`` are unversioned last-write-wins objects.
This module adds an opt-in coordination layer on top of them: before any write
is sent, the current body of every targeted policy is read back and recorded as
version evidence. The evidence is later used to (a) skip writes when another
administrator has changed the policy in the meantime and (b) roll back only the
changes whose evidence still matches, so a policy handed over to another writer
is never overwritten.
"""
import datetime
import hashlib
import json

from hvac import utils
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin
from hvac.exceptions import ParamValidationError, VaultError

# Statuses recorded while the pre-write evidence is being collected.
EVIDENCE_ERROR = "evidence_error"
EVIDENCE_UNKNOWN = "evidence_unknown"

# Statuses recorded while the requested changes are being applied.
APPLY_PENDING = "apply_pending"
APPLY_APPLIED = "applied"
APPLY_CONFLICT = "apply_conflict"
APPLY_ERROR = "apply_error"
APPLY_UNKNOWN = "apply_unknown"

# Statuses recorded during conditional rollback.
ROLLBACK_NOT_ATTEMPTED = "rollback_not_attempted"
ROLLBACK_RESTORED = "restored"
ROLLBACK_DELETED = "restored_by_delete"
ROLLBACK_SKIPPED = "rollback_skipped"
ROLLBACK_ERROR = "rollback_error"
ROLLBACK_UNKNOWN = "rollback_unknown"

# Aggregate statuses for the batch as a whole.
BATCH_SUCCEEDED = "succeeded"
BATCH_FAILED = "failed"
BATCH_UNKNOWN = "unknown"

_KNOWN_ERROR_STATUS_CODES = (400, 401, 403, 404, 429, 500, 501, 502, 503)
_READBACK_ADVICE = (
    "response could not be classified; read the policy back with "
    "sys.read_policy to determine the actual stored state before retrying"
)


class PolicyVersionEvidence:
    """Snapshot of a policy taken before any batch write is attempted."""

    def __init__(
        self,
        name,
        existed,
        rules=None,
        fingerprint=None,
        captured_at=None,
        status_code=None,
        detail=None,
    ):
        self.name = name
        self.existed = existed
        self.rules = rules
        self.fingerprint = fingerprint
        self.captured_at = captured_at or _utc_now()
        self.status_code = status_code
        self.detail = detail

    def to_dict(self):
        return {
            "name": self.name,
            "existed": self.existed,
            "rules": self.rules,
            "fingerprint": self.fingerprint,
            "captured_at": self.captured_at,
            "status_code": self.status_code,
            "detail": self.detail,
        }


class PolicyChangeResult:
    """Per-policy outcome, including its evidence and rollback disposition."""

    def __init__(self, name, desired_policy, evidence=None):
        self.name = name
        self.desired_policy = desired_policy
        self.evidence = evidence
        self.apply_status = APPLY_PENDING
        self.apply_status_code = None
        self.apply_detail = None
        self.rollback_status = ROLLBACK_NOT_ATTEMPTED
        self.rollback_status_code = None
        self.rollback_detail = None
        self.readback_advised = False

    @property
    def final_status(self):
        """Coarse-grained state the policy is expected to be in now."""
        if self.apply_status in (APPLY_UNKNOWN, EVIDENCE_UNKNOWN):
            return "unknown"
        if self.apply_status == APPLY_APPLIED:
            if self.rollback_status in (ROLLBACK_RESTORED, ROLLBACK_DELETED):
                return "reverted"
            if self.rollback_status in (ROLLBACK_ERROR, ROLLBACK_UNKNOWN):
                return "revert_uncertain"
            return "changed"
        if self.apply_status == APPLY_CONFLICT:
            return "untouched_conflict"
        if self.apply_status in (APPLY_ERROR, EVIDENCE_ERROR):
            return "unchanged"
        return "not_attempted"

    def to_dict(self):
        return {
            "name": self.name,
            "desired_policy": self.desired_policy,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "apply_status": self.apply_status,
            "apply_status_code": self.apply_status_code,
            "apply_detail": self.apply_detail,
            "rollback_status": self.rollback_status,
            "rollback_status_code": self.rollback_status_code,
            "rollback_detail": self.rollback_detail,
            "readback_advised": self.readback_advised,
            "final_status": self.final_status,
        }


class PolicyBatchResult:
    """Aggregate result returned by :meth:`PolicyBatch.apply_policy_batch`."""

    def __init__(self, results=None, status=None, readback_required=False):
        self.results = results if results is not None else []
        self.status = status
        self.readback_required = readback_required

    @property
    def readback_names(self):
        return [
            result.name for result in self.results if result.readback_advised
        ]

    def to_dict(self):
        return {
            "status": self.status,
            "readback_required": self.readback_required,
            "readback_names": list(self.readback_names),
            "results": [result.to_dict() for result in self.results],
        }


class PolicyBatch(SystemBackendMixin):
    """Apply a batch of ACL policy changes with version evidence and guarded rollback."""

    def apply_policy_batch(self, changes, rollback_on_failure=True):
        """Apply several policy changes as one guarded batch.

        The batch runs in two phases:

        1. **Evidence phase.** Every named policy is read back and its body is
           fingerprinted. No write is sent until evidence for every policy has
           been collected, so a failure here leaves Vault untouched.
        2. **Apply phase.** Policies are written in order. Immediately before
           each write the policy is read again; if its fingerprint no longer
           matches the evidence, another administrator has taken over and the
           write is skipped as a conflict.

        On a *known* failure (an HTTP error status Vault documents) the already
        applied policies are conditionally restored when ``rollback_on_failure``
        is true. A restore write is only sent while the stored policy still
        matches the body this batch wrote (or the captured evidence for a
        no-op write); a policy another administrator has since changed is left
        alone. On an *unknown* response the batch stops without any automatic
        rollback and the caller is told which policies must be read back.

        :param changes: Iterable of ``(name, policy)`` pairs or mappings with
            ``name`` and ``policy`` keys, where ``policy`` is a policy document
            as accepted by :meth:`Policy.create_or_update_policy`.
        :type changes: list[tuple | dict]
        :param rollback_on_failure: When True (the default), restore applied
            policies whose evidence still matches after a known failure.
        :type rollback_on_failure: bool
        :return: Aggregate, per-policy result with evidence and final statuses.
        :rtype: PolicyBatchResult
        """
        ordered_changes = self._normalize_changes(changes)
        results = [
            PolicyChangeResult(name=name, desired_policy=policy)
            for name, policy in ordered_changes
        ]

        evidence_ok = self._collect_evidence(results)
        if not evidence_ok:
            return self._build_result(results)

        for result in results:
            outcome = self._apply_one(result)
            if outcome in ("conflict", "ok"):
                continue
            if outcome == "known_error":
                if rollback_on_failure:
                    self._rollback_applied(results)
            return self._build_result(results)

        return self._build_result(results)

    def rollback_policy_batch(self, batch_result):
        """Conditionally restore policies from a previously returned result.

        Only policies recorded as ``applied`` (or whose earlier restore did not
        complete) are touched, and only when the policy currently stored in
        Vault still matches the captured evidence. Policies another
        administrator has since modified are reported as skipped and left
        alone. Unknown responses never trigger further blind writes.

        :param batch_result: The :class:`PolicyBatchResult` returned by an
            earlier :meth:`apply_policy_batch` call, or its ``to_dict()`` form.
        :type batch_result: PolicyBatchResult | dict
        :return: The same per-policy results with updated rollback statuses.
        :rtype: PolicyBatchResult
        """
        results = self._results_from(batch_result)
        self._rollback_applied(results)
        return self._build_result(results)

    def _collect_evidence(self, results):
        all_ok = True
        for result in results:
            response = self._request("get", self._policy_url(result.name))
            status_code = _status_code(response)
            if status_code is None:
                all_ok = False
                result.evidence = PolicyVersionEvidence(
                    name=result.name,
                    existed=False,
                    status_code=status_code,
                    detail="response carried no recognizable HTTP status code",
                )
                result.apply_status = EVIDENCE_UNKNOWN
                result.apply_status_code = status_code
                result.apply_detail = _READBACK_ADVICE
                result.readback_advised = True
                continue
            if status_code == 200:
                rules = _extract_rules(response)
                if rules is None:
                    all_ok = False
                    result.evidence = PolicyVersionEvidence(
                        name=result.name,
                        existed=False,
                        status_code=status_code,
                        detail="200 response did not contain data.rules",
                    )
                    result.apply_status = EVIDENCE_UNKNOWN
                    result.readback_advised = True
                    result.apply_detail = _READBACK_ADVICE
                    continue
                result.evidence = PolicyVersionEvidence(
                    name=result.name,
                    existed=True,
                    rules=rules,
                    fingerprint=_fingerprint(rules),
                    status_code=status_code,
                )
            elif status_code == 404:
                result.evidence = PolicyVersionEvidence(
                    name=result.name,
                    existed=False,
                    status_code=status_code,
                )
            elif status_code in _KNOWN_ERROR_STATUS_CODES:
                all_ok = False
                result.evidence = PolicyVersionEvidence(
                    name=result.name,
                    existed=False,
                    status_code=status_code,
                    detail=_error_detail(response),
                )
                result.apply_status = EVIDENCE_ERROR
                result.apply_status_code = status_code
                result.apply_detail = result.evidence.detail
            else:
                all_ok = False
                result.evidence = PolicyVersionEvidence(
                    name=result.name,
                    existed=False,
                    status_code=status_code,
                    detail=_error_detail(response),
                )
                result.apply_status = EVIDENCE_UNKNOWN
                result.apply_status_code = status_code
                result.apply_detail = _READBACK_ADVICE
                result.readback_advised = True
        return all_ok

    def _apply_one(self, result):
        current = self._read_current(result.name)
        if current.status == "unknown":
            result.apply_status = APPLY_UNKNOWN
            result.apply_status_code = current.status_code
            result.apply_detail = _READBACK_ADVICE
            result.readback_advised = True
            return "unknown"

        current_fingerprint = (
            _fingerprint(current.rules) if current.rules is not None else None
        )
        evidence_fingerprint = (
            result.evidence.fingerprint if result.evidence.existed else None
        )
        if current_fingerprint != evidence_fingerprint:
            result.apply_status = APPLY_CONFLICT
            result.apply_status_code = current.status_code
            result.apply_detail = (
                "policy changed since evidence was captured; write skipped"
            )
            return "conflict"

        payload = {"policy": _serialize_policy(result.desired_policy)}
        response = self._request(
            "put", self._policy_url(result.name), json=payload
        )
        status_code = _status_code(response)
        if status_code == 204:
            result.apply_status = APPLY_APPLIED
            result.apply_status_code = status_code
            result.apply_detail = None
            return "ok"
        if status_code in _KNOWN_ERROR_STATUS_CODES:
            result.apply_status = APPLY_ERROR
            result.apply_status_code = status_code
            result.apply_detail = _error_detail(response)
            return "known_error"
        result.apply_status = APPLY_UNKNOWN
        result.apply_status_code = status_code
        result.apply_detail = _READBACK_ADVICE
        result.readback_advised = True
        return "unknown"

    def _read_current(self, name):
        try:
            response = self._request("get", self._policy_url(name))
        except VaultError as exc:
            return _CurrentState("unknown", getattr(exc, "json", None), None)
        status_code = _status_code(response)
        if status_code == 200:
            rules = _extract_rules(response)
            if rules is None:
                return _CurrentState("unknown", None, status_code)
            return _CurrentState("ok", rules, status_code)
        if status_code == 404:
            return _CurrentState("ok", None, status_code)
        if status_code in _KNOWN_ERROR_STATUS_CODES:
            return _CurrentState("unknown", None, status_code)
        return _CurrentState("unknown", None, status_code)

    def _rollback_applied(self, results):
        for result in reversed(results):
            if result.apply_status != APPLY_APPLIED:
                continue
            evidence = result.evidence
            current = self._read_current(result.name)
            if current.status == "unknown":
                result.rollback_status = ROLLBACK_UNKNOWN
                result.rollback_status_code = current.status_code
                result.rollback_detail = _READBACK_ADVICE
                result.readback_advised = True
                continue
            # Roll back only while nobody else has taken over: the stored
            # policy is still the body this batch wrote, or (for a no-op
            # write) it still matches the captured evidence. Any other body
            # means another administrator changed the policy and must win.
            applied_fingerprint = _fingerprint(
                _serialize_policy(result.desired_policy)
            )
            current_fingerprint = (
                _fingerprint(current.rules) if current.rules is not None else None
            )
            evidence_fingerprint = evidence.fingerprint if evidence.existed else None
            if current_fingerprint not in (
                applied_fingerprint,
                evidence_fingerprint,
            ):
                result.rollback_status = ROLLBACK_SKIPPED
                result.rollback_status_code = current.status_code
                result.rollback_detail = (
                    "policy no longer matches the body this batch wrote; "
                    "another writer may own it now, rollback skipped"
                )
                continue
            if evidence.existed:
                response = self._request(
                    "put",
                    self._policy_url(result.name),
                    json={"policy": _serialize_policy(evidence.rules)},
                )
                status_code = _status_code(response)
                if status_code == 204:
                    result.rollback_status = ROLLBACK_RESTORED
                    result.rollback_status_code = status_code
                elif status_code in _KNOWN_ERROR_STATUS_CODES:
                    result.rollback_status = ROLLBACK_ERROR
                    result.rollback_status_code = status_code
                    result.rollback_detail = _error_detail(response)
                else:
                    result.rollback_status = ROLLBACK_UNKNOWN
                    result.rollback_status_code = status_code
                    result.rollback_detail = _READBACK_ADVICE
                    result.readback_advised = True
            else:
                response = self._request("delete", self._policy_url(result.name))
                status_code = _status_code(response)
                if status_code in (204, 404):
                    result.rollback_status = ROLLBACK_DELETED
                    result.rollback_status_code = status_code
                elif status_code in _KNOWN_ERROR_STATUS_CODES:
                    result.rollback_status = ROLLBACK_ERROR
                    result.rollback_status_code = status_code
                    result.rollback_detail = _error_detail(response)
                else:
                    result.rollback_status = ROLLBACK_UNKNOWN
                    result.rollback_status_code = status_code
                    result.rollback_detail = _READBACK_ADVICE
                    result.readback_advised = True

    def _build_result(self, results):
        readback_required = any(result.readback_advised for result in results)
        if readback_required:
            status = BATCH_UNKNOWN
        elif all(result.apply_status == APPLY_APPLIED for result in results):
            status = BATCH_SUCCEEDED
        else:
            # Conflicts, evidence/apply errors, or completed rollbacks all
            # mean the requested end state was not reached in full.
            status = BATCH_FAILED
        return PolicyBatchResult(
            results=results,
            status=status,
            readback_required=readback_required,
        )

    @staticmethod
    def _normalize_changes(changes):
        if not changes:
            raise ParamValidationError(
                "changes must contain at least one (name, policy) entry"
            )
        ordered = []
        seen = set()
        for entry in changes:
            if isinstance(entry, dict):
                name = entry.get("name")
                policy = entry.get("policy")
            else:
                try:
                    name, policy = entry
                except (TypeError, ValueError):
                    raise ParamValidationError(
                        "each change must be a (name, policy) pair or a "
                        "mapping with name and policy keys"
                    )
            if not name or not isinstance(name, str):
                raise ParamValidationError(
                    "policy name must be a non-empty string"
                )
            if policy is None:
                raise ParamValidationError(
                    "a policy document is required for %s" % name
                )
            if name in seen:
                raise ParamValidationError(
                    "duplicate policy name in batch: %s" % name
                )
            seen.add(name)
            ordered.append((name, policy))
        return ordered

    def _results_from(self, batch_result):
        if isinstance(batch_result, PolicyBatchResult):
            return list(batch_result.results)
        if isinstance(batch_result, dict) and "results" in batch_result:
            results = []
            for entry in batch_result["results"]:
                evidence_data = entry.get("evidence")
                evidence = (
                    PolicyVersionEvidence(
                        name=evidence_data["name"],
                        existed=evidence_data["existed"],
                        rules=evidence_data.get("rules"),
                        fingerprint=evidence_data.get("fingerprint"),
                        captured_at=evidence_data.get("captured_at"),
                        status_code=evidence_data.get("status_code"),
                        detail=evidence_data.get("detail"),
                    )
                    if evidence_data
                    else None
                )
                result = PolicyChangeResult(
                    name=entry["name"],
                    desired_policy=entry.get("desired_policy"),
                    evidence=evidence,
                )
                result.apply_status = entry.get(
                    "apply_status", APPLY_PENDING
                )
                result.apply_status_code = entry.get("apply_status_code")
                result.apply_detail = entry.get("apply_detail")
                result.rollback_status = entry.get(
                    "rollback_status", ROLLBACK_NOT_ATTEMPTED
                )
                result.rollback_status_code = entry.get(
                    "rollback_status_code"
                )
                result.rollback_detail = entry.get("rollback_detail")
                result.readback_advised = entry.get(
                    "readback_advised", False
                )
                results.append(result)
            return results
        raise ParamValidationError(
            "batch_result must be a PolicyBatchResult or the dict produced "
            "by its to_dict() method"
        )

    def _request(self, method, url, **kwargs):
        return self._adapter.request(
            method, url, raise_exception=False, **kwargs
        )

    @staticmethod
    def _policy_url(name):
        return utils.format_url("/v1/sys/policy/{name}", name=name)


class _CurrentState:
    def __init__(self, status, rules, status_code):
        self.status = status
        self.rules = rules
        self.status_code = status_code


def _status_code(response):
    status_code = getattr(response, "status_code", None)
    if status_code is not None:
        return status_code
    if isinstance(response, dict):
        return 200
    return None


def _extract_rules(response):
    if isinstance(response, dict):
        data = response.get("data")
        if isinstance(data, dict):
            return data.get("rules")
        return None
    try:
        body = response.json()
    except (AttributeError, ValueError):
        return None
    if not isinstance(body, dict):
        return None
    data = body.get("data")
    if isinstance(data, dict):
        return data.get("rules")
    return None


def _error_detail(response):
    if isinstance(response, dict):
        errors = response.get("errors")
    else:
        errors = None
        try:
            body = response.json()
        except (AttributeError, ValueError):
            body = None
        if isinstance(body, dict):
            errors = body.get("errors")
    if errors:
        return ", ".join(str(error) for error in errors)
    text = getattr(response, "text", None)
    return text


def _fingerprint(rules):
    canonical = _canonical(rules)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical(rules):
    if isinstance(rules, (dict, list)):
        return json.dumps(rules, sort_keys=True, separators=(",", ":"))
    # Vault returns policy bodies as text; that text is usually HCL but may be
    # a JSON document. Compare the parsed structure when we can so harmless
    # formatting differences do not look like concurrent edits.
    try:
        parsed = json.loads(rules)
    except (TypeError, ValueError):
        parsed = None
    if parsed is not None:
        return json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    try:
        import hcl

        parsed = hcl.loads(rules)
    except (ImportError, ValueError, TypeError):
        parsed = None
    if parsed is not None:
        return json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    # Last resort: whitespace-insensitive text comparison. HCL is
    # whitespace-tolerant, so two bodies differing only in spacing are the same
    # policy for coordination purposes.
    return " ".join(rules.split())


def _serialize_policy(policy):
    if isinstance(policy, dict):
        return json.dumps(policy, indent=4, sort_keys=True)
    return policy


def _utc_now():
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
