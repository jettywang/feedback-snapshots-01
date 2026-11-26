"""
A small in-memory IAM rule engine used to reason about the *effective* permissions of a
policy while it is rolled out in multiple batches.

The engine intentionally covers the policy elements that Policy Sentry generates and that
matter for batch safety analysis:

* ``Effect`` / ``Action`` / ``NotAction`` / ``Resource`` / ``NotResource``
* ``Principal`` is treated as opaque and only honoured for resource policies that already
  target the caller.
* ``Condition`` is evaluated for the subset of condition operators that can be decided
  from an in-memory request context; anything else evaluates to ``False`` for an Allow
  and ``True`` for a Deny (i.e. undecidable conditions fail *closed* for allows and
  *open* for denies, matching the conservative posture the release planner needs).

The engine is not an AWS re-implementation. It exists so that every candidate batch plan
can be replayed against concrete requests and compared with the original, fully
installed policy.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

# Operators whose effect should be inverted when the request value does not match.
_SIMPLE_NEGATION = {"stringnotequals", "stringnotlike", "datenotequals",
                    "numericnotequals", "notipaddress", "arnnotequals", "arnnotlike"}


def _as_list(value: Any) -> list[Any]:
    """Normalise an IAM clause (string or list) into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def wildcard_match(pattern: str, value: str) -> bool:
    """
    Case-insensitive IAM style wildcard match supporting ``*`` and ``?``.

    ``fnmatch`` is case sensitive on POSIX, so both sides are lower-cased first; IAM
    action and ARN matching is case insensitive for the pattern characters.
    """
    return fnmatch.fnmatchcase(str(value).lower(), str(pattern).lower())


@dataclass(frozen=True)
class AccessRequest:
    """A concrete request to evaluate against one or more policies."""

    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)
    principal: str = "*"


def _request_matches_clause(request_value: str, clause_values: list[Any]) -> bool:
    return any(wildcard_match(str(clause), request_value) for clause in clause_values)


def _not_clause_matches(request_value: str, clause_values: list[Any]) -> bool:
    # NotAction / NotResource match when *none* of the listed patterns match.
    return not _request_matches_clause(request_value, clause_values)


def _context_key_matches(operator: str, key: str, expected: Any, request: AccessRequest) -> bool:
    """Evaluate a single condition key against the request context (fail closed)."""
    base_operator = operator.split(":", 1)[-1].lower()
    qualified = operator.lower()
    context_value = request.context.get(key)
    if qualified.endswith("ifexists") and context_value is None:
        # IfExists operators vacuously pass when the key is absent.
        return True
    if context_value is None:
        return False

    actual_values = context_value if isinstance(context_value, list) else [context_value]
    expected_values = expected if isinstance(expected, list) else [expected]

    if base_operator in {"stringequals", "stringequalsifexists"}:
        return any(str(actual) == str(want) for actual in actual_values for want in expected_values)
    if base_operator in {"stringnotequals", "stringnotequalsifexists"}:
        return all(str(actual) != str(want) for actual in actual_values for want in expected_values)
    if base_operator in {"stringlike", "stringlikeifexists"}:
        return any(wildcard_match(str(want), str(actual)) for actual in actual_values for want in expected_values)
    if base_operator in {"stringnotlike", "stringnotlikeifexists"}:
        return all(not wildcard_match(str(want), str(actual)) for actual in actual_values for want in expected_values)
    if base_operator.startswith("numeric"):
        try:
            actual_nums = [float(actual) for actual in actual_values]
            expected_nums = [float(want) for want in expected_values]
        except (TypeError, ValueError):
            return False
        if base_operator in {"numericequals"}:
            return any(actual == want for actual in actual_nums for want in expected_nums)
        if base_operator == "numericnotequals":
            return all(actual != want for actual in actual_nums for want in expected_nums)
        if base_operator == "numericlessthan":
            return any(actual < want for actual in actual_nums for want in expected_nums)
        if base_operator == "numericlessthanequals":
            return any(actual <= want for actual in actual_nums for want in expected_nums)
        if base_operator == "numericgreaterthan":
            return any(actual > want for actual in actual_nums for want in expected_nums)
        if base_operator == "numericgreaterthanequals":
            return any(actual >= want for actual in actual_nums for want in expected_nums)
    if base_operator in {"ipaddress", "notipaddress"}:
        # Full CIDR evaluation needs the ipaddress module; exact string matches still work.
        matched = any(str(actual) == str(want) for actual in actual_values for want in expected_values)
        return matched if base_operator == "ipaddress" else not matched
    if base_operator in {"arnequals", "arnlike", "arnnotequals", "arnnotlike"}:
        like = base_operator in {"arnlike", "arnnotlike"}
        matched = any(
            wildcard_match(str(want), str(actual)) if like else str(actual) == str(want)
            for actual in actual_values
            for want in expected_values
        )
        return matched if base_operator not in _SIMPLE_NEGATION else not matched
    # Operator we cannot decide (Bool, Date*, multivalued set-qualifiers, ...): fail closed.
    return False


def _condition_matches(condition_block: dict[str, Any] | None, request: AccessRequest) -> bool:
    if not condition_block:
        return True
    for operator, key_clause in condition_block.items():
        if not isinstance(key_clause, dict):
            return False
        for key, expected in key_clause.items():
            if not _context_key_matches(operator, key, expected, request):
                return False
    return True


def _principal_matches(statement: dict[str, Any], request: AccessRequest) -> bool:
    principal = statement.get("Principal")
    if principal is None:
        # Identity policy: principal is implicit and always matches.
        return True
    if principal == "*":
        return True
    if isinstance(principal, dict):
        values: list[Any] = []
        for clause in principal.values():
            values.extend(_as_list(clause))
    else:
        values = _as_list(principal)
    return _request_matches_clause(request.principal, values)


def statement_matches(statement: dict[str, Any], request: AccessRequest) -> bool:
    """
    Return whether a request matches *every* non-effect element of a statement.

    A returned ``True`` means the statement's Effect applies to the request (allow or
    deny); ``False`` means the statement is irrelevant to the request.
    """
    if not _principal_matches(statement, request):
        return False

    action_clause = statement.get("Action")
    if action_clause is not None:
        if not _request_matches_clause(request.action, _as_list(action_clause)):
            return False
    elif not _not_clause_matches(request.action, _as_list(statement.get("NotAction", []))):
        return False

    resource_clause = statement.get("Resource")
    if resource_clause is not None:
        if not _request_matches_clause(request.resource, _as_list(resource_clause)):
            return False
    elif not _not_clause_matches(request.resource, _as_list(statement.get("NotResource", []))):
        return False

    return _condition_matches(statement.get("Condition"), request)


def evaluate_policies(policies: list[dict[str, Any]], request: AccessRequest) -> str:
    """
    Evaluate a request against the union of several policies (the set currently installed).

    Returns ``"Allow"`` or ``"Deny"`` following the standard evaluation order: an
    explicit Deny anywhere wins; otherwise any matching Allow grants access; otherwise
    the decision is an implicit Deny.
    """
    explicit_deny = False
    explicit_allow = False
    for policy in policies:
        statements = _as_list(policy.get("Statement", []))
        for statement in statements:
            if not statement_matches(statement, request):
                continue
            effect = statement.get("Effect", "Allow")
            if effect == "Deny":
                explicit_deny = True
            else:
                explicit_allow = True
    if explicit_deny:
        return "Deny"
    if explicit_allow:
        return "Allow"
    return "Deny"


def effective_permissions(policies: list[dict[str, Any]], requests: list[AccessRequest]) -> dict[tuple[str, str], str]:
    """Convenience: evaluate a matrix of (action, resource) requests."""
    decisions: dict[tuple[str, str], str] = {}
    for request in requests:
        decisions[(request.action, request.resource)] = evaluate_policies(policies, request)
    return decisions


def requests_from_policy(policy: dict[str, Any]) -> list[AccessRequest]:
    """
    Build concrete probe requests from the explicit actions/resources of a policy.

    Wildcards are kept as literal probe values so that wildcard statements are covered
    during replay. NotAction/NotResource statements contribute no probes of their own;
    their protective behaviour is exercised via the probes generated by the allows.
    """
    requests: list[AccessRequest] = []
    for statement in _as_list(policy.get("Statement", [])):
        if statement.get("Effect") == "Deny":
            continue
        actions = _as_list(statement.get("Action"))
        if not actions:
            continue
        resources = _as_list(statement.get("Resource")) or ["*"]
        for action in actions:
            for resource in resources:
                requests.append(AccessRequest(action=str(action), resource=str(resource)))
    # De-duplicate while preserving order.
    seen: set[tuple[str, str]] = set()
    unique: list[AccessRequest] = []
    for request in requests:
        marker = (request.action, request.resource)
        if marker not in seen:
            seen.add(marker)
            unique.append(request)
    return unique
