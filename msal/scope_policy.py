"""Opt-in policies for narrowing silent token reuse.

The default MSAL cache behavior intentionally reuses an access token when the
requested scopes are a subset of the cached token's scopes.  Backend audits
which require exact consent can opt into :class:`StrictScopePolicy`.

The policy is deliberately data-only and has no dependency on the application
object, so callers can construct one constant and reuse it across calls.
"""

try:  # Python 3.9+
    from collections.abc import Mapping
except ImportError:  # pragma: no cover - supported older runtimes
    from collections import Mapping


# These scopes are added by MSAL/OpenID Connect rather than requested by the
# business API.  Exact business-scope comparison therefore ignores them unless
# a caller explicitly asks for wire-level exactness.
RESERVED_SCOPES = frozenset(("openid", "profile", "offline_access"))

DEFAULT_APPROVED_SOURCES = frozenset((
    "cache",
    "identity_provider",
    "idp",  # Tolerate the short spelling in hand-built fixtures.
    "broker",
))

SCOPE_MISMATCH = "scope_mismatch"
SOURCE_MISMATCH = "source_mismatch"
EXACT_MATCH = "exact_match"


def normalize_scope_set(scopes):
    """Return a case-sensitive set from a list, set, or wire scope string."""
    if scopes is None:
        return frozenset()
    if isinstance(scopes, str):
        scopes = scopes.split()
    return frozenset(scopes)


def exact_scope_set(scopes, *, include_reserved_scopes=False):
    values = normalize_scope_set(scopes)
    if not include_reserved_scopes:
        values = values - RESERVED_SCOPES
    return frozenset(values)


class StrictScopePolicy(object):
    """Require exact scope equivalence and an approved credential source.

    :param approved_sources:
        Source labels allowed to satisfy a strict request.  A cache entry may
        declare its source in ``approval_source``, ``approved_source`` or
        ``source``.  Entries without such a field are treated as ``cache``;
        token endpoint and broker results are treated as
        ``identity_provider`` and ``broker`` respectively.

        Defaults to the built-in MSAL delivery sources.  Pass an explicit
        consent/approval system name (for example
        ``approved_sources={"backend-audit"}``) when provenance must be pinned
        to that system.  ``"*"`` approves any source label.
    :param approved_environments:
        Optional allowlist of authority hosts.  When set, a cache entry or
        token response from any other environment is rejected even if its
        scope and source label match.
    :param include_reserved_scopes:
        Compare the complete wire target, including ``openid``, ``profile`` and
        ``offline_access``.  The default (``False``) compares only the
        business/resource scopes because MSAL adds the reserved OIDC scopes.
    """

    mode = "strict"

    def __init__(
            self,
            approved_sources=None,
            *,
            approved_source=None,
            allowed_sources=None,
            allowed_source=None,
            sources=None,
            source=None,
            approved_environments=None,
            allowed_environments=None,
            source_fields=None,
            include_reserved_scopes=False):
        source_values = self._string_values(
            approved_sources,
            approved_source,
            allowed_sources,
            allowed_source,
            sources,
            source,
        )
        environment_values = self._string_values(
            approved_environments, allowed_environments)

        self.approved_sources = (
            frozenset(DEFAULT_APPROVED_SOURCES)
            if source_values is None else frozenset(source_values))
        self.approved_environments = (
            None if environment_values is None
            else frozenset(value.lower() for value in environment_values))
        self.source_fields = tuple(source_fields or (
            "approval_source",
            "approved_source",
            "source",
            "token_source",
        ))
        self.include_reserved_scopes = include_reserved_scopes

    @staticmethod
    def _string_values(*values):
        result = []
        saw_value = False
        for value in values:
            if value is None:
                continue
            saw_value = True
            if isinstance(value, str):
                result.append(value)
            else:
                result.extend(value)
        return result if saw_value else None

    def scope_key(self, scopes):
        return exact_scope_set(
            scopes, include_reserved_scopes=self.include_reserved_scopes)

    def scopes_are_equal(self, granted_scopes, requested_scopes):
        return self.scope_key(granted_scopes) == self.scope_key(requested_scopes)

    def source_from(self, candidate, fallback=None):
        if not isinstance(candidate, Mapping):
            return fallback
        for field_name in self.source_fields:
            value = candidate.get(field_name)
            if value:
                return value
        return fallback

    def source_is_approved(self, source, environment=None):
        if "*" not in self.approved_sources and source not in self.approved_sources:
            return False
        if self.approved_environments is None:
            return True
        return bool(
            environment
            and environment.lower() in self.approved_environments)

    def evaluate_cache_entry(self, entry, requested_scopes):
        """Return ``(allowed, reason)`` for an AccessToken cache entry."""
        if not isinstance(entry, Mapping):
            return False, SOURCE_MISMATCH
        if not self.scopes_are_equal(entry.get("target"), requested_scopes):
            return False, SCOPE_MISMATCH
        source = self.source_from(entry, self._CACHE_SOURCE)
        if not self.source_is_approved(source, entry.get("environment")):
            return False, SOURCE_MISMATCH
        return True, EXACT_MATCH

    def evaluate_token_response(
            self, response, requested_scopes, *, source, environment=None):
        """Validate a refresh/broker token response before it is returned."""
        if not isinstance(response, Mapping) or "error" in response:
            return False, "error"
        # RFC 6749 permits a refresh response to omit scope; omission means the
        # issued scope is the requested/previously granted scope.  When scope is
        # present, however, it must be exactly equivalent under this policy.
        if "scope" in response and not self.scopes_are_equal(
                response.get("scope"), requested_scopes):
            return False, SCOPE_MISMATCH
        response_source = self.source_from(response, source)
        if not self.source_is_approved(response_source, environment):
            return False, SOURCE_MISMATCH
        return True, EXACT_MATCH

    def evaluate_cache_event(self, event, requested_scopes, *, environment=None):
        response = event.get("response", {}) if isinstance(event, Mapping) else {}
        granted_scopes = response.get("scope", event.get("scope", requested_scopes))
        if not self.scopes_are_equal(granted_scopes, requested_scopes):
            return False, SCOPE_MISMATCH
        source = self.source_from(response) or self.source_from(event) or "identity_provider"
        event_environment = event.get("environment") or environment
        if not self.source_is_approved(source, event_environment):
            return False, SOURCE_MISMATCH
        return True, EXACT_MATCH

    _CACHE_SOURCE = "cache"


def coerce_scope_policy(
        policy=None,
        *,
        strict=False,
        approved_sources=None,
        approved_source=None,
        allowed_sources=None,
        allowed_source=None,
        sources=None,
        source=None):
    """Coerce the public convenience parameters into a policy instance."""
    source_kwargs = dict(
        approved_sources=approved_sources,
        approved_source=approved_source,
        allowed_sources=allowed_sources,
        allowed_source=allowed_source,
        sources=sources,
        source=source,
    )
    has_source_override = any(value is not None for value in source_kwargs.values())

    if policy is None or policy is False:
        if not strict and not has_source_override:
            return None
        return StrictScopePolicy(**source_kwargs)

    if isinstance(policy, StrictScopePolicy):
        if has_source_override:
            # Convenience source arguments narrow/replace a default policy.
            return StrictScopePolicy(
                **source_kwargs,
                approved_environments=policy.approved_environments,
                include_reserved_scopes=policy.include_reserved_scopes,
            )
        return policy

    if policy is True or (isinstance(policy, str) and policy.lower() in ("strict", "exact")):
        return StrictScopePolicy(**source_kwargs)

    if isinstance(policy, Mapping):
        options = dict(policy)
        options.update({k: v for k, v in source_kwargs.items() if v is not None})
        return StrictScopePolicy(**options)

    raise TypeError(
        "scope_policy must be None, True, 'strict', or a StrictScopePolicy; "
        "got {!r}".format(type(policy).__name__))


def pop_scope_policy_kwargs(kwargs):
    """Extract compatibility aliases without sending them on the wire."""
    strict = False
    for name in (
            "strict_scopes",
            "strict_scope",
            "exact_scopes",
            "exact_scope",
            "require_exact_scope",
            "exact_scope_match",
            "strict_scope_match",
            "strict"):
        if name in kwargs:
            strict = bool(kwargs.pop(name)) or strict

    policy = None
    for policy_name in (
            "scope_policy",
            "strict_scope_policy",
            "scope_strategy",
            "strict_scope_strategy"):
        if policy_name in kwargs:
            policy_alias = kwargs.pop(policy_name)
            if policy is None:
                policy = policy_alias
            elif policy_alias is not None:
                strict = bool(policy_alias) or strict
    approved_sources = None
    source_values = {}
    source_aliases = [
            ("approved_sources", "approved_sources"),
            ("allowed_sources", "allowed_sources"),
            ("source_allowlist", "allowed_sources"),
            ("source_allow_list", "allowed_sources"),
            ("trusted_sources", "allowed_sources"),
            ("valid_sources", "approved_sources"),
            ("approved_source", "approved_source"),
            ("allowed_source", "allowed_source"),
            ("trusted_source", "allowed_source"),
    ]
    if strict or policy is not None:
        source_aliases.extend([
            ("sources", "sources"),
            ("source", "source"),
        ])
    for name, option_name in source_aliases:
        if name in kwargs:
            source_values[option_name] = kwargs.pop(name)

    approved_sources = source_values.pop("approved_sources", None)
    allowed_sources = source_values.pop("allowed_sources", None)
    if approved_sources is None:
        approved_sources = allowed_sources
    return coerce_scope_policy(
        policy,
        strict=strict,
        approved_sources=approved_sources,
        **source_values)


def strict_policy_error(reason):
    """Build the non-token error returned by ``..._with_error`` in strict mode."""
    descriptions = {
        SCOPE_MISMATCH: (
            "No cached or refreshed token has exactly the requested scope set."),
        SOURCE_MISMATCH: (
            "No cached or refreshed token comes from an approved source."),
    }
    return {
        "error": "strict_scope_policy_violation",
        "error_description": descriptions.get(
            reason, "The token did not satisfy the strict scope policy."),
        "strict_scope_reason": reason,
    }


# Common naming alternatives used by callers and review checklists.
StrictScopesPolicy = StrictScopePolicy
ExactScopePolicy = StrictScopePolicy
StrictScope = StrictScopePolicy
