"""Application-declared policy for external identity exchanges.

The policy binds the source of identity evidence, the STS audience, and the
service account that may be reached through impersonation. A successful source
read or STS exchange is evidence that the operation happened; it is never
itself authorization for a later delegation stage.
"""

from dataclasses import dataclass, field, replace
import os
from typing import Any, Iterable, Mapping, Optional, Pattern, Tuple

from google.auth import exceptions

STAGE_EVIDENCE = "evidence"
STAGE_EXCHANGE = "exchange"
STAGE_DELEGATION = "delegation"
STAGE_CREDENTIAL_UPDATE = "credential_update"


class ExchangePolicyError(exceptions.GoogleAuthError):
    """Base class for external exchange policy failures."""


class ExchangePermissionDenied(exceptions.RefreshError, PermissionError):
    """The application policy does not permit an exchange stage."""


class ExchangeApprovalRequired(ExchangePermissionDenied):
    """A result was obtained, but the next stage still needs approval."""

    def __init__(self, *args, pending: Any = None, **kwargs):
        super(ExchangeApprovalRequired, self).__init__(*args, **kwargs)
        self.pending = pending


ExchangePolicyViolation = ExchangePermissionDenied
AuthorizationRequired = ExchangeApprovalRequired
ApprovalPendingError = ExchangeApprovalRequired


def _context_kwargs(kwargs):
    aliases = {
        "evidence_source": "source",
        "subject_source": "source",
        "source_identifier": "source",
        "target": "service_account",
        "target_principal": "service_account",
        "service_account_email": "service_account",
        "allowed_service_account": "service_account",
        "token_uri": "token_url",
        "sts_url": "token_url",
        "impersonation_endpoint": "impersonation_url",
    }
    return {aliases.get(key, key): value for key, value in kwargs.items()}


@dataclass(frozen=True)
class ExchangeContext:
    """The immutable source and target to which a policy check applies."""

    source: Optional[Any] = None
    audience: Optional[str] = None
    service_account: Optional[str] = None
    token_url: Optional[str] = None
    impersonation_url: Optional[str] = None
    credential_source: Any = None
    source_aliases: Tuple[str, ...] = ()

    @classmethod
    def coerce(cls, value: Any = None, **kwargs: Any) -> "ExchangeContext":
        if value is None:
            return cls(**_context_kwargs(kwargs))
        if isinstance(value, ExchangeContext):
            if not kwargs:
                return value
            data = {
                "source": value.source,
                "audience": value.audience,
                "service_account": value.service_account,
                "token_url": value.token_url,
                "impersonation_url": value.impersonation_url,
                "credential_source": value.credential_source,
                "source_aliases": value.source_aliases,
            }
            data.update(_context_kwargs(kwargs))
            return cls(**data)
        if isinstance(value, Mapping):
            data = dict(value)
            data.update(_context_kwargs(kwargs))
            known = cls.__dataclass_fields__
            return cls(**{key: val for key, val in data.items() if key in known})
        if isinstance(value, str):
            data = _context_kwargs(kwargs)
            data.setdefault("source", value)
            return cls(**data)
        raise TypeError("Unable to convert value to ExchangeContext")

    @classmethod
    def from_credentials(cls, credentials: Any) -> "ExchangeContext":
        credential_source = getattr(credentials, "_credential_source", None)
        supplier = getattr(credentials, "_subject_token_supplier", None)
        explicit_source = getattr(credentials, "_exchange_source", None)
        aliases = list(
            describe_source_aliases(explicit_source, credential_source, supplier)
        )
        for attribute in (
            "service_account_email",
            "_service_account_email",
            "client_email",
            "_client_email",
        ):
            try:
                value = getattr(credentials, attribute, None)
            except Exception:
                value = None
            if value:
                aliases.append(str(value))
        if not aliases and credentials is not None:
            source_class = credentials.__class__
            aliases.append(
                "{}.{}".format(source_class.__module__, source_class.__name__)
            )
        normalized = []
        for alias in aliases:
            if alias not in normalized:
                normalized.append(alias)
        aliases = tuple(normalized)
        source = (
            explicit_source
            if explicit_source is not None
            else (aliases[0] if aliases else None)
        )
        try:
            service_account = credentials.service_account_email
        except Exception:
            service_account = None
        return cls(
            source=source,
            audience=getattr(credentials, "_audience", None),
            service_account=service_account,
            token_url=getattr(credentials, "_token_url", None),
            impersonation_url=getattr(
                credentials, "_service_account_impersonation_url", None
            ),
            credential_source=credential_source,
            source_aliases=aliases,
        )

    @property
    def source_values(self) -> Tuple[Any, ...]:
        values = []
        if self.source is not None:
            values.append(self.source)
        values.extend(self.source_aliases)
        if isinstance(self.credential_source, Mapping):
            values.append(self.credential_source)
        return tuple(values)


IdentityExchangeContext = ExchangeContext


@dataclass(frozen=True)
class PendingExchange:
    """A completed prefix that must not be exposed as a service account token."""

    context: ExchangeContext
    completed_stages: Tuple[str, ...]
    status: str = "approval_required"

    @property
    def is_service_account_identity(self) -> bool:
        return False

    @property
    def has_usable_token(self) -> bool:
        return False


PendingExchangeResult = PendingExchange


def describe_source_aliases(
    explicit_source: Any = None,
    credential_source: Any = None,
    supplier: Any = None,
) -> Tuple[str, ...]:
    """Returns stable identifiers for an identity-evidence source."""
    aliases = []

    def add(value: Any, prefix: Optional[str] = None) -> None:
        if value is None:
            return
        value = str(value)
        if not value:
            return
        aliases.append(value)
        if prefix:
            aliases.append("{}:{}".format(prefix, value))

    if explicit_source is not None:
        add(explicit_source)

    if isinstance(credential_source, Mapping):
        for key, prefix in (
            ("file", "file"),
            ("url", "url"),
            ("environment_id", "environment"),
            ("regional_cred_verification_url", "url"),
        ):
            add(credential_source.get(key), prefix)
        executable = credential_source.get("executable")
        if isinstance(executable, Mapping):
            add(executable.get("command"), "executable")
            add(executable.get("output_file"), "file")

    if supplier is not None:
        for attribute in ("source_id", "identifier", "location", "path", "url"):
            add(getattr(supplier, attribute, None))
        source_class = supplier.__class__
        add("{}.{}".format(source_class.__module__, source_class.__name__))

    normalized = []
    for alias in aliases:
        if alias not in normalized:
            normalized.append(alias)
    return tuple(normalized)


def _mapping_contains(actual: Mapping[Any, Any], expected: Mapping[Any, Any]) -> bool:
    for key, value in expected.items():
        if key not in actual:
            return False
        if isinstance(value, Mapping):
            if not isinstance(actual[key], Mapping) or not _mapping_contains(
                actual[key], value
            ):
                return False
        elif actual[key] != value:
            return False
    return True


def source_matches(expected: Any, context: ExchangeContext) -> bool:
    if expected is None:
        return False
    if isinstance(expected, os.PathLike):
        expected = os.fspath(expected)
    if isinstance(expected, (list, tuple, set, frozenset)):
        return any(source_matches(item, context) for item in expected)
    if isinstance(expected, Pattern):
        return any(
            isinstance(value, str) and expected.fullmatch(value) is not None
            for value in context.source_values
        )
    if isinstance(expected, Mapping):
        return any(
            isinstance(value, Mapping) and _mapping_contains(value, expected)
            for value in context.source_values
        )
    if callable(expected) and not isinstance(expected, type):
        try:
            if expected(context.source) is True:
                return True
        except Exception:
            pass
        return expected(context) is True
    return expected in context.source_values


def _as_permission_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        return [value]
    return list(value)


def _value_matches(expected: Any, actual: Any) -> bool:
    if expected is None:
        return True
    if isinstance(expected, Pattern):
        return actual is not None and expected.fullmatch(str(actual)) is not None
    if isinstance(expected, (list, tuple, set, frozenset)):
        return actual in expected
    return expected == actual


@dataclass(frozen=True)
class EvidencePermission:
    """Permission to read identity evidence from one source."""

    source: Any
    grant_id: Optional[str] = None

    def matches(self, context: ExchangeContext) -> bool:
        return source_matches(self.source, context)


@dataclass(frozen=True)
class ExchangePermission:
    """Permission to exchange a bound source at a specific STS audience."""

    source: Any
    audience: Any
    token_url: Any = None
    grant_id: Optional[str] = None

    def matches(self, context: ExchangeContext) -> bool:
        return (
            source_matches(self.source, context)
            and _value_matches(self.audience, context.audience)
            and _value_matches(self.token_url, context.token_url)
        )


@dataclass(frozen=True)
class DelegationPermission:
    """Permission to delegate an exchanged identity to a service account."""

    source: Any
    audience: Any
    service_account: Any
    token_url: Any = None
    impersonation_url: Any = None
    grant_id: Optional[str] = None

    def matches(self, context: ExchangeContext) -> bool:
        target = context.service_account
        if isinstance(self.service_account, str) and target is not None:
            target_match = self.service_account.lower() == str(target).lower()
        else:
            target_match = _value_matches(self.service_account, target)
        return (
            source_matches(self.source, context)
            and _value_matches(self.audience, context.audience)
            and target_match
            and _value_matches(self.token_url, context.token_url)
            and _value_matches(self.impersonation_url, context.impersonation_url)
        )


EvidenceGrant = EvidencePermission
ExchangeStagePermission = ExchangePermission
DelegationGrant = DelegationPermission


class ExchangeGrant:
    """A convenient bound source/audience/target declaration."""

    def __init__(
        self,
        source: Any,
        audience: Any = None,
        service_account: Any = None,
        *,
        target_principal: Any = None,
        target: Any = None,
        allowed_service_account: Any = None,
        token_url: Any = None,
        token_uri: Any = None,
        impersonation_url: Any = None,
        impersonation_endpoint: Any = None,
        grant_id: Optional[str] = None,
    ):
        self.source = source
        self.audience = audience
        self.service_account = (
            service_account or target_principal or target or allowed_service_account
        )
        self.token_url = token_url or token_uri
        self.impersonation_url = impersonation_url or impersonation_endpoint
        self.grant_id = grant_id

    def evidence_permission(self) -> EvidencePermission:
        return EvidencePermission(self.source, self.grant_id)

    def exchange_permission(self) -> Optional[ExchangePermission]:
        if self.audience is None:
            return None
        return ExchangePermission(
            self.source, self.audience, self.token_url, self.grant_id
        )

    def delegation_permission(self) -> Optional[DelegationPermission]:
        if self.audience is None or self.service_account is None:
            return None
        return DelegationPermission(
            self.source,
            self.audience,
            self.service_account,
            self.token_url,
            self.impersonation_url,
            self.grant_id,
        )


IdentityExchangeGrant = ExchangeGrant


@dataclass(frozen=True)
class ExchangeApproval:
    """An application approval bound to one immutable source and target."""

    context: ExchangeContext
    policy: "IdentityExchangePolicy" = field(repr=False, compare=False)
    grant_id: Optional[str] = None

    def require(self, stage: str) -> "ExchangeApproval":
        if stage == STAGE_EVIDENCE:
            return self.require_evidence()
        if stage == STAGE_EXCHANGE:
            return self.require_exchange()
        if stage == STAGE_DELEGATION:
            return self.require_delegation()
        if stage == STAGE_CREDENTIAL_UPDATE:
            return self
        raise ExchangePolicyError("Unknown exchange stage: {}".format(stage))

    def require_evidence(self) -> "ExchangeApproval":
        return self.policy.authorize_evidence(self.context)

    def require_exchange(self) -> "ExchangeApproval":
        return self.policy.authorize_exchange(self.context)

    def require_delegation(self) -> "ExchangeApproval":
        return self.policy.authorize_delegation(self.context)


ApprovedExchange = ExchangeApproval


class IdentityExchangePolicy:
    """Declares which source/audience/target combinations are permitted."""

    def __init__(
        self,
        grants: Optional[Iterable[Any]] = None,
        *,
        permissions: Optional[Iterable[Any]] = None,
        evidence: Optional[Iterable[EvidencePermission]] = None,
        exchanges: Optional[Iterable[ExchangePermission]] = None,
        delegations: Optional[Iterable[DelegationPermission]] = None,
    ):
        self.evidence_permissions = []
        self.exchange_permissions = []
        self.delegation_permissions = []
        self._allow_all = False

        for item in _as_permission_list(evidence):
            self.add(item)
        for item in _as_permission_list(exchanges):
            self.add(item)
        for item in _as_permission_list(delegations):
            self.add(item)
        for item in _as_permission_list(grants) + _as_permission_list(permissions):
            self.add(item)

    @classmethod
    def allow_all(cls) -> "IdentityExchangePolicy":
        """Returns a recording-only policy that performs no restriction."""
        policy = cls()
        policy._allow_all = True
        return policy

    def add(self, item: Any) -> "IdentityExchangePolicy":
        if isinstance(item, ExchangeGrant):
            evidence = item.evidence_permission()
            exchange = item.exchange_permission()
            delegation = item.delegation_permission()
            self.evidence_permissions.append(evidence)
            if exchange is not None:
                self.exchange_permissions.append(exchange)
            if delegation is not None:
                self.exchange_permissions.append(exchange)
                self.delegation_permissions.append(delegation)
        elif isinstance(item, EvidencePermission):
            self.evidence_permissions.append(item)
        elif isinstance(item, ExchangePermission):
            self.evidence_permissions.append(EvidencePermission(item.source))
            self.exchange_permissions.append(item)
        elif isinstance(item, DelegationPermission):
            self.evidence_permissions.append(EvidencePermission(item.source))
            self.exchange_permissions.append(
                ExchangePermission(item.source, item.audience, item.token_url)
            )
            self.delegation_permissions.append(item)
        elif isinstance(item, Mapping):
            self.add(_grant_from_mapping(item))
        else:
            raise TypeError("Unsupported exchange permission: {!r}".format(item))
        return self

    def approve(self, value: Any = None, **kwargs: Any) -> ExchangeApproval:
        context = ExchangeContext.coerce(value, **kwargs)
        grant_id = None
        for permission in self.delegation_permissions:
            if permission.matches(context):
                grant_id = permission.grant_id
                break
        if grant_id is None:
            for permission in self.exchange_permissions:
                if permission.matches(context):
                    grant_id = permission.grant_id
                    break
        return ExchangeApproval(context=context, policy=self, grant_id=grant_id)

    def authorize_evidence(self, value: Any = None, **kwargs: Any) -> ExchangeApproval:
        context = ExchangeContext.coerce(value, **kwargs)
        if self._allow_all:
            return ExchangeApproval(context, self)
        for permission in self.evidence_permissions:
            if permission.matches(context):
                return ExchangeApproval(context, self, permission.grant_id)
        raise ExchangePermissionDenied(
            "External identity evidence source is not approved: {!r}".format(
                context.source
            )
        )

    def authorize_exchange(self, value: Any = None, **kwargs: Any) -> ExchangeApproval:
        context = ExchangeContext.coerce(value, **kwargs)
        if self._allow_all:
            return ExchangeApproval(context, self)
        for permission in self.exchange_permissions:
            if permission.matches(context):
                return ExchangeApproval(context, self, permission.grant_id)
        raise ExchangePermissionDenied(
            "External identity exchange is not approved for source={!r}, "
            "audience={!r}".format(context.source, context.audience)
        )

    def authorize_delegation(
        self, value: Any = None, **kwargs: Any
    ) -> ExchangeApproval:
        context = ExchangeContext.coerce(value, **kwargs)
        if self._allow_all:
            return ExchangeApproval(context, self)
        for permission in self.delegation_permissions:
            if permission.matches(context):
                return ExchangeApproval(context, self, permission.grant_id)

        exchange_approved = any(
            permission.matches(context) for permission in self.exchange_permissions
        )
        if exchange_approved:
            pending = PendingExchange(
                context=context,
                completed_stages=(STAGE_EVIDENCE, STAGE_EXCHANGE),
            )
            raise ExchangeApprovalRequired(
                "STS exchange is approved but delegation to {!r} is not "
                "approved for the same source and audience.".format(
                    context.service_account
                ),
                pending=pending,
            )
        raise ExchangePermissionDenied(
            "External identity delegation is not approved for source={!r}, "
            "audience={!r}, service_account={!r}".format(
                context.source, context.audience, context.service_account
            )
        )

    def can(self, stage: str, value: Any = None, **kwargs: Any) -> bool:
        try:
            if stage == STAGE_EVIDENCE:
                self.authorize_evidence(value, **kwargs)
            elif stage == STAGE_EXCHANGE:
                self.authorize_exchange(value, **kwargs)
            elif stage == STAGE_DELEGATION:
                self.authorize_delegation(value, **kwargs)
            else:
                raise ExchangePolicyError("Unknown stage: {}".format(stage))
            return True
        except ExchangePermissionDenied:
            return False


ExchangePolicy = IdentityExchangePolicy


def _grant_from_mapping(data: Mapping[str, Any]) -> ExchangeGrant:
    source = data.get("source") or data.get("evidence_source")
    if source is None:
        raise ValueError("An exchange grant mapping requires a source")
    return ExchangeGrant(
        source=source,
        audience=data.get("audience"),
        service_account=(
            data.get("service_account")
            or data.get("target_principal")
            or data.get("delegate_to")
        ),
        token_url=data.get("token_url") or data.get("token_uri"),
        impersonation_url=(
            data.get("impersonation_url")
            or data.get("service_account_impersonation_url")
        ),
        grant_id=data.get("grant_id") or data.get("id"),
    )


@dataclass(frozen=True)
class ExchangeEvent:
    """One recorded exchange stage."""

    stage: str
    sequence: int


class LocalExchangeRecorder:
    """In-memory recorder used by tests and local diagnostics."""

    def __init__(self) -> None:
        self.events = []
        self._count = 0

    @property
    def stages(self) -> Tuple[str, ...]:
        return tuple(event.stage for event in self.events)

    def record(self, stage: str) -> None:
        self.events.append(ExchangeEvent(stage, self._count))
        self._count += 1

    def reset(self) -> None:
        self.events = []
        self._count = 0

    def assert_order(self, expected: Iterable[str]) -> None:
        expected_tuple = tuple(expected)
        actual = self.stages
        if actual != expected_tuple:
            raise AssertionError(
                "Expected exchange order {!r}, got {!r}".format(expected_tuple, actual)
            )


ExchangeRecorder = LocalExchangeRecorder
LocalRecorder = LocalExchangeRecorder


class ExchangeSession:
    """A single refresh attempt's bound policy and recorder state."""

    def __init__(
        self,
        policy: Optional[IdentityExchangePolicy],
        context: ExchangeContext,
        recorder: Any = None,
    ):
        self.policy = policy or IdentityExchangePolicy.allow_all()
        self.context = context
        self.recorder = recorder
        self._credential_update_recorded = False

    @classmethod
    def from_credentials(
        cls, credentials: Any, recorder: Any = None
    ) -> "ExchangeSession":
        return cls(
            getattr(credentials, "_exchange_policy", None),
            ExchangeContext.from_credentials(credentials),
            recorder or getattr(credentials, "_exchange_recorder", None),
        )

    @classmethod
    def from_impersonated_credentials(cls, credentials: Any) -> "ExchangeSession":
        source = credentials._source_credentials
        context = ExchangeContext.from_credentials(source)
        context = replace(
            context,
            service_account=credentials._target_principal,
            impersonation_url=(
                credentials._iam_endpoint_override or context.impersonation_url
            ),
        )
        policy = getattr(credentials, "_exchange_policy", None) or getattr(
            source, "_exchange_policy", None
        )
        recorder = getattr(credentials, "_exchange_recorder", None) or getattr(
            source, "_exchange_recorder", None
        )
        return cls(policy, context, recorder)

    def _record(self, stage: str) -> None:
        if self.recorder is None:
            return
        if hasattr(self.recorder, "record"):
            self.recorder.record(stage)
        elif callable(self.recorder):
            self.recorder(stage)

    def before_evidence(self) -> ExchangeApproval:
        return self.policy.authorize_evidence(self.context)

    def evidence_completed(self) -> None:
        self._record(STAGE_EVIDENCE)

    def before_exchange(self) -> ExchangeApproval:
        return self.policy.authorize_exchange(self.context)

    def exchange_completed(self) -> None:
        self._record(STAGE_EXCHANGE)

    def before_delegation(self) -> ExchangeApproval:
        return self.policy.authorize_delegation(self.context)

    def delegation_completed(self) -> None:
        self._record(STAGE_DELEGATION)

    def credential_updated(self) -> None:
        if self._credential_update_recorded:
            return
        self._credential_update_recorded = True
        self._record(STAGE_CREDENTIAL_UPDATE)


IdentityExchangeSession = ExchangeSession
