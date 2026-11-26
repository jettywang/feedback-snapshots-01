"""Request-scoped authorization contracts for multi-identity plugins.

An :class:`OperationAuthorization` describes the set of identities that an
operation was approved to use.  It is deliberately separate from the
configured authentication plugins: changing or re-authenticating a plugin
does not change what an individual request was approved to send.
"""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import dataclasses
from typing import Any

from keystoneauth1 import exceptions


USER_IDENTITY = 'user'
SERVICE_IDENTITY = 'service'

USER_ONLY = frozenset({USER_IDENTITY})
DUAL_IDENTITY = frozenset({USER_IDENTITY, SERVICE_IDENTITY})

_current_authorization: ContextVar['OperationAuthorization | None'] = (
    ContextVar('keystoneauth_operation_authorization', default=None)
)


def _plain_scope(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return {str(key): _plain_scope(item) for key, item in value.items()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            key: _plain_scope(item)
            for key, item in dataclasses.asdict(value).items()
            if item is not None
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_plain_scope(item) for item in value]
    for method_name in ('to_dict', 'as_dict'):
        method = getattr(value, method_name, None)
        if callable(method):
            return _plain_scope(method())
    return str(value)


def extract_scope(source: Any, session: Any = None) -> Any:
    """Extract a comparable scope from a plugin or auth reference."""
    if source is None:
        return None
    if isinstance(source, str | Mapping) or dataclasses.is_dataclass(source):
        return source

    for attr_name in (
        'approved_scope',
        'authorized_scope',
        'required_scope',
        'service_scope',
        'current_scope',
        'scope',
    ):
        value = getattr(source, attr_name, None)
        if value is not None and not callable(value):
            return value

    for method_name in ('get_operation_scope', 'get_scope'):
        method = getattr(source, method_name, None)
        if callable(method):
            try:
                value = method(session)
            except TypeError:
                value = method()
            if value is not None:
                return value

    auth_ref = getattr(source, 'auth_ref', None)
    if auth_ref is not None:
        return extract_scope(auth_ref, session)

    scope: dict[str, Any] = {}
    for attr_name in (
        'project_id',
        'project_name',
        'project_domain_id',
        'project_domain_name',
        'domain_id',
        'domain_name',
        'system_scope',
        'trust_id',
    ):
        value = getattr(source, attr_name, None)
        if value:
            scope[attr_name] = value

    if getattr(source, 'system_scoped', False):
        scope.setdefault('system_scope', 'all')
    if getattr(source, 'unscoped', False):
        scope['unscoped'] = True

    return scope or None


def scopes_match(expected: Any, actual: Any) -> bool:
    """Return whether ``actual`` satisfies the approved ``expected`` scope."""
    if expected is None:
        return True
    if actual is None:
        return False

    expected_value = _plain_scope(expected)
    actual_value = _plain_scope(extract_scope(actual))

    if isinstance(expected_value, Mapping):
        if not isinstance(actual_value, Mapping):
            return False
        for key, value in expected_value.items():
            if key not in actual_value or not scopes_match(
                value, actual_value[key]
            ):
                return False
        return True

    return bool(expected_value == actual_value)


@dataclass(frozen=True, init=False)
class OperationAuthorization:
    """The identities and optional service scope approved for one operation."""

    required_identities: frozenset[str]
    service_scope: Any = None
    operation_id: str | None = None
    name: str | None = None

    def __init__(
        self,
        required_identities: Any = USER_ONLY,
        service_scope: Any = None,
        *,
        identities: Any = None,
        user_required: bool | None = None,
        service_required: bool | None = None,
        require_service: bool | None = None,
        scope: Any = None,
        operation_id: str | None = None,
        name: str | None = None,
    ) -> None:
        approved = (
            identities if identities is not None else required_identities
        )
        if isinstance(approved, str):
            resolved = coerce_operation_authorization(approved)
            assert resolved is not None
            # String coercion returns a complete authorization. Preserve the
            # explicit scope/id arguments when callers also supplied them.
            identity_set = resolved.required_identities
        elif isinstance(approved, OperationAuthorization):
            identity_set = approved.required_identities
        else:
            identity_set = frozenset(approved)

        if user_required is not None or service_required is not None:
            identity_values = set(identity_set)
            if user_required:
                identity_values.add(USER_IDENTITY)
            elif user_required is False:
                identity_values.discard(USER_IDENTITY)
            if service_required is True or require_service is True:
                identity_values.add(SERVICE_IDENTITY)
            elif service_required is False or require_service is False:
                identity_values.discard(SERVICE_IDENTITY)
            identity_set = frozenset(identity_values)

        approved_scope = service_scope if service_scope is not None else scope
        object.__setattr__(self, 'required_identities', identity_set)
        object.__setattr__(self, 'service_scope', approved_scope)
        object.__setattr__(self, 'operation_id', operation_id)
        object.__setattr__(self, 'name', name)

    @classmethod
    def user_only(
        cls, *, operation_id: str | None = None, name: str | None = None
    ) -> 'OperationAuthorization':
        return cls(
            required_identities=USER_ONLY, operation_id=operation_id, name=name
        )

    @classmethod
    def single_identity(
        cls, *, operation_id: str | None = None, name: str | None = None
    ) -> 'OperationAuthorization':
        return cls.user_only(operation_id=operation_id, name=name)

    @classmethod
    def dual_identity(
        cls,
        service_scope: Any = None,
        *,
        scope: Any = None,
        operation_id: str | None = None,
        name: str | None = None,
    ) -> 'OperationAuthorization':
        approved_scope = service_scope if service_scope is not None else scope
        return cls(
            required_identities=DUAL_IDENTITY,
            service_scope=approved_scope,
            operation_id=operation_id,
            name=name,
        )

    @classmethod
    def require_service(
        cls,
        service_scope: Any = None,
        *,
        scope: Any = None,
        operation_id: str | None = None,
        name: str | None = None,
    ) -> 'OperationAuthorization':
        return cls.dual_identity(
            service_scope, scope=scope, operation_id=operation_id, name=name
        )

    @property
    def requires_user(self) -> bool:
        return USER_IDENTITY in self.required_identities

    @property
    def requires_service(self) -> bool:
        return SERVICE_IDENTITY in self.required_identities

    @property
    def required_headers(self) -> frozenset[str]:
        headers = set()
        if self.requires_user:
            headers.add('X-Auth-Token')
        if self.requires_service:
            headers.add('X-Service-Token')
        return frozenset(headers)

    @property
    def approved_service_scope(self) -> Any:
        return self.service_scope

    def require_scope_match(self, actual_scope: Any) -> None:
        if self.requires_service and not scopes_match(
            self.service_scope, actual_scope
        ):
            raise exceptions.ServiceScopeMismatch(
                expected=self.service_scope, actual=actual_scope
            )


def coerce_operation_authorization(
    authorization: 'OperationAuthorization | str | Mapping[str, Any] | None',
) -> OperationAuthorization | None:
    """Accept concise string/mapping forms as an operation authorization."""
    if authorization is None or isinstance(
        authorization, OperationAuthorization
    ):
        return authorization
    if isinstance(authorization, str):
        value = authorization.strip().lower().replace('-', '_')
        if value in ('user', 'user_only', 'single', 'single_identity'):
            return OperationAuthorization.user_only()
        if value in (
            'dual',
            'dual_identity',
            'service',
            'service_token',
            'both',
        ):
            return OperationAuthorization.dual_identity()
        raise exceptions.OperationAuthorizationError(
            f'Unknown operation authorization {authorization!r}.'
        )
    if isinstance(authorization, Mapping):
        return OperationAuthorization(**dict(authorization))
    raise TypeError(
        'operation_authorization must be an OperationAuthorization, '
        f'string or mapping, not {type(authorization)!r}'
    )


def current_operation_authorization() -> OperationAuthorization | None:
    """Return the authorization installed for the current execution context."""
    return _current_authorization.get()


@contextmanager
def operation_authorization_context(
    authorization: OperationAuthorization | str | Mapping[str, Any] | None,
) -> Iterator[OperationAuthorization | None]:
    """Install an operation authorization for one call and its retries."""
    resolved = coerce_operation_authorization(authorization)
    if resolved is None:
        yield None
        return

    token = _current_authorization.set(resolved)
    try:
        yield resolved
    finally:
        _current_authorization.reset(token)


def resolve_operation_authorization(
    explicit: Any = None, auth_plugin: Any = None
) -> OperationAuthorization | None:
    """Resolve explicit, request-bound and context authorization sources."""
    authorization = explicit
    if authorization is None:
        authorization = getattr(auth_plugin, 'operation_authorization', None)
    if authorization is None:
        authorization = current_operation_authorization()
    return coerce_operation_authorization(authorization)


def resolve_plugin_operation_authorization(
    explicit: Any = None, auth_plugin: Any = None
) -> OperationAuthorization | None:
    """Resolve an approval while a Session-installed request context wins."""
    authorization = explicit
    if authorization is None:
        authorization = current_operation_authorization()
    if authorization is None:
        authorization = getattr(auth_plugin, 'operation_authorization', None)
    return coerce_operation_authorization(authorization)


def pop_request_operation_authorization(
    kwargs: dict[str, Any], explicit: Any = None
) -> OperationAuthorization | None:
    """Remove optional authorization aliases from outgoing request kwargs."""
    resolved = coerce_operation_authorization(explicit)

    for key in (
        'operation_authorization',
        'operation_approval',
        'authorization',
        'authorization_contract',
        'operation_auth',
        'auth_requirement',
        'grant',
        'approval',
    ):
        value = kwargs.pop(key, None)
        if resolved is None and value is not None:
            resolved = coerce_operation_authorization(value)

    requires_service = any(
        kwargs.pop(key, False)
        for key in (
            'dual_identity',
            'require_dual_identity',
            'require_service',
            'service_required',
            'service_token_required',
        )
    )
    scope_keys = (
        'service_scope',
        'required_service_scope',
        'service_project',
        'scope',
    )
    if requires_service or any(key in kwargs for key in scope_keys):
        scope = None
        for key in scope_keys:
            if key in kwargs:
                scope = kwargs.pop(key)
                break
        if resolved is None:
            resolved = OperationAuthorization.dual_identity(scope)

    authorization_fields = (
        'required_identities',
        'identities',
        'user_required',
        'service_required',
        'operation_id',
        'name',
    )
    if resolved is None and any(key in kwargs for key in authorization_fields):
        values = {
            key: kwargs.pop(key)
            for key in authorization_fields
            if key in kwargs
        }
        resolved = OperationAuthorization(**values)

    return resolved


__all__ = (
    'USER_IDENTITY',
    'SERVICE_IDENTITY',
    'USER_ONLY',
    'DUAL_IDENTITY',
    'OperationAuthorization',
    'coerce_operation_authorization',
    'current_operation_authorization',
    'extract_scope',
    'operation_authorization_context',
    'pop_request_operation_authorization',
    'resolve_operation_authorization',
    'resolve_plugin_operation_authorization',
    'scopes_match',
)
