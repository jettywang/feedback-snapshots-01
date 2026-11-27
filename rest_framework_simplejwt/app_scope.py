"""Optional application-scoped token verification.

Simple JWT tokens normally identify a user only by the configured user ID
claim.  When one API serves several applications with independent user tables,
the same integer ID can refer to different people in each application.  This
module lets a project attach an application scope to tokens and enforce it for
both database-backed (``JWTAuthentication``) and stateless
(``JWTStatelessUserAuthentication``) authentication.

The feature is opt-in through ``APP_SCOPE_RESOLVER``.  A resolver maps a scope
to an :class:`AppScopeBinding`, which names the user source that is authoritative
for that scope.  Tokens without a scope are legacy tokens; they are rejected
unless ``APP_SCOPE_LEGACY_POLICY`` explicitly says how they participate.
"""

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

from .exceptions import AuthenticationFailed
from .models import TokenUser
from .settings import api_settings

LEGACY_POLICY_REJECT = "reject"
LEGACY_POLICY_ALLOW_UNSCOPED = "allow_unscoped"

_ANY_SCOPE = True


class AppScopeBinding:
    """The authoritative user source for one approved application scope.

    ``users`` may be a manager or queryset, for example
    ``User.objects.using("app_b")``; ``user_model`` may be used instead when an
    application has its own user model.  When both are omitted the binding is
    invalid.  ``token_user_class`` can override ``TOKEN_USER_CLASS`` for
    stateless authentication in this scope.
    """

    def __init__(
        self,
        app_scope: str,
        *,
        users: Any = None,
        user_model: type[AbstractBaseUser] | None = None,
        token_user_class: type[TokenUser] | None = None,
        user_id_field: str | None = None,
    ) -> None:
        if not isinstance(app_scope, str):
            app_scope = str(app_scope)

        if not app_scope:
            raise ValueError("App scope must not be empty")

        if users is None and user_model is None:
            raise ValueError("AppScopeBinding requires 'users' or 'user_model'")

        if users is not None and user_model is not None:
            raise ValueError("Specify either 'users' or 'user_model', not both")

        if token_user_class is not None and not issubclass(
            token_user_class, TokenUser
        ):
            raise ValueError("token_user_class must be a TokenUser subclass")

        self.app_scope = app_scope
        self.users = users
        self.user_model = user_model
        self.token_user_class = token_user_class
        self._user_id_field = user_id_field

    @property
    def user_id_field(self) -> str:
        return self._user_id_field or api_settings.USER_ID_FIELD

    @property
    def user_source(self) -> Any:
        if self.users is not None:
            return self.users
        return self.user_model._default_manager

    def get_user(self, user_id: Any) -> AbstractBaseUser:
        return self.user_source.get(**{self.user_id_field: user_id})

    def __repr__(self) -> str:
        source = "users" if self.users is not None else self.user_model
        return f"AppScopeBinding({self.app_scope!r}, source={source!r})"


class AppScopeRegistry:
    """Resolver backed by a fixed mapping of approved application scopes."""

    def __init__(self, bindings: dict[str, AppScopeBinding]) -> None:
        self.bindings = {
            str(app_scope): binding for app_scope, binding in bindings.items()
        }

    def __call__(self, app_scope: str) -> AppScopeBinding | None:
        return self.bindings.get(str(app_scope))


@dataclass(frozen=True)
class ResolvedAppScope:
    """An approved scope resolved from a token and its route requirement."""

    app_scope: str
    binding: AppScopeBinding
    legacy: bool = False


def app_scope_enabled() -> bool:
    return api_settings.APP_SCOPE_RESOLVER is not None


def get_user_lookup(
    validated_token: Any,
    *,
    request: Any = None,
    required_app_scope: Any = None,
) -> tuple[Any, str]:
    """Return the user source and ID field authorized for a token.

    With no scope resolution this is the default user model and
    ``USER_ID_FIELD``.  A resolved binding always wins, so callers such as the
    refresh serializers cannot fall back to a same-numbered user in another
    application.
    """

    if required_app_scope is None:
        required_app_scope = get_required_app_scope(request)

    # Route requirements only exist on authenticated requests.  Token refresh
    # and other token-handling endpoints have no view requirement, but a scoped
    # token is still resolved to its own binding so it cannot cross apps.
    scope = resolve_token_app_scope(
        validated_token,
        required_app_scope=required_app_scope,
        request=request,
    )

    if scope is None:
        return get_user_model()._default_manager, api_settings.USER_ID_FIELD

    return scope.binding.user_source, scope.binding.user_id_field


def normalize_app_scope(value: Any) -> str:
    return str(value)


def get_token_app_scope(validated_token: Any) -> Any | None:
    claim = api_settings.APP_SCOPE_CLAIM
    if claim is None:
        return None
    return validated_token.get(claim)


def _normalize_required(required_app_scope: Any) -> tuple[str, ...] | bool | None:
    if required_app_scope is None or required_app_scope is False:
        return None

    if required_app_scope is True:
        return _ANY_SCOPE

    if isinstance(required_app_scope, str):
        values: Iterable[Any] = (required_app_scope,)
    elif isinstance(required_app_scope, Iterable):
        values = required_app_scope
    else:
        values = (required_app_scope,)

    normalized = tuple(normalize_app_scope(value) for value in values)
    return normalized or None


def _scope_permitted(
    required_app_scope: tuple[str, ...] | bool | None, app_scope: str
) -> bool:
    if required_app_scope is None or required_app_scope is _ANY_SCOPE:
        return True
    return app_scope in required_app_scope


def get_required_app_scope(request: Any = None) -> tuple[str, ...] | bool | None:
    """Return the scope requirement for a request.

    A DRF view can set ``required_app_scope`` to a scope string, an iterable of
    allowed scopes, or ``True`` to require any approved scope.  The global
    ``APP_SCOPE_REQUIRED`` setting can require an approved scope for every
    authenticated route.
    """

    view = None
    if request is not None:
        parser_context = getattr(request, "parser_context", None) or {}
        view = parser_context.get("view")

    required = None
    if view is not None:
        required = getattr(view, "required_app_scope", None)

    if api_settings.APP_SCOPE_REQUIRED and required is None:
        return _ANY_SCOPE

    return _normalize_required(required)


def _load_resolver() -> Callable[[str], Any] | None:
    resolver = api_settings.APP_SCOPE_RESOLVER
    if resolver is None:
        return None

    if isinstance(resolver, dict):
        resolver = AppScopeRegistry(resolver)
    elif isinstance(resolver, str):
        resolver = import_string(resolver)

    if not callable(resolver):
        raise ImproperlyConfigured(
            "SIMPLE_JWT['APP_SCOPE_RESOLVER'] must be a callable, a mapping, "
            "or a dotted path to one"
        )

    return resolver


def _resolve_binding(app_scope: str, resolver: Callable[[str], Any]) -> AppScopeBinding:
    binding = resolver(app_scope)

    if binding is None:
        raise AuthenticationFailed(
            _("Token is not scoped to an approved application"),
            code="app_scope_unknown",
        )

    if not isinstance(binding, AppScopeBinding):
        raise AuthenticationFailed(
            _("Application scope resolver returned an invalid binding"),
            code="app_scope_mapping_invalid",
        )

    if binding.app_scope != app_scope:
        # Fail closed when a registry maps one scope to another scope.  Trusting
        # either value would make the token's ownership ambiguous.
        raise AuthenticationFailed(
            _("Application scope mapping is inconsistent"),
            code="app_scope_mapping_inconsistent",
        )

    return binding


def _reject(required: tuple[str, ...] | bool | None) -> None:
    if required is not None:
        raise AuthenticationFailed(
            _("This route requires an approved application-scoped token"),
            code="app_scope_required",
        )

    raise AuthenticationFailed(
        _("Token is not scoped to an approved application"),
        code="app_scope_missing",
    )


def _legacy_unscoped(
    required: tuple[str, ...] | bool | None,
) -> ResolvedAppScope | None:
    if required is not None:
        _reject(required)
    return None


def _import_policy(policy: str) -> Callable[[Any, Any], Any]:
    try:
        return import_string(policy)
    except ImportError as e:
        raise ImproperlyConfigured(
            "SIMPLE_JWT['APP_SCOPE_LEGACY_POLICY'] must be 'reject', "
            "'allow_unscoped', or a callable / dotted path"
        ) from e


def _resolve_legacy(
    validated_token: Any,
    required: tuple[str, ...] | bool | None,
    request: Any,
) -> ResolvedAppScope | None:
    policy = api_settings.APP_SCOPE_LEGACY_POLICY

    if policy == LEGACY_POLICY_REJECT:
        _reject(required)

    if policy == LEGACY_POLICY_ALLOW_UNSCOPED:
        return _legacy_unscoped(required)

    if isinstance(policy, str):
        policy = _import_policy(policy)

    if not callable(policy):
        raise ImproperlyConfigured(
            "SIMPLE_JWT['APP_SCOPE_LEGACY_POLICY'] must be 'reject', "
            "'allow_unscoped', or a callable / dotted path"
        )

    mapping = policy(validated_token, request)

    if mapping is True:
        return _legacy_unscoped(required)

    if isinstance(mapping, str):
        app_scope = normalize_app_scope(mapping)
        resolver = _load_resolver()
        if resolver is None:
            raise AuthenticationFailed(
                _("Application scope verification is not configured"),
                code="app_scope_not_configured",
            )
        # A legacy migration policy may name a scope, but the scope still has
        # to resolve through the approved registry.
        binding = _resolve_binding(app_scope, resolver)
    else:
        _reject(required)

    if not _scope_permitted(required, app_scope):
        raise AuthenticationFailed(
            _("Token is scoped to a different application"),
            code="app_scope_mismatch",
        )

    return ResolvedAppScope(app_scope, binding, legacy=True)


def resolve_token_app_scope(
    validated_token: Any,
    *,
    required_app_scope: Any = None,
    request: Any = None,
) -> ResolvedAppScope | None:
    """Resolve and authorize a token's application scope.

    Returns ``None`` when the feature is disabled, or when an explicitly
    allowed unscoped legacy token is used on a route with no scope requirement.
    Raises ``AuthenticationFailed`` when the token or route cannot be tied to an
    approved application.
    """

    required = _normalize_required(required_app_scope)
    resolver = _load_resolver()
    app_scope = get_token_app_scope(validated_token)

    if resolver is None:
        # A token that carries a scope must never fall back to an unqualified
        # default-model lookup just because this service forgot to configure a
        # resolver.  Fail closed instead of guessing its owner.
        if required is not None or app_scope is not None:
            raise AuthenticationFailed(
                _("Application scope verification is not configured"),
                code="app_scope_not_configured",
            )
        return None

    if app_scope is None:
        return _resolve_legacy(validated_token, required, request)

    app_scope = normalize_app_scope(app_scope)
    binding = _resolve_binding(app_scope, resolver)

    if not _scope_permitted(required, app_scope):
        raise AuthenticationFailed(
            _("Token is scoped to a different application"),
            code="app_scope_mismatch",
        )

    return ResolvedAppScope(app_scope, binding)
