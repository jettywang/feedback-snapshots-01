"""
Consumption boundary for foreign (OIDC) credentials.

Simple JWT's local ``JWTAuthentication`` and ``TokenBackend`` continue to own
locally issued tokens.  This module is deliberately separate: foreign tokens
are only accepted after an explicitly registered provider claims the ``iss``
value, and only for an approved audience/purpose.  A validated federated token
is an *identity* fact.  It is never an authorization decision; permissions
in ``rest_framework_simplejwt.permissions`` and application code still decide
what the mapped local user may do.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import jwt
from django.utils.translation import gettext_lazy as _
from jwt import InvalidTokenError

from .backends import ALLOWED_ALGORITHMS, TokenBackend
from .exceptions import (
    FederationConfigurationError,
    FederationTokenError,
    TokenBackendError,
    TokenBackendExpiredToken,
)
from .settings import api_settings


def _as_audience_map(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        result = {}
        for audience, purpose in value.items():
            if not isinstance(audience, str) or not audience:
                raise FederationConfigurationError(
                    _("Audience values must be non-empty strings")
                )
            if purpose is None:
                purpose = audience
            if not isinstance(purpose, str) or not purpose:
                raise FederationConfigurationError(
                    _("Audience purposes must be non-empty strings")
                )
            result[audience] = purpose
        return result
    if isinstance(value, str):
        return {value: value}
    if isinstance(value, Iterable):
        result = {}
        for audience in value:
            if not isinstance(audience, str) or not audience:
                raise FederationConfigurationError(
                    _("Audience values must be non-empty strings")
                )
            result[audience] = audience
        return result
    raise FederationConfigurationError(
        _("Audiences must be a mapping, a string, or an iterable of strings")
    )


def _as_application_map(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        result = {}
        for external, local in value.items():
            if not isinstance(external, str) or not external:
                raise FederationConfigurationError(
                    _("External application names must be non-empty strings")
                )
            if not isinstance(local, str) or not local:
                raise FederationConfigurationError(
                    _("Local application names must be non-empty strings")
                )
            result[external] = local
        return result
    if isinstance(value, str):
        return {value: value}
    if isinstance(value, Iterable):
        result = {}
        for application in value:
            if not isinstance(application, str) or not application:
                raise FederationConfigurationError(
                    _("Application names must be non-empty strings")
                )
            result[application] = application
        return result
    raise FederationConfigurationError(
        _("Applications must be a mapping, a string, or an iterable of strings")
    )


@dataclass(frozen=True)
class OIDCProvider:
    """
    One approved OIDC provider.

    ``issuer`` is matched exactly (OIDC issuers are opaque identifiers).  The
    provider owns its keys, algorithms, audiences/purposes and claim mappings;
    nothing is inherited from the local Simple JWT settings or from another
    provider.  In particular, provider A cannot validate provider B's token by
    presenting a different ``iss``.
    """

    name: str
    issuer: str
    audiences: Mapping[str, str]
    algorithm: str = "RS256"
    verifying_key: str = ""
    jwk_url: str | None = None
    leeway: float | int | timedelta | None = None
    subject_claim: str = "sub"
    identity_claim: str | None = None
    identity_template: str = "{provider}:{value}"
    identity_mapping: Mapping[str, str] | None = None
    user_lookup_field: str | None = None
    application_claim: str = "applications"
    applications: Mapping[str, str] = field(default_factory=dict)
    projected_claims: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise FederationConfigurationError(
                _("Provider name must be a non-empty string")
            )
        if not isinstance(self.issuer, str) or not self.issuer:
            raise FederationConfigurationError(
                _("Provider '{}' must declare a non-empty issuer").format(self.name)
            )
        if self.algorithm not in ALLOWED_ALGORITHMS:
            raise FederationConfigurationError(
                _("Provider '{}' uses an unsupported algorithm '{}'").format(
                    self.name, self.algorithm
                )
            )
        if not self.audiences:
            raise FederationConfigurationError(
                _("Provider '{}' must declare at least one audience").format(
                    self.name
                )
            )
        if not isinstance(self.subject_claim, str) or not self.subject_claim:
            raise FederationConfigurationError(
                _("Provider '{}' must declare a subject claim").format(self.name)
            )
        if self.identity_claim is None:
            object.__setattr__(self, "identity_claim", self.subject_claim)
        if "{value}" not in self.identity_template:
            raise FederationConfigurationError(
                _("Provider '{}' identity template must contain '{value}'").format(
                    self.name
                )
            )
        if not isinstance(self.application_claim, str) or not self.application_claim:
            raise FederationConfigurationError(
                _("Provider '{}' must declare an application claim").format(
                    self.name
                )
            )

        object.__setattr__(self, "audiences", dict(self.audiences))
        object.__setattr__(self, "applications", dict(self.applications))
        if self.identity_mapping is not None:
            object.__setattr__(self, "identity_mapping", dict(self.identity_mapping))
        object.__setattr__(self, "projected_claims", tuple(self.projected_claims))

    @classmethod
    def from_config(cls, name: str, config: Mapping[str, Any]) -> OIDCProvider:
        """Build a provider from a settings dictionary or OIDC metadata."""

        if isinstance(config, cls):
            if config.name != name:
                raise FederationConfigurationError(
                    _("Provider key '{}' does not match provider name '{}'").format(
                        name, config.name
                    )
                )
            return config
        if not isinstance(config, Mapping):
            raise FederationConfigurationError(
                _("Provider '{}' configuration must be a mapping").format(name)
            )

        metadata = config.get("metadata") or {}
        if not isinstance(metadata, Mapping):
            raise FederationConfigurationError(
                _("Provider '{}' metadata must be a mapping").format(name)
            )

        metadata_issuer = metadata.get("issuer")
        configured_issuer = config.get("issuer")
        if (
            metadata_issuer
            and configured_issuer
            and metadata_issuer != configured_issuer
        ):
            raise FederationConfigurationError(
                _(
                    "Provider '{}' issuer does not match its discovery metadata"
                ).format(name)
            )
        issuer = configured_issuer or metadata_issuer
        if not issuer:
            raise FederationConfigurationError(
                _("Provider '{}' must declare an issuer").format(name)
            )

        algorithm = config.get("algorithm")
        supported_algorithms = metadata.get("id_token_signing_alg_values_supported")
        if algorithm is None:
            if supported_algorithms:
                algorithm = list(supported_algorithms)[0]
            else:
                algorithm = "RS256"
        if supported_algorithms and algorithm not in supported_algorithms:
            raise FederationConfigurationError(
                _(
                    "Provider '{}' algorithm '{}' is not supported by its metadata"
                ).format(name, algorithm)
            )

        audiences = config.get("audiences")
        if audiences is None:
            audiences = config.get("audience")
        audience_map = _as_audience_map(audiences)
        if not audience_map:
            raise FederationConfigurationError(
                _("Provider '{}' must declare at least one audience").format(name)
            )

        identity = config.get("identity") or {}
        if not isinstance(identity, Mapping):
            raise FederationConfigurationError(
                _("Provider '{}' identity configuration must be a mapping").format(
                    name
                )
            )

        subject_claim = identity.get(
            "subject_claim", config.get("subject_claim", "sub")
        )
        identity_claim = identity.get("claim", config.get("identity_claim"))
        if identity_claim is None:
            identity_claim = subject_claim
        identity_template = identity.get(
            "template", config.get("identity_template", "{provider}:{value}")
        )
        identity_mapping = identity.get("mapping", config.get("identity_mapping"))
        if identity_mapping is not None and not isinstance(identity_mapping, Mapping):
            raise FederationConfigurationError(
                _("Provider '{}' identity mapping must be a mapping").format(name)
            )
        user_lookup_field = identity.get(
            "lookup_field", config.get("user_lookup_field")
        )

        applications = config.get("applications")
        if applications is None:
            applications = config.get("application_mapping")
        application_map = _as_application_map(applications)

        projected_claims = config.get("projected_claims", ())
        if isinstance(projected_claims, str):
            projected_claims = (projected_claims,)

        return cls(
            name=name,
            issuer=issuer,
            audiences=audience_map,
            algorithm=algorithm,
            verifying_key=config.get("verifying_key", ""),
            jwk_url=config.get("jwk_url") or metadata.get("jwks_uri"),
            leeway=config.get("leeway"),
            subject_claim=subject_claim,
            identity_claim=identity_claim,
            identity_template=identity_template,
            identity_mapping=identity_mapping,
            user_lookup_field=user_lookup_field,
            application_claim=config.get("application_claim", "applications"),
            applications=application_map,
            projected_claims=projected_claims,
        )

    def build_backend(self) -> TokenBackend:
        """
        A backend pinned to this provider only.

        A configured static ``verifying_key`` takes precedence over discovery
        JWKS.  This keeps local stand-in metadata usable without network access
        and prevents a remote key set from silently replacing a pinned key.
        """
        is_hmac = self.algorithm.startswith("HS")
        return TokenBackend(
            algorithm=self.algorithm,
            signing_key=self.verifying_key if is_hmac else None,
            verifying_key=self.verifying_key if not is_hmac else "",
            audience=tuple(self.audiences),
            issuer=self.issuer,
            jwk_url=None if self.verifying_key else self.jwk_url,
            leeway=self.leeway,
        )

    def resolve_purpose(self, payload: Mapping[str, Any]) -> str:
        raw_audience = payload.get("aud")
        if isinstance(raw_audience, str):
            audience_values = [raw_audience]
        elif isinstance(raw_audience, (list, tuple)) and all(
            isinstance(item, str) for item in raw_audience
        ):
            audience_values = list(raw_audience)
        else:
            raise FederationTokenError(
                _("Token has no recognizable audience"), "invalid_audience"
            )

        if not audience_values:
            raise FederationTokenError(
                _("Token has no recognizable audience"), "invalid_audience"
            )

        if any(audience not in self.audiences for audience in audience_values):
            raise FederationTokenError(
                _("Token audience is not approved for this provider"),
                "audience_not_allowed",
            )

        purposes = {self.audiences[audience] for audience in audience_values}
        if len(purposes) != 1:
            raise FederationTokenError(
                _("Token audience spans more than one purpose"),
                "ambiguous_purpose",
            )
        return purposes.pop()

    def resolve_applications(self, payload: Mapping[str, Any]) -> tuple[str, ...]:
        """
        Map foreign application identifiers into local application identifiers.

        Only explicitly mapped values survive.  Raw values from the token are
        never reused as local identifiers, so a new provider value cannot grant
        access to a local application by naming it directly.
        """
        raw = payload.get(self.application_claim)
        if raw is None:
            return ()
        if isinstance(raw, str):
            raw_values = [raw]
        elif isinstance(raw, (list, tuple)) and all(
            isinstance(item, str) for item in raw
        ):
            raw_values = list(raw)
        else:
            raise FederationTokenError(
                _("Token application claim has an unsupported shape"),
                "invalid_application_claim",
            )

        mapped: list[str] = []
        for external in raw_values:
            local = self.applications.get(external)
            if local is not None and local not in mapped:
                mapped.append(local)
        return tuple(mapped)

    def map_identity(self, payload: Mapping[str, Any]) -> str:
        """
        Map claims to the local user lookup value.

        There is no implicit use of ``sub`` as a local user id.  The configured
        template (provider-qualified by default) or an explicit mapping decides
        which local identity is meant.  A missing claim or unmapped value fails
        closed.
        """
        value = payload.get(self.identity_claim)  # type: ignore[arg-type]
        if not isinstance(value, str) or not value:
            raise FederationTokenError(
                _("Token has no usable identity claim"), "missing_identity_claim"
            )

        if self.identity_mapping is not None:
            mapped = self.identity_mapping.get(value)
            if mapped is None:
                raise FederationTokenError(
                    _("Token identity is not mapped to a local account"),
                    "identity_not_mapped",
                )
            return mapped

        return self.identity_template.format(provider=self.name, value=value)

    def project_claims(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """
        Return only claims explicitly allow-listed for downstream consumption.

        These claims remain descriptive data attached to ``request.auth``.
        They never become Django permissions or user attributes.
        """
        return {
            claim: payload[claim]
            for claim in self.projected_claims
            if claim in payload
        }


class OIDCProviderRegistry:
    """An explicit, duplicate-free registry keyed by opaque issuer."""

    def __init__(self, providers: Iterable[OIDCProvider] = ()) -> None:
        self._by_name: dict[str, OIDCProvider] = {}
        self._by_issuer: dict[str, OIDCProvider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: OIDCProvider) -> None:
        if provider.name in self._by_name:
            raise FederationConfigurationError(
                _("Provider '{}' is registered more than once").format(provider.name)
            )
        existing = self._by_issuer.get(provider.issuer)
        if existing is not None:
            raise FederationConfigurationError(
                _(
                    "Issuer '{}' is already owned by provider '{}'"
                ).format(provider.issuer, existing.name)
            )
        self._by_name[provider.name] = provider
        self._by_issuer[provider.issuer] = provider

    @classmethod
    def from_settings(cls, config: Mapping[str, Any] | None) -> OIDCProviderRegistry:
        config = config or {}
        if not isinstance(config, Mapping):
            raise FederationConfigurationError(
                _("FEDERATION_PROVIDERS must be a mapping of provider names")
            )
        registry = cls(
            OIDCProvider.from_config(name, provider_config)
            for name, provider_config in config.items()
        )
        registry._reject_local_boundary_reuse()
        return registry

    def _reject_local_boundary_reuse(self) -> None:
        """
        A foreign provider must not share the local issuer or, for HMAC, the
        local signing key.  Otherwise a locally issued token could be routed
        through the federation path and inherit federated claim semantics.
        """
        local_issuer = getattr(api_settings, "ISSUER", None)
        local_algorithm = getattr(api_settings, "ALGORITHM", None)
        local_signing_key = getattr(api_settings, "SIGNING_KEY", None)
        local_verifying_key = getattr(api_settings, "VERIFYING_KEY", None)

        for provider in self._by_name.values():
            if local_issuer and provider.issuer == local_issuer:
                raise FederationConfigurationError(
                    _(
                        "Provider '{}' reuses the local Simple JWT issuer"
                    ).format(provider.name)
                )
            if local_algorithm != provider.algorithm or not provider.verifying_key:
                continue
            if local_algorithm.startswith("HS"):
                if provider.verifying_key == local_signing_key:
                    raise FederationConfigurationError(
                        _(
                            "Provider '{}' reuses the local Simple JWT signing key"
                        ).format(provider.name)
                    )
            elif local_verifying_key and provider.verifying_key == local_verifying_key:
                raise FederationConfigurationError(
                    _(
                        "Provider '{}' reuses the local Simple JWT verifying key"
                    ).format(provider.name)
                )

    def by_name(self, name: str) -> OIDCProvider:
        try:
            return self._by_name[name]
        except KeyError as exc:
            raise FederationTokenError(
                _("Token was issued by an unregistered provider"), "unknown_issuer"
            ) from exc

    def by_issuer(self, issuer: str) -> OIDCProvider:
        try:
            return self._by_issuer[issuer]
        except KeyError as exc:
            raise FederationTokenError(
                _("Token was issued by an unregistered provider"), "unknown_issuer"
            ) from exc

    def __iter__(self):
        return iter(self._by_name.values())

    def __len__(self) -> int:
        return len(self._by_name)


def default_provider_registry() -> OIDCProviderRegistry:
    """Build the registry from the current ``SIMPLE_JWT`` settings."""

    return OIDCProviderRegistry.from_settings(
        getattr(api_settings, "FEDERATION_PROVIDERS", None)
    )


def _unverified_payload(token: str | bytes) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_iss": False,
                "verify_jti": False,
                "verify_nbf": False,
                "verify_sub": False,
            },
        )
    except (InvalidTokenError, TypeError, ValueError) as exc:
        raise FederationTokenError(_("Token is invalid"), "invalid_token") from exc

    if not isinstance(payload, dict):
        raise FederationTokenError(_("Token is invalid"), "invalid_token")
    return payload


class FederatedToken:
    """
    A foreign token accepted under one registered provider's boundary.

    The payload is verified with a provider-specific key, issuer and audience.
    It exposes ``provider``, ``purpose``, ``applications`` and allow-listed
    ``claims``.  It is intentionally not a Simple JWT ``Token`` subclass: it
    cannot be used with the local signing path or the local ``TokenBackend``.
    """

    def __init__(
        self,
        token: str | bytes,
        *,
        registry: OIDCProviderRegistry | None = None,
    ) -> None:
        registry = registry or default_provider_registry()
        unverified = _unverified_payload(token)

        issuer = unverified.get("iss")
        if not isinstance(issuer, str) or not issuer:
            raise FederationTokenError(
                _("Token was issued by an unregistered provider"), "unknown_issuer"
            )

        provider = registry.by_issuer(issuer)
        try:
            payload = provider.build_backend().decode(token)
        except TokenBackendExpiredToken as exc:
            raise FederationTokenError(
                _("Token is expired"), "token_expired"
            ) from exc
        except TokenBackendError as exc:
            raise FederationTokenError(
                _("Token is invalid"), "invalid_token"
            ) from exc

        self.token = token
        self.payload = payload
        self.provider = provider
        self.purpose = provider.resolve_purpose(payload)
        self.applications = provider.resolve_applications(payload)
        self.claims = provider.project_claims(payload)

        subject = payload.get(provider.subject_claim)
        if not isinstance(subject, str) or not subject:
            raise FederationTokenError(
                _("Token has no usable subject"), "missing_subject"
            )
        self.subject = subject

        if "exp" not in payload:
            raise FederationTokenError(
                _("Token has no 'exp' claim"), "missing_exp"
            )

    def __getitem__(self, key: str) -> Any:
        return self.payload[key]

    def __contains__(self, key: str) -> bool:
        return key in self.payload

    def get(self, key: str, default: Any = None) -> Any:
        return self.payload.get(key, default)

    def __repr__(self) -> str:
        return (
            f"FederatedToken(provider={self.provider.name!r}, "
            f"subject={self.subject!r}, purpose={self.purpose!r})"
        )


class FederatedPrincipal:
    """
    The authenticated identity produced by a federated token.

    Permissions are *not* derived from token claims.  If ``user_lookup_field``
    resolved a local user, Django's normal permission machinery is used (which
    is a downstream check, not a signature check).  Otherwise this principal is
    authenticated but has no permissions at all.
    """

    is_authenticated = True
    is_anonymous = False
    is_active = True

    def __init__(
        self,
        identity: str,
        token: FederatedToken,
        user: Any | None = None,
    ) -> None:
        self.id = identity
        self.pk = identity
        self.username = identity
        self.token = token
        self.provider = token.provider
        self.purpose = token.purpose
        self.applications = token.applications
        self.claims = token.claims
        self._user = user

    def __str__(self) -> str:
        return f"FederatedPrincipal {self.id}"

    def __repr__(self) -> str:
        return (
            f"FederatedPrincipal(provider={self.provider.name!r}, "
            f"identity={self.id!r})"
        )

    @property
    def is_staff(self) -> bool:
        return bool(getattr(self._user, "is_staff", False))

    @property
    def is_superuser(self) -> bool:
        return bool(getattr(self._user, "is_superuser", False))

    @property
    def groups(self):
        if self._user is not None:
            return self._user.groups
        return ()

    def get_group_permissions(self, obj: object | None = None) -> set:
        if self._user is not None:
            return self._user.get_group_permissions(obj)
        return set()

    def get_all_permissions(self, obj: object | None = None) -> set:
        if self._user is not None:
            return self._user.get_all_permissions(obj)
        return set()

    def has_perm(self, perm: str, obj: object | None = None) -> bool:
        if self._user is not None:
            return self._user.has_perm(perm, obj)
        return False

    def has_perms(self, perm_list, obj: object | None = None) -> bool:
        if self._user is not None:
            return self._user.has_perms(perm_list, obj)
        return False

    def has_module_perms(self, module: str) -> bool:
        if self._user is not None:
            return self._user.has_module_perms(module)
        return False

    def get_username(self) -> str:
        return self.username

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FederatedPrincipal):
            return NotImplemented
        return (self.provider.name, self.id) == (other.provider.name, other.id)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self.provider.name, self.id))
