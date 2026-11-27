"""
DRF authentication for foreign OIDC credentials.

``FederatedJWTAuthentication`` accepts only tokens whose ``iss`` belongs to a
registered provider.  Locally issued Simple JWT access tokens are not silently
downgraded or reinterpreted: a view that wants both forms composes the two
classes (see ``LocalOrFederatedJWTAuthentication``), and each keeps its own
validation and user-resolution rules.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import authentication
from rest_framework.request import Request

from .authentication import AUTH_HEADER_TYPES, JWTAuthentication
from .exceptions import AuthenticationFailed, FederationTokenError, InvalidToken
from .federation import (
    FederatedPrincipal,
    FederatedToken,
    OIDCProviderRegistry,
    default_provider_registry,
)
from .settings import api_settings


class FederatedJWTAuthentication(authentication.BaseAuthentication):
    """
    Authenticate a request using a foreign OIDC token.

    A successful authentication proves the provider's identity assertion for an
    approved audience/purpose.  It does not prove that the mapped local user may
    perform the operation: that is decided by DRF permissions and application
    code after authentication.  ``request.auth`` is a ``FederatedToken`` so
    downstream checks can inspect the approved purpose and mapped applications.
    """

    www_authenticate_realm = "api"
    media_type = "application/json"

    # Optional tuple of approved purposes for this endpoint.  When empty, any
    # purpose approved by the provider's audience map is accepted for identity
    # authentication; application access is still a separate check.
    purposes: tuple[str, ...] = ()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.user_model = get_user_model()
        self._registry: OIDCProviderRegistry | None = None

    @property
    def registry(self) -> OIDCProviderRegistry:
        # Settings can be reloaded (and tests override them), so providers are
        # resolved lazily instead of captured at import time.
        if self._registry is None:
            self._registry = default_provider_registry()
        return self._registry

    def authenticate(self, request: Request) -> tuple[Any, FederatedToken] | None:
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token

    def authenticate_header(self, request: Request) -> str:
        return '{} realm="{}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def get_header(self, request: Request) -> bytes:
        return JWTAuthentication.get_header(self, request)

    def get_raw_token(self, header: bytes) -> bytes | None:
        return JWTAuthentication.get_raw_token(self, header)

    def get_validated_token(self, raw_token: bytes) -> FederatedToken:
        try:
            token = FederatedToken(raw_token, registry=self.registry)
        except FederationTokenError as exc:
            raise AuthenticationFailed(
                str(exc), code=getattr(exc, "code", "federation_token_invalid")
            ) from exc

        if self.purposes and token.purpose not in self.purposes:
            raise AuthenticationFailed(
                _("Token purpose is not approved for this endpoint"),
                code="purpose_not_allowed",
            )
        return token

    def get_user(self, validated_token: FederatedToken) -> FederatedPrincipal:
        identity = validated_token.provider.map_identity(validated_token.payload)

        user = None
        lookup_field = validated_token.provider.user_lookup_field
        if lookup_field:
            try:
                user = self.user_model.objects.get(**{lookup_field: identity})
            except self.user_model.DoesNotExist as exc:
                raise AuthenticationFailed(
                    _("User not found"), code="user_not_found"
                ) from exc

            if api_settings.CHECK_USER_IS_ACTIVE and not user.is_active:
                raise AuthenticationFailed(_("User is inactive"), code="user_inactive")

        return FederatedPrincipal(identity, validated_token, user=user)


class LocalOrFederatedJWTAuthentication(authentication.BaseAuthentication):
    """
    Try local Simple JWT authentication first, then the federation boundary.

    Ordering is explicit and observable through ``request.auth``: a local
    ``Token`` stays a local token, a ``FederatedToken`` stays federated.  The
    federation layer never accepts a token that merely looks like a local one,
    and the local layer never accepts a foreign issuer.
    """

    # Optional endpoint-level purpose restriction, applied to the federated
    # branch only.  Local tokens have no provider purpose.
    purposes: tuple[str, ...] = ()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.local = JWTAuthentication()
        self.federated = FederatedJWTAuthentication()
        self.federated.purposes = self.purposes

    def authenticate(self, request: Request):
        header = self.local.get_header(request)
        if header is None:
            return None

        raw_token = self.local.get_raw_token(header)
        if raw_token is None:
            return None

        try:
            validated_token = self.local.get_validated_token(raw_token)
        except AuthenticationFailed as local_error:
            try:
                federated_token = self.federated.get_validated_token(raw_token)
            except AuthenticationFailed as federated_error:
                raise InvalidToken(
                    {
                        "detail": _("Given token not valid for any token type"),
                        "messages": [
                            {
                                "token_class": "local",
                                "message": str(local_error.detail),
                            },
                            {
                                "token_class": "federated",
                                "message": str(federated_error.detail),
                            },
                        ],
                    }
                ) from federated_error

            return self.federated.get_user(federated_token), federated_token

        return self.local.get_user(validated_token), validated_token

    def authenticate_header(self, request: Request) -> str:
        return self.local.authenticate_header(request)
