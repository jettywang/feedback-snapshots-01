"""
Verification endpoint for foreign credentials.

This is intentionally separate from ``TokenVerifyView``.  A 200 response from
this endpoint means: a registered provider issued the token for an approved
audience/purpose, and the provider's identity mapping resolved.  It does not
mean the identity is authorized for any application.  Authorization remains a
downstream permission check.
"""

from __future__ import annotations

from typing import Any

from rest_framework import serializers

from .exceptions import FederationTokenError
from .federation import FederatedToken, default_provider_registry
from .views import TokenViewBase


class FederatedTokenVerifySerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        try:
            token = FederatedToken(attrs["token"], registry=default_provider_registry())
        except FederationTokenError as exc:
            raise FederationTokenError(
                str(exc), getattr(exc, "code", "invalid_token")
            ) from exc

        return {
            "token_type": "federated",
            "provider": token.provider.name,
            "issuer": token.provider.issuer,
            "subject": token.subject,
            "purpose": token.purpose,
            "applications": list(token.applications),
            "claims": token.claims,
            # The endpoint only attests identity and provider-approved purpose.
            # It deliberately does not evaluate application authorization.
            "scope": "identity_only",
            "authorization": "not_evaluated",
        }


class FederatedTokenVerifyView(TokenViewBase):
    """
    Verify a foreign OIDC token under the registered provider boundary.

    A 200 response is identity evidence only.  Use a protected view with
    ``HasApplication`` to obtain an authorization decision.
    """

    _serializer_class = (
        "rest_framework_simplejwt.federation_views.FederatedTokenVerifySerializer"
    )


federated_token_verify = FederatedTokenVerifyView.as_view()
