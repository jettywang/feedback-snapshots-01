"""
Authorization checks that are separate from token validation.

A valid signature (local or federated) only establishes an identity.  These
permission classes are the downstream checks that decide whether the
authenticated identity may act on a particular application.
"""

from __future__ import annotations

from django.utils.translation import gettext_lazy as _
from rest_framework import permissions

from .federation import FederatedToken


class HasApplication(permissions.BasePermission):
    """
    Require the authenticated federated token to carry a mapped local
    application.

    ``application`` may be set on the view, or a mapping of ``view.action`` to
    application names may be supplied.  Local Simple JWT tokens never satisfy
    this permission: they have no federated application mapping, so a local
    token cannot bypass the federated application boundary by merely being
    valid.
    """

    message = _("Token is not approved for the requested application")

    def has_permission(self, request, view) -> bool:
        token = request.auth
        if not isinstance(token, FederatedToken):
            return False

        application = getattr(view, "application", None)
        if application is None:
            application_map = getattr(view, "application_map", {}) or {}
            action = getattr(view, "action", None)
            if action is not None:
                application = application_map.get(action)
        if not application:
            return False

        return application in token.applications


class IsFederatedForPurpose(permissions.BasePermission):
    """
    Require a federated token approved for one of the view's purposes.

    Purposes come from the provider's audience map, not from free-form token
    claims.  ``None`` means any approved purpose is acceptable for identity
    checks, but authorization decisions should still use ``HasApplication``.
    """

    message = _("Token is not approved for the requested purpose")

    def has_permission(self, request, view) -> bool:
        token = request.auth
        if not isinstance(token, FederatedToken):
            return False

        purposes = getattr(view, "purposes", None)
        if purposes is None:
            purpose = getattr(view, "purpose", None)
            if purpose is None:
                return True
            return token.purpose == purpose
        return token.purpose in purposes
