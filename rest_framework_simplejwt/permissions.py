from django.utils.translation import gettext_lazy as _
from rest_framework import permissions


class StepUpRequired(permissions.BasePermission):
    """
    Permission for sensitive endpoints that demand a recent step-up (second
    factor) verification. Ordinary authenticated access is not enough: the
    presented token must carry a valid, unexpired step-up claim.

    The decision delegates entirely to ``Token.has_valid_step_up`` so that
    token issuance, refresh and endpoint protection apply the exact same rule
    from a single source of truth. It fails closed: when step-up is disabled,
    or when the request has no token with a live proof, access is denied.

    Capability checking (rather than ``isinstance``) keeps this robust when the
    ``tokens`` module is reloaded, which recreates its class objects.
    """

    message = _("Step-up authentication is required to access this resource")
    code = "step_up_required"

    def has_permission(self, request, view) -> bool:
        token = getattr(request, "auth", None)
        verifier = getattr(token, "has_valid_step_up", None)
        if not callable(verifier):
            return False

        return verifier()

