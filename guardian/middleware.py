"""Request middleware for explicit authorization principals."""

from django.http import HttpResponseForbidden

from guardian.exceptions import PrincipalSwitchDenied, VisitorNotConfigured
from guardian.principals import resolve_request_principal


class GuardianPrincipalMiddleware:
    """Resolve ``request.guardian_principal`` before the view runs.

    The middleware must be placed after Django's
    ``AuthenticationMiddleware`` because it reads ``request.user``.  It never
    rewrites ``request.user``: the authenticated user stays available for
    auditing and for code that deliberately wants the original identity.
    Views that authorize a request should use
    :func:`guardian.principals.get_request_principal` (or the
    ``request.guardian_principal`` attribute) instead.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            principal = resolve_request_principal(request)
        except (PrincipalSwitchDenied, VisitorNotConfigured) as exc:
            # Both are boundary failures: an untraceable transition or a
            # request marked as a visitor without a usable visitor account.
            # Fail closed rather than let the request fall back to a different
            # identity than the ingress layer asked for.
            return HttpResponseForbidden(str(exc))

        request.guardian_principal = principal
        request.guardian_user = principal.user
        return self.get_response(request)
