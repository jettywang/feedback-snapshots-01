"""
Tracing permissions for the permission-audit mini app.

Every check appends one record to ``PERMISSION_CALL_LOG`` so tests can
assert *which* permission class was consulted, at which layer (request vs.
object), instead of only observing the resulting status code.
"""
from rest_framework.permissions import SAFE_METHODS, BasePermission

PERMISSION_CALL_LOG = []


def reset_permission_log():
    PERMISSION_CALL_LOG.clear()


def _record(kind, permission, request, view, obj=None):
    PERMISSION_CALL_LOG.append({
        'kind': kind,
        'permission': permission.__class__.__name__,
        'method': request.method,
        'action': getattr(view, 'action', None),
        'view': view.__class__.__name__,
        'obj_pk': getattr(obj, 'pk', None),
    })


class TracingAllowAny(BasePermission):
    """Class-default policy. Allows everything but records every call."""

    def has_permission(self, request, view):
        _record('has_permission', self, request, view)
        return True

    def has_object_permission(self, request, view, obj):
        _record('has_object_permission', self, request, view, obj)
        return True


class TracingIsStaff(BasePermission):
    """Action-level policy intended to guard sensitive detail operations."""

    def has_permission(self, request, view):
        result = bool(request.user and request.user.is_authenticated
                      and request.user.is_staff)
        _record('has_permission', self, request, view)
        return result

    def has_object_permission(self, request, view, obj):
        result = bool(request.user and request.user.is_authenticated
                      and request.user.is_staff)
        _record('has_object_permission', self, request, view, obj)
        return result


class TracingPublicReadAuthenticatedWrite(BasePermission):
    """
    Policy for the shared collection route: safe methods stay public,
    every mutating method requires authentication. Because the router merges
    the GET and POST handlers into one Route, one policy must distinguish
    them by HTTP method -- per-handler permission_classes cannot differ.
    """

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            result = True
        else:
            result = bool(request.user and request.user.is_authenticated)
        _record('has_permission', self, request, view)
        return result

    def has_object_permission(self, request, view, obj):
        result = request.method in SAFE_METHODS or bool(
            request.user and request.user.is_authenticated
        )
        _record('has_object_permission', self, request, view, obj)
        return result
