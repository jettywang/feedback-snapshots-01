from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied


def get_bindable_project_queryset(view):
    """
    Role-conditional entry point shared by the selectable choices, the
    serializer validation and the actual write path. Delegating to the view
    keeps it compatible with the existing queryset filtering and permission
    classes instead of baking a separate rule into each layer.
    """
    entry = getattr(view, 'get_bindable_project_queryset', None)
    if entry is None:
        return view.get_queryset().none()
    return entry()


def requested_project_pk(request):
    """
    The project the request is trying to write, or ``None`` when the request
    does not touch the relation (an unrelated PATCH, or an explicit unbind).
    """
    if not hasattr(request, 'data'):
        return None
    data = request.data
    if not isinstance(data, dict) or 'project' not in data:
        return None
    value = data.get('project')
    if value in (None, ''):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


class ProjectBindingPermission(permissions.BasePermission):
    """
    Authorises writes that associate an employee record with a project.

    Browsing a project/record and binding it are decided separately:
      * ``has_permission`` / ``has_object_permission`` only gate writes.
      * A record that already points at a project the user can no longer bind
        stays readable and editable as long as the relation is not changed.
      * A *new* binding must target a project returned by the shared
        role-conditional entry point (approved + manager role).
    """

    message = 'You do not have permission to bind records to this project.'

    def _new_binding_allowed(self, request, view, current_project_id):
        target_pk = requested_project_pk(request)
        if target_pk is None:
            # Relation untouched (or explicitly cleared): nothing to authorise.
            return True
        if target_pk == current_project_id:
            # Pre-existing, unchanged association: keep it without re-checking
            # the binding role the user may have lost since it was set.
            return True
        if target_pk not in get_bindable_project_queryset(view).values_list(
            'pk', flat=True
        ):
            return False
        return True

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        if view.lookup_field not in getattr(view, 'kwargs', {}):
            # Create: there is no existing association, so every supplied
            # project is a new binding that must pass the role condition.
            target_pk = requested_project_pk(request)
            if target_pk is None:
                return True
            return target_pk in get_bindable_project_queryset(view).values_list(
                'pk', flat=True
            )
        return True

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        current_project_id = obj.project_id
        if not self._new_binding_allowed(request, view, current_project_id):
            raise PermissionDenied(self.message)
        return True
