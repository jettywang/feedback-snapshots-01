from django.db.models import Q
from rest_framework import (
    metadata,
    permissions,
    serializers as drf_serializers,
    viewsets,
)

from tests.employee.models import EmployeeRecord, Project
from tests.employee.permissions import ProjectBindingPermission
from tests.employee.serializers import EmployeeRecordSerializer, ProjectAssociationField


class ProjectBindingMetadata(metadata.SimpleMetadata):
    """
    Exposes the selectable project choices in OPTIONS responses. The default
    metadata skips related fields, so the role-conditional queryset would
    otherwise be invisible to clients; the choices themselves still come from
    the field's single bindable queryset.
    """

    def get_field_info(self, field):
        field_info = super().get_field_info(field)
        if isinstance(field, ProjectAssociationField):
            field_info['choices'] = [
                {'value': value, 'display_name': display_name}
                for value, display_name in field.choices.items()
            ]
        return field_info


class ProjectSerializer(drf_serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ('id', 'name', 'status')


class ProjectViewSet(viewsets.ReadOnlyModelViewSet):
    """Lists exactly the projects the current user is allowed to browse."""

    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Project.objects.visible_to(self.request.user)


class EmployeeRecordViewSet(viewsets.ModelViewSet):
    metadata_class = ProjectBindingMetadata
    permission_classes = [
        permissions.IsAuthenticated,
        ProjectBindingPermission,
    ]
    serializer_class = EmployeeRecordSerializer

    def get_queryset(self):
        # Existing visibility filtering is preserved: a record is only
        # reachable when it is unbound or its project is one the user can
        # browse. Objects shown here are still distinct from the objects the
        # user is allowed to write a binding to.
        visible_projects = Project.objects.visible_to(self.request.user)
        return EmployeeRecord.objects.filter(
            Q(project__isnull=True) | Q(project__in=visible_projects)
        ).distinct()

    def get_visible_project_queryset(self):
        return Project.objects.visible_to(self.request.user)

    def get_bindable_project_queryset(self):
        # The single role-conditional entry point reused by the selectable
        # choices, serializer validation and the actual write path.
        return Project.objects.bindable_for(self.request.user)
