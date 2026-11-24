from rest_framework import serializers

from tests.employee.models import EmployeeRecord, Project
from tests.employee.permissions import get_bindable_project_queryset


class ProjectAssociationField(serializers.PrimaryKeyRelatedField):
    """
    PrimaryKeyRelatedField that distinguishes projects the user may *see* from
    projects the user may *bind*:

      * ``queryset`` stays the visible-projects queryset, so an already stored
        association renders correctly and an unchanged value round-trips.
      * ``bindable_queryset`` is the role-conditional set used for the
        selectable choices and for authorising any actual (re)binding.
    """

    def __init__(self, *args, **kwargs):
        self.bindable_queryset = kwargs.pop('bindable_queryset', Project.objects.none())
        super().__init__(*args, **kwargs)
        self._rendering_choices = False

    def get_queryset(self):
        if self._rendering_choices:
            return self.bindable_queryset
        return super().get_queryset()

    def get_choices(self, cutoff=None):
        self._rendering_choices = True
        try:
            return super().get_choices(cutoff=cutoff)
        finally:
            self._rendering_choices = False

    def to_internal_value(self, data):
        project = super().to_internal_value(data)
        if self.root.instance is not None and project.pk == getattr(
            self.root.instance, 'project_id', None
        ):
            # Existing, unchanged association: accept it even if the user's
            # binding role on that project has since been removed.
            return project
        if not self.bindable_queryset.filter(pk=project.pk).exists():
            self.fail('does_not_exist', pk=project.pk)
        return project


class EmployeeRecordSerializer(serializers.ModelSerializer):
    project = ProjectAssociationField(
        queryset=Project.objects.none(),
        bindable_queryset=Project.objects.none(),
        allow_null=True,
        required=False,
    )

    class Meta:
        model = EmployeeRecord
        fields = ('id', 'title', 'project')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        view = self.context.get('view')
        request = self.context.get('request')
        if view is None or request is None:
            return
        visible = view.get_visible_project_queryset()
        field = self.fields['project']
        field.queryset = visible
        field.bindable_queryset = get_bindable_project_queryset(view)
