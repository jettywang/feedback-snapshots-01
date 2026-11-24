from django_filters import rest_framework as df_filters

from .models import CaseRecord
from .visibility import FieldVisibility


class CaseRecordFilterSet(df_filters.FilterSet):
    """The approved exact-match filter surface for the list endpoint."""

    class Meta:
        model = CaseRecord
        # ``dataset`` is intentionally absent: it is not an API field.
        fields = FieldVisibility.all_fields()
