from rest_framework import generics, permissions, renderers

from .backends import (
    VisibilityDjangoFilterBackend,
    VisibilityOrderingFilter,
    VisibilitySearchFilter,
)
from .filters import CaseRecordFilterSet
from .models import CaseRecord
from .pagination import VisibilityPageNumberPagination
from .renderers import CSVCasesRenderer
from .visibility import CaseRecordSerializer, FieldVisibility


class CaseRecordList(generics.ListAPIView):
    """List endpoint whose whole surface shares one visibility policy."""

    queryset = CaseRecord.objects.all()
    serializer_class = CaseRecordSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = VisibilityPageNumberPagination
    filter_backends = [
        VisibilityDjangoFilterBackend,
        VisibilityOrderingFilter,
        VisibilitySearchFilter,
    ]
    filterset_class = CaseRecordFilterSet
    # Search over every approved text field; the backend strips the hidden
    # ones for non-staff callers.
    search_fields = ['name', 'category', 'status', 'internal_note']
    # The full approved ordering surface; the backend intersects it with the
    # caller's visible fields.
    ordering_fields = list(FieldVisibility.all_fields())
    renderer_classes = [renderers.JSONRenderer, CSVCasesRenderer]


class CaseRecordDetail(generics.RetrieveAPIView):
    """Detail endpoint; the same serializer hides internal fields."""

    queryset = CaseRecord.objects.all()
    serializer_class = CaseRecordSerializer
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [renderers.JSONRenderer, CSVCasesRenderer]
