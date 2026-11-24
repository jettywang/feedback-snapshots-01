"""
Pagination whose metadata is derived from the same visible, filtered queryset.

``count`` always describes the queryset the caller actually receives after the
visibility-aware filters have run, and the envelope echoes the effective field
visibility so clients can verify that the representation and the page metadata
follow one consistent rule.
"""

from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from .visibility import FieldVisibility


class VisibilityPageNumberPagination(PageNumberPagination):
    page_size = 3
    page_size_query_param = 'page_size'
    max_page_size = 25

    def get_paginated_response(self, data):
        visibility = FieldVisibility.from_request(self.request)
        return Response({
            'count': self.page.paginator.count,
            'page_size': self.get_page_size(self.request),
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'visible_fields': list(visibility.visible_fields()),
            'results': data,
        })
