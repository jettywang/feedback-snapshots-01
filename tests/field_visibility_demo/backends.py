"""
Filter / ordering backends that honour the shared visibility policy.

Rule enforced here:

* Staff/admins may filter and order on every *approved* field.
* For a non-staff caller, any term that references a hidden field is dropped.
  Because a hidden filter never reaches the ORM, the presence or value of an
  internal field can never decide whether a row appears in the result set, and
  it cannot be used as a probe to infer hidden data.
"""

from django_filters.rest_framework import DjangoFilterBackend

from rest_framework import filters

from .visibility import FieldVisibility


class VisibilityOrderingFilter(filters.OrderingFilter):
    """Ordering whose valid field set is exactly the caller's visible fields."""

    def get_valid_fields(self, queryset, view, context=None):
        context = context or {}
        request = context.get('request') or getattr(view, 'request', None)
        visibility = FieldVisibility.from_request(request)
        allowed = set(visibility.visible_fields())
        valid = super().get_valid_fields(queryset, view, context)
        return [(name, label) for name, label in valid if name in allowed]


class VisibilitySearchFilter(filters.SearchFilter):
    """Search restricted to the text fields the caller is allowed to see."""

    def get_search_fields(self, view, request=None):
        configured = super().get_search_fields(view, request)
        visibility = FieldVisibility.from_request(request)
        allowed = set(visibility.visible_fields())
        return [
            term for term in configured
            if term.lstrip('^=@$').split('__')[0] in allowed
        ]


class VisibilityDjangoFilterBackend(DjangoFilterBackend):
    """
    Exact-match filtering on approved fields only.

    Query parameters that target a hidden field are ignored for non-staff
    callers instead of being applied, so internal values cannot influence the
    returned rows. Staff retain the full approved filter set.
    """

    def get_filterset_kwargs(self, request, queryset, view):
        kwargs = super().get_filterset_kwargs(request, queryset, view)
        visibility = FieldVisibility.from_request(request)
        data = kwargs.get('data')
        if data is not None:
            cleaned = data.copy()
            for param in list(cleaned):
                base = param.split('__')[0]
                is_approved = base in FieldVisibility.all_fields()
                if is_approved and not visibility.is_field_visible(base):
                    cleaned.pop(param)
            kwargs['data'] = cleaned
        return kwargs
