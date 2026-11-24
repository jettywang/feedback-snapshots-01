"""
Field-visibility policy.

This module is the *single source of truth* for which model fields a given
caller is allowed to see. Every other concern in the demo -- serialization,
ordering, filtering, search, pagination metadata and CSV export -- derives its
allowed field set from :class:`FieldVisibility`, so the public representation
and the operations that shape the result set can never drift apart.
"""

from rest_framework import serializers

from .models import CaseRecord


class FieldVisibility:
    """Resolves the set of model fields visible to a request's caller."""

    #: Fields every authenticated caller may see.
    PUBLIC_FIELDS = ('id', 'name', 'category', 'status')

    #: Fields reserved for staff/admins.
    STAFF_ONLY_FIELDS = ('internal_note', 'risk_score')

    def __init__(self, request):
        self.request = request
        self.is_staff = bool(
            request is not None
            and getattr(request, 'user', None) is not None
            and request.user.is_authenticated
            and request.user.is_staff
        )

    @classmethod
    def all_fields(cls):
        return cls.PUBLIC_FIELDS + cls.STAFF_ONLY_FIELDS

    def visible_fields(self):
        if self.is_staff:
            return self.all_fields()
        return self.PUBLIC_FIELDS

    def is_field_visible(self, field_name):
        return field_name in self.visible_fields()

    @classmethod
    def from_request(cls, request):
        return cls(request)


# A plain serializer exposing every field; visibility is applied by dropping
# the hidden fields for non-staff callers rather than maintaining two serializers.
class CaseRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = CaseRecord
        fields = FieldVisibility.all_fields()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        visibility = FieldVisibility.from_request(request)
        for hidden in set(self.fields) - set(visibility.visible_fields()):
            self.fields.pop(hidden)
