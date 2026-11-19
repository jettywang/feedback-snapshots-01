from django.contrib.admin import SimpleListFilter
from django.utils.translation import gettext_lazy as _


class ResourceTypeFilter(SimpleListFilter):
    title = _("Resource Type")
    parameter_name = "resource_type"

    def lookups(self, request, model_admin):
        qs = model_admin.get_queryset(request)
        types = qs.values_list("content_type_id", "content_type__model")
        return list(types.order_by("content_type__model").distinct())

    def queryset(self, request, queryset):
        if self.value() is None:
            return queryset
        return queryset.filter(content_type_id=self.value())


class CIDFilter(SimpleListFilter):
    title = _("Correlation ID")
    parameter_name = "cid"

    def lookups(self, request, model_admin):
        return []

    def has_output(self):
        return True

    def queryset(self, request, queryset):
        if self.value() is None:
            return queryset
        return queryset.filter(cid=self.value())


class OnBehalfOfFilter(SimpleListFilter):
    title = _("On behalf of")
    parameter_name = "on_behalf_of"

    def lookups(self, request, model_admin):
        return (
            ("yes", _("Performed on behalf of another user")),
            ("no", _("Performed directly")),
        )

    def queryset(self, request, queryset):
        if self.value() == "yes":
            return queryset.exclude(on_behalf_of__isnull=True)
        if self.value() == "no":
            return queryset.filter(on_behalf_of__isnull=True)
        return queryset
