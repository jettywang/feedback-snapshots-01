from functools import cached_property

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from auditlog import get_logentry_model
from auditlog.filters import CIDFilter, OnBehalfOfFilter, ResourceTypeFilter
from auditlog.mixins import LogEntryAdminMixin

LogEntry = get_logentry_model()


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin, LogEntryAdminMixin):
    date_hierarchy = "timestamp"
    list_select_related = ["content_type", "actor", "on_behalf_of"]
    list_display = [
        "created",
        "resource_url",
        "action",
        "msg_short",
        "user_url",
        "on_behalf_of_url",
        "cid_url",
    ]
    search_fields = [
        "timestamp",
        "object_repr",
        "changes",
        "actor__first_name",
        "actor__last_name",
        f"actor__{get_user_model().USERNAME_FIELD}",
        "actor_email",
        "on_behalf_of__first_name",
        "on_behalf_of__last_name",
        f"on_behalf_of__{get_user_model().USERNAME_FIELD}",
        "on_behalf_of_email",
    ]
    list_filter = ["action", ResourceTypeFilter, OnBehalfOfFilter, CIDFilter]
    readonly_fields = [
        "created",
        "resource_url",
        "action",
        "user_url",
        "on_behalf_of_url",
        "msg",
    ]
    fieldsets = [
        (
            None,
            {
                "fields": [
                    "created",
                    "user_url",
                    "on_behalf_of_url",
                    "resource_url",
                    "cid",
                ]
            },
        ),
        (_("Changes"), {"fields": ["action", "msg"]}),
    ]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @cached_property
    def _own_url_names(self):
        return [pattern.name for pattern in self.urls if pattern.name]

    def has_delete_permission(self, request, obj=None):
        if (
            request.resolver_match
            and request.resolver_match.url_name not in self._own_url_names
        ):
            # only allow cascade delete to satisfy delete_related flag
            return super().has_delete_permission(request, obj)
        return False

    def get_queryset(self, request):
        self.request = request
        return super().get_queryset(request=request)
