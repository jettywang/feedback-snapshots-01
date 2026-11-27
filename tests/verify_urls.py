from django.urls import re_path

from rest_framework_simplejwt import views as jwt_views

from . import views
from .verify_support import (
    AdminOnlyEchoView,
    ServiceObtainPairView,
    StatelessAdminEchoView,
    ServiceRefreshView,
    StatelessSubjectEchoView,
    SubjectEchoView,
)

urlpatterns = [
    re_path(r"^token/pair/$", jwt_views.token_obtain_pair, name="token_obtain_pair"),
    re_path(r"^token/refresh/$", jwt_views.token_refresh, name="token_refresh"),
    re_path(
        r"^token/sliding/$", jwt_views.token_obtain_sliding, name="token_obtain_sliding"
    ),
    re_path(
        r"^token/sliding/refresh/$",
        jwt_views.token_refresh_sliding,
        name="token_refresh_sliding",
    ),
    re_path(r"^token/verify/$", jwt_views.token_verify, name="token_verify"),
    re_path(r"^token/blacklist/$", jwt_views.token_blacklist, name="token_blacklist"),
    re_path(r"^token/custom/pair/$", ServiceObtainPairView.as_view(), name="token_custom_pair"),
    re_path(
        r"^token/custom/refresh/$",
        ServiceRefreshView.as_view(),
        name="token_custom_refresh",
    ),
    re_path(r"^protected/$", SubjectEchoView.as_view(), name="protected"),
    re_path(r"^admin-only/$", AdminOnlyEchoView.as_view(), name="admin_only"),
    re_path(
        r"^admin-only-stateless/$",
        StatelessAdminEchoView.as_view(),
        name="admin_only_stateless",
    ),
    re_path(
        r"^protected-stateless/$",
        StatelessSubjectEchoView.as_view(),
        name="protected_stateless",
    ),
    re_path(r"^test-view/$", views.test_view, name="test_view"),
]
