from django.urls import re_path

from rest_framework_simplejwt import federation_views
from rest_framework_simplejwt import views as jwt_views

from . import views

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
    re_path(r"^test-view/$", views.test_view, name="test_view"),
    re_path(
        r"^federation/verify/$",
        federation_views.federated_token_verify,
        name="federated_token_verify",
    ),
    re_path(
        r"^federation/identity/$",
        views.federation_identity_view,
        name="federation_identity",
    ),
    re_path(
        r"^federation/local-or-federated/$",
        views.local_or_federated_identity_view,
        name="local_or_federated_identity",
    ),
    re_path(
        r"^federation/company-portal/$",
        views.company_portal_view,
        name="company_portal",
    ),
    re_path(
        r"^federation/billing/$",
        views.billing_application_view,
        name="billing_application",
    ),
]
