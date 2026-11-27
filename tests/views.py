from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt import authentication, federation
from rest_framework_simplejwt import federation_authentication
from rest_framework_simplejwt.permissions import HasApplication
from rest_framework_simplejwt.settings import api_settings


class TestView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (authentication.JWTAuthentication,)

    def get(self, request):
        return Response({"foo": "bar"})


test_view = TestView.as_view()


class FederationIdentityView(APIView):
    authentication_classes = (
        federation_authentication.FederatedJWTAuthentication,
    )
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        token = request.auth
        if isinstance(token, federation.FederatedToken):
            return Response(
                {
                    "token_kind": "federated",
                    "provider": token.provider.name,
                    "purpose": token.purpose,
                    "applications": list(token.applications),
                    "identity": str(request.user.id),
                }
            )
        return Response(
            {
                "token_kind": "local",
                "token_type": token.get(api_settings.TOKEN_TYPE_CLAIM),
                "identity": str(request.user.id),
            }
        )


federation_identity_view = FederationIdentityView.as_view()


class LocalOrFederatedIdentityView(APIView):
    authentication_classes = (
        federation_authentication.LocalOrFederatedJWTAuthentication,
    )
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        token = request.auth
        if isinstance(token, federation.FederatedToken):
            return Response(
                {
                    "token_kind": "federated",
                    "provider": token.provider.name,
                    "purpose": token.purpose,
                    "applications": list(token.applications),
                    "identity": str(request.user.id),
                }
            )
        return Response(
            {
                "token_kind": "local",
                "token_type": token.get(api_settings.TOKEN_TYPE_CLAIM),
                "identity": str(request.user.id),
            }
        )


local_or_federated_identity_view = LocalOrFederatedIdentityView.as_view()


class CompanyPurposeAuthentication(
    federation_authentication.LocalOrFederatedJWTAuthentication
):
    purposes = ("company-portal",)


class CompanyPortalView(APIView):
    authentication_classes = (CompanyPurposeAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        return Response({"purpose": request.auth.purpose})


company_portal_view = CompanyPortalView.as_view()


class BillingApplicationView(APIView):
    """A downstream endpoint that requires one local application."""

    authentication_classes = (
        federation_authentication.LocalOrFederatedJWTAuthentication,
    )
    permission_classes = (permissions.IsAuthenticated, HasApplication)
    application = "billing"

    def get(self, request):
        return Response({"billing": True})


billing_application_view = BillingApplicationView.as_view()
