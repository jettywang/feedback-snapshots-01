from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt import authentication
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


class ServiceAccessToken(AccessToken):
    """Custom access-like class used by the third deployment."""

    token_type = "service-access"


class ServiceRefreshToken(RefreshToken):
    """Custom refresh class; its access sibling is ServiceAccessToken."""

    token_type = "service-refresh"
    access_token_class = ServiceAccessToken


class ServiceObtainPairSerializer(TokenObtainPairSerializer):
    token_class = ServiceRefreshToken


class ServiceRefreshSerializer(TokenRefreshSerializer):
    token_class = ServiceRefreshToken


class ServiceObtainPairView(TokenObtainPairView):
    serializer_class = ServiceObtainPairSerializer


class ServiceRefreshView(TokenRefreshView):
    serializer_class = ServiceRefreshSerializer


class SubjectEchoView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (authentication.JWTAuthentication,)

    def get(self, request):
        return Response({"subject": str(request.user.pk)})


class StatelessSubjectEchoView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (authentication.JWTStatelessUserAuthentication,)

    def get(self, request):
        return Response({"subject": str(request.user.pk)})


class AdminOnlyEchoView(APIView):
    permission_classes = (permissions.IsAuthenticated, permissions.IsAdminUser)
    authentication_classes = (authentication.JWTAuthentication,)

    def get(self, request):
        return Response({"subject": str(request.user.pk)})


class StatelessAdminEchoView(APIView):
    permission_classes = (permissions.IsAuthenticated, permissions.IsAdminUser)
    authentication_classes = (authentication.JWTStatelessUserAuthentication,)

    def get(self, request):
        return Response({"subject": str(request.user.pk)})
