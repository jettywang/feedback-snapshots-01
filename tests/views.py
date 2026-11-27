from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt import authentication
from rest_framework_simplejwt.permissions import StepUpRequired


class TestView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (authentication.JWTAuthentication,)

    def get(self, request):
        return Response({"foo": "bar"})


class SensitiveView(APIView):
    permission_classes = (permissions.IsAuthenticated, StepUpRequired)
    authentication_classes = (authentication.JWTAuthentication,)

    def get(self, request):
        return Response({"secret": "treasure"})


test_view = TestView.as_view()
sensitive_view = SensitiveView.as_view()
