from django.utils.module_loading import import_string
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import BaseSerializer

from .authentication import AUTH_HEADER_TYPES
from .exceptions import InvalidToken, TokenError
from .settings import api_settings


class TokenViewBase(generics.GenericAPIView):
    permission_classes = ()
    authentication_classes = ()

    serializer_class: type[BaseSerializer] | None = None
    _serializer_class = ""

    www_authenticate_realm = "api"

    def get_serializer_class(self) -> type[BaseSerializer]:
        """
        If serializer_class is set, use it directly. Otherwise get the class from settings.
        """

        if self.serializer_class:
            return self.serializer_class
        try:
            return import_string(self._serializer_class)
        except ImportError as e:
            msg = f"Could not import serializer '{self._serializer_class}'"
            raise ImportError(msg) from e

    def get_authenticate_header(self, request: Request) -> str:
        return '{} realm="{}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0]) from e

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class TokenObtainPairView(TokenViewBase):
    """
    Takes a set of user credentials and returns an access and refresh JSON web
    token pair to prove the authentication of those credentials.
    """

    _serializer_class = api_settings.TOKEN_OBTAIN_SERIALIZER


token_obtain_pair = TokenObtainPairView.as_view()


class TokenRefreshView(TokenViewBase):
    """
    Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.
    """

    _serializer_class = api_settings.TOKEN_REFRESH_SERIALIZER


token_refresh = TokenRefreshView.as_view()


class TokenObtainSlidingView(TokenViewBase):
    """
    Takes a set of user credentials and returns a sliding JSON web token to
    prove the authentication of those credentials.
    """

    _serializer_class = api_settings.SLIDING_TOKEN_OBTAIN_SERIALIZER


token_obtain_sliding = TokenObtainSlidingView.as_view()


class TokenRefreshSlidingView(TokenViewBase):
    """
    Takes a sliding JSON web token and returns a new, refreshed version if the
    token's refresh period has not expired.
    """

    _serializer_class = api_settings.SLIDING_TOKEN_REFRESH_SERIALIZER


token_refresh_sliding = TokenRefreshSlidingView.as_view()


class TokenVerifyView(TokenViewBase):
    """
    Takes a token and indicates if it is valid.  This view provides no
    information about a token's fitness for a particular use.
    """

    _serializer_class = api_settings.TOKEN_VERIFY_SERIALIZER


token_verify = TokenVerifyView.as_view()


class TokenBlacklistView(TokenViewBase):
    """
    Takes a token and blacklists it. Must be used with the
    `rest_framework_simplejwt.token_blacklist` app installed.
    """

    _serializer_class = api_settings.TOKEN_BLACKLIST_SERIALIZER


token_blacklist = TokenBlacklistView.as_view()


class ApprovalObtainView(generics.GenericAPIView):
    """
    Issues a temporary approval for one operation after step-up confirmation.

    Requires an authenticated request; a refresh token cannot be used to
    obtain an approval, only the caller's existing access credential plus the
    business's own extra-confirmation flow.
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = None

    def get_serializer_class(self):
        from .serializers import ApprovalObtainSerializer

        return ApprovalObtainSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_201_CREATED)


class _ApprovalViewBase(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)


class ApprovalWithdrawView(_ApprovalViewBase):
    """
    Withdraws a pending approval before it is committed.
    """

    def get_serializer_class(self):
        from .serializers import ApprovalWithdrawSerializer

        return ApprovalWithdrawSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class ApprovalCommitView(_ApprovalViewBase):
    """
    Commits the business operation authorized by an approval.

    The real business action is supplied by subclasses overriding
    :meth:`run_operation`, or globally through the
    ``APPROVAL_OPERATION_RUNNER`` setting.  It is invoked only for the single
    executor that wins the claim.
    """

    def run_operation(self, approval) -> str:
        runner = api_settings.APPROVAL_OPERATION_RUNNER
        if runner is None:
            raise NotImplementedError(
                "Configure APPROVAL_OPERATION_RUNNER or override run_operation()"
            )
        return runner(approval)

    def get_serializer_class(self):
        from .serializers import ApprovalCommitSerializer

        return ApprovalCommitSerializer

    def get_serializer_context(self) -> dict:
        context = super().get_serializer_context()
        context["operation_runner"] = self.run_operation
        return context

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


approval_obtain = ApprovalObtainView.as_view()
approval_withdraw = ApprovalWithdrawView.as_view()
approval_commit = ApprovalCommitView.as_view()
