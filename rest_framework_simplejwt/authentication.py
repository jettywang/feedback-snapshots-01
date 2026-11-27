from contextvars import ContextVar
from typing import Optional, TypeVar

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _
from rest_framework import HTTP_HEADER_ENCODING, authentication
from rest_framework.request import Request

from .app_scope import (
    AppScopeBinding,
    ResolvedAppScope,
    get_required_app_scope,
    resolve_token_app_scope,
)
from .exceptions import AuthenticationFailed, InvalidToken, TokenError
from .models import TokenUser
from .settings import api_settings
from .tokens import Token
from .utils import get_md5_hash_password

AUTH_HEADER_TYPES = api_settings.AUTH_HEADER_TYPES

if not isinstance(api_settings.AUTH_HEADER_TYPES, (list, tuple)):
    AUTH_HEADER_TYPES = (AUTH_HEADER_TYPES,)

AUTH_HEADER_TYPE_BYTES: set[bytes] = {
    h.encode(HTTP_HEADER_ENCODING) for h in AUTH_HEADER_TYPES
}

# Pre-lowered for case-insensitive scheme matching per RFC 7235 §2.1.
_AUTH_HEADER_TYPE_BYTES_LOWER: set[bytes] = {h.lower() for h in AUTH_HEADER_TYPE_BYTES}

AuthUser = TypeVar("AuthUser", AbstractBaseUser, TokenUser)

_current_request: ContextVar[Request | None] = ContextVar(
    "rest_framework_simplejwt_current_request", default=None
)


class JWTAuthentication(authentication.BaseAuthentication):
    """
    An authentication plugin that authenticates requests through a JSON web
    token provided in a request header.
    """

    www_authenticate_realm = "api"
    media_type = "application/json"

    default_error_messages = {
        "password_changed": _("The user's password has been changed."),
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.user_model = get_user_model()

    def authenticate(self, request: Request) -> tuple[AuthUser, Token] | None:
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)

        # Keep calling ``get_user`` with only the token: subclasses in the wild
        # override that method with the original one-argument signature.  The
        # request is available to the base implementation through a ContextVar,
        # so concurrent requests sharing one backend instance cannot observe
        # each other's route requirements.
        token = _current_request.set(request)
        try:
            return self.get_user(validated_token), validated_token
        finally:
            _current_request.reset(token)

    def authenticate_header(self, request: Request) -> str:
        return '{} realm="{}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def get_header(self, request: Request) -> bytes:
        """
        Extracts the header containing the JSON web token from the given
        request.
        """
        header = request.META.get(api_settings.AUTH_HEADER_NAME)

        if isinstance(header, str):
            # Work around django test client oddness
            header = header.encode(HTTP_HEADER_ENCODING)

        return header

    def get_raw_token(self, header: bytes) -> bytes | None:
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = header.split()

        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None

        if parts[0].lower() not in _AUTH_HEADER_TYPE_BYTES_LOWER:
            # Assume the header does not contain a JSON web token
            return None

        if len(parts) != 2:
            raise AuthenticationFailed(
                _("Authorization header must contain two space-delimited values"),
                code="bad_authorization_header",
            )

        return parts[1]

    def get_validated_token(self, raw_token: bytes) -> Token:
        """
        Validates an encoded JSON web token and returns a validated token
        wrapper object.
        """
        messages = []
        for AuthToken in api_settings.AUTH_TOKEN_CLASSES:
            try:
                return AuthToken(raw_token)
            except TokenError as e:
                messages.append(
                    {
                        "token_class": AuthToken.__name__,
                        "token_type": AuthToken.token_type,
                        "message": e.args[0],
                    }
                )

        raise InvalidToken(
            {
                "detail": _("Given token not valid for any token type"),
                "messages": messages,
            }
        )

    def get_app_scope(
        self, validated_token: Token, request: Request | None = None
    ) -> ResolvedAppScope | None:
        """
        Resolves the token's application scope, if application scopes are
        configured.  The same resolution is used by stateful and stateless
        authentication so both backends authorize identically.
        """
        return resolve_token_app_scope(
            validated_token,
            required_app_scope=self.get_required_app_scope(request),
            request=request,
        )

    def get_required_app_scope(
        self, request: Request | None = None
    ) -> tuple[str, ...] | bool | None:
        """
        Returns the application scope requirement for a request.  Subclasses may
        override this to translate route metadata into a requirement.
        """
        return get_required_app_scope(request)

    def get_user_source(self, scope: ResolvedAppScope | None) -> tuple[object, str]:
        """
        Returns the user source and user ID field for the token's scope.

        Without a resolved scope this is the default user model.  With a scope
        the binding decides which user table is authoritative; IDs are never
        looked up with the default manager when a scope is present.
        """
        if scope is None:
            return self.user_model._default_manager, api_settings.USER_ID_FIELD

        binding: AppScopeBinding = scope.binding
        return binding.user_source, binding.user_id_field

    def get_user(
        self, validated_token: Token, request: Request | None = None, **kwargs
    ) -> AuthUser:
        """
        Attempts to find and return a user using the given validated token.
        """
        if request is None:
            request = _current_request.get()

        try:
            user_id = validated_token[api_settings.USER_ID_CLAIM]
        except KeyError as e:
            raise InvalidToken(
                _("Token contained no recognizable user identification")
            ) from e

        scope = self.get_app_scope(validated_token, request=request)
        user_source, user_id_field = self.get_user_source(scope)

        try:
            user = user_source.get(**{user_id_field: user_id})
        except ObjectDoesNotExist as e:
            raise AuthenticationFailed(
                _("User not found"), code="user_not_found"
            ) from e

        if api_settings.CHECK_USER_IS_ACTIVE and not getattr(
            user, "is_active", True
        ):
            raise AuthenticationFailed(_("User is inactive"), code="user_inactive")

        if api_settings.CHECK_REVOKE_TOKEN:
            if validated_token.get(
                api_settings.REVOKE_TOKEN_CLAIM
            ) != get_md5_hash_password(getattr(user, "password", "")):
                raise AuthenticationFailed(
                    self.default_error_messages["password_changed"],
                    code="password_changed",
                )

        return user


class JWTStatelessUserAuthentication(JWTAuthentication):
    """
    An authentication plugin that authenticates requests through a JSON web
    token provided in a request header without performing a database lookup to obtain a user instance.
    """

    def get_token_user_class(self, scope: ResolvedAppScope | None) -> type[TokenUser]:
        if scope is not None and scope.binding.token_user_class is not None:
            return scope.binding.token_user_class
        return api_settings.TOKEN_USER_CLASS

    def get_user(
        self, validated_token: Token, request: Request | None = None, **kwargs
    ) -> AuthUser:
        """
        Returns a stateless user object which is backed by the given validated
        token.
        """
        if request is None:
            request = _current_request.get()

        if api_settings.USER_ID_CLAIM not in validated_token:
            # The TokenUser class assumes tokens will have a recognizable user
            # identifier claim.
            raise InvalidToken(_("Token contained no recognizable user identification"))

        # Resolve the scope before constructing the user so a stateless caller
        # can never observe user data from an unapproved or mismatched scope.
        scope = self.get_app_scope(validated_token, request=request)

        return self.get_token_user_class(scope)(validated_token)


JWTTokenUserAuthentication = JWTStatelessUserAuthentication


def default_user_authentication_rule(user: AuthUser | None) -> bool:
    # Prior to Django 1.10, inactive users could be authenticated with the
    # default `ModelBackend`.  As of Django 1.10, the `ModelBackend`
    # prevents inactive users from authenticating.  App designers can still
    # allow inactive users to authenticate by opting for the new
    # `AllowAllUsersModelBackend`.  However, we explicitly prevent inactive
    # users from authenticating to enforce a reasonable policy and provide
    # sensible backwards compatibility with older Django versions.
    return user is not None and (
        not api_settings.CHECK_USER_IS_ACTIVE or user.is_active
    )
