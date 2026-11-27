from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import permissions
from rest_framework.exceptions import (
    AuthenticationFailed as DRFAuthenticationFailed,
)
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from rest_framework_simplejwt.app_scope import (
    AppScopeBinding,
    AppScopeRegistry,
    resolve_token_app_scope,
)
from rest_framework_simplejwt.authentication import (
    JWTAuthentication,
    JWTStatelessUserAuthentication,
)
from rest_framework_simplejwt.models import TokenUser
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from .app_a.models import User as AppAUser
from .app_b.models import User as AppBUser
from .utils import override_api_settings

DefaultUser = get_user_model()

APP_A = "app-a"
APP_B = "app-b"


def scope_registry():
    # Both applications use the same numeric user IDs.  Only the binding
    # decides which collection of users a token is allowed to read.
    return AppScopeRegistry(
        {
            APP_A: AppScopeBinding(APP_A, users=AppAUser.objects),
            APP_B: AppScopeBinding(APP_B, users=AppBUser.objects),
        }
    )


class WhoAmIView(APIView):
    authentication_classes = (
        JWTAuthentication,
        JWTStatelessUserAuthentication,
    )
    permission_classes = (permissions.IsAuthenticated,)
    required_app_scope = None

    def get(self, request):
        return Response(
            {
                "backend": request.successful_authenticator.__class__.__name__,
                "user_pk": request.user.pk,
                "user_id": request.user.id,
                "app_scope": (
                    request.auth.get(api_settings.APP_SCOPE_CLAIM)
                    if request.auth is not None
                    else None
                ),
                "username": getattr(request.user, "username", None),
                "objects": list(self.objects_for(request.user)),
            }
        )

    def objects_for(self, user):
        return []


class AppAObjectsView(WhoAmIView):
    required_app_scope = APP_A

    def objects_for(self, user):
        return AppAUser.objects.filter(pk=user.pk).values_list("username", flat=True)


class AppBObjectsView(WhoAmIView):
    required_app_scope = APP_B

    def objects_for(self, user):
        return AppBUser.objects.filter(pk=user.pk).values_list("username", flat=True)


class StatelessAppObjectsView(APIView):
    authentication_classes = (JWTStatelessUserAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    required_app_scope = APP_A

    def get(self, request):
        # The stateless backend has no ORM identity of its own.  It must use
        # the same scope resolution to learn which application owns the ID.
        resolved = resolve_token_app_scope(
            request.auth, required_app_scope=APP_A
        )
        source = resolved.binding.user_source
        return Response(
            {
                "backend": request.successful_authenticator.__class__.__name__,
                "user_id": request.user.id,
                "app_scope": request.user.app_scope,
                "objects": list(
                    source.filter(pk=request.user.pk).values_list(
                        "username", flat=True
                    )
                ),
            }
        )


class AppScopeTestBase(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.app_a_user = AppAUser.objects.create(pk=1, username="alice-in-a")
        self.app_b_user = AppBUser.objects.create(pk=1, username="bob-in-b")

        self.default_user = DefaultUser.objects.create_user(
            username="default-service-user", pk=1
        )
        self.registry = scope_registry()

    def call(self, view_class, token, **settings):
        view = view_class.as_view()
        request = self.factory.get(
            "/whoami/", HTTP_AUTHORIZATION=f"Bearer {token}"
        )
        with override_api_settings(**settings):
            response = view(request)

        # DRF turns authentication errors into 401 responses.  Normalize them so
        # tests can assert both the outcome and the machine-readable code.
        if response.status_code == 401:
            response.data["code"] = response.data.get("code", "token_not_valid")
        return response


class TestScopedLookup(AppScopeTestBase):
    def test_same_integer_id_reads_the_bound_application(self):
        token_a = AccessToken.for_user(self.app_a_user, app_scope=APP_A)
        token_b = AccessToken.for_user(self.app_b_user, app_scope=APP_B)

        self.assertEqual(self.app_a_user.pk, self.app_b_user.pk)

        res_a = self.call(
            AppAObjectsView,
            token_a,
            APP_SCOPE_RESOLVER=self.registry,
            APP_SCOPE_REQUIRED=True,
        )
        res_b = self.call(
            AppBObjectsView,
            token_b,
            APP_SCOPE_RESOLVER=self.registry,
            APP_SCOPE_REQUIRED=True,
        )

        self.assertEqual(res_a.status_code, 200)
        self.assertEqual(res_b.status_code, 200)
        self.assertEqual(res_a.data["objects"], ["alice-in-a"])
        self.assertEqual(res_b.data["objects"], ["bob-in-b"])
        self.assertEqual(res_a.data["app_scope"], APP_A)
        self.assertEqual(res_b.data["app_scope"], APP_B)
        self.assertEqual(res_a.data["backend"], "JWTAuthentication")
        self.assertEqual(res_b.data["backend"], "JWTAuthentication")

    def test_scope_mismatch_is_rejected_before_reading_objects(self):
        token_a = AccessToken.for_user(self.app_a_user, app_scope=APP_A)

        response = self.call(
            AppBObjectsView, token_a, APP_SCOPE_RESOLVER=self.registry
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_mismatch")

    def test_unknown_scope_is_rejected(self):
        token = AccessToken.for_user(self.app_a_user, app_scope="app-c")

        response = self.call(
            AppAObjectsView, token, APP_SCOPE_RESOLVER=self.registry
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_unknown")

    def test_inconsistent_mapping_is_rejected(self):
        registry = AppScopeRegistry(
            {APP_A: AppScopeBinding(APP_B, users=AppBUser.objects)}
        )
        token = AccessToken.for_user(self.app_a_user, app_scope=APP_A)

        response = self.call(
            AppAObjectsView, token, APP_SCOPE_RESOLVER=registry
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_mapping_inconsistent")

    def test_stateless_uses_the_same_scope_resolution(self):
        token_a = AccessToken.for_user(self.app_a_user, app_scope=APP_A)
        token_b = AccessToken.for_user(self.app_b_user, app_scope=APP_B)

        with override_api_settings(APP_SCOPE_RESOLVER=self.registry):
            backend = JWTStatelessUserAuthentication()

            user_a, _ = backend.authenticate(
                self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token_a}")
            )
            user_b, _ = backend.authenticate(
                self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token_b}")
            )

        self.assertIsInstance(user_a, TokenUser)
        self.assertIsInstance(user_b, TokenUser)
        self.assertEqual(user_a.id, "1")
        self.assertEqual(user_b.id, "1")
        self.assertEqual(user_a.app_scope, APP_A)
        self.assertEqual(user_b.app_scope, APP_B)

    def test_stateless_rejects_mismatch_on_scoped_route(self):
        token_a = AccessToken.for_user(self.app_a_user, app_scope=APP_A)

        response = self.call(
            AppBObjectsView, token_a, APP_SCOPE_RESOLVER=self.registry
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_mismatch")

    def test_stateful_and_stateless_resolve_to_same_bound_user_id(self):
        token_a = AccessToken.for_user(self.app_a_user, app_scope=APP_A)

        with override_api_settings(APP_SCOPE_RESOLVER=self.registry):
            stateful = JWTAuthentication()
            stateless = JWTStatelessUserAuthentication()

            stateful_user, _ = stateful.authenticate(
                self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token_a}")
            )
            stateless_user, _ = stateless.authenticate(
                self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token_a}")
            )

        self.assertEqual(stateful_user.pk, AppAUser.objects.get().pk)
        self.assertEqual(stateless_user.id, str(stateful_user.pk))
        self.assertEqual(stateless_user.app_scope, APP_A)


class TestLegacyTokenPolicy(AppScopeTestBase):
    def test_legacy_token_rejected_by_default(self):
        legacy = AccessToken.for_user(self.default_user)

        response = self.call(
            AppAObjectsView, legacy, APP_SCOPE_RESOLVER=self.registry
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_required")

    def test_legacy_token_allowed_only_on_unscoped_routes(self):
        legacy = AccessToken.for_user(self.default_user)

        with override_api_settings(
            APP_SCOPE_RESOLVER=self.registry,
            APP_SCOPE_LEGACY_POLICY="allow_unscoped",
        ):
            backend = JWTAuthentication()
            user, _ = backend.authenticate(
                self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {legacy}")
            )
        self.assertEqual(user.pk, self.default_user.pk)

        response = self.call(
            AppAObjectsView,
            legacy,
            APP_SCOPE_RESOLVER=self.registry,
            APP_SCOPE_LEGACY_POLICY="allow_unscoped",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_required")

    def test_legacy_migration_callback_can_pin_a_scope(self):
        legacy = AccessToken.for_user(self.default_user)

        def migrate(token, request):
            return APP_B

        legacy_result = self.call(
            AppBObjectsView,
            legacy,
            APP_SCOPE_RESOLVER=AppScopeRegistry(
                {
                    APP_A: AppScopeBinding(APP_A, users=AppAUser.objects),
                    # A legacy migration policy must name a scope that the
                    # registry recognizes; the token's numeric ID then maps to
                    # that application only.
                    APP_B: AppScopeBinding(APP_B, users=AppBUser.objects),
                }
            ),
            APP_SCOPE_LEGACY_POLICY=migrate,
        )

        self.assertEqual(legacy_result.status_code, 200)
        self.assertEqual(legacy_result.data["objects"], ["bob-in-b"])

    def test_legacy_migration_callback_naming_unknown_scope_fails(self):
        legacy = AccessToken.for_user(self.default_user)

        response = self.call(
            AppAObjectsView,
            legacy,
            APP_SCOPE_RESOLVER=self.registry,
            APP_SCOPE_LEGACY_POLICY=lambda token, request: "app-z",
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_unknown")

    def test_legacy_token_without_scope_cannot_be_forced_into_a_route(self):
        legacy = AccessToken.for_user(self.default_user)

        response = self.call(
            AppAObjectsView,
            legacy,
            APP_SCOPE_RESOLVER=self.registry,
            APP_SCOPE_LEGACY_POLICY=lambda token, request: True,
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_required")


class TestScopeIssuance(AppScopeTestBase):
    def test_for_user_embeds_scope(self):
        token = AccessToken.for_user(self.app_a_user, app_scope=APP_A)
        self.assertEqual(token[api_settings.APP_SCOPE_CLAIM], APP_A)

    def test_refresh_access_token_carries_scope(self):
        refresh = RefreshToken.for_user(self.app_a_user, app_scope=APP_A)
        self.assertEqual(
            refresh.access_token[api_settings.APP_SCOPE_CLAIM], APP_A
        )

    def test_unscoped_token_user_has_no_app_scope(self):
        token = AccessToken.for_user(self.default_user)
        user = TokenUser(token)
        self.assertIsNone(user.app_scope)

    def test_scoped_route_without_resolver_is_rejected(self):
        token = AccessToken.for_user(self.app_a_user, app_scope=APP_A)

        response = self.call(AppAObjectsView, token)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_not_configured")

    def test_scoped_token_without_resolver_is_rejected_even_unscoped_route(self):
        token = AccessToken.for_user(self.app_a_user, app_scope=APP_A)

        response = self.call(WhoAmIView, token)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_not_configured")


class TestStatelessObjectAccess(AppScopeTestBase):
    def test_stateless_reads_only_the_scope_owned_objects(self):
        token_a = AccessToken.for_user(self.app_a_user, app_scope=APP_A)

        response = self.call(
            StatelessAppObjectsView,
            token_a,
            APP_SCOPE_RESOLVER=self.registry,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["backend"], "JWTStatelessUserAuthentication")
        self.assertEqual(response.data["user_id"], "1")
        self.assertEqual(response.data["app_scope"], APP_A)
        self.assertEqual(response.data["objects"], ["alice-in-a"])

    def test_stateless_cross_scope_request_matches_stateful_rejection(self):
        token_b = AccessToken.for_user(self.app_b_user, app_scope=APP_B)

        stateless = self.call(
            StatelessAppObjectsView,
            token_b,
            APP_SCOPE_RESOLVER=self.registry,
        )
        stateful = self.call(
            AppAObjectsView,
            token_b,
            APP_SCOPE_RESOLVER=self.registry,
        )

        self.assertEqual(stateless.status_code, 401)
        self.assertEqual(stateful.status_code, 401)
        self.assertEqual(stateless.data["code"], "app_scope_mismatch")
        self.assertEqual(stateful.data["code"], "app_scope_mismatch")

    def test_stateless_rejects_inconsistent_mapping(self):
        registry = AppScopeRegistry(
            {APP_A: AppScopeBinding(APP_B, users=AppBUser.objects)}
        )
        token_a = AccessToken.for_user(self.app_a_user, app_scope=APP_A)

        response = self.call(
            StatelessAppObjectsView, token_a, APP_SCOPE_RESOLVER=registry
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "app_scope_mapping_inconsistent")


class TestRefreshScopeOwnership(AppScopeTestBase):
    def test_refresh_uses_the_tokens_own_scope_user(self):
        refresh = RefreshToken.for_user(self.app_a_user, app_scope=APP_A)

        with override_api_settings(APP_SCOPE_RESOLVER=self.registry):
            serializer = TokenRefreshSerializer(data={"refresh": str(refresh)})
            self.assertTrue(serializer.is_valid(), serializer.errors)

        access = AccessToken(serializer.validated_data["access"])
        self.assertEqual(access[api_settings.APP_SCOPE_CLAIM], APP_A)
        self.assertEqual(access[api_settings.USER_ID_CLAIM], "1")

    def test_refresh_for_missing_scoped_user_does_not_fall_back(self):
        # No app-b user has ID 99, but the default user does.  A fallback
        # lookup would wrongly find that user and mint an app-b token for them.
        refresh = RefreshToken.for_user(self.default_user, app_scope=APP_B)
        refresh[api_settings.USER_ID_CLAIM] = "99"

        with override_api_settings(APP_SCOPE_RESOLVER=self.registry):
            serializer = TokenRefreshSerializer(data={"refresh": str(refresh)})

            with self.assertRaises(DRFAuthenticationFailed):
                serializer.is_valid(raise_exception=True)


class TestBlacklistScopeAttribution(AppScopeTestBase):
    def test_scoped_outstanding_token_is_not_misattributed(self):
        refresh = RefreshToken.for_user(self.app_a_user, app_scope=APP_A)
        outstanding = OutstandingToken.objects.get(jti=refresh["jti"])

        # The default user shares the same numeric ID, but the token belongs to
        # app-a.  Storing the default user would be a false attribution.
        self.assertIsNone(outstanding.user)

    def test_unscoped_outstanding_token_keeps_its_user(self):
        refresh = RefreshToken.for_user(self.default_user)
        outstanding = OutstandingToken.objects.get(jti=refresh["jti"])

        self.assertEqual(outstanding.user, self.default_user)


class TestExtensionCompatibility(AppScopeTestBase):
    def test_legacy_get_user_override_still_receives_one_argument(self):
        calls = []

        class OverriddenAuthentication(JWTAuthentication):
            def get_user(self, validated_token):
                calls.append(validated_token)
                return super().get_user(validated_token)

        token = AccessToken.for_user(self.app_a_user, app_scope=APP_A)

        with override_api_settings(APP_SCOPE_RESOLVER=self.registry):
            user, _ = OverriddenAuthentication().authenticate(
                self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
            )

        self.assertEqual(user.pk, self.app_a_user.pk)
        self.assertEqual(len(calls), 1)
