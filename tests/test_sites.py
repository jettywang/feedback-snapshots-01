from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, TestCase
from django.test.utils import override_settings

from sesame import backends
from sesame.backends import ModelBackend
from sesame.legacy import audit_token
from sesame.tokens import create_token
from sesame.tokens_v2 import parse_token as parse_token_v2
from sesame.utils import get_parameters, get_token, get_user

from .mixins import CaptureLogMixin

SITES = {"site_a": "default", "site_b": "site_b"}

SITE_SETTINGS = dict(
    SESAME_SITE_MODE="enforced",
    SESAME_SITES=SITES,
)

COMPATIBLE_SETTINGS = dict(
    SESAME_SITE_MODE="compatible",
    SESAME_SITES=SITES,
)


class CreateSiteUsersMixin:
    """
    Two SQLite user tables with the same primary key and different accounts.

    """

    databases = {"default", "site_b"}

    def setUp(self):
        super().setUp()
        User = get_user_model()
        # Both sites use the same primary key on purpose.
        self.user_a = self.create_user("alice", User=User, using="default")
        self.user_b = self.create_user("bob", User=User, using="site_b")
        self.assertEqual(self.user_a.pk, self.user_b.pk)
        # Give both accounts the same password hash so that their revocation
        # keys collide. This is the worst case for unbound legacy tokens.
        self.user_b.password = self.user_a.password
        self.user_b.save(using="site_b")

    @staticmethod
    def create_user(username, User, using):
        user = User(username=username)
        user.set_password("letmein")
        user.save(using=using)
        return user


@override_settings(**SITE_SETTINGS)
class TestBoundTokens(CreateSiteUsersMixin, CaptureLogMixin, TestCase):
    def test_token_for_site_a_is_bound(self):
        token = create_token(self.user_a, site="site_a")
        user = ModelBackend().authenticate(request=None, sesame=token, site="site_a")
        self.assertEqual(user.username, "alice")
        self.assertEqual(user._state.db, "default")

    def test_token_for_site_b_is_bound(self):
        token = create_token(self.user_b, site="site_b")
        user = ModelBackend().authenticate(request=None, sesame=token, site="site_b")
        self.assertEqual(user.username, "bob")
        self.assertEqual(user._state.db, "site_b")

    def test_token_for_site_a_is_rejected_on_site_b(self):
        token = create_token(self.user_a, site="site_a")
        user = ModelBackend().authenticate(request=None, sesame=token, site="site_b")
        self.assertIsNone(user)
        self.assertLogsContain("Invalid token for user bob")

    def test_token_for_site_b_is_rejected_on_site_a(self):
        token = create_token(self.user_b, site="site_b")
        user = ModelBackend().authenticate(request=None, sesame=token, site="site_a")
        self.assertIsNone(user)
        self.assertLogsContain("Invalid token for user alice")

    def test_get_token_infers_site_from_database(self):
        token = get_token(self.user_b)
        user = get_user(token, site="site_b")
        self.assertEqual(user.username, "bob")
        self.assertIsNone(get_user(token, site="site_a"))

    def test_get_token_infers_site_from_default_database(self):
        User = get_user_model()
        user = User(username="carol")
        user.set_password("letmein")
        user.save(using="default")
        # The default database is mapped to site_a, so it's inferable.
        self.assertEqual(get_token(user), get_token(user, site="site_a"))

    def test_get_token_requires_a_site_when_enforced(self):
        User = get_user_model()
        user = User(username="orphan")
        user.set_password("letmein")
        user.save(using="default")
        # Simulate a user whose database isn't mapped to any site.
        with override_settings(SESAME_SITES={"site_b": "site_b"}):
            with self.assertRaisesRegex(
                ImproperlyConfigured, "cannot determine the site of this user"
            ):
                get_token(user)

    def test_get_token_may_stay_unbound_in_compatible_mode(self):
        User = get_user_model()
        user = User(username="orphan")
        user.set_password("letmein")
        user.save(using="default")
        with override_settings(
            SESAME_SITE_MODE="compatible", SESAME_SITES={"site_b": "site_b"}
        ):
            token = get_token(user)
        self.assertEqual(token, create_token(user))

    def test_unknown_site_is_rejected(self):
        token = create_token(self.user_a, site="site_a")
        user = ModelBackend().authenticate(
            request=None, sesame=token, site="site_unknown"
        )
        self.assertIsNone(user)
        self.assertLogsContain("Unknown site")


class TestBoundTokensWithResolver(CreateSiteUsersMixin, CaptureLogMixin, TestCase):
    databases = {"default", "site_b"}

    @override_settings(
        SESAME_SITE_MODE="enforced",
        SESAME_SITES=SITES,
        SESAME_SITE_RESOLVER="tests.sites.site_from_header",
    )
    def test_request_site_selects_database(self):
        params = get_parameters(self.user_b, site="site_b")
        request = RequestFactory().get("/", params, HTTP_X_SITE="site_b")
        user = get_user(request)
        self.assertEqual(user.username, "bob")
        self.assertEqual(request.sesame_site, "site_b")
        self.assertEqual(user._state.db, "site_b")

    @override_settings(
        SESAME_SITE_MODE="enforced",
        SESAME_SITES=SITES,
        SESAME_SITE_RESOLVER="tests.sites.site_from_header",
    )
    def test_request_without_site_is_rejected(self):
        request = RequestFactory().get("/")
        token = get_parameters(self.user_b, site="site_b")["sesame"]
        user = ModelBackend().authenticate(request, sesame=token)
        self.assertIsNone(user)
        self.assertLogsContain("Site could not be determined")

    @override_settings(
        SESAME_SITE_MODE="enforced",
        SESAME_SITES=SITES,
        SESAME_SITE_RESOLVER="tests.sites.unknown_resolver",
    )
    def test_unknown_resolved_site_is_rejected(self):
        request = RequestFactory().get("/")
        token = get_parameters(self.user_a, site="site_a")["sesame"]
        user = ModelBackend().authenticate(request, sesame=token)
        self.assertIsNone(user)
        self.assertLogsContain("Unknown site")

    @override_settings(
        SESAME_SITE_MODE="enforced",
        SESAME_SITES=SITES,
        SESAME_SITE_RESOLVER="tests.sites.failing_resolver",
    )
    def test_failing_resolver_is_rejected(self):
        request = RequestFactory().get("/")
        token = get_parameters(self.user_a, site="site_a")["sesame"]
        user = ModelBackend().authenticate(request, sesame=token)
        self.assertIsNone(user)
        self.assertLogsContain("Site resolver failed")

    @override_settings(
        SESAME_SITE_MODE="enforced",
        SESAME_SITES=SITES,
        SESAME_SITE_RESOLVER="tests.sites.site_from_header",
    )
    def test_session_reload_uses_resolved_site(self):
        # Simulate what SiteMiddleware does for a session-backed request.
        request = RequestFactory().get("/", HTTP_X_SITE="site_b")
        site = backends.settings.resolve_site(request)
        with backends.use_site(site):
            user = ModelBackend().get_user(self.user_b.pk)
        self.assertEqual(user.username, "bob")
        self.assertEqual(user._state.db, "site_b")


class TestSamePrimaryKeyDifferentAccounts(CreateSiteUsersMixin, TestCase):
    databases = {"default", "site_b"}

    @override_settings(**SITE_SETTINGS)
    def test_same_pk_is_two_different_accounts(self):
        self.assertEqual(self.user_a.pk, self.user_b.pk)
        self.assertNotEqual(self.user_a.username, self.user_b.username)
        user_a = ModelBackend().authenticate(
            request=None,
            sesame=create_token(self.user_a, site="site_a"),
            site="site_a",
        )
        user_b = ModelBackend().authenticate(
            request=None,
            sesame=create_token(self.user_b, site="site_b"),
            site="site_b",
        )
        self.assertEqual(user_a.username, "alice")
        self.assertEqual(user_b.username, "bob")


@override_settings(**COMPATIBLE_SETTINGS)
class TestCompatibleMode(CreateSiteUsersMixin, CaptureLogMixin, TestCase):
    databases = {"default", "site_b"}

    def legacy_token(self, user):
        # A token generated before site binding: no site in the signature.
        return create_token(user)

    def test_bound_token_still_works(self):
        token = create_token(self.user_a, site="site_a")
        user = ModelBackend().authenticate(request=None, sesame=token, site="site_a")
        self.assertEqual(user.username, "alice")

    def test_legacy_token_is_rejected_when_ambiguous(self):
        token = self.legacy_token(self.user_a)
        user = ModelBackend().authenticate(request=None, sesame=token, site="site_a")
        self.assertIsNone(user)
        self.assertLogsContain("Ambiguous legacy token")

    def test_legacy_token_without_site_is_rejected_when_ambiguous(self):
        token = self.legacy_token(self.user_a)
        user = ModelBackend().authenticate(request=None, sesame=token)
        self.assertIsNone(user)
        self.assertLogsContain("Ambiguous legacy token")

    def test_legacy_token_is_accepted_when_unique_to_site(self):
        # Delete the collision so that only site_a's user remains.
        self.user_b.delete(using="site_b")
        token = self.legacy_token(self.user_a)
        user = ModelBackend().authenticate(request=None, sesame=token, site="site_a")
        self.assertEqual(user.username, "alice")

    def test_legacy_token_cannot_cross_to_other_site(self):
        self.user_b.delete(using="site_b")
        token = self.legacy_token(self.user_a)
        # The token belongs to site_a's database, not site_b's.
        user = ModelBackend().authenticate(request=None, sesame=token, site="site_b")
        self.assertIsNone(user)

    def test_legacy_token_without_site_is_accepted_when_unique(self):
        self.user_b.delete(using="site_b")
        token = self.legacy_token(self.user_a)
        user = ModelBackend().authenticate(request=None, sesame=token)
        self.assertEqual(user.username, "alice")

    def test_legacy_token_without_site_resolves_site(self):
        self.user_b.delete(using="site_b")
        request = RequestFactory().get("/")
        token = self.legacy_token(self.user_a)
        user = ModelBackend().authenticate(request, sesame=token)
        self.assertEqual(user.username, "alice")
        self.assertEqual(request.sesame_site, "site_a")

    def test_legacy_token_without_site_does_not_guess_ambiguous_site(self):
        user = ModelBackend().authenticate(
            request=None, sesame=self.legacy_token(self.user_a)
        )
        self.assertIsNone(user)

    def test_enforced_mode_rejects_legacy_token_without_site(self):
        self.user_b.delete(using="site_b")
        token = self.legacy_token(self.user_a)
        with override_settings(SESAME_SITE_MODE="enforced"):
            user = ModelBackend().authenticate(request=None, sesame=token)
        self.assertIsNone(user)

    def test_legacy_audit_reports_ambiguous(self):
        token = self.legacy_token(self.user_a)
        audit = audit_token(token)
        self.assertEqual(audit.status, "ambiguous")
        self.assertFalse(audit.is_safe)
        self.assertEqual(
            {match.database for match in audit.matches}, {"default", "site_b"}
        )

    def test_legacy_audit_reports_unique(self):
        self.user_b.delete(using="site_b")
        token = self.legacy_token(self.user_a)
        audit = audit_token(token)
        self.assertEqual(audit.status, "unique")
        self.assertTrue(audit.is_safe)
        self.assertEqual(audit.matches[0].database, "default")
        self.assertEqual(audit.matches[0].site, "site_a")

    def test_legacy_audit_reports_invalid(self):
        token = self.legacy_token(self.user_a)
        # Both accounts share the same revocation key, so remove both.
        self.user_a.delete()
        self.user_b.delete(using="site_b")
        audit = audit_token(token)
        self.assertEqual(audit.status, "invalid")


@override_settings(**COMPATIBLE_SETTINGS)
class TestUnmigratedSite(CreateSiteUsersMixin, CaptureLogMixin, TestCase):
    databases = {"default", "site_b"}

    def test_unmigrated_site_uses_default_database(self):
        # site_c isn't in SESAME_SITES: it hasn't been migrated yet.
        request = RequestFactory().get("/")
        token = create_token(self.user_a)
        user = ModelBackend().authenticate(request, sesame=token, site="site_c")
        self.assertEqual(user.username, "alice")
        self.assertEqual(user._state.db, "default")
        self.assertEqual(request.sesame_site, "site_c")

    @override_settings(SESAME_SITE_MODE="enforced")
    def test_enforced_mode_rejects_unmigrated_site(self):
        token = create_token(self.user_a)
        user = ModelBackend().authenticate(request=None, sesame=token, site="site_c")
        self.assertIsNone(user)


class TestDisabledMode(CreateSiteUsersMixin, TestCase):
    databases = {"default", "site_b"}

    @override_settings(SESAME_SITE_MODE="disabled", SESAME_SITES=SITES)
    def test_tokens_are_not_bound(self):
        token = create_token(self.user_a)
        user = ModelBackend().authenticate(request=None, sesame=token)
        self.assertEqual(user.username, "alice")
        # A site argument is ignored as long as sites are disabled.
        self.assertEqual(
            ModelBackend().authenticate(request=None, sesame=token, site="site_b"),
            self.user_a,
        )
        self.assertEqual(get_token(self.user_a), token)

    @override_settings(SESAME_SITE_MODE="disabled", SESAME_SITES=SITES)
    def test_users_are_read_from_the_default_database(self):
        # A user with the same primary key exists in site_b. Disabled mode must
        # keep the historical behavior and never read from another database.
        token = create_token(self.user_a)
        self.assertEqual(
            ModelBackend().authenticate(request=None, sesame=token),
            self.user_a,
        )
        # A token generated from site_b's user is checked against the default
        # database only, so it resolves to the account with that primary key
        # there. It must never reach site_b's database.
        token_b = create_token(self.user_b)
        user = ModelBackend().authenticate(request=None, sesame=token_b)
        self.assertEqual(user.username, "alice")
        self.assertEqual(user._state.db, "default")

    def test_default_site_key_is_unchanged(self):
        # Tokens generated without a site must keep their historical signature.
        token = create_token(self.user_a)
        user = parse_token_v2(token, lambda pk: self.user_a)
        self.assertEqual(user, self.user_a)


class TestV1TokensDontSupportSites(CreateSiteUsersMixin, TestCase):
    databases = {"default", "site_b"}

    @override_settings(SESAME_SITE_MODE="enforced", SESAME_SITES=SITES)
    def test_v1_tokens_are_rejected_when_a_site_is_set(self):
        with override_settings(SESAME_TOKENS=["sesame.tokens_v1"]):
            token = create_token(self.user_a)
        self.assertIsNone(get_user(token, site="site_a"))

    @override_settings(SESAME_SITE_MODE="enforced", SESAME_SITES=SITES)
    def test_v1_tokens_cannot_be_bound(self):
        with override_settings(SESAME_TOKENS=["sesame.tokens_v1"]):
            with self.assertRaises(NotImplementedError):
                create_token(self.user_a, site="site_a")


@override_settings(
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "sesame.middleware.SiteMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "sesame.middleware.AuthenticationMiddleware",
    ],
    SESAME_SITE_MODE="enforced",
    SESAME_SITES=SITES,
    SESAME_SITE_RESOLVER="tests.sites.site_from_header",
)
class TestSiteMiddleware(CreateSiteUsersMixin, TestCase):
    databases = {"default", "site_b"}

    def test_login_then_session_reload_uses_site_database(self):
        params = get_parameters(self.user_b, site="site_b")
        response = self.client.get("/sites/login/b/", params, HTTP_X_SITE="site_b")
        self.assertEqual(response.status_code, 302)

        # The session now points at the user; drop the token from the URL.
        response = self.client.get("/", HTTP_X_SITE="site_b")
        self.assertContains(response, "bob")

    def test_session_is_not_reloaded_from_wrong_site(self):
        params = get_parameters(self.user_b, site="site_b")
        self.client.get("/sites/login/b/", params, HTTP_X_SITE="site_b")
        # Same session cookie, but the request claims the other site. Django
        # sessions store only the primary key, so this must not load alice.
        response = self.client.get("/", HTTP_X_SITE="site_a")
        self.assertEqual(response.content.decode(), "anonymous")

    def test_session_is_reloaded_on_the_same_site(self):
        params = get_parameters(self.user_b, site="site_b")
        self.client.get("/sites/login/b/", params, HTTP_X_SITE="site_b")
        response = self.client.get("/", HTTP_X_SITE="site_b")
        self.assertEqual(response.content.decode(), "bob")

    def test_resolver_failure_is_rejected_in_compatible_mode(self):
        # An unbound token that would otherwise be accepted uniquely must not
        # be accepted when the site cannot be resolved.
        self.user_b.delete(using="site_b")
        token = create_token(self.user_a)
        with override_settings(
            SESAME_SITE_MODE="compatible",
            SESAME_SITE_RESOLVER="tests.sites.failing_resolver",
        ):
            with self.assertLogs("sesame", "ERROR"):
                response = self.client.get("/", {"sesame": token})
        self.assertEqual(response.content.decode(), "anonymous")

    def test_site_middleware_is_a_noop_when_disabled(self):
        with override_settings(SESAME_SITE_MODE="disabled"):
            params = get_parameters(self.user_a)
            response = self.client.get("/login/", params)
            self.assertEqual(response.status_code, 302)
            response = self.client.get("/")
        self.assertContains(response, "alice")


@override_settings(**COMPATIBLE_SETTINGS)
class TestLegacyAuditPerSite(CreateSiteUsersMixin, CaptureLogMixin, TestCase):
    databases = {"default", "site_b"}

    def test_audit_for_specific_site(self):
        self.user_b.delete(using="site_b")
        token = create_token(self.user_a)
        self.assertEqual(audit_token(token, site="site_a").status, "unique")
        self.assertEqual(audit_token(token, site="site_b").status, "invalid")

    def test_audit_for_unknown_site(self):
        token = create_token(self.user_a)
        with self.assertRaises(ValueError):
            audit_token(token, site="site_unknown")
