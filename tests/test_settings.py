import datetime

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

from sesame import settings


class TestSettings(TestCase):
    @override_settings(SESAME_MAX_AGE=datetime.timedelta(minutes=5))
    def test_max_age_timedelta(self):
        self.assertEqual(settings.MAX_AGE, 300)

    @override_settings(
        SESAME_INVALIDATE_ON_PASSWORD_CHANGE=False,
        SESAME_MAX_AGE=None,
    )
    def test_insecure_configuration(self):
        with self.assertRaises(ImproperlyConfigured) as exc:
            settings.check()
        self.assertEqual(
            str(exc.exception),
            "insecure configuration: set SESAME_MAX_AGE to a low value "
            "or set SESAME_INVALIDATE_ON_PASSWORD_CHANGE to True",
        )

    @override_settings(
        SESAME_INVALIDATE_ON_EMAIL_CHANGE=True,
        AUTH_USER_MODEL="tests.StrUser",
    )
    def test_invalid_configuration(self):
        with self.assertRaises(ImproperlyConfigured) as exc:
            settings.check()
        self.assertEqual(
            str(exc.exception),
            "invalid configuration: set User.EMAIL_FIELD correctly "
            "or set SESAME_INVALIDATE_ON_EMAIL_CHANGE to False",
        )


class TestSiteSettings(TestCase):
    @override_settings(SESAME_SITE_MODE="bogus")
    def test_invalid_mode(self):
        with self.assertRaises(ImproperlyConfigured) as exc:
            settings.validate_sites()
        self.assertEqual(
            str(exc.exception),
            "invalid configuration: SESAME_SITE_MODE must be one of "
            "disabled, compatible, enforced",
        )

    @override_settings(SESAME_SITE_MODE="enforced", SESAME_SITES={})
    def test_missing_sites(self):
        with self.assertRaises(ImproperlyConfigured) as exc:
            settings.validate_sites()
        self.assertEqual(
            str(exc.exception),
            "invalid configuration: set SESAME_SITES when "
            "SESAME_SITE_MODE is 'enforced'",
        )

    @override_settings(
        SESAME_SITE_MODE="enforced",
        SESAME_SITES={"site_a": "missing"},
    )
    def test_unknown_database(self):
        with self.assertRaises(ImproperlyConfigured) as exc:
            settings.validate_sites()
        self.assertIn("references unknown databases", str(exc.exception))

    @override_settings(
        SESAME_SITE_MODE="enforced",
        SESAME_SITES={"site_a": "default"},
        SESAME_SITE="site_b",
    )
    def test_unknown_default_site(self):
        with self.assertRaises(ImproperlyConfigured) as exc:
            settings.validate_sites()
        self.assertEqual(
            str(exc.exception),
            "invalid configuration: SESAME_SITE 'site_b' isn't in SESAME_SITES",
        )

    def test_default_key_is_backward_compatible(self):
        # Tokens generated before sites existed must keep the same key.
        self.assertEqual(
            settings.derive_key("secret", "key").hex(),
            "5cf9c5b4d16a9217dfc1673ddd910653"
            "17ebf1a5a7490327e36e0cc0b80fddf9"
            "ba73e00c340cd44f4da7ed79a08c7af6"
            "2c784071143730229207b5186a5d5c10",
        )

    def test_site_key_differs(self):
        self.assertNotEqual(
            settings.derive_key("secret", "key"),
            settings.derive_key("secret", "key", site="site_a"),
        )
        self.assertNotEqual(
            settings.derive_key("secret", "key", site="site_a"),
            settings.derive_key("secret", "key", site="site_a|b"),
        )

    def test_site_key_is_not_confused_by_separators(self):
        self.assertNotEqual(
            settings.derive_key("secret", "key", site="a|b"),
            settings.derive_key("secret", "key", site="a|max_age"),
        )

    def test_site_key_uses_fallback_secrets(self):
        signing_key, verification_keys = settings.get_site_settings("site_a")
        self.assertEqual(len(verification_keys), 1)
        self.assertEqual(signing_key, verification_keys[0])
