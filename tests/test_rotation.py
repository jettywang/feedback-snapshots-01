from contextlib import contextmanager
from unittest import mock

from django.test import TestCase, override_settings
from sesame import tokens_v1, tokens_v2
from sesame.tokens import create_token, parse_token
from sesame.utils import get_user

from .mixins import CreateUserMixin

OLD_KEY = "fake-old-secret-key-000000000000000000000000"
NEW_KEY = "fake-new-secret-key-111111111111111111111111"
SALT = "sesame"
MAX_AGE = 3600
TOKENS = ["sesame.tokens_v2", "sesame.tokens_v1"]


def config(
    secret_key,
    fallbacks=(),
    max_age=MAX_AGE,
    salt=SALT,
    key="",
    tokens=None,
):
    return {
        "SECRET_KEY": secret_key,
        "SECRET_KEY_FALLBACKS": list(fallbacks),
        "SESAME_MAX_AGE": max_age,
        "SESAME_SALT": salt,
        "SESAME_KEY": key,
        "SESAME_TOKENS": list(tokens or TOKENS),
    }


OLD = config(OLD_KEY)
STEP1 = config(OLD_KEY, [NEW_KEY])
STEP2 = config(NEW_KEY, [OLD_KEY])
CONTRACT = config(NEW_KEY)

NONE_OLD = config(OLD_KEY, max_age=None)
NONE_STEP1 = config(OLD_KEY, [NEW_KEY], max_age=None)
NONE_STEP2 = config(NEW_KEY, [OLD_KEY], max_age=None)
NONE_CONTRACT = config(NEW_KEY, max_age=None)


class Clock:
    def __init__(self, now):
        self.now = now

    def time(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@contextmanager
def deployment(cfg):
    with override_settings(**cfg):
        tokens_v1.signer = tokens_v1.get_signer()
        yield


@contextmanager
def frozen(clock):
    with mock.patch("time.time", clock.time):
        yield


def issue(fmt, user, clock):
    with frozen(clock):
        if fmt == "v2":
            return create_token(user)
        return tokens_v1.create_token(user)


def verify(token, user, get_user, clock):
    with frozen(clock):
        return parse_token(token, get_user) == user


class TestRotation(CreateUserMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.clock = Clock(1_700_000_000)

    def issue_in(self, cfg, fmt):
        with deployment(cfg):
            return issue(fmt, self.user, self.clock)

    def verify_in(self, cfg, token):
        with deployment(cfg):
            return verify(token, self.user, self.get_user, self.clock)

    def test_mixed_deployment_two_phase(self):
        for fmt in ("v1", "v2"):
            with self.subTest(fmt=fmt):
                old_link = self.issue_in(OLD, fmt)
                new_link = self.issue_in(STEP2, fmt)
                self.clock.advance(1800)

                self.assertTrue(self.verify_in(STEP1, old_link))
                self.assertTrue(self.verify_in(STEP2, old_link))
                self.assertTrue(self.verify_in(STEP1, new_link))
                self.assertTrue(self.verify_in(STEP2, new_link))

                self.assertTrue(self.verify_in(OLD, old_link))
                self.assertFalse(self.verify_in(CONTRACT, old_link))
                self.assertFalse(self.verify_in(OLD, new_link))
                self.assertTrue(self.verify_in(CONTRACT, new_link))

    def test_direct_rotation_fails_in_mixed_deployment(self):
        for fmt in ("v1", "v2"):
            with self.subTest(fmt=fmt):
                old_link = self.issue_in(OLD, fmt)
                new_link = self.issue_in(CONTRACT, fmt)
                self.clock.advance(1800)

                self.assertFalse(self.verify_in(CONTRACT, old_link))
                self.assertFalse(self.verify_in(OLD, new_link))

    def test_natural_expiry_ends_transition(self):
        for fmt in ("v1", "v2"):
            with self.subTest(fmt=fmt):
                link = self.issue_in(OLD, fmt)
                self.clock.advance(MAX_AGE - 1)
                self.assertTrue(self.verify_in(STEP2, link))
                self.clock.advance(2)
                self.assertFalse(self.verify_in(STEP2, link))
                self.assertFalse(self.verify_in(OLD, link))

    def test_rollback_keeps_both_generations_valid(self):
        for fmt in ("v1", "v2"):
            with self.subTest(fmt=fmt):
                old_link = self.issue_in(OLD, fmt)
                new_link = self.issue_in(STEP2, fmt)
                self.clock.advance(1800)

                rollback_safe = STEP1
                self.assertTrue(self.verify_in(rollback_safe, old_link))
                self.assertTrue(self.verify_in(rollback_safe, new_link))

                rollback_naive = OLD
                self.assertTrue(self.verify_in(rollback_naive, old_link))
                self.assertFalse(self.verify_in(rollback_naive, new_link))

    def test_rollback_after_contract_resurrects_old_links(self):
        for fmt in ("v1", "v2"):
            with self.subTest(fmt=fmt):
                old_link = self.issue_in(OLD, fmt)
                new_link = self.issue_in(STEP2, fmt)
                self.clock.advance(1800)

                self.assertFalse(self.verify_in(CONTRACT, old_link))
                self.assertTrue(self.verify_in(STEP2, old_link))
                self.assertFalse(self.verify_in(CONTRACT, old_link))
                self.assertTrue(self.verify_in(STEP2, new_link))

    def test_non_expiring_historical_links(self):
        self.clock.advance(10 * 365 * 86400)
        for fmt in ("v1", "v2"):
            with self.subTest(fmt=fmt):
                link = self.issue_in(NONE_OLD, fmt)
                self.assertTrue(self.verify_in(NONE_OLD, link))
                self.assertTrue(self.verify_in(NONE_STEP1, link))
                self.assertTrue(self.verify_in(NONE_STEP2, link))
                self.assertFalse(self.verify_in(NONE_CONTRACT, link))

    def test_enabling_max_age_invalidates_historical_links(self):
        for fmt in ("v1", "v2"):
            with self.subTest(fmt=fmt):
                link = self.issue_in(NONE_OLD, fmt)
                self.assertTrue(self.verify_in(NONE_OLD, link))
                self.assertFalse(self.verify_in(OLD, link))

    def test_retiring_v1_verification(self):
        v1_link = self.issue_in(config(OLD_KEY, tokens=["sesame.tokens_v1"]), "v1")
        v2_link = self.issue_in(OLD, "v2")
        v2_only = config(OLD_KEY, tokens=["sesame.tokens_v2"])
        self.assertFalse(self.verify_in(v2_only, v1_link))
        self.assertTrue(self.verify_in(v2_only, v2_link))

    def test_v1_is_not_issued_by_default(self):
        with deployment(OLD):
            token = create_token(self.user)
        self.assertFalse(tokens_v1.detect_token(token))
        self.assertTrue(tokens_v2.detect_token(token))

    def test_sesame_key_rotation_has_no_fallback(self):
        v1_link = self.issue_in(OLD, "v1")
        v2_link = self.issue_in(OLD, "v2")
        rotated = config(NEW_KEY, [OLD_KEY], key="rotated")
        self.assertFalse(self.verify_in(rotated, v2_link))
        self.assertTrue(self.verify_in(rotated, v1_link))

    def test_salt_rotation_has_no_fallback(self):
        v1_link = self.issue_in(OLD, "v1")
        v2_link = self.issue_in(OLD, "v2")
        rotated = config(NEW_KEY, [OLD_KEY], salt="rotated")
        self.assertFalse(self.verify_in(rotated, v1_link))
        self.assertTrue(self.verify_in(rotated, v2_link))

    def test_expiry_boundary_differs_between_formats(self):
        # v1 rejects when age > max_age; v2 rejects when age >= max_age.
        v1_link = self.issue_in(OLD, "v1")
        v2_link = self.issue_in(OLD, "v2")
        self.clock.advance(MAX_AGE)
        self.assertTrue(self.verify_in(STEP2, v1_link))
        self.assertFalse(self.verify_in(STEP2, v2_link))
        self.clock.advance(1)
        self.assertFalse(self.verify_in(STEP2, v1_link))

    def test_rotating_and_toggling_max_age_in_one_step_breaks_everything(self):
        old_v1 = self.issue_in(NONE_OLD, "v1")
        old_v2 = self.issue_in(NONE_OLD, "v2")
        composite = config(NEW_KEY, [OLD_KEY], max_age=MAX_AGE)
        self.assertFalse(self.verify_in(composite, old_v1))
        self.assertFalse(self.verify_in(composite, old_v2))

    def test_real_authentication_path_across_deployment(self):
        for fmt in ("v1", "v2"):
            with self.subTest(fmt=fmt):
                old_link = self.issue_in(OLD, fmt)
                with deployment(STEP2):
                    with frozen(self.clock):
                        self.assertEqual(get_user(old_link), self.user)
                with deployment(CONTRACT):
                    with frozen(self.clock):
                        self.assertIsNone(get_user(old_link))
                with deployment(STEP2):
                    with frozen(self.clock):
                        self.assertEqual(get_user(old_link), self.user)
