from datetime import timedelta

from django.contrib.auth import get_user_model
from freezegun import freeze_time

from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.utils import (
    aware_utcnow,
    datetime_from_epoch,
    datetime_to_epoch,
)

from .utils import APIViewTestCase, override_api_settings
from .verifiers import recording_verifier, rejecting_verifier

User = get_user_model()

STEP_UP_SETTINGS = {
    "STEP_UP_ENABLED": True,
    "STEP_UP_LIFETIME": timedelta(minutes=2),
    "STEP_UP_VERIFIER": "tests.verifiers.verify_step_up",
}

STEP_UP_CLAIM = "step_up_exp"


class StepUpScenarioTestCase(APIViewTestCase):
    """
    Drives the full lifecycle described in the requirement with a frozen clock
    and a recording verifier:

      normal login -> short-lived step-up approval -> refresh while the proof
      is valid -> proof expiry.

    At every stage both the ordinary and the sensitive endpoint are hit once.
    """

    view_name = "token_obtain_pair"

    def setUp(self):
        self.user = User.objects.create_user(
            username="finance_user", password="test_password"
        )
        self._applied = override_api_settings(**STEP_UP_SETTINGS)
        self._applied.__enter__()
        recording_verifier.reset()
        # Epoch claims are whole seconds; freeze on a second boundary so the
        # fake-clock comparisons line up exactly.
        self.base_time = aware_utcnow().replace(microsecond=0)

    def tearDown(self):
        self._applied.__exit__(None, None, None)
        super().tearDown()

    def _login(self):
        res = self.view_post(
            data={"username": "finance_user", "password": "test_password"}
        )
        self.assertEqual(res.status_code, 200)
        return res.data["access"], res.data["refresh"]

    def _step_up(self, access):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        res = self.client.post(
            "/token/step-up/", {"confirmation": "123456"}, format="json"
        )
        return res

    def _refresh(self, refresh):
        return self.client.post(
            "/token/refresh/", {"refresh": refresh}, format="json"
        )

    def _get(self, name, access):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        return self.client.get(f"/{name}/")

    def test_full_lifecycle_with_fake_clock(self):
        with freeze_time(self.base_time) as frozen_time:
            # Stage 1: ordinary login. No step-up claim yet.
            access, refresh = self._login()
            ordinary = AccessToken(access)
            self.assertNotIn(STEP_UP_CLAIM, ordinary.payload)
            self.assertFalse(ordinary.has_valid_step_up())

            # Ordinary page works; sensitive page requires step-up.
            self.assertEqual(self._get("test-view", access).status_code, 200)
            denied = self._get("sensitive-view", access)
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(denied.data["detail"].code, "step_up_required")

            # Stage 2: short-lived step-up approval via the registered verifier.
            res = self._step_up(access)
            self.assertEqual(res.status_code, 200, res.data)
            stepped_access = AccessToken(res.data["access"])
            stepped_refresh = RefreshToken(res.data["refresh"])

            # The server-registered verifier is the source that was trusted.
            self.assertEqual(len(recording_verifier.calls), 1)
            self.assertEqual(recording_verifier.calls[0]["evidence"], "123456")
            self.assertEqual(
                recording_verifier.calls[0]["user"].pk, self.user.pk
            )

            expected_step_up_exp = self.base_time + timedelta(minutes=2)
            self.assertTrue(stepped_access.has_valid_step_up())
            self.assertEqual(
                datetime_from_epoch(stepped_access[STEP_UP_CLAIM]),
                expected_step_up_exp,
            )
            self.assertEqual(
                stepped_refresh[STEP_UP_CLAIM], stepped_access[STEP_UP_CLAIM]
            )
            # The proof lifetime does not change the access token lifetime.
            self.assertEqual(
                stepped_access["exp"],
                ordinary["exp"],
            )

            # Both endpoints are now reachable.
            self.assertEqual(
                self._get("test-view", res.data["access"]).status_code, 200
            )
            self.assertEqual(
                self._get("sensitive-view", res.data["access"]).status_code,
                200,
            )

            # Stage 3: move forward but keep the proof valid, then refresh.
            frozen_time.tick(timedelta(seconds=30))
            refresh_res = self._refresh(res.data["refresh"])
            self.assertEqual(refresh_res.status_code, 200)
            refreshed_access = AccessToken(refresh_res.data["access"])

            # Refresh copies the proof verbatim: same window, same purpose.
            self.assertEqual(
                refreshed_access[STEP_UP_CLAIM], stepped_access[STEP_UP_CLAIM]
            )
            self.assertTrue(refreshed_access.has_valid_step_up())

            # The refreshed token still serves both endpoints.
            self.assertEqual(
                self._get("test-view", refresh_res.data["access"]).status_code,
                200,
            )
            self.assertEqual(
                self._get(
                    "sensitive-view", refresh_res.data["access"]
                ).status_code,
                200,
            )

            # Stage 4: the step-up proof lapses while the access token is alive.
            frozen_time.tick(timedelta(minutes=2))
            lapsed = AccessToken(refresh_res.data["access"])
            self.assertFalse(lapsed.has_valid_step_up())

            # Ordinary page stays available; sensitive page is locked again.
            self.assertEqual(
                self._get("test-view", refresh_res.data["access"]).status_code,
                200,
            )
            lapsed_denied = self._get(
                "sensitive-view", refresh_res.data["access"]
            )
            self.assertEqual(lapsed_denied.status_code, 403)
            self.assertEqual(
                lapsed_denied.data["detail"].code, "step_up_required"
            )

            # Re-refreshing cannot resurrect or extend the lapsed proof.
            second_refresh = self._refresh(res.data["refresh"])
            self.assertEqual(second_refresh.status_code, 200)
            second_access = AccessToken(second_refresh.data["access"])
            self.assertEqual(
                second_access[STEP_UP_CLAIM], stepped_access[STEP_UP_CLAIM]
            )
            self.assertFalse(second_access.has_valid_step_up())
            self.assertEqual(
                self._get(
                    "sensitive-view", second_refresh.data["access"]
                ).status_code,
                403,
            )
            self.assertEqual(
                self._get("test-view", second_refresh.data["access"]).status_code,
                200,
            )

    def test_refresh_rotation_keeps_step_up_proof(self):
        with override_api_settings(ROTATE_REFRESH_TOKENS=True):
            with freeze_time(self.base_time):
                access, _ = self._login()
                stepped = self._step_up(access)
                self.assertEqual(stepped.status_code, 200)

            with freeze_time(self.base_time + timedelta(seconds=10)):
                rotated = self._refresh(stepped.data["refresh"])
                self.assertEqual(rotated.status_code, 200)
                self.assertIn("refresh", rotated.data)

                new_access = AccessToken(rotated.data["access"])
                new_refresh = RefreshToken(rotated.data["refresh"])
                original_access = AccessToken(stepped.data["access"])
                # Rotation preserves the original proof rather than renewing it.
                self.assertEqual(
                    new_access[STEP_UP_CLAIM], original_access[STEP_UP_CLAIM]
                )
                self.assertEqual(
                    new_refresh[STEP_UP_CLAIM], original_access[STEP_UP_CLAIM]
                )


class StepUpVerificationTestCase(APIViewTestCase):
    view_name = "token_step_up"

    def setUp(self):
        self.user = User.objects.create_user(
            username="finance_user", password="test_password"
        )
        recording_verifier.reset()
        rejecting_verifier.reset()

    def _authenticate(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}"
        )

    def test_requires_authentication(self):
        res = self.view_post(data={"confirmation": "123456"})
        self.assertEqual(res.status_code, 401)
        self.assertEqual(len(recording_verifier.calls), 0)

    @override_api_settings(**STEP_UP_SETTINGS)
    def test_rejecting_verifier_denies_and_mints_no_claim(self):
        self._authenticate()
        with override_api_settings(
            STEP_UP_VERIFIER="tests.verifiers.reject_step_up"
        ):
            res = self.view_post(data={"confirmation": "000000"})

        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.data["detail"].code, "step_up_failed")
        self.assertEqual(len(rejecting_verifier.calls), 1)
        self.assertNotIn("access", res.data)

    @override_api_settings(
        STEP_UP_ENABLED=True,
        STEP_UP_VERIFIER="tests.verifiers.verify_step_up",
    )
    def test_missing_verifier_setting_fails_closed(self):
        self._authenticate()
        # Simulate a deployment that enabled step-up but never registered a
        # verifier. The endpoint must refuse rather than mint a proof.
        with override_api_settings(STEP_UP_VERIFIER=None):
            res = self.view_post(data={"confirmation": "123456"})

        self.assertEqual(res.status_code, 403)
        self.assertEqual(
            res.data["detail"].code, "step_up_verifier_not_configured"
        )
        self.assertEqual(len(recording_verifier.calls), 0)

    def test_claim_without_step_up_enabled_is_not_trusted(self):
        # A claim only has meaning when the feature is enabled and the proof
        # was issued through the registered verifier; otherwise every token is
        # treated as lacking step-up proof, even if the claim is present.
        refresh = RefreshToken.for_user(self.user)
        refresh[STEP_UP_CLAIM] = 2_000_000_000
        access = refresh.access_token
        self.assertFalse(access.has_valid_step_up())

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        res = self.client.get("/sensitive-view/")
        self.assertEqual(res.status_code, 403)


class StepUpTokenTestCase(APIViewTestCase):
    @override_api_settings(STEP_UP_ENABLED=True, STEP_UP_LIFETIME=timedelta(minutes=3))
    def test_set_and_check_step_up_claim(self):
        now = aware_utcnow().replace(microsecond=0)
        token = RefreshToken()
        self.assertFalse(token.has_valid_step_up())

        token.set_step_up(at_time=now)
        self.assertTrue(token.has_valid_step_up())
        self.assertEqual(
            token[STEP_UP_CLAIM],
            datetime_to_epoch(now + timedelta(minutes=3)),
        )

        # Expiry boundary: proof valid one second before, lapsed at the instant.
        self.assertTrue(token.has_valid_step_up(now + timedelta(minutes=2, seconds=59)))
        self.assertFalse(token.has_valid_step_up(now + timedelta(minutes=3)))
        self.assertFalse(token.has_valid_step_up(now + timedelta(minutes=4)))

    def test_step_up_disabled_by_default(self):
        token = RefreshToken()
        token.set_step_up()
        self.assertNotIn(STEP_UP_CLAIM, token.payload)
        self.assertFalse(token.has_valid_step_up())
