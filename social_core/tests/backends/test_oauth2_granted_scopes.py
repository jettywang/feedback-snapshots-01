"""Incremental authorization: confirmed OAuth2 scopes must be preserved.

A site can let users sign in with basic scopes and ask for broader grants
(such as calendar access) later. The fake provider below answers the token
exchange in three ways: explicitly granting everything requested, explicitly
granting only the basic scopes, or not listing granted scopes at all.
"""

import json

from social_core.backends.oauth import BaseOAuth2
from social_core.tests.models import User

from .oauth import OAuth2Test

BASIC_SCOPES = ["openid", "profile"]
CALENDAR_SCOPE = "calendar"


class FakeCalendarOAuth2(BaseOAuth2):
    """Fake OAuth2 provider with a basic login scope set and a calendar scope."""

    name = "fake-calendar"
    AUTHORIZATION_URL = "https://fake.example.com/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://fake.example.com/oauth2/token"
    DEFAULT_SCOPE = BASIC_SCOPES

    def get_user_details(self, response):
        return {"username": response.get("username")}

    def user_data(self, access_token, *args, **kwargs):
        return {"id": "fake-user-1", "username": "foobar"}


def calendar_action(social) -> bool:
    """Business gate: the calendar feature requires the calendar grant."""
    return social.has_granted_scope(CALENDAR_SCOPE)


def token_response(access_token: str, granted_scope: str | None) -> str:
    payload = {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": f"refresh-{access_token}",
        "expires_in": 3600,
    }
    if granted_scope is not None:
        payload["scope"] = granted_scope
    return json.dumps(payload)


FULL_GRANT = "openid profile calendar"
BASIC_GRANT = "openid profile"


class FakeCalendarOAuth2Test(OAuth2Test):
    backend_path = (
        "social_core.tests.backends.test_oauth2_granted_scopes.FakeCalendarOAuth2"
    )
    expected_username = "foobar"

    def extra_settings(self):
        settings = super().extra_settings()
        # Site policy: regular login credentials are stored as usual.
        settings[f"SOCIAL_AUTH_{self.name}_EXTRA_DATA"] = [
            "refresh_token",
            "expires_in",
        ]
        return settings

    def complete_flow(self, access_token: str, granted_scope: str | None):
        self.access_token_body = token_response(access_token, granted_scope)
        self.do_start()
        user = next(iter(User.cache.values()))
        return user.social[0]

    def request_calendar_scope(self) -> None:
        self.strategy.set_settings({f"SOCIAL_AUTH_{self.name}_SCOPE": [CALENDAR_SCOPE]})

    def test_basic_login_records_only_confirmed_basic_scopes(self) -> None:
        social = self.complete_flow("token-basic", BASIC_GRANT)
        self.assertEqual(social.get_granted_scopes(), BASIC_SCOPES)
        self.assertEqual(social.extra_data["granted_scopes"], sorted(BASIC_SCOPES))
        self.assertFalse(calendar_action(social))
        # Regular login credentials follow the site policy as usual.
        self.assertEqual(social.extra_data["access_token"], "token-basic")
        self.assertEqual(social.extra_data["refresh_token"], "refresh-token-basic")

    def test_full_acceptance_allows_calendar_action(self) -> None:
        self.request_calendar_scope()
        social = self.complete_flow("token-full", FULL_GRANT)
        self.assertEqual(
            social.get_granted_scopes(), sorted([*BASIC_SCOPES, CALENDAR_SCOPE])
        )
        self.assertTrue(calendar_action(social))

    def test_unlisted_scope_records_nothing_requested(self) -> None:
        # The provider did not list grants: requested scopes must not be
        # assumed confirmed, so the calendar action stays unavailable.
        self.request_calendar_scope()
        social = self.complete_flow("token-unlisted", None)
        self.assertEqual(social.get_granted_scopes(), [])
        self.assertNotIn("granted_scopes", social.extra_data)
        self.assertFalse(calendar_action(social))
        self.assertEqual(social.extra_data["access_token"], "token-unlisted")

    def test_incremental_calendar_authorization_after_basic_login(self) -> None:
        social = self.complete_flow("token-basic", BASIC_GRANT)
        self.assertFalse(calendar_action(social))

        self.request_calendar_scope()
        social = self.complete_flow("token-calendar", FULL_GRANT)
        self.assertEqual(
            social.get_granted_scopes(), sorted([*BASIC_SCOPES, CALENDAR_SCOPE])
        )
        self.assertTrue(calendar_action(social))
        # The newer login credentials replace the old ones per site policy.
        self.assertEqual(social.extra_data["access_token"], "token-calendar")
        self.assertEqual(social.extra_data["refresh_token"], "refresh-token-calendar")

    def test_reconfirmation_without_scope_list_preserves_grants(self) -> None:
        self.request_calendar_scope()
        social = self.complete_flow("token-full", FULL_GRANT)
        granted_before = social.get_granted_scopes()

        # A later login requests even more, but the provider lists nothing:
        # previously confirmed grants stay, nothing new is recorded.
        self.strategy.set_settings(
            {f"SOCIAL_AUTH_{self.name}_SCOPE": [CALENDAR_SCOPE, "email"]}
        )
        social = self.complete_flow("token-relogin", None)
        self.assertEqual(social.get_granted_scopes(), granted_before)
        self.assertNotIn("email", social.get_granted_scopes())
        self.assertTrue(calendar_action(social))
        self.assertEqual(social.extra_data["access_token"], "token-relogin")

    def test_narrower_reconfirmation_preserves_without_expanding(self) -> None:
        self.request_calendar_scope()
        social = self.complete_flow("token-full", FULL_GRANT)

        # The provider explicitly confirms only basic scopes on re-login:
        # the earlier calendar grant is preserved and nothing is added.
        social = self.complete_flow("token-basic-again", BASIC_GRANT)
        self.assertEqual(
            social.get_granted_scopes(), sorted([*BASIC_SCOPES, CALENDAR_SCOPE])
        )
        self.assertTrue(calendar_action(social))

        # Repeating the full confirmation keeps the exact same stored set.
        social = self.complete_flow("token-full-again", FULL_GRANT)
        self.assertEqual(
            social.extra_data["granted_scopes"],
            sorted([*BASIC_SCOPES, CALENDAR_SCOPE]),
        )

    def test_refresh_token_response_scopes_merge_with_stored_grants(self) -> None:
        self.request_calendar_scope()
        social = self.complete_flow("token-full", FULL_GRANT)

        self.refresh_token_body = token_response("token-refreshed", BASIC_GRANT)
        self.do_refresh_token()
        user = next(iter(User.cache.values()))
        social = user.social[0]
        self.assertEqual(
            social.get_granted_scopes(), sorted([*BASIC_SCOPES, CALENDAR_SCOPE])
        )
        self.assertTrue(calendar_action(social))
        self.assertEqual(social.extra_data["access_token"], "token-refreshed")
