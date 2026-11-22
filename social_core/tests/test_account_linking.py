from __future__ import annotations

import json

import responses

from social_core.exceptions import (
    AuthAssociationError,
    AuthInputError,
    AuthSessionError,
)
from social_core.linking import confirm_account_link, suggest_account_link
from social_core.tests.exception_helpers import assert_auth_error
from social_core.tests.models import AnonymousUser, TestUserSocialAuth, User

from .actions.actions import BaseActionTest

PROVIDER = "github"
SHARED_EMAIL = "foo@bar.com"
UNBOUND_UID = "999"


class AccountLinkingWorkflowTest(BaseActionTest):
    """Two provider logins plus one email-only account sharing one address."""

    alternative_user_data_body = json.dumps(
        {
            "login": "foobar2",
            "id": 2,
            "avatar_url": "https://github.com/images/error/foobar2_happy.gif",
            "gravatar_id": "somehexcode",
            "url": "https://api.github.com/users/foobar2",
            "name": "monalisa foobar2",
            "company": "GitHub",
            "blog": "https://github.com/blog",
            "location": "San Francisco",
            "email": SHARED_EMAIL,
            "hireable": False,
            "bio": "There once was...",
            "public_repos": 2,
            "public_gists": 1,
            "followers": 20,
            "following": 0,
            "html_url": "https://github.com/foobar2",
            "created_at": "2008-01-14T04:33:35Z",
            "type": "User",
            "total_private_repos": 100,
            "owned_private_repos": 100,
            "private_gists": 81,
            "disk_usage": 10000,
            "collaborators": 8,
            "plan": {
                "name": "Medium",
                "space": 400,
                "collaborators": 10,
                "private_repos": 20,
            },
        }
    )

    def setUp(self) -> None:
        super().setUp()
        # Two distinct local users may share an email, so the opt-in email
        # auto-association step must not collapse the logins into one account.
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE": (
                    "social_core.pipeline.social_auth.social_details",
                    "social_core.pipeline.social_auth.social_names",
                    "social_core.pipeline.social_auth.social_uid",
                    "social_core.pipeline.social_auth.auth_allowed",
                    "social_core.pipeline.social_auth.social_user",
                    "social_core.pipeline.user.get_username",
                    "social_core.pipeline.user.create_user",
                    "social_core.pipeline.social_auth.associate_user",
                    "social_core.pipeline.social_auth.load_extra_data",
                    "social_core.pipeline.user.user_details",
                )
            }
        )
        # Two test accounts, each established through a real (mocked) provider
        # login, with distinct provider uids but the same email address.
        self.do_login()
        # Clear the first login's mocked user-data response so the second
        # login receives its own identity instead of the cached fixture.
        responses.reset()
        self.do_login(
            user_data_body=self.alternative_user_data_body,
            expected_username="foobar2",
        )
        self.primary = User.get("foobar")
        self.secondary = User.get("foobar2")
        # Third account: same email, no third-party login at all.
        self.email_only = User(username="emailonly", email=SHARED_EMAIL)

    def _social_count(self) -> int:
        return len(TestUserSocialAuth.cache_by_uid)

    def test_suggest_is_read_only_and_reports_shared_evidence(self) -> None:
        before = self._social_count()
        suggestion = suggest_account_link(
            self.backend,
            self.primary,
            PROVIDER,
            UNBOUND_UID,
            email=SHARED_EMAIL,
        )

        self.assertTrue(suggestion.linkable)
        self.assertIsNone(suggestion.conflict)
        self.assertEqual(
            set(suggestion.matching_users),
            {self.primary, self.secondary, self.email_only},
        )
        # The suggestion phase must not write any association.
        self.assertEqual(self._social_count(), before)
        self.assertIsNone(TestUserSocialAuth.cache_by_uid.get((PROVIDER, UNBOUND_UID)))

    def test_accept_creates_association_on_the_logged_in_primary(self) -> None:
        suggest_account_link(
            self.backend, self.primary, PROVIDER, UNBOUND_UID, email=SHARED_EMAIL
        )
        before = self._social_count()

        result = confirm_account_link(
            self.backend,
            self.primary,
            self.secondary,
            PROVIDER,
            UNBOUND_UID,
            "accept",
            email=SHARED_EMAIL,
        )

        self.assertTrue(result.accepted)
        self.assertEqual(result.reason, "linked")
        stored = TestUserSocialAuth.cache_by_uid[(PROVIDER, UNBOUND_UID)]
        # The write corresponds to the two actually authenticated accounts:
        # the new association belongs to the logged-in primary, no one else.
        self.assertIs(stored.user, self.primary)
        self.assertIn(stored, self.primary.social)
        self.assertNotIn(stored, self.secondary.social)
        self.assertNotIn(stored, self.email_only.social)
        self.assertEqual(self._social_count(), before + 1)

    def test_confirmation_follows_the_actual_primary_login(self) -> None:
        # Switching which authenticated user is presented as primary moves the
        # write with it: request data cannot target an arbitrary account.
        result = confirm_account_link(
            self.backend,
            self.secondary,
            self.primary,
            PROVIDER,
            UNBOUND_UID,
            "accept",
            email=SHARED_EMAIL,
        )

        stored = TestUserSocialAuth.cache_by_uid[(PROVIDER, UNBOUND_UID)]
        self.assertIs(result.social_auth, stored)
        self.assertIs(stored.user, self.secondary)

    def test_reject_writes_nothing(self) -> None:
        before = self._social_count()

        result = confirm_account_link(
            self.backend,
            self.primary,
            self.secondary,
            PROVIDER,
            UNBOUND_UID,
            "reject",
            email=SHARED_EMAIL,
        )

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "rejected")
        self.assertIsNone(result.social_auth)
        self.assertEqual(self._social_count(), before)
        self.assertIsNone(TestUserSocialAuth.cache_by_uid.get((PROVIDER, UNBOUND_UID)))

    def test_historical_association_conflict_blocks_linking(self) -> None:
        # The identity was historically bound to the email-only account.
        historical = TestUserSocialAuth(self.email_only, PROVIDER, UNBOUND_UID)
        before = self._social_count()

        suggestion = suggest_account_link(
            self.backend,
            self.primary,
            PROVIDER,
            UNBOUND_UID,
            email=SHARED_EMAIL,
        )
        self.assertFalse(suggestion.linkable)
        self.assertIs(suggestion.conflict.social_auth, historical)
        self.assertEqual(self._social_count(), before)

        # Even with both test accounts logged in, confirmation must fail
        # closed rather than move or duplicate the existing association.
        with assert_auth_error(self, AuthAssociationError, "identity_in_use"):
            confirm_account_link(
                self.backend,
                self.primary,
                self.secondary,
                PROVIDER,
                UNBOUND_UID,
                "accept",
                email=SHARED_EMAIL,
            )
        self.assertIs(
            TestUserSocialAuth.cache_by_uid[(PROVIDER, UNBOUND_UID)],
            historical,
        )
        self.assertEqual(historical.user, self.email_only)
        self.assertEqual(self._social_count(), before)

    def test_duplicate_submission_is_idempotent(self) -> None:
        first = confirm_account_link(
            self.backend,
            self.primary,
            self.secondary,
            PROVIDER,
            UNBOUND_UID,
            "accept",
            email=SHARED_EMAIL,
        )
        self.assertEqual(first.reason, "linked")
        before = self._social_count()

        second = confirm_account_link(
            self.backend,
            self.primary,
            self.secondary,
            PROVIDER,
            UNBOUND_UID,
            "accept",
            email=SHARED_EMAIL,
        )

        self.assertTrue(second.accepted)
        self.assertEqual(second.reason, "already_linked")
        self.assertIs(second.social_auth, first.social_auth)
        self.assertEqual(self._social_count(), before)

    def test_confirm_requires_both_sides_logged_in(self) -> None:
        with assert_auth_error(self, AuthSessionError, "session_context_missing"):
            confirm_account_link(
                self.backend,
                AnonymousUser(),
                self.secondary,
                PROVIDER,
                UNBOUND_UID,
                "accept",
            )
        with assert_auth_error(self, AuthSessionError, "session_context_missing"):
            confirm_account_link(
                self.backend,
                self.primary,
                AnonymousUser(),
                PROVIDER,
                UNBOUND_UID,
                "accept",
            )
        self.assertIsNone(TestUserSocialAuth.cache_by_uid.get((PROVIDER, UNBOUND_UID)))

    def test_linking_an_account_to_itself_is_rejected(self) -> None:
        with assert_auth_error(self, AuthAssociationError, "link_not_authorized"):
            confirm_account_link(
                self.backend,
                self.primary,
                self.primary,
                PROVIDER,
                UNBOUND_UID,
                "accept",
                email=SHARED_EMAIL,
            )

    def test_email_evidence_mismatch_fails_closed(self) -> None:
        with assert_auth_error(self, AuthAssociationError, "link_not_authorized"):
            suggest_account_link(
                self.backend,
                self.primary,
                PROVIDER,
                UNBOUND_UID,
                email="someone-else@example.com",
            )

        other_email_user = User(username="mallory", email="mallory@example.com")
        with assert_auth_error(self, AuthAssociationError, "link_not_authorized"):
            confirm_account_link(
                self.backend,
                self.primary,
                other_email_user,
                PROVIDER,
                UNBOUND_UID,
                "accept",
                email=SHARED_EMAIL,
            )
        self.assertIsNone(TestUserSocialAuth.cache_by_uid.get((PROVIDER, UNBOUND_UID)))

    def test_invalid_decision_is_rejected(self) -> None:
        with assert_auth_error(self, AuthInputError, "invalid_parameter"):
            confirm_account_link(
                self.backend,
                self.primary,
                self.secondary,
                PROVIDER,
                UNBOUND_UID,
                "maybe",  # type: ignore[arg-type]
            )

    def test_inactive_account_cannot_confirm(self) -> None:
        User.set_active(False)
        try:
            with assert_auth_error(self, AuthAssociationError, "link_not_authorized"):
                confirm_account_link(
                    self.backend,
                    self.primary,
                    self.secondary,
                    PROVIDER,
                    UNBOUND_UID,
                    "accept",
                    email=SHARED_EMAIL,
                )
        finally:
            User.set_active(True)
        self.assertIsNone(TestUserSocialAuth.cache_by_uid.get((PROVIDER, UNBOUND_UID)))
