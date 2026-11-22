"""Profile synchronization contracts for a newly integrated identity provider."""

from __future__ import annotations

import unittest
from typing import Any, cast

from social_core.backends.base import BaseAuth
from social_core.pipeline.user import create_user, user_details
from social_core.storage import UserMixin
from social_core.tests.models import TestStorage, TestUserSocialAuth, User
from social_core.tests.strategy import TestStrategy

ADMIN_EMAIL = "admin@example.com"
ADMIN_DISPLAY_NAME = "Admin Chosen Display"
OLD_AVATAR = "https://cdn.example/old.png"
NEW_AVATAR = "https://cdn.example/new.png"
NEW_WEBSITE = "https://ada.dev"
WEBSITE = "https://ada.example"


class ProfileUser(User):
    """Local user with non-sensitive profile fields a provider may synchronize."""

    fullname: str | None = None
    avatar_url: str | None = None
    website: str | None = None

    def __init__(
        self, username: str, email: str | None = None, **extra_user_fields: Any
    ) -> None:
        super().__init__(username, email, **extra_user_fields)
        for name, value in extra_user_fields.items():
            setattr(self, name, value)


class RecordingUserStorage(TestUserSocialAuth):
    """Record exactly the fields the pipeline asks storage to create or save."""

    created_fields: list[dict[str, Any]] = []
    changed_field_sets: list[set[str]] = []

    @classmethod
    def reset_events(cls) -> None:
        cls.created_fields = []
        cls.changed_field_sets = []

    @classmethod
    def user_model(cls) -> type[User]:
        return ProfileUser

    @classmethod
    def create_user(cls, username, email=None, **extra_user_fields):
        fields = {"username": username, "email": email, **extra_user_fields}
        cls.created_fields.append(fields)
        return ProfileUser(**fields)

    @classmethod
    def changed_fields(cls, user, fields) -> None:
        cls.changed_field_sets.append(set(fields))
        super().changed_fields(user, fields)


class ProfileStorage(TestStorage):
    user: type[UserMixin] = RecordingUserStorage


class ProfileSyncStrategy(TestStrategy):
    """Fake strategy backed by storage that records persisted field sets."""

    def __init__(self, settings: dict[str, Any]) -> None:
        super().__init__(ProfileStorage)
        self.set_settings(settings)


class ProfileProvider(BaseAuth):
    name = "profile"


class ProfileSyncTest(unittest.TestCase):
    settings = {
        "SOCIAL_AUTH_USER_FIELDS": [
            "username",
            "email",
            "fullname",
            "avatar_url",
            "website",
        ],
        # Site administrators pin the display name and email locally while
        # non-sensitive profile fields remain provider-managed.
        "SOCIAL_AUTH_PROTECTED_USER_FIELDS": ["fullname", "email"],
    }

    def setUp(self) -> None:
        User.reset_cache()
        RecordingUserStorage.reset_events()
        self.addCleanup(User.reset_cache)
        self.strategy = ProfileSyncStrategy(self.settings)
        self.backend = ProfileProvider(self.strategy)

    @staticmethod
    def first_login_details(**overrides: Any) -> dict[str, Any]:
        details = {
            "username": "ada",
            "email": "ada@example.com",
            "avatar_url": NEW_AVATAR,
            "website": WEBSITE,
        }
        details.update(overrides)
        return details

    @staticmethod
    def existing_user() -> ProfileUser:
        user = ProfileUser("local-ada", email=ADMIN_EMAIL)
        user.fullname = ADMIN_DISPLAY_NAME
        user.avatar_url = OLD_AVATAR
        user.website = WEBSITE
        return user

    def test_first_login_fills_required_and_provider_profile_fields(self) -> None:
        details = self.first_login_details(fullname="Ada Lovelace")

        result = create_user(self.strategy, details, self.backend)

        self.assertIs(result["is_new"], True)
        self.assertEqual(RecordingUserStorage.created_fields, [details])
        user = cast("ProfileUser", result["user"])
        self.assertEqual(
            (user.username, user.email, user.fullname, user.avatar_url, user.website),
            ("ada", "ada@example.com", "Ada Lovelace", NEW_AVATAR, WEBSITE),
        )

    def test_minimal_first_login_still_saves_required_fields(self) -> None:
        result = create_user(
            self.strategy,
            {"username": "ada", "email": "ada@example.com"},
            self.backend,
        )

        self.assertIs(result["is_new"], True)
        self.assertEqual(
            RecordingUserStorage.created_fields,
            [
                {
                    "username": "ada",
                    "email": "ada@example.com",
                    "avatar_url": None,
                    "website": None,
                }
            ],
        )
        user = cast("ProfileUser", result["user"])
        self.assertEqual((user.username, user.email), ("ada", "ada@example.com"))
        self.assertIsNone(user.avatar_url)
        self.assertIsNone(user.website)

    def test_first_login_omitted_none_and_empty_values_save_differently(self) -> None:
        cases: tuple[tuple[str, dict[str, Any], dict[str, Any]], ...] = (
            (
                "omitted",
                {},
                {
                    "username": "ada",
                    "email": "ada@example.com",
                    "avatar_url": NEW_AVATAR,
                    "website": WEBSITE,
                },
            ),
            (
                "none",
                {"fullname": None, "avatar_url": None},
                {
                    "username": "ada",
                    "email": "ada@example.com",
                    "avatar_url": None,
                    "website": WEBSITE,
                },
            ),
            (
                "empty",
                {"fullname": "", "avatar_url": ""},
                {
                    "username": "ada",
                    "email": "ada@example.com",
                    "fullname": "",
                    "avatar_url": "",
                    "website": WEBSITE,
                },
            ),
        )
        for name, overrides, expected in cases:
            with self.subTest(name=name):
                RecordingUserStorage.reset_events()

                create_user(
                    self.strategy,
                    self.first_login_details(**overrides),
                    self.backend,
                )

                self.assertEqual(RecordingUserStorage.created_fields, [expected])

    def test_existing_account_keeps_pinned_profile_and_syncs_avatar(self) -> None:
        user = self.existing_user()

        user_details(
            self.strategy,
            {
                "username": "provider-ada",
                "email": "provider@example.com",
                "fullname": "Provider Display",
                "avatar_url": NEW_AVATAR,
                "website": WEBSITE,
            },
            self.backend,
            user,
        )

        self.assertEqual(RecordingUserStorage.changed_field_sets, [{"avatar_url"}])
        self.assertEqual(user.username, "local-ada")
        self.assertEqual(user.email, ADMIN_EMAIL)
        self.assertEqual(user.fullname, ADMIN_DISPLAY_NAME)
        self.assertEqual(user.avatar_url, NEW_AVATAR)
        self.assertEqual(user.website, WEBSITE)

    def test_existing_account_syncs_all_allowed_non_sensitive_fields(self) -> None:
        user = self.existing_user()

        user_details(
            self.strategy,
            {"avatar_url": NEW_AVATAR, "website": NEW_WEBSITE},
            self.backend,
            user,
        )

        self.assertEqual(
            RecordingUserStorage.changed_field_sets, [{"avatar_url", "website"}]
        )
        self.assertEqual(user.avatar_url, NEW_AVATAR)
        self.assertEqual(user.website, NEW_WEBSITE)
        self.assertEqual(user.email, ADMIN_EMAIL)
        self.assertEqual(user.fullname, ADMIN_DISPLAY_NAME)

    def test_provider_value_states_have_distinct_persisted_results(self) -> None:
        cases: tuple[tuple[str, dict[str, Any], list[set[str]], str], ...] = (
            ("omitted", {}, [], OLD_AVATAR),
            ("none", {"avatar_url": None}, [], OLD_AVATAR),
            ("empty", {"avatar_url": ""}, [{"avatar_url"}], ""),
            ("reconfirmed", {"avatar_url": OLD_AVATAR}, [], OLD_AVATAR),
        )
        for name, details, expected_saves, expected_avatar in cases:
            with self.subTest(name=name):
                RecordingUserStorage.reset_events()
                user = self.existing_user()

                user_details(self.strategy, details, self.backend, user)

                self.assertEqual(
                    RecordingUserStorage.changed_field_sets, expected_saves
                )
                self.assertEqual(user.avatar_url, expected_avatar)

    def test_reconfirmed_value_is_not_saved_twice(self) -> None:
        user = self.existing_user()

        user_details(self.strategy, {"avatar_url": NEW_AVATAR}, self.backend, user)
        user_details(self.strategy, {"avatar_url": NEW_AVATAR}, self.backend, user)

        self.assertEqual(RecordingUserStorage.changed_field_sets, [{"avatar_url"}])
        self.assertEqual(user.avatar_url, NEW_AVATAR)

    def test_repeated_empty_value_is_only_saved_when_it_changes(self) -> None:
        user = self.existing_user()

        user_details(self.strategy, {"avatar_url": ""}, self.backend, user)
        user_details(self.strategy, {"avatar_url": ""}, self.backend, user)

        self.assertEqual(RecordingUserStorage.changed_field_sets, [{"avatar_url"}])
        self.assertEqual(user.avatar_url, "")

    def test_pinned_fields_ignore_provider_omission_and_empty_values(self) -> None:
        cases: tuple[tuple[str, dict[str, Any]], ...] = (
            ("omitted", {}),
            ("none", {"fullname": None, "email": None}),
            ("empty", {"fullname": "", "email": ""}),
            ("different", {"fullname": "Provider Display", "email": "p@example.com"}),
        )
        for name, details in cases:
            with self.subTest(name=name):
                RecordingUserStorage.reset_events()
                user = self.existing_user()

                user_details(self.strategy, details, self.backend, user)

                self.assertEqual(RecordingUserStorage.changed_field_sets, [])
                self.assertEqual(user.fullname, ADMIN_DISPLAY_NAME)
                self.assertEqual(user.email, ADMIN_EMAIL)

    def test_provider_cannot_replace_pinned_identity_with_empty_values(self) -> None:
        user = self.existing_user()

        user_details(
            self.strategy,
            {
                "username": "provider-ada",
                "email": "",
                "fullname": "",
                "avatar_url": NEW_AVATAR,
            },
            self.backend,
            user,
        )

        self.assertEqual(RecordingUserStorage.changed_field_sets, [{"avatar_url"}])
        self.assertEqual(user.username, "local-ada")
        self.assertEqual(user.email, ADMIN_EMAIL)
        self.assertEqual(user.fullname, ADMIN_DISPLAY_NAME)
