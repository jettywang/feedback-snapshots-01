"""Optional atomic refresh saves must not resurrect stale credentials."""

from __future__ import annotations

import io
import logging
import unittest
from typing import Any, cast
from unittest.mock import patch

from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthConfigurationError, AuthCredentialError
from social_core.storage import RefreshResult, UserMixin
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy

ACCESS_MARKER = "TEST_ACCESS_TOKEN_MARKER"
REFRESH_MARKER = "TEST_REFRESH_TOKEN_MARKER"


class RefreshRow:
    """One persisted association row shared by concurrent request contexts."""

    def __init__(self, extra_data: dict[str, Any]) -> None:
        self.extra_data = dict(extra_data)


class ScriptedRefreshBackend(BaseOAuth2[object]):
    """Fake provider returning queued refresh results and recording calls."""

    name = "scripted"

    def __init__(self, strategy) -> None:
        super().__init__(strategy)
        self.responses: list[dict[str, Any]] = []
        self.calls: list[tuple[str, tuple, dict]] = []

    def refresh_token(self, token: str, *args, **kwargs) -> dict[str, Any]:
        self.calls.append((token, args, kwargs))
        return dict(self.responses.pop(0))

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        return dict(response)


class AtomicRefreshUser(UserMixin):
    """Storage double implementing the optional compare-and-swap contract."""

    supports_atomic_refresh_save = True
    provider = "scripted"
    uid = "1"
    user = None

    def __init__(
        self,
        row: RefreshRow,
        events: list[str],
        fail_next_save: bool = False,
    ) -> None:
        self.row = row
        self.events = events
        self.extra_data = dict(row.extra_data)
        self.fail_next_save = fail_next_save
        self.on_before_save: Any = None

    def save(self) -> None:
        self.row.extra_data = dict(self.extra_data)
        self.events.append("save")

    def save_refresh_result(
        self,
        base_extra_data: dict[str, Any],
        refreshed_extra_data: dict[str, Any],
    ) -> str:
        if self.on_before_save is not None:
            hook, self.on_before_save = self.on_before_save, None
            hook()
        if self.fail_next_save:
            self.fail_next_save = False
            self.events.append("save-failed")
            raise OSError(
                f"storage unavailable: {ACCESS_MARKER} {REFRESH_MARKER}"
            )
        merged = self.merge_extra_data(base_extra_data, refreshed_extra_data)
        if self.row.extra_data != base_extra_data:
            self.events.append("superseded")
            return "superseded"
        if merged == base_extra_data:
            self.events.append("unchanged")
            return "unchanged"
        self.row.extra_data = dict(merged)
        self.extra_data = dict(merged)
        self.events.append("saved")
        return "saved"


class DefaultSaveUser(UserMixin):
    """Storage double keeping the historical unconditional save."""

    supports_atomic_refresh_save = False
    provider = "scripted"
    uid = "1"
    user = None

    def __init__(self, row: RefreshRow, events: list[str]) -> None:
        self.row = row
        self.events = events
        self.extra_data = dict(row.extra_data)
        self.fail_save = False

    def save(self) -> None:
        if self.fail_save:
            raise OSError(f"storage unavailable: {ACCESS_MARKER}")
        self.row.extra_data = dict(self.extra_data)
        self.events.append("save")


class MisconfiguredAtomicUser(UserMixin):
    """Opts into atomic saves without implementing the conditional write."""

    supports_atomic_refresh_save = True
    provider = "scripted"
    uid = "1"
    user = None

    def __init__(self, row: RefreshRow) -> None:
        self.row = row
        self.extra_data = dict(row.extra_data)

    def save(self) -> None:
        self.row.extra_data = dict(self.extra_data)


class RefreshAtomicSaveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_KEY": "key", "SOCIAL_AUTH_SECRET": "secret"}
        )
        self.baseline = {
            "access_token": "original-access",
            "refresh_token": "original-refresh",
        }

    def backend(
        self, *responses: dict[str, Any]
    ) -> ScriptedRefreshBackend:
        backend = ScriptedRefreshBackend(self.strategy)
        backend.responses = [dict(response) for response in responses]
        return backend

    def test_later_authorization_wins_when_saves_arrive_in_reverse_order(
        self,
    ) -> None:
        row = RefreshRow(self.baseline)
        events: list[str] = []
        earlier = AtomicRefreshUser(row, events)
        later = AtomicRefreshUser(row, events)
        earlier_backend = self.backend(
            {
                "access_token": "stale-access",
                "refresh_token": "stale-refresh",
            }
        )
        later_backend = self.backend(
            {
                "access_token": "new-access",
                "refresh_token": "new-refresh",
            }
        )

        def later_request_completes_first() -> None:
            with patch.object(
                later, "get_backend_instance", return_value=later_backend
            ):
                later_result = later.refresh_token(self.strategy)
            self.assertEqual(later_result.status, "saved")

        earlier.on_before_save = later_request_completes_first
        with patch.object(
            earlier, "get_backend_instance", return_value=earlier_backend
        ):
            earlier_result = earlier.refresh_token(self.strategy)

        # Both requests exchanged the same original refresh token, but the
        # newer result persisted first and the stale save was discarded.
        self.assertEqual(events, ["saved", "superseded"])
        self.assertEqual(
            row.extra_data,
            {"access_token": "new-access", "refresh_token": "new-refresh"},
        )
        self.assertEqual(earlier_result.status, "superseded")
        self.assertEqual(earlier_result.retry_operation, "none")
        self.assertFalse(earlier_result.can_retry)
        self.assertTrue(earlier_result.refresh_completed)
        self.assertEqual(
            earlier_result.refreshed_extra_data,
            {"access_token": "stale-access", "refresh_token": "stale-refresh"},
        )
        self.assertEqual(earlier.extra_data, self.baseline)
        self.assertEqual(later.extra_data, row.extra_data)
        self.assertEqual(earlier_backend.calls[0][0], "original-refresh")
        self.assertEqual(later_backend.calls[0][0], "original-refresh")

    def test_completed_refresh_with_failed_save_reports_save_retry_only(
        self,
    ) -> None:
        row = RefreshRow(self.baseline)
        events: list[str] = []
        user = AtomicRefreshUser(row, events, fail_next_save=True)
        backend = self.backend(
            {"access_token": "refreshed-access", "refresh_token": "refreshed"}
        )
        output = io.StringIO()
        logger = logging.getLogger("social")
        handler = logging.StreamHandler(output)
        previous_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.removeHandler, handler)
        self.addCleanup(logger.setLevel, previous_level)

        with patch.object(user, "get_backend_instance", return_value=backend):
            failed = user.refresh_token(self.strategy)

        self.assertEqual(failed.status, "save_failed")
        self.assertEqual(failed.retry_operation, "save")
        self.assertTrue(failed.can_retry)
        self.assertTrue(failed.refresh_completed)
        self.assertIsInstance(failed.error, OSError)
        self.assertEqual(row.extra_data, self.baseline)
        self.assertEqual(user.extra_data, self.baseline)
        self.assertEqual(len(backend.calls), 1)
        logged = output.getvalue()
        self.assertIn("credential save failed", logged)
        self.assertIn("scripted", logged)
        self.assertNotIn(ACCESS_MARKER, logged)
        self.assertNotIn(REFRESH_MARKER, logged)

        # Only the save is retried; the provider exchange is not repeated.
        retried = user.retry_refresh_save(failed)
        self.assertEqual(retried.status, "saved")
        self.assertEqual(retried.retry_operation, "none")
        self.assertFalse(retried.can_retry)
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(
            row.extra_data,
            {"access_token": "refreshed-access", "refresh_token": "refreshed"},
        )

    def test_retry_is_rejected_for_every_other_status(self) -> None:
        row = RefreshRow(self.baseline)
        events: list[str] = []
        user = AtomicRefreshUser(row, events)
        for status in ("saved", "unchanged", "superseded", "skipped"):
            with self.subTest(status=status):
                result = RefreshResult(status=cast("Any", status))
                self.assertIs(user.retry_refresh_save(result), result)
        self.assertEqual(events, [])
        self.assertEqual(row.extra_data, self.baseline)

    def test_expired_access_token_fails_closed_after_save_failure(self) -> None:
        row = RefreshRow({**self.baseline, "expires_on": 1})
        user = AtomicRefreshUser(row, [], fail_next_save=True)
        backend = self.backend(
            {"access_token": "refreshed-access", "refresh_token": "refreshed"}
        )
        with (
            patch.object(user, "get_backend_instance", return_value=backend),
            self.assertRaises(AuthCredentialError) as caught,
        ):
            user.get_access_token(self.strategy)
        error = caught.exception
        self.assertEqual(error.code, "refresh_save_failed")
        self.assertEqual(error.source, "storage")
        self.assertEqual(error.stage, "refresh")
        self.assertEqual(error.recovery, "retry_later")
        self.assertEqual(error.context, {"retry_operation": "save"})
        self.assertNotIn(ACCESS_MARKER, str(error))
        self.assertNotIn(REFRESH_MARKER, str(error))
        self.assertEqual(row.extra_data, {**self.baseline, "expires_on": 1})

    def test_atomic_opt_in_requires_a_conditional_write(self) -> None:
        row = RefreshRow(self.baseline)
        user = MisconfiguredAtomicUser(row)
        backend = self.backend({"access_token": "ignored"})
        with (
            patch.object(user, "get_backend_instance", return_value=backend),
            self.assertRaises(AuthConfigurationError) as caught,
        ):
            user.refresh_token(self.strategy)
        self.assertEqual(caught.exception.code, "invalid_setting")
        self.assertEqual(caught.exception.parameter, "save_refresh_result")
        self.assertEqual(caught.exception.stage, "refresh")
        self.assertEqual(backend.calls, [])
        self.assertEqual(row.extra_data, self.baseline)

    def test_default_storage_keeps_unconditional_save(self) -> None:
        row = RefreshRow(self.baseline)
        events: list[str] = []
        user = DefaultSaveUser(row, events)
        backend = self.backend(
            {"access_token": "new-access", "refresh_token": "new-refresh"}
        )
        with patch.object(user, "get_backend_instance", return_value=backend):
            result = user.refresh_token(self.strategy)
        self.assertEqual(result.status, "saved")
        self.assertFalse(result.can_retry)
        self.assertEqual(events, ["save"])
        self.assertEqual(
            row.extra_data,
            {"access_token": "new-access", "refresh_token": "new-refresh"},
        )

        # An unchanged payload neither writes nor claims a new result.
        events.clear()
        backend.responses = [dict(self.baseline)]
        row.extra_data = dict(self.baseline)
        user.extra_data = dict(self.baseline)
        with patch.object(user, "get_backend_instance", return_value=backend):
            result = user.refresh_token(self.strategy)
        self.assertEqual(result.status, "unchanged")
        self.assertEqual(events, [])

    def test_default_storage_propagates_save_errors(self) -> None:
        row = RefreshRow(self.baseline)
        events: list[str] = []
        user = DefaultSaveUser(row, events)
        user.fail_save = True
        backend = self.backend(
            {"access_token": "new-access", "refresh_token": "new-refresh"}
        )
        with (
            patch.object(user, "get_backend_instance", return_value=backend),
            self.assertRaises(OSError) as caught,
        ):
            user.refresh_token(self.strategy)
        self.assertIn(ACCESS_MARKER, str(caught.exception))
        self.assertEqual(row.extra_data, self.baseline)

    def test_unchanged_atomic_result_does_not_write(self) -> None:
        row = RefreshRow(self.baseline)
        events: list[str] = []
        user = AtomicRefreshUser(row, events)
        backend = self.backend(dict(self.baseline))
        with patch.object(user, "get_backend_instance", return_value=backend):
            result = user.refresh_token(self.strategy)
        self.assertEqual(result.status, "unchanged")
        self.assertFalse(result.can_retry)
        self.assertEqual(events, ["unchanged"])
        self.assertEqual(row.extra_data, self.baseline)

    def test_retry_after_newer_authorization_is_superseded(self) -> None:
        row = RefreshRow(self.baseline)
        user = AtomicRefreshUser(row, [], fail_next_save=True)
        backend = self.backend(
            {"access_token": "failed-access", "refresh_token": "failed-refresh"}
        )
        with patch.object(user, "get_backend_instance", return_value=backend):
            failed = user.refresh_token(self.strategy)
        self.assertEqual(failed.status, "save_failed")

        # A later authorized request persists a newer state before the save
        # retry runs, so the retry must not overwrite it.
        row.extra_data = {
            "access_token": "newest-access",
            "refresh_token": "newest-refresh",
        }
        retried = user.retry_refresh_save(failed)
        self.assertEqual(retried.status, "superseded")
        self.assertEqual(retried.retry_operation, "none")
        self.assertEqual(
            row.extra_data,
            {"access_token": "newest-access", "refresh_token": "newest-refresh"},
        )
        self.assertEqual(len(backend.calls), 1)

    def test_result_repr_does_not_render_credentials(self) -> None:
        row = RefreshRow(self.baseline)
        user = AtomicRefreshUser(row, [])
        backend = self.backend(
            {"access_token": ACCESS_MARKER, "refresh_token": REFRESH_MARKER}
        )
        with patch.object(user, "get_backend_instance", return_value=backend):
            result = user.refresh_token(self.strategy)
        self.assertNotIn(ACCESS_MARKER, repr(result))
        self.assertNotIn(REFRESH_MARKER, repr(result))
        self.assertNotIn(ACCESS_MARKER, repr(result.error))
