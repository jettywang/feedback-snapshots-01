"""Staged login authorization evidence for integration diagnostics."""

from __future__ import annotations

import json
from typing import cast

from social_core.exceptions import (
    AuthAssociationError,
    AuthPolicyError,
    AuthResponseError,
)
from social_core.login_evidence import LoginEvidence
from social_core.tests.models import TestStorage, TestUserSocialAuth, User
from social_core.tests.strategy import TestStrategy

from .actions.actions import BaseActionTest


class RecordingStrategy(TestStrategy):
    __test__ = False

    def __init__(self, storage, tpl=None) -> None:
        self.login_evidence: list[LoginEvidence] = []
        self.fail_recording = False
        super().__init__(storage, tpl)

    def record_login_evidence(self, evidence: LoginEvidence) -> None:
        self.login_evidence.append(evidence)
        if self.fail_recording:
            raise RuntimeError("recorder backend unavailable: private detail")


class LoginEvidenceTest(BaseActionTest):
    def setUp(self) -> None:
        self.strategy = RecordingStrategy(TestStorage)
        super().setUp()

    def recorder(self) -> RecordingStrategy:
        return cast("RecordingStrategy", self.strategy)

    def records(self) -> list[LoginEvidence]:
        return self.recorder().login_evidence

    def stages(self) -> list[tuple[str, str, str]]:
        return [(r.stage, r.decision, r.reason) for r in self.records()]

    def assert_no_sensitive_values(self) -> None:
        for record in self.records():
            self.assertEqual(
                set(record.as_dict()),
                {
                    "provider",
                    "pipeline",
                    "pipeline_version",
                    "stage",
                    "decision",
                    "reason",
                    "actor",
                    "association",
                    "association_only",
                    "initiator",
                },
            )
        serialized = json.dumps([r.as_dict() for r in self.records()])
        for sensitive in (
            "foobar",
            "foo@bar.com",
            "a-key",
            "a-secret-key",
            "access_token",
            "refresh_token",
            "monalisa",
        ):
            self.assertNotIn(sensitive, serialized)

    def test_login_only_records_each_allowed_stage(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE_NAME": "primary-login",
                "SOCIAL_AUTH_PIPELINE_VERSION": "2026-11-a",
            }
        )

        self.do_login()

        self.assertEqual(
            self.stages(),
            [
                ("identity", "allowed", "identifier_resolved"),
                ("policy", "allowed", "authentication_allowed"),
                ("association", "allowed", "association_missing"),
                ("association", "allowed", "association_created"),
                ("login", "allowed", "new_user_login"),
            ],
        )
        for record in self.records():
            self.assertEqual(record.provider, "github")
            self.assertEqual(record.pipeline, "primary-login")
            self.assertEqual(record.pipeline_version, "2026-11-a")
            self.assertTrue(record.actor.startswith("social_core."))
            self.assertFalse(record.association_only)
            self.assertEqual(record.initiator, "anonymous")
        self.assertEqual(self.records()[2].association, "none")
        self.assertEqual(self.records()[3].association, "created")
        self.assertEqual(self.records()[4].association, "created")
        self.assert_no_sensitive_values()

    def test_existing_authenticated_user_records_created_association(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_PIPELINE_NAME": "link-login"})
        self.user = cast("object", TestStorage.user.create_user("foobar"))

        self.do_login()

        self.assertEqual(
            self.stages(),
            [
                ("identity", "allowed", "identifier_resolved"),
                ("policy", "allowed", "authentication_allowed"),
                ("association", "allowed", "association_missing"),
                ("association", "allowed", "association_created"),
                ("login", "allowed", "association_only"),
            ],
        )
        self.assertEqual(self.records()[0].initiator, "authenticated")
        self.assertEqual(self.records()[3].association, "created")
        self.assertEqual(self.records()[4].association, "created")
        self.login.assert_not_called()
        self.assert_no_sensitive_values()

    def test_existing_association_records_no_new_binding(self) -> None:
        self.do_login()
        self.recorder().login_evidence.clear()

        self.do_login()

        self.assertEqual(
            [(r.stage, r.reason, r.association) for r in self.records()],
            [
                ("identity", "identifier_resolved", "none"),
                ("policy", "authentication_allowed", "none"),
                ("association", "association_found", "existing"),
                ("login", "existing_user_login", "existing"),
            ],
        )
        self.assert_no_sensitive_values()

    def test_identity_rejection_records_denial_before_policy(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_PIPELINE_NAME": "strict-login"})
        self.user_data_body = json.dumps({"username": "foobar", "email": "foo@bar.com"})

        with self.assertRaises(AuthResponseError) as caught:
            self.do_login()

        self.assertEqual(caught.exception.code, "missing_claim")
        self.assertEqual(
            self.stages(),
            [("identity", "denied", "missing_claim")],
        )
        self.assert_no_sensitive_values()

    def test_policy_rejection_records_denial_without_login(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE_NAME": "strict-login",
                "SOCIAL_AUTH_WHITELISTED_EMAILS": ["allowed@example.com"],
            }
        )

        with self.assertRaises(AuthPolicyError) as caught:
            self.do_login()

        self.assertEqual(caught.exception.code, "authentication_disallowed")
        self.assertEqual(
            self.stages(),
            [
                ("identity", "allowed", "identifier_resolved"),
                ("policy", "denied", "authentication_disallowed"),
            ],
        )
        self.login.assert_not_called()
        self.assertIsNone(TestStorage.user.get_social_auth("github", "1"))
        self.assert_no_sensitive_values()

    def test_recorder_preserves_the_uninstrumented_outcome(self) -> None:
        recording = self.do_login(after_complete_checks=False)
        recorded_social = TestStorage.user.get_social_auth("github", "1")
        assert recorded_social is not None

        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        self.strategy = TestStrategy(TestStorage)
        self.backend = self.backend.__class__(
            self.strategy, redirect_uri="/complete/github"
        )
        plain = self.do_login(after_complete_checks=False)
        plain_social = TestStorage.user.get_social_auth("github", "1")

        self.assertEqual(recording.url, plain.url)
        self.assertEqual(self.strategy.session_get("username"), "foobar")
        self.assertIsNotNone(plain_social)
        assert plain_social is not None
        self.assertEqual(recorded_social.uid, plain_social.uid)
        self.assertEqual(recorded_social.provider, plain_social.provider)

    def test_partial_resume_keeps_one_stage_sequence(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE_NAME": "password-login",
                "SOCIAL_AUTH_PIPELINE": (
                    "social_core.pipeline.social_auth.social_details",
                    "social_core.pipeline.social_auth.social_uid",
                    "social_core.pipeline.social_auth.auth_allowed",
                    "social_core.tests.pipeline.ask_for_password",
                    "social_core.pipeline.social_auth.social_user",
                    "social_core.pipeline.user.get_username",
                    "social_core.pipeline.user.create_user",
                    "social_core.pipeline.social_auth.associate_user",
                    "social_core.pipeline.social_auth.load_extra_data",
                    "social_core.tests.pipeline.set_password",
                    "social_core.pipeline.user.user_details",
                ),
            }
        )

        self.do_login_with_partial_pipeline()

        self.assertEqual(
            self.stages(),
            [
                ("identity", "allowed", "identifier_resolved"),
                ("policy", "allowed", "authentication_allowed"),
                ("association", "allowed", "association_missing"),
                ("association", "allowed", "association_created"),
                ("login", "allowed", "new_user_login"),
            ],
        )
        for record in self.records():
            self.assertEqual(record.pipeline, "password-login")
        self.assertEqual(self.records()[-1].association, "created")
        self.assertEqual(len({r.pipeline_version for r in self.records()}), 1)

    def test_existing_association_only_flow_has_no_new_binding(self) -> None:
        self.do_login()
        user = TestStorage.user.get_social_auth("github", "1")
        assert user is not None
        local_user = User("existing-link")
        self.user = local_user
        self.recorder().login_evidence.clear()
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE": (
                    "social_core.pipeline.social_auth.social_details",
                    "social_core.pipeline.social_auth.social_uid",
                    "social_core.pipeline.social_auth.auth_allowed",
                    "social_core.pipeline.social_auth.social_user",
                    "social_core.pipeline.social_auth.associate_user",
                )
            }
        )
        self.backend = self.backend.__class__(
            self.strategy, redirect_uri="/complete/github"
        )

        with self.assertRaises(AuthAssociationError):
            self.do_login(after_complete_checks=False)

        self.assertEqual(
            self.stages(),
            [
                ("identity", "allowed", "identifier_resolved"),
                ("policy", "allowed", "authentication_allowed"),
                ("association", "denied", "identity_in_use"),
            ],
        )
        self.login.assert_not_called()

    def test_failing_recorder_does_not_change_authorization(self) -> None:
        self.recorder().fail_recording = True

        with self.assertLogs("social", level="WARNING") as logs:
            self.do_login()

        self.login.assert_called_once()
        self.assertEqual(len(self.records()), 5)
        self.assertIsNotNone(TestStorage.user.get_social_auth("github", "1"))
        output = "\n".join(logs.output)
        self.assertIn("login evidence recorder failed (RuntimeError)", output)
        self.assertNotIn("private detail", output)

    def test_failing_recorder_keeps_policy_rejection(self) -> None:
        self.recorder().fail_recording = True
        self.strategy.set_settings(
            {"SOCIAL_AUTH_WHITELISTED_EMAILS": ["someone-else@example.com"]}
        )

        with (
            self.assertLogs("social", level="WARNING"),
            self.assertRaises(AuthPolicyError) as caught,
        ):
            self.do_login()

        self.assertEqual(caught.exception.code, "authentication_disallowed")
        self.assertEqual(caught.exception.stage, "pipeline")
        self.login.assert_not_called()
        self.assertIsNone(TestStorage.user.get_social_auth("github", "1"))

    def test_evidence_pipeline_version_hashes_selected_steps(self) -> None:
        records: list[LoginEvidence] = []

        class VersionStrategy(RecordingStrategy):
            def record_login_evidence(self, evidence: LoginEvidence) -> None:
                records.append(evidence)

        self.strategy = VersionStrategy(TestStorage)
        self.backend = self.backend.__class__(
            self.strategy, redirect_uri="/complete/github"
        )
        self.do_login()

        first_version = records[0].pipeline_version
        self.assertEqual(len(first_version), 64)
        self.assertTrue(all(r.pipeline_version == first_version for r in records))
        self.assertEqual(records[0].pipeline, first_version)

        records.clear()
        self.strategy.session_set("username", None)
        pipeline = list(self.strategy.get_pipeline(self.backend))
        pipeline.remove("social_core.pipeline.social_auth.auth_allowed")
        self.strategy.set_settings({"SOCIAL_AUTH_PIPELINE": pipeline})
        self.do_login()

        self.assertNotEqual(records[0].pipeline_version, first_version)


class DefaultRecorderTest(BaseActionTest):
    def test_recorder_must_not_capture_profile_or_tokens(self) -> None:
        record = LoginEvidence(
            provider="github",
            pipeline="primary",
            pipeline_version="v1",
            stage="login",
            decision="allowed",
            reason="new_user_login",
            actor="social_core.actions.do_complete",
            association="created",
            association_only=False,
            initiator="anonymous",
        )

        self.assertEqual(
            record.as_dict(),
            {
                "provider": "github",
                "pipeline": "primary",
                "pipeline_version": "v1",
                "stage": "login",
                "decision": "allowed",
                "reason": "new_user_login",
                "actor": "social_core.actions.do_complete",
                "association": "created",
                "association_only": False,
                "initiator": "anonymous",
            },
        )

    def test_default_recorder_discards_without_changing_history(self) -> None:
        self.do_login()

        self.login.assert_called_once()
        self.assertIsNotNone(TestStorage.user.get_social_auth("github", "1"))
        self.assertFalse(hasattr(self.backend, "_login_evidence_version"))
