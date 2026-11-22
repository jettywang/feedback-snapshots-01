"""SAML single logout (SLO) session correlation and replay handling.

These tests use the local, fully offline IdP fixtures in ``saml_helpers``.
SLO must act on one IdP-scoped local session at a time: a validated message
ends exactly that session, duplicate and failed messages leave every local
session in place, and another enterprise's session is never touched. Logs
distinguish ended sessions from pending ones and never carry external tickets.
"""

import io
import logging
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from .base import BaseBackendTest

try:
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

    # This backend import must remain optional when the SAML extra is absent.
    # pylint: disable-next=ungrouped-imports
    from . import saml_helpers as saml

    SAML_MODULE_ENABLED = True
except ImportError:
    SAML_MODULE_ENABLED = False

# Values that must never appear in routine SLO logging.
SECRET_MARKERS = (
    "stable-name-id",
    "session-index",
    "logout-id",
    "idp-logout-id",
)


@unittest.skipUnless(SAML_MODULE_ENABLED, "Requires the SAML extra")
class SAMLLogoutTest(BaseBackendTest):
    backend_path = "social_core.backends.saml.SAMLAuth"

    def extra_settings(self):
        return {
            "SOCIAL_AUTH_SAML_SP_ENTITY_ID": saml.SP,
            "SOCIAL_AUTH_SAML_SP_PUBLIC_CERT": saml.keypair("sp")[1].decode(),
            "SOCIAL_AUTH_SAML_SP_PRIVATE_KEY": saml.keypair("sp")[0].decode(),
            "SOCIAL_AUTH_SAML_ORG_INFO": {
                "en-US": {
                    "name": "Example",
                    "displayname": "Example SP",
                    "url": "https://sp.example.com",
                }
            },
            "SOCIAL_AUTH_SAML_TECHNICAL_CONTACT": {
                "givenName": "Technical",
                "emailAddress": "tech@example.com",
            },
            "SOCIAL_AUTH_SAML_SUPPORT_CONTACT": {
                "givenName": "Support",
                "emailAddress": "support@example.com",
            },
            "SOCIAL_AUTH_SAML_SECURITY_CONFIG": {
                "wantMessagesSigned": True,
                "logoutRequestSigned": True,
                "logoutResponseSigned": True,
            },
            "SOCIAL_AUTH_SAML_ENABLED_IDPS": {
                name: {
                    "entity_id": saml.ENTITY,
                    "url": saml.SSO,
                    "slo_url": saml.SLO,
                    "x509cert": saml.keypair("idp")[1].decode(),
                    "attr_username": "username",
                }
                for name in ("idp", "other")
            },
        }

    def setUp(self):
        super().setUp()
        self.backend.redirect_uri = saml.ACS
        self.clock = patch.object(
            OneLogin_Saml2_Utils, "now", return_value=1717243200
        )
        self.clock.start()
        self.addCleanup(self.clock.stop)
        path = patch.object(
            self.strategy, "request_path", return_value="/complete/saml"
        )
        path.start()
        self.addCleanup(path.stop)
        self.log_output = io.StringIO()
        handler = logging.StreamHandler(self.log_output)
        logger = logging.getLogger("social")
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        self.social = SimpleNamespace(
            extra_data={
                "name_id": "stable-name-id",
                "session_index": "session-index",
            }
        )

    def logout_key(self, idp_name: str) -> str:
        return f"saml_{idp_name}_logout_request_id"

    def seen_key(self, idp_name: str) -> str:
        return f"saml_{idp_name}_logout_message_ids"

    def deliver(
        self,
        kind: str,
        *,
        variant: str = "valid",
        relay_state: str | None = "/after",
        request_id: str = "logout-id",
    ) -> None:
        node = saml.logout(
            "LogoutRequest" if kind == "request" else "LogoutResponse",
            request_id=request_id,
        )
        if variant == "status":
            saml.find(node, ".//samlp:StatusCode").set(
                "Value", "urn:oasis:names:tc:SAML:2.0:status:Responder"
            )
        if variant == "destination":
            node.set("Destination", "https://wrong.example.com/slo")
        query = saml.redirect_query(
            node,
            kind="SAMLRequest" if kind == "request" else "SAMLResponse",
            relay_state=relay_state,
        )
        if variant == "unsigned":
            del query["Signature"]
            del query["SigAlg"]
        self.strategy.request_data().clear()
        self.strategy.set_request_data(query, self.backend)

    def test_active_logout_success_ends_only_the_idp_session(self) -> None:
        url = self.backend.request_logout("idp", self.social, return_to="/after")
        node, query = saml.decode_redirect(url, "SAMLRequest")
        saml.verify_redirect(query)
        self.assertEqual(node.get("Destination"), saml.SLO)
        request_id = node.get("ID")
        self.assertEqual(
            self.strategy.session_get(self.logout_key("idp")), request_id
        )

        # A second enterprise session coexists in the same browser session.
        self.strategy.session_set(self.logout_key("other"), "other-transaction")
        delete = Mock()
        self.deliver("response", request_id=request_id)
        returned_url, errors = self.backend.process_logout("idp", delete)

        self.assertEqual(errors, [])
        delete.assert_called_once_with()
        self.assertIsNone(self.strategy.session_get(self.logout_key("idp")))
        # The other enterprise's transaction must survive untouched.
        self.assertEqual(
            self.strategy.session_get(self.logout_key("other")),
            "other-transaction",
        )
        self.assertIsNone(returned_url)
        log_text = self.log_output.getvalue()
        self.assertIn("logout initiated", log_text)
        self.assertIn("logout completed", log_text)
        self.assertIn("local session ended", log_text)
        for marker in SECRET_MARKERS:
            self.assertNotIn(marker, log_text)

    def test_duplicate_logout_response_is_rejected_and_keeps_the_session(self) -> None:
        url = self.backend.request_logout("idp", self.social)
        node, _ = saml.decode_redirect(url, "SAMLRequest")
        request_id = node.get("ID")
        delete = Mock()

        self.deliver("response", request_id=request_id)
        _, first_errors = self.backend.process_logout("idp", delete)
        self.assertEqual(first_errors, [])
        self.assertEqual(delete.call_count, 1)
        # Replay the identical, still valid message in the same browser.
        self.deliver("response", request_id=request_id)
        second_url, second_errors = self.backend.process_logout("idp", delete)
        self.assertEqual(second_errors, ["replayed_logout_response"])
        self.assertIsNone(second_url)
        self.assertEqual(delete.call_count, 1)
        self.assertEqual(
            self.strategy.session_get(self.seen_key("idp")), ["idp-logout-id"]
        )
        self.assertIn("already processed", self.log_output.getvalue())

    def test_server_failure_preserves_every_local_session_for_retry(self) -> None:
        url = self.backend.request_logout("idp", self.social)
        node, _ = saml.decode_redirect(url, "SAMLRequest")
        request_id = node.get("ID")
        self.strategy.session_set(self.logout_key("other"), "other-transaction")

        for variant in ("status", "unsigned", "destination"):
            with self.subTest(variant=variant):
                delete = Mock()
                self.deliver("response", variant=variant, request_id=request_id)
                _, errors = self.backend.process_logout("idp", delete)
                self.assertTrue(errors)
                delete.assert_not_called()
                # The failed message can be retried: no replay history lingers.
                self.assertEqual(
                    self.strategy.session_get(self.seen_key("idp")), []
                )
                # The outstanding transaction and the other IdP are untouched.
                self.assertEqual(
                    self.strategy.session_get(self.logout_key("idp")),
                    request_id,
                )
                self.assertEqual(
                    self.strategy.session_get(self.logout_key("other")),
                    "other-transaction",
                )
                log_text = self.log_output.getvalue()
                self.assertIn("still active", log_text)
                for marker in SECRET_MARKERS:
                    self.assertNotIn(marker, log_text)

        # The same response succeeds once the IdP delivers a valid message.
        delete = Mock()
        self.deliver("response", request_id=request_id)
        _, errors = self.backend.process_logout("idp", delete)
        self.assertEqual(errors, [])
        delete.assert_called_once_with()

    def test_idp_initiated_logout_request_is_replay_protected(self) -> None:
        delete = Mock()
        self.deliver("request")
        url, errors = self.backend.process_logout("idp", delete)
        self.assertEqual(errors, [])
        delete.assert_called_once_with()
        # A LogoutRequest produces a LogoutResponse redirect back to the IdP.
        reply, query = saml.decode_redirect(url, "SAMLResponse")
        saml.verify_redirect(query, "SAMLResponse")
        self.assertEqual(reply.get("InResponseTo"), "idp-logout-id")

        self.deliver("request")
        _, repeated_errors = self.backend.process_logout(
            "idp", delete
        )
        self.assertEqual(repeated_errors, ["replayed_logout_response"])
        self.assertIsNone(repeated_url)
        delete.assert_called_once_with()

    def test_logout_state_is_scoped_per_idp(self) -> None:
        # Two enterprises share one browser but keep independent SLO state.
        for idp_name in ("idp", "other"):
            self.backend.request_logout(idp_name, self.social)
        self.assertIsNotNone(self.strategy.session_get(self.logout_key("idp")))
        self.assertIsNotNone(self.strategy.session_get(self.logout_key("other")))

        delete_idp = Mock()
        self.deliver("response")
        _, errors = self.backend.process_logout("idp", delete_idp)
        self.assertEqual(errors, [])
        delete_idp.assert_called_once_with()

        # Ending the "idp" session neither clears nor blocks "other".
        self.assertIsNone(self.strategy.session_get(self.logout_key("idp")))
        self.assertIsNotNone(self.strategy.session_get(self.logout_key("other")))
        self.assertEqual(self.strategy.session_get(self.seen_key("other")), None)

        delete_other = Mock()
        other_request_id = self.strategy.session_get(self.logout_key("other"))
        other_node = saml.logout("LogoutResponse", request_id=other_request_id)
        other_query = saml.redirect_query(
            other_node, kind="SAMLResponse", relay_state="/after"
        )
        self.strategy.request_data().clear()
        self.strategy.set_request_data(other_query, self.backend)
        _, errors = self.backend.process_logout("other", delete_other)
        self.assertEqual(errors, [])
        delete_other.assert_called_once_with()
