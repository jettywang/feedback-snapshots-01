import unittest
from unittest.mock import Mock, patch

import msal
from msal.delegation import (
    DelegationContext,
    DelegationDecision,
    DelegationDenied,
    DelegationGuard,
    DelegationPolicy,
    DelegationResultCache,
    is_delegation_current,
)


SCOPE = "https://downstream.example/.default"
ASSERTION = "synthetic-user-assertion"
BUSINESS_ID = "order-center"
TENANT_ID = "tenant-1"
SOURCE = "security-group:delegation-admins"


def make_policy():
    policy = DelegationPolicy()
    policy.approve(
        grant_id="shipment-grant",
        business_id=BUSINESS_ID,
        tenant_id=TENANT_ID,
        source=SOURCE,
        action="ship",
        scopes=[SCOPE],
        effective_permissions=["Shipment.Delegate"],
    )
    policy.approve(
        grant_id="refund-grant",
        business_id=BUSINESS_ID,
        tenant_id=TENANT_ID,
        source=SOURCE,
        action="refund",
        scopes=[SCOPE],
        effective_permissions=["Refund.Delegate"],
    )
    return policy


def context(grant_id, action, permission):
    return dict(
        user_assertion=ASSERTION,
        business_id=BUSINESS_ID,
        tenant_id=TENANT_ID,
        source=SOURCE,
        grant_id=grant_id,
        action=action,
        scopes=[SCOPE],
        effective_permissions=[permission],
    )


class DelegationScenarioTest(unittest.TestCase):
    def test_revoked_action_is_denied_but_unaffected_action_uses_cache(self):
        exchange = Mock(side_effect=[
            {"access_token": "ship-token", "expires_in": 3600},
            {"access_token": "refund-token", "expires_in": 3600},
        ])
        cache_store = {}
        guard = DelegationGuard(
            policy=make_policy(),
            cache=cache_store,
            exchange=exchange,
        )
        ship = context("shipment-grant", "ship", "Shipment.Delegate")
        refund = context("refund-grant", "refund", "Refund.Delegate")

        first_ship = guard.acquire_token(**ship)
        first_refund = guard.acquire_token(**refund)
        second_ship = guard.acquire_token(**ship)
        second_refund = guard.acquire_token(**refund)

        self.assertEqual(2, exchange.call_count)
        self.assertEqual("cache", second_ship["token_source"])
        self.assertEqual("cache", second_refund["token_source"])
        self.assertEqual(
            first_ship["access_token"], second_ship["access_token"])
        self.assertEqual(
            first_refund["access_token"], second_refund["access_token"])
        self.assertNotEqual(
            first_ship["access_token"], first_refund["access_token"])
        self.assertEqual(2, len(cache_store))

        guard.policy.revoke("shipment-grant")

        denied = guard.acquire_token(**ship)
        self.assertFalse(denied["allowed"])
        self.assertTrue(denied["denied"])
        self.assertEqual("grant_revoked", denied["authorization_reason"])
        self.assertEqual("authorization", denied["stage"])
        self.assertEqual("revoked", denied["public_category"])
        self.assertEqual(
            {"stage": "authorization", "public_category": "revoked"},
            denied["receipt"].to_dict(),
        )
        self.assertEqual(
            ["stage", "public_category"], list(dict(denied).keys()))
        self.assertEqual("revoked", denied["receipt"]["category"])
        self.assertEqual(2, exchange.call_count)
        self.assertEqual(2, len(cache_store))

        still_working = guard.acquire_token(**refund)
        self.assertEqual("cache", still_working["token_source"])
        self.assertTrue(still_working["delegation_verified"])
        self.assertEqual("grant_active", still_working["authorization_reason"])
        self.assertEqual(2, exchange.call_count)

    def test_revocation_can_raise_minimal_receipt(self):
        guard = DelegationGuard(policy=make_policy(), raise_on_deny=True)
        guard.policy.revoke("refund-grant")
        with self.assertRaises(DelegationDenied) as caught:
            guard.acquire_token(
                **context("refund-grant", "refund", "Refund.Delegate"))
        self.assertEqual(
            {"stage": "authorization", "public_category": "revoked"},
            caught.exception.receipt.to_dict(),
        )

    def test_business_tenant_source_and_permissions_bind_cache(self):
        policy = make_policy()
        cache = DelegationResultCache()
        decision = policy.authorize(
            **context("shipment-grant", "ship", "Shipment.Delegate"))
        first_context = decision.context
        cache.store(first_context, decision, {"access_token": "a"})

        same = cache.get(first_context, decision)
        self.assertEqual("cache", same["token_source"])
        self.assertTrue(is_delegation_current(
            decision,
            business_id=BUSINESS_ID,
            tenant_id=TENANT_ID,
            source=SOURCE,
            effective_permissions=["Shipment.Delegate"]))

        changed_permission = DelegationContext(
            first_context, effective_permissions=["Shipment.Delegate", "Extra"])
        changed_decision = DelegationDecision(
            True, "grant_active", context=changed_permission,
            effective_permissions=["Shipment.Delegate", "Extra"])
        result, reason, stale, _ = cache.lookup(
            changed_permission, changed_decision)
        self.assertIsNone(result)
        self.assertEqual("delegation_fingerprint_mismatch", reason)
        self.assertIsNotNone(stale)
        self.assertIn("a", str(cache.entries))

        changed_source = DelegationContext(first_context, source="another-group")
        self.assertIsNone(cache.get(changed_source))

    def test_expired_cache_is_not_reused_but_old_entry_remains(self):
        policy = make_policy()
        cache = DelegationResultCache(clock=lambda: 100.0)
        ctx = DelegationContext(
            **context("shipment-grant", "ship", "Shipment.Delegate"))
        decision = policy.authorize(ctx)
        cache.store(
            ctx, decision, {"access_token": "old", "expires_in": 10})
        result, reason, entry, _ = cache.lookup(
            ctx, decision, now=200.0)
        self.assertIsNone(result)
        self.assertEqual("cache_entry_expired", reason)
        self.assertIsNotNone(entry)

    def test_synthetic_assertion_supplies_subject_and_tenant_hint(self):
        import base64
        import json

        def part(value):
            raw = json.dumps(value).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        assertion = ".".join([
            part({"alg": "none"}),
            part({"oid": "user-1", "tid": "tenant-from-token"}),
            "sig",
        ])
        ctx = DelegationContext(user_assertion=assertion)
        self.assertEqual("user-1", ctx.subject)
        self.assertEqual("tenant-from-token", ctx.tenant_id)

    def test_confidential_obo_uses_optional_delegation_cache(self):
        from tests.http_client import MinimalResponse
        from tests.test_application import (
            _OIDC_DISCOVERY, _OIDC_DISCOVERY_MOCK)

        policy = make_policy()
        with patch(_OIDC_DISCOVERY, new=_OIDC_DISCOVERY_MOCK):
            app = msal.ConfidentialClientApplication(
                "client-id",
                client_credential="secret",
                authority="https://login.microsoftonline.com/tenant",
                delegation_policy=policy,
            )

        post = Mock(return_value=MinimalResponse(
            status_code=200,
            text='{"access_token":"obo-token","expires_in":3600}'))
        request = context("shipment-grant", "ship", "Shipment.Delegate")
        with patch(_OIDC_DISCOVERY, new=_OIDC_DISCOVERY_MOCK):
            first = app.acquire_token_on_behalf_of(post=post, **request)
            second = app.acquire_token_on_behalf_of(post=post, **request)

        self.assertEqual("identity_provider", first["token_source"])
        self.assertEqual("cache", second["token_source"])
        self.assertEqual(1, post.call_count)

        policy.revoke("shipment-grant")
        denied = app.acquire_token_on_behalf_of(post=post, **request)
        self.assertEqual(
            {"stage": "authorization", "public_category": "revoked"},
            denied.to_dict(),
        )
        self.assertEqual(1, post.call_count)

    def test_package_exports(self):
        for name in (
                "DelegationGuard", "DelegationPolicy", "DelegationGrant",
                "DelegationResultCache", "DelegationContext",
                "DelegationDecision", "DelegationReceipt", "DelegationDenied"):
            self.assertTrue(hasattr(msal, name), name)


if __name__ == "__main__":
    unittest.main()
