import dataclasses
import datetime as dt

import pytest
import requests

from hvac import Client, exceptions

BASE_URL = "https://vault.example.com"
PREFIX = "database/creds/app"
LEASE_A = "database/creds/app/lease-a"
LEASE_B = "database/creds/app/lease-b"


def _now():
    return dt.datetime(2026, 11, 21, 10, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def client():
    return Client(url=BASE_URL, token="root-token", namespace="team-a")


def _mock_scope(requests_mock, keys=(LEASE_A, LEASE_B), prefix=PREFIX):
    requests_mock.register_uri(
        method="LIST",
        url=f"{BASE_URL}/v1/sys/leases/lookup/{prefix}",
        json={"data": {"keys": list(keys)}},
    )


def _mock_revoke(requests_mock, method, target, status_code=204):
    suffix = target
    if method == "revoke":
        url = f"{BASE_URL}/v1/sys/leases/revoke"
    else:
        url = f"{BASE_URL}/v1/sys/leases/{method}/{suffix}"
    requests_mock.register_uri(
        method="PUT",
        url=url,
        status_code=status_code,
        text="",
    )


def _revoke_calls(requests_mock):
    return [
        request
        for request in requests_mock.request_history
        if "/sys/leases/revoke" in request.url
    ]


class TestPlanCreation:
    def test_plan_is_inspectable_and_read_only(self, client, requests_mock):
        _mock_scope(requests_mock)

        plan = client.sys.revocation.create_plan(
            lease_ids=[LEASE_A],
            prefixes=[PREFIX],
            ttl="15m",
            now=_now(),
        )

        assert _revoke_calls(requests_mock) == []
        assert plan.approved is False
        assert plan.namespace == "team-a"
        assert plan.force is False
        assert plan.mode == "prefix+lease"
        assert plan.scope == (LEASE_A, LEASE_B)
        assert plan.expires_at == _now() + dt.timedelta(minutes=15)

        summary = plan.summary(now=_now())
        assert summary["namespace"] == "team-a"
        assert summary["namespace_header"] == "team-a"
        assert summary["prefixes"] == [PREFIX]
        assert summary["lease_ids"] == [LEASE_A]
        assert summary["expires_in_seconds"] == 900
        assert summary["approved"] is False

        description = plan.describe()
        assert "namespace: team-a" in description
        assert PREFIX in description
        assert LEASE_A in description
        assert LEASE_B in description

    def test_plan_records_actual_namespace_on_each_request(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())

        assert plan.namespace == "team-a"
        assert requests_mock.request_history[0].headers["X-Vault-Namespace"] == "team-a"

    def test_unknown_namespace_is_reported_as_root(self, requests_mock):
        local_client = Client(url=BASE_URL, token="root-token")
        _mock_scope(requests_mock)
        plan = local_client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())
        assert plan.summary()["namespace"] == "root"
        assert plan.summary()["namespace_header"] is None

    def test_empty_scope_is_allowed_but_prefix_is_still_visible(self, client, requests_mock):
        _mock_scope(requests_mock, keys=())
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())
        assert plan.scope == ()
        assert plan.summary()["scope"] == []
        assert plan.summary()["prefixes"] == [PREFIX]

    def test_plan_requires_targets(self, client):
        with pytest.raises(exceptions.ParamValidationError, match="at least one"):
            client.sys.revocation.create_plan(now=_now())

    def test_force_requires_prefix_and_explicit_bool(self, client):
        with pytest.raises(exceptions.ParamValidationError, match="provide at least one prefix"):
            client.sys.revocation.create_plan(lease_ids=[LEASE_A], force=True, now=_now())

        with pytest.raises(exceptions.ParamValidationError, match="explicit bool"):
            client.sys.revocation.create_plan(prefixes=[PREFIX], force="yes", now=_now())

    def test_force_is_default_off(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())
        assert plan.force is False
        assert plan.summary()["dangerous"] is False
        assert "warning" not in plan.summary()

    def test_force_is_visible_and_dangerous(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(
            prefixes=[PREFIX], force=True, now=_now()
        )
        assert plan.mode == "force"
        assert plan.summary()["dangerous"] is True
        assert "DANGEROUS FORCE" in plan.describe()
        assert "warning" in plan.summary()


class TestApprovalGate:
    def test_unapproved_plan_sends_zero_revocations(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(
            lease_ids=[LEASE_A], prefixes=[PREFIX], now=_now()
        )

        with pytest.raises(exceptions.RevocationPlanNotApproved):
            client.sys.revocation.execute_plan(plan, now=_now() + dt.timedelta(minutes=1))

        assert _revoke_calls(requests_mock) == []

    def test_expired_plan_sends_zero_revocations(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(
            lease_ids=[LEASE_A], prefixes=[PREFIX], ttl="1m", now=_now()
        )
        approved = client.sys.revocation.approve_plan(
            plan, "alice", now=_now() + dt.timedelta(seconds=10)
        )

        with pytest.raises(exceptions.RevocationPlanExpired, match="expired"):
            client.sys.revocation.execute_plan(
                approved, now=_now() + dt.timedelta(seconds=61)
            )

        assert _revoke_calls(requests_mock) == []

    def test_expired_plan_cannot_be_approved(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], ttl=1, now=_now())

        with pytest.raises(exceptions.RevocationPlanExpired):
            client.sys.revocation.approve_plan(
                plan, "alice", now=_now() + dt.timedelta(seconds=2)
            )

    def test_scope_change_sends_zero_revocations(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(
            lease_ids=[LEASE_A], prefixes=[PREFIX], now=_now()
        )
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        requests_mock.reset_mock()
        _mock_scope(requests_mock, keys=[LEASE_A, LEASE_B, "lease-c"])

        with pytest.raises(exceptions.RevocationPlanScopeChanged) as excinfo:
            client.sys.revocation.execute_plan(
                approved, now=_now() + dt.timedelta(minutes=1)
            )

        assert excinfo.value.added == ("database/creds/app/lease-c",)
        assert _revoke_calls(requests_mock) == []

    def test_namespace_change_sends_zero_revocations(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        client.adapter.namespace = "team-b"

        with pytest.raises(exceptions.RevocationPlanNamespaceChanged) as excinfo:
            client.sys.revocation.execute_plan(
                approved, now=_now() + dt.timedelta(minutes=1)
            )

        assert excinfo.value.planned_namespace == "team-a"
        assert excinfo.value.actual_namespace == "team-b"
        assert _revoke_calls(requests_mock) == []

    def test_namespace_change_before_approval_is_rejected(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())

        client.adapter.namespace = "team-b"

        with pytest.raises(exceptions.RevocationPlanNamespaceChanged):
            client.sys.revocation.approve_plan(plan, "alice", now=_now())

        assert _revoke_calls(requests_mock) == []

    def test_plan_integrity_check_blocks_tampering(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        tampered = dataclasses.replace(approved, force=True)

        with pytest.raises(exceptions.RevocationPlanError, match="integrity"):
            client.sys.revocation.execute_plan(
                tampered, now=_now() + dt.timedelta(minutes=1)
            )

        assert _revoke_calls(requests_mock) == []

    def test_rejected_lease_stops_before_prefix(self, client, requests_mock):
        _mock_scope(requests_mock)
        _mock_revoke(requests_mock, "revoke", LEASE_A, status_code=404)

        plan = client.sys.revocation.create_plan(
            lease_ids=[LEASE_A], prefixes=[PREFIX], now=_now()
        )
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        with pytest.raises(exceptions.RevocationFailed) as excinfo:
            client.sys.revocation.execute_plan(
                approved, now=_now() + dt.timedelta(minutes=1)
            )

        assert excinfo.value.receipt.state == "failed"
        revoke_requests = _revoke_calls(requests_mock)
        assert len(revoke_requests) == 1
        assert revoke_requests[0].url.endswith("/v1/sys/leases/revoke")

    def test_scope_read_failure_sends_zero_revocations(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        requests_mock.register_uri(
            method="LIST",
            url=f"{BASE_URL}/v1/sys/leases/lookup/{PREFIX}",
            status_code=403,
            json={"errors": ["permission denied"]},
        )

        with pytest.raises(exceptions.RevocationPlanError, match="unable to verify"):
            client.sys.revocation.execute_plan(
                approved, now=_now() + dt.timedelta(minutes=1)
            )

        assert _revoke_calls(requests_mock) == []

    def test_scope_change_before_approval_is_rejected(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())

        requests_mock.reset_mock()
        _mock_scope(requests_mock, keys=[LEASE_A])

        with pytest.raises(exceptions.RevocationPlanScopeChanged):
            client.sys.revocation.approve_plan(plan, "alice", now=_now())

        assert _revoke_calls(requests_mock) == []

    def test_approval_cannot_be_reused_for_new_scope(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        with pytest.raises(exceptions.RevocationPlanError, match="already approved"):
            client.sys.revocation.approve_plan(approved, "bob", now=_now())

    def test_approval_requires_named_approver(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())
        with pytest.raises(exceptions.ParamValidationError, match="approver"):
            client.sys.revocation.approve_plan(plan, "  ", now=_now())


class TestExecution:
    def test_approved_plan_revokes_exact_targets(self, client, requests_mock):
        _mock_scope(requests_mock)
        _mock_revoke(requests_mock, "revoke", LEASE_A)
        _mock_revoke(requests_mock, "revoke-prefix", PREFIX)

        plan = client.sys.revocation.create_plan(
            lease_ids=[LEASE_A], prefixes=[PREFIX], now=_now()
        )
        approved = client.sys.revocation.approve_plan(
            plan, "alice", note="INC-42", now=_now()
        )
        receipt = client.sys.revocation.execute_plan(
            approved, now=_now() + dt.timedelta(minutes=1)
        )

        assert receipt.state == "succeeded"
        assert receipt.ok is True
        assert [result.status for result in receipt.results] == ["revoked", "revoked"]
        assert receipt.to_dict()["namespace"] == "team-a"

        revoke_requests = _revoke_calls(requests_mock)
        assert len(revoke_requests) == 2
        assert revoke_requests[0].url.endswith("/v1/sys/leases/revoke")
        assert revoke_requests[0].json() == {"lease_id": LEASE_A}
        assert revoke_requests[1].url.endswith(
            f"/v1/sys/leases/revoke-prefix/{PREFIX}"
        )
        assert revoke_requests[1].json() == {"prefix": PREFIX}
        assert all(
            request.headers["X-Vault-Namespace"] == "team-a"
            for request in revoke_requests
        )

    def test_force_plan_uses_revoke_force_only_when_selected(self, client, requests_mock):
        _mock_scope(requests_mock)
        _mock_revoke(requests_mock, "revoke-force", PREFIX)

        plan = client.sys.revocation.create_plan(
            prefixes=[PREFIX], force=True, now=_now()
        )
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())
        receipt = client.sys.revocation.execute_plan(
            approved, now=_now() + dt.timedelta(minutes=1)
        )

        assert receipt.state == "succeeded"
        revoke_requests = _revoke_calls(requests_mock)
        assert len(revoke_requests) == 1
        assert revoke_requests[0].url.endswith(
            f"/v1/sys/leases/revoke-force/{PREFIX}"
        )

    def test_transport_failure_is_unknown_and_not_retried(self, client, requests_mock):
        _mock_scope(requests_mock)
        requests_mock.register_uri(
            method="PUT",
            url=f"{BASE_URL}/v1/sys/leases/revoke",
            exc=requests.exceptions.ConnectTimeout("timed out"),
        )

        plan = client.sys.revocation.create_plan(lease_ids=[LEASE_A], now=_now())
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        with pytest.raises(exceptions.RevocationOutcomeUnknown) as excinfo:
            client.sys.revocation.execute_plan(
                approved, now=_now() + dt.timedelta(minutes=1)
            )

        exc = excinfo.value
        assert exc.receipt.state == "unknown"
        assert exc.receipt.results[0].status == "unknown"
        assert len(_revoke_calls(requests_mock)) == 1
        assert exc.verification_steps
        assert any("readback" in step for step in exc.verification_steps)
        assert any("audit" in step for step in exc.verification_steps)

    def test_server_error_is_unknown_not_success(self, client, requests_mock):
        _mock_scope(requests_mock)
        requests_mock.register_uri(
            method="PUT",
            url=f"{BASE_URL}/v1/sys/leases/revoke",
            status_code=500,
            json={"errors": ["internal error"]},
        )

        plan = client.sys.revocation.create_plan(lease_ids=[LEASE_A], now=_now())
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        with pytest.raises(exceptions.RevocationOutcomeUnknown):
            client.sys.revocation.execute_plan(
                approved, now=_now() + dt.timedelta(minutes=1)
            )

    def test_rejected_target_reports_partial_receipt(self, client, requests_mock):
        _mock_scope(requests_mock)
        _mock_revoke(requests_mock, "revoke", LEASE_A)
        _mock_revoke(requests_mock, "revoke-prefix", PREFIX, status_code=403)

        plan = client.sys.revocation.create_plan(
            lease_ids=[LEASE_A], prefixes=[PREFIX], now=_now()
        )
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        with pytest.raises(exceptions.RevocationFailed) as excinfo:
            client.sys.revocation.execute_plan(
                approved, now=_now() + dt.timedelta(minutes=1)
            )

        assert excinfo.value.receipt.state == "partial"
        assert [result.status for result in excinfo.value.receipt.results] == [
            "revoked",
            "rejected",
        ]

    def test_readback_surfaces_scope_change_without_revoking(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(
            lease_ids=[LEASE_A], prefixes=[PREFIX], now=_now()
        )
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        requests_mock.reset_mock()
        _mock_scope(requests_mock, keys=[LEASE_B])

        requests_mock.register_uri(
            method="PUT",
            url=f"{BASE_URL}/v1/sys/leases/lookup",
            status_code=404,
            json={"errors": ["lease not found"]},
        )

        readback = client.sys.revocation.readback(approved)

        assert readback["changed"] is True
        assert readback["added"] == []
        assert readback["removed"] == [LEASE_A]
        assert readback["lease_states"] == {LEASE_A: "missing"}
        assert _revoke_calls(requests_mock) == []

    def test_nested_prefix_walk_finds_leases_below_folders(self, client, requests_mock):
        requests_mock.register_uri(
            method="LIST",
            url=f"{BASE_URL}/v1/sys/leases/lookup/{PREFIX}",
            json={"data": {"keys": ["role/"]}},
        )
        requests_mock.register_uri(
            method="LIST",
            url=f"{BASE_URL}/v1/sys/leases/lookup/{PREFIX}/role",
            json={"data": {"keys": ["deep-lease"]}},
        )

        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())

        assert plan.scope == (f"{PREFIX}/role/deep-lease",)


class TestReadbackEvidence:
    def test_readback_reports_exact_lease_present(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(lease_ids=[LEASE_A], now=_now())
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        requests_mock.register_uri(
            method="PUT",
            url=f"{BASE_URL}/v1/sys/leases/lookup",
            json={"data": {"id": LEASE_A}},
        )

        evidence = client.sys.revocation.readback(approved)
        assert evidence["lease_states"] == {LEASE_A: "present"}
        assert _revoke_calls(requests_mock) == []

    def test_readback_reports_unknown_when_lookup_fails(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(lease_ids=[LEASE_A], now=_now())
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        requests_mock.register_uri(
            method="PUT",
            url=f"{BASE_URL}/v1/sys/leases/lookup",
            status_code=500,
            json={"errors": ["backend unavailable"]},
        )

        evidence = client.sys.revocation.readback(approved)
        assert evidence["lease_states"][LEASE_A].startswith("unknown:")
        assert _revoke_calls(requests_mock) == []

    def test_readback_reports_scope_unknown_when_listing_fails(self, client, requests_mock):
        _mock_scope(requests_mock)
        plan = client.sys.revocation.create_plan(prefixes=[PREFIX], now=_now())
        approved = client.sys.revocation.approve_plan(plan, "alice", now=_now())

        requests_mock.reset_mock()
        requests_mock.register_uri(
            method="LIST",
            url=f"{BASE_URL}/v1/sys/leases/lookup/{PREFIX}",
            status_code=403,
            json={"errors": ["permission denied"]},
        )

        evidence = client.sys.revocation.readback(approved)
        assert evidence["changed"] is None
        assert evidence["current_scope"] is None
        assert "scope_error" in evidence
        assert _revoke_calls(requests_mock) == []
