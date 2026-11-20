#!/usr/bin/env python
"""Runnable demo of the guarded ACL policy batch interface.

A fake, in-memory Vault stands in for a real server (no network, no token).
The same fake supports scripted write failures, updates injected by "another
administrator" mid-batch, and responses the client does not know how to
classify. Each scenario ends by reading every policy back and listing the
final state explicitly, including unknown outcomes that must not be reported
as full success or rolled back blindly.

Run it directly:

    .venv/bin/python tests/scripts/policy_batch_demo.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hvac.api.system_backend.policy_batch import (  # noqa: E402
    PolicyBatch,
)


class FakeResponse:
    """Minimal requests.Response look-alike returned by the fake adapter."""

    def __init__(self, status_code, body=None, text=None):
        self.status_code = status_code
        self._body = body
        if text is not None:
            self.text = text
        elif body is not None:
            self.text = json.dumps(body)
        else:
            self.text = ""

    def json(self):
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body


class FakeVault:
    """In-memory implementation of the /sys/policy endpoints."""

    def __init__(self, json_adapter=False):
        self._policies = {"root": 'path "sys" { capabilities = ["deny"] }'}
        # Scripted PUT failures: name -> status code, consumed once.
        self.fail_puts = {}
        # Scripted unclassifiable responses: (method, name) -> status code.
        self.unknown_responses = {}
        # Per-policy hooks fired on the second read of that policy (the
        # client's immediate pre-write check). They model another
        # administrator writing between evidence capture and our write.
        self.before_apply_read_hooks = {}
        self._read_counts = {}
        # When True, 200 reads come back as parsed dicts like JSONAdapter.
        self.json_adapter = json_adapter
        self.request_log = []

    # Test-only hooks used to simulate another administrator.
    def admin_set_policy(self, name, rules):
        self._policies[name] = rules

    def admin_delete_policy(self, name):
        self._policies.pop(name, None)

    def handle(self, method, url, kwargs):
        self.request_log.append((method, url))
        name = url.rsplit("/sys/policy/", 1)[-1]
        if method == "get":
            self._read_counts[name] = self._read_counts.get(name, 0) + 1
            if self._read_counts[name] == 2:
                hook = self.before_apply_read_hooks.pop(name, None)
                if hook is not None:
                    hook()
        scripted = self.unknown_responses.pop((method, name), None)
        if scripted is not None:
            return FakeResponse(scripted, text="gateway produced an unknown reply")
        if method == "get":
            return self._read(name)
        if method == "put":
            return self._write(name, kwargs)
        if method == "delete":
            return self._delete(name)
        return FakeResponse(405, {"errors": ["method not allowed"]})

    def _read(self, name):
        if name not in self._policies:
            return FakeResponse(404, {"errors": ["no policy named %s" % name]})
        body = {"data": {"name": name, "rules": self._policies[name]}}
        if self.json_adapter:
            return body
        return FakeResponse(200, body)

    def _write(self, name, kwargs):
        failure = self.fail_puts.pop(name, None)
        if failure is not None:
            return FakeResponse(failure, {"errors": ["simulated write failure"]})
        payload = kwargs.get("json") or {}
        self._policies[name] = payload.get("policy", "")
        return FakeResponse(204)

    def _delete(self, name):
        self._policies.pop(name, None)
        return FakeResponse(204)

    def snapshot(self):
        return dict(self._policies)


class FakeVaultAdapter:
    """Adapter exposing the small surface PolicyBatch relies on."""

    def __init__(self, vault):
        self._vault = vault

    def request(self, method, url, raise_exception=True, **kwargs):
        return self._vault.handle(method, url, kwargs)


def make_batch(vault):
    return PolicyBatch(adapter=FakeVaultAdapter(vault))


TIGHT_RULES_A = 'path "secret/a/*" { capabilities = ["read"] }'
TIGHT_RULES_B = 'path "secret/b/*" { capabilities = ["read", "list"] }'
TIGHT_RULES_C = 'path "secret/c/*" { capabilities = ["deny"] }'


def banner(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def print_final_states(vault, result):
    print("-- batch status: %s (readback required: %s)" % (
        result.status, result.readback_required
    ))
    for entry in result.results:
        print(
            "  - %-14s apply=%-14s rollback=%-18s final=%s"
            % (
                entry.name,
                entry.apply_status,
                entry.rollback_status,
                entry.final_status,
            )
        )
        if entry.readback_advised:
            print(
                "      ! unknown response: read sys/policy/%s back before "
                "acting on it" % entry.name
            )
    print("-- stored policies after the batch:")
    for name, rules in sorted(vault.snapshot().items()):
        print("    %s -> %s" % (name, rules))


def scenario_create_and_replace():
    banner("Scenario 1: create a new policy and tighten two existing policies")
    vault = FakeVault()
    vault.admin_set_policy("policy-a", 'path "secret/a/*" { capabilities = ["create", "read", "update", "delete"] }')
    vault.admin_set_policy("policy-b", 'path "secret/b/*" { capabilities = ["create", "read", "update"] }')
    result = make_batch(vault).apply_policy_batch(
        [
            ("policy-a", TIGHT_RULES_A),
            ("policy-b", TIGHT_RULES_B),
            ("policy-new", TIGHT_RULES_C),
        ]
    )
    print_final_states(vault, result)
    assert result.status == "succeeded"
    assert all(r.final_status == "changed" for r in result.results)
    assert vault.snapshot()["policy-a"] == TIGHT_RULES_A
    assert "policy-new" in vault.snapshot()


def scenario_write_failure_with_rollback():
    banner("Scenario 2: a write fails; applied policies are conditionally restored")
    vault = FakeVault()
    original_a = 'path "secret/a/*" { capabilities = ["create", "read", "update", "delete"] }'
    original_b = 'path "secret/b/*" { capabilities = ["create", "read", "update"] }'
    vault.admin_set_policy("policy-a", original_a)
    vault.admin_set_policy("policy-b", original_b)
    # The third policy's PUT returns a documented 400; earlier writes succeed.
    vault.fail_puts = {"policy-c": 400}
    result = make_batch(vault).apply_policy_batch(
        [
            ("policy-a", TIGHT_RULES_A),
            ("policy-b", TIGHT_RULES_B),
            ("policy-c", TIGHT_RULES_C),
        ]
    )
    print_final_states(vault, result)
    assert result.status == "failed"
    assert vault.snapshot()["policy-a"] == original_a
    assert vault.snapshot()["policy-b"] == original_b
    assert "policy-c" not in vault.snapshot()
    by_name = {r.name: r for r in result.results}
    assert by_name["policy-a"].rollback_status == "restored"
    assert by_name["policy-c"].apply_status == "apply_error"


def scenario_other_admin_takes_over():
    banner("Scenario 3: another admin edits a policy mid-batch; rollback skips it")
    vault = FakeVault()
    original_a = 'path "secret/a/*" { capabilities = ["create", "read", "update", "delete"] }'
    original_b = 'path "secret/b/*" { capabilities = ["create", "read", "update"] }'
    vault.admin_set_policy("policy-a", original_a)
    vault.admin_set_policy("policy-b", original_b)
    vault.fail_puts = {"policy-c": 500}

    def other_admin_edits_policy_b():
        # Runs after our pre-write read of policy-b but before its PUT, so the
        # client detects the takeover and refuses to overwrite the new body.
        vault.admin_set_policy(
            "policy-b", 'path "secret/b/*" { capabilities = ["sudo"] }'
        )

    vault.before_apply_read_hooks = {"policy-b": other_admin_edits_policy_b}
    result = make_batch(vault).apply_policy_batch(
        [
            ("policy-a", TIGHT_RULES_A),
            ("policy-b", TIGHT_RULES_B),
            ("policy-c", TIGHT_RULES_C),
        ]
    )
    print_final_states(vault, result)
    by_name = {r.name: r for r in result.results}
    # policy-b was never written by us; the other admin's copy survives and
    # the rollback refuses to overwrite it.
    assert by_name["policy-b"].apply_status == "apply_conflict"
    assert vault.snapshot()["policy-b"] == (
        'path "secret/b/*" { capabilities = ["sudo"] }'
    )
    # policy-a was applied by us and nobody else touched it, so it reverts.
    assert by_name["policy-a"].rollback_status == "restored"
    assert vault.snapshot()["policy-a"] == original_a
    assert result.status == "failed"


def scenario_unknown_response():
    banner("Scenario 4: an unclassifiable response; read back, no blind rollback")
    vault = FakeVault()
    original_a = 'path "secret/a/*" { capabilities = ["create", "read", "update", "delete"] }'
    vault.admin_set_policy("policy-a", original_a)
    # 418 is not a status Vault documents for this endpoint; the client must
    # treat it as unknown rather than success or a rollbackable failure.
    vault.unknown_responses = {("put", "policy-b"): 418}
    result = make_batch(vault).apply_policy_batch(
        [
            ("policy-a", TIGHT_RULES_A),
            ("policy-b", TIGHT_RULES_B),
        ]
    )
    print_final_states(vault, result)
    by_name = {r.name: r for r in result.results}
    assert result.status == "unknown"
    assert result.readback_required
    assert by_name["policy-b"].apply_status == "apply_unknown"
    assert by_name["policy-b"].readback_advised
    # The already applied policy-a is NOT rolled back automatically.
    assert by_name["policy-a"].rollback_status == "rollback_not_attempted"
    assert vault.snapshot()["policy-a"] == TIGHT_RULES_A
    print(
        "\nManual recovery: inspect the flagged policies with sys.read_policy, "
        "then call\nrollback_policy_batch(result) once their real state is "
        "known and it is safe to revert."
    )
    reverted = make_batch(vault).rollback_policy_batch(result)
    reverted_by_name = {r.name: r for r in reverted.results}
    assert reverted_by_name["policy-a"].rollback_status == "restored"
    assert vault.snapshot()["policy-a"] == original_a
    print("-- after explicit rollback_policy_batch, policy-a is restored:")
    print("    policy-a -> %s" % vault.snapshot()["policy-a"])


def main():
    scenario_create_and_replace()
    scenario_write_failure_with_rollback()
    scenario_other_admin_takes_over()
    scenario_unknown_response()
    print("\nAll scenarios completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
