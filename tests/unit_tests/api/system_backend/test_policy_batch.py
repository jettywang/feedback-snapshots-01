import json

import pytest

from hvac.api.system_backend.policy_batch import (
    APPLY_APPLIED,
    APPLY_CONFLICT,
    APPLY_ERROR,
    APPLY_UNKNOWN,
    BATCH_FAILED,
    BATCH_SUCCEEDED,
    BATCH_UNKNOWN,
    EVIDENCE_ERROR,
    EVIDENCE_UNKNOWN,
    PolicyBatch,
    PolicyBatchResult,
    ROLLBACK_DELETED,
    ROLLBACK_NOT_ATTEMPTED,
    ROLLBACK_RESTORED,
    ROLLBACK_SKIPPED,
)
from hvac.exceptions import ParamValidationError


class FakeResponse:
    def __init__(self, status_code, body=None, text=None):
        self.status_code = status_code
        self._body = body
        self.text = text if text is not None else json.dumps(body or {})

    def json(self):
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body


class FakeVaultAdapter:
    """Scripted, in-memory adapter mimicking /sys/policy semantics."""

    def __init__(self, store=None, json_200=False):
        self.store = store if store is not None else {}
        self.json_200 = json_200
        self.fail_puts = {}
        self.unknown = {}
        self.apply_phase = False
        self.before_apply_read = {}
        self._read_counts = {}
        self.calls = []

    def request(self, method, url, raise_exception=True, **kwargs):
        self.calls.append((method, url, dict(kwargs, raise_exception=raise_exception)))
        name = url.rsplit("/", 1)[-1]
        if method == "put":
            self.apply_phase = True
        if method == "get":
            self._read_counts[name] = self._read_counts.get(name, 0) + 1
            # The second read of a policy is its pre-write/rollback check.
            if self._read_counts[name] == 2:
                hook = self.before_apply_read.pop(name, None)
                if hook is not None:
                    hook()
        scripted = self.unknown.pop((method, name), None)
        if scripted is not None:
            return FakeResponse(scripted, text="unclassifiable gateway response")
        if method == "get":
            if name not in self.store:
                return FakeResponse(404, {"errors": ["no such policy"]})
            body = {"data": {"name": name, "rules": self.store[name]}}
            return body if self.json_200 else FakeResponse(200, body)
        if method == "put":
            failure = self.fail_puts.pop(name, None)
            if failure is not None:
                return FakeResponse(failure, {"errors": ["write rejected"]})
            self.store[name] = kwargs["json"]["policy"]
            return FakeResponse(204)
        if method == "delete":
            self.store.pop(name, None)
            return FakeResponse(204)
        return FakeResponse(405, {"errors": ["unsupported"]})


@pytest.fixture
def adapter():
    return FakeVaultAdapter()


@pytest.fixture
def batch(adapter):
    return PolicyBatch(adapter=adapter)


ORIGINAL_A = 'path "a" { capabilities = ["create", "read", "update"] }'
ORIGINAL_B = 'path "b" { capabilities = ["create", "read"] }'
TIGHT_A = 'path "a" { capabilities = ["read"] }'
TIGHT_B = 'path "b" { capabilities = ["read"] }'
TIGHT_C = 'path "c" { capabilities = ["deny"] }'


def by_name(result, name):
    return next(entry for entry in result.results if entry.name == name)


class TestEvidence:
    def test_evidence_is_captured_before_any_write(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        batch.apply_policy_batch([("policy-a", TIGHT_A)])
        assert adapter.calls[0][0] == "get"
        assert all(call[0] != "put" for call in adapter.calls[:1])
        assert adapter.calls[1][0] in ("get", "put")

    def test_existing_policy_evidence_holds_rules_and_fingerprint(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        result = batch.apply_policy_batch([("policy-a", TIGHT_A)])
        evidence = by_name(result, "policy-a").evidence
        assert evidence.existed is True
        assert evidence.rules == ORIGINAL_A
        assert evidence.fingerprint
        assert evidence.captured_at

    def test_missing_policy_evidence_marks_absent_and_is_created(self, adapter, batch):
        result = batch.apply_policy_batch([("policy-new", TIGHT_C)])
        entry = by_name(result, "policy-new")
        assert entry.evidence.existed is False
        assert entry.evidence.fingerprint is None
        assert entry.apply_status == APPLY_APPLIED
        assert adapter.store["policy-new"] == TIGHT_C

    def test_evidence_read_failure_aborts_without_any_writes(self, adapter, batch):
        adapter.unknown = {("get", "policy-a"): 503}
        result = batch.apply_policy_batch([("policy-a", TIGHT_A)])
        entry = by_name(result, "policy-a")
        assert entry.apply_status == EVIDENCE_ERROR
        assert all(call[0] != "put" for call in adapter.calls)
        assert result.status == BATCH_FAILED

    def test_unknown_evidence_response_requires_readback(self, adapter, batch):
        adapter.unknown = {("get", "policy-a"): 418}
        result = batch.apply_policy_batch([("policy-a", TIGHT_A)])
        entry = by_name(result, "policy-a")
        assert entry.apply_status == EVIDENCE_UNKNOWN
        assert entry.readback_advised
        assert result.readback_required
        assert result.status == BATCH_UNKNOWN


class TestApply:
    def test_all_writes_succeed(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A, "policy-b": ORIGINAL_B}
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B), ("policy-new", TIGHT_C)]
        )
        assert result.status == BATCH_SUCCEEDED
        assert all(entry.apply_status == APPLY_APPLIED for entry in result.results)
        assert adapter.store["policy-a"] == TIGHT_A
        assert adapter.store["policy-b"] == TIGHT_B
        assert adapter.store["policy-new"] == TIGHT_C

    def test_dict_policy_is_serialized_as_json(self, adapter, batch):
        desired = {"path": {"a": {"capabilities": ["read"]}}}
        batch.apply_policy_batch([("policy-a", desired)])
        assert json.loads(adapter.store["policy-a"]) == desired

    def test_dict_and_tuple_change_shapes_are_accepted(self, adapter, batch):
        result = batch.apply_policy_batch(
            [{"name": "policy-a", "policy": TIGHT_A}, ("policy-b", TIGHT_B)]
        )
        assert {entry.name for entry in result.results} == {"policy-a", "policy-b"}

    def test_known_write_failure_triggers_conditional_rollback(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A, "policy-b": ORIGINAL_B}
        adapter.fail_puts = {"policy-c": 400}
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B), ("policy-c", TIGHT_C)]
        )
        assert result.status == BATCH_FAILED
        assert by_name(result, "policy-c").apply_status == APPLY_ERROR
        assert by_name(result, "policy-a").rollback_status == ROLLBACK_RESTORED
        assert by_name(result, "policy-b").rollback_status == ROLLBACK_RESTORED
        assert adapter.store["policy-a"] == ORIGINAL_A
        assert adapter.store["policy-b"] == ORIGINAL_B
        assert "policy-c" not in adapter.store

    def test_rollback_can_be_disabled(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        adapter.fail_puts = {"policy-b": 500}
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B)],
            rollback_on_failure=False,
        )
        assert result.status == BATCH_FAILED
        assert by_name(result, "policy-a").rollback_status == ROLLBACK_NOT_ATTEMPTED
        assert adapter.store["policy-a"] == TIGHT_A

    def test_rollback_deletes_policy_that_did_not_exist_at_evidence(self, adapter, batch):
        adapter.fail_puts = {"policy-b": 403}
        result = batch.apply_policy_batch(
            [("policy-new", TIGHT_C), ("policy-b", TIGHT_B)]
        )
        entry = by_name(result, "policy-new")
        assert entry.rollback_status == ROLLBACK_DELETED
        assert "policy-new" not in adapter.store

    def test_other_admin_change_is_detected_and_write_skipped(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A, "policy-b": ORIGINAL_B}
        adapter.fail_puts = {"policy-c": 500}
        adapter.before_apply_read = {
            "policy-b": lambda: adapter.store.__setitem__("policy-b", 'path "b" { capabilities = ["sudo"] }')
        }
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B), ("policy-c", TIGHT_C)]
        )
        entry_b = by_name(result, "policy-b")
        assert entry_b.apply_status == APPLY_CONFLICT
        assert adapter.store["policy-b"] == 'path "b" { capabilities = ["sudo"] }'
        # The applied policy-a still reverts; policy-b was never ours to undo.
        assert by_name(result, "policy-a").rollback_status == ROLLBACK_RESTORED

    def test_conflict_only_batch_is_not_reported_as_succeeded(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        adapter.before_apply_read = {
            "policy-a": lambda: adapter.store.__setitem__("policy-a", 'path "a" { capabilities = ["sudo"] }')
        }
        result = batch.apply_policy_batch([("policy-a", TIGHT_A)])
        assert result.status == BATCH_FAILED
        assert by_name(result, "policy-a").final_status == "untouched_conflict"
        assert adapter.store["policy-a"] == 'path "a" { capabilities = ["sudo"] }'

    def test_rollback_skips_policy_another_admin_changed_after_our_write(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        adapter.fail_puts = {"policy-b": 500}

        real_put = adapter.request

        def request_with_takeover(method, url, **kwargs):
            response = real_put(method, url, **kwargs)
            if method == "put" and url.endswith("policy-a"):
                adapter.store["policy-a"] = 'path "a" { capabilities = ["sudo"] }'
            return response

        batch._adapter.request = request_with_takeover
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B)]
        )
        entry_a = by_name(result, "policy-a")
        assert entry_a.rollback_status == ROLLBACK_SKIPPED
        assert adapter.store["policy-a"] == 'path "a" { capabilities = ["sudo"] }'

    def test_unknown_put_status_stops_batch_without_rollback(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        adapter.unknown = {("put", "policy-b"): 418}
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B)]
        )
        assert result.status == BATCH_UNKNOWN
        assert result.readback_required
        assert by_name(result, "policy-b").apply_status == APPLY_UNKNOWN
        assert by_name(result, "policy-b").readback_advised
        assert by_name(result, "policy-a").rollback_status == ROLLBACK_NOT_ATTEMPTED
        assert adapter.store["policy-a"] == TIGHT_A

    def test_unknown_rollback_read_is_surfaced_not_guessed(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        adapter.fail_puts = {"policy-b": 500}
        real_request = adapter.request

        def policy_b_write_attempted():
            return any(
                method == "put" and url.endswith("policy-b")
                for method, url, _ in adapter.calls
            )

        def flaky_rollback_read(method, url, **kwargs):
            # Reads issued after policy-b's write failed are rollback reads.
            if (
                method == "get"
                and url.endswith("policy-a")
                and policy_b_write_attempted()
            ):
                return FakeResponse(418, text="unclassifiable")
            return real_request(method, url, **kwargs)

        adapter.request = flaky_rollback_read
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B)]
        )
        entry_a = by_name(result, "policy-a")
        assert entry_a.rollback_status not in (ROLLBACK_RESTORED, ROLLBACK_DELETED)
        assert entry_a.readback_advised
        assert result.readback_required


class TestExplicitRollback:
    def test_manual_rollback_uses_captured_evidence(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        adapter.unknown = {("put", "policy-b"): 418}
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B)]
        )
        assert adapter.store["policy-a"] == TIGHT_A
        reverted = batch.rollback_policy_batch(result)
        assert by_name(reverted, "policy-a").rollback_status == ROLLBACK_RESTORED
        assert adapter.store["policy-a"] == ORIGINAL_A

    def test_rollback_accepts_dict_form_of_result(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        adapter.unknown = {("put", "policy-b"): 418}
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B)]
        )
        reverted = batch.rollback_policy_batch(result.to_dict())
        assert by_name(reverted, "policy-a").rollback_status == ROLLBACK_RESTORED

    def test_rollback_skips_policy_taken_over_after_the_batch(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        adapter.unknown = {("put", "policy-b"): 418}
        result = batch.apply_policy_batch(
            [("policy-a", TIGHT_A), ("policy-b", TIGHT_B)]
        )
        adapter.store["policy-a"] = 'path "a" { capabilities = ["sudo"] }'
        reverted = batch.rollback_policy_batch(result)
        assert by_name(reverted, "policy-a").rollback_status == ROLLBACK_SKIPPED
        assert adapter.store["policy-a"] == 'path "a" { capabilities = ["sudo"] }'

    def test_invalid_result_input_raises(self, batch):
        with pytest.raises(ParamValidationError):
            batch.rollback_policy_batch({"unexpected": "shape"})


class TestValidation:
    @pytest.mark.parametrize(
        "changes",
        [
            [],
            [("only-name",)],
            [{"name": "policy-a"}],
            [("", TIGHT_A)],
        ],
    )
    def test_invalid_change_shapes_raise(self, batch, changes):
        with pytest.raises(ParamValidationError):
            batch.apply_policy_batch(changes)

    def test_duplicate_names_raise(self, batch):
        with pytest.raises(ParamValidationError, match="duplicate"):
            batch.apply_policy_batch([("policy-a", TIGHT_A), ("policy-a", TIGHT_B)])


class TestResultShape:
    def test_to_dict_is_json_serializable(self, adapter, batch):
        adapter.store = {"policy-a": ORIGINAL_A}
        result = batch.apply_policy_batch([("policy-a", TIGHT_A)])
        encoded = json.dumps(result.to_dict())
        decoded = json.loads(encoded)
        assert decoded["status"] == BATCH_SUCCEEDED
        assert decoded["results"][0]["final_status"] == "changed"
        assert decoded["results"][0]["evidence"]["fingerprint"]

    def test_json_adapter_200_responses_are_supported(self):
        adapter = FakeVaultAdapter(
            store={"policy-a": ORIGINAL_A}, json_200=True
        )
        result = PolicyBatch(adapter=adapter).apply_policy_batch(
            [("policy-a", TIGHT_A)]
        )
        assert result.status == BATCH_SUCCEEDED
        assert by_name(result, "policy-a").evidence.rules == ORIGINAL_A

    def test_result_is_policy_batch_result_type(self, batch):
        result = batch.apply_policy_batch([("policy-a", TIGHT_A)])
        assert isinstance(result, PolicyBatchResult)

    def test_requests_never_ask_the_adapter_to_raise(self, adapter, batch):
        batch.apply_policy_batch([("policy-a", TIGHT_A)])
        assert all(
            kwargs.get("raise_exception") is False for _, _, kwargs in adapter.calls
        )

    def test_response_without_status_code_is_treated_as_unknown(self, batch):
        class ShapelessAdapter:
            def __init__(self):
                self.calls = 0

            def request(self, method, url, raise_exception=True, **kwargs):
                self.calls += 1
                return object()

        adapter = ShapelessAdapter()
        batch_with_shapeless = PolicyBatch(adapter=adapter)
        result = batch_with_shapeless.apply_policy_batch([("policy-a", TIGHT_A)])
        entry = by_name(result, "policy-a")
        assert entry.readback_advised
        assert result.status == BATCH_UNKNOWN
        assert adapter.calls == 1
