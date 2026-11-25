from __future__ import annotations

import pytest

from hatchling.builders.approval import (
    ApprovalController,
    ApprovalPolicy,
    ApprovedList,
    ApprovedMapping,
    HookApprovalError,
    ManagedBuildData,
    OPERATION_ADD,
    OPERATION_CLEAN,
    OPERATION_RELOCATE,
)


def make_controller(config: dict | None = None) -> ApprovalController:
    policy = ApprovalPolicy.from_config(
        config
        or {
            "approvals": {
                "add": ["allowed/a.txt", {"path": "data/x.txt", "source": "x.txt"}],
                "relocate": [{"path": "moved/x.txt", "source": "x.txt"}],
                "clean": ["allowed/a.txt"],
            }
        }
    )
    return ApprovalController("wheel", "standard", {"custom": policy})


def test_policy_rejects_non_table_approvals():
    with pytest.raises(TypeError, match="`approvals` must be a table"):
        ApprovalPolicy.from_config({"approvals": []})


def test_policy_rejects_non_list_bucket():
    with pytest.raises(TypeError, match="`add` must be an array"):
        ApprovalPolicy.from_config({"approvals": {"add": "nope"}})


def test_policy_rejects_empty_string_entry():
    with pytest.raises(ValueError, match="cannot be an empty string"):
        ApprovalPolicy.from_config({"approvals": {"add": [""]}})


def test_policy_rejects_table_without_path():
    with pytest.raises(ValueError, match="requires a non-empty `path`"):
        ApprovalPolicy.from_config({"approvals": {"add": [{"source": "x"}]}})


def test_mapping_add_relocate_clean_and_denial():
    controller = make_controller()
    mapping = ApprovedMapping("force_include", controller, {})
    controller.current_hook = "custom"

    mapping["/tmp/x.txt"] = "data/x.txt"
    mapping["/tmp/x.txt"] = "moved/x.txt"
    assert mapping == {"/tmp/x.txt": "moved/x.txt"}

    with pytest.raises(HookApprovalError, match="not approved to add"):
        mapping["/tmp/secret.txt"] = "secret.txt"

    with pytest.raises(HookApprovalError, match="not approved to clean"):
        del mapping["/tmp/x.txt"]

    kinds = [operation.kind for operation in controller.receipt.operations]
    assert kinds == [OPERATION_ADD, OPERATION_RELOCATE, OPERATION_ADD, OPERATION_CLEAN]
    assert [operation.applied for operation in controller.receipt.operations] == [True, True, False, False]


def test_list_operations_are_gated():
    controller = make_controller()
    members = ApprovedList("artifacts", controller, [])
    controller.current_hook = "custom"

    members.append("allowed/a.txt")
    members.extend(["allowed/a.txt"])
    assert members == ["allowed/a.txt", "allowed/a.txt"]

    members.remove("allowed/a.txt")
    with pytest.raises(HookApprovalError, match="not approved to add"):
        members.append("forbidden/b.txt")

    recorded = [(operation.kind, operation.applied) for operation in controller.receipt.operations]
    assert recorded == [
        (OPERATION_ADD, True),
        (OPERATION_ADD, True),
        (OPERATION_CLEAN, True),
        (OPERATION_ADD, False),
    ]


def test_unmanaged_hook_is_always_allowed():
    controller = make_controller()
    mapping = ApprovedMapping("force_include", controller, {})
    controller.current_hook = "third-party"

    mapping["/tmp/anything.txt"] = "anything.txt"
    del mapping["/tmp/anything.txt"]

    assert all(operation.managed is False and operation.applied for operation in controller.receipt.operations)


def test_managed_build_data_wraps_guarded_fields_only():
    controller = make_controller()
    data = ManagedBuildData(
        {
            "artifacts": [],
            "force_include": {},
            "dependencies": [],
            "pure_python": True,
            "build_hooks": ("custom",),
        },
        controller,
    )

    assert isinstance(data["artifacts"], ApprovedList)
    assert isinstance(data["force_include"], ApprovedMapping)
    # Non-membership fields keep their ordinary type and are not gated.
    assert data["dependencies"] == []
    data["dependencies"].append("some-dependency")
    assert not any(operation.field == "dependencies" for operation in controller.receipt.operations)

    snapshot = data.snapshot()
    assert set(snapshot) >= {"artifacts", "force_include"}
    assert "dependencies" not in snapshot


def test_receipt_records_failure_status():
    controller = make_controller()
    controller.receipt.mark_failed(ValueError("boom"))
    assert controller.receipt.status == "failed"
    assert controller.receipt.error == "boom"
    assert controller.receipt.as_dict()["status"] == "failed"


def test_denied_mutation_leaves_data_unchanged():
    controller = make_controller()
    mapping = ApprovedMapping("force_include", controller, {})
    controller.current_hook = "custom"

    mapping["/tmp/x.txt"] = "data/x.txt"

    with pytest.raises(HookApprovalError):
        del mapping["/tmp/x.txt"]

    # The denied removal did not mutate the mapping.
    assert mapping == {"/tmp/x.txt": "data/x.txt"}

    members = ApprovedList("artifacts", controller, ["allowed/a.txt"])
    with pytest.raises(HookApprovalError):
        members.remove("forbidden/b.txt")

    assert members == ["allowed/a.txt"]
