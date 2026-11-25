from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from gitlab.approval_snapshot import ApprovalSnapshot, export_approval
from gitlab.base import RESTManager, RESTObject
from gitlab.exceptions import GitlabGetError
from gitlab.mixins import RefreshMixin
from gitlab.snapshots import SOURCE_PARENT, SOURCE_PENDING, SOURCE_SERVER


class SyntheticAccessToken(RefreshMixin, RESTObject):
    pass


class SyntheticAccessTokenManager(RESTManager[SyntheticAccessToken]):
    _path = "/projects/{project_id}/access_tokens"
    _obj_cls = SyntheticAccessToken
    _from_parent_attrs = {"project_id": "id"}


def make_token(project_id: int, gl: Mock) -> SyntheticAccessToken:
    manager = SyntheticAccessTokenManager(gl, parent=SimpleNamespace(id=project_id))
    return SyntheticAccessToken(
        manager,
        {
            "id": 42,
            "name": "shared-approval-token",
            "token": f"one-time-value-{project_id}",
            "configuration": {
                "mode": "server",
                "nested": {"enabled": True, "approvers": ["server"]},
            },
        },
    )


ALLOWED_FIELDS = ("id", "name", "project_id", "configuration")


def test_approval_snapshot_freezes_sources_and_parent_context() -> None:
    gl_one = Mock()
    gl_two = Mock()
    token_one = make_token(1001, gl_one)
    token_two = make_token(2002, gl_two)

    token_one.configuration = {
        "mode": "pending",
        "nested": {"enabled": False, "approvers": ["alice"]},
    }
    token_two.configuration = {
        "mode": "pending-two",
        "nested": {"enabled": None, "approvers": ["bob"]},
    }

    snapshot_one = token_one.approval_snapshot(ALLOWED_FIELDS)
    snapshot_two = export_approval(token_two, allowed_fields=ALLOWED_FIELDS)

    first_document = snapshot_one.read()
    second_document = snapshot_one.read()
    assert first_document == second_document
    assert json.loads(snapshot_one.to_json()) == first_document

    assert first_document["values"]["project_id"] == "1001"
    assert snapshot_two["values"]["project_id"] == "2002"
    assert first_document["values"]["name"] == second_document["values"]["name"]
    assert first_document["state_id"] != snapshot_two["state_id"]

    assert first_document["sources"]["id"] == SOURCE_SERVER
    assert first_document["sources"]["name"] == SOURCE_SERVER
    assert first_document["sources"]["project_id"] == SOURCE_PARENT
    assert first_document["sources"]["configuration"] == SOURCE_PENDING
    assert first_document["sources"]["configuration.nested.enabled"] == SOURCE_PENDING
    assert first_document["values"]["configuration"]["nested"]["enabled"] is False

    # The one-time business value remains available through the original API.
    assert token_one.token == "one-time-value-1001"
    assert token_two.token == "one-time-value-2002"

    exported_json = snapshot_one.to_json() + snapshot_two.to_json()
    assert "one-time-value-1001" not in exported_json
    assert "one-time-value-2002" not in exported_json
    assert set(first_document["values"]) == set(ALLOWED_FIELDS)


def test_snapshot_survives_mutation_failed_refresh_retry_and_discard() -> None:
    gl_one = Mock()
    gl_two = Mock()
    token_one = make_token(1001, gl_one)
    token_two = make_token(2002, gl_two)

    pending_config_one = {
        "mode": "pending",
        "nested": {"enabled": False, "approvers": ["alice"]},
    }
    pending_config_two = {
        "mode": "pending-two",
        "nested": {"enabled": None, "approvers": ["bob"]},
    }
    token_one.configuration = pending_config_one
    token_two.configuration = pending_config_two

    snapshot_one = ApprovalSnapshot.capture(token_one, ALLOWED_FIELDS)
    snapshot_two = ApprovalSnapshot.capture(token_two, ALLOWED_FIELDS)
    old_state_one = snapshot_one.state_id
    old_revision_one = snapshot_one.object_revision

    # Mutating both the top-level object and captured nested structures cannot
    # change the approval evidence.
    token_one.name = "locally-renamed"
    pending_config_one["nested"]["enabled"] = True
    token_one.configuration["nested"]["approvers"].append("mallory")

    gl_one.http_get.side_effect = GitlabGetError("temporary failure")
    with pytest.raises(GitlabGetError):
        token_one.refresh()

    assert token_one.name == "locally-renamed"
    assert snapshot_one.read()["values"]["name"] == "shared-approval-token"
    assert snapshot_one.read()["values"]["configuration"]["nested"]["enabled"] is False
    assert snapshot_one.state_id == old_state_one
    assert snapshot_one.object_revision == old_revision_one

    server_response = {
        "id": 42,
        "name": "shared-approval-token",
        "token": "one-time-value-1001",
        "configuration": {
            "mode": "server-after-retry",
            "nested": {"enabled": True, "approvers": ["server", "carol"]},
        },
    }
    gl_one.http_get.side_effect = None
    gl_one.http_get.return_value = server_response
    token_one.refresh()

    assert token_one.configuration["mode"] == "server-after-retry"
    assert token_one.configuration["nested"]["approvers"] == ["server", "carol"]
    assert token_one.token == "one-time-value-1001"
    assert snapshot_one.state_id == old_state_one
    repeated_document = snapshot_one.read()
    assert repeated_document["values"]["configuration"] == {
        "mode": "pending",
        "nested": {"enabled": False, "approvers": ["alice"]},
    }
    assert (
        repeated_document["sources"]["configuration.nested.approvers.0"]
        == SOURCE_PENDING
    )

    # Discarding the second object's pending updates restores server state for
    # business callers but does not rewrite its old approval snapshot.
    token_two.discard_updates()
    assert token_two.configuration["mode"] == "server"
    assert token_two._updated_attrs == {}
    assert snapshot_two.read()["values"]["configuration"] == pending_config_two
    assert snapshot_two.read()["sources"]["configuration"] == SOURCE_PENDING

    # Re-reading and re-exporting the old snapshot remains stable.
    assert snapshot_one.read() == repeated_document
    assert snapshot_one.export().to_dict() == repeated_document
    assert json.loads(snapshot_one.to_json()) == repeated_document


def test_safe_export_supports_dotted_nested_allowlist() -> None:
    token = make_token(3003, Mock())
    token.configuration = {
        "mode": "pending",
        "nested": {"enabled": False, "approvers": ["alice"]},
    }

    document = token.safe_export(
        allowed_fields=("name", "project_id", "configuration.nested.enabled")
    )

    assert document["name"] == "shared-approval-token"
    assert document["project_id"] == "3003"
    assert document["values"]["configuration"] == {"nested": {"enabled": False}}
    assert "mode" not in json.dumps(document["values"])
    assert document["sources"]["configuration.nested.enabled"] == "pending"

    alias_document = token.safe_export(allowlist=("name",))
    assert alias_document["data"] == {"name": "shared-approval-token"}
