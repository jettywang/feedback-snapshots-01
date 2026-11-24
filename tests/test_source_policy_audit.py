from __future__ import annotations

import copy

from dynaconf import Dynaconf
from dynaconf import FieldSourcePolicy
from dynaconf.loaders.base import SourceMetadata


def make_settings(**kwargs):
    options = {
        "dynaconf_skip_loaders": True,
        "environments": False,
        "load_dotenv": False,
    }
    options.update(kwargs)
    return Dynaconf(**options)


def test_nested_merge_splits_accepted_child_and_pending_sibling():
    events = []
    settings = make_settings(
        audit_sink=events,
        source_policies={
            "FEATURE": {"allowed_sources": ["baseline"]},
            "FEATURE.TIMEOUT": {
                "allowed_sources": ["baseline", "ops-source"]
            },
        },
    )

    settings.set(
        "FEATURE",
        {"timeout": 30, "admin": False},
        loader_identifier="baseline",
    )
    settings.set(
        "FEATURE",
        {"timeout": 5, "admin": True},
        loader_identifier="ops-source",
        merge=True,
    )

    assert settings.FEATURE.timeout == 5
    assert settings.FEATURE.admin is False

    latest_batch = settings.audit.batches[-1]
    assert latest_batch["status"] == "partially_pending"
    assert latest_batch["accepted_count"] == 1
    assert latest_batch["pending_count"] == 1

    pending = settings.pending_updates
    assert len(pending) == 1
    record = pending[0]
    assert record.field == "FEATURE.admin"
    assert record.root_key == "FEATURE"
    assert record.source == "ops-source"
    assert record.status == "pending"
    assert record.candidate_value is True
    assert record.effective_value is False
    assert record.previous_value is False
    assert record.fallback_value is False
    assert record.approved_value is False
    assert settings.audit.fallback_for("FEATURE.admin") is False
    assert "not in allowed sources" in record.message

    ops_accepted = [
        item
        for item in settings.accepted_updates
        if item.source == "ops-source" and item.status == "accepted"
    ]
    assert [(item.field, item.effective_value) for item in ops_accepted] == [
        ("FEATURE.timeout", 5)
    ]

    assert events
    assert events[-1]["status"] == "pending"
    assert events[-1]["field"] == "FEATURE.admin"

    explanation = settings.audit.explain("FEATURE")
    assert "FEATURE.timeout" in explanation
    assert "FEATURE.admin" in explanation
    assert "ops-source" in explanation


def test_merged_candidate_without_actual_change_is_not_pending():
    settings = make_settings(
        source_policies={"OUTER": {"allowed_sources": ["approved"]}}
    )

    settings.set(
        "OUTER",
        {"same": "kept", "changed": "old"},
        loader_identifier="approved",
    )
    settings.set(
        "OUTER",
        {"same": "kept", "changed": "new"},
        loader_identifier="unapproved",
        merge=True,
    )

    assert settings.OUTER.same == "kept"
    assert settings.OUTER.changed == "old"
    assert len(settings.pending_updates) == 1
    assert settings.pending_updates[0].field == "OUTER.changed"

    unchanged = [
        item
        for item in settings.audit.trace
        if item["status"] == "unchanged" and item["field"] == "OUTER.same"
    ]
    assert len(unchanged) == 1
    assert "equals active value" in unchanged[0]["reason"]


def test_pending_value_keeps_approved_version_and_can_be_approved():
    settings = make_settings(
        source_policies=[
            FieldSourcePolicy(
                "RELEASE",
                allowed_sources=["release-bot"],
            )
        ]
    )

    settings.set(
        "RELEASE",
        {"version": "1.4.2", "mode": "stable"},
        loader_identifier="release-bot",
    )
    first_version = settings.audit.current_version
    first_snapshot = copy.deepcopy(
        settings.audit.versions[-1]["snapshot"]
    )

    settings.set(
        "RELEASE",
        {"version": "1.5.0", "mode": "canary"},
        loader_identifier="unknown-webhook",
        merge=True,
    )

    assert settings.RELEASE.version == "1.4.2"
    assert settings.RELEASE.mode == "stable"
    assert settings.audit.current_version == first_version
    assert len(settings.pending_updates) == 2

    pending_id = next(
        item.id
        for item in settings.pending_updates
        if item.field == "RELEASE.version"
    )
    approved_record = settings.approve_update(
        pending_id, reviewer="sre-oncall"
    )

    assert approved_record.status == "approved"
    assert approved_record.reviewer == "sre-oncall"
    assert settings.RELEASE.version == "1.5.0"
    assert settings.RELEASE.mode == "stable"
    assert not any(
        item.field == "RELEASE.version"
        for item in settings.pending_updates
    )
    assert any(
        item.reason_code == "approved_pending_update"
        and item.approval_for == pending_id
        for item in settings.audit.records
    )

    assert first_snapshot["RELEASE"]["version"] == "1.4.2"
    assert first_snapshot["RELEASE"]["mode"] == "stable"
    assert settings.audit.versions[0]["snapshot"] == first_snapshot


def test_blocked_new_root_value_is_not_published():
    settings = make_settings(
        source_policies={"ROOT_ONLY_SECRET": ["vault", "ci"]}
    )

    settings.set(
        "ROOT_ONLY_SECRET",
        "from-evil-source",
        loader_identifier="public-form",
    )

    assert settings.get("ROOT_ONLY_SECRET") is None
    pending = settings.pending_updates
    assert len(pending) == 1
    assert pending[0].field == "ROOT_ONLY_SECRET"
    assert pending[0].fallback_value is None
    assert settings.audit.summary()["pending"] == 1


def test_source_metadata_loader_and_environment_are_matched():
    settings = make_settings(
        source_policies={
            "DB": {
                "allowed_sources": [
                    "yaml:secure.yaml:production",
                    "vault",
                ]
            }
        }
    )
    secure_metadata = SourceMetadata(
        loader="yaml",
        identifier="/etc/dynaconf/secure.yaml",
        env="production",
    )
    other_env_metadata = SourceMetadata(
        loader="yaml",
        identifier="/etc/dynaconf/secure.yaml",
        env="development",
    )

    settings.set("DB", {"host": "db.internal"}, secure_metadata)
    assert settings.DB.host == "db.internal"
    assert len(settings.accepted_updates) == 1

    settings.set("DB", {"password": "new"}, other_env_metadata, merge=True)
    assert settings.get("DB.password") is None
    assert len(settings.pending_updates) == 1
    assert settings.pending_updates[0].source_metadata["env"] == "development"


def test_yaml_loader_plugin_uses_file_identity(tmp_path):
    baseline = tmp_path / "baseline.yaml"
    candidate = tmp_path / "candidate.yaml"
    baseline.write_text(
        "security:\n  timeout: 30\n  admin: false\n",
        encoding="utf-8",
    )
    candidate.write_text(
        "dynaconf_merge: true\n"
        "security:\n  timeout: 5\n  admin: true\n",
        encoding="utf-8",
    )

    settings = Dynaconf(
        settings_files=[str(baseline), str(candidate)],
        environments=False,
        load_dotenv=False,
        source_policies={
            "SECURITY": ["baseline.yaml"],
            "SECURITY.TIMEOUT": ["baseline.yaml", "candidate.yaml"],
        },
    )

    assert settings.security.timeout == 5
    assert settings.security.admin is False
    pending = settings.pending_updates
    assert len(pending) == 1
    assert pending[0].field == "SECURITY.admin"
    assert pending[0].source.endswith("candidate.yaml")
    assert pending[0].effective_value is False


def test_audit_record_supports_mapping_and_structured_export():
    sink = []
    settings = make_settings(
        audit_sink=sink,
        source_policies={"PROTECTED": ["allowed-source"]},
    )
    settings.set("PROTECTED", "value", loader_identifier="allowed-source")

    record = settings.audit.records[-1]
    assert record["field"] == "PROTECTED"
    assert record.get("status") == "accepted"
    exported = settings.audit.export()
    assert exported[-1]["field"] == "PROTECTED"
    assert settings.audit.to_json().startswith("[")
    assert sink[-1]["field"] == "PROTECTED"
