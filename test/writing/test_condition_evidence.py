"""Regression tests for approval condition evidence and publication gating."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from policy_sentry.approval.condition_evidence import generate_condition_evidence
from policy_sentry.shared import iam_data

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "files" / "condition_evidence"


@pytest.fixture(scope="module")
def request_data() -> dict:
    return json.loads((FIXTURE_DIR / "request.json").read_text(encoding="utf-8"))


def _generate(request_data: dict, scenario: str) -> dict:
    return generate_condition_evidence(
        request_data["template"],
        request_data["condition_block"],
        overlay=FIXTURE_DIR / "overlays" / f"{scenario}.json",
    )


def test_full_support_is_publishable_and_every_statement_has_condition(
    request_data: dict,
) -> None:
    report = _generate(request_data, "full-support")

    assert report["release_status"] == "publishable"
    assert report["publishable"] is True
    assert report["condition_compiler"] == "SidGroup.get_rendered_policy"
    assert report["publishable_policy"] == report["rendered_policy"]
    assert report["summary"]["statements"] == 2
    assert report["summary"]["covered"] == 2
    assert report["summary"]["blocked"] == 0

    expected_condition = {
        "StringEquals": {"aws:ResourceTag/Project": "proj-approved-204"}
    }
    for statement in report["rendered_policy"]["Statement"]:
        assert statement["Condition"] == expected_condition

    resource_types = {item["resource_type"] for item in report["items"]}
    assert resource_types == {"application-inference-profile", "inference-profile"}
    assert all(item["status"] == "covered" for item in report["items"])


def test_primary_only_does_not_publish_unconstrained_second_statement(
    request_data: dict,
) -> None:
    report = _generate(request_data, "primary-only")

    assert report["release_status"] == "blocked_needs_evidence"
    assert report["publishable"] is False
    assert report["publishable_policy"] is None
    assert report["summary"]["covered"] == 1
    assert report["summary"]["known_unsupported"] == 1

    covered = next(
        item
        for item in report["items"]
        if item["resource_type"] == "application-inference-profile"
    )
    blocked = next(
        item for item in report["items"] if item["resource_type"] == "inference-profile"
    )

    assert covered["status"] == "covered"
    assert covered["statement_index"] == 0
    assert covered["condition_enforced"] is True
    assert blocked["support_status"] == "known_unsupported"
    assert blocked["reason_code"] == "catalog_reports_unsupported"
    assert blocked["status"] == "catalog_unsupported_uncovered"
    assert blocked["condition_enforced"] is False
    assert "补偿控制证据" in blocked["required_evidence"]

    statements = report["rendered_policy"]["Statement"]
    assert "Condition" in statements[covered["statement_index"]]
    assert "Condition" not in statements[blocked["statement_index"]]
    assert report["required_evidence"][0]["sid"] == blocked["sid"]


def test_old_catalog_gap_is_unverifiable_not_known_unsupported(
    request_data: dict,
) -> None:
    report = _generate(request_data, "old-missing")

    assert report["release_status"] == "blocked_needs_evidence"
    assert report["publishable_policy"] is None
    assert report["summary"]["unverifiable"] == 1
    assert report["summary"]["known_unsupported"] == 0

    blocked = next(
        item for item in report["items"] if item["resource_type"] == "inference-profile"
    )
    assert blocked["support_status"] == "unverifiable"
    assert blocked["reason_code"] == "catalog_condition_field_missing"
    assert blocked["status"] == "unverifiable_uncovered"
    assert "目录缺项/资源证据" in blocked["required_evidence"]

    primary = next(
        item
        for item in report["items"]
        if item["resource_type"] == "application-inference-profile"
    )
    assert primary["status"] == "covered"


def test_every_evidence_item_points_to_exact_rendered_statement(
    request_data: dict,
) -> None:
    report = _generate(request_data, "primary-only")

    for item in report["items"]:
        statement = report["rendered_policy"]["Statement"][item["statement_index"]]
        assert statement["Sid"] == item["sid"]
        assert item["action"] in statement["Action"]
        assert item["resource"] in statement["Resource"]
        assert item["actual_statement_condition"] == statement.get("Condition")


def test_catalog_context_restores_bundled_global(request_data: dict) -> None:
    original_catalog = iam_data.iam_definition
    _generate(request_data, "old-missing")
    assert iam_data.iam_definition is original_catalog

    from policy_sentry.querying.all import get_all_service_prefixes

    assert "bedrock" in get_all_service_prefixes()


def test_missing_full_resource_record_is_unknown_not_unsupported(request_data: dict) -> None:
    full_report = _generate(request_data, "full-support")
    old_catalog = {
        "bedrock": {
            "resources": {"inference-profile": None},
        }
    }

    from policy_sentry.approval.condition_evidence import (
        build_condition_evidence_report,
        prepare_catalog,
    )

    catalog = prepare_catalog(None, old_catalog)
    report = build_condition_evidence_report(
        full_report["base_policy"],
        request_data["condition_block"],
        catalog=catalog,
    )

    blocked = next(
        item for item in report["items"] if item["sid"] == "BedrockReadInferenceprofile"
    )
    assert report["publishable"] is False
    assert blocked["support_status"] == "unverifiable"
    assert blocked["reason_code"] == "catalog_record_missing"
    assert report["publishable_policy"] is None
