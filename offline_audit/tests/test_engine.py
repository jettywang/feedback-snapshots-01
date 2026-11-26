import os

import pytest

from auditlab.engine import (
    _iam_glob,
    action_matches,
    arn_matches,
    evaluate_conditions,
    load_bundle,
    run,
    Statement,
)

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY_DIR = os.path.join(HERE, "..", "auditlab", "policies")
TARGETS = os.path.join(POLICY_DIR, "..", "targets.json")


def _manifest(name):
    return os.path.join(POLICY_DIR, name, "manifest.json")


def test_iam_glob_star_matches_path_separators():
    assert _iam_glob("log-group:/ci/*", "log-group:/ci/deployer/x")
    assert _iam_glob("arn*", "arn:aws:s3:::bucket/object")
    assert not _iam_glob("a/b/*", "x/b/c")


def test_arn_matches_resource_level_and_wildcard():
    pattern = "arn:aws:logs:us-east-1:1:log-group:/ci/deployer:*"
    resource = "arn:aws:logs:us-east-1:1:log-group:/ci/deployer:log-stream:web"
    assert arn_matches(pattern, resource)
    assert arn_matches("*", "arn:aws:s3:::anything")
    assert not arn_matches(
        "arn:aws:s3:::bucket/uploads/*", "arn:aws:s3:::other/object")


def test_action_matches_wildcard_expands_via_policy_sentry():
    assert action_matches("s3:GetObject", "s3:getobject")
    assert action_matches("s3:*", "s3:GetObject")
    assert not action_matches("s3:GetObject", "s3:PutObject")


def test_condition_indeterminate_when_value_missing():
    stmt = Statement("src", "boundary", True, "s", "Allow", ["s3:GetObject"],
                     ["*"], {"aws:ResourceTag/env": {
                         "operator": "StringEquals", "operands": ["prod"]}})
    state, evidence = evaluate_conditions(stmt, {"action": "s3:GetObject",
                                                 "request_context": {},
                                                 "resource_facts": {"tags": {}}})
    assert state == "indeterminate"
    assert evidence[0]["status"] == "INDETERMINATE"


def test_condition_satisfied_from_resource_tag():
    stmt = Statement("src", "boundary", True, "s", "Allow", ["s3:GetObject"],
                     ["*"], {"aws:ResourceTag/env": {
                         "operator": "StringEquals", "operands": ["prod"]}})
    state, evidence = evaluate_conditions(
        stmt, {"action": "s3:GetObject", "request_context": {},
               "resource_facts": {"tags": {"env": "prod"}}})
    assert state == "satisfied"
    assert evidence[0]["status"] == "SATISFIED"


def test_unknown_condition_key_is_indeterminate():
    stmt = Statement("src", "inline", True, "s", "Allow", ["s3:GetObject"],
                     ["*"], {"s3:NotARealKey": {
                         "operator": "StringEquals", "operands": ["v"]}})
    state, evidence = evaluate_conditions(
        stmt, {"action": "s3:GetObject", "request_context": {},
               "resource_facts": {}})
    assert state == "indeterminate"
    assert "not recognised" in evidence[0]["reason"]


@pytest.fixture(scope="module")
def incomplete():
    return run(_manifest("missing-attached"), TARGETS)


@pytest.fixture(scope="module")
def complete():
    return run(_manifest("complete"), TARGETS)


def _by_id(report):
    return {r["target_id"]: r for r in report["results"]}


def test_incomplete_snapshot_has_all_required_verdict_shapes(incomplete):
    rows = _by_id(incomplete)
    assert rows["T1"]["verdict"] == "DENY_EXPLICIT"
    assert rows["T1"]["determined"] is True
    assert rows["T2"]["verdict"] == "ALLOW_EFFECTIVE"
    assert rows["T5"]["verdict"] == "ALLOW_EFFECTIVE"
    assert rows["T3"]["verdict"] == "PENDING_MISSING_DATA"
    assert rows["T4"]["verdict"] == "PENDING_MISSING_DATA"
    assert rows["T6"]["verdict"] == "PENDING_CONDITION"
    assert rows["T7"]["verdict"] == "PENDING_CONDITION"
    assert rows["T8"]["verdict"] == "IMPLICIT_DENY"


def test_pending_missing_names_input_and_scope(incomplete):
    row = _by_id(incomplete)["T3"]
    gap = row["relevant_gaps"][0]
    assert gap["input"] == "LogsAndSsmPolicy"
    assert "logs:CreateLogStream" in gap["scope"]


def test_condition_pending_names_boundary_and_range(incomplete):
    row = _by_id(incomplete)["T6"]
    gap = row["relevant_gaps"][0]
    assert gap["input"] == "CiArtifactDeployerBoundary"
    assert "s3:PutObject" in gap["scope"]
    assert row["indeterminate_conditions"][0]["evidence"][0][
        "condition_key"] == "aws:ResourceTag/env"


def test_completing_attachment_only_changes_related_targets(incomplete, complete):
    before, after = _by_id(incomplete), _by_id(complete)
    changed = [tid for tid in before if before[tid]["verdict"] != after[tid]["verdict"]]
    assert sorted(changed) == ["T3", "T4"]
    assert after["T3"]["verdict"] == "ALLOW_EFFECTIVE"
    assert after["T4"]["verdict"] == "ALLOW_EFFECTIVE"
    # Determined results and condition-pending results remain untouched.
    for tid in ("T1", "T2", "T5", "T6", "T7", "T8"):
        assert before[tid]["verdict"] == after[tid]["verdict"]


def test_individual_policies_remain_independently_loadable():
    bundle = load_bundle(_manifest("complete"))
    sources = {stmt.source for stmt in bundle.statements}
    assert {
        "inline-ci-artifact-deployer",
        "ArtifactsReadPolicy",
        "LogsAndSsmPolicy",
        "CiArtifactDeployerBoundary",
    }.issubset(sources)
