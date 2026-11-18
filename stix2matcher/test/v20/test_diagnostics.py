import json

import pytest

from stix2matcher.matcher import (DIAG_COMPARISON_FAILED, DIAG_PATH_MISSING,
                                  DIAG_REFERENCE_UNREACHABLE,
                                  DIAG_TEMPORAL_FAILED, DIAG_TYPE_MISMATCH,
                                  DiagnosticReport, MatcherException, match,
                                  match_with_diagnostics)

_stix_version = '2.0'

# One observation containing a single file object.  Individual tests override
# the object's properties to make the same rule fail at a different stage.
_OBSERVATION = {
    "type": "observed-data",
    "id": "observed-data--11111111-1111-4111-8111-111111111111",
    "number_observed": 1,
    "first_observed": "2020-01-01T00:00:00Z",
    "last_observed": "2020-01-01T00:00:10Z",
    "objects": {
        "0": {
            "type": "file",
            "name": "alice",
            "size": 5,
        }
    }
}

# A single rule used throughout.  It covers a path, a reference hop, a type,
# an ordered comparison, and two observation expressions joined by AND.
_RULE = (
    "[file:name = 'alice' AND file:parent_ref.size > 10]"
)

_STAGE_ORDER = [
    DIAG_PATH_MISSING,
    DIAG_REFERENCE_UNREACHABLE,
    DIAG_TYPE_MISMATCH,
    DIAG_COMPARISON_FAILED,
    DIAG_TEMPORAL_FAILED,
]


def _observation(**props):
    observation = json.loads(json.dumps(_OBSERVATION))
    observation["objects"]["0"].update(props)
    return observation


def _referenced_observation(value, value_type="artifact"):
    """Observation whose file object references a second object."""
    observation = _observation(parent_ref="1")
    observation["objects"]["1"] = {
        "id": "1", "type": value_type, "size": value,
    }
    return observation


def _report(pattern, observations, version=_stix_version):
    report = match_with_diagnostics(
        pattern, observations, stix_version=version,
    )
    assert isinstance(report, DiagnosticReport)
    return report


def _single_stage(report):
    assert report["matched"] is False
    assert report["matches"] == []
    assert report["stages"], report
    assert len(report["stages"]) == 1, report["stages"]
    return report["stages"][0]


def test_diagnostic_stages_are_distinct():
    assert len(set(_STAGE_ORDER)) == len(_STAGE_ORDER)


def test_path_missing_is_reported():
    # The file has no parent_ref property at all.
    report = _report(_RULE, [_observation()])
    assert _single_stage(report) == DIAG_PATH_MISSING
    elimination = report["eliminations"][0]
    assert elimination["reason"] == "missing_key"
    assert elimination["path"] == "file:parent_ref.size"
    assert elimination["object"]["id"] == "0"
    assert elimination["observation"]["id"] == _OBSERVATION["id"]
    assert elimination["rule"]["text"]


def test_reference_unreachable_is_reported():
    # The reference target does not exist.
    report = _report(_RULE, [_observation(parent_ref="1")])
    assert _single_stage(report) == DIAG_REFERENCE_UNREACHABLE
    elimination = report["eliminations"][0]
    assert elimination["reason"] == "reference_target_absent"
    assert elimination["detail"]["reference"] == "1"
    assert elimination["object"]["id"] == "0"


def test_type_mismatch_is_reported():
    # The reference resolves, but the referenced value has the wrong type.
    report = _report(_RULE, [_referenced_observation("enormous")])
    assert _single_stage(report) == DIAG_TYPE_MISMATCH
    elimination = report["eliminations"][0]
    assert elimination["detail"]["pattern_type"] == "int"
    assert elimination["detail"]["value_type"] == "str"


def test_comparison_failed_is_reported():
    # The reference resolves and the type is right, but the value loses.
    report = _report(_RULE, [_referenced_observation(3)])
    assert _single_stage(report) == DIAG_COMPARISON_FAILED
    elimination = report["eliminations"][0]
    assert elimination["reason"] == "order_test_failed"
    assert elimination["expected"] == 10
    assert elimination["actual"] == 3


def test_four_material_sets_explain_the_difference():
    path_missing = _report(_RULE, [_observation()])
    reference_unreachable = _report(
        _RULE, [_observation(parent_ref="1")]
    )
    type_mismatch = _report(
        _RULE, [_referenced_observation("big")]
    )
    comparison_failed = _report(
        _RULE, [_referenced_observation(1)]
    )

    stages = [
        _single_stage(report) for report in (
            path_missing, reference_unreachable, type_mismatch,
            comparison_failed,
        )
    ]
    assert stages == [
        DIAG_PATH_MISSING,
        DIAG_REFERENCE_UNREACHABLE,
        DIAG_TYPE_MISMATCH,
        DIAG_COMPARISON_FAILED,
    ]
    assert all(not report["matched"] for report in (
        path_missing, reference_unreachable, type_mismatch,
        comparison_failed,
    ))


def test_temporal_combination_failure_is_reported():
    observations = [
        {
            "type": "observed-data",
            "id": "observed-data--22222222-2222-4222-8222-222222222222",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {"0": {"type": "person", "name": "alice"}},
        },
        {
            "type": "observed-data",
            "id": "observed-data--33333333-3333-4333-8333-333333333333",
            "number_observed": 1,
            "first_observed": "2020-01-01T01:00:00Z",
            "last_observed": "2020-01-01T01:00:00Z",
            "objects": {"0": {"type": "person", "name": "alice"}},
        },
    ]
    # Both observations satisfy the comparison and can be combined for the
    # repetition; only the temporal combination constraint eliminates them.
    pattern = "[person:name = 'alice'] REPEATS 2 TIMES WITHIN 30 SECONDS"
    report = _report(pattern, observations)
    assert _single_stage(report) == DIAG_TEMPORAL_FAILED
    assert report["eliminations"][0]["reason"] == "within_duration_exceeded"
    assert len(report["eliminations"][0]["observations"]) == 2


def test_followedby_order_failure_is_temporal():
    observations = [
        {
            "type": "observed-data",
            "id": "observed-data--44444444-4444-4444-8444-444444444444",
            "number_observed": 1,
            "first_observed": "2020-01-01T02:00:00Z",
            "last_observed": "2020-01-01T02:00:00Z",
            "objects": {"0": {"type": "person", "name": "alice"}},
        },
        {
            "type": "observed-data",
            "id": "observed-data--55555555-5555-4555-8555-555555555555",
            "number_observed": 1,
            "first_observed": "2020-01-01T01:00:00Z",
            "last_observed": "2020-01-01T01:00:00Z",
            "objects": {"0": {"type": "person", "name": "bob"}},
        },
    ]
    pattern = "[person:name = 'alice'] FOLLOWEDBY [person:name = 'bob']"
    report = _report(pattern, observations)
    assert report["matched"] is False
    assert DIAG_TEMPORAL_FAILED in report["stages"]
    assert any(
        elimination["reason"] == "followedby_time_order_violated"
        for elimination in report["eliminations"]
    )


def test_or_branch_can_succeed_while_reporting_failed_branch():
    pattern = "[file:name = 'alice' OR file:size > 100]"
    report = _report(pattern, [_observation()])
    assert report["matched"] is True
    assert report["matches"]
    assert report["stages"] == []
    assert report["partial"] is False
    assert any(
        branch["operator"] == "comparison OR" and
        branch["left"] is True and
        branch["right"] is False
        for branch in report["branches"]
    )


def test_observation_or_branch_can_succeed():
    observations = [
        {
            "type": "observed-data",
            "id": "observed-data--66666666-6666-4666-8666-666666666666",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {"0": {"type": "person", "name": "alice"}},
        },
        {
            "type": "observed-data",
            "id": "observed-data--77777777-7777-4777-8777-777777777777",
            "number_observed": 1,
            "first_observed": "2020-01-01T00:00:00Z",
            "last_observed": "2020-01-01T00:00:00Z",
            "objects": {"0": {"type": "person", "name": "bob"}},
        },
    ]
    pattern = "[person:name = 'alice'] OR [person:name = 'bob']"
    report = _report(pattern, observations)
    assert report["matched"] is True
    assert any(
        branch["operator"] == "OR" and branch["result"] is True
        for branch in report["branches"]
    )


def test_partial_and_is_not_reported_as_a_match():
    pattern = "[file:name = 'alice' AND file:size > 100]"
    report = _report(pattern, [_observation()])
    assert report["matched"] is False
    assert report["matches"] == []
    assert report["partial"] is True
    assert any(
        branch["operator"] == "comparison AND" and
        branch["left"] is True and
        branch["right"] is False
        for branch in report["branches"]
    )


def test_diagnostics_do_not_change_determination():
    second = json.loads(json.dumps(_OBSERVATION))
    second["id"] = "observed-data--88888888-8888-4888-8888-888888888888"
    second["objects"]["0"]["name"] = "alice"

    materials = [
        [_observation()],
        [_observation(name="bob")],
        [_observation(parent_ref="1")],
        [_referenced_observation("big")],
        [_referenced_observation(1)],
        [_observation(), second],
    ]
    patterns = [
        _RULE,
        "[file:name = 'alice']",
        "[file:name = 'alice' OR file:size = 5]",
        "[file:name = 'alice' AND file:size = 5]",
        "[file:name = 'alice'] REPEATS 2 TIMES",
        "[file:name = 'alice'] REPEATS 2 TIMES WITHIN 100 SECONDS",
        "[file:name = 'alice'] FOLLOWEDBY [file:size = 5]",
        "[file:name LIKE 'a%']",
        "[file:name MATCHES 'al.*']",
        "[file:size IN (5, 6)]",
        "[file:size NOT IN (5, 6)]",
        "[file:name = 'alice'] WITHIN 30 SECONDS",
    ]
    for pattern in patterns:
        for observations in materials:
            normal = match(pattern, observations, stix_version=_stix_version)
            report = _report(pattern, observations)
            assert bool(report["matches"]) == bool(normal)
            assert report["matched"] == bool(normal)


def test_error_classes_are_not_reclassified_as_no_match():
    from stix2patterns.pattern import ParseException

    with pytest.raises(ParseException):
        match_with_diagnostics(
            "[file:name = ]", [_observation()], stix_version=_stix_version,
        )

    with pytest.raises(MatcherException):
        match_with_diagnostics(
            "[file:name = 'alice'] WITHIN 0 SECONDS", [_observation()],
            stix_version=_stix_version,
        )

    with pytest.raises(MatcherException):
        match_with_diagnostics(
            "[file:name = 'alice']", [{"type": "observed-data"}],
            stix_version=_stix_version,
        )


def test_report_does_not_include_unrelated_objects_or_bundle():
    unrelated = {"type": "file", "name": "unrelated", "id": "9"}
    observation = _observation()
    observation["objects"]["9"] = unrelated
    report = _report(_RULE, [observation])

    serialized = json.dumps(report, default=str)
    assert "unrelated" not in serialized
    assert "_OBSERVATION" not in serialized

    # Only the matched SDOs may appear in "matches"; never all input objects.
    assert report["matches"] == []


def test_report_is_json_serializable():
    report = _report(_RULE, [_observation()])
    encoded = json.dumps(report, default=str)
    decoded = json.loads(encoded)
    assert decoded["matched"] is report["matched"]
    assert decoded["stages"] == report["stages"]


def test_is_match_tracks_determination():
    matched = _report("[file:name = 'alice']", [_observation()])
    missed = _report(_RULE, [_observation()])
    assert matched.is_match is True
    assert matched["matched"] is True
    assert missed.is_match is False
    assert missed["matched"] is False


def test_report_with_indent_is_not_empty_json():
    # A dict subclass whose truthiness was overridden used to serialize as
    # "{}" with the pure-Python encoder (used when indent is given).
    report = _report(_RULE, [_observation()])
    encoded = json.dumps(report, indent=2, default=str)
    decoded = json.loads(encoded)
    assert decoded["matched"] is False
    assert decoded["stages"] == [DIAG_PATH_MISSING]
    assert decoded["eliminations"]


def test_diagnostics_false_preserves_normal_return_type():
    result = match(
        "[file:name = 'alice']", [_observation()],
        stix_version=_stix_version, diagnostics=False,
    )
    assert isinstance(result, list)
    assert result


def test_negated_tests_are_comparison_failures():
    observation = _observation()
    for pattern in (
        "[file:name NOT = 'alice']",
        "[file:name NOT IN ('alice')]",
        "[file:name NOT LIKE 'al%']",
        "[file:name NOT MATCHES 'al.*']",
    ):
        report = _report(pattern, [observation])
        assert report["matched"] is False
        assert _single_stage(report) == DIAG_COMPARISON_FAILED
        assert report["eliminations"][0]["stage"] == DIAG_COMPARISON_FAILED


def test_followedby_reuses_same_observation_is_temporal():
    pattern = "[file:name = 'alice'] FOLLOWEDBY [file:size = 5]"
    report = _report(pattern, [_observation()])
    assert report["matched"] is False
    assert _single_stage(report) == DIAG_TEMPORAL_FAILED
    assert report["eliminations"][0]["reason"] == \
        "followedby_observations_not_distinct"


def test_multiline_pattern_reports_line_and_offsets():
    pattern = (
        "[file:name = 'alice' AND\n"
        " file:size > 10]"
    )
    report = _report(pattern, [_observation()])
    rule = report["eliminations"][0]["rule"]
    assert rule["line"] == 2
    assert rule["column"] == 1
    assert rule["text"] == "file:size > 10"
    assert pattern[rule["start"]:rule["stop"] + 1] == "file:size > 10"


def test_eliminations_are_bounded_and_report_truncation():
    from stix2matcher.matcher import MatchDiagnostics

    objects = {
        str(i): {"type": "file", "name": "n{}".format(i)}
        for i in range(MatchDiagnostics.MAX_ELIMINATIONS + 50)
    }
    observation = {
        "type": "observed-data",
        "id": "observed-data--99999999-9999-4999-8999-999999999999",
        "number_observed": 1,
        "first_observed": "2020-01-01T00:00:00Z",
        "last_observed": "2020-01-01T00:00:00Z",
        "objects": objects,
    }
    report = _report("[file:name = 'absent']", [observation])
    assert report["matched"] is False
    assert len(report["eliminations"]) <= MatchDiagnostics.MAX_ELIMINATIONS
    assert report["truncated"] is True
