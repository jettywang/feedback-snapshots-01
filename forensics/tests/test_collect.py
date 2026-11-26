"""Regression guarantees for the forensic replay.

These assertions are the executable form of the runbook claims. If a future
change to a propagator alters ordering semantics, extraction, or sampling
defaults, the tests fail at the same stage the report would name.
"""

from __future__ import annotations

import json

import pytest

from forensics import collect


@pytest.fixture(scope="module")
def report():
    return collect.run()


@pytest.fixture(scope="module")
def runs(report):
    return {(run["fixture_id"], run["order_id"]): run for run in report["runs"]}


def test_manual_replay_matches_real_composite(report):
    assert report["runs"]
    for run in report["runs"]:
        assert run["composite_matches_replay"] is True, (
            run["fixture_id"],
            run["order_id"],
        )


def test_prefix_stages_are_identical(report):
    for comparison in report["comparisons"]:
        for pair in comparison["stage_pairs"][:2]:
            assert pair["material"] is False, pair
            assert pair["differing_fields"] == {}


def test_first_divergence_is_stage_three_for_both_requests(report):
    assert {c["fixture_id"] for c in report["comparisons"]} == {"full", "partial"}
    for comparison in report["comparisons"]:
        first = comparison["first_divergence"]
        assert first is not None
        assert first["index"] == 3
        assert first["propagator_A"] == "B3MultiFormat"
        assert first["propagator_B"] == "JaegerPropagator"


def test_trace_id_stays_the_same(report):
    for comparison in report["comparisons"]:
        assert comparison["final"]["same_trace_id"] is True
        assert comparison["final"]["trace_id_A"] == collect.TRACE_ID
        assert comparison["final"]["trace_id_B"] == collect.TRACE_ID


def test_full_request_distinguishes_parent_and_baggage(report):
    full = report["findings"]["full"]
    assert full["parent_changed"] is True
    assert full["baggage_rewritten"] is True
    assert full["tracestate_no_longer_applies"] is True
    assert full["tracestate_absent_inbound"] is False
    assert full["sampling_changed"] is False
    comparison = next(c for c in report["comparisons"] if c["fixture_id"] == "full")
    assert comparison["final"]["parent_A"] == collect.B3_SPAN_ID
    assert comparison["final"]["parent_B"] == collect.JAEGER_SPAN_ID
    assert comparison["final"]["baggage_A"]["tenant"] == "blue"
    assert comparison["final"]["baggage_B"]["tenant"] == "green"


def test_partial_request_distinguishes_sampling(report):
    partial = report["findings"]["partial"]
    assert partial["parent_changed"] is True
    assert partial["sampling_changed"] is True
    assert partial["tracestate_no_longer_applies"] is False
    assert partial["tracestate_absent_inbound"] is True
    comparison = next(c for c in report["comparisons"] if c["fixture_id"] == "partial")
    assert comparison["final"]["sampled_A"] is False
    assert comparison["final"]["sampled_B"] is True


def test_three_observations_per_stage(report):
    for run in report["runs"]:
        assert len(run["stages"]) == 3
        for stage in run["stages"]:
            assert stage["inbound_carrier"]
            assert stage["returned_context"]["span"]["trace_id"] == collect.TRACE_ID
            assert stage["child_span"]["exported_count"] in (0, 1)
            assert stage["final_injected"]


def test_child_span_recording_follows_sampling(runs):
    a_partial = runs[("partial", "A")]
    b_partial = runs[("partial", "B")]
    a_final = a_partial["stages"][-1]["child_span"]
    b_final = b_partial["stages"][-1]["child_span"]
    assert a_final["recording"] is False
    assert a_final["exported_count"] == 0
    assert b_final["recording"] is True
    assert b_final["exported_count"] == 1
    # The recorded child must point at the winning remote parent, not at the
    # inbound W3C span.
    assert b_final["exported"][0]["parent_span_id"] == collect.JAEGER_SPAN_ID
    assert b_final["exported"][0]["attributes"]["e2e.id"] == collect.E2E_ID


def test_report_is_byte_for_byte_reproducible():
    first = collect.run()
    second = collect.run()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_e2e_correlation_identifier_is_present(report):
    assert report["e2e_id"] == collect.E2E_ID
    for fixture in report["fixtures"]:
        assert fixture["e2e_id"] == collect.E2E_ID
    for run in report["runs"]:
        assert run["e2e_id"] == collect.E2E_ID
