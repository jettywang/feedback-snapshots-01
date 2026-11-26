"""Independent call-order criterion for the local recording functions.

These tests do not look at the returned JSON at all: they assert the
ordered log of extension-function invocations.  That is what catches an
implementation that evaluates a short-circuit branch it should have
skipped, even when the value happens to be identical.
"""

import jmespath
from jmespath.visitor import Options

from tests.regression.calls import (
    assert_call_order,
    assert_same_call_order,
    probe_labels,
)
from tests.regression.observations import RecordingFunctions, observe


def _obs(expr, document):
    return observe(expr, document)


def test_or_short_circuits_without_right_probe():
    document = {"a": 2, "b": "x"}
    observation = _obs("probe('L', a) || probe('R', b)", document)
    assert observation.value == 2
    assert_call_order(observation, [("probe", "L", 2)])
    assert probe_labels(observation) == ("L",)


def test_not_null_always_runs_right_probe():
    document = {"a": 2, "b": "x"}
    observation = _obs("not_null(probe('L', a), probe('R', b))", document)
    assert observation.value == 2
    assert_call_order(
        observation, [("probe", "L", 2), ("probe", "R", "x")])
    assert probe_labels(observation) == ("L", "R")


def test_same_value_still_reports_extra_branch():
    document = {"a": 2, "b": "x"}
    left = _obs("probe('L', a) || probe('R', b)", document)
    right = _obs("not_null(probe('L', a), probe('R', b))", document)
    assert left.value == right.value == 2
    # Independent criterion: the call sequences differ by exactly one call.
    assert left.calls != right.calls
    assert len(right.calls) == len(left.calls) + 1
    assert right.calls[0] == left.calls[0]


def test_null_fallthrough_makes_call_orders_match():
    document = {"a": None, "b": 5}
    left = _obs("probe('L', a) || probe('R', b)", document)
    right = _obs("not_null(probe('L', a), probe('R', b))", document)
    assert left.value == right.value == 5
    assert_same_call_order(left, right)
    assert_call_order(
        left, [("probe", "L", None), ("probe", "R", 5)])


def test_projection_and_map_call_each_element_once():
    document = {"items": [{"a": 1}, {"a": 2}, {"a": 3}]}
    for expression in ("items[*].probe('p', a)",
                       "map(&probe('p', a), items)",
                       "items[*] | [*].probe('p', a)"):
        observation = _obs(expression, document)
        assert_call_order(
            observation,
            [("probe", "p", 1), ("probe", "p", 2), ("probe", "p", 3)],
            note=expression)


def test_projection_calls_probe_for_null_elements_but_drops_result():
    # The projection still *calls* probe for every element; only its
    # non-null return values are appended to the result.  This is why the
    # call log must be checked separately from the JSON value.
    document = {"items": [{"a": 1}, {"a": None}, {}]}
    observation = _obs("items[*].probe('p', a)", document)
    assert observation.value == [1]
    assert_call_order(
        observation,
        [("probe", "p", 1), ("probe", "p", None), ("probe", "p", None)])


def test_filter_argument_order_is_recorded():
    document = {"items": [{"a": 1}, {"a": 2}]}
    observation = _obs("items[?probe('c', a) == `1`].probe('m', a)", document)
    assert observation.value == [1]
    assert_call_order(
        observation,
        [("probe", "c", 1), ("probe", "m", 1), ("probe", "c", 2)])


def test_custom_functions_are_used_through_the_public_api():
    recorder = RecordingFunctions()
    options = Options(custom_functions=recorder)
    result = jmespath.search(
        "probe('L', a) || probe('R', b)", {"a": None, "b": 5},
        options=options)
    assert result == 5
    assert tuple(recorder.calls) == (("probe", "L", None), ("probe", "R", 5))
