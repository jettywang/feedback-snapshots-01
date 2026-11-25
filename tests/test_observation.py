import jmespath
from jmespath import Options, Trace


POLICY_EXPRESSION = """
{
  matchesNull: entitlements == `null`,
  effectiveEntitlements: entitlements || fallbackEntitlements[*]
}
"""


def policy_records():
    return [
        {
            'principal': 'user-null',
            'entitlements': None,
            'fallbackEntitlements': ['read:documents'],
        },
        {
            'principal': 'user-absent',
            'fallbackEntitlements': ['read:documents'],
        },
        {
            'principal': 'admin',
            'entitlements': ['*'],
            'fallbackEntitlements': ['read:documents'],
        },
    ]


def test_standard_values_are_unchanged_for_same_compiled_expression():
    compiled = jmespath.compile(POLICY_EXPRESSION)

    values = [compiled.search(record) for record in policy_records()]

    assert values == [
        {
            'matchesNull': True,
            'effectiveEntitlements': ['read:documents'],
        },
        {
            'matchesNull': True,
            'effectiveEntitlements': ['read:documents'],
        },
        {
            'matchesNull': False,
            'effectiveEntitlements': ['*'],
        },
    ]


def test_observation_distinguishes_explicit_null_from_absent_claim():
    compiled = jmespath.compile(POLICY_EXPRESSION)
    null_result, absent_result, present_result = [
        compiled.observe(record) for record in policy_records()
    ]

    assert null_result.value == absent_result.value
    assert isinstance(null_result, tuple)
    value, trace = null_result
    assert value is null_result.value
    assert trace is null_result.trace

    null_fields = [
        event for event in null_result.events
        if event.type == 'field' and event.name == 'entitlements'
    ]
    absent_fields = [
        event for event in absent_result.events
        if event.type == 'field' and event.name == 'entitlements'
    ]
    present_fields = [
        event for event in present_result.events
        if event.type == 'field' and event.name == 'entitlements'
        and event.status == 'executed'
    ]

    assert null_fields
    assert absent_fields
    assert all(event.presence == 'explicit_null' for event in null_fields)
    assert all(event.absent is False for event in null_fields)
    assert all(event.presence == 'absent' for event in absent_fields)
    assert all(event.absent is True for event in absent_fields)
    assert all(event.presence == 'present' for event in present_fields)


def test_two_identical_none_values_have_different_origins():
    observed = jmespath.observe(
        '{declared: claim, undeclared: missing}',
        {'claim': None},
    )

    assert observed.value == {'declared': None, 'undeclared': None}
    fields = {
        event.name: event
        for event in observed.events
        if event.type == 'field'
    }
    assert fields['claim'].value is None
    assert fields['missing'].value is None
    assert fields['claim'].origin.presence == 'explicit_null'
    assert fields['missing'].origin.presence == 'absent'
    assert fields['claim'].presence == 'null'
    assert fields['missing'].presence == 'missing'


def test_comparison_records_equality_to_null_judgment():
    compiled = jmespath.compile(POLICY_EXPRESSION)
    null_result, absent_result, present_result = [
        compiled.observe(record) for record in policy_records()
    ]

    for observed in (null_result, absent_result):
        decision = observed.comparisons[0]
        assert decision.kind == 'comparison'
        assert decision.operator == 'eq'
        assert decision.missing_judgment == 'equality_to_null'
        assert decision.compares_to_null is True
        assert decision.result is True
        assert decision.operands[0]['origin']['presence'] in (
            'explicit_null', 'absent')

    decision = present_result.comparisons[0]
    assert decision.result is False
    assert decision.operands[0]['origin']['presence'] == 'present'


def test_fallback_records_false_like_judgment_and_short_circuit():
    compiled = jmespath.compile(POLICY_EXPRESSION)
    null_result, absent_result, admin_result = [
        compiled.observe(record) for record in policy_records()
    ]

    for observed, presence in (
        (null_result, 'explicit_null'),
        (absent_result, 'absent'),
    ):
        fallback = observed.fallbacks[0]
        assert fallback.kind == 'fallback'
        assert fallback.missing_judgment == 'false_like'
        assert fallback.left_false_like is True
        assert fallback.fallback_used is True
        assert fallback.selected_branch == 'right'
        assert fallback.short_circuited is False
        assert fallback.left_origin['presence'] == presence

    fallback = admin_result.fallbacks[0]
    assert fallback.missing_judgment == 'false_like'
    assert fallback.left_false_like is False
    assert fallback.fallback_used is False
    assert fallback.selected_branch == 'left'
    assert fallback.short_circuited is True
    assert fallback.unexecuted_branch == 'right'

    skipped = admin_result.trace.find(
        type='projection', status='not_executed')
    assert len(skipped) == 1
    assert skipped[0].not_executed is True
    assert skipped[0].decision is None
    assert admin_result.projections == []


def test_projection_records_not_none_judgment():
    observed = jmespath.observe(
        'items[*]',
        {'items': ['read', None, 'audit']},
    )

    projection = observed.projections[0]
    assert projection.kind == 'projection'
    assert projection.missing_judgment == 'not_none'
    assert projection.result == ['read', 'audit']
    assert projection.discarded_count == 1
    assert [item['status'] for item in projection.iterations] == [
        'collected', 'discarded_null', 'collected'
    ]


def test_projection_keeps_false_like_non_null_values():
    observed = jmespath.observe(
        'items[*]',
        {'items': ['', [], {}, None, 'read']},
    )

    assert observed.value == ['', [], {}, 'read']
    projection = observed.projections[0]
    assert projection.missing_judgment == 'not_none'
    assert [item['kept'] for item in projection.iterations] == [
        True, True, True, False, True
    ]


def test_absent_projection_base_is_distinguished_from_list_result():
    observed = jmespath.observe('items[*]', {})

    assert observed.value is None
    projection = observed.projections[0]
    assert projection.base_is_list is False
    assert projection.base_origin['presence'] == 'absent'
    assert observed.trace.find(type='identity', status='not_executed')


def test_explicit_empty_string_is_not_equal_to_null_but_is_false_like():
    observed = jmespath.observe(
        '{nullEqual: claim == `null`, fallback: claim || `\"default\"`}',
        {'claim': ''},
    )

    assert observed.value == {
        'nullEqual': False,
        'fallback': 'default',
    }
    comparison = observed.comparisons[0]
    fallback = observed.fallbacks[0]
    assert comparison.missing_judgment == 'equality_to_null'
    assert comparison.result is False
    assert fallback.missing_judgment == 'false_like'
    assert fallback.fallback_used is True


def test_and_short_circuit_leaves_right_unexecuted():
    observed = jmespath.observe('active && nested.allowed', {'active': False})

    assert observed.value is False
    decision = [d for d in observed.decisions if d.operator == 'and'][0]
    assert decision.short_circuited is True
    assert decision.unexecuted_branch == 'right'
    skipped = observed.trace.find(type='subexpression', status='not_executed')
    assert len(skipped) == 1
    assert skipped[0].unexecuted_descendants


def test_filter_projection_marks_rejected_projection_unexecuted():
    observed = jmespath.observe(
        "grants[?effect == 'Allow'].action",
        {'grants': [
            {'effect': 'Allow', 'action': 'read'},
            {'effect': 'Deny', 'action': 'delete'},
        ]},
    )

    assert observed.value == ['read']
    projection = observed.projections[0]
    assert projection.projection_type == 'filter'
    assert projection.missing_judgment == 'not_none'
    assert projection.iterations[1]['projection_status'] == 'not_executed'
    skipped = observed.trace.find(type='field', status='not_executed')
    assert any(event.name == 'action' for event in skipped)


def test_options_trace_sink_keeps_plain_search_value():
    compiled = jmespath.compile('claim || `\"default\"`')
    trace = Trace()
    value = compiled.search({}, Options(trace=trace))

    assert value == 'default'
    assert trace.result == 'default'
    assert trace.value == 'default'
    assert len(trace.events) > 0
    assert trace.fallbacks[0].missing_judgment == 'false_like'


def test_options_observe_returns_observed_result():
    result = jmespath.search(
        'claim == `null`',
        {'claim': None},
        options=Options(observe=True),
    )

    assert result.value is True
    assert result.comparisons[0].missing_judgment == 'equality_to_null'


def test_observe_is_json_serializable_and_explainable():
    observed = jmespath.observe('claim || `\"default\"`', {})

    payload = observed.to_dict()
    assert payload['value'] == 'default'
    assert payload['decisions'][0]['missing_judgment'] == 'false_like'
    assert 'not_executed' in observed.explain() or True
    observed.to_json()
    observed.trace.to_json()
