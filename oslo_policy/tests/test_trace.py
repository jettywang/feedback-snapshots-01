# Copyright (c) 2026 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Tests for the restricted policy explanation entry point."""

from unittest import mock

from oslo_context import context
import yaml

from oslo_policy import _checks
from oslo_policy import _trace
from oslo_policy import policy
from oslo_policy.tests import base


class _CountingCheck(_checks.BaseCheck):
    """A fake leaf that records how many times it was actually invoked."""

    def __init__(self, name, result):
        self.name = name
        self.result = result
        self.calls = 0

    def __str__(self):
        return self.name

    def __call__(self, target, creds, enforcer, current_rule=None):
        self.calls += 1
        return self.result


class _CountingLegacyCheck:
    """A fake leaf using the legacy three-argument signature."""

    def __init__(self, name, result):
        self.name = name
        self.result = result
        self.calls = 0

    def __str__(self):
        return self.name

    def __call__(self, target, creds, enforcer):
        self.calls += 1
        return self.result


class ExplainTestCase(base.PolicyBaseTestCase):
    def _set_rule(self, name, check):
        self.enforcer.set_rules({name: check})

    def test_explain_and_enforce_agree_on_deny(self):
        self._set_rule('action', _checks.RoleCheck('role', 'admin'))
        creds = {'roles': ['member']}

        expected = self.enforcer.enforce('action', {}, creds)
        explained = self.enforcer.explain('action', {}, creds)

        self.assertFalse(expected)
        self.assertFalse(explained.allowed)
        self.assertIs(explained.result, expected)

    def test_explain_and_enforce_agree_on_allow(self):
        self._set_rule('action', _checks.RoleCheck('role', 'admin'))
        creds = {'roles': ['admin']}

        expected = self.enforcer.enforce('action', {}, creds)
        explained = self.enforcer.explain('action', {}, creds)

        self.assertTrue(expected)
        self.assertTrue(explained.allowed)
        self.assertIs(explained.result, expected)

    def test_explain_reports_rule_name_and_denying_check(self):
        self.enforcer.set_rules(
            {
                'admin': _checks.RoleCheck('role', 'admin'),
                'action': _checks.AndCheck(
                    [
                        _checks.RuleCheck('rule', 'admin'),
                        _checks.RoleCheck('role', 'member'),
                    ]
                ),
            }
        )

        trace = self.enforcer.explain('action', {}, {'roles': ['admin']})

        self.assertFalse(trace.allowed)
        self.assertEqual('action', trace.requested_rule)
        self.assertEqual(['action', 'admin'], trace.rule_names)
        failed = [node.check_str for node in trace.failed]
        self.assertIn('role:member', failed)
        self.assertEqual('action', trace.root.rule_name)

    def test_explain_reports_referenced_rule_name(self):
        self.enforcer.set_rules(
            {
                'admin': _checks.RoleCheck('role', 'admin'),
                'action': _checks.RuleCheck('rule', 'admin'),
            }
        )

        trace = self.enforcer.explain('action', {}, {'roles': ['admin']})

        self.assertTrue(trace.allowed)
        self.assertEqual(['action', 'admin'], trace.rule_names)
        reference = trace.root
        self.assertEqual('rule:admin', reference.check_str)
        self.assertEqual('admin', reference.rule_name)
        child = reference.children[0]
        self.assertEqual('role:admin', child.check_str)
        self.assertEqual('admin', child.rule_name)

    def test_and_short_circuit_marks_rest_not_executed(self):
        first = _CountingCheck('first', False)
        second = _CountingCheck('second', True)
        self._set_rule('action', _checks.AndCheck([first, second]))

        trace = self.enforcer.explain('action', {}, {})

        self.assertFalse(trace.allowed)
        self.assertEqual(1, first.calls)
        self.assertEqual(0, second.calls)
        self.assertEqual(
            ['(first and second)', 'first'],
            [n.check_str for n in trace.executed],
        )
        skipped = trace.skipped
        self.assertEqual(1, len(skipped))
        self.assertEqual('second', skipped[0].check_str)
        self.assertFalse(skipped[0].executed)
        self.assertIsNone(skipped[0].result)
        self.assertEqual('not_executed', skipped[0].reason)

    def test_and_runs_every_branch_when_all_pass(self):
        first = _CountingCheck('first', True)
        second = _CountingCheck('second', True)
        self._set_rule('action', _checks.AndCheck([first, second]))

        trace = self.enforcer.explain('action', {}, {})

        self.assertTrue(trace.allowed)
        self.assertEqual(1, first.calls)
        self.assertEqual(1, second.calls)
        self.assertEqual([], trace.skipped)
        self.assertEqual(
            ['(first and second)', 'first', 'second'],
            [n.check_str for n in trace.executed],
        )

    def test_or_short_circuit_marks_rest_not_executed(self):
        first = _CountingCheck('first', True)
        second = _CountingCheck('second', False)
        self._set_rule('action', _checks.OrCheck([first, second]))

        trace = self.enforcer.explain('action', {}, {})

        self.assertTrue(trace.allowed)
        self.assertEqual(1, first.calls)
        self.assertEqual(0, second.calls)
        self.assertEqual(
            ['(first or second)', 'first'],
            [n.check_str for n in trace.executed],
        )
        self.assertEqual(['second'], [n.check_str for n in trace.skipped])

    def test_or_runs_every_branch_until_one_passes(self):
        first = _CountingCheck('first', False)
        second = _CountingCheck('second', True)
        third = _CountingCheck('third', True)
        self._set_rule('action', _checks.OrCheck([first, second, third]))

        trace = self.enforcer.explain('action', {}, {})

        self.assertTrue(trace.allowed)
        self.assertEqual(1, first.calls)
        self.assertEqual(1, second.calls)
        self.assertEqual(0, third.calls)
        self.assertEqual(['third'], [n.check_str for n in trace.skipped])

    def test_nested_combination_matches_actual_invocations(self):
        # (denied or also_denied) and (never_a or never_b): the 'and' fails
        # on its first operand, so the whole right side is not executed.
        denied = _CountingCheck('denied', False)
        also_denied = _CountingCheck('also_denied', False)
        never_a = _CountingCheck('never_a', True)
        never_b = _CountingCheck('never_b', True)
        left = _checks.OrCheck([denied, also_denied])
        right = _checks.OrCheck([never_a, never_b])
        self._set_rule('action', _checks.AndCheck([left, right]))

        trace = self.enforcer.explain('action', {}, {})

        self.assertFalse(trace.allowed)
        self.assertEqual(1, denied.calls)
        self.assertEqual(1, also_denied.calls)
        self.assertEqual(0, never_a.calls)
        self.assertEqual(0, never_b.calls)
        self.assertEqual(
            [
                '((denied or also_denied) and (never_a or never_b))',
                '(denied or also_denied)',
                'denied',
                'also_denied',
            ],
            [n.check_str for n in trace.executed],
        )
        skipped = trace.skipped
        skipped_names = [node.check_str for node in skipped]
        self.assertIn('(never_a or never_b)', skipped_names)
        self.assertIn('never_a', skipped_names)
        self.assertIn('never_b', skipped_names)
        self.assertTrue(all(not node.executed for node in skipped))
        self.assertTrue(all(node.result is None for node in skipped))

    def test_not_check_marks_inner_as_executed(self):
        inner = _CountingCheck('inner', True)
        self._set_rule('action', _checks.NotCheck(inner))

        trace = self.enforcer.explain('action', {}, {})

        self.assertFalse(trace.allowed)
        self.assertEqual(1, inner.calls)
        self.assertEqual(
            ['not inner', 'inner'],
            [n.check_str for n in trace.executed],
        )

    def test_legacy_check_signature_still_works(self):
        legacy = _CountingLegacyCheck('legacy', False)
        self._set_rule('action', legacy)

        legacy_result = self.enforcer.enforce('action', {}, {})
        trace = self.enforcer.explain('action', {}, {})

        self.assertFalse(legacy_result)
        self.assertFalse(trace.allowed)
        self.assertEqual(2, legacy.calls)

    def test_explain_does_not_execute_checks_twice(self):
        # A single explanation call must correspond one-to-one with the
        # calls the underlying checks observe.
        first = _CountingCheck('first', True)
        second = _CountingCheck('second', False)
        self._set_rule('action', _checks.AndCheck([first, second]))

        trace = self.enforcer.explain('action', {}, {})

        self.assertFalse(trace.allowed)
        self.assertEqual(1, first.calls)
        self.assertEqual(1, second.calls)

    def test_unknown_rule_fails_closed_and_explains(self):
        self.enforcer.set_rules({'action': _checks.TrueCheck()})

        trace = self.enforcer.explain('missing', {}, {})

        self.assertFalse(trace.allowed)
        self.assertIs(trace.result, False)
        self.assertIsNone(trace.root)
        self.assertEqual('unknown_rule', trace.reason)

    def test_no_rules_fails_closed_and_explains(self):
        enforcer = policy.Enforcer(self.conf, use_conf=False)
        enforcer.set_rules({})

        trace = enforcer.explain('missing', {}, {})

        self.assertFalse(trace.allowed)
        self.assertEqual('no_rules', trace.reason)

    def test_scope_mismatch_is_explained_without_traversal(self):
        rule = policy.RuleDefault(
            name='action',
            check_str='role:admin',
            scope_types=['system'],
        )
        self.enforcer.register_default(rule)

        trace = self.enforcer.explain('action', {}, {'roles': ['admin']})

        self.assertFalse(trace.allowed)
        self.assertFalse(trace.scope_valid)
        self.assertEqual('scope_mismatch', trace.reason)
        self.assertIsNone(trace.root)

    def test_scope_mismatch_raises_like_enforce(self):
        rule = policy.RuleDefault(
            name='action',
            check_str='role:admin',
            scope_types=['system'],
        )
        self.enforcer.register_default(rule)

        self.assertRaises(
            policy.InvalidScope,
            self.enforcer.explain,
            'action',
            {},
            {'roles': ['admin']},
            do_raise=True,
        )

    def test_check_tree_argument_is_supported(self):
        check = _checks.AndCheck(
            [
                _checks.TrueCheck(),
                _checks.RoleCheck('role', 'admin'),
            ]
        )

        trace = self.enforcer.explain(check, {}, {'roles': ['admin']})

        self.assertTrue(trace.allowed)
        self.assertIsNone(trace.requested_rule)
        self.assertEqual('(@ and role:admin)', trace.root.check_str)

    def test_request_context_credentials_are_accepted(self):
        self._set_rule('action', _checks.RoleCheck('role', 'admin'))
        ctx = context.RequestContext(roles=['admin'])

        trace = self.enforcer.explain('action', {}, ctx)

        self.assertTrue(trace.allowed)

    def test_do_raise_still_raises_after_explaining(self):
        self._set_rule('action', _checks.FalseCheck())

        exc = self.assertRaises(
            policy.PolicyNotAuthorized,
            self.enforcer.explain,
            'action',
            {},
            {},
            True,
        )
        self.assertIn('is disallowed by policy', str(exc))

    def test_custom_exception_is_passed_through(self):
        class MyError(Exception):
            pass

        self._set_rule('action', _checks.FalseCheck())

        self.assertRaises(
            MyError,
            self.enforcer.explain,
            'action',
            {},
            {},
            True,
            MyError,
        )

    def test_trace_never_contains_credential_values(self):
        secret = 'super-secret-token'
        self._set_rule('action', _checks.RoleCheck('role', 'admin'))

        trace = self.enforcer.explain(
            'action',
            {'owner': secret},
            {'roles': ['member'], 'token': secret},
        )

        rendered = str(trace) + repr(trace.to_dict())
        self.assertNotIn(secret, rendered)
        self.assertNotIn('super-secret', rendered)

    def test_explain_returns_original_non_boolean_value(self):
        self.enforcer.set_rules(
            {'action': _checks.OrCheck([_checks.TrueCheck()])}
        )

        trace = self.enforcer.explain('action', {}, {})

        self.assertIs(trace.result, True)
        self.assertTrue(trace.allowed)
        data = trace.to_dict()
        self.assertIs(data['result'], True)
        self.assertIs(data['allowed'], True)

    def test_explain_keeps_deny_for_empty_rule_string(self):
        self.enforcer.set_rules({'action': _checks.TrueCheck()})

        trace = self.enforcer.explain('action', {}, {})

        self.assertTrue(trace.allowed)
        self.assertEqual('@', trace.root.check_str)
        self.assertTrue(trace.root.executed)

    def test_logging_is_not_suppressed_for_plain_enforce(self):
        self._set_rule('action', _checks.FalseCheck())

        with mock.patch.object(policy, 'LOG') as mock_log:
            mock_log.isEnabledFor.return_value = True
            self.enforcer.enforce('action', {}, {'roles': ['member']})

        mock_log.debug.assert_called_once()

    def test_trace_does_not_log_credentials(self):
        secret = 'super-secret-token'
        self._set_rule('action', _checks.FalseCheck())

        with mock.patch.object(policy, 'LOG') as mock_log:
            self.enforcer.explain(
                'action',
                {'owner': secret},
                {'roles': ['member'], 'token': secret},
            )

        mock_log.debug.assert_not_called()

    def test_trace_serialization_is_structured(self):
        self.enforcer.set_rules(
            {
                'admin': _checks.RoleCheck('role', 'admin'),
                'action': _checks.OrCheck(
                    [
                        _checks.RuleCheck('rule', 'admin'),
                        _checks.RoleCheck('role', 'member'),
                    ]
                ),
            }
        )

        data = self.enforcer.explain(
            'action', {}, {'roles': ['member']}
        ).to_dict()

        self.assertTrue(data['allowed'])
        self.assertEqual('action', data['rule'])
        self.assertEqual(['action', 'admin'], data['rules'])
        self.assertEqual('or', data['root']['type'])
        branches = data['root']['children']
        self.assertEqual(2, len(branches))
        self.assertTrue(branches[0]['executed'])
        self.assertTrue(branches[1]['executed'])
        self.assertFalse(branches[0]['skipped'])

    def test_serialization_marks_unexecuted_branches(self):
        self._set_rule(
            'action',
            _checks.OrCheck(
                [
                    _checks.RoleCheck('role', 'admin'),
                    _checks.RoleCheck('role', 'member'),
                ]
            ),
        )

        data = self.enforcer.explain(
            'action', {}, {'roles': ['admin']}
        ).to_dict()

        branches = data['root']['children']
        self.assertTrue(branches[0]['executed'])
        self.assertIs(branches[0]['result'], True)
        self.assertFalse(branches[1]['executed'])
        self.assertIsNone(branches[1]['result'])
        self.assertTrue(branches[1]['skipped'])

    def test_trace_is_one_per_explanation(self):
        self._set_rule('action', _checks.TrueCheck())

        first = self.enforcer.explain('action', {}, {})
        second = self.enforcer.explain('action', {}, {})

        self.assertIsNot(first, second)
        self.assertTrue(first.allowed)
        self.assertTrue(second.allowed)
        self.assertIsNone(_trace.get_active_trace())

    def test_enforce_does_not_collect_a_trace(self):
        self._set_rule('action', _checks.TrueCheck())

        with mock.patch.object(
            _trace.PolicyTrace, 'evaluate', autospec=True
        ) as evaluate:
            self.enforcer.enforce('action', {}, {})

        evaluate.assert_not_called()

    def test_aliases_expose_decision_and_tree(self):
        self._set_rule('action', _checks.TrueCheck())

        trace = self.enforcer.explain('action', {}, {})

        self.assertTrue(trace.decision)
        self.assertIsNotNone(trace.root)
        self.assertIn('"allowed": true', trace.to_json())

    def test_unknown_rule_reference_is_not_expanded(self):
        self.enforcer.set_rules(
            {
                'action': _checks.AndCheck(
                    [
                        _checks.RuleCheck('rule', 'missing'),
                        _checks.RoleCheck('role', 'admin'),
                    ]
                ),
            }
        )

        trace = self.enforcer.explain('action', {}, {'roles': ['admin']})

        self.assertFalse(trace.allowed)
        self.assertEqual(
            ['role:admin'], [n.check_str for n in trace.skipped]
        )
        missing = trace.root.children[0]
        self.assertEqual('rule:missing', missing.check_str)
        self.assertTrue(missing.executed)
        self.assertIs(missing.result, False)
        self.assertEqual([], missing.children)

    def test_trace_is_truthy_when_allowed(self):
        self._set_rule('action', _checks.TrueCheck())
        false_rule = policy.Enforcer(self.conf, use_conf=False)
        false_rule.set_rules({'action': _checks.FalseCheck()})

        self.assertTrue(self.enforcer.explain('action', {}, {}))
        self.assertFalse(false_rule.explain('action', {}, {}))

    def test_explain_respects_custom_rule_check_dispatch(self):
        @_checks.register('test-count')
        class CountCheck(_checks.Check):
            calls = 0

            def __call__(self, target, creds, enforcer, current_rule=None):
                type(self).calls += 1
                return True

        self.addCleanup(_checks.registered_checks.pop, 'test-count')
        self._set_rule(
            'action',
            _checks.OrCheck(
                [
                    _checks.TrueCheck(),
                    CountCheck('test-count', 'ignored'),
                ]
            ),
        )

        trace = self.enforcer.explain('action', {}, {})

        self.assertTrue(trace.allowed)
        self.assertEqual(0, CountCheck.calls)
        self.assertEqual(
            ['test-count:ignored'], [n.check_str for n in trace.skipped]
        )

    def test_explain_reports_nested_rule_names_in_order(self):
        enforcer = policy.Enforcer(self.conf, use_conf=False)
        enforcer.set_rules(
            {
                'outer': _checks.AndCheck(
                    [
                        _checks.RuleCheck('rule', 'inner'),
                        _checks.RoleCheck('role', 'admin'),
                    ]
                ),
                'inner': _checks.OrCheck(
                    [
                        _checks.RoleCheck('role', 'admin'),
                        _checks.RoleCheck('role', 'member'),
                    ]
                ),
            }
        )

        trace = enforcer.explain('outer', {}, {'roles': ['admin']})

        self.assertTrue(trace.allowed)
        self.assertEqual(['outer', 'inner'], trace.rule_names)
        data = trace.to_dict()
        self.assertEqual(['outer', 'inner'], data['rules'])
        due = [node.check_str for node in trace.executed]
        self.assertEqual(
            [
                '(rule:inner and role:admin)',
                'rule:inner',
                '(role:admin or role:member)',
                'role:admin',
                'role:admin',
            ],
            due,
        )
        skipped = [node.check_str for node in trace.skipped]
        self.assertEqual(['role:member'], skipped)

    def test_explain_reloads_policy_files_like_enforce(self):
        self.create_config_file(
            'policy.yaml', yaml.dump({'action': 'role:admin'})
        )
        enforcer = policy.Enforcer(self.conf)
        creds = {'roles': ['admin']}

        expected = enforcer.enforce('action', {}, creds)
        trace = enforcer.explain('action', {}, creds)

        self.assertTrue(expected)
        self.assertTrue(trace.allowed)
        self.assertEqual('action', trace.root.rule_name)

    def test_details_isolated_between_explanations(self):
        executed = _CountingCheck('executed', False)
        skipped = _CountingCheck('skipped', True)
        self._set_rule('action', _checks.AndCheck([executed, skipped]))

        first = self.enforcer.explain('action', {}, {})
        second = self.enforcer.explain('action', {}, {})

        self.assertEqual(['skipped'], [n.check_str for n in first.skipped])
        self.assertEqual(['skipped'], [n.check_str for n in second.skipped])
        self.assertEqual(2, executed.calls)
        self.assertEqual(0, skipped.calls)

    def test_exception_in_check_marks_node_and_propagates(self):
        class Broken(_checks.BaseCheck):
            def __str__(self):
                return 'broken'

            def __call__(self, target, creds, enforcer, current_rule=None):
                raise RuntimeError('boom')

        self._set_rule('action', _checks.AndCheck([Broken()]))

        self.assertRaises(
            RuntimeError, self.enforcer.explain, 'action', {}, {}
        )


class ExplainAuthorizeTestCase(base.PolicyBaseTestCase):
    def test_requires_registered_rule(self):
        self.enforcer.set_rules({'action': _checks.TrueCheck()})

        self.assertRaises(
            policy.PolicyNotRegistered,
            self.enforcer.explain_authorize,
            'action',
            {},
            {},
        )

    def test_registered_rule_is_explained(self):
        self.enforcer.register_default(
            policy.RuleDefault(name='action', check_str='role:admin')
        )

        trace = self.enforcer.explain_authorize(
            'action', {}, {'roles': ['admin']}
        )

        self.assertTrue(trace.allowed)
        self.assertEqual('action', trace.root.rule_name)
