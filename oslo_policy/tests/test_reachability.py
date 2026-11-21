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

import io
from unittest import mock

from oslo_config import cfg

from oslo_policy import policy
from oslo_policy import reachability
from oslo_policy import reachability_shell
from oslo_policy.tests import base


# Registered API actions: these are the roots reachability starts from.
ACTION_ROOTS = [
    'service:create',
    'service:list',
    'service:disable',
    'service:legacy',
    'service:broken',
    'service:loop_a',
]


class ReachabilityTestCase(base.PolicyBaseTestCase):
    def _enforcer_with(self, defaults):
        enforcer = policy.Enforcer(cfg.ConfigOpts(), use_conf=False)
        enforcer.register_defaults(defaults)
        enforcer.load_rules()
        self.addCleanup(enforcer.clear)
        return enforcer

    def _nested_enforcer(self):
        # Tiny nested graph, rooted at the API actions in ACTION_ROOTS:
        #   create  -> admin_required -> role:admin
        #   list    -> viewer_required -> role:reader
        #   disable -> "!" (action explicitly disabled)
        #   legacy  -> old_service_rule (name kept as a deprecated alias)
        #   broken  -> does_not_exist (undefined reference)
        #   loop_a  -> loop_b -> loop_a (cycle)
        #   orphan  -> referenced by no action (advisory only)
        defaults = [
            policy.RuleDefault('service:admin_required', 'role:admin'),
            policy.RuleDefault('service:viewer_required', 'role:reader'),
            policy.RuleDefault(
                'service:create', 'rule:service:admin_required'
            ),
            policy.RuleDefault(
                'service:list', 'rule:service:viewer_required'
            ),
            policy.RuleDefault('service:disable', '!'),
            policy.RuleDefault(
                'service:legacy',
                'rule:old_service_rule',
                deprecated_rule=policy.DeprecatedRule(
                    name='old_service_rule',
                    check_str='role:admin',
                    deprecated_reason='renamed',
                    deprecated_since='2026.1',
                ),
            ),
            policy.RuleDefault('service:broken', 'rule:does_not_exist'),
            policy.RuleDefault('service:loop_a', 'rule:service:loop_b'),
            policy.RuleDefault('service:loop_b', 'rule:service:loop_a'),
            policy.RuleDefault('service:orphan', 'role:member'),
        ]
        return self._enforcer_with(defaults)

    def test_reachable_set_follows_nested_rule_refs(self):
        enforcer = self._nested_enforcer()
        report = reachability.analyze(enforcer, ACTION_ROOTS)

        self.assertIn('service:create', report.reachable)
        self.assertIn('service:admin_required', report.reachable)
        self.assertIn('service:list', report.reachable)
        self.assertIn('service:viewer_required', report.reachable)

    def test_disabled_action_is_reachable_and_flagged(self):
        enforcer = self._nested_enforcer()
        report = reachability.analyze(enforcer, ACTION_ROOTS)

        self.assertIn('service:disable', report.reachable)
        self.assertEqual(['service:disable'], report.disabled)

    def test_legacy_alias_reference_is_valid(self):
        enforcer = self._nested_enforcer()
        report = reachability.analyze(
            enforcer, ['service:legacy', 'service:create']
        )

        self.assertIn('old_service_rule', report.legacy_aliases)
        self.assertEqual([], report.issues)
        self.assertIn('service:legacy', report.reachable)

    def test_undefined_reference_reports_action_chain(self):
        enforcer = self._nested_enforcer()
        report = reachability.analyze(enforcer, ['service:broken'])

        self.assertEqual(1, len(report.issues))
        issue = report.issues[0]
        self.assertEqual('undefined', issue.kind)
        self.assertEqual('service:broken', issue.source)
        self.assertEqual(('service:broken',), issue.chain)
        self.assertEqual('does_not_exist', issue.reference)
        self.assertEqual(
            'service:broken -> rule:does_not_exist', issue.path
        )

    def test_nested_undefined_reference_keeps_full_chain(self):
        enforcer = self._enforcer_with(
            [
                policy.RuleDefault('svc:action', 'rule:svc:middle'),
                policy.RuleDefault('svc:middle', 'rule:svc:missing'),
            ]
        )
        report = reachability.analyze(enforcer, ['svc:action'])

        self.assertEqual(1, len(report.issues))
        issue = report.issues[0]
        self.assertEqual('undefined', issue.kind)
        self.assertEqual(('svc:action', 'svc:middle'), issue.chain)
        self.assertEqual('svc:missing', issue.reference)
        self.assertEqual(
            'svc:action -> svc:middle -> rule:svc:missing', issue.path
        )

    def test_cycle_reports_action_chain(self):
        enforcer = self._nested_enforcer()
        report = reachability.analyze(enforcer, ['service:loop_a'])

        self.assertEqual(1, len(report.issues))
        issue = report.issues[0]
        self.assertEqual('cycle', issue.kind)
        self.assertEqual('service:loop_a', issue.source)
        self.assertEqual(
            ('service:loop_a', 'service:loop_b'), issue.chain
        )
        self.assertEqual('service:loop_a', issue.reference)

    def test_unreachable_is_advisory_not_failure(self):
        enforcer = self._nested_enforcer()
        report = reachability.analyze(enforcer, ACTION_ROOTS)

        # The orphan and the unused helpers are defined but not reachable
        # from any API action; this must not be treated as a failure.
        self.assertIn('service:orphan', report.unreachable)
        self.assertNotIn('service:orphan', report.reachable)
        blocking_sources = {issue.source for issue in report.issues}
        self.assertNotIn('service:orphan', blocking_sources)

    def test_clean_graph_passes_with_unreachable_helper(self):
        enforcer = self._enforcer_with(
            [
                policy.RuleDefault('svc:action', 'rule:svc:used'),
                policy.RuleDefault('svc:used', 'role:admin'),
                policy.RuleDefault('svc:unused_helper', 'role:member'),
            ]
        )
        report = reachability.analyze(enforcer, ['svc:action'])

        self.assertTrue(report.ok)
        self.assertEqual(['svc:unused_helper'], report.unreachable)
        self.assertEqual([], report.issues)

    def test_diamond_dependency_has_no_false_cycle(self):
        enforcer = self._enforcer_with(
            [
                policy.RuleDefault('svc:root', 'rule:svc:shared'),
                policy.RuleDefault(
                    'svc:shared',
                    '(rule:svc:left and rule:svc:right)',
                ),
                policy.RuleDefault('svc:left', 'role:a'),
                policy.RuleDefault('svc:right', 'rule:svc:left'),
            ]
        )
        report = reachability.analyze(enforcer, ['svc:root'])

        self.assertTrue(report.ok)
        self.assertIn('svc:left', report.reachable)
        self.assertIn('svc:right', report.reachable)

    def test_not_check_keeps_nested_rule_reference(self):
        enforcer = self._enforcer_with(
            [
                policy.RuleDefault('svc:neg', 'not rule:svc:hidden'),
                policy.RuleDefault('svc:hidden', 'role:x'),
                policy.RuleDefault('svc:bad_neg', 'not rule:svc:ghost'),
            ]
        )
        report = reachability.analyze(
            enforcer, ['svc:neg', 'svc:bad_neg']
        )

        self.assertIn('svc:hidden', report.reachable)
        self.assertEqual(1, len(report.issues))
        issue = report.issues[0]
        self.assertEqual('undefined', issue.kind)
        self.assertEqual('svc:bad_neg', issue.source)
        self.assertEqual('svc:ghost', issue.reference)

    def test_default_roots_are_all_registered_actions(self):
        enforcer = self._enforcer_with(
            [
                policy.RuleDefault('svc:action', 'role:admin'),
                policy.RuleDefault('svc:helper', 'role:member'),
            ]
        )
        report = reachability.analyze(enforcer)

        # Without explicit roots every registered policy seeds the traversal,
        # so nothing is unreachable. Explicit roots give the stricter view.
        self.assertEqual(sorted(report.roots), ['svc:action', 'svc:helper'])
        self.assertEqual([], report.unreachable)

    def test_explicit_roots_must_be_registered(self):
        enforcer = self._nested_enforcer()
        self.assertRaises(
            KeyError, reachability.analyze, enforcer, ['not:registered']
        )

    def test_analysis_is_read_only(self):
        enforcer = self._nested_enforcer()
        before = dict(enforcer.registered_rules)
        reachability.analyze(enforcer, ACTION_ROOTS)
        self.assertEqual(before, enforcer.registered_rules)
        # Effective rule store is untouched by the read-only analysis.
        self.assertEqual({}, dict(enforcer.rules))

    def test_format_report_mentions_chain_and_unreachable(self):
        enforcer = self._nested_enforcer()
        text = reachability.format_report(
            reachability.analyze(enforcer, ACTION_ROOTS)
        )

        self.assertIn('Blocking issues found', text)
        self.assertIn('service:broken -> rule:does_not_exist', text)
        self.assertIn('Unreachable rules', text)
        self.assertIn('service:orphan', text)


class ReachabilityShellTestCase(base.PolicyBaseTestCase):
    def _write_policy(self, contents):
        self.create_config_file('policy.yaml', contents)
        return self.get_config_file_fullname('policy.yaml')

    def test_cli_clean_file_returns_zero(self):
        path = self._write_policy(
            "svc:action: 'rule:svc:used'\n"
            "svc:used: 'role:admin'\n"
            "svc:unused_helper: 'role:member'\n"
        )
        stdout = self._capture_stdout()
        exit_code = reachability_shell.main(['--policy-file', path])

        self.assertEqual(0, exit_code)
        self.assertIn(
            'No undefined or cyclical rule references', stdout.getvalue()
        )

    def test_cli_broken_file_returns_nonzero_with_chain(self):
        path = self._write_policy(
            "svc:ok: 'role:admin'\n"
            "svc:bad: 'rule:svc:missing_rule'\n"
        )
        stdout = self._capture_stdout()
        exit_code = reachability_shell.main(
            ['--policy-file', path, '--quiet']
        )

        self.assertEqual(1, exit_code)
        output = stdout.getvalue()
        self.assertIn('[undefined]', output)
        self.assertIn('svc:bad -> rule:svc:missing_rule', output)
        # The healthy policy must not be reported as a failure.
        self.assertNotIn('svc:ok', output)

    def test_cli_cycle_file_returns_nonzero(self):
        path = self._write_policy(
            "svc:a: 'rule:svc:b'\n"
            "svc:b: 'rule:svc:a'\n"
        )
        self._capture_stdout()
        exit_code = reachability_shell.main(['--policy-file', path])
        self.assertEqual(1, exit_code)

    def test_cli_requires_a_source(self):
        with mock.patch('sys.stderr', io.StringIO()):
            self.assertRaises(SystemExit, reachability_shell.main, [])
