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

import json
from unittest import mock

from oslo_policy import _checks
from oslo_policy import _external
from oslo_policy import policy
from oslo_policy import replay
from oslo_policy.tests import base


class _FakeResponse:
    """Minimal requests.Response stand-in supporting contextlib.closing."""

    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

    def close(self):
        pass


class ReplayBaseTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()
        # HttpCheck is normally registered by the consuming service.
        self._original_http = _checks.registered_checks.get('http')
        _checks.registered_checks['http'] = _external.HttpCheck
        self.addCleanup(self._restore_http_check)
        self.target = {
            'case_id': 'C-2026-1121',
            'project_id': 'p-123',
            'victim_email': 'victim@example.com',
        }
        self.creds = {
            'roles': ['support'],
            'project_id': 'p-123',
            'token': 'super-secret-token',
        }

    def _restore_http_check(self):
        if self._original_http is None:
            _checks.registered_checks.pop('http', None)
        else:
            _checks.registered_checks['http'] = self._original_http

    def enforcer_with(self, rules):
        enforcer = policy.Enforcer(self.conf, use_conf=False)
        enforcer.set_rules(policy.Rules.from_dict(rules))
        return enforcer

    @property
    def deterministic_rules(self):
        return {
            'complaint:view': 'role:support and rule:is_owner',
            'is_owner': 'project_id:%(project_id)s',
        }

    @property
    def remote_rules(self):
        return {
            'complaint:triage': (
                'role:support and ' 'http://risk.example/%(case_id)s'
            ),
        }


class RecordDeterministicTestCase(ReplayBaseTestCase):
    def test_record_matches_native_enforce(self):
        enforcer = self.enforcer_with(self.deterministic_rules)
        decision, record = replay.record_decision(
            enforcer,
            'complaint:view',
            self.target,
            self.creds,
            decision_id='d1',
            recorded_at='2026-11-20T08:30:00Z',
        )
        self.assertTrue(decision)
        self.assertEqual(
            decision,
            enforcer.enforce('complaint:view', self.target, self.creds),
        )
        self.assertEqual(
            [(n.node_id, n.observed_result) for n in record.trace],
            [
                ('n.a0:role:support', True),
                ('n.a1:rule:is_owner', True),
            ],
        )
        self.assertEqual([], record.external_calls)

    def test_record_keeps_no_raw_business_values(self):
        enforcer = self.enforcer_with(self.deterministic_rules)
        _, record = replay.record_decision(
            enforcer,
            'complaint:view',
            self.target,
            self.creds,
            decision_id='d2',
            recorded_at='2026-11-20T08:30:00Z',
        )
        serialized = record.to_json()
        self.assertNotIn('super-secret-token', serialized)
        self.assertNotIn('victim@example.com', serialized)
        self.assertNotIn('p-123', serialized)
        # Evidence still anchors the exact inputs via digests.
        self.assertEqual(replay.digest(self.target), record.target_digest)
        self.assertEqual(replay.digest(self.creds), record.creds_digest)

    def test_allowlist_only_exposes_scalar_whitelisted_keys(self):
        enforcer = self.enforcer_with(self.deterministic_rules)
        _, record = replay.record_decision(
            enforcer,
            'complaint:view',
            self.target,
            self.creds,
            decision_id='d3',
            recorded_at='2026-11-20T08:30:00Z',
            input_allowlist=['project_id'],
        )
        self.assertEqual(
            {'project_id': 'p-123'}, record.input_preview['target']
        )
        self.assertNotIn('victim_email', record.input_preview['target'])

    def test_round_trip_json_is_stable(self):
        enforcer = self.enforcer_with(self.deterministic_rules)
        _, record = replay.record_decision(
            enforcer,
            'complaint:view',
            self.target,
            self.creds,
            decision_id='d4',
            recorded_at='2026-11-20T08:30:00Z',
        )
        rebuilt = replay.DecisionRecord.from_json(record.to_json())
        self.assertEqual(record.to_dict(), rebuilt.to_dict())


class ReplayDeterministicTestCase(ReplayBaseTestCase):
    def _record(self):
        enforcer = self.enforcer_with(self.deterministic_rules)
        return enforcer, replay.record_decision(
            enforcer,
            'complaint:view',
            self.target,
            self.creds,
            decision_id='r1',
            recorded_at='2026-11-20T08:30:00Z',
        )[1]

    def test_offline_replay_reproduces_full_decision(self):
        enforcer, record = self._record()
        report = replay.DecisionReplayer(record).replay(
            enforcer,
            self.target,
            self.creds,
        )
        self.assertEqual(replay.VERDICT_REPRODUCED, report.verdict)
        self.assertTrue(report.recomputed_decision)
        self.assertEqual(
            {'n.a0:role:support', 'n.a1:rule:is_owner'},
            set(report.to_dict()['recomputable_now']),
        )
        self.assertEqual([], report.to_dict()['not_verifiable_offline'])

    def test_input_drift_is_flagged_not_silently_replayed(self):
        enforcer, record = self._record()
        drifted_creds = dict(self.creds, project_id='other-project')
        report = replay.DecisionReplayer(record).replay(
            enforcer,
            self.target,
            drifted_creds,
        )
        self.assertEqual(replay.VERDICT_INPUT_DRIFT, report.verdict)
        self.assertFalse(report.inputs_match)

    def test_rule_drift_is_flagged(self):
        _, record = self._record()
        changed = self.enforcer_with(
            {
                'complaint:view': 'role:admin',
                'is_owner': 'project_id:%(project_id)s',
            }
        )
        report = replay.DecisionReplayer(record).replay(
            changed,
            self.target,
            self.creds,
        )
        self.assertEqual(replay.VERDICT_RULE_DRIFT, report.verdict)
        self.assertFalse(report.ruleset_matches)

    def test_leaf_mismatch_surfaces_as_mismatch(self):
        # Same input/rule digests, but a deterministic leaf would now
        # return a different value because the credentials roles changed
        # while preserving digest mismatch expectations.
        enforcer, record = self._record()
        # Keep digest matching by re-recording is impossible; instead
        # verify mismatch on a leaf by swapping the recorded trace only.
        tampered = json.loads(record.to_json())
        tampered['trace'][0]['observed_result'] = False
        tampered_record = replay.DecisionRecord.from_dict(tampered)
        report = replay.DecisionReplayer(tampered_record).replay(
            enforcer,
            self.target,
            self.creds,
        )
        self.assertEqual(replay.VERDICT_MISMATCH, report.verdict)


class ShortCircuitTestCase(ReplayBaseTestCase):
    def test_and_short_circuit_records_only_evaluated_leaf(self):
        enforcer = self.enforcer_with(
            {'r': 'role:admin and project_id:%(project_id)s'}
        )
        decision, record = replay.record_decision(
            enforcer,
            'r',
            self.target,
            self.creds,
            decision_id='sc1',
            recorded_at='2026-11-20T08:30:00Z',
        )
        self.assertFalse(decision)
        self.assertEqual(1, len(record.trace))
        self.assertEqual('n.a0:role:admin', record.trace[0].node_id)
        report = replay.DecisionReplayer(record).replay(
            enforcer,
            self.target,
            self.creds,
        )
        self.assertEqual(replay.VERDICT_REPRODUCED, report.verdict)
        self.assertFalse(report.recomputed_decision)
        self.assertEqual(1, len(report.leaves))

    def test_or_all_false_evaluates_every_leaf(self):
        enforcer = self.enforcer_with({'r': 'role:admin or role:auditor'})
        creds = {'roles': ['member']}
        decision, record = replay.record_decision(
            enforcer,
            'r',
            {},
            creds,
            decision_id='sc2',
            recorded_at='2026-11-20T08:30:00Z',
        )
        self.assertFalse(decision)
        self.assertEqual(2, len(record.trace))
        report = replay.DecisionReplayer(record).replay(
            enforcer,
            {},
            creds,
        )
        self.assertEqual(replay.VERDICT_REPRODUCED, report.verdict)
        self.assertEqual(2, len(report.leaves))

    def test_not_check_reproduces(self):
        enforcer = self.enforcer_with({'r': 'not role:stack_user'})
        creds = {'roles': ['member']}
        decision, record = replay.record_decision(
            enforcer,
            'r',
            {},
            creds,
            decision_id='sc3',
            recorded_at='2026-11-20T08:30:00Z',
        )
        self.assertTrue(decision)
        report = replay.DecisionReplayer(record).replay(
            enforcer,
            {},
            creds,
        )
        self.assertEqual(replay.VERDICT_REPRODUCED, report.verdict)
        self.assertTrue(report.recomputed_decision)


class RawCheckTreeTestCase(ReplayBaseTestCase):
    def test_raw_check_tree_is_replayable_without_rule_name(self):
        from oslo_policy import _parser

        enforcer = self.enforcer_with({})
        tree = _parser.parse_rule('role:support')
        decision, record = replay.record_decision(
            enforcer,
            tree,
            self.target,
            self.creds,
            decision_id='raw1',
            recorded_at='2026-11-20T08:30:00Z',
        )
        self.assertTrue(decision)
        self.assertIsNone(record.rule_name)
        report = replay.DecisionReplayer(record).replay(
            enforcer,
            self.target,
            self.creds,
        )
        self.assertEqual(replay.VERDICT_REPRODUCED, report.verdict)


class RemoteCheckTestCase(ReplayBaseTestCase):
    def _record_remote(self, response_text='True'):
        enforcer = self.enforcer_with(self.remote_rules)
        recorder = replay.DecisionRecorder(
            'x1',
            '2026-11-20T08:30:00Z',
        )
        with mock.patch(
            'requests.post',
            return_value=_FakeResponse(response_text),
        ) as posted:
            decision, record = recorder.record(
                enforcer,
                'complaint:triage',
                self.target,
                self.creds,
            )
        return enforcer, recorder, record, decision, posted

    def test_records_digests_not_request_bodies(self):
        enforcer, _, record, decision, posted = self._record_remote()
        self.assertEqual(1, posted.call_count)
        self.assertTrue(decision)
        self.assertEqual(1, len(record.external_calls))
        call = record.external_calls[0]
        self.assertTrue(call.observed_result)
        self.assertIsNone(call.error)
        self.assertNotEqual(replay.digest(None), call.request_digest)
        self.assertNotEqual(replay.digest(None), call.response_digest)
        serialized = record.to_json()
        self.assertNotIn('super-secret-token', serialized)
        self.assertNotIn('victim@example.com', serialized)

    def test_offline_replay_marks_remote_leaf_external(self):
        enforcer, _, record, _, _ = self._record_remote()
        # No requests.post patch: offline replay must not touch network.
        with mock.patch(
            'requests.post', side_effect=AssertionError('network call')
        ):
            report = replay.DecisionReplayer(record, mode='offline').replay(
                enforcer,
                self.target,
                self.creds,
            )
        self.assertEqual(replay.VERDICT_EXTERNAL, report.verdict)
        statuses = {leaf.kind: leaf.status for leaf in report.leaves}
        self.assertEqual(replay.VERDICT_REPRODUCED, statuses['role'])
        self.assertEqual(replay.VERDICT_EXTERNAL, statuses['http'])
        not_verifiable = report.to_dict()['not_verifiable_offline']
        self.assertEqual(1, len(not_verifiable))
        self.assertIsNone(
            next(
                leaf.recomputed_result
                for leaf in report.leaves
                if leaf.kind == 'http'
            )
        )

    def test_live_replay_with_provider_reproduces(self):
        enforcer, _, record, _, _ = self._record_remote()

        def provider(check, target, creds, current_rule):
            return target['case_id'] == 'C-2026-1121'

        report = replay.DecisionReplayer(
            record,
            mode='live',
            remote_provider=provider,
        ).replay(enforcer, self.target, self.creds)
        self.assertEqual(replay.VERDICT_REPRODUCED, report.verdict)
        http_leaf = next(leaf for leaf in report.leaves if leaf.kind == 'http')
        self.assertTrue(http_leaf.recomputed_result)

    def test_live_replay_detects_changed_remote_outcome(self):
        enforcer, _, record, _, _ = self._record_remote()
        report = replay.DecisionReplayer(
            record,
            mode='live',
            remote_provider=lambda *args: False,
        ).replay(enforcer, self.target, self.creds)
        self.assertEqual(replay.VERDICT_MISMATCH, report.verdict)
        http_leaf = next(leaf for leaf in report.leaves if leaf.kind == 'http')
        self.assertTrue(http_leaf.observed_result)
        self.assertFalse(http_leaf.recomputed_result)

    def test_remote_error_is_captured_as_evidence(self):
        enforcer = self.enforcer_with(self.remote_rules)
        recorder = replay.DecisionRecorder(
            'x2',
            '2026-11-20T09:00:00Z',
        )

        def raise_timeout(url, **kwargs):
            raise TimeoutError('timeout')

        with mock.patch('requests.post', side_effect=raise_timeout):
            self.assertRaises(
                TimeoutError,
                recorder.record,
                enforcer,
                'complaint:triage',
                self.target,
                self.creds,
            )
        self.assertEqual(1, len(recorder._external_calls))
        self.assertEqual('TimeoutError', recorder._external_calls[0].error)
        # The failure evidence is retained even though no record is
        # returned to the caller.
        self.assertFalse(recorder._external_calls[0].observed_result)


class SealTestCase(ReplayBaseTestCase):
    def test_valid_seal_reproduces(self):
        enforcer = self.enforcer_with(self.deterministic_rules)
        _, record = replay.record_decision(
            enforcer,
            'complaint:view',
            self.target,
            self.creds,
            decision_id='s1',
            recorded_at='2026-11-20T08:30:00Z',
            secret=b'trusted-env-key',
        )
        report = replay.DecisionReplayer(
            record,
            secret=b'trusted-env-key',
        ).replay(enforcer, self.target, self.creds)
        self.assertTrue(report.seal_valid)
        self.assertEqual(replay.VERDICT_REPRODUCED, report.verdict)

    def test_tampered_evidence_fails_seal(self):
        enforcer = self.enforcer_with(self.deterministic_rules)
        _, record = replay.record_decision(
            enforcer,
            'complaint:view',
            self.target,
            self.creds,
            decision_id='s2',
            recorded_at='2026-11-20T08:30:00Z',
            secret=b'trusted-env-key',
        )
        tampered = json.loads(record.to_json())
        tampered['observed_decision'] = not tampered['observed_decision']
        tampered_record = replay.DecisionRecord.from_dict(tampered)
        report = replay.DecisionReplayer(
            tampered_record,
            secret=b'trusted-env-key',
        ).replay(enforcer, self.target, self.creds)
        self.assertFalse(report.seal_valid)
        self.assertEqual(replay.VERDICT_TAMPERED, report.verdict)

    def test_wrong_key_fails_seal(self):
        enforcer = self.enforcer_with(self.deterministic_rules)
        _, record = replay.record_decision(
            enforcer,
            'complaint:view',
            self.target,
            self.creds,
            decision_id='s3',
            recorded_at='2026-11-20T08:30:00Z',
            secret=b'right-key',
        )
        report = replay.DecisionReplayer(
            record,
            secret=b'wrong-key',
        ).replay(enforcer, self.target, self.creds)
        self.assertFalse(report.seal_valid)
        self.assertEqual(replay.VERDICT_TAMPERED, report.verdict)


class FailClosedTestCase(ReplayBaseTestCase):
    def test_unknown_rule_fails_closed_like_enforce(self):
        enforcer = self.enforcer_with(self.deterministic_rules)
        decision, record = replay.record_decision(
            enforcer,
            'does:not:exist',
            self.target,
            self.creds,
            decision_id='f1',
            recorded_at='2026-11-20T08:30:00Z',
        )
        self.assertFalse(decision)
        self.assertFalse(
            enforcer.enforce('does:not:exist', self.target, self.creds)
        )
        self.assertFalse(record.observed_decision)
        self.assertEqual('!', record.rule_text)


class CustomRemoteKindTestCase(ReplayBaseTestCase):
    def test_mark_remote_kind_classifies_custom_check(self):
        class FraudCheck(_checks.Check):
            def __call__(
                self,
                target,
                creds,
                enforcer,
                current_rule=None,
            ):
                return target['case_id'] == 'C-2026-1121'

        _checks.register('fraud', FraudCheck)
        self.addCleanup(_checks.registered_checks.pop, 'fraud')
        replay.mark_remote_kind('fraud')
        self.addCleanup(replay._REMOTE_KINDS.discard, 'fraud')

        enforcer = self.enforcer_with({'r': 'role:support and fraud:score'})
        decision, record = replay.record_decision(
            enforcer,
            'r',
            self.target,
            self.creds,
            decision_id='c1',
            recorded_at='2026-11-20T08:30:00Z',
        )
        self.assertTrue(decision)
        fraud_node = next(
            node for node in record.trace if node.kind == 'fraud'
        )
        self.assertTrue(fraud_node.remote)

        report = replay.DecisionReplayer(record, mode='offline').replay(
            enforcer,
            self.target,
            self.creds,
        )
        self.assertEqual(replay.VERDICT_EXTERNAL, report.verdict)
        fraud_leaf = next(
            leaf for leaf in report.leaves if leaf.kind == 'fraud'
        )
        self.assertEqual(replay.VERDICT_EXTERNAL, fraud_leaf.status)
