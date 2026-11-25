import unittest

import jmespath
from jmespath import functions
from jmespath import parser as parser_module
from jmespath.policy import ExtensionRevokedError


class Gate(object):
    """A controllable rendezvous for a logging-only extension."""

    def __init__(self):
        self.calls = 0

    def __call__(self, value):
        self.calls += 1
        return value


class HandoffFunctions(functions.Functions):
    """Extensions that only record when their body is actually entered."""

    def __init__(self, echo_gate, map_gate):
        super(HandoffFunctions, self).__init__()
        self.echo_gate = echo_gate
        self.map_gate = map_gate

    @functions.signature({'types': ['string']})
    def _func_audit_echo(self, text):
        return self.echo_gate(text)

    @functions.signature({'types': ['expref']}, {'types': ['array']})
    def _func_audit_map(self, expref, array):
        self.map_gate(len(array))
        return [expref.visit(expref.expression, item) for item in array]


class PolicyHandoffTest(unittest.TestCase):
    def setUp(self):
        parser_module.Parser.purge()
        self.echo_gate = Gate()
        self.map_gate = Gate()
        self.registry = HandoffFunctions(self.echo_gate, self.map_gate)
        self.options = jmespath.Options(custom_functions=self.registry)
        self.policy = jmespath.Policy(
            allowed=['audit_echo', 'audit_map'])
        self.audit = jmespath.AuditLog()
        self.data = {'name': 'alpha', 'items': ['a', 'b', 'c']}

    def tearDown(self):
        parser_module.Parser.purge()

    def search(self, expression, query_id):
        return jmespath.search(
            expression, self.data, self.options, policy=self.policy,
            audit=self.audit, query_id=query_id)

    def events(self, query_id):
        return self.audit.for_query(query_id)

    def test_default_search_without_policy_is_unchanged(self):
        result = jmespath.search('length(name)', self.data)
        self.assertEqual(result, 5)

    def test_revocation_before_entry_blocks_without_entering_function(self):
        self.policy.revoke('audit_echo')
        with self.assertRaises(ExtensionRevokedError) as captured:
            self.search('audit_echo(name)', 'before-entry')
        self.assertEqual(captured.exception.checkpoint, 'function_entry')
        self.assertEqual(self.echo_gate.calls, 0)
        status = [e['event'] for e in self.events('before-entry')]
        self.assertEqual(status, ['search_start', 'function_check',
                                  'search_cancelled'])
        check = self.events('before-entry')[1]
        self.assertFalse(check['allowed'])

    def test_revocation_after_entry_lets_search_complete(self):
        def revoke_while_running(_value):
            # The body is already running: revoke before it returns.
            self.policy.revoke('audit_echo')
            self.echo_gate.calls += 1
            return 'ran'

        self.registry.echo_gate = revoke_while_running
        result = self.search('audit_echo(name)', 'after-entry')
        self.assertEqual(result, 'ran')
        status = [e['event'] for e in self.events('after-entry')]
        self.assertEqual(status, ['search_start', 'function_check',
                                  'search_completed'])
        check = self.events('after-entry')[1]
        self.assertTrue(check['allowed'])
        self.assertEqual(check['policy_revision'], 0)

    def test_revocation_before_deferred_expression_cancels_late(self):
        def revoke_before_expref(_size):
            # audit_map already started, but its expref has not run yet.
            self.policy.revoke('audit_echo')

        self.registry.map_gate = revoke_before_expref
        with self.assertRaises(ExtensionRevokedError) as captured:
            self.search('audit_map(&audit_echo(@), items)', 'deferred')
        self.assertEqual(captured.exception.checkpoint,
                         'deferred_expression')
        self.assertEqual(self.map_gate.calls, 0)
        checks = [e for e in self.events('deferred')
                  if e['event'] == 'function_check']
        self.assertEqual(
            [(c['function'], c['checkpoint'], c['allowed']) for c in checks],
            [('audit_map', 'function_entry', True),
             ('audit_echo', 'deferred_expression', False)])
        self.assertEqual(
            [e['event'] for e in self.events('deferred')][-1],
            'search_cancelled')
        # The higher order function body was entered; the nested extension
        # body never was.
        self.assertEqual(self.echo_gate.calls, 0)

    def test_next_request_observes_new_revision(self):
        self.assertEqual(self.search('audit_echo(name)', 'rev0'), 'alpha')
        self.policy.revoke('audit_echo')
        with self.assertRaises(ExtensionRevokedError):
            self.search('audit_echo(name)', 'rev1')
        start_revisions = [
            e['policy_revision'] for e in self.audit.records
            if e['event'] == 'search_start']
        self.assertEqual(start_revisions, [0, 1])

    def test_compiled_result_reused_on_extension_free_path(self):
        compiled = jmespath.compile('length(name)')
        first = compiled.search(self.data, policy=self.policy,
                                audit=self.audit, query_id='cache-1')
        self.policy.revoke('audit_echo')
        second = compiled.search(self.data, policy=self.policy,
                                 audit=self.audit, query_id='cache-2')
        self.assertEqual((first, second), (5, 5))
        self.assertIn(compiled, parser_module.Parser._CACHE.values())

    def test_compiled_extension_expression_blocks_on_reuse(self):
        compiled = jmespath.compile('audit_echo(name)')
        self.assertEqual(
            compiled.search(self.data, options=self.options,
                            policy=self.policy, audit=self.audit,
                            query_id='reuse-ok'), 'alpha')
        self.policy.revoke('audit_echo')
        with self.assertRaises(ExtensionRevokedError):
            compiled.search(self.data, options=self.options,
                            policy=self.policy, audit=self.audit,
                            query_id='reuse-blocked')

    def test_shared_functions_instance_is_not_mutated(self):
        original_call = self.registry.__dict__.get('call_function')
        self.search('audit_echo(name)', 'shared-a')
        # The gate is installed on the interpreter's copy, never on the
        # shared registry handed in through Options.
        self.assertNotIn('call_function', self.registry.__dict__)
        self.assertIsNone(original_call)
        self.policy.revoke('audit_echo')
        with self.assertRaises(ExtensionRevokedError):
            self.search('audit_echo(name)', 'shared-b')
        self.assertNotIn('call_function', self.registry.__dict__)

    def test_built_in_functions_bypass_the_policy(self):
        self.policy.revoke('audit_echo')
        result = self.search('length(name)', 'builtin')
        self.assertEqual(result, 5)
        checks = [e for e in self.events('builtin')
                  if e['event'] == 'function_check']
        self.assertEqual(checks, [])


if __name__ == '__main__':
    unittest.main()
