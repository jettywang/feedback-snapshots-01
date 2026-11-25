import unittest

import jmespath
from jmespath import functions
from jmespath import parser as parser_module
from jmespath.policy import FunctionPermissionError


class Counter(object):
    """A side-effect-free record of how often a function body ran."""

    def __init__(self):
        self.calls = 0

    def __call__(self, *args):
        self.calls += 1
        return self.calls


class CountingFunctions(functions.Functions):
    def __init__(self, outer, inner):
        super(CountingFunctions, self).__init__()
        self.outer_counter = outer
        self.inner_counter = inner

    @functions.signature({'types': ['string']})
    def _func_outer(self, value):
        self.outer_counter(value)
        return value

    @functions.signature({'types': ['string']})
    def _func_inner(self, value):
        self.inner_counter(value)
        return value

    @functions.signature({'types': ['expref']}, {'types': ['array']})
    def _func_collect(self, expref, items):
        return [expref.visit(expref.expression, item) for item in items]


class FunctionPolicyTest(unittest.TestCase):
    def setUp(self):
        parser_module.Parser.purge()
        self.outer_counter = Counter()
        self.inner_counter = Counter()
        self.registry = CountingFunctions(
            self.outer_counter, self.inner_counter)
        self.data = {'name': 'alpha', 'items': ['a', 'b']}

    def tearDown(self):
        parser_module.Parser.purge()

    def options(self, policy):
        return jmespath.Options(
            custom_functions=self.registry, function_policy=policy)

    def search(self, expression, options):
        return jmespath.search(expression, self.data, options=options)

    def test_denied_outer_does_not_evaluate_an_allowed_argument(self):
        policy = jmespath.FunctionPolicy(allowed=['inner'])
        compiled = jmespath.compile('outer(inner(name))')
        with self.assertRaises(FunctionPermissionError) as captured:
            compiled.search(self.data, self.options(policy))
        self.assertEqual(captured.exception.function_name, 'outer')
        self.assertEqual(captured.exception.path, ('outer',))
        self.assertEqual(captured.exception.checkpoint, 'function_entry')
        self.assertEqual(self.outer_counter.calls, 0)
        self.assertEqual(self.inner_counter.calls, 0)

    def test_allowed_outer_with_denied_inner_reports_the_path(self):
        policy = jmespath.FunctionPolicy(allowed=['outer'])
        with self.assertRaises(FunctionPermissionError) as captured:
            self.search('outer(inner(name))', self.options(policy))
        error = captured.exception
        self.assertEqual(error.function_name, 'inner')
        self.assertEqual(error.path, ('outer', 'inner'))
        self.assertEqual(error.outer_function, 'outer')
        self.assertEqual(error.checkpoint, 'function_entry')
        self.assertEqual(self.inner_counter.calls, 0)

    def test_allowed_nested_functions_both_run(self):
        policy = jmespath.FunctionPolicy(allowed=['outer', 'inner'])
        self.assertEqual(
            self.search('outer(inner(name))', self.options(policy)),
            'alpha')
        self.assertEqual(self.outer_counter.calls, 1)
        self.assertEqual(self.inner_counter.calls, 1)

    def test_expression_reference_direct_denial_names_the_outer_function(self):
        policy = jmespath.FunctionPolicy(allowed=['collect'])
        compiled = jmespath.compile('collect(&inner(@), items)')
        with self.assertRaises(FunctionPermissionError) as captured:
            compiled.search(self.data, self.options(policy))
        error = captured.exception
        self.assertEqual(error.function_name, 'inner')
        self.assertEqual(error.path, ('collect', 'inner'))
        self.assertEqual(error.checkpoint, 'expression_reference')
        self.assertEqual(self.inner_counter.calls, 0)

    def test_expression_reference_uses_the_same_caller_capabilities(self):
        policy = jmespath.FunctionPolicy(allowed=['collect', 'outer'])
        compiled = jmespath.compile(
            'collect(&outer(inner(@)), items)')
        with self.assertRaises(FunctionPermissionError) as captured:
            compiled.search(self.data, self.options(policy))
        error = captured.exception
        self.assertEqual(error.function_name, 'inner')
        self.assertEqual(error.path, ('collect', 'outer', 'inner'))
        self.assertEqual(error.checkpoint, 'expression_reference')
        # ``outer`` is itself allowed, but its argument ``inner(@)`` is
        # resolved before its body can run, so neither body was entered.
        self.assertEqual(self.outer_counter.calls, 0)
        self.assertEqual(self.inner_counter.calls, 0)

    def test_fully_authorized_policy_matches_a_plain_search(self):
        expression = 'collect(&outer(@), items)'
        compiled = jmespath.compile(expression)
        plain = compiled.search(
            self.data,
            options=jmespath.Options(custom_functions=self.registry))
        policy = jmespath.FunctionPolicy(
            allowed=['collect', 'outer', 'inner'])
        gated = compiled.search(self.data, options=self.options(policy))
        self.assertEqual(gated, plain)
        self.assertEqual(gated, ['a', 'b'])
        self.assertEqual(self.outer_counter.calls, 4)

    def test_same_compiled_expression_supports_different_callers(self):
        compiled = jmespath.compile('outer(inner(name))')
        allowed = jmespath.FunctionPolicy(allowed=['outer', 'inner'])
        denied = jmespath.FunctionPolicy(allowed=['outer'])
        self.assertEqual(
            compiled.search(self.data, self.options(allowed)), 'alpha')
        with self.assertRaises(FunctionPermissionError):
            compiled.search(self.data, self.options(denied))
        self.assertEqual(
            compiled.search(self.data, self.options(allowed)), 'alpha')
        self.assertEqual(self.outer_counter.calls, 2)
        self.assertEqual(self.inner_counter.calls, 2)

    def test_builtins_and_unknown_functions_are_unchanged(self):
        policy = jmespath.FunctionPolicy(allowed=[])
        self.assertEqual(
            self.search('length(name)', self.options(policy)), 5)
        with self.assertRaises(jmespath.exceptions.UnknownFunctionError):
            self.search('no_such_function(name)', self.options(policy))

    def test_registry_override_of_a_builtin_is_treated_as_an_extension(self):
        class OverrideLength(functions.Functions):
            @functions.signature({'types': ['array']})
            def _func_length(self, value):
                return 'custom'

        options = jmespath.Options(
            custom_functions=OverrideLength(),
            function_policy=jmespath.FunctionPolicy(allowed=[]))
        with self.assertRaises(FunctionPermissionError) as captured:
            jmespath.search('length(items)', self.data, options=options)
        self.assertEqual(captured.exception.function_name, 'length')

    def test_plain_iterable_can_describe_allowed_extensions(self):
        options = self.options(['outer', 'inner'])
        self.assertEqual(self.search('outer(inner(name))', options), 'alpha')

    def test_allowed_function_still_validates_arguments(self):
        policy = jmespath.FunctionPolicy(
            allowed=['outer', 'inner', 'collect'])
        options = self.options(policy)
        with self.assertRaises(jmespath.exceptions.ArityError):
            self.search('inner(name, name)', options)
        with self.assertRaises(jmespath.exceptions.JMESPathTypeError):
            self.search('inner(items)', options)
        self.assertEqual(self.inner_counter.calls, 0)
        self.assertEqual(
            self.search('collect(&inner(@), items)', options), ['a', 'b'])
        self.assertEqual(self.inner_counter.calls, 2)

    def test_policy_changes_apply_to_the_next_search(self):
        compiled = jmespath.compile('outer(inner(name))')
        policy = jmespath.FunctionPolicy(allowed=['outer', 'inner'])
        options = self.options(policy)
        self.assertEqual(compiled.search(self.data, options), 'alpha')
        revision = policy.revision
        policy.deny('inner')
        self.assertGreater(policy.revision, revision)
        with self.assertRaises(FunctionPermissionError):
            compiled.search(self.data, options)
        policy.allow('inner')
        self.assertEqual(compiled.search(self.data, options), 'alpha')

    def test_default_allowed_permits_unlisted_extensions(self):
        policy = jmespath.FunctionPolicy(default_allowed=True)
        self.assertEqual(
            self.search('outer(inner(name))', self.options(policy)), 'alpha')
        policy.deny('inner')
        with self.assertRaises(FunctionPermissionError):
            self.search('outer(inner(name))', self.options(policy))

    def test_plain_search_without_policy_is_unchanged(self):
        self.assertEqual(
            jmespath.search('length(name)', self.data), 5)


if __name__ == '__main__':
    unittest.main()
