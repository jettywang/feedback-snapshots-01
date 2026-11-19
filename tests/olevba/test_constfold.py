# -*- coding: utf-8 -*-
"""
Tests for the traceable static VBA constant-expression folder
(oletools.vba_constfold).

These tests focus on the guarantees required for safe deobfuscation review:
- the same value can come from different source fragments and is reported
  separately each time;
- partially evaluable expressions keep their derived steps but do not invent a
  final value;
- unknown variables, object/member calls and overflow stop evaluation with a
  reason instead of being guessed;
- results are bound to their module and exact character span;
- nothing relies on eval/exec or on executing VBA.
"""

import unittest

from oletools import vba_constfold as cf


class TestFoldExpression(unittest.TestCase):
    """Single-expression folding via fold_expression()."""

    def test_chr_concatenation(self):
        result = cf.fold_expression('Chr(65) & Chr(66)')
        self.assertEqual(result.status, cf.FoldResult.FULL)
        self.assertEqual(result.value, 'AB')
        self.assertEqual(result.vtype, cf.TYPE_STRING)

    def test_nested_functions_and_parentheses(self):
        result = cf.fold_expression('UCase(Mid("abcdef", 2, 3))')
        self.assertEqual(result.status, cf.FoldResult.FULL)
        self.assertEqual(result.value, 'BCD')

    def test_hex_literal_and_arithmetic(self):
        result = cf.fold_expression('Chr(&H41 + 0)')
        self.assertEqual(result.status, cf.FoldResult.FULL)
        self.assertEqual(result.value, 'A')

    def test_strreverse(self):
        result = cf.fold_expression('StrReverse("olleH")')
        self.assertEqual(result.status, cf.FoldResult.FULL)
        self.assertEqual(result.value, 'Hello')

    def test_steps_are_recomputable(self):
        result = cf.fold_expression('Chr(1 + 2)')
        self.assertEqual(result.status, cf.FoldResult.FULL)
        operations = [step['operation'] for step in result.steps]
        self.assertIn('+', operations)
        self.assertEqual(operations[-1], 'Chr')
        # every step carries the exact source it came from
        for step in result.steps:
            self.assertTrue(step['source'])
            self.assertIn(step['type'],
                          (cf.TYPE_STRING, cf.TYPE_INTEGER, cf.TYPE_LONG,
                           cf.TYPE_LONGLONG))

    def test_unknown_variable_stops_but_keeps_input(self):
        # No transformation completes when the variable is unknown, so this is
        # a STOPPED expression; the quoted input is still retained as a step.
        result = cf.fold_expression('"Shell" & SomeVariable')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)
        self.assertIsNone(result.value)
        self.assertTrue(result.steps)            # "Shell" input is retained
        self.assertIn('SomeVariable', result.stop_reason)

    def test_partial_requires_a_completed_transformation(self):
        # Chr(100) fully evaluates to "d" before the member call is reached,
        # so one derived step exists and the result is PARTIAL.
        result = cf.fold_expression('Chr(100) & obj.Environment')
        self.assertEqual(result.status, cf.FoldResult.PARTIAL)
        self.assertEqual(len(result.steps), 2)   # literal 100 and Chr(100)
        self.assertIn('member access', result.stop_reason)

    def test_failed_function_with_only_input_is_stopped(self):
        result = cf.fold_expression('Asc("")')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)
        self.assertIn('non-empty', result.stop_reason)

    def test_unknown_function_stops(self):
        result = cf.fold_expression('EvilFunc(1)')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)
        self.assertIn('whitelist', result.stop_reason)

    def test_division_by_zero_stops(self):
        result = cf.fold_expression('10 \\ 0')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)
        self.assertIn('division by zero', result.stop_reason)

    def test_explicit_integer_overflow_stops(self):
        # explicit "%" fixes the 16-bit boundary: this must overflow, not wrap
        result = cf.fold_expression('32767% + 1%')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)
        self.assertIn('overflow', result.stop_reason)

    def test_bare_literal_promotes_on_overflow(self):
        # bare literals are allowed to widen Integer -> Long like VBA
        result = cf.fold_expression('32767 + 1')
        self.assertEqual(result.status, cf.FoldResult.FULL)
        self.assertEqual(result.value, 32768)
        self.assertEqual(result.vtype, cf.TYPE_LONG)

    def test_explicit_long_overflow_stops(self):
        result = cf.fold_expression('2147483647& + 1')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)
        self.assertIn('overflow', result.stop_reason)

    def test_floating_point_not_guessed(self):
        result = cf.fold_expression('1.5 + 2')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)
        self.assertIn('floating-point', result.stop_reason)

    def test_float_division_not_supported(self):
        result = cf.fold_expression('10 / 4')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)
        self.assertIn('floating-point division', result.stop_reason)

    def test_chr_out_of_range_stops(self):
        result = cf.fold_expression('Chr(300)')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)

    def test_concat_needs_strings(self):
        result = cf.fold_expression('10 & 20')
        self.assertEqual(result.status, cf.FoldResult.STOPPED)
        self.assertIn('CStr', result.stop_reason)

    def test_explicit_cstr_concat(self):
        result = cf.fold_expression('CStr(10) & CStr(20)')
        self.assertEqual(result.status, cf.FoldResult.FULL)
        self.assertEqual(result.value, '1020')

    def test_comparison_operators_stop(self):
        for expression in ('1 = 1', '5 > 3', 'Chr(65) = Chr(65)'):
            result = cf.fold_expression(expression)
            self.assertEqual(result.status, cf.FoldResult.STOPPED, expression)
            self.assertIn('comparison', result.stop_reason)

    def test_bitwise_operators_are_supported(self):
        self.assertEqual(cf.fold_expression('3 AND 5').value, 1)
        self.assertEqual(cf.fold_expression('1 OR 2').value, 3)
        self.assertEqual(cf.fold_expression('6 XOR 3').value, 5)

    def test_integer_division_and_mod(self):
        self.assertEqual(cf.fold_expression('10 \\ 3').value, 3)
        self.assertEqual(cf.fold_expression('10 Mod 3').value, 1)

    def test_chrw_negative_code_point(self):
        result = cf.fold_expression('ChrW(-1)')
        self.assertEqual(result.status, cf.FoldResult.FULL)
        self.assertEqual(result.value, '￿')


class TestModuleScanning(unittest.TestCase):
    """Module-level scanning, span binding and source traceability."""

    MODULE = (
        'Sub AutoOpen()\n'
        '    a = Chr(119) & Chr(115) & Chr(99) & Chr(114) & Chr(105) '
        '& Chr(112) & Chr(116)\n'
        '    b = "wscrip" & "t"\n'
        '    c = StrReverse("tpircsw")\n'
        '    d = Chr(83 + 4) & _\n'
        '        Chr(104)\n'
        '    e = "Shell" & SomeVariable\n'
        '    f = Chr(100) & obj.Environment\n'
        'End Sub\n'
    )

    def test_same_value_different_sources(self):
        results = cf.evaluate_module('Module1', self.MODULE)
        full = [r for r in results if r.status == cf.FoldResult.FULL
                and r.value == 'wscript']
        # Chr chain, literal concatenation and StrReverse are three distinct
        # source fragments that all yield the same value.
        self.assertEqual(len(full), 3)
        sources = {r.source for r in full}
        self.assertEqual(len(sources), 3)
        for result in full:
            self.assertEqual(result.module_name, 'Module1')

    def test_strreverse_same_value_third_source(self):
        results = cf.evaluate_module('Module1', self.MODULE)
        reverse = [r for r in results if 'StrReverse' in r.source]
        self.assertEqual(len(reverse), 1)
        self.assertEqual(reverse[0].value, 'wscript')

    def test_line_continuation_is_folded(self):
        results = cf.evaluate_module('Module1', self.MODULE)
        cont = [r for r in results if '_' in r.source]
        self.assertEqual(len(cont), 1)
        self.assertEqual(cont[0].status, cf.FoldResult.FULL)
        self.assertEqual(cont[0].value, 'Wh')

    def test_span_binds_to_original_text(self):
        results = cf.evaluate_module('Module1', self.MODULE)
        for result in results:
            self.assertEqual(
                self.MODULE[result.start:result.end], result.source)

    def test_partial_and_stop_classification(self):
        results = cf.evaluate_module(
            'Module1', self.MODULE, include_stops=True)
        stop_var = next(r for r in results if 'SomeVariable' in r.source)
        partial_obj = next(r for r in results if 'obj.Environment' in r.source)
        # unknown variable with no completed transformation -> STOPPED, but the
        # quoted "Shell" input fragment is still retained as a step
        self.assertEqual(stop_var.status, cf.FoldResult.STOPPED)
        self.assertIn('SomeVariable', stop_var.stop_reason)
        self.assertTrue(any(s['source'] == '"Shell"' for s in stop_var.steps))
        # object member access after Chr(100) -> PARTIAL, "d" was derived
        self.assertEqual(partial_obj.status, cf.FoldResult.PARTIAL)
        self.assertIn('member access', partial_obj.stop_reason)

    def test_stops_excluded_by_default(self):
        default = cf.evaluate_module('Module1', self.MODULE)
        with_stops = cf.evaluate_module(
            'Module1', self.MODULE, include_stops=True)
        self.assertGreaterEqual(len(with_stops), len(default))
        self.assertTrue(
            all(r.status != cf.FoldResult.STOPPED for r in default))

    def test_no_bulk_decode_unrelated_strings(self):
        # A hex-looking literal that is never part of an expression must not be
        # decoded out of context: only parsed expressions produce results.
        code = 'Const x As String = "4142"\n'
        results = cf.evaluate_module('Module1', code)
        # the bare quoted string alone carries no operation, so no fold result
        self.assertEqual(results, [])

    def test_to_dict_is_json_ready(self):
        result = cf.fold_expression('Chr(65)')
        data = result.to_dict()
        self.assertEqual(data['value'], 'A')
        self.assertIsInstance(data['steps'], list)
        self.assertTrue(all('start' in s and 'end' in s for s in data['steps']))

    def test_colon_separated_statements(self):
        code = 'x = Chr(65): y = Mid("ABCDEF", 2, 3) & Chr(66)\n'
        results = cf.evaluate_module('Module1', code)
        values = sorted(r.value for r in results)
        self.assertEqual(values, ['A', 'BCDB'])

    def test_commas_inside_call_are_not_separators(self):
        results = cf.evaluate_module('M', 'z = Replace("a-b", "-", "+")\n')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].value, 'a+b')


class TestNoDynamicExecution(unittest.TestCase):
    """Guard against accidentally introducing eval/exec-style evaluation."""

    def test_module_has_no_dynamic_execution(self):
        import inspect
        source = inspect.getsource(cf)
        for forbidden in ('eval(', 'exec(', 'compile(', 'subprocess',
                          'os.system', '__import__'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
