"""
Tests for the per-module VBA stomping detection in olevba.

Two layers are tested, on purpose:

* Pure-function unit tests over synthetic pcodedmp output. These pin down the
  module-scoped comparison, in particular that a same-named constant living in
  another module cannot hide a real P-code/source divergence.
* End-to-end tests over real OLE fixtures in
  tests/test-data/olevba/stomping. Those files are produced by
  make_stomping_fixtures.py from sample_with_vba.ppt by rewriting only the
  compressed source region of a module; the P-code performance cache is left
  untouched and is disassembled by the real pcodedmp. No macro is executed and
  no pcodedmp output is fabricated for the end-to-end checks.
"""

import os
import unittest
from os.path import join

from tests.test_utils import DATA_BASE_DIR
from oletools import olevba

STOMPING_DIR = join(DATA_BASE_DIR, 'olevba', 'stomping')

# A synthetic two-module pcodedmp disassembly. The two modules reference the
# same-named constant but each holds a different value.
TWO_MODULE_PCODE = (
    'Processing file: sample.bin\n'
    '=' * 79 + '\n'
    'Module streams:\n'
    'VBA/ModuleA - 100 bytes\n'
    'Line #0:\n'
    '\tLitStr 0x000A "TOKEN_ALPHA"\n'
    'Line #1:\n'
    'VBA/ModuleB - 100 bytes\n'
    'Line #0:\n'
    '\tLitStr 0x000A "TOKEN_BETA"\n'
    'Line #1:\n'
)


class TestParsePcodedmp(unittest.TestCase):
    """parse_pcodedmp_output must attribute every instruction to its module."""

    def test_splits_modules_and_keywords(self):
        modules, errors = olevba.parse_pcodedmp_output(TWO_MODULE_PCODE)
        self.assertEqual(sorted(modules), ['ModuleA', 'ModuleB'])
        self.assertEqual(modules['ModuleA']['stream_path'], 'VBA/ModuleA')
        self.assertEqual(modules['ModuleA']['keywords'], {'"TOKEN_ALPHA"'})
        self.assertEqual(modules['ModuleB']['keywords'], {'"TOKEN_BETA"'})
        # instruction lines are retained as the comparison basis
        self.assertTrue(modules['ModuleA']['raw_lines'])
        self.assertEqual(errors, [])

    def test_strips_call_prefix_and_id_tokens(self):
        output = (
            'Module streams:\n'
            'VBA/Mod - 10 bytes\n'
            'Line #0:\n'
            '\tArgsCall (Call) CreateObject 0x0001 \n'
            '\tLd id_FFFF 0x0000 \n'
            '\tSt counter 0x0000 \n'
        )
        modules, _ = olevba.parse_pcodedmp_output(output)
        self.assertEqual(modules['Mod']['keywords'],
                         {'CreateObject', 'counter'})

    def test_normalizes_embedded_double_quotes(self):
        output = (
            'Module streams:\n'
            'VBA/Mod - 10 bytes\n'
            'Line #0:\n'
            '\tLitStr 0x0006 "a ""quoted"" word"\n'
        )
        modules, _ = olevba.parse_pcodedmp_output(output)
        # pcodedmp emits single quotes; the parser doubles them to match VBA
        self.assertEqual(modules['Mod']['keywords'],
                         {'"a """"quoted"""" word"'})

    def test_collects_error_lines(self):
        output = (
            'Module streams:\n'
            'VBA/Mod - 10 bytes\n'
            'Error: something went wrong.\n'
        )
        modules, errors = olevba.parse_pcodedmp_output(output)
        self.assertEqual(modules['Mod']['raw_lines'], [])
        self.assertEqual(errors, ['Error: something went wrong.'])

    def test_module_header_with_parent_prefix(self):
        output = (
            'Module streams:\n'
            'Macros/VBA/Sheet1 - 12 bytes\n'
            'Line #0:\n'
            '\tLd foo 0x0000 \n'
        )
        modules, _ = olevba.parse_pcodedmp_output(output)
        self.assertIn('Sheet1', modules)
        self.assertEqual(modules['Sheet1']['stream_path'], 'Macros/VBA/Sheet1')


class TestModuleScopedComparison(unittest.TestCase):
    """The comparison must stay inside each module boundary."""

    def setUp(self):
        self.pcode_modules, _ = olevba.parse_pcodedmp_output(TWO_MODULE_PCODE)

    def test_same_named_constant_in_other_module_does_not_mask(self):
        # Each source contains the OTHER module's token: a global search would
        # find both strings somewhere and wrongly report "no stomping".
        source = {
            'ModuleA': 'Const SECRET = "TOKEN_BETA"\r\n',
            'ModuleB': 'Const SECRET = "TOKEN_ALPHA"\r\n',
        }
        results = olevba.compare_pcode_with_source(self.pcode_modules, source)
        self.assertEqual(results['ModuleA']['status'], olevba.STOMPING_MISMATCH)
        self.assertEqual(results['ModuleA']['missing_keywords'],
                         ['"TOKEN_ALPHA"'])
        self.assertEqual(results['ModuleB']['status'], olevba.STOMPING_MISMATCH)
        self.assertEqual(results['ModuleB']['missing_keywords'],
                         ['"TOKEN_BETA"'])

    def test_same_module_placement_matches(self):
        source = {
            'ModuleA': 'Const SECRET = "TOKEN_ALPHA"\r\n',
            'ModuleB': 'Const SECRET = "TOKEN_BETA"\r\n',
        }
        results = olevba.compare_pcode_with_source(self.pcode_modules, source)
        self.assertTrue(all(r['status'] == olevba.STOMPING_MATCH
                            for r in results.values()))
        self.assertTrue(all(not r['missing_keywords'] for r in results.values()))

    def test_missing_source_is_distinct_status(self):
        # ModuleB's source could not be extracted: it must not be called clean
        source = {'ModuleA': 'Const SECRET = "TOKEN_ALPHA"\r\n'}
        results = olevba.compare_pcode_with_source(self.pcode_modules, source)
        self.assertEqual(results['ModuleA']['status'], olevba.STOMPING_MATCH)
        self.assertEqual(results['ModuleB']['status'],
                         olevba.STOMPING_SOURCE_MISSING)
        self.assertFalse(results['ModuleB']['source_present'])
        # the unanalysed module still carries its P-code evidence for review
        self.assertEqual(results['ModuleB']['missing_keywords'],
                         ['"TOKEN_BETA"'])


class TestEndToEndFixtures(unittest.TestCase):
    """Real OLE files processed by both olevba and pcodedmp; no macro runs."""

    def _parser(self, filename):
        return olevba.VBA_Parser(join(STOMPING_DIR, filename))

    def test_clean_recompressed_matches(self):
        parser = self._parser('clean_recompressed.bin')
        try:
            self.assertFalse(parser.detect_vba_stomping())
            report = parser.get_vba_stomping_report()
            self.assertTrue(report['analysed'])
            self.assertEqual(report['overall_status'], olevba.STOMPING_MATCH)
            module = report['modules']['Module1']
            self.assertEqual(module['status'], olevba.STOMPING_MATCH)
            self.assertEqual(module['missing_keywords'], [])
            self.assertTrue(module['source_present'])
        finally:
            parser.close()

    def test_stomped_module_is_detected_with_module_evidence(self):
        parser = self._parser('stomped_module.bin')
        try:
            self.assertTrue(parser.detect_vba_stomping())
            report = parser.get_vba_stomping_report()
            self.assertEqual(report['overall_status'],
                             olevba.STOMPING_MISMATCH)
            self.assertEqual(report['mismatched_modules'], ['Module1'])
            module = report['modules']['Module1']
            self.assertEqual(module['status'], olevba.STOMPING_MISMATCH)
            # the evidence traces back to the module and the exact P-code
            # string that the module's own source code is missing
            self.assertIn('"The action button clicked!"',
                          module['missing_keywords'])
            self.assertEqual(module['stream_path'], 'VBA/Module1')
        finally:
            parser.close()

    def test_repeated_calls_are_stable_and_ignore_synthetic_pcode_module(self):
        # After the first detection a synthetic "VBA P-code" macro is appended
        # for keyword scanning; it must not pollute the per-module source map on
        # subsequent calls or flip the cached verdict.
        parser = self._parser('stomped_module.bin')
        try:
            first = parser.detect_vba_stomping()
            parser.extract_all_macros()  # populates self.modules incl. synthetic
            second = parser.detect_vba_stomping()
            self.assertEqual(first, second)
            report = parser.get_vba_stomping_report()
            self.assertEqual(set(report['modules']), {'Module1'})
            self.assertNotIn('VBA P-code', report['modules'])
        finally:
            parser.close()

    def test_unparseable_pcode_is_not_cached_as_clean(self):
        parser = self._parser('pcode_unparseable.bin')
        try:
            # the parser still extracts the (benign) source code...
            self.assertTrue(parser.extract_all_macros())
            # ...but cannot compare it, and must not answer False ("no stomping")
            self.assertIsNone(parser.detect_vba_stomping())
            report = parser.get_vba_stomping_report()
            self.assertFalse(report['analysed'])
            self.assertEqual(report['overall_status'],
                             olevba.STOMPING_PCODE_PARSE_ERROR)
            # calling again keeps the inconclusive state, never flips to clean
            self.assertIsNone(parser.detect_vba_stomping())
            self.assertIsNone(parser.vba_stomping_detected)
        finally:
            parser.close()

    def test_in_memory_input_is_inconclusive(self):
        path = join(STOMPING_DIR, 'stomped_module.bin')
        with open(path, 'rb') as handle:
            parser = olevba.VBA_Parser('from_memory.bin', data=handle.read())
        try:
            self.assertFalse(parser.file_on_disk)
            self.assertIsNone(parser.detect_vba_stomping())
            report = parser.get_vba_stomping_report()
            self.assertFalse(report['analysed'])
            self.assertEqual(report['overall_status'],
                             olevba.STOMPING_IN_MEMORY)
        finally:
            parser.close()

    def test_unsupported_pcode_tool_is_inconclusive(self):
        # Reproduce the state left by a failed pcodedmp import: the detection
        # must report "unsupported" rather than a negative result.
        parser = self._parser('stomped_module.bin')
        try:
            parser.pcode_status = olevba.STOMPING_PCODE_UNSUPPORTED
            parser.pcodedmp_output = ''
            self.assertIsNone(parser.detect_vba_stomping())
            report = parser.get_vba_stomping_report()
            self.assertFalse(report['analysed'])
            self.assertEqual(report['overall_status'],
                             olevba.STOMPING_PCODE_UNSUPPORTED)
        finally:
            parser.close()

    def test_text_input_is_a_genuine_negative(self):
        text_path = join(os.path.dirname(STOMPING_DIR), os.pardir,
                         'basic', 'text')
        text_path = os.path.abspath(text_path)
        parser = olevba.VBA_Parser(text_path)
        try:
            self.assertFalse(parser.detect_vba_stomping())
            report = parser.get_vba_stomping_report()
            self.assertTrue(report['analysed'])
            self.assertEqual(report['overall_status'], olevba.STOMPING_MATCH)
        finally:
            parser.close()


class TestModuleKeyNormalization(unittest.TestCase):
    def test_stream_path_variants(self):
        key = olevba._module_key_from_stream_path
        self.assertEqual(key('VBA/Module1'), 'Module1')
        self.assertEqual(key('Macros/VBA/Module1'), 'Module1')
        self.assertEqual(key('word/vbaProject.bin/VBA/Sheet1'), 'Sheet1')
        self.assertEqual(key('Module1'), 'Module1')


class TestStatusTaxonomy(unittest.TestCase):
    def test_analysed_and_unanalysed_partition(self):
        # every status belongs to exactly one of the two groups
        all_statuses = {
            olevba.STOMPING_MATCH, olevba.STOMPING_MISMATCH,
            olevba.STOMPING_SOURCE_MISSING, olevba.STOMPING_PCODE_UNSUPPORTED,
            olevba.STOMPING_IN_MEMORY, olevba.STOMPING_PCODE_PARSE_ERROR,
        }
        grouped = (set(olevba.STOMPING_ANALYSED_STATUSES)
                   | set(olevba.STOMPING_UNANALYSED_STATUSES))
        self.assertEqual(grouped, all_statuses)
        self.assertFalse(
            set(olevba.STOMPING_ANALYSED_STATUSES)
            & set(olevba.STOMPING_UNANALYSED_STATUSES))
        # the three inconclusive states are exactly the ones callers must not
        # treat as a clean result
        self.assertEqual(set(olevba.STOMPING_UNANALYSED_STATUSES),
                         {olevba.STOMPING_PCODE_UNSUPPORTED,
                          olevba.STOMPING_IN_MEMORY,
                          olevba.STOMPING_PCODE_PARSE_ERROR})


if __name__ == '__main__':
    unittest.main()
