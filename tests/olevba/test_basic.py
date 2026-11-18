"""
Test basic functionality of olevba[3]
"""

import unittest
import os
from os.path import join, splitext
import re
import json

# Directory with test data, independent of current working directory
from tests.test_utils import DATA_BASE_DIR, call_and_capture


class TestOlevbaBasic(unittest.TestCase):
    """Tests olevba basic functionality"""

    def test_text_behaviour(self):
        """Test behaviour of olevba when presented with pure text file."""
        self.do_test_behaviour('text')

    def test_empty_behaviour(self):
        """Test behaviour of olevba when presented with pure text file."""
        self.do_test_behaviour('empty')

    def do_test_behaviour(self, filename):
        """Helper for test_{text,empty}_behaviour."""
        input_file = join(DATA_BASE_DIR, 'basic', filename)
        output, _ = call_and_capture('olevba', args=(input_file, ))

        # check output
        self.assertTrue(re.search(r'^Type:\s+Text\s*$', output, re.MULTILINE),
                        msg='"Type: Text" not found in output:\n' + output)
        self.assertTrue(re.search(r'^No suspicious .+ found.$', output,
                                  re.MULTILINE),
                        msg='"No suspicous...found" not found in output:\n' + \
                            output)
        self.assertNotIn('error', output.lower())

        # check warnings
        for line in output.splitlines():
            if line.startswith('WARNING ') and 'encrypted' in line:
                continue   # encryption warnings are ok
            elif 'warn' in line.lower():
                raise self.fail('Found "warn" in output line: "{}"'
                                .format(line.rstrip()))
        # TODO: I disabled this test because we do not log "not encrypted" as warning anymore
        # to avoid other issues.
        # If we really want to test this, then the test should be run with log level INFO:
        # self.assertIn('not encrypted', output)

    def test_rtf_behaviour(self):
        """Test behaviour of olevba when presented with an rtf file."""
        input_file = join(DATA_BASE_DIR, 'msodde', 'RTF-Spec-1.7.rtf')
        output, ret_code = call_and_capture('olevba', args=(input_file, ),
                                            accept_nonzero_exit=True)

        # check that return code is olevba.RETURN_OPEN_ERROR
        self.assertEqual(ret_code, 5)

        # check output:
        self.assertIn('FileOpenError', output)
        self.assertIn('is RTF', output)
        self.assertIn('rtfobj', output)
        # TODO: I disabled this test because we do not log "not encrypted" as warning anymore
        # to avoid other issues.
        # If we really want to test this, then the test should be run with log level INFO:
        # self.assertIn('not encrypted', output)

        # check warnings
        for line in output.splitlines():
            if line.startswith('WARNING ') and 'encrypted' in line:
                continue   # encryption warnings are ok
            elif 'warn' in line.lower():
                raise self.fail('Found "warn" in output line: "{}"'
                                .format(line.rstrip()))

    def test_crypt_return(self):
        """
        Test that encrypted files give a certain return code.

        Currently, only the encryption applied by Office 2010 (CryptoApi RC4
        Encryption) is tested.
        """
        CRYPT_DIR = join(DATA_BASE_DIR, 'encrypted')
        CRYPT_RETURN_CODE = 9
        ADD_ARGS = [], ['-d', ], ['-a', ], ['-j', ], ['-t', ]   # only 1st file
        EXCEPTIONS = ['autostart-encrypt-standardpassword.xls',   # These ...
                      'autostart-encrypt-standardpassword.xlsm',  # files ...
                      'autostart-encrypt-standardpassword.xlsb',  # are ...
                      'dde-test-encrypt-standardpassword.xls',    # automati...
                      'dde-test-encrypt-standardpassword.xlsx',   # ...cally...
                      'dde-test-encrypt-standardpassword.xlsm',   # decrypted.
                      'dde-test-encrypt-standardpassword.xlsb']
        for filename in os.listdir(CRYPT_DIR):
            if filename in EXCEPTIONS:
                continue
            full_name = join(CRYPT_DIR, filename)
            for args in ADD_ARGS:
                _, ret_code = call_and_capture('olevba',
                                               args=[full_name, ] + args,
                                               accept_nonzero_exit=True)
                self.assertEqual(ret_code, CRYPT_RETURN_CODE,
                                 msg='Wrong return code {} for args {}'\
                                     .format(ret_code, args + [filename, ]))

                # test only first file with all arg combinations, others just
                # without arg (test takes too long otherwise
                ADD_ARGS = ([], )

    def test_xlm(self):
        """Test that xlm macros are found."""
        XLM_DIR = join(DATA_BASE_DIR, 'excel4-macros')
        ADD_ARGS = ['-j']

        for filename in os.listdir(XLM_DIR):
            full_name = join(XLM_DIR, filename)
            suffix = splitext(filename)[1]
            out_str, ret_code = call_and_capture('olevba',
                                                 args=[full_name, ] + ADD_ARGS,
                                                 accept_nonzero_exit=True)
            output = json.loads(out_str)
            self.assertGreaterEqual(len(output), 2)
            self.assertEqual(output[0]['type'], 'MetaInformation')
            self.assertEqual(output[0]['script_name'], 'olevba')
            for entry in output[1:]:
                if entry['type'] in ('msg', 'warning'):
                    continue    # ignore messages
                result = entry
                break
            self.assertTrue(result['json_conversion_successful'])
            if suffix in ('.xlsb', '.xltm', '.xlsm'):
                # TODO: cannot extract xlm macros for these types yet
                self.assertEqual(result['macros'], [])
            else:
                code = result['macros'][0]['code']
                if suffix == '.slk':
                    self.assertIn('Excel 4 macros extracted', code)
                else:
                    self.assertIn('Excel 4.0 macro sheet', code)
                self.assertIn('Auto_Open', code)
                if 'excel5' not in filename:    # TODO: is not found in excel5
                    self.assertIn('ALERT(', code)
                self.assertIn('HALT()', code)

                self.assertIn(len(result['analysis']), (2, 3))
                types = [entry['type'] for entry in result['analysis']]
                keywords = [entry['keyword'] for entry in result['analysis']]
                self.assertIn('Auto_Open', keywords)
                self.assertIn('XLM macro', keywords)
                self.assertIn('AutoExec', types)
                self.assertIn('Suspicious', types)

    def test_dir_stream_record_project_compat_version(self):
        """Test PROJECTCOMPATVERSION record on dir stream with a ppt file."""
        input_file = join(DATA_BASE_DIR, 'olevba', 'sample_with_vba.ppt')
        output, ret_code = call_and_capture('olevba', args=(input_file, "--loglevel", "debug"))

        # check return code
        self.assertEqual(ret_code, 0)

        # not expected string:
        self.assertNotIn('invalid value for PROJECTLCID_Id expected 0002 got', output)
        self.assertNotIn('Error in _extract_vba', output)

        # compat version in debug mode:
        self.assertIn('compat version: 2', output)

        # vba contents:
        self.assertIn('Sub Action_Click()\n  MsgBox "The action button clicked!"\nEnd Sub', output)


class TestXlmStatusAccounting(unittest.TestCase):
    """
    Verify that macro-sheet presence, formula extraction and analysis are
    reported separately, and that JSON and triage state the same fact.

    Uses the repository's small XLM samples plus controlled fakes for
    capability failures; no full Office installation or optional
    XLMMacroDeobfuscator is required.
    """

    XLM_DIR = join(DATA_BASE_DIR, 'excel4-macros')

    def _json_result(self, filename, args=('-j',)):
        output, _ = call_and_capture('olevba', args=list(args) + [filename],
                                     accept_nonzero_exit=True,
                                     exclude_stderr=True)
        for entry in json.loads(output):
            if entry.get('type') in ('MetaInformation', 'msg', 'warning', 'error'):
                continue
            return entry
        self.fail('no result entry in JSON output')

    def _triage_line(self, filename):
        output, _ = call_and_capture('olevba', args=('-t', filename),
                                     accept_nonzero_exit=True,
                                     exclude_stderr=True)
        for line in output.splitlines():
            if os.path.basename(filename) in line and '(Flags' not in line:
                return line
        self.fail('no triage line for %s in output:\n%s' % (filename, output))

    def test_complete_analysis_no_findings_is_clean(self):
        """A fully analysed Excel file without macro sheets may be called clean."""
        filename = join(DATA_BASE_DIR, 'msodde', 'dde-test.xlsx')
        result = self._json_result(filename)
        self.assertEqual(result['xlm']['status'], 'none')
        self.assertFalse(result['xlm']['macro_sheet_found'])
        self.assertTrue(result['xlm']['analysis_complete'])
        self.assertTrue(result['xlm']['extraction_complete'])
        # triage: no M flag, and no "incomplete"/"failed"/"not checked" caveat
        line = self._triage_line(filename)
        self.assertIn('OpX:-', line)
        self.assertNotIn('INCOMPLETE', line)
        self.assertNotIn('FAILED', line)
        self.assertNotIn('not checked', line)

    def test_macro_present_and_extracted(self):
        """OLE XLM sample: present, extracted, analysed, and flagged in both modes."""
        filename = join(self.XLM_DIR, 'excel4_sample_macro.xls')
        result = self._json_result(filename)
        self.assertEqual(result['xlm']['status'], 'extracted')
        self.assertTrue(result['xlm']['macro_sheet_found'])
        self.assertTrue(result['xlm']['analysis_complete'])
        self.assertEqual(result['xlm']['method'], 'plugin_biff')
        self.assertIn('XLM macro', [e['keyword'] for e in result['analysis']])
        line = self._triage_line(filename)
        self.assertIn('OLE:MAS', line)
        self.assertNotIn('INCOMPLETE', line)

    def test_macro_present_but_not_analysed(self):
        """OpenXML XLM sample: presence proven, formulas not extracted -> not clean.

        This is the regression for the misleading 'No VBA or XLM macros found.'
        message and for triage showing no M flag while JSON had no analysis.
        """
        for name in ('excel4_sample_macro.xlsm', 'excel4_sample_macro.xltm',
                     'excel4_sample_macro.xlsb'):
            filename = join(self.XLM_DIR, name)
            result = self._json_result(filename)
            self.assertEqual(result['xlm']['status'], 'present', name)
            self.assertTrue(result['xlm']['macro_sheet_found'], name)
            self.assertFalse(result['xlm']['extraction_complete'], name)
            self.assertFalse(result['xlm']['analysis_complete'], name)
            # triage must show the macro and the caveat, matching JSON
            line = self._triage_line(filename)
            self.assertIn(':M', line, name)
            self.assertIn('analysis INCOMPLETE', line, name)

            # detailed mode must not claim there are no macros
            output, _ = call_and_capture('olevba', args=(filename,),
                                         accept_nonzero_exit=True,
                                         exclude_stderr=True)
            self.assertNotIn('No VBA or XLM macros found.', output, name)
            self.assertIn('not extracted', output, name)
            self.assertIn('does not cover the XLM code', output, name)

    def test_plugin_biff_failure_is_not_clean_and_not_malicious(self):
        """Controlled plugin_biff failure: no clean verdict, no malicious verdict."""
        from oletools import olevba

        class FailingBiff(object):
            def __init__(self, *args, **kwargs):
                pass

            def Analyze(self):
                raise RuntimeError('simulated BIFF parser failure')

        filename = join(self.XLM_DIR, 'excel4_sample_macro.xls')
        parser = olevba.VBA_Parser(filename)
        original = olevba.cBIFF
        try:
            olevba.cBIFF = FailingBiff
            self.assertFalse(parser.detect_xlm_macros())
        finally:
            olevba.cBIFF = original
            parser.close()

        status = parser.get_xlm_status()
        self.assertEqual(status['status'], 'error')
        self.assertIsNone(status['macro_sheet_found'])
        self.assertFalse(status['analysis_complete'])
        self.assertIn('plugin_biff', status['reason'])

    def test_deobfuscator_failure_falls_back_without_clean_verdict(self):
        """Controlled XLMMacroDeobfuscator failure must not become 'no macro'."""
        from oletools import olevba

        class FailingDeobfuscator(object):
            SILENT = False

            @staticmethod
            def process_file(**kwargs):
                raise RuntimeError('simulated deobfuscator failure')

        filename = join(self.XLM_DIR, 'excel4_sample_macro.xls')
        parser = olevba.VBA_Parser(filename)
        original_flag = olevba.XLMDEOBFUSCATOR
        original_mod = getattr(olevba, 'xlmdeobfuscator', None)
        try:
            olevba.XLMDEOBFUSCATOR = True
            olevba.xlmdeobfuscator = FailingDeobfuscator
            # plugin_biff fallback still finds the macro, but the failure is recorded
            self.assertTrue(parser.detect_xlm_macros())
        finally:
            olevba.XLMDEOBFUSCATOR = original_flag
            if original_mod is not None:
                olevba.xlmdeobfuscator = original_mod
            else:
                del olevba.xlmdeobfuscator
            parser.close()
        status = parser.get_xlm_status()
        self.assertTrue(status['macro_sheet_found'])
        # the optional capability was reported available for this run
        self.assertTrue(status['deobfuscation_available'])
        self.assertEqual(status['status'], 'extracted')
        self.assertFalse(status['deobfuscation_used'])
        self.assertIsNotNone(status['deobfuscation_error'])
        self.assertIn('XLMMacroDeobfuscator', status['deobfuscation_error'])

    def test_plugin_biff_failure_json_and_triage_agree(self):
        """Parse failure: both outputs say 'failed', neither says clean or malicious."""
        import io
        import contextlib
        from oletools import olevba

        class FailingBiff(object):
            def __init__(self, *args, **kwargs):
                pass

            def Analyze(self):
                raise RuntimeError('simulated BIFF parser failure')

        filename = join(self.XLM_DIR, 'excel4_sample_macro.xls')
        original = olevba.cBIFF
        try:
            olevba.cBIFF = FailingBiff
            parser = olevba.VBA_Parser_CLI(filename)
            json_result = parser.process_file_json()
            parser.close()

            parser = olevba.VBA_Parser_CLI(filename)
            triage_out = io.StringIO()
            with contextlib.redirect_stdout(triage_out):
                parser.process_file_triage()
            parser.close()
        finally:
            olevba.cBIFF = original
            parser.close()

        self.assertEqual(json_result['xlm']['status'], 'error')
        self.assertIsNone(json_result['xlm']['macro_sheet_found'])
        self.assertFalse(json_result['xlm']['analysis_complete'])
        self.assertEqual(json_result['macros'], [])
        self.assertIsNone(json_result['analysis'])

        line = triage_out.getvalue()
        self.assertIn('XLM analysis FAILED', line)
        self.assertNotIn(':M', line)     # no macro proven, but not called clean either
        # neither output declares a clean ("none") status or a finding
        self.assertNotEqual(json_result['xlm']['status'], 'none')
        self.assertEqual(json_result['analysis'], None)

    def test_no_xlm_is_not_reported_as_clean(self):
        """--no-xlm skips detection; the output must say so, not claim absence."""
        filename = join(self.XLM_DIR, 'excel4_sample_macro.xls')
        result = self._json_result(filename, args=('-j', '--no-xlm'))
        self.assertEqual(result['xlm']['status'], 'not_checked')
        self.assertIn('no-xlm', result['xlm']['reason'])
        self.assertFalse(result['xlm']['analysis_complete'])
        output, _ = call_and_capture('olevba', args=('--no-xlm', filename),
                                     accept_nonzero_exit=True)
        self.assertNotIn('No VBA or XLM macros found.', output)
        self.assertIn('NOT PERFORMED', output)

    def test_encrypted_file_is_unknown_for_xlm(self):
        """Encrypted file: XLM status unknown, not 'none'."""
        filename = join(DATA_BASE_DIR, 'encrypted', 'encrypted.doc')
        result = self._json_result(filename)
        self.assertEqual(result['xlm']['status'], 'not_checked')
        self.assertIsNone(result['xlm']['macro_sheet_found'])
        self.assertIn('encrypted', result['xlm']['reason'])
        line = self._triage_line(filename)
        self.assertIn('XLM not checked', line)

    def test_json_and_triage_agree_on_macro_samples(self):
        """For every XLM sample, JSON presence and triage M flag must agree."""
        for name in os.listdir(self.XLM_DIR):
            filename = join(self.XLM_DIR, name)
            result = self._json_result(filename)
            line = self._triage_line(filename)
            macro_in_json = result['xlm']['macro_sheet_found']
            macro_in_triage = ':M' in line
            self.assertEqual(macro_in_json, macro_in_triage,
                             'JSON/triage disagree for %s: %r vs %r'
                             % (name, macro_in_json, line))
            self.assertEqual(result['xlm']['analysis_complete'],
                             'INCOMPLETE' not in line,
                             'JSON/triage analysis status disagree for %s' % name)


# just in case somebody calls this file as a script
if __name__ == '__main__':
    unittest.main()
