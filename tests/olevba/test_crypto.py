"""Check decryption of files from olevba works."""

import io
import os
import sys
import unittest
from os.path import basename, join as pjoin
import json
from collections import OrderedDict
from tempfile import mkdtemp, mkstemp

from tests.test_utils import DATA_BASE_DIR, call_and_capture

from oletools import crypto


@unittest.skipIf(not crypto.check_msoffcrypto(),
                 'Module msoffcrypto not installed for {}'
                 .format(basename(sys.executable)))
class OlevbaCryptoWriteProtectTest(unittest.TestCase):
    """
    Test documents that are 'write-protected' through encryption.

    Excel has a way to 'write-protect' documents by encrypting them with a
    hard-coded standard password. When looking at the file-structure you see
    an OLE-file with streams `EncryptedPackage`, `StrongEncryptionSpace`, and
    `EncryptionInfo`. Contained in the first is the actual file.  When opening
    such a file in excel, it is decrypted without the user noticing.

    Olevba should detect such encryption, try to decrypt with the standard
    password and look for VBA code in the decrypted file.

    All these tests are skipped if the module `msoffcrypto-tools` is not
    installed.
    """
    def test_autostart(self):
        """Check that autostart macro is found in xls[mb] sample file."""
        for suffix in 'xlsm', 'xlsb':
            example_file = pjoin(
                DATA_BASE_DIR, 'encrypted',
                'autostart-encrypt-standardpassword.' + suffix)
            output, _ = call_and_capture('olevba', args=('-j', example_file),
                                         exclude_stderr=True)
            data = json.loads(output, object_pairs_hook=OrderedDict)
            # debug: json.dump(data, sys.stdout, indent=4)
            self.assertGreaterEqual(len(data), 3)

            # first 2 parts: general info about script and file
            self.assertIn('script_name', data[0])
            self.assertIn('version', data[0])
            self.assertEqual(data[0]['type'], 'MetaInformation')
            self.assertEqual(data[1]['container'], None)
            self.assertEqual(data[1]['file'], example_file)
            self.assertEqual(data[1]['analysis'], None)
            self.assertEqual(data[1]['macros'], [])
            self.assertEqual(data[1]['type'], 'OLE')
            self.assertTrue(data[1]['json_conversion_successful'])

            for entry in data[2:]:
                if entry['type'] in ('msg', 'warning'):
                    continue
                result = entry
                break

            # last part is the actual result
            self.assertEqual(result['container'], example_file)
            self.assertNotEqual(result['file'], example_file)
            self.assertEqual(result['type'], "OpenXML")
            analysis = result['analysis']
            self.assertEqual(analysis[0]['type'], 'AutoExec')
            self.assertEqual(analysis[0]['keyword'], 'Auto_Open')
            macros = result['macros']
            self.assertEqual(macros[0]['vba_filename'], 'Modul1.bas')
            self.assertIn('Sub Auto_Open()', macros[0]['code'])
            self.assertTrue(result['json_conversion_successful'])


class OlevbaNestedDecryptionReportTest(unittest.TestCase):
    """olevba must report layers and keep secrets out of diagnostics."""

    def setUp(self):
        self.temp_dir = mkdtemp(prefix='oletools-test-olevba-nested-')
        self.files = []

    def tearDown(self):
        for name in self.files:
            if os.path.isfile(name):
                os.unlink(name)
        os.rmdir(self.temp_dir)

    def _write(self, data, suffix='.docx'):
        handle, name = mkstemp(suffix=suffix, dir=self.temp_dir)
        with os.fdopen(handle, 'wb') as writer:
            writer.write(data)
        self.files.append(name)
        return name

    def _nested_vba_document(self):
        """Two encrypted layers around a docm containing the autostart macro."""
        try:
            from msoffcrypto.method.ecma376_agile import ECMA376Agile
        except ImportError:
            self.skipTest('msoffcrypto method module not available')
        with open(pjoin(DATA_BASE_DIR, 'msodde', 'dde-test.xlsm'), 'rb') as f:
            plain = f.read()
        inner = ECMA376Agile.encrypt('Vba-Inner!42', io.BytesIO(plain),
                                     spin_count=1000)
        outer = ECMA376Agile.encrypt('Vba-Outer!42', io.BytesIO(inner),
                                     spin_count=1000)
        return outer

    def test_json_report_lists_layers_and_hides_password(self):
        path = self._write(self._nested_vba_document(), suffix='.xlsm')
        output, ret_code = call_and_capture(
            'olevba', args=('-j', '-p', 'Vba-Outer!42', '-p', 'Vba-Inner!42',
                            path),
            accept_nonzero_exit=True, exclude_stderr=True)
        data = json.loads(output)
        reports = [entry for entry in data if entry.get('type') == 'decryption']
        self.assertTrue(reports, 'no decryption report in JSON output')
        report = reports[0]
        self.assertTrue(report['complete'])
        self.assertTrue(report['success'])
        self.assertGreaterEqual(len(report['layers']), 2)
        depths = [layer['depth'] for layer in report['layers']]
        self.assertIn(0, depths)
        self.assertIn(1, depths)
        for layer in report['layers']:
            self.assertTrue(layer['identity'])
            self.assertNotIn('Vba-Outer!42', json.dumps(layer))
            self.assertNotIn('Vba-Inner!42', json.dumps(layer))

    def test_inner_failure_is_still_reported(self):
        path = self._write(self._nested_vba_document(), suffix='.xlsm')
        context = crypto.DecryptionContext()
        from oletools import olevba
        options = olevba.parse_args(
            ['-j', '-p', 'Vba-Outer!42', path])
        # Run in JSON mode but capture the report object directly.
        options.output_mode = 'json'
        return_code = olevba.process_file(path, None, None, options,
                                          decryption_context=context)
        self.assertEqual(return_code, olevba.RETURN_ENCRYPTED)
        self.assertFalse(context.report.complete)
        self.assertEqual(context.report.stopped_at, 1)
        self.assertEqual(context.report.layers[0].outcome,
                         crypto.OUTCOME_DECRYPTED)
        self.assertFalse(context.report.layers[0].analyzable)
        self.assertEqual(context.report.layers[1].outcome,
                         crypto.OUTCOME_WRONG_PASSWORD)


if __name__ == '__main__':
    unittest.main()
