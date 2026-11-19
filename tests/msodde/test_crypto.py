"""Check decryption of files from msodde works."""

import io
import os
import sys
import unittest
from os.path import basename, join as pjoin
from tempfile import mkdtemp, mkstemp

from tests.test_utils import DATA_BASE_DIR, call_and_capture

from oletools import crypto, msodde

try:
    from msoffcrypto.method.ecma376_agile import ECMA376Agile
except ImportError:
    ECMA376Agile = None


#: fixed passwords used by the generated nested fixtures
OUTER_PASSWORD = 'Outer-Fixed!42'
INNER_PASSWORD = 'Inner-Fixed!42'


def _make_nested_encrypted_document(inner_payload=None, outer_password=OUTER_PASSWORD,
                                    inner_password=INNER_PASSWORD,
                                    outer_suffix='.xlsx'):
    """Return bytes of: encrypted(encrypted(inner payload)).

    The payload is a genuine OOXML file from the test data, so the innermost
    layer can be analyzed for DDE links.  Encryption is deterministic enough
    for a test because we only care about successful decryption, not the
    exact ciphertext.
    """
    if ECMA376Agile is None:
        raise unittest.SkipTest('msoffcrypto method module not available')
    if inner_payload is None:
        with open(pjoin(DATA_BASE_DIR, 'msodde', 'dde-test.xlsx'), 'rb') as f:
            inner_payload = f.read()
    inner = ECMA376Agile.encrypt(inner_password, io.BytesIO(inner_payload),
                                 spin_count=1000)
    outer = ECMA376Agile.encrypt(outer_password, io.BytesIO(inner),
                                 spin_count=1000)
    return outer


class NestedDecryptionReportTest(unittest.TestCase):
    """Nested layers must be individually identified and reported."""

    def setUp(self):
        self.temp_dir = mkdtemp(prefix='oletools-test-nested-')
        self.temp_files = []

    def tearDown(self):
        for name in self.temp_files:
            if os.path.isfile(name):
                os.unlink(name)
        if os.path.isdir(self.temp_dir):
            os.rmdir(self.temp_dir)

    def temp_path(self, suffix='.xlsx'):
        handle, name = mkstemp(suffix=suffix, dir=self.temp_dir)
        os.close(handle)
        os.unlink(name)
        self.temp_files.append(name)
        return name

    def test_two_layers_both_reported(self):
        """Both layers are decrypted, analyzed and bound to distinct content."""
        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        context = crypto.DecryptionContext()
        result = msodde.process_maybe_encrypted(
            path, [OUTER_PASSWORD, INNER_PASSWORD], context=context,
            field_filter_mode=msodde.FIELD_FILTER_BLACKLIST)

        self.assertIn('cmd /c calc.exe', result)
        self.assertFalse(result.stopped)
        report = context.report
        self.assertTrue(report.complete)
        self.assertTrue(report.success)
        self.assertEqual([layer.depth for layer in report.layers], [0, 1])
        for layer in report.layers:
            self.assertTrue(layer.decrypted)
            self.assertTrue(layer.analyzable)
            self.assertTrue(layer.identity)
        self.assertNotEqual(report.layers[0].identity,
                            report.layers[1].identity)

    def test_wrong_inner_password_keeps_outer_result(self):
        """Outer layer is decrypted; report stops exactly at the inner layer."""
        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        context = crypto.DecryptionContext()
        result = msodde.process_maybe_encrypted(
            path, [OUTER_PASSWORD], context=context,
            field_filter_mode=msodde.FIELD_FILTER_BLACKLIST)

        self.assertTrue(result.stopped)
        self.assertEqual(result.stopped_at, 1)
        report = context.report
        self.assertFalse(report.complete)
        self.assertFalse(report.success)
        self.assertEqual(report.stopped_at, 1)
        self.assertEqual(report.stopped_reason, crypto.OUTCOME_WRONG_PASSWORD)
        self.assertEqual(report.layers[0].outcome, crypto.OUTCOME_DECRYPTED)
        self.assertFalse(report.layers[0].analyzable)
        self.assertEqual(report.layers[1].outcome,
                         crypto.OUTCOME_WRONG_PASSWORD)

    def test_same_name_different_content_not_reused(self):
        """Two inner documents with the same display name stay separate."""
        inner_other = _make_nested_encrypted_document(
            inner_payload=b'PK\x03\x04' + b'not-the-same' * 20,
            inner_password='Different!42')
        path_a = self.temp_path('.xlsx')
        path_b = self.temp_path('.xlsx')
        with open(path_a, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())
        with open(path_b, 'wb') as writer:
            writer.write(inner_other)

        context = crypto.DecryptionContext()
        first = crypto.decrypt(path_a, [OUTER_PASSWORD], context=context)
        second = crypto.decrypt(path_b, [OUTER_PASSWORD], context=context)
        self.assertIsNotNone(first[0])
        self.assertIsNotNone(second[0])
        self.assertNotEqual(context.report.layers[0].identity,
                            context.report.layers[1].identity)
        os.unlink(first[0])
        os.unlink(second[0])

    def test_attempt_budget_preserves_outer_layer(self):
        """Hitting the attempt budget reports a partial result, not success."""
        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        context = crypto.DecryptionContext(max_attempts=1)
        result = msodde.process_maybe_encrypted(
            path, [OUTER_PASSWORD], context=context,
            field_filter_mode=msodde.FIELD_FILTER_BLACKLIST)

        self.assertTrue(result.stopped)
        self.assertEqual(context.report.stopped_reason,
                         crypto.OUTCOME_ATTEMPT_LIMIT)
        self.assertEqual(context.report.layers[0].outcome,
                         crypto.OUTCOME_DECRYPTED)
        self.assertFalse(context.report.layers[0].analyzable)
        self.assertFalse(context.report.complete)
        self.assertFalse(context.report.success)

    def test_nesting_budget_preserves_outer_layer(self):
        """Hitting the depth budget also yields a partial, non-success report."""
        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        context = crypto.DecryptionContext(max_nesting=1)
        result = msodde.process_maybe_encrypted(
            path, [OUTER_PASSWORD, INNER_PASSWORD], context=context,
            field_filter_mode=msodde.FIELD_FILTER_BLACKLIST)

        self.assertTrue(result.stopped)
        self.assertEqual(context.report.stopped_reason,
                         crypto.OUTCOME_NESTING_LIMIT)
        self.assertFalse(context.report.success)

    def test_temp_plaintext_is_removed(self):
        """Temporary plaintext files are deleted after processing."""
        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        created = []
        real_mkstemp = crypto.mkstemp

        def recording_mkstemp(*args, **kwargs):
            handle, name = real_mkstemp(*args, **kwargs)
            created.append(name)
            return handle, name

        context = crypto.DecryptionContext()
        crypto.mkstemp = recording_mkstemp
        try:
            result = msodde.process_maybe_encrypted(
                path, [OUTER_PASSWORD, INNER_PASSWORD],
                decrypted_dir=None, context=context,
                field_filter_mode=msodde.FIELD_FILTER_BLACKLIST)
        finally:
            crypto.mkstemp = real_mkstemp

        self.assertIn('cmd /c calc.exe', result)
        self.assertTrue(created, 'test did not observe decryption temp files')
        for name in created:
            self.assertFalse(os.path.exists(name),
                             'plaintext temp file left behind: ' + name)
        self.assertEqual(context._temp_files, [])

    def test_temp_plaintext_removed_on_midway_failure(self):
        """A failure in a deeper layer must still remove outer plaintext files."""
        # Outer layer uses a password we provide; inner one does not.
        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        created = []
        real_mkstemp = crypto.mkstemp

        def recording_mkstemp(*args, **kwargs):
            handle, name = real_mkstemp(*args, **kwargs)
            created.append(name)
            return handle, name

        context = crypto.DecryptionContext()
        crypto.mkstemp = recording_mkstemp
        try:
            result = msodde.process_maybe_encrypted(
                path, [OUTER_PASSWORD], context=context,
                field_filter_mode=msodde.FIELD_FILTER_BLACKLIST)
        finally:
            crypto.mkstemp = real_mkstemp

        self.assertTrue(result.stopped)
        for name in created:
            self.assertFalse(os.path.exists(name),
                             'plaintext temp file left behind: ' + name)

    def test_repeated_call_has_fresh_state(self):
        """A new context must not inherit attempts or layers from a previous run."""
        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        first_context = crypto.DecryptionContext()
        msodde.process_maybe_encrypted(
            path, [OUTER_PASSWORD, INNER_PASSWORD], context=first_context,
            field_filter_mode=msodde.FIELD_FILTER_BLACKLIST)
        second_context = crypto.DecryptionContext()
        result = msodde.process_maybe_encrypted(
            path, [OUTER_PASSWORD, INNER_PASSWORD], context=second_context,
            field_filter_mode=msodde.FIELD_FILTER_BLACKLIST)

        self.assertIn('cmd /c calc.exe', result)
        self.assertTrue(second_context.report.success)
        self.assertEqual(second_context.report.attempts,
                         first_context.report.attempts)
        self.assertEqual(len(second_context.report.layers), 2)

    def test_passwords_never_reach_logs(self):
        """Debug logging must not contain either password."""
        import logging
        from oletools.common.log_helper import log_helper

        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        stream = io.StringIO()
        log_helper.enable_logging(level='debug', stream=stream)
        crypto.enable_logging()
        try:
            context = crypto.DecryptionContext()
            crypto.decrypt(path, [OUTER_PASSWORD], context=context)
            crypto.decrypt(path, ['wrong-password-sentinel'], context=context)
        finally:
            log_helper.end_logging()
        logged = stream.getvalue()
        self.assertNotIn(OUTER_PASSWORD, logged)
        self.assertNotIn('wrong-password-sentinel', logged)



    def test_cli_reports_stopping_layer(self):
        """CLI text output names the layer that could not be decrypted."""
        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        output, ret_code = call_and_capture(
            'msodde', ['-p', OUTER_PASSWORD, path],
            accept_nonzero_exit=True)
        self.assertEqual(ret_code, 1)
        self.assertIn('DDE Links:', output)
        self.assertIn('Decryption layer 1 (container ole): wrong_password',
                      output)
        self.assertIn('Decryption stopped at layer 1: wrong_password', output)
        self.assertNotIn(OUTER_PASSWORD, output)
        self.assertNotIn(INNER_PASSWORD, output)

    def test_retry_does_not_repeat_attempts_for_same_identity(self):
        """Repeated decrypt calls for the same bytes reuse the attempt record."""
        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        context = crypto.DecryptionContext()
        first = crypto.decrypt(path, ['nope'], context=context)
        second = crypto.decrypt(path, ['nope'], context=context)
        self.assertEqual(first, (None, None))
        self.assertEqual(second, (None, None))
        self.assertEqual(context.report.attempts, 1)
        self.assertEqual(len(context.report.layers), 1)

    def test_cli_json_report_is_parseable(self):
        """msodde -j emits a decryption entry with layer details."""
        import json

        path = self.temp_path()
        with open(path, 'wb') as writer:
            writer.write(_make_nested_encrypted_document())

        output, ret_code = call_and_capture(
            'msodde', ['-j', '-p', OUTER_PASSWORD, path],
            accept_nonzero_exit=True, exclude_stderr=True)
        self.assertEqual(ret_code, 1)
        entries = json.loads(output)
        reports = [entry for entry in entries
                   if entry.get('type') == 'decryption']
        self.assertTrue(reports)
        message = reports[0]['msg']
        self.assertIn('stopped_at=1', message)
        self.assertIn('wrong_password', message)
        self.assertNotIn(OUTER_PASSWORD, output)


class ControlledFailureTest(unittest.TestCase):
    """Distinguish wrong password, unsupported algorithm and corruption."""

    def setUp(self):
        self.temp_dir = mkdtemp(prefix='oletools-test-fail-')

    def tearDown(self):
        for name in os.listdir(self.temp_dir):
            os.unlink(os.path.join(self.temp_dir, name))
        os.rmdir(self.temp_dir)

    def _write(self, contents, suffix='.xlsx'):
        handle, name = mkstemp(suffix=suffix, dir=self.temp_dir)
        with os.fdopen(handle, 'wb') as writer:
            writer.write(contents)
        return name

    def test_wrong_password(self):
        path = self._write(_make_nested_encrypted_document())
        context = crypto.DecryptionContext()
        result = crypto.decrypt(path, ['definitely-wrong'], context=context)
        self.assertEqual(result, (None, None))
        self.assertEqual(context.report.layers[0].outcome,
                         crypto.OUTCOME_WRONG_PASSWORD)
        self.assertEqual(context.report.stopped_reason,
                         crypto.OUTCOME_WRONG_PASSWORD)

    def test_unsupported_algorithm(self):
        if ECMA376Agile is None:
            self.skipTest('msoffcrypto method module not available')
        import olefile
        from msoffcrypto.method.ecma376_agile import ECMA376Agile as agile

        path = self._write(agile.encrypt(INNER_PASSWORD, io.BytesIO(b'PK\x03\x04' + b'x' * 20),
                                         spin_count=1000))
        # Turn the Agile header into an Extensible header: parseable container,
        # unsupported encryption algorithm.
        with olefile.OleFileIO(path, write_mode=True) as ole:
            info = bytearray(ole.openstream('EncryptionInfo').read())
            info[0:2] = (3).to_bytes(2, 'little')
            info[2:4] = (3).to_bytes(2, 'little')
            ole.write_stream('EncryptionInfo', bytes(info))

        context = crypto.DecryptionContext()
        with self.assertRaises(crypto.UnsupportedEncryptionError):
            crypto.decrypt(path, [INNER_PASSWORD], context=context)
        self.assertEqual(context.report.layers[0].outcome,
                         crypto.OUTCOME_UNSUPPORTED)
        self.assertEqual(context.report.stopped_reason,
                         crypto.OUTCOME_UNSUPPORTED)

    def test_corrupt_structure(self):
        path = self._write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 200,
                           suffix='.doc')
        context = crypto.DecryptionContext()
        with self.assertRaises(crypto.CorruptedEncryptionError):
            crypto.decrypt(path, ['anything'], context=context)
        self.assertEqual(context.report.layers[0].outcome,
                         crypto.OUTCOME_CORRUPT)
        self.assertEqual(context.report.stopped_reason, crypto.OUTCOME_CORRUPT)


    def test_msodde_reports_structurally_damaged_container(self):
        """A container that cannot be parsed at all is reported as corrupt."""
        path = self._write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 300,
                           suffix='.doc')
        with self.assertRaises(Exception) as raised:
            msodde.process_maybe_encrypted(path, ['anything'])
        report = getattr(raised.exception, 'report', None)
        self.assertIsNotNone(report)
        self.assertEqual(report.stopped_reason, crypto.OUTCOME_CORRUPT)
        self.assertEqual(report.layers[0].outcome, crypto.OUTCOME_CORRUPT)
        self.assertFalse(report.success)

    def test_report_has_no_secret_material(self):
        path = self._write(_make_nested_encrypted_document())
        context = crypto.DecryptionContext()
        crypto.decrypt(path, [OUTER_PASSWORD], context=context)
        blob = repr(context.report.to_dict())
        self.assertNotIn(OUTER_PASSWORD, blob)
        self.assertNotIn(INNER_PASSWORD, blob)
        self.assertNotIn('calc.exe', blob)


@unittest.skipIf(not crypto.check_msoffcrypto(),
                 'Module msoffcrypto not installed for {}'
                 .format(basename(sys.executable)))
class MsoddeCryptoTest(unittest.TestCase):
    """Test integration of decryption in msodde."""

    def test_standard_password(self):
        """Check dde-link is found in xls[mb] sample files."""
        for suffix in 'xls', 'xlsx', 'xlsm', 'xlsb':
            example_file = pjoin(DATA_BASE_DIR, 'encrypted',
                                 'dde-test-encrypt-standardpassword.' + suffix)
            output, _ = call_and_capture('msodde', [example_file, ])
            self.assertIn('\nDDE Links:\ncmd /c calc.exe\n', output,
                          msg='Unexpected output {!r} for {}'
                              .format(output, suffix))

    # TODO: add more, in particular a sample with a "proper" password


if __name__ == '__main__':
    unittest.main()
