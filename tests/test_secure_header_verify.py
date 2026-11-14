#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))

import secure_header_verify as shv
import make_shf_samples as samples


def entry(name, value, status='duplicated', position=0):
    return shv.SecuredEntry(name=name, value=value, status=status,
                            position=position)


class CanonTestCase(unittest.TestCase):
    def test_relaxed_unfolds_and_compresses_wsp(self):
        value = ' Quarterly\r\n\tresults  and   roadmap\r\n discussion'
        self.assertEqual(
            'Quarterly results and roadmap discussion',
            shv.canon_relaxed_value(value))

    def test_relaxed_strips_leading_and_trailing_wsp(self):
        self.assertEqual('a b', shv.canon_relaxed_value('  a \t b\t'))

    def test_simple_keeps_value_untouched(self):
        value = ' Quarterly\r\n results  and\tmore '
        self.assertEqual(value, shv.canon_simple_value(value))


class ParseHeadersTestCase(unittest.TestCase):
    def test_order_duplicates_and_folding_preserved(self):
        raw = (b'From: a@example.com\r\n'
               b'From: b@example.com\r\n'
               b'Subject: one\r\n two\r\n'
               b'\r\n'
               b'body\r\n')
        headers = shv.parse_headers(raw)
        self.assertEqual(
            [('From', ' a@example.com'),
             ('From', ' b@example.com'),
             ('Subject', ' one\r\n two')],
            headers)


class DuplicateFromOrderTestCase(unittest.TestCase):
    algorithm = shv.ALGORITHM_RELAXED

    def test_matching_order_confirms_each_entry(self):
        entries = [entry('From', 'alice@example.com', position=0),
                   entry('From', 'bob@example.com', position=1)]
        received = [('From', ' alice@example.com'),
                    ('From', ' bob@example.com')]
        report = shv.verify_secure_headers(entries, self.algorithm, received)
        self.assertEqual([shv.CONFIRMED, shv.CONFIRMED],
                         [r.outcome for r in report.entries])
        self.assertEqual(shv.VERDICT_VALID, report.verdict)

    def test_swapped_duplicates_fail_per_entry_not_by_dict(self):
        entries = [entry('From', 'alice@example.com', position=0),
                   entry('From', 'bob@example.com', position=1)]
        received = [('From', ' bob@example.com'),
                    ('From', ' alice@example.com')]
        report = shv.verify_secure_headers(entries, self.algorithm, received)
        self.assertEqual([shv.CHANGED, shv.CHANGED],
                         [r.outcome for r in report.entries])
        self.assertEqual(' bob@example.com', report.entries[0].received_value)
        self.assertEqual(' alice@example.com', report.entries[1].received_value)
        self.assertEqual(shv.VERDICT_INVALID, report.verdict)


class StatusSemanticsTestCase(unittest.TestCase):
    algorithm = shv.ALGORITHM_RELAXED

    def test_deleted_absent_is_expected_not_failure(self):
        entries = [entry('X-Internal-Tag', 'secret-42', status='deleted')]
        report = shv.verify_secure_headers(entries, self.algorithm, [])
        self.assertEqual(shv.ABSENT_AS_EXPECTED, report.entries[0].outcome)
        self.assertEqual(shv.VERDICT_VALID_WITH_DIFFERENCES, report.verdict)

    def test_modified_different_value_is_expected_difference(self):
        entries = [entry('X-Note', 'original', status='modified')]
        received = [('X-Note', ' *** replaced by DCA ***')]
        report = shv.verify_secure_headers(entries, self.algorithm, received)
        self.assertEqual(shv.EXPECTED_DIFFERENCE, report.entries[0].outcome)
        self.assertEqual(shv.VERDICT_VALID_WITH_DIFFERENCES, report.verdict)

    def test_duplicated_different_value_is_integrity_failure(self):
        entries = [entry('Subject', 'Launch plan')]
        received = [('Subject', ' [list] Launch plan')]
        report = shv.verify_secure_headers(entries, self.algorithm, received)
        self.assertEqual(shv.CHANGED, report.entries[0].outcome)
        self.assertEqual(shv.VERDICT_INVALID, report.verdict)

    def test_duplicated_missing_header_is_failure(self):
        entries = [entry('Subject', 'Launch plan')]
        report = shv.verify_secure_headers(entries, self.algorithm, [])
        self.assertEqual(shv.MISSING, report.entries[0].outcome)
        self.assertEqual(shv.VERDICT_INVALID, report.verdict)


class UnknownAlgorithmTestCase(unittest.TestCase):
    def test_unknown_algorithm_yields_unconfirmed(self):
        entries = [entry('From', 'alice@example.com')]
        received = [('From', ' alice@example.com')]
        report = shv.verify_secure_headers(entries, 7, received)
        self.assertEqual('unknown', report.algorithm)
        self.assertEqual([shv.UNCONFIRMED],
                         [r.outcome for r in report.entries])
        self.assertEqual(shv.VERDICT_UNCONFIRMED, report.verdict)


class AmbiguousMatchTestCase(unittest.TestCase):
    algorithm = shv.ALGORITHM_RELAXED

    def test_unresolvable_correspondence_is_unconfirmed(self):
        entries = [entry('X-Trace', 'a')]
        received = [('X-Trace', ' x'), ('X-Trace', ' y')]
        report = shv.verify_secure_headers(entries, self.algorithm, received)
        self.assertEqual([shv.UNCONFIRMED],
                         [r.outcome for r in report.entries])
        self.assertEqual(shv.VERDICT_UNCONFIRMED, report.verdict)
        self.assertEqual([], report.extra_headers)


class ExtraHeaderTestCase(unittest.TestCase):
    algorithm = shv.ALGORITHM_RELAXED

    def test_injected_header_with_secured_name_is_flagged(self):
        entries = [entry('From', 'alice@example.com')]
        received = [('From', ' "CEO" <ceo@example.com>'),
                    ('From', ' alice@example.com')]
        report = shv.verify_secure_headers(entries, self.algorithm, received)
        self.assertEqual([shv.CONFIRMED],
                         [r.outcome for r in report.entries])
        self.assertEqual([('From', ' "CEO" <ceo@example.com>')],
                         report.extra_headers)
        self.assertEqual(shv.VERDICT_INVALID, report.verdict)

    def test_extra_check_skipped_without_shared_policy(self):
        entries = [entry('From', 'alice@example.com')]
        received = [('From', ' "CEO" <ceo@example.com>'),
                    ('From', ' alice@example.com')]
        report = shv.verify_secure_headers(
            entries, self.algorithm, received, shared_policy=False)
        self.assertEqual([], report.extra_headers)
        self.assertEqual(shv.VERDICT_VALID, report.verdict)


class UnsecuredDisplayedTestCase(unittest.TestCase):
    def test_displayed_identity_header_not_secured_is_reported(self):
        entries = [entry('From', 'alice@example.com')]
        received = [('From', ' alice@example.com'),
                    ('Reply-To', ' attacker@evil.example')]
        report = shv.verify_secure_headers(
            entries, shv.ALGORITHM_RELAXED, received)
        self.assertEqual(['reply-to'], report.unsecured_displayed)
        self.assertEqual(shv.VERDICT_VALID, report.verdict)


class AttributeRoundTripTestCase(unittest.TestCase):
    def test_entries_from_attribute_preserves_order_and_status(self):
        der = samples.build_attribute(samples.SAMPLES['03-relay-modified']['original'])
        attr_path = os.path.join(
            tempfile.mkdtemp(), 'attr.b64')
        self.addCleanup(shutil.rmtree, os.path.dirname(attr_path))
        import base64
        with open(attr_path, 'w') as f:
            f.write(base64.encodebytes(der).decode('ascii'))
        shf = shv.load_attribute_file(attr_path)
        algorithm, entries = shv.entries_from_attribute(shf)
        self.assertEqual(shv.ALGORITHM_RELAXED, algorithm)
        self.assertEqual(
            ['From', 'To', 'Subject', 'Date', 'Message-ID',
             'X-Confidential-Note', 'X-Internal-Tag'],
            [e.name for e in entries])
        self.assertEqual('modified', entries[5].status)
        self.assertEqual('deleted', entries[6].status)
        self.assertEqual('duplicated', entries[0].status)


class SampleSetTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        samples.write_samples(self.tmpdir)

    def verify(self, name):
        shf = shv.load_attribute_file(
            os.path.join(self.tmpdir, name + '.shf.b64'))
        algorithm, entries = shv.entries_from_attribute(shf)
        with open(os.path.join(self.tmpdir, name + '.eml'), 'rb') as f:
            received = shv.parse_headers(f.read())
        return shv.verify_secure_headers(entries, algorithm, received)

    def test_duplicate_from_valid(self):
        report = self.verify('01-duplicate-from')
        self.assertEqual(shv.VERDICT_VALID, report.verdict)
        from_entries = [r for r in report.entries if r.entry.name == 'From']
        self.assertEqual(2, len(from_entries))
        self.assertEqual('alice@example.com', from_entries[0].entry.value)
        self.assertEqual('bob@example.com', from_entries[1].entry.value)

    def test_folded_subject_valid_under_relaxed(self):
        report = self.verify('02-folded-subject')
        self.assertEqual(shv.VERDICT_VALID, report.verdict)

    def test_relay_modifications_documented_not_invalid(self):
        report = self.verify('03-relay-modified')
        self.assertEqual(
            shv.VERDICT_VALID_WITH_DIFFERENCES, report.verdict)
        outcomes = {r.entry.name: r.outcome for r in report.entries}
        self.assertEqual(shv.EXPECTED_DIFFERENCE,
                         outcomes['X-Confidential-Note'])
        self.assertEqual(shv.ABSENT_AS_EXPECTED,
                         outcomes['X-Internal-Tag'])
        self.assertEqual([], report.extra_headers)

    def test_attacker_inserted_headers_detected(self):
        report = self.verify('04-attacker-inserted')
        self.assertEqual(shv.VERDICT_INVALID, report.verdict)
        self.assertEqual(
            [('From', ' "CEO" <ceo@example.com>')], report.extra_headers)
        self.assertEqual(['reply-to'], report.unsecured_displayed)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
