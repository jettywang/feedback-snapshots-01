""" Test DDE field extraction in complex and nested Word fields.

The fixtures are generated on the fly: they are short, contain no executable
payloads and exist only to exercise the field state machine in
``msodde.process_docx_fields`` / ``msodde.process_doc_stream_fields``.
"""

from __future__ import print_function

import io
import os
import tempfile
import unittest
import zipfile

from oletools import msodde

NS_W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'

#: A field instruction that is not executable on its own. The program name
#: "cmd" is present, but the argument is intentionally harmless.
SAFE_DDE = 'DDE "cmd" "/c echo oletools-test"'
SAFE_DDE_SPLIT = ('DDE "cmd" ', '"/c echo ', 'oletools-test"')
SAFE_DDEAUTO = 'DDEAUTO "cmd" "/c echo nested"'
FAKE_RESULT = 'display text that mentions DDE "cmd" "/c echo fake"'


def _run(text):
    """ one run carrying a fragment of a field instruction """
    return '<w:r><w:instrText xml:space="preserve">%s</w:instrText></w:r>' \
           % text


def _display(text):
    return '<w:r><w:t xml:space="preserve">%s</w:t></w:r>' % text


def _fldchar(kind):
    return '<w:r><w:fldChar w:fldCharType="%s"/></w:r>' % kind


def xml_attr(text):
    """ escape text for use in a double-quoted XML attribute """
    return text.replace('&', '&amp;').replace('"', '&quot;') \
               .replace('<', '&lt;').replace('>', '&gt;')


def build_docx(document_body, extra_parts=None):
    """ build a minimal Word 2007 file with the given body xml

    The other package parts are copied from the harmless sample so that
    ooxml.get_type() accepts the file. ``word/document.xml`` is replaced with
    ``document_body``; ``extra_parts`` maps additional part names to XML.
    """
    sample = os.path.join(os.path.dirname(__file__), '..', 'test-data',
                          'msodde', 'harmless-clean.docx')
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="%s"><w:body>%s</w:body></w:document>'
        % (NS_W, document_body))
    target = tempfile.NamedTemporaryFile(suffix='.docx', delete=False)
    target.close()
    with zipfile.ZipFile(sample) as source:
        parts = [(name, source.read(name))
                 for name in source.namelist()
                 if name != 'word/document.xml']
    with zipfile.ZipFile(target.name, 'w', zipfile.ZIP_DEFLATED) as dest:
        for name, data in parts:
            dest.writestr(name, data)
        dest.writestr('word/document.xml', document)
        for name, xml in (extra_parts or {}).items():
            dest.writestr(name, xml)
    return target.name


def build_ole_stream(data):
    """ build a fake Word stream object from raw bytes """
    return io.BytesIO(data)


class _DocxFixture(unittest.TestCase):
    """ base class creating and cleaning one docx per test """

    def setUp(self):
        self.tmpfiles = []

    def tearDown(self):
        for path in self.tmpfiles:
            try:
                os.unlink(path)
            except OSError:
                pass

    def docx(self, body, extra_parts=None):
        path = build_docx(body, extra_parts)
        self.tmpfiles.append(path)
        return path

    def fields(self, body):
        return msodde.process_docx_fields(self.docx(body))


class TestSplitInstruction(_DocxFixture):
    """ instruction text split over several runs is reassembled """

    def test_split_over_runs(self):
        body = (
            '<w:p>' + _fldchar('begin') + _run(SAFE_DDE_SPLIT[0]) +
            _run(SAFE_DDE_SPLIT[1]) + _run(SAFE_DDE_SPLIT[2]) +
            _fldchar('separate') + _display(FAKE_RESULT) +
            _fldchar('end') + '</w:p>')
        fields = self.fields(body)
        self.assertEqual(len(fields), 1)
        field = fields[0]
        self.assertEqual(field.instruction, SAFE_DDE)
        self.assertTrue(field.is_dde)
        self.assertTrue(field.complete)
        self.assertEqual(field.result, FAKE_RESULT)
        # the individual instruction fragments keep their positions
        self.assertEqual([fragment.text for fragment in field.fragments],
                         list(SAFE_DDE_SPLIT))

    def test_split_and_adjacent_paragraph(self):
        body = (
            '<w:p>' + _fldchar('begin') + _run(SAFE_DDE_SPLIT[0]) +
            _run(SAFE_DDE_SPLIT[1]) + _run(SAFE_DDE_SPLIT[2]) +
            _fldchar('separate') + _display(FAKE_RESULT) +
            _fldchar('end') + '</w:p>'
            '<w:p>' + _display('ordinary paragraph after the field') +
            '</w:p>')
        fields = self.fields(body)
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].instruction, SAFE_DDE)
        self.assertNotIn('ordinary paragraph', fields[0].instruction)


class TestResultTextIgnored(_DocxFixture):
    """ display text that looks like a command is not extracted """

    def test_fake_result_is_not_dde(self):
        body = (
            '<w:p>' + _fldchar('begin') +
            _run('MACROBUTTON harmless display') + _fldchar('separate') +
            _display(FAKE_RESULT) + _fldchar('end') + '</w:p>')
        fields = self.fields(body)
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].instruction, 'MACROBUTTON harmless display')
        self.assertFalse(fields[0].is_dde)
        self.assertEqual(fields[0].result, FAKE_RESULT)

    def test_only_fake_result_in_dde_mode(self):
        body = (
            '<w:p>' + _fldchar('begin') +
            _run('MACROBUTTON harmless display') + _fldchar('separate') +
            _display(FAKE_RESULT) + _fldchar('end') + '</w:p>')
        output = msodde.process_docx(self.docx(body),
                                     msodde.FIELD_FILTER_DDE)
        self.assertEqual(output, '')

    def test_display_text_without_field(self):
        body = '<w:p>' + _display(FAKE_RESULT) + '</w:p>'
        self.assertEqual(self.fields(body), [])
        self.assertEqual(
            msodde.process_docx(self.docx(body), msodde.FIELD_FILTER_ALL), '')


class TestNestedFields(_DocxFixture):
    """ nested fields keep their own instruction and parent relationship """

    def test_nested_dde(self):
        body = (
            '<w:p>' +
            _fldchar('begin') + _run('IF ') +
            _fldchar('begin') + _run(SAFE_DDEAUTO) +
            _fldchar('separate') + _display('nested display') +
            _fldchar('end') +
            _run(' = 1 "yes" "no"') +
            _fldchar('separate') + _display('outer display') +
            _fldchar('end') +
            '</w:p>')
        fields = self.fields(body)
        self.assertEqual(len(fields), 2)
        outer, inner = fields
        self.assertEqual(outer.instruction, 'IF  = 1 "yes" "no"')
        self.assertEqual(outer.depth, 0)
        self.assertIsNone(outer.parent)
        self.assertEqual(inner.instruction, SAFE_DDEAUTO)
        self.assertEqual(inner.depth, 1)
        self.assertEqual(inner.parent, outer.position)
        self.assertTrue(inner.is_dde)
        self.assertFalse(outer.is_dde)
        self.assertEqual(inner.result, 'nested display')

    def test_nested_instruction_not_in_parent(self):
        body = (
            '<w:p>' +
            _fldchar('begin') + _run('IF ') +
            _fldchar('begin') + _run(SAFE_DDEAUTO) +
            _fldchar('end') +
            _run('"outer"') + _fldchar('end') +
            '</w:p>')
        fields = self.fields(body)
        self.assertEqual(len(fields), 2)
        outer, inner = fields
        self.assertEqual(outer.instruction, 'IF "outer"')
        self.assertEqual(inner.instruction, SAFE_DDEAUTO)
        self.assertTrue(inner.parent == outer.position)


class TestIncompleteFields(_DocxFixture):
    """ fields without an end marker are reported, not extended """

    def test_missing_end_is_incomplete(self):
        body = (
            '<w:p>' + _fldchar('begin') + _run(SAFE_DDE) +
            _fldchar('separate') + _display(FAKE_RESULT) +
            '</w:p>'
            '<w:p>' + _display('later paragraph without field markers') +
            '</w:p>')
        fields = self.fields(body)
        self.assertEqual(len(fields), 1)
        self.assertFalse(fields[0].complete)
        self.assertEqual(fields[0].instruction, SAFE_DDE)
        self.assertEqual(fields[0].result, FAKE_RESULT)
        self.assertNotIn('later paragraph', fields[0].instruction)

    def test_missing_end_without_separator(self):
        body = (
            '<w:p>' + _fldchar('begin') + _run(SAFE_DDE) +
            '</w:p><w:p>' + _display('plain text') + '</w:p>')
        fields = self.fields(body)
        self.assertEqual(len(fields), 1)
        self.assertFalse(fields[0].complete)
        self.assertEqual(fields[0].instruction, SAFE_DDE)

    def test_end_without_begin(self):
        body = '<w:p>' + _fldchar('end') + _display('plain text') + '</w:p>'
        self.assertEqual(self.fields(body), [])

    def test_duplicate_instruction_text(self):
        """ the same command twice yields two fields, not one merged text """
        body = (
            '<w:p>' + _fldchar('begin') + _run(SAFE_DDE) +
            _fldchar('end') + '</w:p>'
            '<w:p>' + _fldchar('begin') + _run(SAFE_DDE) +
            _fldchar('end') + '</w:p>')
        fields = self.fields(body)
        self.assertEqual(len(fields), 2)
        self.assertEqual([field.instruction for field in fields],
                         [SAFE_DDE, SAFE_DDE])
        self.assertNotEqual(fields[0].position, fields[1].position)


class TestFieldProvenance(_DocxFixture):
    """ part, position, depth and fragments identify the original field """

    def test_dde_only_filter_and_provenance(self):
        body = (
            '<w:p>' + _fldchar('begin') + _run('DATE \\@ "yyyy"') +
            _fldchar('end') + '</w:p>'
            '<w:p>' + _fldchar('begin') + _run(SAFE_DDE_SPLIT[0]) +
            _run(SAFE_DDE_SPLIT[1] + SAFE_DDE_SPLIT[2]) +
            _fldchar('separate') + _display(FAKE_RESULT) +
            _fldchar('end') + '</w:p>')
        path = self.docx(body)
        all_fields = msodde.process_docx_fields(path)
        self.assertEqual(len(all_fields), 2)
        dde_fields = [field for field in all_fields if field.is_dde]
        self.assertEqual(len(dde_fields), 1)
        dde_field = dde_fields[0]
        self.assertEqual(dde_field.part, 'word/document.xml')
        self.assertEqual(dde_field.kind, msodde.FIELD_KIND_COMPLEX)
        self.assertEqual(len(dde_field.fragments), 2)
        self.assertTrue(all(fragment.position for
                            fragment in dde_field.fragments))

        output = msodde.process_docx(path, msodde.FIELD_FILTER_DDE)
        self.assertEqual(output, SAFE_DDE)

    def test_simple_field(self):
        body = '<w:p><w:fldSimple w:instr=" %s ">' \
               '<w:r><w:t>shown</w:t></w:r></w:fldSimple></w:p>' \
               % xml_attr(SAFE_DDE)
        fields = self.fields(body)
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].kind, msodde.FIELD_KIND_SIMPLE)
        self.assertEqual(fields[0].instruction.strip(), SAFE_DDE)
        self.assertTrue(fields[0].is_dde)


class TestOleFields(unittest.TestCase):
    """ the same state machine is used for Word 97-2003 streams """

    def test_ascii_nested(self):
        raw = (
            b'prefix\x13' + b'IF ' +
            b'\x13' + SAFE_DDEAUTO.encode('ascii') + b'\x14nested\x15' +
            b' "yes" "no"'
            b'\x14outer result\x15 suffix')
        fields = msodde.process_doc_stream_fields(build_ole_stream(raw))
        self.assertEqual(len(fields), 2)
        outer, inner = fields
        self.assertEqual(outer.instruction, 'IF  "yes" "no"')
        self.assertEqual(outer.result, 'outer result')
        self.assertEqual(inner.instruction, SAFE_DDEAUTO)
        self.assertEqual(inner.result, 'nested')
        self.assertEqual(inner.parent, outer.position)

    def test_unterminated_field_stops_at_paragraph(self):
        raw = (b'\x13' + SAFE_DDE.encode('ascii') + b'\r'
               b'following paragraph must not be appended')
        fields = msodde.process_doc_stream_fields(build_ole_stream(raw))
        self.assertEqual(len(fields), 1)
        self.assertFalse(fields[0].complete)
        self.assertEqual(fields[0].instruction, SAFE_DDE)

    def test_unterminated_field_does_not_take_next_field(self):
        raw = (b'\x13' + SAFE_DDE.encode('ascii') + b'\r'
               b'\x13DATE\x15')
        fields = msodde.process_doc_stream_fields(build_ole_stream(raw))
        self.assertEqual(len(fields), 2)
        incomplete, date = fields
        self.assertFalse(incomplete.complete)
        self.assertEqual(incomplete.instruction, SAFE_DDE)
        self.assertTrue(date.complete)
        self.assertEqual(date.instruction, 'DATE')

    def test_utf16le(self):
        text = u'\x13' + u'DDEAUTO "cmd" "/c echo ünicöde"' + \
               u'\x14shown DDE text\x15'
        raw = text.encode('utf-16le')
        fields = msodde.process_doc_stream_fields(build_ole_stream(raw))
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].instruction,
                         u'DDEAUTO "cmd" "/c echo ünicöde"')
        self.assertEqual(fields[0].result, u'shown DDE text')
        self.assertTrue(fields[0].is_dde)

    def test_result_text_is_not_instruction(self):
        raw = (b'\x13QUOTE "harmless"\x14DDE "cmd" "/c echo fake"\x15')
        fields = msodde.process_doc_stream_fields(build_ole_stream(raw))
        self.assertEqual(len(fields), 1)
        self.assertFalse(fields[0].is_dde)
        self.assertEqual(fields[0].instruction, 'QUOTE "harmless"')


if __name__ == '__main__':
    unittest.main()


class TestSplitInvariance(_DocxFixture):
    """ splitting an instruction into runs must not change its meaning """

    @staticmethod
    def body_for(text_fragments):
        return (
            '<w:p>' + _fldchar('begin') +
            ''.join(_run(fragment) for fragment in text_fragments) +
            _fldchar('separate') + _display(FAKE_RESULT) +
            _fldchar('end') + '</w:p>')

    def test_same_instruction_for_different_splits(self):
        splits = (
            [SAFE_DDE],
            ['DDE ', '"cmd" "/c ', 'echo ', 'oletools-test"'],
            ['D', 'DE "cmd"', ' "/c echo ole', 'tools-test"'],
            list(SAFE_DDE),   # one character per run
        )
        expected = None
        for split in splits:
            fields = self.fields(self.body_for(split))
            self.assertEqual(len(fields), 1, 'split {0!r}'.format(split))
            field = fields[0]
            self.assertEqual(field.instruction, SAFE_DDE,
                             'split {0!r}'.format(split))
            self.assertEqual(field.result, FAKE_RESULT)
            self.assertEqual(len(field.fragments), len(split))
            if expected is None:
                expected = field
            else:
                # positions differ by construction; text and semantics do not
                self.assertEqual(field.instruction, expected.instruction)
                self.assertEqual(field.is_dde, expected.is_dde)

    def test_fragments_keep_order_and_positions(self):
        fields = self.fields(self.body_for(
            ['DDE ', '"cmd" ', '"/c echo ', 'oletools-test"']))
        positions = [fragment.position for fragment in fields[0].fragments]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(len(set(positions)), len(positions))


class TestPartProvenance(_DocxFixture):
    """ fields in different package parts are reported separately """

    def test_header_and_document(self):
        header = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:hdr xmlns:w="%s"><w:p>' % NS_W +
            _fldchar('begin') + _run(SAFE_DDE_SPLIT[0]) +
            _run(SAFE_DDE_SPLIT[1] + SAFE_DDE_SPLIT[2]) +
            _fldchar('separate') + _display(FAKE_RESULT) +
            _fldchar('end') + '</w:p></w:hdr>')
        body = (
            '<w:p>' + _fldchar('begin') + _run(SAFE_DDEAUTO) +
            _fldchar('separate') + _display('header test') +
            _fldchar('end') + '</w:p>')
        path = self.docx(body, extra_parts={'word/header1.xml': header})
        fields = msodde.process_docx_fields(path)
        self.assertEqual(len(fields), 2)
        by_part = dict((field.part, field) for field in fields)
        self.assertEqual(set(by_part), {'word/document.xml',
                                        'word/header1.xml'})
        self.assertEqual(by_part['word/header1.xml'].instruction, SAFE_DDE)
        self.assertEqual(by_part['word/document.xml'].instruction,
                         SAFE_DDEAUTO)
        self.assertTrue(all(field.is_dde for field in fields))
