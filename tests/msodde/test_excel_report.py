"""Tests for Excel DDE declaration/reference evidence reporting."""

import os
import re
import shutil
import struct
import tempfile
import unittest
import zipfile
from os.path import join

from oletools import msodde_excel
from tests.test_utils import DATA_BASE_DIR, decrypt_sample


class TestOoxmlReport(unittest.TestCase):
    """OOXML declarations, references and broken indexes."""

    def _rewrite_xlsx(self, formula=None, drop_cell=False):
        """Copy dde-test.xlsx, optionally changing/removing the B4 formula."""
        source = join(DATA_BASE_DIR, 'msodde', 'dde-test.xlsx')
        handle, destination = tempfile.mkstemp(suffix='.xlsx')
        os.close(handle)
        self.addCleanup(os.unlink, destination)
        with zipfile.ZipFile(source) as zin, \
                zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == 'xl/worksheets/sheet1.xml':
                    text = data.decode('utf-8')
                    if drop_cell:
                        text = re.sub(r'<c r="B4".*?</c>', '', text)
                    elif formula is not None:
                        text = text.replace('[1]!_xlbgnm.A1', formula)
                    data = text.encode('utf-8')
                zout.writestr(item, data)
        return destination

    def test_valid_reference(self):
        report = msodde_excel.analyze_workbook(
            join(DATA_BASE_DIR, 'msodde', 'dde-test.xlsx'))
        self.assertEqual(report.document_evidence(),
                         msodde_excel.EVIDENCE_CONFIRMED)
        self.assertEqual(len(report.declarations), 1)
        declaration = report.declarations[0]
        self.assertEqual(declaration.kind, msodde_excel.KIND_DDE)
        self.assertEqual(declaration.service, 'cmd')
        self.assertEqual(declaration.topic, '/c calc.exe')
        self.assertIn('externalLink1.xml', declaration.location)
        self.assertEqual(len(report.references), 1)
        reference = report.references[0]
        self.assertEqual(reference.sheet, 'Tabelle1')
        self.assertEqual(reference.cell, 'B4')
        self.assertEqual(reference.declaration_index, 0)
        self.assertEqual(reference.evidence,
                         msodde_excel.EVIDENCE_CONFIRMED)
        self.assertEqual(report.sheet_entries()['Tabelle1'],
                         msodde_excel.EVIDENCE_CONFIRMED)

    def test_unused_declaration(self):
        path = self._rewrite_xlsx(drop_cell=True)
        report = msodde_excel.analyze_workbook(path)
        self.assertEqual(report.document_evidence(),
                         msodde_excel.EVIDENCE_DECLARATION)
        self.assertEqual(len(report.declarations), 1)
        self.assertEqual(report.references, [])
        self.assertEqual(report.sheet_entries()['Tabelle1'],
                         msodde_excel.EVIDENCE_NONE)
        self.assertEqual(report.limitations, [])

    def test_broken_index_is_unresolved(self):
        path = self._rewrite_xlsx(formula='[2]!_xlbgnm.A1')
        report = msodde_excel.analyze_workbook(path)
        self.assertEqual(len(report.references), 1)
        reference = report.references[0]
        self.assertEqual(reference.evidence,
                         msodde_excel.EVIDENCE_UNRESOLVED)
        self.assertEqual(reference.declaration_index, 1)
        self.assertEqual(report.document_evidence(),
                         msodde_excel.EVIDENCE_UNRESOLVED)
        reasons = [lim.reason for lim in report.limitations]
        self.assertIn('formula references a missing external link index',
                      reasons)

    def test_ordinary_external_workbook_not_dde(self):
        report = msodde_excel.analyze_workbook(
            join(DATA_BASE_DIR, 'oleobj', 'external_link',
                 'sample_with_external_link_to_doc.xlsx'))
        self.assertEqual(report.document_evidence(),
                         msodde_excel.EVIDENCE_NONE)
        self.assertEqual(len(report.declarations), 1)
        self.assertEqual(report.declarations[0].kind,
                         msodde_excel.KIND_OLE)
        self.assertNotIn(msodde_excel.KIND_DDE,
                         [decl.kind for decl in report.declarations])


class TestOoxmlCoverage(unittest.TestCase):
    """Parse failures must not look like clean "no reference" results."""

    def test_unparseable_worksheet_is_incomplete(self):
        source = join(DATA_BASE_DIR, 'msodde', 'dde-test.xlsx')
        handle, destination = tempfile.mkstemp(suffix='.xlsx')
        os.close(handle)
        self.addCleanup(os.unlink, destination)
        with zipfile.ZipFile(source) as zin, \
                zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == 'xl/worksheets/sheet1.xml':
                    data = data[:len(data) // 2]
                zout.writestr(item, data)
        report = msodde_excel.analyze_workbook(destination)
        self.assertEqual(report.document_evidence(),
                         msodde_excel.EVIDENCE_INCOMPLETE)
        self.assertEqual(report.sheet_entries()['Tabelle1'],
                         msodde_excel.EVIDENCE_INCOMPLETE)
        self.assertTrue(report.limitations)

    def test_shared_formula_master_reference(self):
        source = join(DATA_BASE_DIR, 'msodde', 'dde-test.xlsx')
        handle, destination = tempfile.mkstemp(suffix='.xlsx')
        os.close(handle)
        self.addCleanup(os.unlink, destination)
        with zipfile.ZipFile(source) as zin, \
                zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == 'xl/worksheets/sheet1.xml':
                    text = data.decode('utf-8')
                    text = text.replace(
                        '<f>[1]!_xlbgnm.A1</f>',
                        '<f t="shared" ref="B4:B5" si="0">'
                        '[1]!_xlbgnm.A1</f>')
                    data = text.encode('utf-8')
                zout.writestr(item, data)
        report = msodde_excel.analyze_workbook(destination)
        self.assertEqual(len(report.references), 1)
        self.assertEqual(report.references[0].detail,
                         'shared formula master')
        self.assertEqual(report.references[0].evidence,
                         msodde_excel.EVIDENCE_CONFIRMED)


class TestBiffReport(unittest.TestCase):
    """BIFF (xls) supports the same declaration/reference distinction."""

    @classmethod
    def setUpClass(cls):
        cls.sample = join(DATA_BASE_DIR, 'encrypted',
                          'dde-test-encrypt-standardpassword.xls')

    def _report(self):
        from oletools import crypto
        folder = tempfile.mkdtemp(prefix='oletools-dde-report-')
        self.addCleanup(shutil.rmtree, folder, True)
        decrypted, _ = crypto.decrypt(self.sample, crypto.DEFAULT_PASSWORDS,
                                      folder)
        self.addCleanup(lambda: os.path.exists(decrypted) and
                        os.unlink(decrypted))
        return msodde_excel.analyze_workbook(decrypted)

    def test_biff_confirmed_reference(self):
        report = self._report()
        self.assertEqual(report.document_evidence(),
                         msodde_excel.EVIDENCE_CONFIRMED)
        self.assertEqual(len(report.declarations), 1)
        declaration = report.declarations[0]
        self.assertEqual(declaration.kind, msodde_excel.KIND_DDE)
        self.assertEqual(declaration.service, 'cmd')
        self.assertEqual(declaration.topic, '/c calc.exe')
        self.assertIn('SupBook', declaration.location)
        self.assertIsNotNone(declaration.record_offset)
        self.assertEqual(len(report.references), 1)
        reference = report.references[0]
        self.assertEqual(reference.sheet, 'Tabelle1')
        self.assertEqual(reference.evidence,
                         msodde_excel.EVIDENCE_CONFIRMED)
        self.assertTrue(reference.token.startswith('0x39'))
        self.assertIn('ptgNameX', reference.token)


class TestXlsbReport(unittest.TestCase):
    """XLSB declarations are read from externalLink*.bin parts."""

    @classmethod
    def setUpClass(cls):
        cls.sample = join(DATA_BASE_DIR, 'msodde', 'dde-test.xlsb')

    def test_xlsb_confirmed_reference(self):
        report = msodde_excel.analyze_workbook(self.sample)
        self.assertEqual(report.document_evidence(),
                         msodde_excel.EVIDENCE_CONFIRMED)
        self.assertEqual(len(report.declarations), 1)
        declaration = report.declarations[0]
        self.assertEqual(declaration.kind, msodde_excel.KIND_DDE)
        self.assertEqual(declaration.service, 'cmd')
        self.assertEqual(declaration.topic, '/c calc.exe')
        self.assertIn('externalLink1.bin', declaration.location)
        self.assertEqual(len(report.references), 1)
        reference = report.references[0]
        self.assertEqual(reference.sheet, 'Tabelle1')
        self.assertEqual(reference.cell, 'B4')
        self.assertEqual(reference.evidence,
                         msodde_excel.EVIDENCE_CONFIRMED)

    def test_xlsb_ordinary_external_link_not_dde(self):
        report = msodde_excel.analyze_workbook(
            join(DATA_BASE_DIR, 'oleobj', 'external_link',
                 'sample_with_external_link_to_doc.xlsb'))
        self.assertEqual(report.document_evidence(),
                         msodde_excel.EVIDENCE_NONE)
        self.assertEqual(len(report.declarations), 1)
        self.assertEqual(report.declarations[0].kind,
                         msodde_excel.KIND_OLE)


class TestTokenCoverage(unittest.TestCase):
    """Unknown tokens and broken indexes must be visible limitations."""

    def test_unknown_token_is_reported(self):
        # 0x18 ptgExtended is not implemented; it must not be silently
        # skipped and then reported as "no reference".
        parser = msodde_excel._BiffTokenParser(b'\x18\x01\x02')
        parser.parse()
        self.assertEqual(parser.unknown_tokens, [0x18])
        self.assertEqual(parser.references, [])

    def test_truncated_reference_is_reported(self):
        # ptgNameX header cut in the middle.
        parser = msodde_excel._BiffTokenParser(b'\x39\x00\x00')
        parser.parse()
        self.assertTrue(parser.truncated)
        self.assertEqual(parser.references, [])

    def test_bad_extern_sheet_index_is_unresolved(self):
        report = msodde_excel.ExcelDdeReport('synthetic')
        collector = msodde_excel._BiffCollector.__new__(
            msodde_excel._BiffCollector)
        collector.report = report
        collector.declarations = []
        collector.xti = []
        reference = collector._make_reference('S', 'A1', 'S!A1', 0x39, 9)
        self.assertEqual(reference.evidence,
                         msodde_excel.EVIDENCE_UNRESOLVED)
        self.assertIn('invalid ExternSheet index',
                      report.limitations[0].reason)


if __name__ == '__main__':
    unittest.main()
