#!/usr/bin/env python
"""
msodde_excel.py

Evidence-oriented DDE reporting for Excel workbooks.

The existing :py:mod:`oletools.msodde` API returns text lines for DDE links.
That is enough to say "a DDE declaration exists", but not enough to say
whether any worksheet actually uses it.  This module keeps the declarations
and the formula references apart and does not try to evaluate formulas.

The report deliberately distinguishes:

* a declaration (``ddeLink`` in OOXML, ``SupBook`` in BIFF,
  ``BrtBeginSupBook`` in XLSB);
* a formula reference to that declaration, which mentions the declaration
  index and the cell that contains the formula;
* coverage limitations (unknown formula tokens, broken indexes, unsupported
  conditional/shared formula parts).  A missing reference is *not* reported as
  "will not trigger" when the tokens could not be understood.

All analysis is read-only: nothing is executed, no target is contacted and
formulas are never evaluated.
"""

from __future__ import print_function

import os
import re
import zipfile
from collections import OrderedDict

from oletools import ooxml
from oletools import xls_parser
from oletools.common.log_helper import log_helper

__version__ = '0.1'

logger = log_helper.get_or_create_silent_logger('msodde_excel')


# Evidence levels.  Higher values are stronger evidence.
EVIDENCE_NONE = 'none'
EVIDENCE_DECLARATION = 'declaration-only'
EVIDENCE_REFERENCE = 'formula-reference'
EVIDENCE_CONFIRMED = 'confirmed-reference'
EVIDENCE_UNRESOLVED = 'unresolved-reference'
EVIDENCE_INCOMPLETE = 'incomplete-analysis'
EVIDENCE_OTHER_LINK = 'other-external-link'

EVIDENCE_RANK = {
    EVIDENCE_NONE: 0,
    EVIDENCE_DECLARATION: 1,
    EVIDENCE_INCOMPLETE: 2,
    EVIDENCE_UNRESOLVED: 3,
    EVIDENCE_REFERENCE: 4,
    EVIDENCE_CONFIRMED: 5,
    EVIDENCE_OTHER_LINK: 0,
}

# declaration kinds
KIND_DDE = 'dde'
KIND_OLE = 'ole'
KIND_EXTERNAL_WORKBOOK = 'external-workbook'
KIND_INTERNAL = 'internal'
KIND_UNKNOWN = 'unknown'

# BIFF ptgNameX/Ref3d style tokens
PTG_NAME = 0x23
PTG_NAME_X = 0x39
PTG_REF_3D = 0x3A
PTG_AREA_3D = 0x3B
PTG_REF_ERR_3D = 0x3C
PTG_AREA_ERR_3D = 0x3D
PTG_ATTR = 0x19
PTG_STR = 0x17

# XLSB record ids for external link structures
XLSB_SUPBOOK_SRC = 0x0163
XLSB_SUP_SELF = 0x0165
XLSB_SUP_SAME = 0x0166
XLSB_SUP_TABS = 0x0167
XLSB_SUP_ADDIN = 0x029B

#: index in an OOXML external reference such as ``[1]Sheet1!A1``
_EXTERNAL_INDEX_RE = re.compile(r'\[\s*(\d+)\s*\]')


def _clean_text(value):
    if value is None:
        return u''
    return value.replace(u'\u0003', u' ').strip()


class DdeDeclaration(object):
    """A DDE/OLE/external declaration found in the workbook."""

    def __init__(self, kind, service=u'', topic=u'', location=u'',
                 index=None, format_name=u'', detail=u'', targets=None,
                 record_offset=None, extern_name_count=None):
        self.kind = kind
        self.service = service or u''
        self.topic = topic or u''
        self.location = location or u''
        self.index = index
        self.format_name = format_name or u''
        self.detail = detail or u''
        self.targets = list(targets or [])
        self.record_offset = record_offset
        self.extern_name_count = extern_name_count

    @property
    def is_dde(self):
        return self.kind == KIND_DDE

    def as_dict(self):
        return OrderedDict([
            ('kind', self.kind),
            ('service', self.service),
            ('topic', self.topic),
            ('location', self.location),
            ('index', self.index),
            ('format', self.format_name),
            ('detail', self.detail),
            ('record_offset', self.record_offset),
            ('extern_name_count', self.extern_name_count),
            ('targets', self.targets),
        ])

    def link_text(self):
        if self.service and self.topic:
            return u'{0} {1}'.format(self.service, self.topic)
        return self.service or self.topic


_TOKEN_NAMES = {
    PTG_NAME: 'ptgName',
    PTG_NAME_X: 'ptgNameX',
    PTG_REF_3D: 'ptgRef3d',
    PTG_AREA_3D: 'ptgArea3d',
    PTG_REF_ERR_3D: 'ptgRefErr3d',
    PTG_AREA_ERR_3D: 'ptgAreaErr3d',
}


class DdeReference(object):
    """A formula that mentions an external declaration."""

    def __init__(self, sheet, cell, formula, declaration_index=None,
                 declaration_kind=None, token=u'', evidence=EVIDENCE_UNRESOLVED,
                 location=u'', detail=u''):
        self.sheet = sheet
        self.cell = cell
        self.formula = formula
        self.declaration_index = declaration_index
        self.declaration_kind = declaration_kind
        self.token = token
        self.evidence = evidence
        self.location = location
        self.detail = detail

    def as_dict(self):
        return OrderedDict([
            ('sheet', self.sheet),
            ('cell', self.cell),
            ('formula', self.formula),
            ('declaration_index', self.declaration_index),
            ('declaration_kind', self.declaration_kind),
            ('token', self.token),
            ('evidence', self.evidence),
            ('location', self.location),
            ('detail', self.detail),
        ])


class CoverageLimitation(object):
    """Something which prevents a complete reference analysis."""

    def __init__(self, location, reason, token=None, detail=u''):
        self.location = location
        self.reason = reason
        self.token = token
        self.detail = detail

    def as_dict(self):
        return OrderedDict([
            ('location', self.location),
            ('reason', self.reason),
            ('token', self.token),
            ('detail', self.detail),
        ])


class ExcelDdeReport(object):
    """Result of the DDE declaration/reference analysis."""

    def __init__(self, filename=None):
        self.filename = filename or u''
        self.format = None
        self.declarations = []
        self.references = []
        self.sheets = OrderedDict()
        self.limitations = []
        self.notes = []
        #: sheets for which reference extraction was not complete
        self.incomplete_sheets = set()

    def add_declaration(self, declaration):
        self.declarations.append(declaration)

    def add_reference(self, reference):
        self.references.append(reference)

    def add_limitation(self, limitation):
        self.limitations.append(limitation)

    def declarations_by_kind(self, kind):
        return [decl for decl in self.declarations if decl.kind == kind]

    def evidence_for_sheet(self, sheet):
        refs = [ref for ref in self.references
                if ref.sheet == sheet and ref.evidence != EVIDENCE_OTHER_LINK]
        if not refs:
            if sheet in self.incomplete_sheets:
                return EVIDENCE_INCOMPLETE
            return EVIDENCE_NONE
        if any(ref.evidence == EVIDENCE_CONFIRMED for ref in refs):
            return EVIDENCE_CONFIRMED
        if any(ref.evidence == EVIDENCE_REFERENCE for ref in refs):
            return EVIDENCE_REFERENCE
        return EVIDENCE_UNRESOLVED

    def document_evidence(self):
        level = EVIDENCE_NONE
        if any(decl.is_dde for decl in self.declarations):
            level = EVIDENCE_DECLARATION
        for ref in self.references:
            if ref.evidence == EVIDENCE_OTHER_LINK:
                continue
            if EVIDENCE_RANK[ref.evidence] > EVIDENCE_RANK[level]:
                level = ref.evidence
        if self.incomplete_sheets and \
                EVIDENCE_RANK[level] < EVIDENCE_RANK[EVIDENCE_INCOMPLETE]:
            level = EVIDENCE_INCOMPLETE
        if self.limitations and not self.references and \
                EVIDENCE_RANK[level] < EVIDENCE_RANK[EVIDENCE_INCOMPLETE]:
            level = EVIDENCE_INCOMPLETE
        return level

    def sheet_entries(self):
        entries = OrderedDict()
        for sheet in self.sheets:
            entries[sheet] = self.evidence_for_sheet(sheet)
        for ref in self.references:
            if ref.evidence == EVIDENCE_OTHER_LINK:
                continue
            if ref.sheet not in entries:
                entries[ref.sheet] = ref.evidence
        return entries

    def link_texts(self):
        texts = []
        for declaration in self.declarations:
            if not declaration.is_dde:
                continue
            text = declaration.link_text()
            if text and text not in texts:
                texts.append(text)
        return texts

    def has_unresolved_coverage(self):
        return bool(self.limitations)

    def as_dict(self):
        sheets = []
        for name, level in self.sheet_entries().items():
            sheets.append(OrderedDict([
                ('name', name),
                ('evidence', level),
                ('references', [ref.as_dict() for ref in self.references
                                if ref.sheet == name]),
            ]))
        return OrderedDict([
            ('file', self.filename),
            ('format', self.format),
            ('evidence', self.document_evidence()),
            ('declarations', [decl.as_dict() for decl in self.declarations]),
            ('sheets', sheets),
            ('references', [ref.as_dict() for ref in self.references]),
            ('coverage_limitations',
             [lim.as_dict() for lim in self.limitations]),
            ('notes', self.notes),
        ])

    def summary(self):
        """One-line counts useful for logs and tests."""
        dde = len([decl for decl in self.declarations if decl.is_dde])
        refs = len([ref for ref in self.references
                    if ref.evidence != EVIDENCE_OTHER_LINK])
        return '{0} DDE declaration(s), {1} referencing formula(s), ' \
               '{2} coverage limitation(s)'.format(
                   dde, refs, len(self.limitations))

    def text_report(self):
        lines = []
        lines.append('Excel DDE analysis: {0}'.format(self.filename))
        lines.append('Format: {0}'.format(self.format or 'unknown'))
        lines.append('Workbook evidence: {0}'.format(self.document_evidence()))
        lines.append('Summary: {0}'.format(self.summary()))
        lines.append(u'Declarations:')
        if not self.declarations:
            lines.append(u'  (none)')
        for decl in self.declarations:
            entry = u'  [{0}] {1}'.format(decl.kind, decl.location)
            if decl.service or decl.topic:
                entry += u': service={0!r} topic={1!r}'.format(
                    decl.service, decl.topic)
            if decl.format_name:
                entry += u' format={0}'.format(decl.format_name)
            lines.append(entry)
        lines.append(u'Sheets and evidence:')
        if not self.sheet_entries():
            lines.append(u'  (none)')
        for name, level in self.sheet_entries().items():
            lines.append(u'  {0}: {1}'.format(name, level))
            for ref in self.references:
                if ref.sheet != name:
                    continue
                lines.append(u'    {0} {1} token={2!r} -> declaration {3}'.format(
                    ref.cell or '?', ref.evidence, ref.token,
                    ref.declaration_index))
                if ref.formula:
                    lines.append(u'      formula: {0}'.format(ref.formula))
        lines.append(u'Coverage limitations:')
        if not self.limitations:
            lines.append(u'  (none)')
        for lim in self.limitations:
            entry = u'  {0}: {1}'.format(lim.location, lim.reason)
            if lim.token:
                entry += u' token=0x{0:02X}'.format(lim.token)
            if lim.detail:
                entry += u' ({0})'.format(lim.detail)
            lines.append(entry)
        return u'\n'.join(lines)


# -----------------------------------------------------------------------------
# BIFF / XLSB token parsing
# -----------------------------------------------------------------------------


class _BiffTokenParser(object):
    """Walk a BIFF8 or XLSB token stream for external references.

    Only token lengths and the handful of 3-D reference tokens are decoded.
    Any unknown or malformed token immediately stops parsing and reports a
    coverage limitation.  An incomplete walk must never be reported as
    "no reference".
    """

    #: BIFF8 sizes including the token byte itself (MS-XLS 2.5.198)
    BIFF_FIXED_SIZES = {
        0x00: 8, 0x01: 5, 0x02: 5, 0x03: 1, 0x04: 1, 0x05: 1, 0x06: 1,
        0x07: 1, 0x08: 1, 0x09: 1, 0x0A: 1, 0x0B: 1, 0x0C: 1, 0x0D: 1,
        0x0E: 1, 0x0F: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 1, 0x14: 1,
        0x15: 1, 0x16: 1,
        0x1C: 2, 0x1D: 2, 0x1E: 3, 0x1F: 9,
        0x20: 8, 0x21: 3, 0x22: 4, 0x23: 5, 0x24: 5, 0x25: 9,
        0x26: 7, 0x27: 7, 0x28: 7, 0x29: 3, 0x2A: 5, 0x2B: 9,
        0x2C: 5, 0x2D: 9, 0x2E: 3, 0x2F: 3,
    }

    #: XLSB sizes including the token byte (MS-XLSB 2.5.97)
    XLSB_FIXED_SIZES = {
        0x00: 1, 0x01: 5, 0x02: 5, 0x03: 1, 0x04: 1, 0x05: 1, 0x06: 1, 0x07: 1, 0x08: 1,
        0x09: 1, 0x0A: 1, 0x0B: 1, 0x0C: 1, 0x0D: 1, 0x0E: 1, 0x0F: 1,
        0x10: 1, 0x11: 1, 0x12: 1, 0x13: 1, 0x14: 1, 0x15: 1, 0x16: 1,
        0x18: 5, 0x1C: 2, 0x1D: 2, 0x1E: 3, 0x1F: 9,
        0x20: 15, 0x21: 3, 0x22: 4, 0x23: 5, 0x24: 7, 0x25: 13,
        0x26: 7, 0x27: 7, 0x28: 7, 0x29: 3, 0x2A: 9, 0x2B: 15,
        0x2C: 7, 0x2D: 13, 0x2E: 3, 0x2F: 3,
    }

    def __init__(self, rgce, xlsb=False):
        self.rgce = rgce
        self.xlsb = xlsb
        self.unknown_tokens = []
        self.references = []
        self.truncated = False

    def _u16(self, pos):
        return int.from_bytes(self.rgce[pos:pos + 2], 'little')

    def _u32(self, pos):
        return int.from_bytes(self.rgce[pos:pos + 4], 'little')

    def _token_base(self, op):
        return (op & 0x1F) + 32 if op & 0x60 else op & 0x1F

    def _ref_size(self, base):
        if self.xlsb:
            return {PTG_NAME_X: 7, PTG_REF_3D: 9, PTG_AREA_3D: 15,
                    PTG_REF_ERR_3D: 9, PTG_AREA_ERR_3D: 15,
                    PTG_NAME: 5}.get(base)
        return {PTG_NAME_X: 7, PTG_REF_3D: 7, PTG_AREA_3D: 11,
                PTG_REF_ERR_3D: 7, PTG_AREA_ERR_3D: 11,
                PTG_NAME: 5}.get(base)

    def _read_ref(self, base, pos):
        if base == PTG_NAME_X:
            ixti = self._u16(pos + 1)
            nameindex = self._u32(pos + 3)
            return (base, ixti, nameindex)
        if base == PTG_REF_3D:
            ixti = self._u16(pos + 1)
            if self.xlsb:
                row = self._u32(pos + 3)
                col = self._u16(pos + 7) & 0x3FFF
            else:
                row = self._u16(pos + 3)
                col = self._u16(pos + 5) & 0x3FFF
            return (base, ixti, (row, col))
        if base == PTG_AREA_3D:
            ixti = self._u16(pos + 1)
            if self.xlsb:
                r1 = self._u32(pos + 3)
                r2 = self._u32(pos + 7)
                c1 = self._u16(pos + 11) & 0x3FFF
                c2 = self._u16(pos + 13) & 0x3FFF
            else:
                r1 = self._u16(pos + 3)
                r2 = self._u16(pos + 5)
                c1 = self._u16(pos + 7) & 0x3FFF
                c2 = self._u16(pos + 9) & 0x3FFF
            return (base, ixti, (r1, r2, c1, c2))
        if base in (PTG_REF_ERR_3D, PTG_AREA_ERR_3D):
            return (base, self._u16(pos + 1), None)
        if base == PTG_NAME:
            return (base, None, self._u16(pos + 1))
        return None

    def _attr_size(self, pos):
        if pos + 4 > len(self.rgce):
            return None
        subop = self.rgce[pos + 1]
        if subop == 0x04:          # ptgAttrChoose
            n = self._u16(pos + 2)
            return 6 + 2 * n
        # All other attributes are 4 bytes in-stream; padding/space text is
        # stored in the separate extra-data block, not in rgce.
        return 4

    def parse(self):
        pos = 0
        length = len(self.rgce)
        sizes = self.XLSB_FIXED_SIZES if self.xlsb else self.BIFF_FIXED_SIZES
        while pos < length:
            op = self.rgce[pos]
            base = self._token_base(op)
            if base == 0x18:        # ptgExtended, BIFF only
                self.unknown_tokens.append(op)
                return
            if base == PTG_ATTR:
                size = self._attr_size(pos)
                if size is None or pos + size > length:
                    self.truncated = True
                    return
                pos += size
                continue
            ref_size = self._ref_size(base)
            if ref_size is not None:
                if pos + ref_size > length:
                    self.truncated = True
                    return
                ref = self._read_ref(base, pos)
                if ref is not None:
                    self.references.append(ref)
                pos += ref_size
                continue
            if base == PTG_STR:
                if self.xlsb:
                    if pos + 3 > length:
                        self.truncated = True
                        return
                    cch = self._u16(pos + 1)
                    pos += 3 + 2 * cch
                else:
                    if pos + 3 > length:
                        self.truncated = True
                        return
                    cch = self.rgce[pos + 1]
                    flags = self.rgce[pos + 2]
                    pos += 3 + (2 * cch if flags & 0x01 else cch)
                if pos > length:
                    self.truncated = True
                    return
                continue
            size = sizes.get(base)
            if size is None:
                self.unknown_tokens.append(op)
                return
            pos += size
            if pos > length:
                self.truncated = True
                return


def _col_to_letters(col):
    letters = u''
    col += 1
    while col:
        col, rem = divmod(col - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


class _OoxmlCollector(object):
    """Collect declarations and formula references from an OOXML workbook."""

    def __init__(self, filepath, report):
        self.filepath = filepath
        self.report = report

    def _read_rels(self, zipper, path):
        try:
            data = zipper.read(path)
        except KeyError:
            return {}
        rels = {}
        try:
            root = ooxml.ET.fromstring(data)
        except Exception:
            return rels
        for elem in root.iter():
            if not elem.tag.endswith('Relationship'):
                continue
            rel_id = elem.attrib.get('Id')
            if not rel_id:
                continue
            target = elem.attrib.get('Target', u'')
            if target.startswith('/'):
                target = target[1:]
            else:
                base = os.path.dirname(os.path.dirname(path))
                target = os.path.normpath(os.path.join(base, target)).replace(
                    os.sep, '/')
            rels[rel_id] = {
                'type': elem.attrib.get('Type', u''),
                'target': target,
                'target_mode': elem.attrib.get('TargetMode', u''),
            }
        return rels

    def collect(self):
        zipper = zipfile.ZipFile(self.filepath)
        try:
            return self._collect(zipper)
        finally:
            zipper.close()

    def _collect(self, zipper):
        workbook = None
        for name in ('xl/workbook.xml', 'xl/workbook.bin'):
            if name in zipper.namelist():
                workbook = name
                break
        if workbook is None:
            self.report.add_limitation(CoverageLimitation(
                'workbook', 'workbook part not found'))
            return self.report
        wb_rels = self._read_rels(
            zipper, 'xl/_rels/{0}.rels'.format(os.path.basename(workbook)))

        # sheets: rId -> name
        sheets = OrderedDict()
        external_refs = []
        if workbook.endswith('.xml'):
            try:
                root = ooxml.ET.fromstring(zipper.read(workbook))
            except Exception as exc:
                self.report.add_limitation(CoverageLimitation(
                    workbook, 'workbook XML could not be parsed',
                    detail=str(exc)))
                return self.report
            for elem in root.iter():
                if elem.tag.endswith('}sheet'):
                    rid = None
                    for key, value in elem.attrib.items():
                        if key.endswith('}id'):
                            rid = value
                    if rid:
                        sheets[rid] = elem.attrib.get('name', rid)
                elif elem.tag.endswith('}externalReference'):
                    rid = None
                    for key, value in elem.attrib.items():
                        if key.endswith('}id'):
                            rid = value
                    if rid:
                        external_refs.append(rid)

        # The [1]-style index in formulas follows workbook.xml's
        # externalReference order, including entries whose relationship is
        # broken.  Keep those slots so later indexes do not shift.
        declarations = []
        for rid in external_refs:
            rel = wb_rels.get(rid)
            if rel is None:
                self.report.add_limitation(CoverageLimitation(
                    workbook, 'external reference relationship is missing',
                    detail='rId={0}'.format(rid)))
                declarations.append(DdeDeclaration(
                    KIND_UNKNOWN, location=workbook,
                    index=len(declarations)))
                continue
            target = rel['target']
            declarations.append(self._read_external_link(
                zipper, target, len(declarations)))

        self.declarations = declarations
        for declaration in declarations:
            if declaration.kind in (KIND_DDE, KIND_OLE,
                                    KIND_EXTERNAL_WORKBOOK):
                self.report.add_declaration(declaration)

        # formulas per worksheet
        for rid, sheet_name in sheets.items():
            rel = wb_rels.get(rid)
            if rel is None or rel['type'].rsplit('/', 1)[-1] != 'worksheet':
                # Chartsheets cannot contain formulas with DDE references,
                # but a missing relationship would hide a real sheet.
                if rel is None:
                    self.report.add_limitation(CoverageLimitation(
                        workbook, 'sheet relationship is missing',
                        detail=rid))
                continue
            self._collect_sheet(zipper, rel['target'], sheet_name)
        return self.report

    def _read_external_link(self, zipper, path, index):
        try:
            root = ooxml.ET.fromstring(zipper.read(path))
        except Exception as exc:
            self.report.add_limitation(CoverageLimitation(
                path, 'external link XML could not be parsed', detail=str(exc)))
            return DdeDeclaration(KIND_UNKNOWN, location=path, index=index)
        for elem in root.iter():
            tag = elem.tag.rsplit('}', 1)[-1]
            if tag == 'ddeLink':
                return DdeDeclaration(
                    KIND_DDE,
                    service=elem.attrib.get('ddeService', u''),
                    topic=elem.attrib.get('ddeTopic', u''),
                    location=path, index=index, format_name='OOXML',
                    detail='ddeLink')
            if tag == 'oleLink':
                return DdeDeclaration(
                    KIND_OLE, location=path, index=index,
                    format_name='OOXML', detail='oleLink')
        return DdeDeclaration(KIND_EXTERNAL_WORKBOOK, location=path,
                              index=index, format_name='OOXML')

    def _formula_refs(self, formula, sheet_name, cell, location):
        refs = []
        for match in _EXTERNAL_INDEX_RE.finditer(formula):
            index = int(match.group(1)) - 1
            refs.append(DdeReference(
                sheet_name, cell, formula, declaration_index=index,
                evidence=EVIDENCE_REFERENCE, location=location,
                token=match.group(0)))
        return refs

    def _collect_sheet(self, zipper, path, sheet_name):
        try:
            root = ooxml.ET.fromstring(zipper.read(path))
        except Exception as exc:
            self.report.add_limitation(CoverageLimitation(
                path, 'worksheet XML could not be parsed', detail=str(exc)))
            self.report.sheets[sheet_name] = path
            self.report.incomplete_sheets.add(sheet_name)
            return
        self.report.sheets[sheet_name] = path
        for elem in root.iter():
            if elem.tag.rsplit('}', 1)[-1] != 'c':
                continue
            cell = elem.attrib.get('r', u'')
            formula = None
            shared = False
            for child in elem:
                if child.tag.rsplit('}', 1)[-1] == 'f' and child.text:
                    formula = child.text
                    # Only the master of a shared formula carries text; the
                    # range in @ref is recorded as context.
                    shared = child.attrib.get('t') == 'shared'
                    break
            if not formula:
                continue
            for ref in self._formula_refs(formula, sheet_name, cell, path):
                ref.declaration_kind = None
                if ref.declaration_index is not None:
                    if ref.declaration_index < len(self.declarations):
                        decl = self.declarations[ref.declaration_index]
                        ref.declaration_kind = decl.kind
                        if decl.is_dde:
                            ref.evidence = EVIDENCE_CONFIRMED
                        else:
                            ref.evidence = EVIDENCE_OTHER_LINK
                    else:
                        ref.evidence = EVIDENCE_UNRESOLVED
                        self.report.add_limitation(CoverageLimitation(
                            '{0}!{1}'.format(sheet_name, cell),
                            'formula references a missing external link index',
                            detail='[{0}]'.format(ref.declaration_index + 1)))
                if shared:
                    ref.detail = 'shared formula master'
                self.report.add_reference(ref)


class _BiffCollector(object):
    """Collect declarations and references from an .xls Workbook stream."""

    def __init__(self, filepath, report):
        self.filepath = filepath
        self.report = report

    def collect(self):
        xls_file = xls_parser.XlsFile(self.filepath)
        try:
            for stream in xls_file.iter_streams():
                if isinstance(stream, xls_parser.WorkbookStream):
                    self._collect_records(stream)
        finally:
            xls_file.close()
        return self.report

    def _collect_records(self, stream):
        declarations = []
        extern_names = []
        extern_sheets = []
        sheets = OrderedDict()
        formulas = []
        shared_formulas = []
        arrays = []
        names = []
        for record in stream.iter_records():
            if isinstance(record, xls_parser.XlsRecordBoundSheet):
                if record.sheet_type == 0:
                    sheets[record.offset] = record.name
            elif isinstance(record, xls_parser.XlsRecordSupBook):
                declaration = self._make_declaration(record, len(declarations))
                declarations.append(declaration)
                # EXTERNNAME records directly following a SUPBOOK belong to
                # that SupBook and are indexed from 1 in ptgNameX.
                extern_names.append([])
            elif isinstance(record, xls_parser.XlsRecordExternName):
                if extern_names:
                    extern_names[-1].append(record.name)
            elif isinstance(record, xls_parser.XlsRecordExternSheet):
                extern_sheets.append(record)
            elif isinstance(record, xls_parser.XlsRecordFormula):
                formulas.append(record)
            elif isinstance(record, xls_parser.XlsRecordShrFmla):
                shared_formulas.append(record)
            elif isinstance(record, xls_parser.XlsRecordArray):
                arrays.append(record)
            elif isinstance(record, xls_parser.XlsRecordName):
                names.append(record)

        self.declarations = declarations
        for declaration, extern_names_for_supbook in zip(declarations,
                                                          extern_names):
            declaration.extern_name_count = len(extern_names_for_supbook)
            if declaration.kind in (KIND_DDE, KIND_OLE,
                                    KIND_EXTERNAL_WORKBOOK):
                self.report.add_declaration(declaration)

        xti = []
        for record in extern_sheets:
            xti.extend(record.entries)
            if record.truncated:
                self.report.add_limitation(CoverageLimitation(
                    'Workbook!ExternSheet',
                    'ExternSheet record is truncated'))
        self.xti = xti

        unsupported = sum(1 for declaration in declarations
                          if declaration.kind == KIND_UNKNOWN)
        self.ordered_offsets = sorted(sheets)
        self.sheets = sheets
        for name in sheets.values():
            self.report.sheets[name] = 'Workbook!BoundSheet'
        # BOUNDSHEET offsets are in the Workbook stream but record.pos is
        # relative to that same stream, so the comparison is direct.

        for record in formulas:
            self._collect_formula(record)
        for record in shared_formulas:
            self._collect_shared_formula(record)
        for record in arrays:
            self._collect_array_formula(record)
        for record in names:
            self._collect_name(record)

        if unsupported:
            self.report.notes.append(
                '{} SupBook(s) had no recognizable link type and were not '
                'treated as DDE declarations'.format(unsupported))

    def _make_declaration(self, record, index):
        kind = KIND_UNKNOWN
        if record.support_link_type == \
                xls_parser.XlsRecordSupBook.LINK_TYPE_OLE_DDE:
            # BIFF uses the same SupBook kind for DDE and OLE links.  Only a
            # service/topic pair separated by 0x03 is a DDE address; anything
            # else is an OLE link and must not be labeled DDE.
            if u'\x03' in record.virt_path:
                kind = KIND_DDE
            else:
                kind = KIND_OLE
        elif record.support_link_type == \
                xls_parser.XlsRecordSupBook.LINK_TYPE_EXTERNAL:
            kind = KIND_EXTERNAL_WORKBOOK
        elif record.support_link_type in (
                xls_parser.XlsRecordSupBook.LINK_TYPE_SELF,
                xls_parser.XlsRecordSupBook.LINK_TYPE_SAMESHEET,
                xls_parser.XlsRecordSupBook.LINK_TYPE_ADDIN):
            kind = KIND_INTERNAL
        location = 'Workbook!SupBook[{0}]'.format(index)
        service = topic = u''
        if kind == KIND_DDE:
            service, topic = record.virt_path.split(u'\x03', 1)
            service = _clean_text(service)
            topic = _clean_text(topic)
        elif kind in (KIND_EXTERNAL_WORKBOOK, KIND_OLE):
            service = _clean_text(record.virt_path)
        return DdeDeclaration(
            kind, service=service, topic=topic, location=location,
            index=index, format_name='BIFF',
            detail=record.support_link_type,
            record_offset=record.pos)

    def _sheet_for_offset(self, offset):
        current = None
        for off in self.ordered_offsets:
            if off <= offset:
                current = self.sheets[off]
            else:
                break
        return current or u'?'

    def _collect_formula(self, record):
        sheet = self._sheet_for_offset(record.pos)
        cell = '{0}{1}'.format(_col_to_letters(record.col), record.row + 1)
        location = 'Workbook!{0}!{1}'.format(sheet, cell)
        if record.truncated:
            self.report.add_limitation(CoverageLimitation(
                location, 'formula record is truncated'))
        self._scan_tokens(record.rgce, sheet, cell, location)

    def _collect_shared_formula(self, record):
        sheet = self._sheet_for_offset(record.pos)
        row1, row2, col1, col2 = record.range
        cell = '{0}{1}'.format(_col_to_letters(col1), row1 + 1)
        location = 'Workbook!{0}!{1}'.format(sheet, cell)
        if record.truncated:
            self.report.add_limitation(CoverageLimitation(
                location, 'shared formula record is truncated'))
        self._scan_tokens(record.rgce, sheet, cell, location,
                          shared=True)

    def _collect_array_formula(self, record):
        sheet = self._sheet_for_offset(record.pos)
        row1, row2, col1, col2 = record.range
        cell = '{0}{1}'.format(_col_to_letters(col1), row1 + 1)
        location = 'Workbook!{0}!{1}'.format(sheet, cell)
        if record.truncated:
            self.report.add_limitation(CoverageLimitation(
                location, 'array formula record is truncated'))
        self._scan_tokens(record.rgce, sheet, cell, location)

    def _collect_name(self, record):
        location = 'Workbook!NAME[{0}]'.format(record.name)
        if record.truncated:
            self.report.add_limitation(CoverageLimitation(
                location, 'defined name record is truncated'))
        self._scan_tokens(record.rgce, u'<defined name>', record.name,
                          location, name=True)

    def _scan_tokens(self, rgce, sheet, cell, location, shared=False,
                     name=False):
        if not rgce:
            return
        parser = _BiffTokenParser(rgce)
        parser.parse()
        for token, ixti, extra in parser.references:
            self._add_reference(sheet, cell, location, token, ixti,
                                shared=shared, name=name,
                                name_index=extra if token == PTG_NAME_X else None)
        if parser.truncated:
            self.report.add_limitation(CoverageLimitation(
                location, 'formula token stream is truncated'))
            if sheet not in (u'<defined name>',):
                self.report.incomplete_sheets.add(sheet)
        for token in parser.unknown_tokens:
            self.report.add_limitation(CoverageLimitation(
                location, 'unsupported formula token', token=token))
            if sheet not in (u'<defined name>',):
                self.report.incomplete_sheets.add(sheet)

    def _add_reference(self, sheet, cell, location, token, ixti,
                       shared=False, name=False, name_index=None):
        ref = self._make_reference(sheet, cell, location, token, ixti,
                                   name_index=name_index)
        if ref is None:
            return
        if shared:
            ref.detail = (ref.detail + '; shared formula over range').strip('; ')
        if name:
            if ref.declaration_kind == KIND_DDE:
                ref.evidence = EVIDENCE_UNRESOLVED
            ref.detail = (ref.detail + '; via defined name').strip('; ')
        self.report.add_reference(ref)

    def _make_reference(self, sheet, cell, location, token, ixti,
                        name_index=None):
        decl = self._resolve_ixti(ixti)
        if decl is None:
            self.report.add_limitation(CoverageLimitation(
                location, 'formula references an invalid ExternSheet index',
                detail='ixti={0}'.format(ixti)))
            return DdeReference(
                sheet, cell, u'', token=u'0x{0:02X}'.format(token),
                evidence=EVIDENCE_UNRESOLVED, location=location,
                detail='ixti={0}'.format(ixti))
        if decl.kind == KIND_INTERNAL:
            # Internal 3-D references (current workbook / sheets) are not
            # external links and must not appear as DDE evidence.
            return None
        token_name = _TOKEN_NAMES.get(token, token)
        detail = 'ixti={0}'.format(ixti)
        evidence = EVIDENCE_REFERENCE
        if token == PTG_NAME_X and name_index is not None:
            detail += ', nameindex={0}'.format(name_index)
            count = decl.extern_name_count
            if count is not None and not (1 <= name_index <= count):
                self.report.add_limitation(CoverageLimitation(
                    location, 'ptgNameX refers to a missing ExternName',
                    detail='nameindex={0}, available={1}'.format(
                        name_index, count)))
                evidence = EVIDENCE_UNRESOLVED
        ref = DdeReference(
            sheet, cell, u'', declaration_index=decl.index,
            declaration_kind=decl.kind, token=u'0x{0:02X} {1}'.format(
                token, token_name),
            evidence=evidence, location=location, detail=detail)
        if decl.is_dde:
            if evidence == EVIDENCE_REFERENCE:
                ref.evidence = EVIDENCE_CONFIRMED
        else:
            ref.evidence = EVIDENCE_OTHER_LINK
        return ref

    def _resolve_ixti(self, ixti):
        if ixti is None or ixti < 0 or ixti >= len(self.xti):
            return None
        supbook_index, first, last = self.xti[ixti]
        if supbook_index < 0 or supbook_index >= len(self.declarations):
            return None
        return self.declarations[supbook_index]


class _XlsbCollector(object):
    """Collect declarations and references from an XLSB workbook."""

    def __init__(self, filepath, report):
        self.filepath = filepath
        self.report = report

    def collect(self):
        zipper = zipfile.ZipFile(self.filepath)
        try:
            return self._collect(zipper)
        finally:
            zipper.close()

    def _rels(self, zipper, path):
        rels = {}
        try:
            root = ooxml.ET.fromstring(zipper.read(path))
        except Exception:
            return rels
        for elem in root.iter():
            if not elem.tag.endswith('Relationship'):
                continue
            rid = elem.attrib.get('Id')
            if not rid:
                continue
            target = elem.attrib.get('Target', u'')
            base = os.path.dirname(os.path.dirname(path))
            if not target.startswith('/'):
                target = os.path.normpath(
                    os.path.join(base, target)).replace(os.sep, '/')
            else:
                target = target[1:]
            rels[rid] = {'type': elem.attrib.get('Type', u''),
                         'target': target}
        return rels

    def _collect(self, zipper):
        wb_rels = self._rels(zipper, 'xl/_rels/workbook.bin.rels')
        sheets = OrderedDict()
        supbooks = []
        extern_sheets = []
        names = []

        try:
            with ooxml.ZipSubFile(zipper, 'xl/workbook.bin') as handle:
                for record in xls_parser.parse_xlsb_part(
                        handle, None, 'xl/workbook.bin'):
                    if isinstance(record, xls_parser.XlsbBundleSh):
                        sheets[record.rel_id] = record.name
                    elif record.type == XLSB_SUPBOOK_SRC:
                        supbooks.append((record.type, record.rel_id))
                    elif record.type in (XLSB_SUP_SELF, XLSB_SUP_SAME,
                                         XLSB_SUP_TABS, XLSB_SUP_ADDIN):
                        supbooks.append((record.type, None))
                    elif isinstance(record, xls_parser.XlsbExternSheet):
                        extern_sheets.append(record)
                    elif isinstance(record, xls_parser.XlsbName):
                        names.append(record)
        except Exception as exc:
            self.report.add_limitation(CoverageLimitation(
                'xl/workbook.bin', 'workbook binary part could not be parsed',
                detail=str(exc)))

        declarations = []
        for rec_type, rid in supbooks:
            if rec_type != XLSB_SUPBOOK_SRC:
                declarations.append(DdeDeclaration(
                    KIND_INTERNAL, location='xl/workbook.bin',
                    index=len(declarations), format_name='XLSB',
                    detail='internal supbook record 0x{0:04X}'.format(
                        rec_type)))
                continue
            rel = wb_rels.get(rid)
            if rel is None:
                self.report.add_limitation(CoverageLimitation(
                    'xl/workbook.bin',
                    'external link relationship is missing', detail=rid))
                declarations.append(DdeDeclaration(
                    KIND_UNKNOWN, location='xl/workbook.bin',
                    index=len(declarations)))
                continue
            declarations.append(
                self._read_external_bin(zipper, rel['target'],
                                        len(declarations)))
        self.declarations = declarations
        for declaration in declarations:
            if declaration.kind in (KIND_DDE, KIND_OLE,
                                    KIND_EXTERNAL_WORKBOOK):
                self.report.add_declaration(declaration)

        xti = []
        for record in extern_sheets:
            xti.extend(record.entries)
        self.xti = xti

        for rid, name in sheets.items():
            rel = wb_rels.get(rid)
            if rel is None:
                self.report.add_limitation(CoverageLimitation(
                    'xl/workbook.bin', 'sheet relationship is missing',
                    detail=rid))
                continue
            self.report.sheets[name] = rel['target']
            self._collect_sheet(zipper, rel['target'], name)

        for record in names:
            location = 'Workbook!NAME[{0}]'.format(record.name)
            if record.truncated:
                self.report.add_limitation(CoverageLimitation(
                    location, 'defined name record is truncated'))
            self._scan_tokens(record.rgce, u'<defined name>', record.name,
                              location, name=True)
        return self.report

    def _read_external_bin(self, zipper, path, index):
        decl = DdeDeclaration(KIND_EXTERNAL_WORKBOOK, location=path,
                              index=index, format_name='XLSB')
        try:
            with ooxml.ZipSubFile(zipper, path) as handle:
                for record in xls_parser.parse_xlsb_part(handle, None, path):
                    if not isinstance(record, xls_parser.XlsbBeginSupBook):
                        continue
                    decl.record_offset = record.pos
                    if record.link_type == \
                            xls_parser.XlsbBeginSupBook.LINK_TYPE_DDE:
                        decl.kind = KIND_DDE
                        decl.service = _clean_text(record.string1)
                        decl.topic = _clean_text(record.string2)
                        decl.detail = 'BrtBeginSupBook sbt=1'
                    elif record.link_type == \
                            xls_parser.XlsbBeginSupBook.LINK_TYPE_OLE:
                        decl.kind = KIND_OLE
                        decl.detail = 'BrtBeginSupBook sbt=2'
                    elif record.link_type == \
                            xls_parser.XlsbBeginSupBook.LINK_TYPE_WORKBOOK:
                        decl.kind = KIND_EXTERNAL_WORKBOOK
                        decl.detail = 'BrtBeginSupBook sbt=0'
                    else:
                        decl.kind = KIND_UNKNOWN
                        decl.detail = 'BrtBeginSupBook sbt={0}'.format(
                            getattr(record, 'sbt', u'?'))
        except Exception as exc:
            self.report.add_limitation(CoverageLimitation(
                path, 'external link binary part could not be parsed',
                detail=str(exc)))
        return decl

    def _collect_sheet(self, zipper, path, sheet_name):
        try:
            with ooxml.ZipSubFile(zipper, path) as handle:
                row = None
                for record in xls_parser.parse_xlsb_part(handle, None, path):
                    if isinstance(record, xls_parser.XlsbRowHdr):
                        row = record.row
                    elif isinstance(record, xls_parser.XlsbFormula):
                        cell = '{0}{1}'.format(
                            _col_to_letters(record.col), (row or 0) + 1)
                        location = '{0}!{1}'.format(sheet_name, cell)
                        if record.truncated:
                            self.report.add_limitation(CoverageLimitation(
                                location, 'formula record is truncated'))
                        self._scan_tokens(record.rgce, sheet_name, cell,
                                          location)
                    elif isinstance(record, xls_parser.XlsbShrFmla):
                        r1, r2, c1, c2 = record.range
                        cell = '{0}{1}'.format(_col_to_letters(c1), r1 + 1)
                        location = '{0}!{1}'.format(sheet_name, cell)
                        if record.truncated:
                            self.report.add_limitation(CoverageLimitation(
                                location, 'shared formula record is truncated'))
                        self._scan_tokens(record.rgce, sheet_name, cell,
                                          location, shared=True)
                    elif isinstance(record, xls_parser.XlsbArrFmla):
                        r1, r2, c1, c2 = record.range
                        cell = '{0}{1}'.format(_col_to_letters(c1), r1 + 1)
                        location = '{0}!{1}'.format(sheet_name, cell)
                        if record.truncated:
                            self.report.add_limitation(CoverageLimitation(
                                location, 'array formula record is truncated'))
                        self._scan_tokens(record.rgce, sheet_name, cell,
                                          location)
        except Exception as exc:
            self.report.add_limitation(CoverageLimitation(
                path, 'worksheet binary part could not be parsed',
                detail=str(exc)))
            self.report.incomplete_sheets.add(sheet_name)

    def _scan_tokens(self, rgce, sheet, cell, location, shared=False,
                     name=False):
        if not rgce:
            return
        parser = _BiffTokenParser(rgce, xlsb=True)
        parser.parse()
        for token, ixti, extra in parser.references:
            ref = self._make_reference(
                sheet, cell, location, token, ixti,
                name_index=extra if token == PTG_NAME_X else None)
            if ref is None:
                continue
            if shared:
                ref.detail = (ref.detail + '; shared formula over range'
                              ).strip('; ')
            if name:
                if ref.declaration_kind == KIND_DDE:
                    ref.evidence = EVIDENCE_UNRESOLVED
                ref.detail = (ref.detail + '; via defined name').strip('; ')
            self.report.add_reference(ref)
        if parser.truncated:
            self.report.add_limitation(CoverageLimitation(
                location, 'formula token stream is truncated'))
            if sheet not in (u'<defined name>',):
                self.report.incomplete_sheets.add(sheet)
        for token in parser.unknown_tokens:
            self.report.add_limitation(CoverageLimitation(
                location, 'unsupported formula token', token=token))
            if sheet not in (u'<defined name>',):
                self.report.incomplete_sheets.add(sheet)

    def _make_reference(self, sheet, cell, location, token, ixti,
                        name_index=None):
        decl = self._resolve_ixti(ixti)
        if decl is None:
            self.report.add_limitation(CoverageLimitation(
                location, 'formula references an invalid ExternSheet index',
                detail='ixti={0}'.format(ixti)))
            return DdeReference(
                sheet, cell, u'', token=u'0x{0:02X}'.format(token),
                evidence=EVIDENCE_UNRESOLVED, location=location,
                detail='ixti={0}'.format(ixti))
        if decl.kind == KIND_INTERNAL:
            # Internal 3-D references (current workbook / sheets) are not
            # external links and must not appear as DDE evidence.
            return None
        token_name = _TOKEN_NAMES.get(token, token)
        detail = 'ixti={0}'.format(ixti)
        evidence = EVIDENCE_REFERENCE
        if token == PTG_NAME_X and name_index is not None:
            detail += ', nameindex={0}'.format(name_index)
            count = decl.extern_name_count
            if count is not None and not (1 <= name_index <= count):
                self.report.add_limitation(CoverageLimitation(
                    location, 'ptgNameX refers to a missing ExternName',
                    detail='nameindex={0}, available={1}'.format(
                        name_index, count)))
                evidence = EVIDENCE_UNRESOLVED
        ref = DdeReference(
            sheet, cell, u'', declaration_index=decl.index,
            declaration_kind=decl.kind, token=u'0x{0:02X} {1}'.format(
                token, token_name),
            evidence=evidence, location=location, detail=detail)
        if decl.is_dde:
            if evidence == EVIDENCE_REFERENCE:
                ref.evidence = EVIDENCE_CONFIRMED
        else:
            ref.evidence = EVIDENCE_OTHER_LINK
        return ref

    def _resolve_ixti(self, ixti):
        if ixti is None or ixti < 0 or ixti >= len(self.xti):
            return None
        supbook_index, first, last = self.xti[ixti]
        if supbook_index < 0 or supbook_index >= len(self.declarations):
            return None
        return self.declarations[supbook_index]


def analyze_workbook(filepath):
    """Analyze an Excel workbook and return an :class:`ExcelDdeReport`.

    Accepts OOXML (.xlsx/.xlsm), XLSB and BIFF (.xls).  Raises a
    :class:`ValueError` if the file is not an Excel workbook.
    """
    report = ExcelDdeReport(filepath)
    try:
        doctype = ooxml.get_type(filepath)
    except Exception:
        doctype = None
    if doctype == ooxml.DOCTYPE_EXCEL:
        if zipfile.is_zipfile(filepath):
            names = zipfile.ZipFile(filepath).namelist()
            if 'xl/workbook.bin' in names:
                report.format = 'XLSB (OOXML package)'
                return _XlsbCollector(filepath, report).collect()
        report.format = 'OOXML (xlsx/xlsm)'
        return _OoxmlCollector(filepath, report).collect()
    if xls_parser.is_xls(filepath):
        report.format = 'BIFF (xls)'
        return _BiffCollector(filepath, report).collect()
    raise ValueError('not an Excel workbook: {0}'.format(filepath))
