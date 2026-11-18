"""
Tests for identity-preserving OOXML macro project discovery.

These tests build adversarial OOXML packages in memory: two physical ZIP
members with the same part name but different bytes, an orphan macro project,
contradictory content types and relationship targets that try to escape the
package. No file is ever read from the host directory to satisfy a package
relationship.
"""

import io
import unittest
import warnings
import zipfile

import olefile

from oletools import ooxml_macros
from oletools.olevba import VBA_Parser
from tests.test_utils import DATA_BASE_DIR
from os.path import join

#: a real, valid OLE macro project used as building block
SAMPLE_DOCM = join(DATA_BASE_DIR, 'oleform', 'oleform-PR314.docm')
VBAPROJECT_PART = 'word/vbaProject.bin'

CT_NS = 'http://schemas.openxmlformats.org/package/2006/content-types'
REL_NS = 'http://schemas.openxmlformats.org/package/2006/relationships'
VBA_REL = 'http://schemas.microsoft.com/office/2006/relationships/vbaProject'


def _real_ole_bytes():
    with zipfile.ZipFile(SAMPLE_DOCM) as zipper:
        return zipper.read(VBAPROJECT_PART)


def _mutate_ole(data, marker):
    """Return a same-size but byte-different, still valid OLE project."""
    buffer = io.BytesIO(data)
    ole = olefile.OleFileIO(buffer, write_mode=True)
    project = bytearray(ole.openstream('PROJECT').read())
    project[5:5 + 36] = ((marker * 40)[:36]).encode('ascii')
    ole.write_stream('PROJECT', bytes(project))
    ole.close()
    return buffer.getvalue()


def _content_types(extra_defaults=(), overrides=()):
    parts = ['<Default Extension="rels" '
             'ContentType="application/vnd.openxmlformats-package.'
             'relationships+xml"/>',
             '<Default Extension="xml" ContentType="application/xml"/>']
    parts.extend(extra_defaults)
    parts.extend(overrides)
    return ('<?xml version="1.0"?><Types xmlns="{0}">{1}</Types>'
            .format(CT_NS, ''.join(parts))).encode()


def _relationships(entries):
    body = ''.join(
        '<Relationship Id="r{0}" Type="{1}" Target="{2}"{3}/>'.format(
            idx, rel_type, target,
            ' TargetMode="External"' if external else '')
        for idx, (rel_type, target, external) in enumerate(entries))
    return ('<?xml version="1.0"?><Relationships xmlns="{0}">{1}</Relationships>'
            .format(REL_NS, body)).encode()


def _build_zip(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zipper:
        for name, data in members:
            zipper.writestr(name, data)
    return buffer.getvalue()


class TestOOXMLMacroDiscovery(unittest.TestCase):
    """Direct tests for the discovery helper."""

    def setUp(self):
        warnings.simplefilter('ignore')  # zipfile warns on duplicate names
        self.ole = _real_ole_bytes()

    def _discover(self, package_bytes):
        zipper = zipfile.ZipFile(io.BytesIO(package_bytes))
        discovery = ooxml_macros.OOXMLMacroDiscovery(zipper)
        return zipper, discovery.discover()

    def test_duplicate_members_keep_separate_identities(self):
        """Same-named, different members must both survive classification."""
        first = _mutate_ole(self.ole, 'A')
        second = _mutate_ole(self.ole, 'B')
        self.assertNotEqual(first, second)
        package = _build_zip([
            ('[Content_Types].xml', _content_types(
                ['<Default Extension="bin" '
                 'ContentType="application/vnd.ms-office.vbaProject"/>'])),
            ('word/_rels/document.xml.rels', _relationships(
                [(VBA_REL, 'vbaProject.bin', False)])),
            (VBAPROJECT_PART, first),
            (VBAPROJECT_PART, second),
        ])
        zipper, candidates = self._discover(package)
        conflicts = [c for c in candidates if c.category ==
                     ooxml_macros.CATEGORY_CONFLICT]
        self.assertEqual(2, len(conflicts))
        # distinct physical identities, distinct bytes, neither replaced
        self.assertEqual(2, len({c.member_index for c in conflicts}))
        self.assertEqual(2, len({c.crc for c in conflicts}))
        for candidate in conflicts:
            self.assertTrue(any('duplicate part name' in reason
                                for reason in candidate.reasons))
            # opening by name would return the last member; opening by ZipInfo
            # must always return this candidate's own bytes
            self.assertEqual(candidate.read_bytes(zipper),
                             zipper.open(candidate.zip_info).read())
        # explicit proof that name-based access is ambiguous on purpose
        self.assertEqual(zipper.read(VBAPROJECT_PART), second)
        zipper.close()

    def test_orphan_ole_member_is_adopted_separately(self):
        """An OLE member with no relationship/content type is an orphan."""
        package = _build_zip([
            ('[Content_Types].xml', _content_types()),
            ('word/stray.bin', self.ole),
        ])
        _, candidates = self._discover(package)
        orphans = [c for c in candidates
                   if c.category == ooxml_macros.CATEGORY_ORPHAN]
        self.assertEqual(1, len(orphans))
        orphan = orphans[0]
        self.assertEqual('word/stray.bin', orphan.part_name)
        self.assertFalse(orphan.referenced)
        self.assertTrue(any('orphan' in reason for reason in orphan.reasons))

    def test_explicit_reference_is_adopted(self):
        """A single referenced OLE part lands in the explicit group."""
        package = _build_zip([
            ('[Content_Types].xml', _content_types(
                ['<Default Extension="bin" '
                 'ContentType="application/vnd.ms-office.vbaProject"/>'])),
            ('word/_rels/document.xml.rels', _relationships(
                [(VBA_REL, 'vbaProject.bin', False)])),
            (VBAPROJECT_PART, self.ole),
        ])
        _, candidates = self._discover(package)
        explicit = [c for c in candidates
                    if c.category == ooxml_macros.CATEGORY_EXPLICIT]
        self.assertEqual(1, len(explicit))
        self.assertTrue(explicit[0].referenced)

    def test_contradictory_content_type_creates_conflict(self):
        """Relationship says vbaProject, content type says something else."""
        package = _build_zip([
            ('[Content_Types].xml', _content_types(overrides=[
                '<Override PartName="/word/vbaProject.bin" '
                'ContentType="application/octet-stream"/>'])),
            ('word/_rels/document.xml.rels', _relationships(
                [(VBA_REL, 'vbaProject.bin', False)])),
            (VBAPROJECT_PART, self.ole),
        ])
        _, candidates = self._discover(package)
        conflicts = [c for c in candidates
                     if c.category == ooxml_macros.CATEGORY_CONFLICT]
        self.assertEqual(1, len(conflicts))
        self.assertTrue(any('disagrees' in reason
                            for reason in conflicts[0].reasons))

    def test_referenced_non_ole_member_is_rejected(self):
        """A relationship cannot turn a non-OLE member into a macro project."""
        package = _build_zip([
            ('[Content_Types].xml', _content_types(overrides=[
                '<Override PartName="/word/vbaProject.bin" '
                'ContentType="application/vnd.ms-office.vbaProject"/>'])),
            ('word/_rels/document.xml.rels', _relationships(
                [(VBA_REL, 'vbaProject.bin', False)])),
            (VBAPROJECT_PART, b'plain text, definitely not an OLE file'),
        ])
        zipper = zipfile.ZipFile(io.BytesIO(package))
        discovery = ooxml_macros.OOXMLMacroDiscovery(zipper)
        discovery.discover()
        rejected = [c for c in discovery.rejected_candidates()
                    if c.part_name == VBAPROJECT_PART]
        self.assertEqual(1, len(rejected))
        self.assertTrue(any('OLE compound file magic' in reason
                            for reason in rejected[0].reasons))
        self.assertEqual([], discovery.adopted_candidates())
        zipper.close()

    def test_external_and_traversal_targets_are_not_resolved(self):
        """External and parent-path targets stay anomalies, never fetched."""
        package = _build_zip([
            ('[Content_Types].xml', b'<Types xmlns="%s"/>' % CT_NS.encode()),
            ('word/_rels/document.xml.rels', _relationships([
                (VBA_REL, 'http://evil.example/x.bin', True),
                (VBA_REL, '../escape.bin', False),
                (VBA_REL, 'missing.bin', False)])),
        ])
        zipper = zipfile.ZipFile(io.BytesIO(package))
        discovery = ooxml_macros.OOXMLMacroDiscovery(zipper)
        discovery.discover()
        joined = '\n'.join(discovery.anomalies)
        self.assertIn('external', joined)
        self.assertIn('invalid target', joined)
        self.assertIn('missing', joined)
        # nothing was adopted because no in-package OLE member exists
        self.assertEqual([], discovery.adopted_candidates())
        zipper.close()

    def test_name_normalisation_does_not_merge_members(self):
        """Backslash/leading-slash variants compare equal but stay distinct."""
        package = _build_zip([
            ('[Content_Types].xml', _content_types()),
            ('word/vbaProject.bin', self.ole),
            ('/word/vbaProject.bin', _mutate_ole(self.ole, 'Z')),
        ])
        _, candidates = self._discover(package)
        ole_candidates = [c for c in candidates if c.is_ole]
        self.assertEqual(2, len(ole_candidates))
        # both normalise to the same comparison key ...
        self.assertEqual(
            len({c.normalized_name for c in ole_candidates}), 1)
        # ... yet keep two physical identities
        self.assertEqual(
            len({c.member_index for c in ole_candidates}), 2)

    def test_relationship_target_is_case_insensitive(self):
        """OPC part names are case-insensitive, so an upper-case target hits."""
        package = _build_zip([
            ('[Content_Types].xml', _content_types()),
            ('word/_rels/document.xml.rels', _relationships(
                [(VBA_REL, 'VBAPROJECT.BIN', False)])),
            (VBAPROJECT_PART, self.ole),
        ])
        _, candidates = self._discover(package)
        explicit = [c for c in candidates
                    if c.category == ooxml_macros.CATEGORY_EXPLICIT]
        self.assertEqual(1, len(explicit))
        self.assertTrue(explicit[0].referenced)

    def test_relationship_resolves_relative_to_source_part(self):
        """A target in a sibling folder resolves within the package only."""
        package = _build_zip([
            ('[Content_Types].xml', _content_types()),
            ('word/_rels/document.xml.rels', _relationships(
                [(VBA_REL, 'macros/vbaProject.bin', False)])),
            ('word/macros/vbaProject.bin', self.ole),
        ])
        _, candidates = self._discover(package)
        explicit = [c for c in candidates
                    if c.category == ooxml_macros.CATEGORY_EXPLICIT]
        self.assertEqual(1, len(explicit))
        self.assertEqual('word/macros/vbaProject.bin',
                         explicit[0].part_name)


class TestVbaParserIntegration(unittest.TestCase):
    """End-to-end behaviour through the public VBA_Parser API."""

    def setUp(self):
        warnings.simplefilter('ignore')
        self.ole = _real_ole_bytes()
        self.first = _mutate_ole(self.ole, 'A')
        self.second = _mutate_ole(self.ole, 'B')
        self.orphan = self.ole

    def _adversarial_package(self):
        # No default .bin -> vbaProject content type here: the duplicate named
        # members are identified through the relationship, while backup.bin
        # remains a genuine orphan (no reference, no vbaProject content type).
        return _build_zip([
            ('[Content_Types].xml', _content_types()),
            ('_rels/.rels', _relationships([])),
            ('word/_rels/document.xml.rels', _relationships(
                [(VBA_REL, 'vbaProject.bin', False)])),
            (VBAPROJECT_PART, self.first),
            (VBAPROJECT_PART, self.second),
            ('word/embedded/backup.bin', self.orphan),
        ])

    def test_candidates_are_grouped_and_explained(self):
        parser = VBA_Parser('adversarial.docm',
                            data=self._adversarial_package())
        try:
            grouped = parser.get_ooxml_macro_candidates()
            self.assertEqual(0, len(grouped['explicit']))
            self.assertEqual(2, len(grouped['conflict']))
            self.assertEqual(1, len(grouped['orphan']))
            for candidate in grouped['conflict'] + grouped['orphan']:
                self.assertTrue(candidate.reasons)
        finally:
            parser.close()

    def test_extracted_bytes_return_to_each_member(self):
        package = self._adversarial_package()
        parser = VBA_Parser('adversarial.docm', data=package)
        try:
            grouped = parser.get_ooxml_macro_candidates()
            conflict_bytes = []
            for candidate in grouped['conflict']:
                raw = parser.read_ooxml_candidate_bytes(candidate)
                conflict_bytes.append(raw)
                # bytes must match the exact physical member represented
                self.assertEqual(raw, candidate.read_bytes(
                    zipfile.ZipFile(io.BytesIO(package))))
                self.assertIn(raw, (self.first, self.second))
            self.assertEqual(set(conflict_bytes), {self.first, self.second})
            orphan = grouped['orphan'][0]
            self.assertEqual(
                parser.read_ooxml_candidate_bytes(orphan), self.orphan)
        finally:
            parser.close()

    def test_each_physical_member_gets_its_own_subparser(self):
        parser = VBA_Parser('adversarial.docm',
                            data=self._adversarial_package())
        try:
            sub_names = {sub.filename for sub in parser.ole_subfiles}
            self.assertIn('word/vbaProject.bin#3', sub_names)
            self.assertIn('word/vbaProject.bin#4', sub_names)
            self.assertIn('word/embedded/backup.bin', sub_names)
            self.assertTrue(parser.detect_vba_macros())
            module_owners = {module[0]
                             for module in parser.extract_all_macros()}
            # macros from every adopted member are present and attributed
            self.assertTrue(
                {'word/vbaProject.bin#3',
                 'word/vbaProject.bin#4'}.issubset(module_owners))
        finally:
            parser.close()

    def test_normal_ooxml_input_unchanged(self):
        """An ordinary package still works and keeps the plain part name."""
        with open(SAMPLE_DOCM, 'rb') as handle:
            parser = VBA_Parser(SAMPLE_DOCM, data=handle.read())
        try:
            self.assertEqual('OpenXML', parser.type)
            self.assertEqual([VBAPROJECT_PART],
                             [sub.filename for sub in parser.ole_subfiles])
            grouped = parser.get_ooxml_macro_candidates()
            self.assertEqual(1, len(grouped['explicit']))
            self.assertEqual([], grouped['conflict'])
            self.assertEqual([], grouped['orphan'])
            self.assertTrue(parser.detect_vba_macros())
            self.assertGreater(len(parser.extract_all_macros()), 0)
        finally:
            parser.close()


if __name__ == '__main__':
    unittest.main()
