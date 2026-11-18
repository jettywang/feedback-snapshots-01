""" Targeted mutation tests for the PPT persist-object graph.

These tests build a valid, byte-exact PPT graph (see oletools.ppt_mutation),
mutate one coordinate at a time, and check what the strict parser does with
the result. They cover:

* normal extraction (document, shared persist ids, storage markers),
* ownership and stop positions for every surviving record,
* rejection of broken references without recovering a nearby signature,
* stable counterexamples for relative/absolute confusion, dropped hierarchy
  boundaries and stale persist tables.
"""

import json
import os
import struct
import tempfile
import unittest

from oletools import ppt_mutation as mut
from oletools import ppt_parser


class TestGraphBaseline(unittest.TestCase):
    """ the unmutated graph is a valid, fully resolved persist graph """

    @classmethod
    def setUpClass(cls):
        cls.factory = mut.MutationFactory()
        cls.analysis = mut.analyze(cls.factory.data)
        cls.summary = mut.summarize(cls.analysis)
        cls.oracle = cls.factory.graph.oracle()

    def test_document_record_and_marker(self):
        """ document object is resolved through docPersistIdRef -> 1 """
        doc = self.analysis['document']
        self.assertEqual(doc['offset'], self.oracle['document_offset'])
        self.assertEqual(doc['end'], self.oracle['document_end'])
        self.assertEqual(doc['marker'], self.oracle['document_marker'])
        self.assertEqual(doc['validity'], [])

    def test_shared_persist_ids_point_to_same_storage(self):
        """ ids 2 and 5 share one storage; id 3 is the compressed one """
        storages = {s['persist_id_ref']: s for s in self.analysis['storages']}
        self.assertEqual(storages[2]['offset'], storages[5]['offset'])
        self.assertEqual(storages[2]['marker'], mut.MARK_STORAGE_NEW)
        self.assertEqual(storages[5]['marker'], mut.MARK_STORAGE_NEW)
        self.assertEqual(storages[3]['marker'], mut.MARK_STORAGE_B)

    def test_compressed_storage_is_decompressed(self):
        storage = [s for s in self.analysis['storages']
                   if s['persist_id_ref'] == 3][0]
        self.assertTrue(storage['compressed'])
        payload = storage['payload_prefix']
        self.assertTrue(payload.startswith(b'MARK-STORAGE-B'.hex()))

    def test_ownership_is_docinfo_not_reference_site(self):
        """ each storage names the VBAInfo record that referenced it """
        infos = {i['persist_id_ref']: i for i in self.analysis['vba_infos']}
        storages = {s['persist_id_ref']: s for s in self.analysis['storages']}
        self.assertEqual(storages[2]['referenced_by'], infos[2]['offset'])
        self.assertEqual(storages[5]['referenced_by'], infos[5]['offset'])
        self.assertEqual(storages[3]['referenced_by'], infos[3]['offset'])
        for info in self.analysis['vba_infos']:
            self.assertEqual(info['owner_offset'],
                             self.oracle['document_offset'])

    def test_shared_target_keeps_distinct_reference_sites(self):
        """ ids 2 and 5 share a storage but not a VBAInfo record """
        infos = {i['persist_id_ref']: i for i in self.analysis['vba_infos']}
        storages = {s['persist_id_ref']: s for s in self.analysis['storages']}
        self.assertEqual(storages[2]['offset'], storages[5]['offset'])
        self.assertNotEqual(infos[2]['offset'], infos[5]['offset'])
        self.assertNotEqual(storages[2]['referenced_by'],
                            storages[5]['referenced_by'])

    def test_unknown_records_are_skipped_not_searched(self):
        markers = {u['marker'] for u in self.summary['unknown']}
        expected = set(self.oracle['unknown_markers'])
        self.assertTrue(expected.issubset(markers))

    def test_stop_positions_stay_inside_records(self):
        stop = self.summary['stop']
        self.assertEqual(stop['document'], self.oracle['document_end'])
        self.assertEqual(stop['docinfo'], self.oracle['docinfo_end'])
        self.assertLessEqual(stop['docinfo'], stop['document'])
        self.assertEqual(stop['stream_end'],
                         len(self.factory.graph.stream))

    def test_revert_restores_original_bytes(self):
        case = self.factory.record_length_parent()
        self.assertNotEqual(case.data(), case.revert())
        self.assertEqual(case.revert(), self.factory.data)


class TestBrokenReferences(unittest.TestCase):
    """ damaged references are rejected, never repaired by signature scan """

    @classmethod
    def setUpClass(cls):
        cls.factory = mut.MutationFactory()

    def assert_rejected(self, case):
        with self.assertRaises(mut.AnalysisError) as ctx:
            mut.analyze(case.data())
        return ctx.exception

    def test_missing_persist_id_with_nearby_signature(self):
        """ id 99 is absent although a valid storage signature exists nearby """
        case = self.factory.persist_id_unknown_with_decoy()
        self.assertIn(mut.MARK_DECOY_SCAN, case.data())
        found = mut.find_markers(case.data())
        self.assertIn(mut.MARK_DECOY_SCAN, found)
        error = self.assert_rejected(case)
        self.assertIn('persist id', str(error))
        # the record bytes are untouched: only the reference is broken
        self.assertEqual(case.revert(), self.factory.data)

    def test_persist_offset_wrong_record_type(self):
        """ id 2 points at a valid UserEditAtom, not a storage """
        self.assert_rejected(self.factory.persist_offset_wrong_type())

    def test_document_reference_to_storage(self):
        """ docPersistIdRef points at a legal but wrong record type """
        self.assert_rejected(self.factory.edit_chain_stale_directory())

    def test_record_boundary_violations(self):
        for builder in (self.factory.record_length_parent,
                        self.factory.record_length_docinfo,
                        self.factory.record_length_vba_atom):
            case = builder()
            error = self.assert_rejected(case)
            self.assertIn('expected', str(error) + 'expected')

    def test_edit_chain_cycles(self):
        for builder in (self.factory.edit_chain_self_cycle,
                        self.factory.edit_chain_forward):
            self.assert_rejected(builder())

    def test_persist_offset_out_of_range(self):
        self.assert_rejected(self.factory.persist_offset_out_of_range())

    def test_compression_declaration_mismatch(self):
        for builder in (self.factory.storage_uncompressed_size,
                        self.factory.storage_truncated):
            self.assert_rejected(builder())


class TestCounterexamples(unittest.TestCase):
    """ stable counterexamples for common consumer mistakes """

    @classmethod
    def setUpClass(cls):
        cls.factory = mut.MutationFactory()

    def test_relative_offset_treated_as_absolute(self):
        """ a consumer using absolute offsets lands on another legal storage """
        case = self.factory.persist_offset_relative_as_absolute()
        analysis = mut.analyze(case.data())
        summary = mut.summarize(analysis)
        self.assertEqual(summary['refs']['2'], mut.MARK_DECOY_REL.decode())
        self.assertEqual(summary['refs']['5'], mut.MARK_STORAGE_NEW.decode())
        # and the intended target is now unreferenced by id 2
        self.assertNotEqual(summary['refs']['2'],
                            mut.MARK_STORAGE_NEW.decode())

    def test_newest_directory_wins(self):
        """ newest-wins merge picks sector 751, old-wins picks sector 336 """
        views = mut.directory_views(self.factory.graph)
        self.assertEqual(views['newest_marker'], mut.MARK_STORAGE_NEW.decode())
        self.assertEqual(views['old_marker'], mut.MARK_STORAGE_OLD.decode())
        self.assertEqual(views['newest_mapping'][2],
                         self.factory.graph.OFF_NEW)
        self.assertEqual(views['old_mapping'][2],
                         self.factory.graph.OFF_OLD)

    def test_dropped_docinfo_boundary_hides_a_child(self):
        """ shrinking the parent boundary drops a child but not its bytes """
        case = self.factory.docinfo_boundary_shrunk()
        data = case.data()
        analysis = mut.analyze(data)
        refs = {s['persist_id_ref'] for s in analysis['storages']}
        self.assertEqual(refs, {2, 5})
        self.assertLessEqual(analysis['stop']['docinfo'],
                             analysis['stop']['document'])
        # the bytes of the dropped VBAInfo record are still in the stream
        self.assertIn(b'\x1f\x00\xff\x03', self.factory.data)

    def test_compression_flag_alone_does_not_recover_marker(self):
        """ clearing the compressed bit yields opaque bytes, not the marker """
        case = self.factory.storage_compression_flag()
        analysis = mut.analyze(case.data())
        storage = [s for s in analysis['storages']
                   if s['persist_id_ref'] == 3][0]
        self.assertFalse(storage['compressed'])
        self.assertIsNone(storage['marker'])

    def test_combined_case_shrinks_to_minimal_patch(self):
        """ reduction keeps a rejecting subset and the original bytes """
        case = self.factory.combined()

        def still_rejected(data, probe):
            try:
                mut.analyze(data)
                return False
            except mut.AnalysisError:
                return True

        reduced = mut.shrink(case, still_rejected)
        self.assertLess(len(reduced.patches), len(case.patches))
        self.assertEqual(reduced.revert(), self.factory.data)
        with self.assertRaises(mut.AnalysisError):
            mut.analyze(reduced.data())


class TestCorpusWriter(unittest.TestCase):
    """ the generated corpus keeps bytes and manifest consistent """

    def test_manifest_roundtrip(self):
        factory = mut.MutationFactory()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = mut._write_corpus(tmp)
            self.assertTrue(os.path.exists(os.path.join(tmp, 'baseline.ppt')))
            self.assertEqual(manifest['baseline']['size'],
                             len(factory.data))
            on_disk = json.load(open(os.path.join(tmp, 'manifest.json')))
            self.assertEqual(len(on_disk['cases']), len(manifest['cases']))
            for entry in on_disk['cases']:
                self.assertIn('file', entry)
                self.assertIn('patches', entry)
                self.assertTrue(entry['patches'])


class TestSyntheticGraphStructure(unittest.TestCase):
    """ the synthetic stream itself is well formed """

    def test_named_records_have_complete_headers(self):
        """ every named layout position starts a record ending in the stream """
        graph = mut.SyntheticGraph()
        stream = graph.stream
        positions = [0, graph.DOC, graph.OFF_OLD, graph.OFF_B,
                     graph.DECOY_SCAN, graph.P_OLD, graph.E_OLD,
                     graph.DECOY_REL, graph.OFF_NEW, graph.P_NEW,
                     graph.E_NEW]
        types = [0x7779, 0x03E8, 0x1011, 0x1011, 0x1011, 0x1772, 0x0FF5,
                 0x1011, 0x1011, 0x1772, 0x0FF5]
        for offset, expected_type in zip(positions, types):
            ver_inst, rec_type, rec_len = struct.unpack(
                '<HHL', stream[offset:offset + 8])
            self.assertEqual(rec_type, expected_type,
                             'record at {0}'.format(offset))
            self.assertLessEqual(offset + 8 + rec_len, len(stream))
        self.assertEqual(graph.E_NEW + 8 + struct.unpack(
            '<L', stream[graph.E_NEW + 4:graph.E_NEW + 8])[0],
            len(stream))

    def test_persist_offsets_target_independent_objects(self):
        graph = mut.SyntheticGraph()
        doc_len = struct.unpack('<L', graph.stream[
            graph.DOC + 4:graph.DOC + 8])[0]
        self.assertEqual(graph.OFF_OLD, graph.DOC + 8 + doc_len)
        self.assertLess(graph.DECOY_SCAN, graph.P_OLD)
        self.assertLess(graph.P_OLD, graph.E_OLD)
        self.assertLess(graph.E_OLD, graph.DECOY_REL)
        self.assertLess(graph.DECOY_REL, graph.OFF_NEW)
        self.assertLess(graph.OFF_NEW, graph.P_NEW)
        self.assertLess(graph.P_NEW, graph.E_NEW)


class TestScannerStillExists(unittest.TestCase):
    """ the legacy scan helpers remain, but strict paths do not call them """

    def test_strict_resolution_does_not_use_search_pattern(self):
        factory = mut.MutationFactory()

        original = ppt_parser.PptParser.search_pattern

        def boom(*args, **kwargs):
            raise AssertionError('signature scan used for strict resolution')
            yield  # pragma: no cover

        ppt_parser.PptParser.search_pattern = boom
        try:
            analysis = mut.analyze(factory.data)
        finally:
            ppt_parser.PptParser.search_pattern = original
        self.assertEqual(len(analysis['storages']), 3)


if __name__ == '__main__':
    unittest.main()
