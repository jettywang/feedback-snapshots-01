"""
Tests for the static MS-OVBA VBA project inventory (olefile.vba).

The fixtures are minimal OLE/CFB files synthesized in memory: no macro is
ever executed, and no malicious/benign verdict is produced - only structural
evidence and explicit findings are tested.
"""

from __future__ import print_function

import io
import os
import struct
import sys
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _thismodule_dir not in sys.path:
    sys.path.insert(0, _thismodule_dir)

import olefile
from olefile import vba
from cfb_builder import build_cfb, STGTY_STORAGE, STGTY_STREAM

CODEPAGE = 1252


# --- MS-OVBA compression helpers used to build legitimate fixtures --------

def literal_container(source):
    """Compress ``source`` with literal-only tokens (no CopyTokens)."""
    out = bytearray(b'\x01')
    for chunk_start in range(0, max(len(source), 1), 4096):
        chunk = source[chunk_start:chunk_start + 4096]
        body = bytearray()
        for seq_start in range(0, max(len(chunk), 1), 8):
            seq = chunk[seq_start:seq_start + 8]
            if not seq:
                break
            body.append(0x00)  # FlagByte: every token is a literal
            body.extend(seq)
        size = len(body) + 2  # chunk includes its 2-byte header
        header = (0b011 << 12) | 0x8000 | (size - 3)
        out += struct.pack('<H', header) + bytes(body)
    return bytes(out)


def copy_overrun_container():
    """
    Build a compressed container whose CopyToken points before the start of
    the only DecompressedChunk.  At the first token the chunk output is empty,
    so any offset is out of bounds (MS-OVBA 2.4.1.3.19).
    """
    # At DecompressedCurrent - DecompressedChunkStart == 0 the bit count is
    # clamped to 4: offset occupies the high 12 bits, length the low 4 bits.
    # Offset 1 would place CopySource at -1, before the chunk start.
    token = ((1 - 1) << 4) | (3 - 3)
    flag_byte = 0x01  # first token is a CopyToken
    body = bytes([flag_byte]) + struct.pack('<H', token)
    size = len(body) + 2
    header = (0b011 << 12) | 0x8000 | (size - 3)
    return b'\x01' + struct.pack('<H', header) + body


# --- MS-OVBA dir stream record builders ------------------------------------

class DirBuilder(object):
    """Accumulates records of a decompressed dir stream."""

    def __init__(self):
        self.buf = bytearray()

    def record(self, record_id, payload):
        self.buf += struct.pack('<HI', record_id, len(payload))
        self.buf += payload
        return self

    def dword(self, record_id, value):
        return self.record(record_id, struct.pack('<I', value))

    def word(self, record_id, value):
        return self.record(record_id, struct.pack('<H', value))

    def mbcs_name(self, record_id, name, reserved, codepage=CODEPAGE):
        mbcs = name.encode('cp%d' % codepage)
        uni = name.encode('utf-16-le')
        payload = struct.pack('<I', len(mbcs)) + mbcs
        payload += struct.pack('<H', reserved)
        payload += struct.pack('<I', len(uni)) + uni
        return self.record(record_id, payload)

    def project_information(self, name='TestProject', codepage=CODEPAGE):
        self.dword(0x0001, 0x00000003)   # PROJECTSYSKIND: Win64
        self.dword(0x004A, 1)            # PROJECTCOMPATVERSION
        self.dword(0x0002, 0x00000409)   # PROJECTLCID
        self.dword(0x0014, 0x00000409)   # PROJECTLCIDINVOKE
        self.word(0x0003, codepage)      # PROJECTCODEPAGE
        self.record(0x0004, name.encode('cp%d' % codepage))  # PROJECTNAME
        self.mbcs_name(0x0005, 'doc', 0x0040)   # PROJECTDOCSTRING
        self.mbcs_name(0x0006, 'help.hlp', 0x003D)
        self.dword(0x0007, 0)            # PROJECTHELPCONTEXT
        self.dword(0x0008, 0)            # PROJECTLIBFLAGS
        # PROJECTVERSION: reserved(4) + major(4) + minor(2)
        self.record(0x0009, struct.pack('<IIH', 4, 1, 0))
        return self

    def reference_registered(self, name, libid):
        mbcs = name.encode('cp%d' % CODEPAGE)
        uni = name.encode('utf-16-le')
        name_payload = struct.pack('<I', len(mbcs)) + mbcs
        name_payload += struct.pack('<H', 0x003E)
        name_payload += struct.pack('<I', len(uni)) + uni
        self.record(0x0016, name_payload)  # REFERENCENAME
        libid_bytes = libid.encode('cp%d' % CODEPAGE)
        payload = struct.pack('<I', len(libid_bytes)) + libid_bytes
        payload += struct.pack('<IH', 0, 0)
        return self.record(0x000D, payload)  # REFERENCEREGISTERED

    def reference_project(self, name, absolute, relative):
        mbcs = name.encode('cp%d' % CODEPAGE)
        uni = name.encode('utf-16-le')
        name_payload = struct.pack('<I', len(mbcs)) + mbcs
        name_payload += struct.pack('<H', 0x003E)
        name_payload += struct.pack('<I', len(uni)) + uni
        self.record(0x0016, name_payload)
        abs_bytes = absolute.encode('cp%d' % CODEPAGE)
        rel_bytes = relative.encode('cp%d' % CODEPAGE)
        payload = struct.pack('<I', len(abs_bytes)) + abs_bytes
        payload += struct.pack('<I', len(rel_bytes)) + rel_bytes
        payload += struct.pack('<IH', 2, 5)
        return self.record(0x000E, payload)  # REFERENCEPROJECT

    def reference_control(self, name, twiddled, extended, guid_bytes,
                          cookie):
        mbcs = name.encode('cp%d' % CODEPAGE)
        uni = name.encode('utf-16-le')
        name_payload = struct.pack('<I', len(mbcs)) + mbcs
        name_payload += struct.pack('<H', 0x003E)
        name_payload += struct.pack('<I', len(uni)) + uni
        self.record(0x0016, name_payload)  # REFERENCENAME
        twiddled_bytes = twiddled.encode('cp%d' % CODEPAGE)
        extended_bytes = extended.encode('cp%d' % CODEPAGE)
        payload = b''
        # SizeTwiddled = SizeOfLibidTwiddled(4) + libid + Reserved1(4) +
        # Reserved2(2)
        payload += struct.pack('<I', 4 + len(twiddled_bytes) + 6)
        payload += struct.pack('<I', len(twiddled_bytes)) + twiddled_bytes
        payload += struct.pack('<IH', 0, 0)
        payload += struct.pack('<H', 0x0030)  # Reserved3
        # SizeExtended = size fields + libid + reserved(6) + GUID(16) +
        # cookie(4)
        size_extended = (4 + len(extended_bytes) + 6 + 16 + 4)
        payload += struct.pack('<I', size_extended)
        payload += struct.pack('<I', len(extended_bytes)) + extended_bytes
        payload += struct.pack('<IH', 0, 0)
        payload += guid_bytes
        payload += struct.pack('<I', cookie)
        return self.record(0x002F, payload)  # REFERENCECONTROL

    def module(self, name, stream_name, text_offset, module_type=0x0021,
               readonly=False, private=False, doc=''):
        name_mbcs = name.encode('cp%d' % CODEPAGE)
        self.record(0x0019, name_mbcs)               # MODULENAME
        self.record(0x0047, name.encode('utf-16-le'))  # MODULENAMEUNICODE
        self.mbcs_name(0x001A, stream_name, 0x0032)  # MODULESTREAMNAME
        self.mbcs_name(0x001C, doc, 0x0048)          # MODULEDOCSTRING
        self.dword(0x0031, text_offset)              # MODULEOFFSET
        self.dword(0x001E, 0)                        # MODULEHELPCONTEXT
        self.word(0x002C, 0xFFFF)                    # MODULECOOKIE
        self.record(module_type, struct.pack('<I', 0))  # MODULETYPE
        if readonly:
            self.record(0x0025, struct.pack('<I', 0))
        if private:
            self.record(0x0028, struct.pack('<I', 0))
        self.record(0x002B, b'')                     # MODULETERMINATOR
        self.buf += b'\x00\x00\x00\x00'              # reserved
        return self

    def modules_header(self, count, cookie=0xFFFF):
        self.word(0x000F, count)                     # PROJECTMODULES
        self.word(0x0013, cookie)                   # PROJECTCOOKIE
        return self

    def terminator(self):
        self.buf += struct.pack('<H', 0x0010)       # DIRTERMINATOR
        self.buf += b'\x00\x00\x00\x00'             # reserved
        return self

    def build(self):
        return bytes(self.buf)


def make_module_stream(source, performance_cache=b''):
    """A Module Stream is PerformanceCache + CompressedSourceCode."""
    return performance_cache + literal_container(source)


def make_vba_cfb(entries_override=None, dir_data=None, module_streams=None,
                 extra_streams=None):
    """
    Build a complete in-memory CFB containing a VBA storage.

    :param dir_data: decompressed dir bytes; compressed when stored
    :param module_streams: mapping stream name -> raw module stream bytes
    """
    entries = [{'name': 'VBA', 'type': STGTY_STORAGE}]
    compressed_dir = literal_container(dir_data)
    entries.append({'name': 'dir', 'type': STGTY_STREAM,
                    'data': compressed_dir, 'parent_index': 0})
    entries.append({'name': '_VBA_PROJECT', 'type': STGTY_STREAM,
                    'data': b'\xCC\x61' + b'\xFF\xFF' + b'\x00'
                            + b'\x00\x00', 'parent_index': 0})
    for stream_name, stream_data in (module_streams or {}).items():
        entries.append({'name': stream_name, 'type': STGTY_STREAM,
                        'data': stream_data, 'parent_index': 0})
    for stream_name, stream_data in (extra_streams or {}).items():
        entries.append({'name': stream_name, 'type': STGTY_STREAM,
                        'data': stream_data, 'parent_index': 0})
    if entries_override is not None:
        entries = entries_override
    return build_cfb(entries)


def open_inventory(cfb_bytes, limits=None):
    ole = olefile.OleFileIO(io.BytesIO(cfb_bytes))
    try:
        return vba.vba_inventory(ole, limits=limits), ole
    except Exception:
        ole.close()
        raise


# ===--------------------------------------------------------------------===
# Decompression unit tests (MS-OVBA 2.4.1)
# ===--------------------------------------------------------------------===

class TestDecompression(unittest.TestCase):

    def test_empty_container_rejected(self):
        with self.assertRaises(vba.VbaCompressionError) as context:
            vba.decompress_container(b'')
        self.assertEqual(context.exception.code,
                         vba.F_BAD_SIGNATURE)

    def test_bad_signature_rejected(self):
        with self.assertRaises(vba.VbaCompressionError) as context:
            vba.decompress_container(b'\x02\x00\x00')
        self.assertEqual(context.exception.code,
                         vba.F_BAD_SIGNATURE)

    def test_literal_round_trip(self):
        source = b'Attribute VB_Name = "Module1"\r\nSub Hello()\r\nEnd Sub\r\n'
        out = vba.decompress_container(literal_container(source))
        self.assertEqual(out, source)

    def test_raw_chunk_round_trip(self):
        source = (b'A' * 4096) + b'B'
        container = bytearray(b'\x01')
        raw_header = (0b011 << 12) | 0x0FFF  # flag 0, size 4098
        container += struct.pack('<H', raw_header) + source[:4096]
        # final literal chunk for the remaining byte
        container += literal_container(b'B')[1:]
        out = vba.decompress_container(bytes(container))
        self.assertEqual(out, source)

    def test_copy_token_round_trip(self):
        source = b'ABCABCABCABC'
        # Build a container with one CopyToken manually: after 3 literals,
        # copy length 3 offset 3 (difference==3 -> bit count 4).  A complete
        # TokenSequence carries eight token slots, so four literals pad it.
        body = bytearray()
        body.append(0b00001000)  # three literals, then one CopyToken
        body += b'ABC'
        # MS-OVBA 2.4.1.3.19: offset occupies the high BitCount (4) bits,
        # length the low 12 bits; both are stored minus 1 and 3 respectively.
        token = ((3 - 1) << 12) | (6 - 3)
        body += struct.pack('<H', token)
        body += b'XYZ\x00'  # literals for the four remaining token slots
        size = len(body) + 2
        header = (0b011 << 12) | 0x8000 | (size - 3)
        container = b'\x01' + struct.pack('<H', header) + bytes(body)
        out = vba.decompress_container(container)
        self.assertEqual(out, b'ABCABCABCXYZ\x00')

    def test_copy_out_of_bounds_is_flagged(self):
        with self.assertRaises(vba.VbaCompressionError) as context:
            vba.decompress_container(copy_overrun_container())
        self.assertEqual(context.exception.code,
                         vba.F_COPY_OUT_OF_BOUNDS)

    def test_copy_cannot_expand_chunk_beyond_4096(self):
        # At difference == 1 the length field has 12 bits, so a forged token
        # can claim up to 4098 bytes while the chunk currently holds one byte.
        # The decoder must reject that rather than emit a 4KB+ chunk.
        body = bytearray()
        body.append(0b00000011)  # literal, then CopyToken as second token
        body += b'A'
        token = ((1 - 1) << 4) | (4098 - 3)  # offset 1, length 4098
        body += struct.pack('<H', token)
        size = len(body) + 2
        header = (0b011 << 12) | 0x8000 | (size - 3)
        container = b'\x01' + struct.pack('<H', header) + bytes(body)
        with self.assertRaises(vba.VbaCompressionError) as context:
            vba.decompress_container(container)
        self.assertEqual(context.exception.code,
                         vba.F_COPY_OUT_OF_BOUNDS)

    def test_output_limit_enforced(self):
        source = b'X' * 1000
        container = literal_container(source)
        with self.assertRaises(vba.VbaCompressionError) as context:
            vba.decompress_container(container, max_output=128)
        self.assertEqual(context.exception.code, vba.F_OUTPUT_LIMIT)

    def test_truncated_chunk_flagged(self):
        good = literal_container(b'hello world')
        truncated = good[:-2]
        with self.assertRaises(vba.VbaCompressionError) as context:
            vba.decompress_container(truncated)
        self.assertIn(context.exception.code,
                      (vba.F_TRUNCATED_CHUNK, vba.F_TRUNCATED_TOKEN,
                       vba.F_BAD_CHUNK_HEADER))

    def test_bad_chunk_signature_flagged(self):
        header = (0b101 << 12) | 0x8000 | 0  # signature must be 0b011
        container = b'\x01' + struct.pack('<H', header) + b'\x00'
        with self.assertRaises(vba.VbaCompressionError) as context:
            vba.decompress_container(container)
        self.assertEqual(context.exception.code,
                         vba.F_BAD_CHUNK_HEADER)


# ===--------------------------------------------------------------------===
# End-to-end inventory tests on synthesized minimal VBA projects
# ===--------------------------------------------------------------------===

def build_normal_project():
    builder = DirBuilder()
    builder.project_information()
    builder.reference_registered('VBA',
        r'*\G{000204EF-0000-0000-C000-000000000046}#4.2#9#Win64')
    builder.reference_project('OtherProj', 'C:\\libs\\other.vba',
                              '..\\other.vba')
    source_one = b'Attribute VB_Name = "Module1"\r\nSub Main()\r\nEnd Sub\r\n'
    source_two = b'Attribute VB_Name = "ThisWorkbook"\r\n'
    cache_one = b'\xAA' * 16
    builder.modules_header(2)
    builder.module('Module1', 'Module1', text_offset=len(cache_one))
    builder.module('ThisWorkbook', 'ThisWorkbook', text_offset=0,
                   module_type=0x0022)
    builder.terminator()
    streams = {
        'Module1': make_module_stream(source_one, cache_one),
        'ThisWorkbook': make_module_stream(source_two),
    }
    return builder.build(), streams, (source_one, source_two)


class TestNormalProject(unittest.TestCase):

    def setUp(self):
        dir_data, streams, self.sources = build_normal_project()
        cfb = make_vba_cfb(dir_data=dir_data, module_streams=streams)
        self.inventory, self.ole = open_inventory(cfb)

    def tearDown(self):
        self.ole.close()

    def test_inventory_complete_and_located(self):
        self.assertTrue(self.inventory.has_vba_project)
        self.assertTrue(self.inventory.complete)
        self.assertEqual(self.inventory.vba_storage_path, ['VBA'])
        self.assertEqual(self.inventory.codepage, CODEPAGE)
        self.assertEqual(self.inventory.codepage_encoding, 'cp1252')

    def test_project_evidence(self):
        project = self.inventory.project
        self.assertEqual(project['name'], 'TestProject')
        self.assertEqual(project['syskind'], 3)
        self.assertEqual(project['declared_module_count'], 2)
        self.assertEqual(project['version_major'], 1)

    def test_modules_correlated_with_real_streams(self):
        modules = self.inventory.modules
        self.assertEqual(len(modules), 2)
        by_name = dict((module['name'], module) for module in modules)
        module_one = by_name['Module1']
        self.assertEqual(module_one['stream']['name'], 'Module1')
        self.assertEqual(module_one['stream']['source_range'],
                         [16, module_one['stream']['size']])
        self.assertEqual(
            module_one['stream']['performance_cache_range'], [0, 16])
        self.assertTrue(
            module_one['stream']['compressed_signature_ok'])
        self.assertEqual(
            module_one['stream']['decompressed_source_size'],
            len(self.sources[0]))
        self.assertTrue(
            module_one['source']['preview'].startswith(
                'Attribute VB_Name'))
        self.assertEqual(module_one['type'], 'procedural')
        self.assertEqual(by_name['ThisWorkbook']['type'],
                         'document/class/designer')

    def test_references_parsed_with_evidence(self):
        references = self.inventory.references
        self.assertEqual(len(references), 2)
        registered = references[0]
        self.assertEqual(registered['kind'], 'registered')
        self.assertEqual(registered['name'], 'VBA')
        self.assertIn('000204EF', registered['libid'])
        self.assertTrue(registered['dir_evidence'])
        project_ref = references[1]
        self.assertEqual(project_ref['kind'], 'project')
        self.assertEqual(project_ref['libid_relative'], '..\\other.vba')
        self.assertEqual(project_ref['major_version'], 2)
        self.assertEqual(project_ref['minor_version'], 5)

    def test_records_keep_dir_offsets(self):
        records = self.inventory.records
        ids = [record['id'] for record in records]
        self.assertIn(0x0003, ids)  # PROJECTCODEPAGE
        self.assertIn(0x0031, ids)  # MODULEOFFSET
        for record in records:
            self.assertGreaterEqual(record['offset'], 0)
            self.assertGreater(record['size'], 0)
        module = self.inventory.modules[0]
        offset_evidence = [evidence for evidence in module['dir_evidence']
                           if evidence['record_id'] == 0x0031]
        self.assertEqual(len(offset_evidence), 1)

    def test_no_structural_findings(self):
        self.assertEqual(self.inventory.issues, [])
        for module in self.inventory.modules:
            self.assertEqual(module['issues'], [])

    def test_to_dict_is_plain_data(self):
        import json
        data = self.inventory.to_dict()
        self.assertTrue(data['has_vba_project'])
        self.assertEqual(len(data['modules']), 2)
        self.assertEqual(data['codepage'], CODEPAGE)
        # The inventory must be directly JSON serializable and carry no raw
        # byte fields (all MBCS content is exposed as decoded text).
        encoded = json.dumps(data)
        self.assertIsInstance(encoded, str)

        def contains_bytes(obj):
            if isinstance(obj, (bytes, bytearray)):
                return True
            if isinstance(obj, dict):
                return any(contains_bytes(value) for value in obj.values())
            if isinstance(obj, list):
                return any(contains_bytes(value) for value in obj)
            return False

        self.assertFalse(contains_bytes(data))


class TestReferenceControl(unittest.TestCase):

    def test_control_reference_guid_and_libids(self):
        # GUID bytes in the mixed-endian on-disk layout of a CLSID.
        guid_bytes = struct.pack('<IHH', 0xC62A69F0, 0x16DC, 0x11CE)
        guid_bytes += bytes([0x9E, 0x98, 0x00, 0xAA, 0x00, 0x57, 0x4A, 0x4F])
        builder = DirBuilder()
        builder.project_information()
        builder.reference_control(
            'Forms',
            r'*\G{00000000-0000-0000-0000-000000000000}#0.0#0##',
            r'*\G{C62A69F0-16DC-11CE-9E98-00AA00574A4F}#2.0#0##',
            guid_bytes, cookie=0x00000001)
        builder.modules_header(0)
        builder.terminator()
        cfb = make_vba_cfb(dir_data=builder.build())
        inventory, ole = open_inventory(cfb)
        try:
            self.assertTrue(inventory.complete, inventory.issues)
            self.assertEqual(len(inventory.references), 1)
            reference = inventory.references[0]
            self.assertEqual(reference['kind'], 'control')
            self.assertEqual(reference['name'], 'Forms')
            self.assertEqual(
                reference['original_typelib'],
                '{C62A69F0-16DC-11CE-9E98-00AA00574A4F}')
            self.assertEqual(reference['cookie'], 1)
            self.assertIn('C62A69F0', reference['libid_extended'])
            self.assertTrue(reference['dir_evidence'])
        finally:
            ole.close()


class TestForgedOffset(unittest.TestCase):

    def test_text_offset_beyond_stream_is_flagged(self):
        dir_data, streams, _ = build_normal_project()
        # Rebuild dir claiming an impossible MODULEOFFSET for Module1.
        builder = DirBuilder()
        builder.project_information()
        builder.reference_registered(
            'VBA', r'*\G{000204EF-0000-0000-C000-000000000046}#4.2#9#Win64')
        builder.modules_header(1)
        real_stream = streams['Module1']
        builder.module('Module1', 'Module1',
                       text_offset=len(real_stream) + 50)
        builder.terminator()
        cfb = make_vba_cfb(dir_data=builder.build(),
                           module_streams={'Module1': real_stream})
        inventory, ole = open_inventory(cfb)
        try:
            self.assertFalse(inventory.complete)
            codes = [finding['code'] for finding in
                     inventory.findings_by_code(vba.F_OFFSET_OUT_OF_RANGE)]
            self.assertEqual(len(codes), 1)
            # The stream range evidence is still retained.
            module = inventory.modules[0]
            self.assertEqual(module['stream']['size'], len(real_stream))
            self.assertIsNone(module['stream']['source_range'])
        finally:
            ole.close()

    def test_text_offset_at_end_flags_no_source(self):
        source = b'Attribute VB_Name = "M"\r\n'
        stream = make_module_stream(source)
        builder = DirBuilder()
        builder.project_information()
        builder.modules_header(1)
        builder.module('M', 'M', text_offset=len(stream))
        builder.terminator()
        cfb = make_vba_cfb(dir_data=builder.build(),
                           module_streams={'M': stream})
        inventory, ole = open_inventory(cfb)
        try:
            self.assertFalse(inventory.complete)
            self.assertTrue(inventory.findings_by_code(
                vba.F_NO_COMPRESSED_SOURCE))
        finally:
            ole.close()


class TestMissingStream(unittest.TestCase):

    def test_declared_module_without_stream_is_flagged(self):
        builder = DirBuilder()
        builder.project_information()
        builder.modules_header(1)
        builder.module('Ghost', 'Ghost', text_offset=0)
        builder.terminator()
        cfb = make_vba_cfb(dir_data=builder.build(), module_streams={})
        inventory, ole = open_inventory(cfb)
        try:
            self.assertFalse(inventory.complete)
            missing = inventory.findings_by_code(
                vba.F_MODULE_STREAM_MISSING)
            self.assertEqual(len(missing), 1)
            self.assertIn('Ghost', missing[0]['message'])
            # Directory evidence remains even though the stream is absent.
            module = inventory.modules[0]
            self.assertIsNone(module['stream'])
            self.assertTrue(module['dir_evidence'])
            self.assertEqual(module['name'], 'Ghost')
        finally:
            ole.close()

    def test_duplicate_module_mapping_is_flagged(self):
        source = b'Attribute VB_Name = "M"\r\n'
        stream = make_module_stream(source)
        builder = DirBuilder()
        builder.project_information()
        builder.modules_header(2)
        builder.module('First', 'Shared', text_offset=0)
        builder.module('Second', 'Shared', text_offset=0)
        builder.terminator()
        cfb = make_vba_cfb(
            dir_data=builder.build(),
            module_streams={'Shared': stream})
        inventory, ole = open_inventory(cfb)
        try:
            self.assertFalse(inventory.complete)
            dupes = inventory.findings_by_code(
                vba.F_DUPLICATE_STREAM_MAPPING)
            self.assertEqual(len(dupes), 1)
            self.assertIn('Shared', dupes[0]['message'])
        finally:
            ole.close()


class TestCompressionCorruption(unittest.TestCase):

    def test_module_copy_overrun_is_flagged_not_raised(self):
        # The dir stream itself is legitimate; one module stream carries a
        # forged CompressedSourceCode with an out-of-bounds CopyToken.
        builder = DirBuilder()
        builder.project_information()
        builder.modules_header(1)
        builder.module('Evil', 'Evil', text_offset=4)
        builder.terminator()
        evil_stream = b'\x00' * 4 + copy_overrun_container()
        cfb = make_vba_cfb(
            dir_data=builder.build(),
            module_streams={'Evil': evil_stream})
        inventory, ole = open_inventory(cfb)
        try:
            self.assertFalse(inventory.complete)
            findings = inventory.findings_by_code(
                vba.F_MODULE_COMPRESSION)
            self.assertEqual(len(findings), 1)
            module = inventory.modules[0]
            # Evidence of the intended source range is retained.
            self.assertEqual(module['stream']['source_range'],
                             [4, len(evil_stream)])
            self.assertTrue(module['stream']['compressed_signature_ok'])
            self.assertIsNone(
                module['stream']['decompressed_source_size'])
        finally:
            ole.close()

    def test_dir_compression_failure_is_reported(self):
        entries = [
            {'name': 'VBA', 'type': STGTY_STORAGE},
            {'name': 'dir', 'type': STGTY_STREAM,
             'data': b'\x02not a valid container', 'parent_index': 0},
        ]
        cfb = build_cfb(entries)
        inventory, ole = open_inventory(cfb)
        try:
            self.assertTrue(inventory.has_vba_project)
            self.assertFalse(inventory.complete)
            self.assertTrue(inventory.findings_by_code(
                vba.F_DIR_COMPRESSION))
        finally:
            ole.close()


class TestUnknownAndLimits(unittest.TestCase):

    def test_unknown_record_marks_incomplete(self):
        builder = DirBuilder()
        builder.project_information()
        # Inject a record id that MS-OVBA does not define in this position.
        builder.record(0x0777, b'unknown-bytes')
        builder.modules_header(0)
        builder.terminator()
        cfb = make_vba_cfb(dir_data=builder.build())
        inventory, ole = open_inventory(cfb)
        try:
            self.assertFalse(inventory.complete)
            unknowns = inventory.findings_by_code(vba.F_UNKNOWN_RECORD)
            self.assertTrue(unknowns)
            # The unknown record itself is retained with its byte range but
            # must not be silently interpreted.
            raw_record = [record for record in inventory.records
                          if record['id'] == 0x0777]
            self.assertEqual(len(raw_record), 1)
            self.assertIsNone(raw_record[0]['name'])
        finally:
            ole.close()

    def test_module_record_limit(self):
        builder = DirBuilder()
        builder.project_information()
        builder.modules_header(2)
        builder.module('M1', 'M1', text_offset=0)
        builder.module('M2', 'M2', text_offset=0)
        builder.terminator()
        source = b'Attribute VB_Name = "M"\r\n'
        cfb = make_vba_cfb(
            dir_data=builder.build(),
            module_streams={'M1': make_module_stream(source),
                            'M2': make_module_stream(source)})
        inventory, ole = open_inventory(cfb, limits={'max_modules': 1})
        try:
            self.assertFalse(inventory.complete)
            self.assertTrue(inventory.findings_by_code(
                vba.F_MODULE_LIMIT))
            self.assertEqual(len(inventory.modules), 1)
        finally:
            ole.close()

    def test_record_limit_stops_parsing(self):
        builder = DirBuilder()
        builder.project_information()
        builder.modules_header(0)
        builder.terminator()
        inventory = None
        cfb = make_vba_cfb(dir_data=builder.build())
        inventory, ole = open_inventory(cfb, limits={'max_records': 2})
        try:
            self.assertFalse(inventory.complete)
            self.assertTrue(inventory.findings_by_code(
                vba.F_RECORD_LIMIT))
        finally:
            ole.close()

    def test_decompression_output_limit_on_dir(self):
        builder = DirBuilder()
        builder.project_information()
        builder.modules_header(0)
        builder.terminator()
        cfb = make_vba_cfb(dir_data=builder.build())
        inventory, ole = open_inventory(
            cfb, limits={'max_decompressed': 8})
        try:
            self.assertFalse(inventory.complete)
            self.assertTrue(inventory.findings_by_code(
                vba.F_DIR_COMPRESSION))
        finally:
            ole.close()


class TestStorageLayout(unittest.TestCase):

    def test_file_without_vba_storage(self):
        entries = [
            {'name': 'WordDocument', 'type': STGTY_STREAM,
             'data': b'x' * 100},
        ]
        cfb = build_cfb(entries)
        inventory, ole = open_inventory(cfb)
        try:
            self.assertFalse(inventory.has_vba_project)
            self.assertTrue(inventory.complete)
            self.assertEqual(inventory.modules, [])
        finally:
            ole.close()

    def test_vba_storage_without_dir_stream(self):
        entries = [
            {'name': 'VBA', 'type': STGTY_STORAGE},
            {'name': 'Module1', 'type': STGTY_STREAM,
             'data': b'y' * 50, 'parent_index': 0},
        ]
        cfb = build_cfb(entries)
        inventory, ole = open_inventory(cfb)
        try:
            self.assertTrue(inventory.has_vba_project)
            self.assertFalse(inventory.complete)
            self.assertTrue(inventory.findings_by_code(
                vba.F_NO_DIR_STREAM))
        finally:
            ole.close()

    def test_orphan_stream_is_reported(self):
        builder = DirBuilder()
        builder.project_information()
        builder.modules_header(1)
        builder.module('Module1', 'Module1', text_offset=0)
        builder.terminator()
        source = b'Attribute VB_Name = "Module1"\r\n'
        cfb = make_vba_cfb(
            dir_data=builder.build(),
            module_streams={'Module1': make_module_stream(source)},
            extra_streams={'SuspiciousExtra': b'data'})
        inventory, ole = open_inventory(cfb)
        try:
            orphans = inventory.findings_by_code(vba.F_ORPHAN_STREAM)
            self.assertEqual(len(orphans), 1)
            self.assertIn('SuspiciousExtra', orphans[0]['message'])
            self.assertEqual(orphans[0]['severity'], vba.SEVERITY_INFO)
        finally:
            ole.close()


class TestNoVerdictBehavior(unittest.TestCase):

    def test_inventory_has_no_malicious_attribute(self):
        # The inventory exposes structural data only; there must be no API
        # surface that turns names or source strings into a malware verdict.
        dir_data, streams, _ = build_normal_project()
        cfb = make_vba_cfb(dir_data=dir_data, module_streams=streams)
        inventory, ole = open_inventory(cfb)
        try:
            data = inventory.to_dict()
            self.assertNotIn('malicious', data)
            self.assertNotIn('is_malware', data)
            for module in data['modules']:
                self.assertNotIn('malicious', module)
        finally:
            ole.close()


if __name__ == '__main__':
    unittest.main()
