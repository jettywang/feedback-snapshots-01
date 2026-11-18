# -*- coding: utf-8 -*-
"""
Tests for the resolution of VBA module names to actual OLE streams.

These tests build minimal in-memory VBA projects (dir stream + PROJECT
stream + module streams) to check that the source code of each module is
attributed to the right OLE stream, even when:
- module/stream names are non-ASCII (project code page matters),
- two name records decode to similar text (replacement characters must not
  merge distinct modules),
- the ANSI and Unicode MODULESTREAMNAME records contradict each other,
- two real streams differ only by case (ambiguous match).
"""

import struct
import unittest
from io import BytesIO

from oletools.olevba import (VBA_Project, _decode_name_record,
                             _match_stream_name)

# cp1252 bytes that are undefined and therefore decode with replacement chars:
UNDEFINED_CP1252 = (b'\x81', b'\x8d', b'\x8f', b'\x90', b'\x9d')


def compress_container(data):
    """
    Build a MS-OVBA 2.4.1.1.1 CompressedContainer using literal tokens only.
    """
    out = bytearray(b'\x01')  # signature byte
    for start in range(0, len(data), 4096):
        chunk = data[start:start + 4096]
        body = bytearray()
        for pos in range(0, len(chunk), 8):
            body.append(0x00)  # FlagByte: 8 literal tokens follow
            body.extend(chunk[pos:pos + 8])
        # CompressedChunkHeader: size = chunk size - 3, signature 0b011,
        # flag 1 (compressed):
        header = (len(body) - 1) | 0x3000 | 0x8000
        out += struct.pack('<H', header)
        out += body
    return bytes(out)


def _rec(record_id, payload):
    """dir stream record: Id (2 bytes) + Size (4 bytes) + payload."""
    return struct.pack('<HL', record_id, len(payload)) + payload


def build_dir_stream(codepage, modules, project_name=b'TestProject'):
    """
    Build the (uncompressed) dir stream for a small VBA project.

    :param codepage: project code page (PROJECTCODEPAGE record)
    :param modules: list of dicts with keys:
        name (bytes, code page encoded), name_unicode (bytes UTF-16LE, opt.),
        stream (bytes, opt.), stream_unicode (bytes, required if stream),
        offset (int, opt.), type (0x21/0x22, opt.)
    """
    out = bytearray()
    out += _rec(0x0001, struct.pack('<L', 1))          # PROJECTSYSKIND
    out += _rec(0x0002, struct.pack('<L', 0x409))      # PROJECTLCID
    out += _rec(0x0014, struct.pack('<L', 0x409))      # PROJECTLCIDINVOKE
    out += _rec(0x0003, struct.pack('<H', codepage))   # PROJECTCODEPAGE
    out += _rec(0x0004, project_name)                  # PROJECTNAME
    out += struct.pack('<HLHL', 0x0005, 0, 0x0040, 0)  # PROJECTDOCSTRING
    out += struct.pack('<HLHL', 0x0006, 0, 0x003D, 0)  # PROJECTHELPFILEPATH
    out += _rec(0x0007, struct.pack('<L', 0))          # PROJECTHELPCONTEXT
    out += _rec(0x0008, struct.pack('<L', 0))          # PROJECTLIBFLAGS
    out += struct.pack('<HLLH', 0x0009, 4, 1, 0)       # PROJECTVERSION
    out += struct.pack('<HLHL', 0x000C, 0, 0x003C, 0)  # PROJECTCONSTANTS
    out += _rec(0x000F, struct.pack('<H', len(modules)))  # PROJECTMODULES
    out += _rec(0x0013, struct.pack('<H', 0))          # ProjectCookieRecord
    for mod in modules:
        out += _rec(0x0019, mod['name'])               # MODULENAME
        if mod.get('name_unicode') is not None:
            out += _rec(0x0047, mod['name_unicode'])   # MODULENAMEUNICODE
        if mod.get('stream') is not None:
            out += _rec(0x001A, mod['stream'])         # MODULESTREAMNAME
            out += struct.pack('<HL', 0x0032, len(mod['stream_unicode']))
            out += mod['stream_unicode']
        out += _rec(0x0031, struct.pack('<L', mod.get('offset', 0)))
        out += struct.pack('<HL', mod.get('type', 0x0021), 0)  # MODULETYPE
        out += struct.pack('<HL', 0x002B, 0)           # TERMINATOR
    return bytes(out)


def build_project_stream(names, codec):
    """Build a PROJECT stream declaring the given module names."""
    lines = ['ID="{00000000-0000-0000-0000-000000000000}"']
    lines += ['Module=' + name for name in names]
    return ('\r\n'.join(lines) + '\r\n').encode(codec)


class FakeOle(object):
    """
    Minimal emulation of olefile.OleFileIO for VBA_Project: case-insensitive
    stream lookup (like olefile.OleFileIO._find) and listdir.
    """

    def __init__(self, streams):
        # streams: dict mapping tuple of path components -> bytes
        self._streams = dict(streams)

    def listdir(self, streams=True, storages=False):
        return [list(path) for path in self._streams]

    def openstream(self, path):
        if isinstance(path, str):
            path = path.split('/')
        lowered = [part.lower() for part in path]
        for stored_path, data in self._streams.items():
            if [part.lower() for part in stored_path] == lowered:
                return BytesIO(data)
        raise IOError('file not found: %r' % (path,))

    def exists(self, path):
        try:
            self.openstream(path)
            return True
        except IOError:
            return False


def make_module_record(name, codec, stream_name=None, stream_ansi=None,
                       stream_uni=None, name_unicode=None):
    """
    Build a module record description for build_dir_stream.

    :param name: module name (str)
    :param codec: project code page codec
    :param stream_name: if given and stream_ansi/stream_uni are not, both
        MODULESTREAMNAME records are built consistently from it
    :param stream_ansi: raw bytes for the ANSI MODULESTREAMNAME (or None to
        omit the whole MODULESTREAMNAME record)
    :param stream_uni: raw bytes for the Unicode MODULESTREAMNAME
    """
    record = {'name': name.encode(codec)}
    if name_unicode is not False:
        record['name_unicode'] = (name_unicode if name_unicode is not None
                                  else name).encode('utf-16le')
    if stream_name is not None:
        record['stream'] = stream_name.encode(codec)
        record['stream_unicode'] = stream_name.encode('utf-16le')
    if stream_ansi is not None:
        record['stream'] = stream_ansi
        record['stream_unicode'] = stream_uni
    return record


def run_project(modules, module_streams, codepage=1252, codec='cp1252',
                project_names=None, vba_root='Macros/'):
    """
    Run VBA_Project parsing on a synthetic project.

    :param modules: module record descriptions (see make_module_record)
    :param module_streams: dict stream name (str) -> source code (bytes,
        code page encoded); streams are created under <vba_root>VBA/
    :return: (VBA_Project, list of yielded (code_path, filename, code))
    """
    if project_names is None:
        project_names = [mod['name'].decode(codec) for mod in modules]
    prefix = tuple(part for part in vba_root.split('/') if part)
    streams = {prefix + ('VBA', 'dir'): compress_container(
                   build_dir_stream(codepage, modules)),
               prefix + ('PROJECT',): build_project_stream(project_names,
                                                           codec)}
    for stream_name, source in module_streams.items():
        streams[prefix + ('VBA', stream_name)] = compress_container(source)
    ole = FakeOle(streams)
    project = VBA_Project(ole, vba_root, vba_root + 'PROJECT',
                          vba_root + 'VBA/dir', relaxed=True)
    project.parse_project_stream()
    results = list(project.parse_modules())
    return project, results


class TestDecodeNameRecord(unittest.TestCase):
    """Unit tests for _decode_name_record."""

    def test_strict_decode(self):
        text, lossy = _decode_name_record('Módulo'.encode('cp1252'), 'cp1252')
        self.assertEqual(text, 'Módulo')
        self.assertFalse(lossy)

    def test_lossy_decode_flagged(self):
        for bad_byte in UNDEFINED_CP1252:
            text, lossy = _decode_name_record(b'M' + bad_byte + b'dulo',
                                              'cp1252')
            self.assertTrue(lossy)
            self.assertIn('�', text)

    def test_distinct_bytes_collapse_to_same_lossy_text(self):
        # this is why lossy names must never identify a stream:
        text1, _ = _decode_name_record(b'M\x81dulo', 'cp1252')
        text2, _ = _decode_name_record(b'M\x8ddulo', 'cp1252')
        self.assertEqual(text1, text2)

    def test_none(self):
        self.assertEqual(_decode_name_record(None, 'cp1252'), (None, False))


class TestMatchStreamName(unittest.TestCase):
    """Unit tests for _match_stream_name."""

    def test_exact_match(self):
        self.assertEqual(_match_stream_name('Mod', ['mod', 'Mod', 'MOD']),
                         ('Mod', []))

    def test_case_insensitive_unique(self):
        self.assertEqual(_match_stream_name('module1', ['Module1']),
                         ('Module1', []))

    def test_case_insensitive_ambiguous(self):
        match, ambiguous = _match_stream_name('module1', ['Module1', 'MODULE1'])
        self.assertIsNone(match)
        self.assertEqual(ambiguous, ['Module1', 'MODULE1'])

    def test_no_match(self):
        self.assertEqual(_match_stream_name('Nope', ['Module1']), (None, []))


class TestModuleStreamResolution(unittest.TestCase):
    """Integration tests: module records resolved against actual streams."""

    def test_legit_project_extracted_unchanged(self):
        """A normal, consistent project extracts exactly as before."""
        source1 = b'Sub One()\r\nEnd Sub\r\n'
        source2 = b'Sub Two()\r\nEnd Sub\r\n'
        modules = [make_module_record('Module1', 'cp1252',
                                      stream_name='Module1'),
                   make_module_record('Module2', 'cp1252',
                                      stream_name='Module2')]
        project, results = run_project(
            modules, {'Module1': source1, 'Module2': source2})
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][0], 'Macros/VBA/Module1')
        self.assertEqual(results[0][1], 'Module1.bas')
        self.assertEqual(results[0][2], source1.decode('cp1252'))
        self.assertEqual(results[1][2], source2.decode('cp1252'))
        for module in project.modules:
            self.assertEqual(module.stream_name_issues, [])

    def test_non_ascii_name_cp1252(self):
        """Non-ASCII names decoded with the project code page work."""
        source = 'Sub Test()\r\n\' accentué\r\nEnd Sub\r\n'.encode('cp1252')
        modules = [make_module_record('Módulo', 'cp1252',
                                      stream_name='Módulo')]
        project, results = run_project(modules, {'Módulo': source})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'Macros/VBA/Módulo')
        self.assertEqual(results[0][1], 'Módulo.bas')
        self.assertEqual(results[0][2], source.decode('cp1252'))
        self.assertEqual(project.modules[0].stream_name_issues, [])

    def test_non_ascii_name_cp1251(self):
        """The project code page (here Cyrillic 1251) drives decoding."""
        source = 'Sub Test()\r\n\' Привет\r\nEnd Sub\r\n'.encode('cp1251')
        modules = [make_module_record('Модуль', 'cp1251',
                                      stream_name='Модуль')]
        project, results = run_project(modules, {'Модуль': source},
                                       codepage=1251, codec='cp1251')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'Macros/VBA/Модуль')
        self.assertEqual(results[0][2], source.decode('cp1251'))
        self.assertEqual(project.codepage, 1251)

    def test_lossy_ansi_names_do_not_merge_modules(self):
        """
        Two ANSI stream names that are both undecodable in the project code
        page collapse to the same text with replacement characters; they must
        not be merged nor matched to any stream. The UTF-16 records (which do
        not depend on the code page) still give the correct attribution.
        """
        source_a = b'Sub A()\r\nEnd Sub\r\n'
        source_b = b'Sub B()\r\nEnd Sub\r\n'
        modules = [
            make_module_record('ModuloA', 'cp1252',
                               stream_ansi=b'M\x81dulo',
                               stream_uni='ModuloA'.encode('utf-16le')),
            make_module_record('ModuloB', 'cp1252',
                               stream_ansi=b'M\x8ddulo',
                               stream_uni='ModuloB'.encode('utf-16le')),
        ]
        project, results = run_project(
            modules, {'ModuloA': source_a, 'ModuloB': source_b})
        # both modules extracted from their own stream:
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][0], 'Macros/VBA/ModuloA')
        self.assertEqual(results[0][2], source_a.decode('cp1252'))
        self.assertEqual(results[1][0], 'Macros/VBA/ModuloB')
        self.assertEqual(results[1][2], source_b.decode('cp1252'))
        # evidence: both ANSI records were lossy, raw bytes preserved:
        mod_a, mod_b = project.modules
        self.assertTrue(mod_a.streamname_lossy)
        self.assertTrue(mod_b.streamname_lossy)
        self.assertEqual(mod_a.streamname_raw, b'M\x81dulo')
        self.assertEqual(mod_b.streamname_raw, b'M\x8ddulo')
        self.assertTrue(any('replacement' in issue
                            for issue in mod_a.stream_name_issues))
        self.assertTrue(any('replacement' in issue
                            for issue in mod_b.stream_name_issues))

    def test_contradictory_records_are_unconfirmable(self):
        """
        Module A's ANSI stream name points to module B's stream while its
        Unicode record points to A's own stream: the attribution cannot be
        confirmed, so no source code may be picked for A (and B's source must
        stay with B only).
        """
        source_a = b'Sub A()\r\nEnd Sub\r\n'
        source_b = 'Sub B()\r\n\' Módulo B\r\nEnd Sub\r\n'.encode('cp1252')
        modules = [
            make_module_record('ModuloA', 'cp1252',
                               stream_ansi='Módulo'.encode('cp1252'),
                               stream_uni='ModuloA'.encode('utf-16le')),
            make_module_record('Módulo', 'cp1252', stream_name='Módulo'),
        ]
        project, results = run_project(
            modules, {'Módulo': source_b, 'ModuloA': source_a})
        # only module B (index 1) is extracted, with its own source:
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'Macros/VBA/Módulo')
        self.assertEqual(results[0][2], source_b.decode('cp1252'))
        # module A is unconfirmable, with explicit evidence:
        mod_a = project.modules[0]
        self.assertIsNone(mod_a.code)
        self.assertIsNone(mod_a.code_path)
        self.assertTrue(any('contradict' in issue
                            for issue in mod_a.stream_name_issues))
        # raw bytes of both conflicting records are preserved as evidence:
        self.assertEqual(mod_a.streamname_raw, 'Módulo'.encode('cp1252'))
        self.assertEqual(mod_a._streamname_unicode_raw,
                         'ModuloA'.encode('utf-16le'))

    def test_case_only_streams_are_ambiguous(self):
        """
        Two real streams differing only by case cannot be told apart by a
        case-insensitive lookup: the attribution is unconfirmable instead of
        silently opening the first one.
        """
        modules = [make_module_record('module1', 'cp1252',
                                      stream_name='module1')]
        project, results = run_project(
            modules, {'Module1': b'Sub One()\r\nEnd Sub\r\n',
                      'MODULE1': b'Sub Two()\r\nEnd Sub\r\n'})
        self.assertEqual(results, [])
        module = project.modules[0]
        self.assertIsNone(module.code)
        self.assertTrue(any('ambiguous' in issue
                            for issue in module.stream_name_issues))

    def test_display_name_fallback_is_explicit(self):
        """
        Without any MODULESTREAMNAME record, the module display name may
        designate the stream, but this substitution is recorded as evidence.
        """
        source = b'Sub Solo()\r\nEnd Sub\r\n'
        record = make_module_record('Solo', 'cp1252')
        project, results = run_project([record], {'Solo': source})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'Macros/VBA/Solo')
        self.assertEqual(results[0][2], source.decode('cp1252'))
        self.assertTrue(any('display name' in issue
                            for issue in project.modules[0].stream_name_issues))


if __name__ == '__main__':
    unittest.main()
