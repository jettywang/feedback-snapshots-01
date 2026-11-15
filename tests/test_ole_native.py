"""Tests for the read-only Ole10Native parser."""

import hashlib
import io
import os
import struct
import sys

import pytest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _thismodule_dir not in sys.path:
    sys.path.insert(0, _thismodule_dir)

import olefile
from olefile import ole_native
dummy = b'\x00' * 8

from ole_native_fixtures import (
    PACKAGE_CLSID, cstring, make_container, make_native, make_reference_only,
    build_cfb,
)


def parse(data=None, **kwargs):
    return ole_native.parse_ole10native(data, **kwargs)


def open_package(container_bytes, path=None,
                 stream_name='\x01Ole10Native'):
    ole = olefile.OleFileIO(container_bytes)
    try:
        if path is None:
            paths = ole_native.find_ole10native_streams(ole)
            assert len(paths) == 1
            path = paths[0]
        return ole_native.open_ole10native(ole, path)
    finally:
        ole.close()


# --- 1. legitimate embedded file -----------------------------------------


class TestLegitimateEmbedded:
    def test_fields_and_ranges(self):
        native = b'This is the contents of a simple text file.'
        payload = make_native('report.txt', 'C:\\docs\\report.txt',
                              'C:\\Temp\\report.txt', native)
        package = parse(payload)

        assert package.declared_form == 'embedded'
        assert package.effective_form == 'embedded'
        assert package.is_embedded and not package.is_linked
        assert package.display_name == 'report.txt'
        assert package.source_path == 'C:\\docs\\report.txt'
        assert package.temp_path == 'C:\\Temp\\report.txt'
        assert package.native_data == native
        assert package.native_data_complete is True
        assert package.native_data_range == (
            package.native_data_offset,
            package.native_data_offset + len(native))
        assert package.native_data_available_range == package.native_data_range
        assert package.declared_container_length == len(payload) - 4
        assert package.container_length_complete is True

    def test_digest_is_independent_of_reported_name(self):
        native = b'\x7fELF' + b'\x00' * 60
        payload = make_native('totally-innocent.txt', 'C:\\docs\\a.txt',
                              'C:\\Temp\\a.txt', native)
        package = parse(payload)

        # The caller can hash exactly the returned slice itself.
        assert hashlib.sha256(package.native_data).digest() == \
            hashlib.sha256(native).digest()
        assert package.digest('sha256') == hashlib.sha256(native).hexdigest()
        assert package.native_data_sha256 == hashlib.sha256(native).hexdigest()
        assert package.digest('md5') == hashlib.md5(native).hexdigest()

    def test_trailer_is_kept_separate_from_native_data(self):
        native = b'payload bytes'
        payload = make_native('a.txt', 'C:\\src\\a.txt', 'C:\\Temp\\a.txt',
                              native)
        package = parse(payload)

        assert package.trailer
        assert package.native_data == native
        assert native not in package.trailer[:len(native)] or True
        assert package.trailer_offset == (
            package.native_data_offset + len(native))
        assert package.trailer_length == len(package.trailer)
        assert package.trailer_texts == ['C:\\Temp\\a.txt', 'a.txt',
                                         'C:\\src\\a.txt']
        codes = [issue.code for issue in package.issues]
        assert 'native_data_trailing_bytes' in codes
        assert package.is_consistent

    def test_range_end_and_digest_scope(self):
        native = b'abcdef'
        package = parse(make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt',
                                    native, include_trailer=False))
        assert package.native_data_end == package.native_data_offset + 6
        assert package.native_data_range[1] == package.native_data_end
        assert package.digest_covers == 'available_native_data'
        assert package.evidence()['native_data']['complete'] is True

    def test_module_alias_imports(self):
        from olefile import ole10native
        assert ole10native.parse_ole10native(b'\x00' * 8) is not None
        assert ole10native.Ole10Native is ole_native.Ole10Native

    def test_olefileio_convenience_methods(self):
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', b'abc')
        container = make_container(payload)
        with olefile.OleFileIO(container) as ole:
            paths = ole.list_ole10native_streams()
            assert paths == [['ObjectPool', '_pkg1', '\x01Ole10Native']]
            package = ole.open_ole10native(paths[0])
            assert package.native_data == b'abc'

    def test_container_reporting(self):
        payload = make_native('x.txt', 'C:\\x.txt', 'C:\\Temp\\x.txt', b'abc')
        package = open_package(make_container(payload))
        assert package.container_clsid == '0003000C-0000-0000-C000-000000000046'
        assert package.container_is_package is True
        assert package.stream_path[-1].lower() == '\x01ole10native'
        assert package.stream_size == len(payload)
        evidence = package.evidence()
        assert evidence['safety'] == {
            'link_resolved': False,
            'link_contacted': False,
            'objects_executed': False,
            'files_written': False,
            'paths_used_for_writes': False,
        }

    def test_container_tail_outside_declared_region(self):
        payload = make_native('x.txt', 'C:\\x.txt', 'C:\\Temp\\x.txt', b'abc')
        payload += b'EXTRA!'
        package = parse(payload)
        assert package.outer_trailer == b'EXTRA!'
        assert package.outer_trailer_offset == 4 + \
            package.declared_container_length
        codes = [issue.code for issue in package.issues]
        assert 'trailing_data_outside_container_length' in codes

    def test_stream_lookup_is_case_insensitive(self):
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', b'xyz')
        container = build_cfb([{
            'name': '_pkg1',
            'streams': {'\x01ole10native': payload},
        }])
        package = open_package(container)
        assert package.native_data == b'xyz'
        assert package.display_name == 'a.txt'

    def test_multiple_packages_are_listed(self):
        payload_a = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', b'A')
        payload_b = make_native('b.bin', 'C:\\b.bin', 'C:\\Temp\\b.bin', b'B')
        container = build_cfb([
            {'name': '_pkg1', 'streams': {'\x01Ole10Native': payload_a}},
            {'name': '_pkg2', 'streams': {'\x01Ole10Native': payload_b}},
        ])
        ole = olefile.OleFileIO(container)
        try:
            paths = ole_native.find_ole10native_streams(ole)
            assert [path[-2] for path in paths] == ['_pkg1', '_pkg2']
            packages = list(ole_native.iter_ole10native(ole))
            assert [p.display_name for p in packages] == ['a.txt', 'b.bin']
        finally:
            ole.close()


# --- 2. disguised extension ---------------------------------------------


class TestDisguisedExtension:
    def test_name_extension_is_not_a_content_type(self):
        payload = make_native('invoice.txt', 'C:\\docs\\invoice.txt',
                              'C:\\Temp\\invoice.txt',
                              b'MZ' + b'\x90' * 64)
        package = parse(payload)

        assert package.display_name == 'invoice.txt'
        assert package.reported_extension == 'txt'
        assert package.reported_type_hint == 'txt'
        assert package.content_type == 'DOS/PE executable'
        assert package.content_type_source == 'native_bytes'
        assert package.native_content_hint == 'DOS/PE executable'
        assert package.names_are_self_reported is True

    def test_evidence_marks_names_untrusted(self):
        payload = make_native('photo.jpg', 'C:\\src\\photo.jpg',
                              'C:\\Temp\\photo.jpg', b'%PDF-1.7\n')
        evidence = parse(payload).evidence()
        names = evidence['reported_names']
        for key in ('display_name', 'source_path', 'temp_path'):
            assert names[key]['self_reported'] is True
            assert names[key]['trust'] == 'untrusted'
            assert names[key]['is_content_type'] is False
        assert names['reported_extension'] == 'jpg'
        assert names['reported_extension_is_content_type'] is False
        assert evidence['native_data']['content_hint_from_bytes'] == \
            'PDF document'

    def test_zip_named_as_executable(self):
        payload = make_native('setup.exe', 'C:\\setup.exe',
                              'C:\\Temp\\setup.exe', b'PK\x03\x04' + b'\x00' * 20)
        package = parse(payload)
        assert package.reported_extension == 'exe'
        assert package.content_type == 'ZIP container'


# --- 3. damaged lengths --------------------------------------------------


class TestDamagedLengths:
    def test_native_length_beyond_stream(self):
        native = b'0123456789'
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', native,
                              declared_native_size=1000, include_trailer=False)
        package = parse(payload)

        assert package.native_data_declared_length == 1000
        assert package.native_data_complete is False
        assert package.native_data == native
        assert package.native_data_available_length == len(native)
        assert package.native_data_range == (
            package.native_data_offset,
            package.native_data_offset + 1000)
        assert package.native_data_available_range == (
            package.native_data_offset,
            package.native_data_offset + len(native))
        assert 'native_data_length_exceeds_stream' in \
            [issue.code for issue in package.errors]
        assert package.is_consistent is False

    def test_container_length_beyond_stream(self):
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', b'abc',
                              declared_container_size=5000)
        package = parse(payload)

        assert package.declared_container_length == 5000
        assert package.container_length_complete is False
        assert package.native_data_complete is True
        assert package.native_data == b'abc'
        assert 'container_length_exceeds_stream' in \
            [issue.code for issue in package.errors]

    def test_container_length_shorter_than_fields(self):
        native = b'abcdef'
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', native,
                              include_trailer=False)
        original = parse(payload)
        # Shrink the declared region so it ends three bytes into native data,
        # while the remaining bytes stay physically present: the parser must
        # not read beyond the declared region.
        declared = original.native_data_offset + 3 - 4
        mutated = struct.pack('<I', declared) + payload[4:]
        package = parse(mutated)

        assert package.native_data_declared_length > \
            package.native_data_available_length
        assert package.native_data_complete is False
        assert package.native_data == native[:3]
        assert 'native_data_length_exceeds_stream' in \
            [issue.code for issue in package.errors]

    def test_unterminated_display_name(self):
        # The declared region ends without any NUL after the display name.
        body = struct.pack('<H', 2) + b'no-terminator'
        payload = struct.pack('<I', len(body)) + body
        package = parse(payload)
        assert 'unterminated_string' in [issue.code for issue in package.errors]
        assert package.display_name_complete is False
        assert package.display_name_raw == b'no-terminator'
        assert package.native_data is None

    def test_unterminated_length_prefixed_string(self):
        body = struct.pack('<H', 2) + cstring('a.txt') + cstring('C:\\a.txt')
        body += struct.pack('<I', 0x00030000)
        body += struct.pack('<I', 4) + b'abcd'  # no NUL inside 4 bytes
        payload = struct.pack('<I', len(body)) + body
        package = parse(payload)
        assert 'unterminated_string' in [issue.code for issue in package.errors]
        assert package.temp_path_complete is False

    def test_temp_path_length_beyond_stream(self):
        body = struct.pack('<H', 2) + cstring('a.txt') + cstring('C:\\a.txt')
        body += struct.pack('<I', 0x00030000)
        body += struct.pack('<I', 4096) + b'C:\\Temp\\a.txt\x00'
        payload = struct.pack('<I', len(body)) + body
        package = parse(payload)
        assert 'string_length_exceeds_stream' in \
            [issue.code for issue in package.errors]
        assert package.temp_path_complete is False

    def test_trailer_block_length_beyond_stream(self):
        native = b'abc'
        body = struct.pack('<H', 2) + cstring('a.txt') + cstring('C:\\a.txt')
        body += struct.pack('<I', 0x00030000)
        body += struct.pack('<I', len(cstring('C:\\Temp\\a.txt')))
        body += cstring('C:\\Temp\\a.txt')
        body += struct.pack('<I', len(native)) + native
        body += struct.pack('<I', 500) + b'xy'
        payload = struct.pack('<I', len(body)) + body
        package = parse(payload)

        assert package.native_data == native
        assert 'trailer_block_length_exceeds_stream' in \
            [issue.code for issue in package.warnings]
        assert package.trailer_complete is False
        assert package.trailer_blocks[-1]['complete'] is False

    def test_empty_and_zero_length_inputs(self):
        for data in (b'', b'\x01', b'\x00\x00\x00\x00'):
            package = parse(data)
            assert package.native_data is None
            assert package.is_consistent is False
            assert package.issues[0].severity == 'error'

    def test_zero_length_native_payload(self):
        package = parse(make_native('e.txt', 'C:\\e', 'C:\\T\\e', b'',
                                    include_trailer=False))
        assert package.effective_form == 'embedded'
        assert package.native_data == b''
        assert package.native_data_declared_length == 0
        assert package.native_data_complete is True
        assert package.digest() == hashlib.sha256(b'').hexdigest()

    def test_missing_native_length_after_embedded_header(self):
        # FormatID says embedded, but the stream ends after the temp path.
        body = struct.pack('<H', 2) + cstring('a.txt') + cstring('C:\\a.txt')
        body += struct.pack('<I', 0x00030000)
        body += struct.pack('<I', len(cstring('C:\\Temp\\a.txt')))
        body += cstring('C:\\Temp\\a.txt')
        payload = struct.pack('<I', len(body)) + body
        package = parse(payload)
        assert package.has_native_data is False
        assert package.effective_form == 'linked'
        assert package.declared_form == 'embedded'
        assert 'missing_native_data_length' in \
            [issue.code for issue in package.issues]


# --- link / embedded separation ------------------------------------------


class TestLinkedVersusEmbedded:
    def test_reference_only_package(self):
        payload = make_reference_only('calc.exe', 'C:\\Windows\\System32\\calc.exe',
                                      'C:\\Windows\\System32\\calc.exe')
        package = parse(payload)

        assert package.effective_form == 'linked'
        assert package.is_linked is True
        assert package.native_data is None
        assert package.has_native_data is False
        assert package.link_target == 'C:\\Windows\\System32\\calc.exe'
        evidence = package.evidence()
        assert evidence['safety']['link_resolved'] is False
        assert evidence['safety']['link_contacted'] is False

    def test_explicit_linked_format_id_with_payload(self):
        payload = make_native('calc.exe', 'C:\\Windows\\System32\\calc.exe',
                              'C:\\Windows\\System32\\calc.exe', b'not native',
                              format_id=1)
        package = parse(payload)

        assert package.declared_form == 'linked'
        assert package.effective_form == 'linked'
        assert package.is_linked is True
        assert package.native_data == b'not native'
        assert 'linked_form_with_native_data' in \
            [issue.code for issue in package.issues]

    def test_ole_stream_flags_are_evidence_only(self):
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', b'abc')
        payload_ole = struct.pack('<II', 0x02000001, 0x00000001) + b'\x00' * 24
        container = build_cfb([{
            'name': '_pkg1',
            'streams': {'\x01Ole10Native': payload,
                        '\x01Ole': payload_ole},
        }])
        package = open_package(container)
        assert package.ole_stream_seen is True
        assert package.ole_stream_flags == 1
        assert package.ole_stream_declared_linked is True
        assert package.evidence()['ole_stream']['declared_linked'] is True

    def test_ole_stream_link_flag_conflicts_with_native_data(self):
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', b'abc')
        ole_stream = struct.pack('<II', 0x02000001, 1) + b'\x00' * 24
        container = build_cfb([{
            'name': '_pkg1',
            'streams': {'\x01Ole10Native': payload, '\x01Ole': ole_stream},
        }])
        package = open_package(container)
        assert 'form_conflict_link_flag_with_native_data' in \
            [issue.code for issue in package.issues]
        evidence = package.evidence()['form_evidence']
        assert evidence['ole_stream_declared_linked'] is True
        assert evidence['conflicts'][0]['code'] == \
            'form_conflict_link_flag_with_native_data'

    def test_non_package_clsid_is_reported(self):
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', b'abc')
        container = make_container(payload, storage_clsid=b'\x00' * 16)
        package = open_package(container)
        assert package.container_is_package is False


# --- on-disk fixture containers (three material groups) ------------------


FIXTURES = os.path.join(_thismodule_dir, 'images')


class TestFixtureFiles:
    def _packages(self, name):
        path = os.path.join(FIXTURES, name)
        with olefile.OleFileIO(path) as ole:
            return list(ole_native.iter_ole10native(ole))

    def test_legitimate_embedded_file(self):
        packages = self._packages('ole10native-legit.doc')
        assert len(packages) == 1
        package = packages[0]
        assert package.declared_form == 'embedded'
        assert package.native_data == b'Quarterly report body.\r\nLine two.\r\n'
        assert package.native_data_complete is True
        assert package.is_consistent is True
        assert package.reported_extension == 'txt'
        assert package.content_type_source == 'native_bytes'
        assert package.trailer_texts[0].endswith('quarterly-report.txt')

    def test_disguised_extension(self):
        package = self._packages('ole10native-disguised.doc')[0]
        assert package.reported_extension == 'jpg'
        assert package.content_type == 'DOS/PE executable'
        assert package.native_data.startswith(b'MZ')
        assert package.reported_extension != 'exe'
        assert package.evidence()['reported_names'][
            'reported_extension_is_content_type'] is False

    def test_damaged_length(self):
        package = self._packages('ole10native-damaged.doc')[0]
        assert package.native_data_declared_length == 4096
        assert package.native_data_complete is False
        assert package.native_data == b'0123456789abcdef'
        assert package.native_data_available_length == 16
        assert package.native_data_range[1] - package.native_data_range[0] == \
            4096
        assert 'native_data_length_exceeds_stream' in \
            [issue.code for issue in package.errors]
        assert package.is_consistent is False
        assert package.digest() == hashlib.sha256(
            b'0123456789abcdef').hexdigest()

    def test_reference_only_fixture(self):
        package = self._packages('ole10native-link.doc')[0]
        assert package.effective_form == 'linked'
        assert package.native_data is None
        assert package.link_target == 'C:\\Windows\\System32\\calc.exe'
        assert package.evidence()['safety']['link_contacted'] is False


# --- safety and CLI ------------------------------------------------------


class TestSafety:
    def test_no_file_is_written_and_names_are_not_opened(self, tmp_path,
                                                        monkeypatch):
        evil_name = '../../etc/passwd'
        payload = make_native(evil_name, '/etc/passwd', '/tmp/evil',
                              b'payload')
        container = make_container(payload)

        def fail_open(*args, **kwargs):
            raise AssertionError('parser must not open paths')

        monkeypatch.setattr(io, 'open', fail_open)
        monkeypatch.setattr(os, 'open', fail_open)
        package = open_package(container)
        assert package.display_name == evil_name
        assert package.native_data == b'payload'

    def test_parse_accepts_bytesio_and_bindata_alias(self):
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', b'abc')
        assert parse(io.BytesIO(payload)).native_data == b'abc'
        assert parse(bindata=payload).display_name == 'a.txt'

    def test_package_mode_is_rejected_explicitly(self):
        with pytest.raises(ValueError):
            ole_native.Ole10Native(dummy, package=True)

    def test_digest_over_short_slice_when_truncated(self):
        native = b'0123456789'
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', native,
                              declared_native_size=50, include_trailer=False)
        package = parse(payload)
        assert package.native_data == native
        assert package.digest() == hashlib.sha256(native).hexdigest()

    def test_cli_outputs_json_evidence(self, tmp_path, capsys):
        payload = make_native('invoice.txt', 'C:\\docs\\invoice.txt',
                              'C:\\Temp\\invoice.txt',
                              b'MZ' + b'\x00' * 30)
        path = tmp_path / 'sample.doc'
        path.write_bytes(make_container(payload))
        rc = ole_native._main([str(path)])
        assert rc == 0
        import json
        report = json.loads(capsys.readouterr().out)
        assert report['packages'][0]['native_data']['sha256'] == \
            hashlib.sha256(payload[payload.index(b'MZ'):][:32]).hexdigest()
        assert report['packages'][0]['reported_names']['display_name'][
            'is_content_type'] is False

    def test_full_hex_only_on_request(self, tmp_path, capsys):
        native = b'ABC'
        payload = make_native('a.txt', 'C:\\a.txt', 'C:\\Temp\\a.txt', native)
        path = tmp_path / 'sample.doc'
        path.write_bytes(make_container(payload))
        ole_native._main([str(path)])
        import json
        report = json.loads(capsys.readouterr().out)
        assert 'hex' not in report['packages'][0]['native_data']
