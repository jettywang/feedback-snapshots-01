"""
olefile.vba

Static inventory of VBA projects embedded in OLE2/CFB files, implemented from
the MS-OVBA specification (VBA File Structure).

This module only parses and cross-checks on-disk structures:

* the compressed ``dir`` stream of the VBA storage is decompressed
  (MS-OVBA section 2.4.1) and its records are interpreted
  (MS-OVBA section 2.3.4.2);
* every MODULE record is correlated with its real Module Stream
  (MS-OVBA sections 2.3.4.2.3 and 2.3.4.3);
* module stream names, PROJECTCODEPAGE, MODULEOFFSET source offsets and
  REFERENCE records are checked against the actual streams.

Nothing in this module executes VBA source code, and no heuristic based on
file names or source strings (for example looking for "AutoOpen") is used to
classify a document as malicious.  Structural inconsistencies are reported as
explicit findings, each carrying the directory evidence (record id and byte
range in the decompressed dir stream) and the stream ranges they refer to.

Bounded decompression and bounded record counts are used so that a malformed or
hostile file cannot force unbounded memory allocation or parsing work.  When a
limit is hit, or when an unknown record is encountered, the inventory is marked
as incomplete: unknown data is never presented as the result of a full scan.

olefile is copyright (c) 2005-2023 Philippe Lagadec (https://www.decalage.info)
"""

# Python 2.7 / 3.5+ compatibility:
from __future__ import print_function

import struct

from .olefile import OleFileIO


# ===--------------------------------------------------------------------===
# Default resource limits.  They are deliberately generous for legitimate
# projects but bound the work and memory a single file can require.
# ===--------------------------------------------------------------------===

#: maximum bytes returned by one decompression (dir stream or module source)
DEFAULT_MAX_DECOMPRESSED = 64 * 1024 * 1024

#: maximum number of records interpreted in one dir stream
DEFAULT_MAX_RECORDS = 100000

#: maximum number of MODULE records in one project
DEFAULT_MAX_MODULES = 10000

#: maximum number of REFERENCE records in one project
DEFAULT_MAX_REFERENCES = 10000

#: maximum number of bytes of decoded source kept as a preview per module
DEFAULT_SOURCE_PREVIEW = 200

#: maximum nesting depth of REFERENCEORIGINAL/REFERENCECONTROL records
DEFAULT_MAX_REFERENCE_DEPTH = 32


# ===--------------------------------------------------------------------===
# Finding codes.  These describe structural facts only, never a verdict on
# whether the document is malicious.
# ===--------------------------------------------------------------------===

# compression / decompression
F_BAD_SIGNATURE = 'compression.bad_signature'
F_TRUNCATED_CHUNK = 'compression.truncated_chunk'
F_BAD_CHUNK_HEADER = 'compression.bad_chunk_header'
F_TRUNCATED_TOKEN = 'compression.truncated_token'
F_COPY_OUT_OF_BOUNDS = 'compression.copy_out_of_bounds'
F_OUTPUT_LIMIT = 'compression.output_limit'
F_DIR_COMPRESSION = 'dir.compression_error'
F_MODULE_COMPRESSION = 'module.compression_error'

# dir stream structure
F_UNKNOWN_RECORD = 'dir.unknown_record'
F_TRUNCATED_RECORD = 'dir.truncated_record'
F_RECORD_LIMIT = 'dir.record_limit'
F_MODULE_LIMIT = 'dir.module_limit'
F_REFERENCE_LIMIT = 'dir.reference_limit'
F_NO_TERMINATOR = 'dir.no_terminator'
F_BAD_CODEPAGE = 'project.bad_codepage'
F_MISSING_CODEPAGE = 'project.missing_codepage'

# module / stream correlation
F_MODULE_STREAM_MISSING = 'module.stream_missing'
F_DUPLICATE_STREAM_MAPPING = 'module.duplicate_stream_mapping'
F_OFFSET_OUT_OF_RANGE = 'module.offset_out_of_range'
F_NO_COMPRESSED_SOURCE = 'module.no_compressed_source'
F_ORPHAN_STREAM = 'module.orphan_stream'

# storage layout
F_NO_VBA_STORAGE = 'storage.no_vba_storage'
F_NO_DIR_STREAM = 'storage.no_dir_stream'

# severity levels
SEVERITY_ERROR = 'error'
SEVERITY_WARNING = 'warning'
SEVERITY_INFO = 'info'


class VbaError(Exception):
    """Base class for VBA inventory errors."""


class VbaCompressionError(VbaError):
    """
    Raised internally when an MS-OVBA CompressedContainer cannot be decoded.

    :ivar str code: one of the ``compression.*`` finding codes
    :ivar int offset: byte offset in the compressed container where the
        problem was detected (when known, otherwise -1)
    """

    def __init__(self, code, message, offset=-1):
        super(VbaCompressionError, self).__init__(message)
        self.code = code
        self.offset = offset


class VbaStructureError(VbaError):
    """
    Raised internally when the decompressed dir stream cannot be parsed.

    :ivar str code: one of the ``dir.*`` finding codes
    :ivar int offset: byte offset in the decompressed dir stream where the
        problem was detected (when known, otherwise -1)
    """

    def __init__(self, code, message, offset=-1):
        super(VbaStructureError, self).__init__(message)
        self.code = code
        self.offset = offset


# ===--------------------------------------------------------------------===
# MS-OVBA 2.4.1.3.1 Compression container decompression
# ===--------------------------------------------------------------------===

def decompress_container(data, max_output=DEFAULT_MAX_DECOMPRESSED):
    """
    Decompress an MS-OVBA CompressedContainer (section 2.4.1).

    The algorithm is implemented strictly: every CopyToken is checked against
    the bytes already produced in its own DecompressedChunk, so a forged
    container cannot make the decoder read before the chunk start or beyond
    the output produced so far.

    :param bytes data: the compressed container (a whole dir stream or the
        ``CompressedSourceCode`` part of a module stream)
    :param int max_output: maximum number of decompressed bytes that may be
        produced
    :return: decompressed bytes
    :rtype: bytes
    :raises VbaCompressionError: if the container is malformed, a copy token
        points outside the available data, or ``max_output`` would be exceeded
    """
    if not data:
        raise VbaCompressionError(F_BAD_SIGNATURE,
                                  'empty compressed container', 0)
    if bytevalue(data, 0) != 0x01:
        raise VbaCompressionError(
            F_BAD_SIGNATURE,
            'invalid CompressedContainer signature byte 0x%02X (expected 0x01)'
            % bytevalue(data, 0), 0)

    output = bytearray()
    compressed_current = 1
    record_end = len(data)

    while compressed_current < record_end:
        chunk_start = compressed_current
        # A CompressedChunkHeader needs two bytes:
        if record_end - compressed_current < 2:
            raise VbaCompressionError(
                F_TRUNCATED_CHUNK,
                'truncated CompressedChunk header at offset %d' % chunk_start,
                chunk_start)
        header = struct.unpack_from('<H', data, compressed_current)[0]
        chunk_size = (header & 0x0FFF) + 3
        chunk_flag = (header & 0x8000) >> 15
        chunk_signature = (header & 0x7000) >> 12
        if chunk_signature != 0b011:
            raise VbaCompressionError(
                F_BAD_CHUNK_HEADER,
                'invalid CompressedChunk signature 0x%X at offset %d'
                % (chunk_signature, chunk_start), chunk_start)
        if chunk_flag == 0 and (header & 0x0FFF) != 0x0FFF:
            raise VbaCompressionError(
                F_BAD_CHUNK_HEADER,
                'uncompressed chunk must declare size 4095, got %d at '
                'offset %d' % (chunk_size, chunk_start), chunk_start)
        if chunk_size < 3:
            raise VbaCompressionError(
                F_BAD_CHUNK_HEADER,
                'CompressedChunk size smaller than 3 at offset %d'
                % chunk_start, chunk_start)

        # The chunk must be fully contained in the container.  A header that
        # claims more bytes than are present is malformed data, not padding.
        compressed_end = min(record_end, chunk_start + chunk_size)
        if chunk_start + chunk_size > record_end:
            raise VbaCompressionError(
                F_TRUNCATED_CHUNK,
                'CompressedChunk at offset %d declares %d bytes but only %d '
                'remain' % (chunk_start, chunk_size,
                            record_end - chunk_start), chunk_start)

        compressed_current = chunk_start + 2
        decompressed_chunk_start = len(output)

        if chunk_flag == 0:
            # RawChunk: exactly 4096 uncompressed bytes follow the header.
            raw_end = compressed_current + 4096
            if raw_end > compressed_end:
                raise VbaCompressionError(
                    F_TRUNCATED_CHUNK,
                    'uncompressed chunk at offset %d is shorter than 4096 '
                    'bytes' % chunk_start, chunk_start)
            _append_output(output, data[compressed_current:raw_end],
                           max_output, chunk_start)
            compressed_current = raw_end
        else:
            while compressed_current < compressed_end:
                flag_byte = bytevalue(data, compressed_current)
                compressed_current += 1
                for index in range(8):
                    if compressed_current >= compressed_end:
                        break
                    if (flag_byte >> index) & 1 == 0:
                        # LiteralToken: one byte copied as-is.
                        _append_output(output,
                                       data[compressed_current:
                                            compressed_current + 1],
                                       max_output, compressed_current)
                        compressed_current += 1
                    else:
                        # CopyToken: two little-endian bytes.
                        if compressed_end - compressed_current < 2:
                            raise VbaCompressionError(
                                F_TRUNCATED_TOKEN,
                                'truncated CopyToken at offset %d'
                                % compressed_current, compressed_current)
                        token = struct.unpack_from(
                            '<H', data, compressed_current)[0]
                        difference = (len(output) -
                                      decompressed_chunk_start)
                        bit_count = _copy_token_bit_count(difference)
                        length_mask = 0xFFFF >> bit_count
                        offset_mask = (~length_mask) & 0xFFFF
                        length = (token & length_mask) + 3
                        offset = ((token & offset_mask) >>
                                  (16 - bit_count)) + 1
                        copy_source = len(output) - offset
                        # The CopySequence must start at or after the start of
                        # the current DecompressedChunk and before the current
                        # write position.  This rejects forged copy tokens that
                        # reach outside the data produced so far.
                        if copy_source < decompressed_chunk_start or \
                                offset > difference:
                            raise VbaCompressionError(
                                F_COPY_OUT_OF_BOUNDS,
                                'CopyToken at offset %d references position %d '
                                'outside the current chunk (chunk starts at '
                                '%d, current position %d)'
                                % (compressed_current, copy_source,
                                   decompressed_chunk_start, len(output)),
                                compressed_current)
                        # A DecompressedChunk never holds more than 4096 bytes
                        # in a valid container.  Reject a token that would grow
                        # it beyond that, regardless of the global output cap.
                        if len(output) + length - \
                                decompressed_chunk_start > 4096:
                            raise VbaCompressionError(
                                F_COPY_OUT_OF_BOUNDS,
                                'CopyToken at offset %d would expand the '
                                'current chunk beyond 4096 bytes (length=%d)'
                                % (compressed_current, length),
                                compressed_current)
                        # Byte Copy with overlapping source and destination:
                        # one byte at a time, exactly as in MS-OVBA 2.4.1.3.11.
                        for _ in range(length):
                            if len(output) >= max_output:
                                raise VbaCompressionError(
                                    F_OUTPUT_LIMIT,
                                    'decompressed output exceeds limit of %d '
                                    'bytes' % max_output, compressed_current)
                            output.append(output[copy_source])
                            copy_source += 1
                        compressed_current += 2

        # Defensive check: every chunk must consume exactly its declared size.
        if compressed_current != compressed_end:
            raise VbaCompressionError(
                F_BAD_CHUNK_HEADER,
                'CompressedChunk at offset %d consumed %d bytes, declared %d'
                % (chunk_start, compressed_current - chunk_start,
                   chunk_size), chunk_start)
    return bytes(output)


def bytevalue(data, index):
    """Return a single byte as an integer on both Python 2 and Python 3."""
    value = data[index]
    if isinstance(value, str):  # Python 2 str indexing returns a char
        return ord(value)
    return value


def _append_output(output, chunk, max_output, offset):
    """Append ``chunk`` to ``output`` while enforcing ``max_output``."""
    if len(output) + len(chunk) > max_output:
        raise VbaCompressionError(
            F_OUTPUT_LIMIT,
            'decompressed output exceeds limit of %d bytes' % max_output,
            offset)
    output.extend(chunk)


def _copy_token_bit_count(difference):
    """MS-OVBA 2.4.1.3.19.1 CopyToken Help bit count."""
    bit_count = 0
    value = difference
    while value > 0:
        bit_count += 1
        value >>= 1
    if bit_count < 4:
        bit_count = 4
    return bit_count


# ===--------------------------------------------------------------------===
# MS-OVBA 2.3.4.2 dir stream record interpretation
# ===--------------------------------------------------------------------===

# Record ids defined by MS-OVBA.  Anything not in this table is an unknown
# record and forces the inventory to be reported as incomplete.
_RECORD_IDS = {
    0x0001: 'PROJECTSYSKIND',
    0x004A: 'PROJECTCOMPATVERSION',
    0x0002: 'PROJECTLCID',
    0x0014: 'PROJECTLCIDINVOKE',
    0x0003: 'PROJECTCODEPAGE',
    0x0004: 'PROJECTNAME',
    0x0005: 'PROJECTDOCSTRING',
    0x0006: 'PROJECTHELPFILEPATH',
    0x0007: 'PROJECTHELPCONTEXT',
    0x0008: 'PROJECTLIBFLAGS',
    0x0009: 'PROJECTVERSION',
    0x000C: 'PROJECTCONSTANTS',
    0x0016: 'REFERENCENAME',
    0x002F: 'REFERENCECONTROL',
    0x0033: 'REFERENCEORIGINAL',
    0x000D: 'REFERENCEREGISTERED',
    0x000E: 'REFERENCEPROJECT',
    0x000F: 'PROJECTMODULES',
    0x0013: 'PROJECTCOOKIE',
    0x0019: 'MODULENAME',
    0x0047: 'MODULENAMEUNICODE',
    0x001A: 'MODULESTREAMNAME',
    0x001C: 'MODULEDOCSTRING',
    0x0031: 'MODULEOFFSET',
    0x001E: 'MODULEHELPCONTEXT',
    0x002C: 'MODULECOOKIE',
    0x0021: 'MODULETYPE_PROCEDURAL',
    0x0022: 'MODULETYPE_DOCUMENT',
    0x0025: 'MODULEREADONLY',
    0x0028: 'MODULEPRIVATE',
    0x002B: 'MODULETERMINATOR',
    0x0010: 'DIRTERMINATOR',
}

# Ids of fixed-size records made of Id (2) + Size (4) + Value (4)
_FIXED_DWORD_IDS = frozenset((
    0x0001, 0x004A, 0x0002, 0x0014, 0x0007, 0x0008, 0x0031, 0x001E,
))
# Id (2) + Size (4) + Value (2)
_FIXED_WORD_IDS = frozenset((0x0003, 0x0013, 0x002C))
# Id (2) + Reserved (4) + DWORD + WORD (no Size field)
_RESERVED_DWORD_WORD_IDS = frozenset((0x0021, 0x0022, 0x0025, 0x0028))


class _DirReader(object):
    """Cursor over the decompressed dir stream bytes."""

    def __init__(self, data, max_records):
        self.data = data
        self.pos = 0
        self.records_seen = 0
        self.max_records = max_records

    def remaining(self):
        return len(self.data) - self.pos

    def take(self, count):
        if count < 0 or self.pos + count > len(self.data):
            raise VbaStructureError(
                F_TRUNCATED_RECORD,
                'need %d bytes at offset %d but %d remain'
                % (count, self.pos, len(self.data) - self.pos), self.pos)
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def u16(self):
        return struct.unpack('<H', self.take(2))[0]

    def peek_u16(self):
        """Return the record id at the current position without consuming."""
        if self.remaining() < 2:
            raise VbaStructureError(
                F_TRUNCATED_RECORD,
                'need a record id at offset %d but %d bytes remain'
                % (self.pos, self.remaining()), self.pos)
        return struct.unpack_from('<H', self.data, self.pos)[0]

    def u32(self):
        return struct.unpack('<I', self.take(4))[0]

    def read_id_size(self):
        start = self.pos
        record_id = self.u16()
        size = self.u32()
        self.records_seen += 1
        if self.records_seen > self.max_records:
            raise VbaStructureError(
                F_RECORD_LIMIT,
                'more than %d records in dir stream' % self.max_records,
                start)
        if size > self.remaining():
            raise VbaStructureError(
                F_TRUNCATED_RECORD,
                'record 0x%04X at offset %d declares %d bytes but %d remain'
                % (record_id, start, size, self.remaining()), start)
        return record_id, size, start

    def read_string_with_unicode(self):
        """
        Read the common MBCS string + Reserved + unicode size + unicode bytes
        layout used by PROJECTDOCSTRING, MODULESTREAMNAME, MODULEDOCSTRING and
        REFERENCENAME.
        """
        size_mbcs = self.u32()
        mbcs = self.take(size_mbcs)
        reserved = self.u16()
        size_unicode = self.u32()
        unicode_data = self.take(size_unicode)
        return mbcs, reserved, unicode_data


def _decode_mbcs(data, codepage):
    """Decode MBCS bytes using the project code page, never raising."""
    encoding = _codepage_encoding(codepage)
    if encoding is None:
        return None
    try:
        return data.decode(encoding, errors='replace')
    except (LookupError, TypeError):
        return None


def _codepage_encoding(codepage):
    if not codepage:
        return None
    # Python's "cp%d" codec naming covers the Windows code pages used by VBA.
    return 'cp%d' % codepage


def _apply_project_dword(project, record_id, value):
    if record_id == 0x0001:
        project['syskind'] = value
    elif record_id == 0x0002:
        project['lcid'] = value
    elif record_id == 0x0014:
        project['lcid_invoke'] = value
    elif record_id == 0x0007:
        project['help_context'] = value
    elif record_id == 0x0008:
        project['lib_flags'] = value


def _parse_dir_stream_strict(data, limits):
    """
    State-machine parser for the decompressed dir stream following the fixed
    MS-OVBA record order: PROJECTINFORMATION -> PROJECTREFERENCES ->
    PROJECTMODULES -> terminator 0x0010 + reserved.
    """
    reader = _DirReader(data, limits['max_records'])
    issues = []
    records = []
    project = {
        'name': None,
        'codepage': None,
        'codepage_encoding': None,
        'syskind': None,
        'lcid': None,
        'lcid_invoke': None,
        'doc_string': None,
        'help_file_path': None,
        'help_context': None,
        'lib_flags': None,
        'version_major': None,
        'version_minor': None,
        'constants': None,
        'project_information_complete': False,
        'project_cookie': None,
        'declared_module_count': None,
    }
    references = []
    modules = []
    modules_count = None
    incomplete = False

    def note(code, message, severity, offset=-1, record_id=None):
        issues.append(_finding(code, message, severity, offset, record_id))

    def next_record():
        start = reader.pos
        record_id, size, start = reader.read_id_size()
        end = reader.pos + size
        records.append({'id': record_id,
                        'name': _RECORD_IDS.get(record_id),
                        'offset': start,
                        'size': 2 + 4 + size})
        return record_id, size, start, end

    try:
        # ---------- PROJECTINFORMATION ------------------------------------
        while reader.remaining() >= 6:
            peek = reader.peek_u16()
            if peek == 0x000F or peek in _REFERENCE_START_IDS:
                break
            record_id, size, start, end = next_record()
            if record_id in _FIXED_DWORD_IDS:
                _apply_project_dword(project, record_id, reader.u32())
            elif record_id in _FIXED_WORD_IDS:
                value = reader.u16()
                if record_id == 0x0003:
                    project['codepage'] = value
                    project['codepage_encoding'] = \
                        _codepage_encoding(value)
            elif record_id == 0x0004:
                project['name'] = _decode_mbcs(reader.take(size),
                                                project['codepage'])
            elif record_id in (0x0005, 0x0006, 0x000C):
                mbcs, _res, _uni = reader.read_string_with_unicode()
                text = _decode_mbcs(mbcs, project['codepage'])
                if record_id == 0x0005:
                    project['doc_string'] = text
                elif record_id == 0x0006:
                    project['help_file_path'] = text
                else:
                    project['constants'] = text
            elif record_id == 0x0009:
                reader.u32()  # reserved
                project['version_major'] = reader.u32()
                project['version_minor'] = reader.u16()
            else:
                note(F_UNKNOWN_RECORD,
                     'unknown record 0x%04X at offset %d in '
                     'PROJECTINFORMATION' % (record_id, start),
                     SEVERITY_ERROR, start, record_id)
                incomplete = True
                reader.pos = end
                break
            reader.pos = end

        # ---------- PROJECTREFERENCES -------------------------------------
        while reader.remaining() >= 6 and \
                reader.peek_u16() in _REFERENCE_START_IDS:
            if len(references) >= limits['max_references']:
                note(F_REFERENCE_LIMIT,
                     'more than %d REFERENCE records'
                     % limits['max_references'], SEVERITY_ERROR, reader.pos)
                incomplete = True
                break
            reference, ref_issues, stop = _parse_reference(
                reader, records, project['codepage'], 0, limits)
            references.append(reference)
            issues.extend(ref_issues)
            if ref_issues:
                incomplete = True
            if stop:
                break

        # ---------- PROJECTMODULES header ---------------------------------
        if reader.remaining() < 6 or reader.peek_u16() != 0x000F:
            note(F_UNKNOWN_RECORD,
                 'PROJECTREFERENCES must be followed by PROJECTMODULES '
                 '(0x000F), next record is 0x%04X'
                 % (reader.peek_u16() if reader.remaining() >= 2 else -1),
                 SEVERITY_ERROR, reader.pos)
            incomplete = True
        else:
            record_id, size, start, end = next_record()
            if size != 2:
                note(F_TRUNCATED_RECORD,
                     'PROJECTMODULES size is %d, expected 2' % size,
                     SEVERITY_ERROR, start, record_id)
                incomplete = True
            modules_count = reader.u16()
            reader.pos = end

            # PROJECTCOOKIE (0x0013)
            if reader.remaining() >= 6 and reader.peek_u16() == 0x0013:
                cookie_id, cookie_size, cookie_start, cookie_end = \
                    next_record()
                if cookie_size != 2:
                    note(F_TRUNCATED_RECORD,
                         'PROJECTCOOKIE size is %d, expected 2'
                         % cookie_size, SEVERITY_ERROR, cookie_start,
                         cookie_id)
                    incomplete = True
                else:
                    project['project_cookie'] = reader.u16()
                reader.pos = cookie_end
            else:
                note(F_UNKNOWN_RECORD,
                     'PROJECTMODULES must be followed by PROJECTCOOKIE '
                     '(0x0013)', SEVERITY_ERROR, reader.pos)
                incomplete = True

            # ---------- MODULE records ------------------------------------
            parsed_modules = 0
            while reader.remaining() >= 6 and \
                    reader.peek_u16() != 0x0010:
                if modules_count is not None and \
                        parsed_modules >= modules_count:
                    note(F_UNKNOWN_RECORD,
                         'extra records after the declared %d MODULE '
                         'records' % modules_count, SEVERITY_WARNING,
                         reader.pos)
                    incomplete = True
                    break
                if parsed_modules >= limits['max_modules']:
                    note(F_MODULE_LIMIT,
                         'more than %d MODULE records'
                         % limits['max_modules'], SEVERITY_ERROR,
                         reader.pos)
                    incomplete = True
                    break
                module, module_issues, stop = _parse_module(
                    reader, records, project['codepage'], limits)
                issues.extend(module_issues)
                if module_issues:
                    incomplete = True
                if module is not None:
                    modules.append(module)
                    parsed_modules += 1
                if stop:
                    break

            if modules_count is not None and \
                    len(modules) != modules_count:
                note(F_TRUNCATED_RECORD,
                     'PROJECTMODULES declares %d modules but %d MODULE '
                     'records were parsed'
                     % (modules_count, len(modules)), SEVERITY_ERROR)
                incomplete = True

        # ---------- terminator 0x0010 + 4 reserved bytes ------------------
        if reader.remaining() >= 2:
            terminator = reader.u16()
            if terminator != 0x0010:
                note(F_NO_TERMINATOR,
                     'dir stream terminator is 0x%04X, expected 0x0010'
                     % terminator, SEVERITY_WARNING, reader.pos - 2)
                incomplete = True
            elif reader.remaining() < 4:
                note(F_TRUNCATED_RECORD,
                     'dir stream ends without 4 reserved bytes after '
                     'terminator', SEVERITY_WARNING, reader.pos)
                incomplete = True
            else:
                reader.take(4)
        else:
            note(F_NO_TERMINATOR,
                 'dir stream has no 0x0010 terminator', SEVERITY_WARNING,
                 reader.pos)
            incomplete = True

        if reader.remaining() != 0:
            note(F_UNKNOWN_RECORD,
                 '%d trailing bytes after the dir terminator are not part '
                 'of any known record' % reader.remaining(),
                 SEVERITY_WARNING, reader.pos)
            incomplete = True
    except VbaStructureError as exc:
        note(exc.code, str(exc), SEVERITY_ERROR, exc.offset)
        incomplete = True

    if project['codepage'] is None:
        note(F_MISSING_CODEPAGE,
             'dir stream contains no PROJECTCODEPAGE record; MBCS strings '
             'cannot be decoded reliably', SEVERITY_WARNING)
    else:
        try:
            b'test'.decode(project['codepage_encoding'])
        except LookupError:
            note(F_BAD_CODEPAGE,
                 'PROJECTCODEPAGE %d (codec %s) is not supported'
                 % (project['codepage'], project['codepage_encoding']),
                 SEVERITY_WARNING)

    project['project_information_complete'] = not incomplete
    project['declared_module_count'] = modules_count
    return project, references, modules, records, issues


_REFERENCE_START_IDS = frozenset((0x0016, 0x002F, 0x0033, 0x000D, 0x000E))


def _parse_reference_name(reader, records, codepage):
    """Parse an optional/required REFERENCENAME (0x0016) record."""
    record_id, size, start, end = _next_ref_record(reader, records)
    if record_id != 0x0016:
        raise VbaStructureError(F_UNKNOWN_RECORD,
                                'expected REFERENCENAME (0x0016), got 0x%04X'
                                % record_id, start)
    name_size = reader.u32()
    name_mbcs = reader.take(name_size)
    reader.u16()  # reserved 0x003E
    unicode_size = reader.u32()
    name_unicode = reader.take(unicode_size)
    reader.pos = end
    return {
        'name': _decode_mbcs(name_mbcs, codepage),
        'name_unicode': _decode_utf16(name_unicode),
        'evidence': {'record_id': record_id, 'offset': start,
                     'size': 2 + 4 + size},
    }


def _next_ref_record(reader, records):
    start = reader.pos
    record_id, size, start = reader.read_id_size()
    end = reader.pos + size
    records.append({'id': record_id,
                    'name': _RECORD_IDS.get(record_id),
                    'offset': start,
                    'size': 2 + 4 + size})
    return record_id, size, start, end


def _parse_reference(reader, records, codepage, depth, limits):
    """
    Parse one REFERENCE record (MS-OVBA 2.3.4.2.2) including the optional
    REFERENCENAME and the nested REFERENCECONTROL of REFERENCEORIGINAL.
    """
    issues = []
    evidence = []
    reference = {
        'kind': 'unknown',
        'name': None,
        'name_unicode': None,
        'libid': None,
        'libid_absolute': None,
        'libid_relative': None,
        'libid_twiddled': None,
        'libid_extended': None,
        'original_typelib': None,
        'major_version': None,
        'minor_version': None,
        'cookie': None,
        'nested_control': None,
        'dir_evidence': evidence,
        'issues': issues,
    }
    stop = False

    def note(code, message, severity, offset=-1, record_id=None):
        issues.append(_finding(code, message, severity, offset, record_id))

    try:
        if depth > limits['max_reference_depth']:
            raise VbaStructureError(
                F_REFERENCE_LIMIT,
                'REFERENCEORIGINAL nesting deeper than %d'
                % limits['max_reference_depth'], reader.pos)

        # Optional REFERENCENAME.
        if reader.remaining() >= 6 and reader.peek_u16() == 0x0016:
            name_record = _parse_reference_name(reader, records, codepage)
            reference['name'] = name_record['name']
            reference['name_unicode'] = name_record['name_unicode']
            evidence.append(name_record['evidence'])

        if reader.remaining() < 6:
            raise VbaStructureError(F_TRUNCATED_RECORD,
                                    'truncated REFERENCE record', reader.pos)
        record_id, size, start, end = _next_ref_record(reader, records)
        evidence.append({'record_id': record_id, 'offset': start,
                         'size': 2 + 4 + size})

        if record_id == 0x000D:  # REFERENCEREGISTERED
            reference['kind'] = 'registered'
            libid_size = reader.u32()
            reference['libid'] = _decode_mbcs(reader.take(libid_size),
                                               codepage)
            reader.u32()  # Reserved1
            reader.u16()  # Reserved2
        elif record_id == 0x000E:  # REFERENCEPROJECT
            reference['kind'] = 'project'
            abs_size = reader.u32()
            reference['libid_absolute'] = _decode_mbcs(
                reader.take(abs_size), codepage)
            rel_size = reader.u32()
            reference['libid_relative'] = _decode_mbcs(
                reader.take(rel_size), codepage)
            reference['major_version'] = reader.u32()
            reference['minor_version'] = reader.u16()
        elif record_id == 0x002F:  # REFERENCECONTROL
            reference['kind'] = 'control'
            reader.u32()  # SizeTwiddled (ignored on read)
            twiddled_size = reader.u32()
            reference['libid_twiddled'] = _decode_mbcs(
                reader.take(twiddled_size), codepage)
            reader.u32()  # Reserved1
            reader.u16()  # Reserved2
            # Optional NameRecordExtended.
            if reader.remaining() >= 6 and reader.peek_u16() == 0x0016:
                name_record = _parse_reference_name(reader, records,
                                                     codepage)
                if reference['name'] is None:
                    reference['name'] = name_record['name']
                    reference['name_unicode'] = name_record['name_unicode']
                evidence.append(name_record['evidence'])
            reader.u16()  # Reserved3 0x0030
            reader.u32()  # SizeExtended (ignored on read)
            extended_size = reader.u32()
            reference['libid_extended'] = _decode_mbcs(
                reader.take(extended_size), codepage)
            reader.u32()  # Reserved4
            reader.u16()  # Reserved5
            reference['original_typelib'] = _format_guid(reader.take(16))
            reference['cookie'] = reader.u32()
        elif record_id == 0x0033:  # REFERENCEORIGINAL + nested CONTROL
            reference['kind'] = 'original'
            original_size = reader.u32()
            reference['libid'] = _decode_mbcs(reader.take(original_size),
                                               codepage)
            if reader.remaining() < 6 or reader.peek_u16() != 0x002F:
                raise VbaStructureError(
                    F_UNKNOWN_RECORD,
                    'REFERENCEORIGINAL must be followed by '
                    'REFERENCECONTROL (0x002F)', reader.pos)
            nested, nested_issues, nested_stop = _parse_reference(
                reader, records, codepage, depth + 1, limits)
            reference['nested_control'] = nested
            issues.extend(nested_issues)
            stop = nested_stop
        else:
            note(F_UNKNOWN_RECORD,
                 'unknown reference record 0x%04X at offset %d'
                 % (record_id, start), SEVERITY_ERROR, start, record_id)
            stop = True
        reader.pos = end
    except VbaStructureError as exc:
        note(exc.code, str(exc), SEVERITY_ERROR, exc.offset)
        stop = True
    return reference, issues, stop


def _format_guid(guid_bytes):
    """Format 16 little-endian GUID bytes as the conventional string."""
    if len(guid_bytes) != 16:
        return None
    d1, d2, d3 = struct.unpack('<IHH', guid_bytes[:8])
    rest = guid_bytes[8:16]
    return '{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}' % (
        d1, d2, d3, rest[0], rest[1], rest[2], rest[3], rest[4], rest[5],
        rest[6], rest[7])


def _parse_module(reader, records, codepage, limits):
    """Parse one MODULE record (MS-OVBA 2.3.4.2.3.2)."""
    module = {
        'name': None,
        'name_unicode': None,
        'stream_name': None,
        'stream_name_unicode': None,
        'doc_string': None,
        'text_offset': None,
        'help_context': None,
        'cookie': None,
        'type': None,
        'readonly': False,
        'private': False,
        'dir_evidence': [],
        'stream': None,
        'source': None,
        'issues': [],
    }
    stop = False

    def note(code, message, severity, offset=-1, record_id=None):
        finding = _finding(code, message, severity, offset, record_id)
        module['issues'].append(finding)

    try:
        # MODULENAME (0x0019) is mandatory and first.
        record_id, size, start, end = _next_ref_record(reader, records)
        if record_id != 0x0019:
            note(F_UNKNOWN_RECORD,
                 'MODULE record starts with 0x%04X instead of MODULENAME'
                 % record_id, SEVERITY_ERROR, start, record_id)
            reader.pos = end
            return module, module['issues'], True
        module['name'] = _decode_mbcs(reader.take(size), codepage)
        module['dir_evidence'].append(
            {'record_id': record_id, 'offset': start,
             'size': 2 + 4 + size})
        reader.pos = end

        while True:
            if reader.remaining() < 6:
                note(F_TRUNCATED_RECORD,
                     'MODULE %r ends before MODULETERMINATOR' % module['name'],
                     SEVERITY_ERROR, reader.pos)
                stop = True
                break
            record_id, size, start, end = _next_ref_record(reader, records)
            module['dir_evidence'].append(
                {'record_id': record_id, 'offset': start,
                 'size': 2 + 4 + size})
            if record_id == 0x002B:  # MODULETERMINATOR
                if size != 0:
                    note(F_TRUNCATED_RECORD,
                         'MODULETERMINATOR size is %d, expected 0' % size,
                         SEVERITY_WARNING, start, record_id)
                reader.pos = end
                # 4 reserved bytes follow the terminator.
                if reader.remaining() < 4:
                    note(F_TRUNCATED_RECORD,
                         'MODULE %r missing 4 reserved bytes after terminator'
                         % module['name'], SEVERITY_ERROR, reader.pos)
                    stop = True
                else:
                    reader.take(4)
                break
            if record_id == 0x0047:  # MODULENAMEUNICODE
                module['name_unicode'] = _decode_utf16(reader.take(size))
            elif record_id == 0x001A:  # MODULESTREAMNAME
                mbcs, _res, uni = reader.read_string_with_unicode()
                module['stream_name'] = _decode_mbcs(mbcs, codepage)
                module['stream_name_unicode'] = _decode_utf16(uni)
            elif record_id == 0x001C:  # MODULEDOCSTRING
                mbcs, _res, _uni = reader.read_string_with_unicode()
                module['doc_string'] = _decode_mbcs(mbcs, codepage)
            elif record_id == 0x0031:  # MODULEOFFSET
                module['text_offset'] = reader.u32()
            elif record_id == 0x001E:  # MODULEHELPCONTEXT
                module['help_context'] = reader.u32()
            elif record_id == 0x002C:  # MODULECOOKIE
                module['cookie'] = reader.u16()
            elif record_id in (0x0021, 0x0022):  # MODULETYPE
                reader.u32()  # reserved
                module['type'] = ('procedural' if record_id == 0x0021
                                  else 'document/class/designer')
            elif record_id == 0x0025:  # MODULEREADONLY
                reader.u32()
                module['readonly'] = True
            elif record_id == 0x0028:  # MODULEPRIVATE
                reader.u32()
                module['private'] = True
            else:
                note(F_UNKNOWN_RECORD,
                     'unknown record 0x%04X at offset %d inside MODULE %r'
                     % (record_id, start, module['name']), SEVERITY_ERROR,
                     start, record_id)
                stop = True
                reader.pos = end
                break
            reader.pos = end
    except VbaStructureError as exc:
        note(exc.code, str(exc), SEVERITY_ERROR, exc.offset)
        stop = True
    return module, module['issues'], stop


def _decode_utf16(data):
    try:
        return data.decode('utf-16-le', errors='replace')
    except Exception:
        return None


def _finding(code, message, severity, offset=-1, record_id=None):
    return {
        'code': code,
        'message': message,
        'severity': severity,
        'dir_offset': offset,
        'record_id': record_id,
    }


# ===--------------------------------------------------------------------===
# High-level static inventory built from an OLE/CFB file
# ===--------------------------------------------------------------------===

def default_limits():
    """Return a fresh copy of the default resource limits."""
    return {
        'max_decompressed': DEFAULT_MAX_DECOMPRESSED,
        'max_records': DEFAULT_MAX_RECORDS,
        'max_modules': DEFAULT_MAX_MODULES,
        'max_references': DEFAULT_MAX_REFERENCES,
        'max_reference_depth': DEFAULT_MAX_REFERENCE_DEPTH,
        'source_preview': DEFAULT_SOURCE_PREVIEW,
    }


class VbaInventory(object):
    """
    Static inventory of the VBA project(s) in an OLE file.

    The inventory only reports structural evidence parsed from the
    compressed ``dir`` stream and cross-checked against the real Module
    Streams.  It never executes macros and never reports a file as malicious
    based on its name or on source strings.

    Attributes:
        vba_storage_path: list of path components of the VBA storage, or None
        codepage: PROJECTCODEPAGE value (or None when absent)
        codepage_encoding: Python codec name derived from the code page
        project: project-level PROJECTINFORMATION evidence
        modules: list of module inventories, each with dir evidence and the
            correlated stream range
        references: list of external REFERENCE records with dir evidence
        records: every record interpreted in the decompressed dir stream
            (record id, name and byte range in the decompressed stream)
        issues: structural findings (see the ``F_*`` finding codes)
        complete: True only when no limit, unknown record or structural
            error prevented a full interpretation of the dir stream
        limits: resource limits actually applied
    """

    def __init__(self, vba_storage_path=None, project=None, modules=None,
                 references=None, records=None, issues=None, complete=False,
                 limits=None, dir_stream=None, storage_streams=None):
        self.vba_storage_path = vba_storage_path
        self.project = project or {}
        self.modules = modules or []
        self.references = references or []
        self.records = records or []
        self.issues = issues or []
        self.complete = complete
        self.limits = limits or default_limits()
        self.codepage = self.project.get('codepage')
        self.codepage_encoding = self.project.get('codepage_encoding')
        self.dir_stream = dir_stream
        self.storage_streams = storage_streams or []

    @property
    def has_vba_project(self):
        """True when a VBA storage containing a dir stream was found."""
        return self.vba_storage_path is not None

    def findings_by_code(self, code):
        """Return all findings (project-level and per-module) with ``code``."""
        result = list(self.issues)
        for module in self.modules:
            result.extend(module.get('issues', []))
        for reference in self.references:
            result.extend(reference.get('issues', []))
        return [finding for finding in result if finding['code'] == code]

    def to_dict(self):
        """Return a plain-dict representation suitable for JSON output."""
        return {
            'has_vba_project': self.has_vba_project,
            'complete': self.complete,
            'vba_storage_path': self.vba_storage_path,
            'dir_stream': self.dir_stream,
            'codepage': self.codepage,
            'codepage_encoding': self.codepage_encoding,
            'project': self.project,
            'references': self.references,
            'modules': self.modules,
            'records': self.records,
            'issues': self.issues,
            'limits': self.limits,
            'storage_streams': self.storage_streams,
        }

    def to_text(self):
        """Return a human-readable, line-oriented rendering of the inventory."""
        lines = []
        if not self.has_vba_project:
            lines.append('No VBA storage found.')
            return '\n'.join(lines)
        lines.append('VBA storage: %s' % '/'.join(self.vba_storage_path))
        lines.append('Complete inventory: %s' % self.complete)
        if self.codepage is not None:
            lines.append('PROJECTCODEPAGE: %d (%s)'
                         % (self.codepage, self.codepage_encoding))
        if self.project.get('name') is not None:
            lines.append('PROJECTNAME: %s' % self.project['name'])
        lines.append('References: %d' % len(self.references))
        for reference in self.references:
            lines.append('  - [%s] name=%r libid=%r'
                         % (reference['kind'], reference.get('name'),
                            reference.get('libid')
                            or reference.get('libid_absolute')))
        lines.append('Modules: %d (declared: %s)'
                     % (len(self.modules),
                        self.project.get('declared_module_count')))
        for module in self.modules:
            stream = module.get('stream')
            if stream is None:
                stream_desc = 'STREAM MISSING'
            else:
                source_range = stream.get('source_range')
                if source_range is None:
                    stream_desc = ('stream=%r size=%d source_range=n/a'
                                   % (stream['name'], stream['size']))
                else:
                    stream_desc = ('stream=%r size=%d source_range=[%d:%d]'
                                   % (stream['name'], stream['size'],
                                      source_range[0], source_range[1]))
            lines.append('  - module=%r %s text_offset=%r type=%s'
                         % (module.get('name'), stream_desc,
                            module.get('text_offset'), module.get('type')))
        all_findings = []
        all_findings.extend(self.issues)
        for module in self.modules:
            for finding in module.get('issues', []):
                all_findings.append(dict(finding,
                                         module=module.get('name')))
        lines.append('Findings: %d' % len(all_findings))
        for finding in all_findings:
            prefix = '  - '
            if 'module' in finding and finding['module'] is not None:
                prefix = '  - [%s] ' % finding['module']
            lines.append('%s%s: %s (dir_offset=%s)'
                         % (prefix, finding['severity'], finding['message'],
                            finding['dir_offset']))
        return '\n'.join(lines)


def vba_inventory(ole, limits=None):
    """
    Build a static :class:`VbaInventory` from an open :class:`OleFileIO`.

    :param ole: an :class:`OleFileIO` opened on the document to inspect.  The
        caller owns the object and is responsible for closing it.
    :param dict limits: optional overrides for the resource limits; see
        :func:`default_limits`
    :return: :class:`VbaInventory`
    """
    # Duck typing instead of isinstance(): when olefile is executed as a
    # script (``python -m olefile.olefile``) the module can be imported under
    # two names, so identity checks against the class object can fail even
    # though the same object is passed in.
    for attribute in ('exists', 'openstream', 'get_size', 'listdir'):
        if not hasattr(ole, attribute):
            raise TypeError(
                'ole must be an open olefile.OleFileIO-like object')
    effective_limits = default_limits()
    if limits:
        for key, value in limits.items():
            if key not in effective_limits:
                raise ValueError('unknown limit %r' % key)
            effective_limits[key] = value

    issues = []
    vba_path = _find_vba_storage(ole)
    if vba_path is None:
        return VbaInventory(issues=issues, complete=True,
                            limits=effective_limits)

    # Enumerate every stream inside the VBA storage so that module mappings
    # can be checked against the streams that actually exist.
    storage_streams = _list_storage_streams(ole, vba_path)
    streams_by_lower = {}
    for entry in storage_streams:
        streams_by_lower.setdefault(entry['name'].lower(), []).append(entry)

    dir_path = vba_path + ['dir']
    if not ole.exists(dir_path):
        issues.append(_finding(
            F_NO_DIR_STREAM,
            'VBA storage %r contains no dir stream' % '/'.join(vba_path),
            SEVERITY_ERROR))
        return VbaInventory(vba_storage_path=vba_path, issues=issues,
                            complete=False, limits=effective_limits,
                            storage_streams=storage_streams)

    dir_size = ole.get_size(dir_path)
    dir_raw = ole.openstream(dir_path).read()
    dir_evidence = {'name': '/'.join(dir_path), 'compressed_size': dir_size}
    try:
        dir_data = decompress_container(
            dir_raw, max_output=effective_limits['max_decompressed'])
    except VbaCompressionError as exc:
        issues.append(_finding(
            F_DIR_COMPRESSION,
            'cannot decompress dir stream: %s' % exc, SEVERITY_ERROR,
            exc.offset))
        return VbaInventory(vba_storage_path=vba_path, issues=issues,
                            complete=False, limits=effective_limits,
                            dir_stream=dir_evidence,
                            storage_streams=storage_streams)
    dir_evidence['decompressed_size'] = len(dir_data)

    project, references, modules, records, parse_issues = \
        _parse_dir_stream_strict(dir_data, effective_limits)
    issues.extend(parse_issues)

    _correlate_modules(ole, vba_path, modules, streams_by_lower,
                       storage_streams, effective_limits, issues,
                       project.get('codepage_encoding'))

    # A finding on any module or reference also means the inventory cannot
    # be presented as the result of an unbroken full interpretation.
    incomplete = any(
        module.get('issues') for module in modules) or any(
        reference.get('issues') for reference in references)
    complete = project.get('project_information_complete', False) \
        and not incomplete and not issues

    return VbaInventory(vba_storage_path=vba_path, project=project,
                        modules=modules, references=references,
                        records=records, issues=issues, complete=complete,
                        limits=effective_limits, dir_stream=dir_evidence,
                        storage_streams=storage_streams)


def _find_vba_storage(ole):
    """Return the path of the VBA storage (case-insensitive) or None."""
    for path in ole.listdir(streams=False, storages=True):
        if len(path) == 1 and path[0].lower() == 'vba':
            return path
    # Some hosts nest the VBA storage (e.g. "Macros/VBA"); accept any storage
    # whose final component is "VBA" and which contains a dir stream.
    for path in ole.listdir(streams=False, storages=True):
        if path[-1].lower() == 'vba' and ole.exists(path + ['dir']):
            return path
    return None


def _list_storage_streams(ole, storage_path):
    """List immediate stream children of a storage with their sizes."""
    result = []
    prefix_len = len(storage_path)
    for path in ole.listdir(streams=True, storages=False):
        if len(path) == prefix_len + 1 and \
                path[:prefix_len] == storage_path:
            name = path[-1]
            result.append({
                'name': name,
                'path': path,
                'size': ole.get_size(path),
            })
    return result


def _correlate_modules(ole, vba_path, modules, streams_by_lower,
                       storage_streams, limits, issues, source_encoding):
    """
    Cross-check every MODULE record against the real Module Streams.

    Checks implemented here:
      * stream named by MODULESTREAMNAME exists;
      * two MODULE records do not map to the same stream;
      * MODULEOFFSET lies inside the stream and leaves a non-empty
        CompressedSourceCode region;
      * the CompressedSourceCode region is a valid CompressedContainer and
        copy tokens stay in bounds;
      * streams of the VBA storage that no module references are reported as
        orphans (ignoring spec-mandated non-module streams).
    """
    referenced_names = set()
    for module in modules:
        stream_name = module.get('stream_name')
        if not stream_name:
            module['issues'].append(_finding(
                F_MODULE_STREAM_MISSING,
                'MODULE %r has no MODULESTREAMNAME record'
                % module.get('name'), SEVERITY_ERROR))
            continue
        key = stream_name.lower()
        referenced_names.add(key)
        candidates = streams_by_lower.get(key)
        if not candidates:
            module['issues'].append(_finding(
                F_MODULE_STREAM_MISSING,
                'dir stream names module stream %r for module %r but no such '
                'stream exists in the VBA storage'
                % (stream_name, module.get('name')), SEVERITY_ERROR))
            continue
        if len(candidates) > 1:
            # Cannot happen through olefile's duplicate-name check at one
            # storage level, but keep the explicit guard for evidence.
            module['issues'].append(_finding(
                F_DUPLICATE_STREAM_MAPPING,
                'stream name %r resolves to %d directory entries'
                % (stream_name, len(candidates)), SEVERITY_ERROR))
        stream_entry = candidates[0]
        stream_path = stream_entry['path']
        stream_size = stream_entry['size']
        text_offset = module.get('text_offset')

        stream_info = {
            'name': stream_name,
            'path': '/'.join(stream_path),
            'size': stream_size,
            'text_offset': text_offset,
            'performance_cache_range': None,
            'source_range': None,
            'compressed_signature_ok': False,
            'decompressed_source_size': None,
            'source_preview': None,
            'source_truncated': False,
        }

        if text_offset is None:
            module['issues'].append(_finding(
                F_OFFSET_OUT_OF_RANGE,
                'module %r has no MODULEOFFSET record' % module.get('name'),
                SEVERITY_ERROR))
            module['stream'] = stream_info
            continue
        if text_offset < 0 or text_offset > stream_size:
            module['issues'].append(_finding(
                F_OFFSET_OUT_OF_RANGE,
                'MODULEOFFSET %d is outside module stream %r of size %d'
                % (text_offset, stream_name, stream_size), SEVERITY_ERROR))
            module['stream'] = stream_info
            continue
        if text_offset == stream_size:
            module['issues'].append(_finding(
                F_NO_COMPRESSED_SOURCE,
                'MODULEOFFSET %d points at the end of stream %r (size %d); '
                'no CompressedSourceCode bytes remain'
                % (text_offset, stream_name, stream_size), SEVERITY_ERROR))
            module['stream'] = stream_info
            continue

        stream_info['performance_cache_range'] = [0, text_offset]
        stream_info['source_range'] = [text_offset, stream_size]
        raw = ole.openstream(stream_path).read()
        compressed_source = raw[text_offset:]
        if not compressed_source or \
                bytevalue(compressed_source, 0) != 0x01:
            module['issues'].append(_finding(
                F_NO_COMPRESSED_SOURCE,
                'CompressedSourceCode of stream %r does not start with the '
                '0x01 signature byte' % stream_name, SEVERITY_ERROR))
            module['stream'] = stream_info
            continue
        stream_info['compressed_signature_ok'] = True
        try:
            source = decompress_container(
                compressed_source,
                max_output=limits['max_decompressed'])
        except VbaCompressionError as exc:
            module['issues'].append(_finding(
                F_MODULE_COMPRESSION,
                'cannot decompress source of module %r: %s'
                % (module.get('name'), exc), SEVERITY_ERROR, exc.offset))
            module['stream'] = stream_info
            continue
        stream_info['decompressed_source_size'] = len(source)
        preview_limit = limits['source_preview']
        if len(source) > preview_limit:
            stream_info['source_truncated'] = True
        stream_info['source_preview'] = _decode_source_preview(
            source, source_encoding, preview_limit)
        module['source'] = {
            'decompressed_size': len(source),
            'preview': stream_info['source_preview'],
            'preview_truncated': stream_info['source_truncated'],
            'encoding': source_encoding,
        }
        module['stream'] = stream_info

    # Duplicate mapping: several MODULE records pointing at one stream.
    seen = {}
    for module in modules:
        stream_name = module.get('stream_name')
        if not stream_name:
            continue
        key = stream_name.lower()
        if key in seen:
            finding = _finding(
                F_DUPLICATE_STREAM_MAPPING,
                'modules %r and %r both map to stream %r'
                % (seen[key], module.get('name'), stream_name),
                SEVERITY_ERROR)
            module['issues'].append(finding)
        else:
            seen[key] = module.get('name')

    # Orphan streams inside the VBA storage (spec-mandated streams excluded).
    known_non_module = set(
        name.lower() for name in ('_VBA_PROJECT', 'dir', 'PROJECT',
                                  'PROJECTwm', 'PROJECTlk'))
    for entry in storage_streams:
        name = entry['name']
        key = name.lower()
        if key in referenced_names or key in known_non_module:
            continue
        if key.startswith('__srp_'):
            continue
        issues.append(_finding(
            F_ORPHAN_STREAM,
            'stream %r in the VBA storage is not referenced by any MODULE '
            'record' % name, SEVERITY_INFO))


def _decode_source_preview(source, encoding, preview_limit):
    """Decode a bounded prefix of the module source using its code page."""
    preview_bytes = source[:preview_limit]
    if encoding is None:
        return None
    try:
        return preview_bytes.decode(encoding, errors='replace')
    except LookupError:
        return None
