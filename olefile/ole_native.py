"""
Read-only parsing of OLE 1.0 native data stored in ``\\x01Ole10Native``.

An OLE Package object is a storage containing a stream named
``"\\x01Ole10Native"``.  The stream starts with an OLENativeStream structure
(see [MS-OLEDS] 2.3.6) followed by the native bytes of the embedded object.
The display name, source path and temporary path in that structure are all
chosen by the document author: they are metadata, not a content type and not
a trusted file name.

This module only parses bytes that the caller already read from an OLE
container.  It does not resolve links, does not execute embedded objects and
does not write files.  In particular, none of the names found in the stream is
ever used as a filesystem path.

The public entry points are:

``parse_ole10native(data)``
    Parse the bytes of one ``\\x01Ole10Native`` stream.

``open_ole10native(ole, path)``
    Read one stream through an :class:`olefile.OleFileIO` instance and add
    container evidence (stream path, storage CLSID, declared stream size).

``find_ole10native_streams(ole)``
    List the paths of all ``\\x01Ole10Native`` streams in a container.

``iter_ole10native(ole)``
    Iterate over all packages in a container.

The parser keeps the following distinctions explicit:

* the declared outer length and the bytes actually available;
* the declared native-data length and the bytes actually available;
* the native-data range and any trailing bytes after it;
* the self-reported display name/source path and the native bytes, from which
  the caller can independently compute a digest.
"""

from __future__ import unicode_literals

import hashlib
import struct

__all__ = [
    'OLE10NATIVE_STREAM_NAME',
    'OLE10NATIVE_FORMAT_LINKED',
    'OLE10NATIVE_FORMAT_EMBEDDED',
    'OLE10NATIVE_PACKAGE_CLSID',
    'Ole10Native',
    'Ole10NativeStream',
    'OleNativeStream',
    'Ole10NativeIssue',
    'OleNative',
    'parse_ole10native',
    'parse_ole10native_dict',
    'parse_ole10native_stream',
    'open_ole10native',
    'find_ole10native_streams',
    'iter_ole10native',
]

#: Name of the stream used by OLE Package objects (case-insensitive lookup).
OLE10NATIVE_STREAM_NAME = '\x01Ole10Native'

#: CLSID of the OLE Package storage class (MS-OLEDS).  This identifies the
#: container class, not the type of the native bytes.
OLE10NATIVE_PACKAGE_CLSID = '0003000C-0000-0000-C000-000000000046'

#: OLENativeStream FormatID values (MS-OLEDS 2.2.4).
OLE10NATIVE_FORMAT_LINKED = 0x0001
OLE10NATIVE_FORMAT_EMBEDDED = 0x0002

# Flags used by the optional ``\x01Ole`` stream in the same storage.
_OLE_STREAM_FLAG_LINKED = 0x00000001

_SELF_REPORTED_NOTE = (
    'Value is self-reported by the document/package author. It is not a '
    'content type, not a filesystem path to use, and must not be trusted.'
)

# Byte signatures used only to describe the native bytes.  This information is
# deliberately independent from the display name extension.
_NATIVE_SIGNATURES = (
    (b'MZ', 'DOS/PE executable'),
    (b'\x7fELF', 'ELF executable'),
    (b'PK\x03\x04', 'ZIP container'),
    (b'PK\x05\x06', 'ZIP container (empty)'),
    (b'%PDF-', 'PDF document'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'OLE compound file'),
    (b'{\\rtf', 'RTF document'),
    (b'\x89PNG\r\n\x1a\n', 'PNG image'),
    (b'GIF87a', 'GIF image'),
    (b'GIF89a', 'GIF image'),
    (b'Rar!\x1a\x07', 'RAR archive'),
    (b'7z\xbc\xaf\x27\x1c', '7-Zip archive'),
)


def _hex(raw):
    if raw is None:
        return None
    try:
        return raw.hex()
    except AttributeError:  # Python 2
        return ''.join('%02x' % byte for byte in bytearray(raw))


def _u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def _as_text(raw):
    """Decode an ANSI-ish byte string reversibly for display.

    The code page of OLENativeStream strings is not recorded in the stream.
    Latin-1 is used so that every byte is preserved and callers that need the
    original bytes can use the matching ``*_raw`` attribute.
    """
    if raw is None:
        return None
    return raw.decode('latin-1')


def _decode_utf16(raw):
    if raw is None:
        return None
    return raw.decode('utf-16-le', 'replace')


class Ole10NativeIssue(object):
    """One piece of parsing evidence.

    ``code`` is stable and machine-readable, ``message`` is for humans and
    ``offset``/``length`` locate the bytes concerned (relative to the stream).
    ``declared`` and ``available`` are filled for length-related issues.
    """

    __slots__ = ('code', 'message', 'severity', 'offset', 'length',
                 'declared', 'available')

    def __init__(self, code, message, severity='warning', offset=None,
                 length=None, declared=None, available=None):
        self.code = code
        self.message = message
        self.severity = severity
        self.offset = offset
        self.length = length
        self.declared = declared
        self.available = available

    def as_dict(self):
        return {
            'code': self.code,
            'message': self.message,
            'severity': self.severity,
            'offset': self.offset,
            'length': self.length,
            'declared': self.declared,
            'available': self.available,
        }

    def __repr__(self):
        return 'Ole10NativeIssue(%r, severity=%r, offset=%r, length=%r)' % (
            self.code, self.severity, self.offset, self.length)


class Ole10Native(object):
    """Read-only view of an OLENativeStream structure.

    The object is built from the payload of a ``\\x01Ole10Native`` stream.
    It never owns a file handle and never writes anything.

    Important attributes:

    ``stream_path`` / ``stream_size``
        Path inside the OLE container and the number of stream bytes read.
    ``declared_form``
        ``'linked'`` (FormatID 1), ``'embedded'`` (FormatID 2) or
        ``'unknown'``.  This is the form declared by the stream.
    ``effective_form``
        ``'linked'`` when no native payload length is present, otherwise
        ``'embedded'``.  This exposes FormatID 2 packages that only contain a
        reference path and no native bytes.
    ``display_name`` / ``source_path`` / ``temp_path``
        Best-effort Latin-1 decoding of self-reported strings.
    ``display_name_raw`` / ``source_path_raw`` / ``temp_path_raw``
        Exact bytes of those strings, without their terminating NUL.
    ``declared_container_length``
        The leading NativeDataSize field (length of everything after it).
    ``native_data_declared_length``
        The length field immediately before the native bytes.
    ``native_data``
        Available native bytes, as a bytes object.  When
        ``native_data_complete`` is False this is only the available prefix;
        the declared range is still recorded in ``native_data_range``.
    ``native_data_range``
        Declared ``(start, end)`` byte range of native data in the stream.
    ``native_data_available_range``
        Range actually present in the stream.
    ``trailer``
        Bytes between the end of the declared native data and the end of the
        declared container region.  Empty when no such bytes exist.
    ``outer_trailer``
        Bytes after ``4 + declared_container_length`` (data outside the
        declared OLENativeStream structure).
    ``issues``
        List of :class:`Ole10NativeIssue` evidence records.

    The display name is *not* a content type.  Use ``native_data`` to compute
    a digest or inspect bytes; ``native_content_hint`` is derived only from
    the native bytes.
    """

    # Compatible names for callers familiar with python-oletools.
    TYPE_LINKED = OLE10NATIVE_FORMAT_LINKED
    TYPE_EMBEDDED = OLE10NATIVE_FORMAT_EMBEDDED

    def __init__(self, data=None, stream_path=None, container_clsid=None,
                 storage_path=None, stream_declared_size=None,
                 bindata=None, package=None):
        self.stream_path = _path_list(stream_path)
        self.storage_path = _path_list(storage_path)
        if self.storage_path is None and self.stream_path:
            self.storage_path = self.stream_path[:-1]
        self.container_clsid = container_clsid
        self.stream_declared_size = stream_declared_size
        if data is None and bindata is not None:
            data = bindata
        if package:
            raise ValueError(
                'package=True (an OLE1.0 Package object without a leading '
                'NativeDataSize) is not an Ole10Native stream; use '
                'parse_ole10native on the OLENativeStream payload instead')
        self.raw_data = None
        self.reset()
        if data is not None:
            self.parse(data)

    def reset(self):
        self.raw_data = None
        self.stream_size = None
        self.issues = []

        self.declared_container_length = None
        self.container_region_end = None
        self.container_length_complete = None
        self.container_data_offset = None
        self.outer_trailer = b''
        self.outer_trailer_offset = None
        self.outer_trailer_length = 0

        self.format_id = None
        self.declared_form = None
        self.effective_form = None
        self.layout_variant = None
        self.marker_value = None

        self.display_name_raw = None
        self.display_name = None
        self.display_name_complete = None
        self.source_path_raw = None
        self.source_path = None
        self.source_path_complete = None
        self.temp_path_raw = None
        self.temp_path = None
        self.temp_path_complete = None
        self.temp_path_flag = None

        self.has_native_data = False
        self.native_data_declared_length = None
        self.native_data_available_length = None
        self.native_data_offset = None
        self.native_data = None
        self.native_data_complete = None
        self.native_data_range = None
        self.native_data_available_range = None
        self.native_data_ambiguous_suffix = False

        self.trailer = b''
        self.trailer_offset = None
        self.trailer_length = 0
        self.trailer_complete = None
        self.trailer_blocks = []
        self.trailer_texts = []

        self.ole_stream_seen = False
        self.ole_stream_flags = None
        self.ole_stream_declared_linked = None

        self.header_complete = False

    # -- public helpers ---------------------------------------------------

    @property
    def is_linked(self):
        """True when there is no native payload (reference-only form)."""
        return self.effective_form == 'linked'

    @property
    def is_embedded(self):
        """True when a native payload length field was present."""
        return self.effective_form == 'embedded'

    @property
    def is_link(self):
        return self.is_linked

    # Aliases matching common Ole10Native parser attribute names.  All names
    # below are metadata from the stream, never a trusted file path.
    @property
    def filename(self):
        return self.display_name

    @property
    def src_path(self):
        return self.source_path

    @property
    def native_data_size(self):
        return self.declared_container_length

    @property
    def actual_size(self):
        return self.native_data_declared_length

    @property
    def declared_length(self):
        """Declared length of the native data (inner length field)."""
        return self.native_data_declared_length

    @property
    def data_offset(self):
        return self.native_data_offset

    @property
    def trailing_data(self):
        """Bytes after the declared native data, kept as evidence."""
        return self.trailer

    @property
    def data(self):
        return self.native_data

    @property
    def unknown_short(self):
        return self.format_id

    @property
    def link_target(self):
        """Self-reported source path of a reference-only object.

        No attempt is made to resolve, open or contact this path.
        """
        if self.is_linked:
            return self.source_path
        return None

    @property
    def reported_names(self):
        return {
            'display_name': self.display_name,
            'source_path': self.source_path,
            'temp_path': self.temp_path,
        }

    @property
    def original_path(self):
        """Alias of ``source_path`` (self-reported, untrusted)."""
        return self.source_path

    @property
    def native_range(self):
        """Alias of ``native_data_range``."""
        return self.native_data_range

    @property
    def declared_size(self):
        """Alias of ``declared_container_length``."""
        return self.declared_container_length

    @property
    def native_data_end(self):
        """End offset of the declared native-data range, or None."""
        if self.native_data_range is None:
            return None
        return self.native_data_range[1]

    @property
    def digest_covers(self):
        """Describe what :meth:`digest` hashes.

        Always ``'available_native_data'`` when bytes are present; callers must
        check ``native_data_complete`` to know whether that equals the declared
        range.
        """
        if self.native_data is None:
            return None
        return 'available_native_data'

    @property
    def native_data_sha256(self):
        """SHA-256 of the available native bytes, or None.

        Callers that need an independent digest can instead use
        ``hashlib.sha256(pkg.native_data).hexdigest()``; the bytes are exposed
        unchanged for that purpose.
        """
        if self.native_data is None:
            return None
        return hashlib.sha256(self.native_data).hexdigest()

    def digest(self, name='sha256'):
        """Return a hexadecimal digest over the available native bytes."""
        if self.native_data is None:
            return None
        try:
            h = hashlib.new(name)
        except ValueError:
            raise ValueError('unsupported hash algorithm: %r' % (name,))
        h.update(self.native_data)
        return h.hexdigest()

    @property
    def native_magic(self):
        """First 16 native bytes as hex (evidence, not a type claim)."""
        if not self.native_data:
            return None
        return _hex(self.native_data[:16])

    @property
    def native_content_hint(self):
        """Best-effort description derived only from native bytes.

        This intentionally never consults ``display_name``.
        """
        if not self.native_data:
            return None
        for signature, description in _NATIVE_SIGNATURES:
            if self.native_data.startswith(signature):
                return description
        return 'unknown (no known signature in native bytes)'

    @property
    def names_are_self_reported(self):
        """Always True: display/source/temp names are untrusted metadata."""
        return True

    @property
    def content_type(self):
        """Type description derived only from native bytes.

        Never derived from the display name or its extension.  ``None`` when
        no native payload is present.
        """
        return self.native_content_hint

    @property
    def content_type_source(self):
        return 'native_bytes' if self.native_data else None

    @property
    def reported_type_hint(self):
        """Extension from the self-reported name (untrusted, not a type)."""
        return self.reported_extension

    @property
    def reported_extension(self):
        """Extension from the self-reported display name.

        Exposed only to show that the name was recorded; it is not a content
        type.  ``native_content_hint`` is the byte-based alternative.
        """
        if not self.display_name_raw:
            return None
        name = self.display_name_raw
        if b'.' not in name:
            return None
        return name.rsplit(b'.', 1)[1].decode('latin-1').lower()

    # -- parser -----------------------------------------------------------

    def _issue(self, code, message, severity='warning', offset=None,
               length=None, declared=None, available=None):
        self.issues.append(Ole10NativeIssue(
            code, message, severity=severity, offset=offset, length=length,
            declared=declared, available=available))

    @property
    def errors(self):
        """Issues that contradict the declared structure (severity error)."""
        return [issue for issue in self.issues if issue.severity == 'error']

    @property
    def warnings(self):
        return [issue for issue in self.issues if issue.severity == 'warning']

    @property
    def is_consistent(self):
        """True when no structural error was found.

        Optional trailing metadata and informational records do not make a
        package inconsistent.  When false, ``native_data_complete`` and the
        other completeness flags describe what could be read.
        """
        return not self.errors

    @property
    def container_is_package(self):
        """True when the containing storage CLSID is the Package class."""
        return (self.container_clsid or '').upper() == OLE10NATIVE_PACKAGE_CLSID

    @property
    def effective_form_basis(self):
        if self.format_id == OLE10NATIVE_FORMAT_LINKED:
            return 'format_id_linked'
        if self.native_data_declared_length is not None:
            return 'native_data_length_present'
        if self.format_id == OLE10NATIVE_FORMAT_EMBEDDED:
            return 'format_id_embedded_without_native_length'
        return 'unknown_format'

    def _read_cstring(self, offset, limit, role):
        """Read a NUL-terminated byte string within [offset, limit)."""
        if offset >= limit:
            self._issue('missing_field', 'No bytes available for %s' % role,
                        severity='error', offset=offset, available=0)
            return b'', offset, False
        end = self.raw_data.find(b'\x00', offset, limit)
        if end < 0:
            raw = self.raw_data[offset:limit]
            self._issue('unterminated_string',
                        '%s has no NUL terminator before the end of the '
                        'declared region' % role,
                        severity='error', offset=offset, length=len(raw))
            return raw, limit, False
        return self.raw_data[offset:end], end + 1, True

    def _string_from_length_prefix(self, offset, limit, role):
        """Read a uint32 length followed by that many bytes.

        The length is expected to include the terminating NUL when present.
        Returns (value_without_NUL, next_offset, complete).
        """
        if offset + 4 > limit:
            self._issue('missing_field',
                        'No length field available for %s' % role,
                        severity='error', offset=offset,
                        available=max(0, limit - offset))
            return b'', offset, False
        declared = _u32(self.raw_data, offset)
        offset += 4
        available = max(0, limit - offset)
        if declared > available:
            raw = self.raw_data[offset:limit]
            self._issue('string_length_exceeds_stream',
                        '%s length %d exceeds the %d available bytes' %
                        (role, declared, available),
                        severity='error', offset=offset, length=available,
                        declared=declared, available=available)
            return self._strip_nul(raw, role, offset, complete=False), limit, False
        raw = self.raw_data[offset:offset + declared]
        complete = True
        nul = raw.find(b'\x00')
        if nul < 0:
            self._issue('unterminated_string',
                        '%s has a length but no NUL terminator' % role,
                        severity='error', offset=offset, length=len(raw))
            complete = False
        elif nul != len(raw) - 1:
            self._issue('string_bytes_after_terminator',
                        '%s has %d byte(s) after the NUL terminator' %
                        (role, len(raw) - nul - 1),
                        offset=offset + nul + 1, length=len(raw) - nul - 1)
        return self._strip_nul(raw, role, offset, complete=complete), \
            offset + declared, complete

    def _strip_nul(self, raw, role, offset, complete):
        nul = raw.find(b'\x00')
        if nul < 0:
            return raw
        return raw[:nul]

    def parse(self, data):
        """Parse the payload of one ``\\x01Ole10Native`` stream.

        ``data`` may be bytes, bytearray, memoryview or a readable file-like
        object.  A stream is read once, in memory; nothing is written.
        """
        self.reset()
        if hasattr(data, 'read'):
            data = data.read()
        if isinstance(data, memoryview):
            data = bytes(bytearray(data))
        self.raw_data = bytes(data)
        self.stream_size = len(self.raw_data)
        limit = self.stream_size

        if limit < 4:
            self._issue('truncated_header',
                        'OLENativeStream is shorter than NativeDataSize',
                        severity='error', offset=0, length=limit)
            return self

        # Leading NativeDataSize covers everything after the four-byte field.
        self.declared_container_length = _u32(self.raw_data, 0)
        self.container_data_offset = 4
        declared_end = 4 + self.declared_container_length
        available = max(0, limit - 4)
        if self.declared_container_length > available:
            self.container_length_complete = False
            self.container_region_end = limit
            self._issue('container_length_exceeds_stream',
                        'NativeDataSize %d exceeds the %d available bytes' %
                        (self.declared_container_length, available),
                        severity='error', offset=0, length=4,
                        declared=self.declared_container_length,
                        available=available)
        elif self.declared_container_length < available:
            self.container_length_complete = True
            self.container_region_end = declared_end
            self.outer_trailer_offset = declared_end
            self.outer_trailer = self.raw_data[declared_end:]
            self.outer_trailer_length = len(self.outer_trailer)
            self._issue('trailing_data_outside_container_length',
                        '%d byte(s) follow the declared OLENativeStream '
                        'region' % self.outer_trailer_length,
                        offset=declared_end, length=self.outer_trailer_length,
                        declared=self.declared_container_length,
                        available=available)
        else:
            self.container_length_complete = True
            self.container_region_end = declared_end

        end = self.container_region_end
        pos = 4

        if pos + 2 > end:
            self._issue('truncated_header',
                        'FormatID is outside the declared region',
                        severity='error', offset=pos,
                        available=max(0, end - pos))
            return self
        self.format_id = _u16(self.raw_data, pos)
        pos += 2
        if self.format_id == OLE10NATIVE_FORMAT_LINKED:
            self.declared_form = 'linked'
        elif self.format_id == OLE10NATIVE_FORMAT_EMBEDDED:
            self.declared_form = 'embedded'
        else:
            self.declared_form = 'unknown'
            self._issue('invalid_format_id',
                        'FormatID is %d, expected 1 (linked) or 2 (embedded)' %
                        self.format_id, severity='error', offset=pos - 2,
                        length=2)

        self.display_name_raw, pos, self.display_name_complete = \
            self._read_cstring(pos, end, 'display name')
        self.display_name = _as_text(self.display_name_raw)

        self.source_path_raw, pos, self.source_path_complete = \
            self._read_cstring(pos, end, 'source path')
        self.source_path = _as_text(self.source_path_raw)

        if not (self.display_name_complete and self.source_path_complete):
            # Later fields cannot be located reliably; keep the evidence we
            # have instead of guessing where the next field begins.
            self._set_effective_form()
            return self

        # The optional temp-path region has two observed shapes:
        #   marker 0x00030000, uint32 length, bytes (embedded packages)
        #   marker 0x00010000/0x00020000, uint16 flag, C string (link packages)
        marker = None
        if pos + 4 <= end:
            marker = _u32(self.raw_data, pos)
        if marker in (0x00010000, 0x00020000, 0x00030000):
            self.marker_value = marker
            subtype = (marker >> 16) & 0xFFFF
            self.layout_variant = 'marker-%d' % subtype
            pos += 4
            if subtype == 3:
                self.temp_path_raw, pos, self.temp_path_complete = \
                    self._string_from_length_prefix(pos, end, 'temp path')
            else:
                # Observed in reference-only packages: a uint16 flag followed
                # by a NUL-terminated path.
                if pos + 2 <= end:
                    self.temp_path_flag = _u16(self.raw_data, pos)
                    pos += 2
                self.temp_path_raw, pos, self.temp_path_complete = \
                    self._read_cstring(pos, end, 'temp path')
        else:
            # Older/alternate layout without the marker: try a length-prefixed
            # string, then fall back to a C string.
            self.layout_variant = 'no-marker'
            if pos + 4 <= end:
                maybe_length = _u32(self.raw_data, pos)
                plausible = (maybe_length <= end - pos - 4)
            else:
                plausible = False
            if plausible:
                self.temp_path_raw, pos, self.temp_path_complete = \
                    self._string_from_length_prefix(pos, end, 'temp path')
            else:
                self.temp_path_raw, pos, self.temp_path_complete = \
                    self._read_cstring(pos, end, 'temp path')

        self.temp_path = _as_text(self.temp_path_raw)

        if not self.temp_path_complete:
            self._set_effective_form()
            return self

        # Native-data length and bytes.
        if pos + 4 > end:
            self.has_native_data = False
            self.effective_form = 'linked'
            if self.format_id == OLE10NATIVE_FORMAT_EMBEDDED:
                self._issue('missing_native_data_length',
                            'FormatID declares an embedded object but no '
                            'native-data length is present',
                            offset=pos, available=max(0, end - pos))
            self._set_effective_form()
            return self

        self.has_native_data = True
        self.native_data_declared_length = _u32(self.raw_data, pos)
        pos += 4
        self.native_data_offset = pos
        data_available = max(0, end - pos)
        self.native_data_available_length = min(
            self.native_data_declared_length, data_available)
        self.native_data_range = (
            self.native_data_offset,
            self.native_data_offset + self.native_data_declared_length)
        self.native_data_available_range = (
            self.native_data_offset,
            self.native_data_offset + self.native_data_available_length)

        if self.native_data_declared_length > data_available:
            self.native_data_complete = False
            self.native_data_ambiguous_suffix = bool(data_available > 0)
            self.native_data = self.raw_data[pos:end]
            self._issue('native_data_length_exceeds_stream',
                        'NativeData length %d exceeds the %d available bytes' %
                        (self.native_data_declared_length, data_available),
                        severity='error', offset=pos, length=data_available,
                        declared=self.native_data_declared_length,
                        available=data_available)
            self._set_effective_form()
            return self

        self.native_data_complete = True
        self.native_data = self.raw_data[pos:pos +
                                         self.native_data_declared_length]
        pos += self.native_data_declared_length

        if self.format_id == OLE10NATIVE_FORMAT_LINKED:
            self._issue('linked_form_with_native_data',
                        'FormatID is linked but a native payload is present',
                        offset=self.native_data_offset,
                        length=self.native_data_declared_length)

        # Anything left inside the declared container is trailing data.  It is
        # parsed opportunistically as count-prefixed UTF-16 strings but the raw
        # bytes are always retained.
        if pos < end:
            self.trailer_offset = pos
            self.trailer = self.raw_data[pos:end]
            self.trailer_length = len(self.trailer)
            self._issue('native_data_trailing_bytes',
                        '%d byte(s) follow the declared native data' %
                        self.trailer_length,
                        severity='info', offset=pos, length=self.trailer_length,
                        declared=self.native_data_declared_length,
                        available=data_available)
            self._parse_trailer(pos, end)
        else:
            self.trailer_complete = True

        self._set_effective_form()
        self.header_complete = True
        return self

    def _check_form_conflict(self):
        """Record conflicts between the stream fields and the OLE storage."""
        if self.ole_stream_declared_linked is None:
            return
        if self.ole_stream_declared_linked and self.has_native_data:
            self._issue('form_conflict_link_flag_with_native_data',
                        '\\x01Ole flags declare a linked object but native '
                        'data is present in \\x01Ole10Native',
                        severity='warning',
                        offset=self.native_data_offset,
                        length=self.native_data_available_length)
        elif not self.ole_stream_declared_linked and self.effective_form == 'linked':
            self._issue('form_conflict_embedded_flag_without_native_data',
                        '\\x01Ole flags declare an embedded object but no '
                        'native data is present',
                        severity='warning', offset=self.container_region_end,
                        available=0)

    def _set_effective_form(self):
        if self.format_id == OLE10NATIVE_FORMAT_LINKED:
            self.effective_form = 'linked'
        elif self.native_data_declared_length is not None:
            self.effective_form = 'embedded'
        elif self.format_id == OLE10NATIVE_FORMAT_EMBEDDED:
            # FormatID says embedded, but no payload length exists.  Treat it
            # as a reference-only object while keeping declared_form intact.
            self.effective_form = 'linked'
        else:
            self.effective_form = 'unknown'

    def _parse_trailer(self, offset, end):
        """Parse optional count-prefixed UTF-16 strings in the trailer."""
        pos = offset
        complete = True
        while pos < end:
            if pos + 4 > end:
                self._issue('trailer_truncated',
                            'Trailing data ends inside a block length',
                            severity='warning', offset=pos, length=end - pos)
                complete = False
                break
            count = _u32(self.raw_data, pos)
            block_offset = pos
            pos += 4
            byte_length = count * 2
            if byte_length > end - pos:
                self._issue('trailer_block_length_exceeds_stream',
                            'Trailer block declares %d UTF-16 units but only '
                            '%d byte(s) remain' % (count, end - pos),
                            severity='warning', offset=block_offset, length=4,
                            declared=byte_length, available=end - pos)
                self.trailer_blocks.append({
                    'offset': block_offset,
                    'chars': count,
                    'byte_length': byte_length,
                    'text': None,
                    'complete': False,
                })
                complete = False
                break
            raw = self.raw_data[pos:pos + byte_length]
            text = _decode_utf16(raw)
            self.trailer_blocks.append({
                'offset': block_offset,
                'chars': count,
                'byte_length': byte_length,
                'text': text,
                'complete': True,
            })
            self.trailer_texts.append(text)
            pos += byte_length
        self.trailer_complete = complete
        if complete and pos != end:
            self._issue('trailer_unparsed_bytes',
                        '%d trailer byte(s) were not consumed' % (end - pos),
                        offset=pos, length=end - pos)
            self.trailer_complete = False

    # -- evidence ---------------------------------------------------------

    def to_dict(self):
        """Alias of :meth:`evidence`."""
        return self.evidence()

    def evidence(self, include_hex=False):
        """Return a JSON-friendly evidence mapping.

        ``include_hex`` only controls the complete native bytes; offsets,
        lengths, SHA-256 and a short preview are always included.

        The returned values are copied from the parser; no file or network
        access takes place.  Byte values are represented as hex where binary.
        """
        def name_evidence(raw, text):
            return {
                'text': text,
                'raw_hex': _hex(raw),
                'self_reported': True,
                'trust': 'untrusted',
                'is_content_type': False,
                'note': _SELF_REPORTED_NOTE,
            }

        native = None
        if self.native_data_declared_length is not None:
            native = {
                'offset': self.native_data_offset,
                'declared_length': self.native_data_declared_length,
                'available_length': self.native_data_available_length,
                'declared_range': list(self.native_data_range)
                if self.native_data_range else None,
                'available_range': list(self.native_data_available_range)
                if self.native_data_available_range else None,
                'complete': self.native_data_complete,
                'sha256': self.native_data_sha256,
                'magic_hex': self.native_magic,
                'preview_hex': (_hex(self.native_data[:32])
                                if self.native_data else None),
                'preview_length': min(32, len(self.native_data or b'')),
                'content_hint_from_bytes': self.native_content_hint,
                'content_type_source': self.content_type_source,
                'declared_extends_past_stream': not self.native_data_complete,
                'available_prefix_may_include_unparsed_bytes':
                    self.native_data_ambiguous_suffix,
                'digest_scope': self.digest_covers,
                'note': ('When the declared length exceeds the stream, the '
                         'digest covers only the available prefix; it is not '
                         'a digest of the declared range.'),
            }
            if include_hex:
                native['hex'] = _hex(self.native_data)

        trailer = {
            'offset': self.trailer_offset,
            'length': self.trailer_length,
            'complete': self.trailer_complete,
            'blocks': list(self.trailer_blocks),
            'texts': list(self.trailer_texts),
            'raw_hex': _hex(self.trailer) if self.trailer else '',
            'note': 'Trailing bytes are retained as evidence; they are not '
                    'folded into the declared native-data digest.',
        }
        outer = {
            'offset': self.outer_trailer_offset,
            'length': self.outer_trailer_length,
            'raw_hex': _hex(self.outer_trailer) if self.outer_trailer else '',
            'note': 'Bytes outside the leading NativeDataSize region.',
        }

        return {
            'stream_path': self.stream_path,
            'storage_path': self.storage_path,
            'container_clsid': self.container_clsid,
            'stream_declared_size': self.stream_declared_size,
            'stream_size': self.stream_size,
            'declared_container_length': self.declared_container_length,
            'container_length_complete': self.container_length_complete,
            'container_region_end': self.container_region_end,
            'format_id': self.format_id,
            'declared_form': self.declared_form,
            'effective_form': self.effective_form,
            'effective_form_basis': self.effective_form_basis,
            'form_evidence': {
                'format_id': self.format_id,
                'native_data_length_present': self.has_native_data,
                'native_data_length': self.native_data_declared_length,
                'native_data_complete': self.native_data_complete,
                'ole_stream_flags': self.ole_stream_flags,
                'ole_stream_declared_linked': self.ole_stream_declared_linked,
                'conflicts': [issue.as_dict() for issue in self.issues
                              if issue.code.startswith('form_conflict_')],
            },
            'layout_variant': self.layout_variant,
            'marker_value': self.marker_value,
            'has_native_data': self.has_native_data,
            'native_data': native,
            'reported_names': {
                'display_name': name_evidence(
                    self.display_name_raw, self.display_name),
                'source_path': name_evidence(
                    self.source_path_raw, self.source_path),
                'temp_path': name_evidence(
                    self.temp_path_raw, self.temp_path),
                'reported_extension': self.reported_extension,
                'reported_extension_is_content_type': False,
            },
            'trailer': trailer,
            'outer_trailer': outer,
            'ole_stream': {
                'seen': self.ole_stream_seen,
                'flags': self.ole_stream_flags,
                'declared_linked': self.ole_stream_declared_linked,
            },
            'issues': [issue.as_dict() for issue in self.issues],
            'safety': {
                'link_resolved': False,
                'link_contacted': False,
                'objects_executed': False,
                'files_written': False,
                'paths_used_for_writes': False,
            },
        }

    def __repr__(self):
        return ('Ole10Native(stream_path=%r, form=%r, declared_length=%r, '
                'available_length=%r, native_data_complete=%r, issues=%r)' %
                (self.stream_path, self.effective_form,
                 self.native_data_declared_length,
                 self.native_data_available_length,
                 self.native_data_complete,
                 [issue.code for issue in self.issues]))


def _path_list(path):
    if path is None:
        return None
    if isinstance(path, (list, tuple)):
        return [item for item in path]
    if isinstance(path, bytes):
        path = path.decode('utf-8', 'surrogateescape')
    return str(path).split('/')


def _is_ole10native_name(name):
    if isinstance(name, bytes):
        return name.lower() == b'\x01ole10native'
    return name.lower() == '\x01ole10native'


def _read_ole_stream_flags(ole, storage_path):
    """Read link/embed flags from ``\\x01Ole`` if present (no resolution)."""
    if not storage_path:
        return False, None, None
    ole_path = list(storage_path) + ['\x01Ole']
    try:
        if not ole.exists(ole_path):
            return False, None, None
        data = ole.openstream(ole_path).read(8)
    except Exception:
        return False, None, None
    if len(data) < 8:
        return True, None, None
    flags = _u32(data, 4)
    return True, flags, bool(flags & _OLE_STREAM_FLAG_LINKED)


def parse_ole10native_dict(data=None, **kwargs):
    """Parse one stream and return only the JSON-friendly evidence dict."""
    include_hex = kwargs.pop('include_hex', False)
    return parse_ole10native(data, **kwargs).evidence(include_hex=include_hex)


def parse_ole10native_stream(data, **kwargs):
    """Alias of :func:`parse_ole10native` for explicit stream wording."""
    return parse_ole10native(data, **kwargs)


def parse_ole10native(data=None, **kwargs):
    """Parse the bytes of a ``\\x01Ole10Native`` stream.

    Extra keyword arguments are forwarded to :class:`Ole10Native`
    (``stream_path``, ``container_clsid``, ``storage_path``,
    ``stream_declared_size``, ``bindata``).  Only the supplied in-memory bytes
    (or one read from a caller-provided stream) are parsed.
    """
    return Ole10Native(data, **kwargs)


# Compatibility with parsers that call the structure by its spec name.
Ole10NativeStream = Ole10Native
OleNativeStream = Ole10Native
# Generic name for code that already knows it handles an Ole10Native stream.
OleNative = Ole10Native


def open_ole10native(ole, stream_path):
    """Read and parse one ``\\x01Ole10Native`` stream from an OleFileIO.

    :param ole: an open :class:`olefile.OleFileIO` instance.
    :param stream_path: stream path as a list/tuple or slash-separated string.
    :returns: :class:`Ole10Native` with container evidence attached.
    :raises IOError: if the stream cannot be opened.
    """
    path = _path_list(stream_path)
    stream = ole.openstream(path)
    try:
        data = stream.read()
    finally:
        try:
            stream.close()
        except Exception:
            pass

    declared_size = None
    try:
        declared_size = ole.get_size(path)
    except Exception:
        pass

    container_clsid = None
    if len(path) > 1:
        try:
            container_clsid = ole.getclsid(path[:-1])
        except Exception:
            pass

    result = Ole10Native(
        data,
        stream_path=path,
        storage_path=path[:-1] if len(path) > 1 else [],
        container_clsid=container_clsid,
        stream_declared_size=declared_size,
    )
    if not path or not _is_ole10native_name(path[-1]):
        result._issue('not_ole10native_stream_name',
                      'The parsed stream is not named \\x01Ole10Native',
                      offset=0, length=result.stream_size)
    if declared_size is not None and declared_size != result.stream_size:
        result._issue('stream_size_mismatch',
                      'Container declares %d stream bytes but %d were read' %
                      (declared_size, result.stream_size),
                      severity='warning', offset=0,
                      declared=declared_size,
                      available=result.stream_size)
    seen, flags, linked = _read_ole_stream_flags(ole, path[:-1])
    result.ole_stream_seen = seen
    result.ole_stream_flags = flags
    result.ole_stream_declared_linked = linked
    result._check_form_conflict()
    return result


def find_ole10native_streams(ole):
    """Return paths of all ``\\x01Ole10Native`` streams in an OleFileIO."""
    result = []
    for path in ole.listdir():
        if path and _is_ole10native_name(path[-1]):
            result.append(path)
    return result


def iter_ole10native(ole):
    """Yield an :class:`Ole10Native` for every package stream in ``ole``."""
    for path in find_ole10native_streams(ole):
        yield open_ole10native(ole, path)


def _main(argv=None):
    """Print JSON evidence for packages in an OLE file (read-only).

    The output contains offsets, lengths, digests and short previews.  No
    native bytes are written to disk and self-reported names are never used
    as paths.
    """
    import argparse
    import json
    import sys
    import olefile

    parser = argparse.ArgumentParser(
        description='Read-only Ole10Native package evidence (JSON on stdout)')
    parser.add_argument('filename', help='OLE file to inspect')
    parser.add_argument('--include-native-hex', action='store_true',
                        help='include the complete native bytes as hex')
    args = parser.parse_args(argv)

    with olefile.OleFileIO(args.filename) as ole:
        packages = []
        for pkg in iter_ole10native(ole):
            packages.append(pkg.evidence(include_hex=args.include_native_hex))
    json.dump({'filename': args.filename, 'packages': packages},
              sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(_main())
