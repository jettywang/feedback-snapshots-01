"""forensics.py

Read-only forensic parsing of OpenPGP data.

Unlike the high-level :py:class:`~pgpy.PGPMessage` and :py:class:`~pgpy.PGPKey`
loaders, the entry points in this module never re-encode, decrypt, verify, or
execute anything.  They walk the raw packet stream and report *where every
byte went*:

* the original packet order is preserved,
* every packet records its on-wire byte range in the offset space it was
  actually found in (the outer stream, or inside a compressed container),
* packets nested inside a :py:class:`~pgpy.packet.packets.CompressedData`
  packet keep a parent link back to that container,
* new-format partial-length packets keep the individual byte ranges of every
  partial segment rather than a recomputed length,
* unknown tags, ignored packets, un-assembled packets, and trailing bytes are
  reported instead of silently disappearing,
* a failure while parsing one packet keeps every range confirmed up to that
  point and never returns a message that pretends to be complete.

The module is deliberately independent of the mutating
:py:meth:`pgpy.packet.types.Header.parse` implementation: that helper deletes
bytes from the working buffer as it goes, which makes it unsuitable for
retaining original positions.  The scanner below only reads.
"""
from __future__ import annotations

import collections

from .constants import CompressionAlgorithm
from .constants import PacketTag
from .errors import PGPError
from .types import Armorable

__all__ = ['ByteRange',
           'PartialSegment',
           'ForensicPacket',
           'ForensicReport',
           'forensic_scan',
           'forensic_scan_file', ]


# packet tags whose payload is ciphertext and must never be decrypted here
_ENCRYPTED_TAGS = frozenset({
    PacketTag.PublicKeyEncryptedSessionKey,
    PacketTag.SymmetricKeyEncryptedSessionKey,
    PacketTag.SymmetricallyEncryptedData,
    PacketTag.SymmetricallyEncryptedIntegrityProtectedData,
})

# tags that nest another packet stream once their payload is transformed
_COMPRESSED_TAG = PacketTag.CompressedData


class ByteRange(collections.namedtuple('ByteRange', ('start', 'end'))):
    """A half-open ``[start, end)`` byte range inside one offset space."""

    __slots__ = ()

    @property
    def length(self):
        return self.end - self.start

    def slice(self, data):
        return bytes(data[self.start:self.end])


class PartialSegment(collections.namedtuple('PartialSegment',
                                           ('index', 'header', 'body', 'partial'))):
    """One segment of a new-format (possibly partial-length) packet.

    ``header`` and ``body`` are :py:class:`ByteRange` values in the same
    offset space as the owning packet; ``partial`` is ``True`` for the
    intermediate partial-length headers and ``False`` for the final header.
    """

    __slots__ = ()


class ForensicPacket(object):
    """A single packet located inside an OpenPGP byte stream.

    :ivar int index: zero-based position in the packet walk, depth-first.
    :ivar int tag: raw packet tag value as it appeared on the wire.
    :ivar str tag_name: name of the tag when known, otherwise ``'Unknown'``.
    :ivar bool known: whether PGPy recognises the tag at all.
    :ivar ByteRange range: full on-wire range (all headers and bodies).
    :ivar ByteRange header_range: range of the leading packet header.
    :ivar ByteRange body_range: range of the packet body (payload).
    :ivar bool partial_length: ``True`` when new-format partial lengths were used.
    :ivar list[PartialSegment] segments: individual partial-length segments.
    :ivar bool new_format: ``True`` for new-format headers, ``False`` for old.
    :ivar int depth: nesting depth; ``0`` is the outermost stream.
    :ivar ForensicPacket parent: enclosing compressed packet, if any.
    :ivar str offset_space: label of the coordinate system of the ranges.
    :ivar str container: ``'outer'``, ``'compressed'``, or ``'encrypted'``.
    :ivar str disposition: what the high-level API does with this packet.
    :ivar str status: ``'parsed'``, ``'opaque'``, or ``'error'``.
    :ivar str error: error message when ``status == 'error'``.
    :ivar object packet: the parsed PGPy packet object, when available.
    """

    def __init__(self, index, tag, range, header_range, body_range,
                 new_format, partial_length, segments, depth, parent,
                 offset_space, container):
        self.index = index
        self.tag = int(tag)
        try:
            self.tag_name = PacketTag(self.tag).name
            self.known = True
        except ValueError:
            self.tag_name = 'Unknown'
            self.known = False

        self.range = range
        self.header_range = header_range
        self.body_range = body_range
        self.new_format = new_format
        self.partial_length = partial_length
        self.segments = segments
        self.depth = depth
        self.parent = parent
        self.offset_space = offset_space
        self.container = container
        self.status = 'parsed'
        self.error = None
        self.packet = None
        self.disposition = 'unexamined'

    @property
    def is_encrypted(self):
        return self.tag in _ENCRYPTED_TAGS

    @property
    def is_compressed(self):
        return self.tag == _COMPRESSED_TAG

    @property
    def nested_data(self):
        """Decompressed bytes of a compressed container, otherwise ``None``."""
        return getattr(self, '_nested_source', None) if self.is_compressed else None

    def __repr__(self):
        return ("<ForensicPacket #{idx:d} tag={tag:02d} ({name:s}) "
                "{space:s}[{start:d}:{end:d}] {status:s}>").format(
            idx=self.index, tag=self.tag, name=self.tag_name,
            space=self.offset_space, start=self.range.start,
            end=self.range.end, status=self.status)


class ForensicReport(object):
    """The result of a forensic scan.

    :ivar list[ForensicPacket] packets: every located packet in walk order.
    :ivar ByteRange trailing: bytes after the last confirmed packet, if any.
    :ivar bool complete: ``True`` only when the whole input was accounted for.
    :ivar dict armor: metadata recovered when the input was ASCII-armored.
    :ivar bytes source: the exact de-armored bytes that were scanned.
    """

    def __init__(self, source, armor=None):
        self.source = bytes(source)
        self.armor = armor
        self.packets = []
        self.trailing = ByteRange(0, 0)
        self.complete = True
        self.fatal_error = None

    def __iter__(self):
        return iter(self.packets)

    def __len__(self):
        return len(self.packets)

    @property
    def errors(self):
        """All packets that could not be fully parsed, in walk order."""
        return [p for p in self.packets if p.status == 'error']

    @property
    def unknown_packets(self):
        return [p for p in self.packets if not p.known]

    @property
    def ignored_packets(self):
        return [p for p in self.packets if p.disposition == 'ignored']

    @property
    def unassembled_packets(self):
        return [p for p in self.packets if p.disposition in ('unassembled', 'rejected')]

    def children(self, packet):
        """Packets directly nested inside the given container packet."""
        return [p for p in self.packets if p.parent is packet]

    def high_level_message(self):
        """Best-effort :py:class:`~pgpy.PGPMessage` built only from accepted packets.

        This mirrors :py:meth:`PGPMessage.parse` over the packets the
        forensic walk actually confirmed: ignored packets (markers, unknown
        tags, one-pass signatures, trust) are skipped, compressed containers
        unwrap their nested packets, and only the first literal data packet
        becomes the message body.

        Returns ``None`` only when the scan was incomplete, so callers cannot
        mistake a partial parse for a fully assembled message.  Packets the
        loader has no slot for are omitted here but stay listed in the report.
"""
        if not self.complete:
            return None

        from .pgp import PGPMessage

        message = PGPMessage()
        literal_seen = False
        for entry in self.packets:
            if entry.depth != 0 or entry.status == 'error' or entry.packet is None:
                continue
            if entry.disposition == 'ignored':
                continue
            if entry.tag == PacketTag.LiteralData:
                if literal_seen:
                    # PGPMessage keeps only the first literal packet; the
                    # extra one is not part of the assembled message
                    continue
                literal_seen = True
            try:
                message |= entry.packet
            except Exception:
                # a packet the high-level loader cannot attach (for example an
                # opaque tag it has no slot for) is simply not represented;
                # the forensic report remains the authoritative record
                continue
        return message

    def reassemble(self):
        """Concatenate every accounted byte range and return the raw bytes.

        The result equals the original input when ``complete`` is ``True``.
        """
        out = bytearray()
        for entry in self._ordered_ranges():
            out += self._slice(entry)
        if self.trailing is not None:
            out += self.source[self.trailing.start:self.trailing.end]
        return bytes(out)

    def _ordered_ranges(self):
        # outer packets first (already in order); nested packets are reached
        # through their parent, which keeps every byte in a single ordering
        return [p for p in self.packets if p.depth == 0]

    def _slice(self, entry):
        if entry.container == 'outer':
            return self.source[entry.range.start:entry.range.end]
        # nested bytes live inside the (decompressed) payload of the parent
        return entry.parent.nested_data[entry.range.start:entry.range.end]

    def explain(self):
        """Return a human-readable explanation of where every byte went."""
        lines = []
        for entry in self.packets:
            indent = '  ' * entry.depth
            seg = ''
            if entry.partial_length:
                seg = ' partial={:d} segments'.format(len(entry.segments))
            lines.append(
                '{indent}#{idx:d} tag {tag:02d} {name:s} {space:s}[{start:d}:{end:d}] '
                '({status:s}{seg}) -> {disp:s}'.format(
                    indent=indent, idx=entry.index, tag=entry.tag,
                    name=entry.tag_name, space=entry.offset_space,
                    start=entry.range.start, end=entry.range.end,
                    status=entry.status, seg=seg, disp=entry.disposition))
            if entry.error is not None:
                lines.append('{indent}    error: {err:s}'.format(
                    indent=indent, err=entry.error))
        if self.trailing is not None and self.trailing.length:
            lines.append('trailing garbage [{:d}:{:d}] ({:d} byte(s))'.format(
                self.trailing.start, self.trailing.end, self.trailing.length))
        if not self.complete:
            lines.append('INCOMPLETE: {err:s}'.format(
                err=self.fatal_error or 'unparseable region'))
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# low-level, non-mutating header scanning
# ---------------------------------------------------------------------------

def _scan_header(data, offset):
    """Scan one packet header starting at ``offset`` without mutating ``data``.

    Returns a dict describing the header and every length segment, or raises
    :py:class:`~pgpy.errors.PGPError` when the header is truncated or invalid.
    """
    total = len(data)
    if offset >= total:
        raise PGPError('no byte available for packet tag at offset {:d}'.format(offset))

    first = data[offset]
    if not (first & 0x80):
        raise PGPError(
            'invalid packet tag byte 0x{:02x} at offset {:d} (MSB not set)'.format(
                first, offset))

    new_format = bool(first & 0x40)
    tag = (first & 0x3F) if new_format else ((first & 0x3C) >> 2)
    header_start = offset
    cursor = offset + 1

    segments = []

    if not new_format:
        length_type = first & 0x03
        size = {0: 1, 1: 2, 2: 4, 3: 0}[length_type]
        if size == 0:
            # indeterminate length: the packet runs to the end of the buffer
            length = total - cursor
            header_end = cursor
        else:
            if cursor + size > total:
                raise PGPError(
                    'truncated old-format length at offset {:d}'.format(cursor))
            length = int.from_bytes(data[cursor:cursor + size], 'big')
            header_end = cursor + size
        return {
            'tag': tag,
            'new_format': False,
            'header_range': ByteRange(header_start, header_end),
            'body_start': header_end,
            'declared_length': length,
            'indeterminate': size == 0,
            'segments': segments,
            'partial': False,
        }

    # new-format length, which may be a chain of partial-length headers
    declared = 0
    partial_seen = False
    while True:
        if cursor >= total:
            raise PGPError(
                'truncated new-format length at offset {:d}'.format(cursor))
        length_byte = data[cursor]
        length_header_start = cursor
        length_header_end = cursor + 1

        if length_byte < 192:
            part = length_byte
        elif length_byte < 224:
            if length_header_end + 1 > total:
                raise PGPError(
                    'truncated two-octet length at offset {:d}'.format(length_header_start))
            part = ((length_byte - 192) << 8) + data[length_header_end] + 192
            length_header_end += 1
        elif length_byte < 255:
            part = 1 << (length_byte & 0x1F)
            partial_seen = True
        else:
            if length_header_end + 4 > total:
                raise PGPError(
                    'truncated five-octet length at offset {:d}'.format(length_header_start))
            part = int.from_bytes(
                data[length_header_end:length_header_end + 4], 'big')
            length_header_end += 4

        body_start_seg = length_header_end
        body_end_seg = body_start_seg + part
        if body_end_seg > total:
            raise PGPError(
                'packet body extends past end of data at offset {:d}'.format(body_start_seg))

        is_partial = (length_byte >= 224 and length_byte < 255)
        segments.append(PartialSegment(
            index=len(segments),
            header=ByteRange(length_header_start, length_header_end),
            body=ByteRange(body_start_seg, body_end_seg),
            partial=is_partial,
        ))
        declared += part
        cursor = body_end_seg

        if not is_partial:
            break

    return {
        'tag': tag,
        'new_format': True,
        # for a single (non-partial) length this is the complete header;
        # partial packets derive their overall header from ``segments``
        'header_range': ByteRange(header_start, segments[0].header.end),
        'body_start': segments[0].body.start,
        'declared_length': declared,
        'indeterminate': False,
        'segments': segments,
        'partial': partial_seen,
    }


def _build_forensic_packet(index, data, offset, depth, parent,
                           offset_space, container, nested_source=None):
    info = _scan_header(data, offset)
    declared = info['declared_length']

    if info['partial']:
        # The packet spans the first tag byte through the end of the final
        # segment body.  Each recorded segment keeps its own header/body
        # ranges, so partial positions are never replaced by a recomputed
        # single length.
        first_segment = info['segments'][0]
        last_segment = info['segments'][-1]
        header_range = ByteRange(info['header_range'].start,
                                 last_segment.header.end)
        body_start = first_segment.body.start
        body_end = last_segment.body.end
        range_ = ByteRange(info['header_range'].start, body_end)
    else:
        body_start = info['body_start']
        body_end = body_start + declared
        header_range = info['header_range']
        range_ = ByteRange(info['header_range'].start, body_end)

    entry = ForensicPacket(
        index=index,
        tag=info['tag'],
        range=range_,
        header_range=header_range,
        body_range=ByteRange(body_start, body_end),
        new_format=info['new_format'],
        partial_length=info['partial'],
        segments=info['segments'],
        depth=depth,
        parent=parent,
        offset_space=offset_space,
        container=container,
    )
    entry._nested_source = nested_source if container == 'compressed' else None
    entry._indeterminate = info['indeterminate']
    return entry, body_end


def _classify_disposition(entry):
    """Describe what the high-level PGPMessage loader does with a packet."""
    tag = entry.tag

    if not entry.known:
        return 'ignored'
    if tag == PacketTag.Marker:
        # PGPMessage.__or__ accepts a Marker and returns the message unchanged
        return 'ignored'
    if tag == PacketTag.Trust:
        # filtered out of keyring streams before grouping; not part of messages
        return 'ignored'
    if tag == PacketTag.OnePassSignature:
        # consumed during composition/verification, not retained on load
        return 'ignored'
    if tag in _ENCRYPTED_TAGS:
        # retained as opaque ciphertext; never decrypted without a key
        return 'assembled'
    if tag == PacketTag.CompressedData:
        # unwrapped: its nested packets take its place in the message
        return 'unwrapped'
    if tag == PacketTag.LiteralData:
        # the first literal becomes the message body; later ones are rejected
        return 'candidate-literal'
    if tag in (PacketTag.Signature, PacketTag.MDC):
        return 'assembled'
    if tag in (PacketTag.PublicKey, PacketTag.SecretKey,
               PacketTag.PublicSubKey, PacketTag.SecretSubKey,
               PacketTag.UserID, PacketTag.UserAttribute):
        return 'key-material'
    return 'unassembled'


def _walk_stream(data, report, depth, parent, offset_space, container,
                 nested_source, counter):
    offset = 0
    total = len(data)

    while offset < total:
        try:
            entry, next_offset = _build_forensic_packet(
                counter[0], data, offset, depth, parent,
                offset_space, container, nested_source)
        except PGPError as ex:
            # keep every range confirmed so far; the unparseable remainder
            # stays visible instead of being dropped
            report.complete = False
            report.fatal_error = '{space:s}: {msg}'.format(
                space=offset_space, msg=ex)
            if depth == 0:
                report.trailing = ByteRange(offset, total)
            elif parent is not None:
                parent.status = 'error'
                parent.error = 'nested stream truncated: {msg}'.format(msg=ex)
            return

        counter[0] += 1
        report.packets.append(entry)
        entry.disposition = _classify_disposition(entry)
        _parse_packet(entry, data)
        _inspect_container(entry, data, report, counter)

        offset = next_offset

    if depth == 0:
        # only the outermost stream owns the report-level trailing range;
        # trailing bytes inside a container stay attached to that container
        report.trailing = ByteRange(total, total)


def _parse_packet(entry, data):
    """Attempt a best-effort parse without changing the forensic record."""
    if entry.is_encrypted:
        # do not touch ciphertext: no key material, no authorization
        entry.status = 'opaque'
        return

    # parse against an independent copy so the PGPy parser can freely mutate
    candidate = bytearray(data[entry.range.start:entry.range.end])
    try:
        from .packet import Packet as _Packet
        parsed = _Packet(candidate)
    except Exception as ex:  # noqa: BLE001 - forensic tooling must keep going
        entry.status = 'error'
        entry.error = '{cls}: {msg}'.format(cls=ex.__class__.__name__, msg=ex)
        return

    if not entry.known or parsed.__class__.__name__ == 'Opaque':
        entry.status = 'opaque'
    else:
        entry.status = 'parsed'
    entry.packet = parsed


def _inspect_container(entry, data, report, counter):
    """Recurse into containers that expose another packet stream."""
    if entry.is_encrypted:
        # encrypted payloads stay sealed; nothing inside can be located
        entry._nested_source = None
        return

    if not entry.is_compressed:
        entry._nested_source = None
        return

    if entry.status == 'error':
        entry._nested_source = None
        return

    # the first body octet names the compression algorithm; the remainder is
    # the compressed packet block (RFC 4880 5.6)
    alg_byte = data[entry.body_range.start]
    try:
        alg = CompressionAlgorithm(alg_byte)
    except ValueError:
        entry.status = 'error'
        entry.error = 'unknown compression algorithm 0x{:02x}'.format(alg_byte)
        entry._nested_source = None
        return

    compressed = data[entry.body_range.start + 1:entry.body_range.end]
    try:
        decompressed = bytearray(alg.decompress(bytes(compressed)))
    except Exception as ex:  # noqa: BLE001
        entry.status = 'error'
        entry.error = 'decompression failed: {msg}'.format(msg=ex)
        entry._nested_source = None
        return

    nested = bytes(decompressed)
    entry._nested_source = nested
    child_space = 'compressed@{:d}'.format(entry.index)
    _walk_stream(decompressed, report, entry.depth + 1, entry,
                 child_space, 'compressed', nested, counter)


def _refine_literal_dispositions(report):
    """Apply PGPMessage's first-literal-wins rule across the whole tree."""
    literal_seen = False
    for entry in report.packets:
        if entry.depth != 0:
            # nested literals surface through their compressed parent instead
            continue
        if entry.tag == PacketTag.LiteralData:
            if not literal_seen:
                entry.disposition = 'assembled'
                literal_seen = True
            else:
                entry.disposition = 'rejected'


def forensic_scan(blob):
    """Scan OpenPGP data read-only and produce a :py:class:`ForensicReport`.

    :param blob: binary or ASCII-armored OpenPGP data (``bytes``,
                 ``bytearray``, or ``str``).
    :returns: :py:class:`ForensicReport`
    """
    if blob is None or len(blob) == 0:
        source = bytearray()
        armor = {'magic': None, 'headers': None, 'crc': None}
    else:
        unarmored = Armorable.ascii_unarmor(blob)
        source = bytearray(unarmored['body'])
        armor = {key: unarmored.get(key) for key in ('magic', 'headers', 'crc')}

    report = ForensicReport(source, armor=armor)
    report.trailing = ByteRange(0, 0)
    counter = [0]
    _walk_stream(source, report, depth=0, parent=None,
                 offset_space='outer', container='outer',
                 nested_source=bytes(source), counter=counter)
    _refine_literal_dispositions(report)
    return report


def forensic_scan_file(path):
    """Read a file from disk and run :py:func:`forensic_scan` on it."""
    with open(path, 'rb') as handle:
        return forensic_scan(bytearray(handle.read()))
