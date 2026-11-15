#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Schema-neutral DER/BER TLV dissection.

The forensic walkers in :mod:`pyasn1.forensics` need a description of the
*transmitted* bytes that does not depend on any ASN.1 schema.  Decoding a bare
context-specific tag with the regular DER decoder requires an ``asn1Spec`` (it
raises ``... not in asn1Spec: None`` otherwise), which would let a schema
silently decide what the bytes mean.  This module parses only the X.690
identifier and length octets and never interprets a value: the meaning of each
primitive is left to the schema-driven layer.

The output is a tree of :class:`RawNode` objects that records, for every TLV,
its byte span, tag class/format/number, the raw identifier, length and content
octets, and (for constructed encodings) its child TLVs.  Indefinite-length
BER is accepted so that the same walker serves BER evidence; DER never emits
it, and an indefinite-length container is flagged rather than normalised away.
"""
from pyasn1.type import tag

__all__ = ['RawNode', 'ForensicError', 'walk_tlv', 'parse_tlv',
           'MAX_NESTING_DEPTH']

#: Tag class octet bits (X.690 8.1.2).
_CLASS_BITS = (
    tag.tagClassUniversal,
    tag.tagClassApplication,
    tag.tagClassContext,
    tag.tagClassPrivate,
)
_CLASS_NAMES = ('universal', 'application', 'context', 'private')

#: Maximum constructed-TLV nesting depth.  Mirrors the BER decoder's
#: ``MAX_NESTING_DEPTH`` so attacker-controlled substrate fails with a clean
#: error rather than exhausting the Python call stack (RecursionError).
MAX_NESTING_DEPTH = 100


class ForensicError(Exception):
    """Raised when substrate cannot be dissected into well-formed TLVs."""


class RawNode(object):
    """One schema-neutral TLV element.

    Attributes
    ----------
    path: :class:`str`
        Dotted zero-based child index path from the root (``""`` for the
        root, ``"0.1"`` for the second child of the first child, ...).
    tag_class: :class:`int`
        X.690 tag class constant (one of the ``tag.tagClass*`` values).
    tag_class_name: :class:`str`
        Human-readable tag class (``universal`` ... ``private``).
    constructed: :class:`bool`
        :obj:`True` when the constructed bit (bit 6) is set.
    tag_number: :class:`int`
        Tag number, including multi-octet (high-tag-number form) values.
    identifier_octets: :class:`bytes`
        The exact identifier octets as transmitted.
    content_octets: :class:`bytes`
        The exact value octets, excluding identifier and length octets.
    length_octets: :class:`bytes`
        The exact length octets as transmitted.
    indefinite: :class:`bool`
        :obj:`True` for an indefinite-length container (BER only).
    start: :class:`int`
        Offset of the identifier octet within the root substrate.
    header_end: :class:`int`
        Offset just past the length octets.
    content_end: :class:`int`
        Offset just past the content (and, for indefinite encodings, the
        end-of-contents octets), i.e. one past the whole TLV.
    children: :class:`tuple` of :class:`RawNode`
        Parsed child TLVs for constructed encodings, otherwise an empty
        tuple.  Primitive encodings always have no children even when their
        content happens to look like nested TLVs.
    """

    def __init__(self, path, tag_class, tag_class_name, constructed,
                 tag_number, identifier_octets, length_octets,
                 content_octets, indefinite, start, header_end,
                 content_end, children):
        self.path = path
        self.tag_class = tag_class
        self.tag_class_name = tag_class_name
        self.constructed = constructed
        self.tag_number = tag_number
        self.identifier_octets = identifier_octets
        self.length_octets = length_octets
        self.content_octets = content_octets
        self.indefinite = indefinite
        self.start = start
        self.header_end = header_end
        self.content_end = content_end
        self.children = tuple(children)

    @property
    def tlv_octets(self):
        """Full TLV octets exactly as they appear in the root substrate."""
        octets = self.identifier_octets + self.length_octets + \
            self.content_octets
        if self.indefinite:
            octets += b'\x00\x00'
        return octets

    @property
    def tag_annotation(self):
        """Compact ``class[/constructed]:number`` tag label."""
        kind = 'constructed' if self.constructed else 'primitive'
        return '%s/%s:%d' % (self.tag_class_name, kind, self.tag_number)

    def to_dict(self):
        return {
            'path': self.path,
            'tagClass': self.tag_class_name,
            'tagClassCode': self.tag_class,
            'constructed': self.constructed,
            'tagNumber': self.tag_number,
            'identifierOctets': self.identifier_octets.hex(),
            'lengthOctets': self.length_octets.hex(),
            'contentOctets': self.content_octets.hex(),
            'indefiniteLength': self.indefinite,
            'start': self.start,
            'headerEnd': self.header_end,
            'contentEnd': self.content_end,
            'children': [child.to_dict() for child in self.children],
        }


def _read_identifier(data, offset):
    if offset >= len(data):
        raise ForensicError('Missing identifier octet at offset %d' % offset)
    start = offset
    first = data[offset]
    offset += 1
    tag_class = first & 0xC0
    constructed = bool(first & 0x20)
    low = first & 0x1F
    if low < 0x1F:
        tag_number = low
    else:
        # High-tag-number form: base-128, leading continuation octets.
        number = 0
        while True:
            if offset >= len(data):
                raise ForensicError(
                    'Truncated high-tag-number identifier at offset %d'
                    % start)
            octet = data[offset]
            offset += 1
            number = (number << 7) | (octet & 0x7F)
            if not octet & 0x80:
                break
        tag_number = number
    identifier_octets = data[start:offset]
    return tag_class, constructed, tag_number, identifier_octets, offset


def _read_length(data, offset):
    if offset >= len(data):
        raise ForensicError('Missing length octet at offset %d' % offset)
    start = offset
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, data[start:offset], False, offset
    if first == 0x80:
        return -1, data[start:offset], True, offset
    count = first & 0x7F
    if count == 0x7F:
        raise ForensicError('Reserved length form 0xFF at offset %d' % start)
    if offset + count > len(data):
        raise ForensicError('Truncated long-form length at offset %d' % start)
    length = 0
    for octet in data[offset:offset + count]:
        length = (length << 8) | octet
    offset += count
    return length, data[start:offset], False, offset


def parse_tlv(data, offset=0, path='', _depth=0):
    """Dissect one TLV starting at *offset*.

    Returns a :class:`RawNode` and the offset immediately following the TLV.
    Constructed encodings are dissected recursively; primitive contents are
    kept verbatim and never interpreted.
    """
    if _depth > MAX_NESTING_DEPTH:
        raise ForensicError(
            'ASN.1 TLV nesting depth exceeds limit (%d) at offset %d'
            % (MAX_NESTING_DEPTH, offset))
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ForensicError(
            'Substrate must be bytes-like, got %s' % type(data).__name__)
    data = bytes(data)
    start = offset
    tag_class, constructed, tag_number, identifier_octets, offset = \
        _read_identifier(data, offset)
    length, length_octets, indefinite, offset = _read_length(data, offset)
    header_end = offset

    children = []
    if indefinite:
        content_start = offset
        child_index = 0
        while True:
            if offset >= len(data):
                raise ForensicError(
                    'Unterminated indefinite-length TLV at offset %d' % start)
            if data[offset:offset + 2] == b'\x00\x00':
                offset += 2
                break
            child, offset = parse_tlv(
                data, offset,
                '%s%d' % (path + '.' if path else '', child_index),
                _depth + 1)
            children.append(child)
            child_index += 1
        # Content spans the octets between the length marker and the
        # end-of-contents pair.
        content_octets = data[content_start:offset - 2]
        content_end = offset
    else:
        content_start = offset
        content_end = offset + length
        if content_end > len(data):
            raise ForensicError(
                'Declared length %d overruns substrate at offset %d'
                % (length, start))
        content_octets = data[content_start:content_end]
        offset = content_end
        if constructed:
            child_offset = content_start
            child_index = 0
            while child_offset < content_end:
                child, child_offset = parse_tlv(
                    data, child_offset,
                    '%s%d' % (path + '.' if path else '', child_index),
                    _depth + 1)
                children.append(child)
                child_index += 1
            if child_offset != content_end:
                raise ForensicError(
                    'Constructed content is not a whole number of TLVs at '
                    'offset %d' % start)

    try:
        class_index = _CLASS_BITS.index(tag_class)
    except ValueError:
        raise ForensicError('Unknown tag class bits 0x%02X' % tag_class)

    node = RawNode(
        path=path,
        tag_class=tag_class,
        tag_class_name=_CLASS_NAMES[class_index],
        constructed=constructed,
        tag_number=tag_number,
        identifier_octets=identifier_octets,
        length_octets=length_octets,
        content_octets=content_octets,
        indefinite=indefinite,
        start=start,
        header_end=header_end,
        content_end=content_end,
        children=children)
    return node, offset


def walk_tlv(data):
    """Dissect a complete single outer TLV and reject trailing bytes."""
    root, end = parse_tlv(bytes(data), 0, '')
    if end != len(data):
        raise ForensicError(
            'Trailing %d byte(s) after outer TLV' % (len(data) - end))
    return root
