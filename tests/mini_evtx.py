"""
a tiny, dependency free writer for single-chunk EVTX files.

python-evtx is a parser, so the forensic output tests need controlled
records whose BinXML values contain specific byte sequences (C0 control
characters, lone UTF-16 surrogates, non-BMP characters, markup and the
display marker literal).  Only the structures the parser walks are
populated; checksums are zero because the rendering path never verifies
them.

the produced record uses inline name strings (the standard on-disk
layout): each OpenStartElementNode and AttributeNode is followed by the
NameStringNode it references, and the parser grows the node's tag length
to include that name.
"""
from __future__ import absolute_import

import struct

CHUNK_SIZE = 0x10000
HEADER_SIZE = 0x1000
CHUNK_HEADER_SIZE = 0x200
RECORD_HEADER_SIZE = 0x18

# BinXML system tokens.
T_END_OF_STREAM = 0x00
T_OPEN_START_ELEMENT = 0x01
T_CLOSE_START_ELEMENT = 0x02
T_CLOSE_ELEMENT = 0x04
T_ATTRIBUTE = 0x06
T_TEMPLATE_INSTANCE = 0x0C
T_NORMAL_SUBSTITUTION = 0x0D
T_STREAM_START = 0x0F

# Variant value types.
VT_WSTRING = 0x01


def _wstring_bytes(value):
    # surrogatepass keeps lone surrogate code units byte faithful.
    return value.encode("utf-16-le", "surrogatepass")


def _name_string(value):
    encoded = _wstring_bytes(value)
    char_count = len(encoded) // 2
    # NameStringNode: next_offset (dword), hash (word), string_length
    # (word), the UTF-16LE bytes and two trailing null code units.
    return struct.pack("<IHH", 0, 0, char_count) + encoded + b"\x00\x00"


class BinXmlBuilder(object):
    """
    assemble the BinXML payload (template instance, template with inline
    names and substitutions) for one record.

    the rendered document has the shape::

        <Event Attr="..."><Data>...</Data></Event>

    where both the attribute value and the element text are normal
    WSTRING substitutions, exercising the attribute and text encoding
    branches in Evtx.Views.
    """

    def __init__(self, attribute_value, text_value, payload_chunk_offset=None):
        self.attribute_value = attribute_value
        self.text_value = text_value
        # chunk relative offset of the first byte of this record's
        # BinXML payload (defaults to the first record's position).
        self.payload_chunk_offset = (
            payload_chunk_offset
            if payload_chunk_offset is not None
            else CHUNK_HEADER_SIZE + RECORD_HEADER_SIZE
        )

    def build(self):
        name_event = _name_string("Event")
        name_data = _name_string("Data")
        name_attr = _name_string("Attr")

        # chunk relative offsets.  the template instance is the first
        # byte of the payload because RootNode.template_instance() reads
        # there, so every record needs its own offset base.
        instance_chunk_offset = self.payload_chunk_offset
        instance_size = 10  # token, unknown0, template_id, template_offset
        template_offset = instance_chunk_offset + instance_size
        template_header_size = 0x18
        body_start = template_offset + template_header_size

        # build the body sequentially, tracking the running chunk offset
        # so every inline name string gets a correct back-reference.
        body = bytearray()

        def here():
            return body_start + len(body)

        body += struct.pack("<BBH", T_STREAM_START, 0x01, 0x01)

        # <Event Attr="sub0">
        open_event_header_pos = len(body)
        body += b"\x00" * 11  # OpenStartElementNode header, patched below
        event_name_offset = here()
        body += name_event

        attr_header_pos = len(body)
        body += b"\x00" * 5  # AttributeNode header, patched below
        attr_name_offset = here()
        body += name_attr
        body += struct.pack("<BHB", T_NORMAL_SUBSTITUTION, 0, VT_WSTRING)
        body += struct.pack("<B", T_CLOSE_START_ELEMENT)

        # <Data>sub1</Data>
        open_data_header_pos = len(body)
        body += b"\x00" * 11
        data_name_offset = here()
        body += name_data
        body += struct.pack("<BHB", T_NORMAL_SUBSTITUTION, 1, VT_WSTRING)
        body += struct.pack("<B", T_CLOSE_ELEMENT)

        body += struct.pack("<B", T_CLOSE_ELEMENT)
        body += struct.pack("<B", T_END_OF_STREAM)

        # patch the inline name references.
        struct.pack_into(
            "<BHII", body, open_event_header_pos, T_OPEN_START_ELEMENT, 0, 0, event_name_offset
        )
        struct.pack_into("<BI", body, attr_header_pos, T_ATTRIBUTE, attr_name_offset)
        struct.pack_into(
            "<BHII", body, open_data_header_pos, T_OPEN_START_ELEMENT, 0, 0, data_name_offset
        )

        # TemplateNode tag is 0x18 bytes; data_length lives at offset 0x14.
        template_header = bytearray(template_header_size)
        struct.pack_into("<I", template_header, 0x14, len(body))

        # substitution region directly follows the body; RootNode locates
        # it through tag_and_children_length().
        attr_bytes = _wstring_bytes(self.attribute_value) + b"\x00\x00"
        text_bytes = _wstring_bytes(self.text_value) + b"\x00\x00"
        sub_table = struct.pack("<I", 2)
        sub_table += struct.pack("<HBB", len(attr_bytes), VT_WSTRING, 0)
        sub_table += struct.pack("<HBB", len(text_bytes), VT_WSTRING, 0)
        sub_table += attr_bytes + text_bytes

        template_instance = struct.pack("<BBII", T_TEMPLATE_INSTANCE, 0, 0, template_offset)

        return b"".join([template_instance, bytes(template_header), bytes(body), sub_table])


def build_record(record_num, attribute_value, text_value, timestamp=0, payload_chunk_offset=None):
    payload = BinXmlBuilder(
        attribute_value, text_value, payload_chunk_offset=payload_chunk_offset
    ).build()
    size = RECORD_HEADER_SIZE + len(payload)
    header = struct.pack("<IIQq", 0x00002A2A, size, record_num, timestamp)
    return header + payload


def build_evtx(records):
    """
    build a complete, mmap-able EVTX image containing one active chunk.

    Args:
      records (list[tuple[int, str, str]]): record number, attribute
        value and text value triples.

    Returns:
      bytes: the EVTX image.
    """
    file_header = bytearray(HEADER_SIZE)
    file_header[0:8] = b"ElfFile\x00"
    struct.pack_into("<Q", file_header, 0x10, 1)  # current chunk number
    struct.pack_into("<Q", file_header, 0x18, len(records) + 1)  # next record number
    struct.pack_into("<I", file_header, 0x20, HEADER_SIZE)  # header size
    struct.pack_into("<H", file_header, 0x24, 1)  # minor version
    struct.pack_into("<H", file_header, 0x26, 3)  # major version
    struct.pack_into("<H", file_header, 0x28, 0x1000)  # header chunk size
    struct.pack_into("<H", file_header, 0x2A, 1)  # chunk count

    chunk = bytearray(CHUNK_SIZE)
    chunk[0:8] = b"ElfChnk\x00"
    struct.pack_into("<Q", chunk, 0x8, 1)  # file first record number
    struct.pack_into("<Q", chunk, 0x10, len(records))  # file last record number
    struct.pack_into("<Q", chunk, 0x18, 1)
    struct.pack_into("<Q", chunk, 0x20, len(records))
    struct.pack_into("<I", chunk, 0x28, CHUNK_HEADER_SIZE)  # header size

    cursor = CHUNK_HEADER_SIZE
    for record_num, attribute_value, text_value in records:
        payload_chunk_offset = cursor + RECORD_HEADER_SIZE
        record = build_record(
            record_num,
            attribute_value,
            text_value,
            payload_chunk_offset=payload_chunk_offset,
        )
        chunk[cursor : cursor + len(record)] = record
        cursor += len(record)

    struct.pack_into("<I", chunk, 0x2C, cursor)  # last record offset (absolute)
    struct.pack_into("<I", chunk, 0x30, cursor)  # next record offset, chunk relative

    return bytes(file_header) + bytes(chunk)
