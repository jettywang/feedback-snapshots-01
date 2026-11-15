"""
Minimal synthetic EVTX file generator for ConditionalSubstitution regression
tests. The binary layout is hand-built from the EVTX/BXML token specification
and cross-checked against python-evtx's own parser (including chunk checksums);
it is never captured from renderer output.

One chunk holds a single shared template instantiated by several records that
differ only in their substitution values.
"""
import struct
import binascii

# system tokens
T_END = 0x00
T_OPEN = 0x01
T_CLOSE_START = 0x02
T_CLOSE_EMPTY = 0x03
T_CLOSE_ELEM = 0x04
T_VALUE = 0x05
T_ATTR = 0x06
T_TEMPLATE_INST = 0x0C
T_NORMAL_SUB = 0x0D
T_COND_SUB = 0x0E
T_STREAM = 0x0F

# variant types
V_NULL = 0x00
V_WSTRING = 0x01
V_UBYTE = 0x04
V_DWORD = 0x08

TEMPLATE_ID = 0x1337
TEMPLATE_GUID = bytes(16)


def fnv1_hash16(s):
    # EVTX name string hash: low 16 bits of FNV-1 (32-bit) over UTF-16LE.
    h = 0x811C9DC5
    for byte in s.encode("utf-16-le"):
        h = ((h * 0x01000193) ^ byte) & 0xFFFFFFFF
    return h & 0xFFFF


class EvtxBuilder:
    """
    Builds one chunk containing a resident template and a set of records that
    instantiate the template with different substitution values.
    """

    # ---- low level bxml tokens ------------------------------------------------

    @staticmethod
    def stream_start():
        return struct.pack("<BBH", T_STREAM, 1, 1)

    @staticmethod
    def name_string(s):
        # next_offset(4) hash(2) length(2) UTF-16 chars + 2 trailing null bytes
        enc = s.encode("utf-16-le")
        return struct.pack("<IHH", 0, fnv1_hash16(s), len(s)) + enc + b"\x00\x00"

    def open_element(self, s, has_attributes=False):
        """
        open-start-element with an inline NameString immediately following the
        fixed token. The stored string_offset is a forward (chunk-relative)
        offset to that inline name, which is how real EVTX templates encode it.

        Token layout (body-relative):
          +0 token, +1 unknown0(word), +3 size(dword), +7 string_offset(dword)
          flag 0x04 appends a 4-byte (zero) extension before the inline name.
        Returns (head, inline name, body-relative offset of the string_offset
        dword, body-relative offset where the inline name begins).
        """
        head_len = 15 if has_attributes else 11
        token = T_OPEN | (0x40 if has_attributes else 0)
        if has_attributes:
            head = struct.pack("<BHIII", token, 0xFFFF, 0, 0, 0)
        else:
            head = struct.pack("<BHII", token, 0, 0, 0)
        name = self.name_string(s)
        return head, name, 7, head_len

    def attribute(self, s):
        # token byte + string_offset dword (5 bytes), then the inline name.
        head = struct.pack("<BI", T_ATTR, 0)
        name = self.name_string(s)
        return head, name, 1, 5

    @staticmethod
    def close_start():
        return bytes([T_CLOSE_START])

    @staticmethod
    def close_empty():
        return bytes([T_CLOSE_EMPTY])

    @staticmethod
    def close_element():
        return bytes([T_CLOSE_ELEM])

    @staticmethod
    def end_of_stream():
        return bytes([T_END])

    @staticmethod
    def value_wstring(s):
        return struct.pack("<BBH", T_VALUE, V_WSTRING, len(s)) + s.encode("utf-16-le")

    @staticmethod
    def normal_sub(index, vtype):
        return struct.pack("<BHB", T_NORMAL_SUB, index, vtype)

    @staticmethod
    def cond_sub(index, vtype):
        return struct.pack("<BHB", T_COND_SUB, index, vtype)

    @staticmethod
    def variant_bytes(vtype, value):
        """return (declared_size, raw_bytes) for a substitution value."""
        if vtype == V_NULL:
            # NullTypeNode consumes no bytes; the declaration size is zero.
            return 0, b""
        if vtype == V_WSTRING:
            raw = value.encode("utf-16-le") + b"\x00\x00"
            return len(raw), raw
        if vtype == V_UBYTE:
            return 1, struct.pack("<B", value)
        if vtype == V_DWORD:
            return 4, struct.pack("<I", value)
        raise NotImplementedError(vtype)

    # ---- template body --------------------------------------------------------

    def build_template_body(self):
        """
        Assemble the bxml stream shared by every record.

        Logical structure (N = normal substitution, C = conditional):

          <Event xmlns="http://example.com/forensic">
            <Data>N0</Data>                                   independent sibling
            <Optional>C1</Optional>                           element-level suppress
            <Group>
              <OptAttr Attr="C2"></OptAttr>                   attribute-level suppress
              <Nested>C3</Nested>                             nested conditional
            </Group>
          </Event>

        Returns (body_bytes, patches) where patches maps a body-relative offset
        to the name string whose chunk-relative address must be filled in once
        the template's final location is known.
        """
        parts = []
        # (body offset of string_offset field, body offset of the inline name)
        patches = []

        def emit(blob):
            parts.append(blob)
            return sum(len(p) for p in parts)

        def emit_named(token_pack):
            head, name, field_rel, name_rel = token_pack
            head_start = sum(len(p) for p in parts)
            parts.append(head)
            parts.append(name)
            patches.append((head_start + field_rel, head_start + name_rel))

        emit(self.stream_start())

        emit_named(self.open_element("Event", has_attributes=True))
        emit_named(self.attribute("xmlns"))
        emit(self.value_wstring("http://example.com/forensic"))
        emit(self.close_start())

        # <Data> normal substitution 0: always present, an independent sibling.
        emit_named(self.open_element("Data"))
        emit(self.close_start())
        emit(self.normal_sub(0, V_WSTRING))
        emit(self.close_element())

        # <Optional> conditional substitution 1: element-level suppression.
        emit_named(self.open_element("Optional"))
        emit(self.close_start())
        emit(self.cond_sub(1, V_WSTRING))
        emit(self.close_element())

        # <Group> with nested elements.
        emit_named(self.open_element("Group"))
        emit(self.close_start())

        # <OptAttr Attr="conditional sub 2"></OptAttr>: attribute suppression.
        emit_named(self.open_element("OptAttr", has_attributes=True))
        emit_named(self.attribute("Attr"))
        emit(self.cond_sub(2, V_WSTRING))
        emit(self.close_empty())

        # <Nested> conditional sub 3 inside the group.
        emit_named(self.open_element("Nested"))
        emit(self.close_start())
        emit(self.cond_sub(3, V_WSTRING))
        emit(self.close_element())

        emit(self.close_element())  # /Group
        emit(self.close_element())  # /Event
        emit(self.end_of_stream())

        return b"".join(parts), patches

    def template_node_blob(self, body, patches, chunk_rel_body_offset):
        """
        build a resident TemplateNode (0x18 header + bxml body), resolving each
        inline name's string_offset against the body's chunk-relative location.
        """
        body = bytearray(body)
        for field_rel, name_rel in patches:
            name_abs = chunk_rel_body_offset + name_rel
            struct.pack_into("<I", body, field_rel, name_abs)

        hdr = (struct.pack("<II", 0, TEMPLATE_ID) + TEMPLATE_GUID)[:0x14]
        hdr += struct.pack("<I", len(body))
        return bytes(hdr) + bytes(body)

    def build_record(self, record_num, timestamp, subs, template_node):
        """
        Build one record around a resident TemplateNode.

        Layout (record-relative):
          0x00 header: magic, size, record_num, timestamp (0x18 bytes)
          0x18 RootNode: StreamStart, TemplateInstance -> TemplateNode,
               substitution count, substitution declarations, substitution data
          tail duplicate size field (size2 == size)
        """
        stream = self.stream_start()
        instance = bytearray(10)  # patched with the resident template offset
        root = stream + bytes(instance) + template_node

        decl = b""
        data = b""
        for vtype, value in subs:
            size, raw = self.variant_bytes(vtype, value)
            decl += struct.pack("<HBB", size, vtype, 0)  # size, type, padding
            data += raw
        root += struct.pack("<I", len(subs)) + decl + data

        total_size = 0x18 + len(root) + 4
        header = struct.pack("<IIQQ", 0x2A2A, total_size, record_num, timestamp)
        # the trailing field duplicates the full record size; Record.verify()
        # requires size2 == size (observed in real EVTX records).
        size2 = struct.pack("<I", total_size)
        return bytearray(header + root + size2)

    def build_chunk(self, records_spec):
        """records_spec: list of (record_num, timestamp, subs). Returns bytes."""
        CHUNK_SIZE = 0x10000
        DATA_START = 0x200

        body, patches = self.build_template_body()

        records = bytearray()
        for record_num, ts, subs in records_spec:
            record_rel = DATA_START + len(records)
            root_rel = record_rel + 0x18
            # RootNode = StreamStart(4) then TemplateInstance(10) then the
            # resident TemplateNode, whose 0x18 header precedes the bxml body.
            node_rel = root_rel + 4 + 10
            body_rel = node_rel + 0x18
            template_node = self.template_node_blob(body, patches, body_rel)

            rec = self.build_record(record_num, ts, subs, template_node)
            # point the resident TemplateInstanceNode (at root + 4) at the node.
            struct.pack_into(
                "<BBII", rec, 0x18 + 4, T_TEMPLATE_INST, 1, TEMPLATE_ID, node_rel
            )
            records += rec

        next_record_offset = DATA_START + len(records)

        chunk = bytearray(CHUNK_SIZE)
        first = records_spec[0][0]
        last = records_spec[-1][0]
        chunk[0:8] = b"ElfChnk\x00"
        struct.pack_into("<Q", chunk, 0x08, first)
        struct.pack_into("<Q", chunk, 0x10, last)
        struct.pack_into("<Q", chunk, 0x18, first)
        struct.pack_into("<Q", chunk, 0x20, last)
        struct.pack_into("<I", chunk, 0x28, 0x1F8)
        struct.pack_into("<I", chunk, 0x2C, next_record_offset)
        struct.pack_into("<I", chunk, 0x30, next_record_offset)
        struct.pack_into("<I", chunk, 0x34, 0)  # data_checksum placeholder
        chunk[DATA_START:DATA_START + len(records)] = records

        data_crc = binascii.crc32(bytes(chunk[0x200:next_record_offset])) & 0xFFFFFFFF
        struct.pack_into("<I", chunk, 0x34, data_crc)

        hdr_crc = binascii.crc32(bytes(chunk[0x0:0x78]) + bytes(chunk[0x80:0x200])) & 0xFFFFFFFF
        struct.pack_into("<I", chunk, 0x7C, hdr_crc)
        return bytes(chunk)

    def build_file(self, records_spec):
        chunk = self.build_chunk(records_spec)
        hdr = bytearray(0x1000)
        struct.pack_into("<8sQQQIHH", hdr, 0, b"ElfFile\x00", 1, 0, len(records_spec) + 1, 0x80, 1, 3)
        struct.pack_into("<H", hdr, 0x28, 0x1000)
        struct.pack_into("<H", hdr, 0x2A, 1)
        struct.pack_into("<I", hdr, 0x78, 0)
        crc = binascii.crc32(bytes(hdr[0:0x78])) & 0xFFFFFFFF
        struct.pack_into("<I", hdr, 0x7C, crc)
        return bytes(hdr) + chunk
