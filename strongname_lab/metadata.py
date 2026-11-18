"""Minimal ECMA-335 metadata reader/writer for the lab's synthetic fixtures.

Only the tables that matter for strong-name identity and verification are
handled: Module, TypeRef, TypeDef, MethodDef, Assembly, AssemblyRef, File and
ManifestResource.  The reader is intentionally strict about bounds so a
truncated or malformed file is reported instead of silently accepted.
"""

from __future__ import annotations

import struct

from . import crypto

METADATA_SIGNATURE = b"BSJB"
METADATA_VERSION = "v4.0.30319"

TABLE_MODULE = 0x00
TABLE_TYPEREF = 0x01
TABLE_TYPEDEF = 0x02
TABLE_FIELDPTR = 0x03
TABLE_FIELD = 0x04
TABLE_METHODPTR = 0x05
TABLE_METHODDEF = 0x06
TABLE_PARAMPTR = 0x07
TABLE_PARAM = 0x08
TABLE_INTERFACEIMPL = 0x09
TABLE_MEMBERREF = 0x0A
TABLE_CONSTANT = 0x0B
TABLE_CUSTOMATTRIBUTE = 0x0C
TABLE_FIELDMARSHAL = 0x0D
TABLE_DECLSECURITY = 0x0E
TABLE_CLASSLAYOUT = 0x0F
TABLE_FIELDLAYOUT = 0x10
TABLE_STANDALONESIG = 0x11
TABLE_EVENTMAP = 0x12
TABLE_EVENTPTR = 0x13
TABLE_EVENT = 0x14
TABLE_PROPERTYMAP = 0x15
TABLE_PROPERTYPTR = 0x16
TABLE_PROPERTY = 0x17
TABLE_METHODSEMANTICS = 0x18
TABLE_METHODIMPL = 0x19
TABLE_MODULEREF = 0x1A
TABLE_TYPESPEC = 0x1B
TABLE_IMPLMAP = 0x1C
TABLE_FIELDRVA = 0x1D
TABLE_ENCLOG = 0x1E
TABLE_ENCMAP = 0x1F
TABLE_ASSEMBLY = 0x20
TABLE_ASSEMBLYPROCESSOR = 0x21
TABLE_ASSEMBLYOS = 0x22
TABLE_ASSEMBLYREF = 0x23
TABLE_ASSEMBLYREFPROCESSOR = 0x24
TABLE_ASSEMBLYREFOS = 0x25
TABLE_FILE = 0x26
TABLE_EXPORTEDTYPE = 0x27
TABLE_MANIFESTRESOURCE = 0x28
TABLE_NESTEDCLASS = 0x29
TABLE_GENERICPARAM = 0x2A
TABLE_METHODSPEC = 0x2B
TABLE_GENERICPARAMCONSTRAINT = 0x2C

C_STRING, C_GUID, C_BLOB = "str", "guid", "blob"
C_U16, C_U32 = "u2", "u4"
C_TABLE = "table:"
C_CODED = "coded:"

TABLE_NAMES = {
    "Module": 0x00, "TypeRef": 0x01, "TypeDef": 0x02, "FieldPtr": 0x03, "Field": 0x04,
    "MethodPtr": 0x05, "MethodDef": 0x06, "ParamPtr": 0x07, "Param": 0x08,
    "InterfaceImpl": 0x09, "MemberRef": 0x0A, "Constant": 0x0B, "CustomAttribute": 0x0C,
    "FieldMarshal": 0x0D, "DeclSecurity": 0x0E, "ClassLayout": 0x0F, "FieldLayout": 0x10,
    "StandAloneSig": 0x11, "EventMap": 0x12, "EventPtr": 0x13, "Event": 0x14,
    "PropertyMap": 0x15, "PropertyPtr": 0x16, "Property": 0x17, "MethodSemantics": 0x18,
    "MethodImpl": 0x19, "ModuleRef": 0x1A, "TypeSpec": 0x1B, "ImplMap": 0x1C,
    "FieldRVA": 0x1D, "ENCLog": 0x1E, "ENCMap": 0x1F, "Assembly": 0x20,
    "AssemblyProcessor": 0x21, "AssemblyOS": 0x22, "AssemblyRef": 0x23,
    "AssemblyRefProcessor": 0x24, "AssemblyRefOS": 0x25, "File": 0x26,
    "ExportedType": 0x27, "ManifestResource": 0x28, "NestedClass": 0x29,
    "GenericParam": 0x2A, "MethodSpec": 0x2B, "GenericParamConstraint": 0x2C,
}

SCHEMAS = {
    0x00: [("Generation", C_U16), ("Name", C_STRING), ("Mvid", C_GUID), ("EncId", C_GUID), ("EncBaseId", C_GUID)],
    0x01: [("ResolutionScope", C_CODED + "ResolutionScope"), ("TypeName", C_STRING), ("TypeNamespace", C_STRING)],
    0x02: [
        ("Flags", C_U32), ("TypeName", C_STRING), ("TypeNamespace", C_STRING),
        ("Extends", C_CODED + "TypeDefOrRef"), ("FieldList", C_TABLE + "Field"), ("MethodList", C_TABLE + "MethodDef"),
    ],
    0x03: [("Field", C_TABLE + "Field")],
    0x04: [("Flags", C_U16), ("Name", C_STRING), ("Signature", C_BLOB)],
    0x05: [("Method", C_TABLE + "MethodDef")],
    0x06: [
        ("RVA", C_U32), ("ImplFlags", C_U16), ("Flags", C_U16), ("Name", C_STRING),
        ("Signature", C_BLOB), ("ParamList", C_TABLE + "Param"),
    ],
    0x07: [("Param", C_TABLE + "Param")],
    0x08: [("Flags", C_U16), ("Sequence", C_U16), ("Name", C_STRING)],
    0x09: [("Class", C_TABLE + "TypeDef"), ("Interface", C_CODED + "TypeDefOrRef")],
    0x0A: [("Class", C_CODED + "MemberRefParent"), ("Name", C_STRING), ("Signature", C_BLOB)],
    0x0B: [("Type", C_U16), ("Parent", C_CODED + "HasConstant"), ("Value", C_BLOB)],
    0x0C: [("Parent", C_CODED + "HasCustomAttribute"), ("Type", C_CODED + "CustomAttributeType"), ("Value", C_BLOB)],
    0x0D: [("Parent", C_CODED + "HasFieldMarshal"), ("NativeType", C_BLOB)],
    0x0E: [("Action", C_U16), ("Parent", C_CODED + "HasDeclSecurity"), ("PermissionSet", C_BLOB)],
    0x0F: [("PackingSize", C_U16), ("ClassSize", C_U32), ("Parent", C_TABLE + "TypeDef")],
    0x10: [("Offset", C_U32), ("Field", C_TABLE + "Field")],
    0x11: [("Signature", C_BLOB)],
    0x12: [("Parent", C_TABLE + "TypeDef"), ("EventList", C_TABLE + "Event")],
    0x13: [("Event", C_TABLE + "Event")],
    0x14: [("EventFlags", C_U16), ("Name", C_STRING), ("EventType", C_CODED + "TypeDefOrRef")],
    0x15: [("Parent", C_TABLE + "TypeDef"), ("PropertyList", C_TABLE + "Property")],
    0x16: [("Property", C_TABLE + "Property")],
    0x17: [("Flags", C_U16), ("Name", C_STRING), ("Type", C_BLOB)],
    0x18: [("Semantics", C_U16), ("Method", C_TABLE + "MethodDef"), ("Association", C_CODED + "HasSemantics")],
    0x19: [
        ("Class", C_TABLE + "TypeDef"), ("MethodBody", C_CODED + "MethodDefOrRef"),
        ("MethodDeclaration", C_CODED + "MethodDefOrRef"),
    ],
    0x1A: [("Name", C_STRING)],
    0x1B: [("Signature", C_BLOB)],
    0x1C: [
        ("MappingFlags", C_U16), ("MemberForwarded", C_CODED + "MemberForwarded"),
        ("ImportName", C_STRING), ("ImportScope", C_TABLE + "ModuleRef"),
    ],
    0x1D: [("RVA", C_U32), ("Field", C_TABLE + "Field")],
    0x1E: [("Token", C_U32), ("FuncCode", C_U32)],
    0x1F: [("Token", C_U32)],
    0x20: [
        ("HashAlgId", C_U32), ("MajorVersion", C_U16), ("MinorVersion", C_U16), ("BuildNumber", C_U16),
        ("RevisionNumber", C_U16), ("Flags", C_U32), ("PublicKey", C_BLOB), ("Name", C_STRING), ("Culture", C_STRING),
    ],
    0x21: [("Processor", C_U32)],
    0x22: [("OSPlatformID", C_U32), ("OSMajor", C_U32), ("OSMinor", C_U32)],
    0x23: [
        ("MajorVersion", C_U16), ("MinorVersion", C_U16), ("BuildNumber", C_U16), ("RevisionNumber", C_U16),
        ("Flags", C_U32), ("PublicKeyOrToken", C_BLOB), ("Name", C_STRING), ("Culture", C_STRING), ("HashValue", C_BLOB),
    ],
    0x24: [("Processor", C_U32), ("AssemblyRef", C_TABLE + "AssemblyRef")],
    0x25: [("OSPlatformID", C_U32), ("OSMajor", C_U32), ("OSMinor", C_U32), ("AssemblyRef", C_TABLE + "AssemblyRef")],
    0x26: [("Flags", C_U32), ("Name", C_STRING), ("HashValue", C_BLOB)],
    0x27: [
        ("Flags", C_U32), ("TypeDefId", C_U32), ("TypeName", C_STRING), ("TypeNamespace", C_STRING),
        ("Implementation", C_CODED + "Implementation"),
    ],
    0x28: [
        ("Offset", C_U32), ("Flags", C_U32), ("Name", C_STRING),
        ("Implementation", C_CODED + "Implementation"),
    ],
    0x29: [("NestedClass", C_TABLE + "TypeDef"), ("EnclosingClass", C_TABLE + "TypeDef")],
    0x2A: [("Number", C_U16), ("Flags", C_U16), ("Owner", C_CODED + "TypeOrMethodDef"), ("Name", C_STRING)],
    0x2B: [("Method", C_CODED + "MethodDefOrRef"), ("Instantiation", C_BLOB)],
    0x2C: [("Owner", C_TABLE + "GenericParam"), ("Constraint", C_CODED + "TypeDefOrRef")],
}

# ECMA-335 II.24.2.6: (tag bits, tables by tag value).  None = unused tag.
CODED_INDEXES = {
    "TypeDefOrRef": (2, [0x02, 0x01, 0x1B]),
    "HasConstant": (2, [0x04, 0x08, 0x17]),
    "HasCustomAttribute": (5, [
        0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17,
        0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A,
        0x2C, 0x2B,
    ]),
    "HasFieldMarshal": (1, [0x04, 0x08]),
    "HasDeclSecurity": (2, [0x02, 0x06, 0x20]),
    "MemberRefParent": (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
    "HasSemantics": (1, [0x14, 0x17]),
    "MethodDefOrRef": (1, [0x06, 0x0A]),
    "MemberForwarded": (1, [0x04, 0x06]),
    "Implementation": (2, [0x26, 0x23, 0x27]),
    "CustomAttributeType": (3, [None, None, 0x06, 0x0A, None]),
    "ResolutionScope": (2, [0x00, 0x1A, 0x23, 0x01]),
    "TypeOrMethodDef": (1, [0x02, 0x06]),
}


class MetadataError(ValueError):
    pass


def compressed_uint(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return struct.pack(">H", 0x8000 | value)
    if value < 0x20000000:
        return struct.pack(">I", 0xC0000000 | value)
    raise MetadataError("compressed integer too large")


def read_compressed_uint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise MetadataError("truncated compressed integer")
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    if first & 0xC0 == 0x80:
        if offset + 2 > len(data):
            raise MetadataError("truncated 2-byte compressed integer")
        return ((first & 0x3F) << 8) | data[offset + 1], offset + 2
    if first & 0xE0 == 0xC0:
        if offset + 4 > len(data):
            raise MetadataError("truncated 4-byte compressed integer")
        return ((first & 0x1F) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3], offset + 4
    raise MetadataError("invalid compressed integer prefix")


def _align4(value: int) -> int:
    return (value + 3) & ~3


class MetadataBuilder:
    """Build a deterministic, valid metadata root with the tables the lab needs."""

    def __init__(self, assembly_name: str, *, version: str = "1.2.3.4", culture: str = "", flags: int = 0,
                 hash_alg_id: int = crypto.CALG_SHA1):
        self.strings: list[str] = [""]
        self.string_index: dict[str, int] = {"": 0}
        self.blobs: list[bytes] = [b""]
        self.blob_index: dict[bytes, int] = {b"": 0}
        self.guids: list[bytes] = [bytes(16)]
        self.rows: dict[int, list[dict]] = {
            table: [] for table in set(SCHEMAS) | {TABLE_MODULEREF}
        }
        self.assembly_name = assembly_name
        self.version = version
        self.culture = culture
        self.flags = flags
        self.hash_alg_id = hash_alg_id
        self.public_key = b""
        self.files: list[dict] = []
        self.resources: list[dict] = []

    # --- heaps --------------------------------------------------------
    def string(self, value: str) -> int:
        if value not in self.string_index:
            self.string_index[value] = len(self._string_heap())
            self.strings.append(value)
        return self.string_index[value]

    def _string_heap(self) -> bytes:
        out = bytearray(b"\x00")
        for value in self.strings[1:]:
            out += value.encode("utf-8") + b"\x00"
        return bytes(out)

    def blob(self, value: bytes) -> int:
        if value not in self.blob_index:
            self.blob_index[value] = len(self._blob_heap())
            self.blobs.append(value)
        return self.blob_index[value]

    def _blob_heap(self) -> bytes:
        out = bytearray(b"\x00")
        for value in self.blobs[1:]:
            out += compressed_uint(len(value)) + value
        return bytes(out)

    # --- rows ---------------------------------------------------------
    def add_assembly_ref(self, name: str, version: str, public_key_or_token: bytes, flags: int = 0) -> int:
        self.rows[TABLE_ASSEMBLYREF].append({
            "MajorVersion": int(version.split(".")[0]),
            "MinorVersion": int(version.split(".")[1]),
            "BuildNumber": int(version.split(".")[2]),
            "RevisionNumber": int(version.split(".")[3]),
            "Flags": flags,
            "PublicKeyOrToken": self.blob(public_key_or_token),
            "Name": self.string(name),
            "Culture": self.string(""),
            "HashValue": self.blob(b""),
        })
        return len(self.rows[TABLE_ASSEMBLYREF])

    def add_file(self, name: str, digest: bytes, flags: int = 0) -> None:
        self.files.append({"Flags": flags, "Name": self.string(name), "HashValue": self.blob(digest)})

    def add_resource(self, name: str, offset: int, flags: int = 0) -> None:
        self.resources.append({"Offset": offset, "Flags": flags, "Name": self.string(name), "Implementation": 0})

    def build(self) -> bytes:
        major, minor, build, revision = (int(x) for x in self.version.split("."))
        self.rows[TABLE_MODULE] = [{
            "Generation": 0, "Name": self.string("unnamed.mod"), "Mvid": 0, "EncId": 0, "EncBaseId": 0,
        }]
        self.rows[TABLE_ASSEMBLY] = [{
            "HashAlgId": self.hash_alg_id,
            "MajorVersion": major, "MinorVersion": minor, "BuildNumber": build, "RevisionNumber": revision,
            "Flags": self.flags, "PublicKey": self.blob(self.public_key),
            "Name": self.string(self.assembly_name), "Culture": self.string(self.culture),
        }]
        self.rows[TABLE_FILE] = list(self.files)
        self.rows[TABLE_MANIFESTRESOURCE] = list(self.resources)
        self.rows[TABLE_TYPEREF] = [{
            "ResolutionScope": 0, "TypeName": self.string("Object"), "TypeNamespace": self.string("System"),
        }]
        self.rows[TABLE_TYPEDEF] = [{
            "Flags": 0x00100001, "TypeName": self.string("<Module>"), "TypeNamespace": self.string(""),
            "Extends": 0, "FieldList": 1, "MethodList": 1,
        }]

        heaps = {
            "#Strings": self._string_heap(),
            "#GUID": b"".join(self.guids),
            "#Blob": self._blob_heap(),
        }
        table_stream = self._build_tables(len(heaps["#Strings"]), len(heaps["#Blob"]))
        version_bytes = METADATA_VERSION.encode("ascii") + b"\x00"
        version_bytes += b"\x00" * ((-len(version_bytes)) % 4)
        streams = [
            (b"#~", table_stream),
            (b"#Strings", heaps["#Strings"]),
            (b"#US", b"\x00"),
            (b"#GUID", heaps["#GUID"]),
            (b"#Blob", heaps["#Blob"]),
        ]

        root_header = 16 + len(version_bytes) + 2 + 2
        header_size = root_header + sum(8 + _align4(len(name) + 1) for name, _ in streams)
        offsets: list[int] = []
        cursor = header_size
        for _, payload in streams:
            offsets.append(cursor)
            cursor += _align4(len(payload))
        header = bytearray(METADATA_SIGNATURE + struct.pack("<HHII", 1, 1, 0, len(version_bytes)))
        header += version_bytes + struct.pack("<HH", 0, len(streams))
        for (name, payload), offset in zip(streams, offsets):
            header += struct.pack("<II", offset, len(payload)) + name + b"\x00" * (_align4(len(name) + 1) - len(name))
        if len(header) != header_size:
            raise MetadataError(f"internal stream header size mismatch {len(header)} != {header_size}")
        body = bytearray()
        for _, payload in streams:
            body += payload + b"\x00" * (_align4(len(payload)) - len(payload))
        return bytes(header) + bytes(body)

    # --- table stream -------------------------------------------------
    def _coded_size(self, coded: str) -> int:
        bits, tables = CODED_INDEXES[coded]
        max_rows = max((len(self.rows.get(table, [])) for table in tables if table is not None), default=0)
        return 2 if max_rows < (1 << (16 - bits)) else 4

    def _column_size(self, kind: str, string_size: int, blob_size: int) -> int:
        if kind == C_U16:
            return 2
        if kind == C_U32:
            return 4
        if kind == C_STRING:
            return 2 if string_size < 0x10000 else 4
        if kind == C_GUID:
            return 2 if len(self.guids) < 0x10000 else 4
        if kind == C_BLOB:
            return 2 if blob_size < 0x10000 else 4
        if kind.startswith(C_TABLE):
            table = TABLE_NAMES[kind[len(C_TABLE):]]
            return 2 if len(self.rows[table]) < 0x10000 else 4
        if kind.startswith(C_CODED):
            return self._coded_size(kind[len(C_CODED):])
        raise MetadataError(f"unknown column kind {kind}")

    def _build_tables(self, string_size: int, blob_size: int) -> bytes:
        present = [(table, len(rows)) for table, rows in sorted(self.rows.items()) if rows]
        valid = sum(1 << table for table, _ in present)
        stream = bytearray(struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0))
        for _, count in present:
            stream += struct.pack("<I", count)
        for table, _ in present:
            for row in self.rows[table]:
                for name, kind in SCHEMAS[table]:
                    size = self._column_size(kind, string_size, blob_size)
                    stream += int(row.get(name, 0)).to_bytes(size, "little")
        return bytes(stream)


class Metadata:
    """Parsed metadata root plus the Assembly row and strong-name slot info."""

    def __init__(self, data: bytes, rva: int):
        self.data = data
        self.rva = rva
        if len(data) < 20 or not data.startswith(METADATA_SIGNATURE):
            raise MetadataError("missing BSJB metadata signature")
        version_length = struct.unpack_from("<I", data, 12)[0]
        if version_length % 4 or 16 + version_length + 4 > len(data):
            raise MetadataError("invalid metadata version length")
        self.version = data[16:16 + version_length].split(b"\x00", 1)[0].decode("ascii", "replace")
        cursor = 16 + version_length
        stream_count = struct.unpack_from("<H", data, cursor + 2)[0]
        cursor += 4
        self.streams: dict[str, tuple[int, int]] = {}
        for _ in range(stream_count):
            if cursor + 8 > len(data):
                raise MetadataError("truncated stream header")
            offset, size = struct.unpack_from("<II", data, cursor)
            cursor += 8
            end = data.find(b"\x00", cursor)
            if end < 0:
                raise MetadataError("unterminated stream name")
            name = data[cursor:end].decode("ascii", "replace")
            cursor = _align4(end + 1)
            if offset + size > len(data):
                raise MetadataError(f"stream {name} out of bounds")
            if name in self.streams:
                raise MetadataError(f"duplicate stream {name}")
            self.streams[name] = (offset, size)
        for required in ("#~", "#Strings", "#Blob", "#GUID"):
            if required not in self.streams:
                raise MetadataError(f"missing {required} stream")
        self.sizes: dict[int, int] = {}
        self.table_rows: dict[int, list[dict]] = {}
        self._parse_tables()
        rows = self.table_rows.get(TABLE_ASSEMBLY, [])
        if len(rows) != 1:
            raise MetadataError("metadata must contain exactly one Assembly row")
        self.assembly = rows[0]

    def _stream(self, name: str) -> bytes:
        offset, size = self.streams[name]
        return self.data[offset:offset + size]

    @staticmethod
    def _heap_string(heap: bytes, index: int) -> str:
        if index >= len(heap):
            raise MetadataError("string heap index out of bounds")
        end = heap.find(b"\x00", index)
        if end < 0:
            raise MetadataError("unterminated string heap entry")
        return heap[index:end].decode("utf-8", "replace")

    @staticmethod
    def _heap_blob(heap: bytes, index: int) -> bytes:
        if index >= len(heap):
            raise MetadataError("blob heap index out of bounds")
        length, cursor = read_compressed_uint(heap, index)
        if cursor + length > len(heap):
            raise MetadataError("blob heap entry out of bounds")
        return heap[cursor:cursor + length]

    def _parse_tables(self) -> None:
        data = self._stream("#~")
        self._table_stream_base = self.streams["#~"][0]
        if len(data) < 24:
            raise MetadataError("table stream too short")
        heap_sizes = data[6]
        valid = struct.unpack_from("<Q", data, 8)[0]
        cursor = 24
        present = []
        for table in range(64):
            if valid >> table & 1:
                if cursor + 4 > len(data):
                    raise MetadataError("truncated table row counts")
                self.sizes[table] = struct.unpack_from("<I", data, cursor)[0]
                cursor += 4
                present.append(table)
        if heap_sizes & 0x40:
            cursor += 4
        self._row_offsets: dict[int, int] = {}
        for table in present:
            if table not in SCHEMAS:
                raise MetadataError(f"unsupported metadata table 0x{table:02x} in fixture")
            self._row_offsets[table] = cursor
            cursor += self.sizes[table] * self._row_size(table)
        if cursor > len(data):
            raise MetadataError("table rows exceed table stream")
        for table in present:
            self._parse_rows(table)

    def _row_size(self, table: int) -> int:
        return sum(self._column_size(kind) for _, kind in SCHEMAS[table])

    def _coded_size(self, coded: str) -> int:
        bits, tables = CODED_INDEXES[coded]
        max_rows = max((self.sizes.get(table, 0) for table in tables if table is not None), default=0)
        return 2 if max_rows < (1 << (16 - bits)) else 4

    def _column_size(self, kind: str) -> int:
        if kind == C_U16:
            return 2
        if kind == C_U32:
            return 4
        if kind == C_STRING:
            return 2 if self.streams["#Strings"][1] < 0x10000 else 4
        if kind == C_GUID:
            return 2 if self.streams["#GUID"][1] < 0x10000 else 4
        if kind == C_BLOB:
            return 2 if self.streams["#Blob"][1] < 0x10000 else 4
        if kind.startswith(C_TABLE):
            table = TABLE_NAMES[kind[len(C_TABLE):]]
            return 2 if self.sizes.get(table, 0) < 0x10000 else 4
        if kind.startswith(C_CODED):
            return self._coded_size(kind[len(C_CODED):])
        raise MetadataError(f"unknown column kind {kind}")

    def _parse_rows(self, table: int) -> None:
        strings = self._stream("#Strings")
        blobs = self._stream("#Blob")
        rows = []
        cursor = self._table_stream_base + self._row_offsets[table]
        for _ in range(self.sizes[table]):
            row = {}
            for name, kind in SCHEMAS[table]:
                size = self._column_size(kind)
                value = int.from_bytes(self.data[cursor:cursor + size], "little")
                cursor += size
                if kind == C_STRING:
                    value = self._heap_string(strings, value)
                elif kind == C_BLOB:
                    value = self._heap_blob(blobs, value)
                row[name] = value
            rows.append(row)
        self.table_rows[table] = rows
