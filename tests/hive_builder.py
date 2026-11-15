"""Minimal offline registry hive builder used by the link tests.

It produces byte streams that :class:`dissect.regf.RegistryHive` can parse, so
link resolution can be exercised without touching the host registry or any
binary test fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO

from dissect.regf.c_regf import (
    KEY,
    REG_LINK,
    REG_SZ,
    VALUE,
    c_regf,
)

NO_CELL = 0xFFFFFFFF
HBASE_SIGNATURE = 0x66676572
HBIN_SIGNATURE = 0x6E696268
ALIGNMENT = 8
PAGE = 0x1000


@dataclass
class Cell:
    payload: bytes
    patches: dict[int, int] = field(default_factory=dict)


@dataclass
class CellRef:
    name: str


@dataclass
class ValueSpec:
    name: str
    type: int
    data: bytes


@dataclass
class KeySpec:
    name: str
    values: list[ValueSpec] = field(default_factory=list)
    subkeys: list[KeySpec] = field(default_factory=list)
    link: bool = False
    root: bool = False


def _pad(payload: bytes) -> bytes:
    overflow = len(payload) % ALIGNMENT
    if overflow:
        payload += b"\x00" * (ALIGNMENT - overflow)
    return payload


class HiveBuilder:
    def __init__(self, filename: str = "BUILDER"):
        self.filename = filename
        self._cells: dict[str, Cell] = {}
        self._names: dict[str, str] = {}

    def _unique(self, prefix: str) -> str:
        index = len(self._cells)
        return f"{prefix}_{index}"

    def add_data(self, data: bytes) -> CellRef:
        name = self._unique("data")
        self._cells[name] = Cell(_pad(data))
        return CellRef(name)

    def add_value(self, spec: ValueSpec) -> CellRef:
        name_blob = spec.name.encode("utf-16-le")
        struct = c_regf.CM_KEY_VALUE()
        struct.Signature = b"vk"
        struct.NameLength = len(name_blob)
        struct.Type = spec.type
        struct.Flags = VALUE(0)
        struct.Spare = 0

        # Always store data in its own cell with the high bit clear, the layout
        # RegistryHive.KeyValue.data expects when reading a cell offset.
        data_ref = self.add_data(spec.data)
        struct.DataLength = len(spec.data)
        cell = Cell(_pad(struct.dumps() + name_blob))
        cell.patches = {c_regf.CM_KEY_VALUE.fields["Data"].offset: ("ref", data_ref)}

        name = self._unique("vk")
        self._cells[name] = cell
        return CellRef(name)

    def add_key(self, spec: KeySpec, parent_ref: CellRef | None = None) -> CellRef:
        name_blob = spec.name.encode("utf-16-le")
        struct = c_regf.CM_KEY_NODE()
        struct.Signature = b"nk"
        flags = KEY(0)
        if spec.link:
            flags |= KEY.SYM_LINK
        if spec.root:
            flags |= KEY.HIVE_ENTRY | KEY.NO_DELETE | KEY.COMP_NAME
        struct.Flags = flags
        struct.Parent = NO_CELL
        struct.Security = NO_CELL
        struct.Class = NO_CELL
        struct.NameLength = len(name_blob)
        struct.ClassLength = 0

        value_refs = [self.add_value(value) for value in spec.values]
        struct.ValueList.Count = len(value_refs)
        patches: dict[int, object] = {}
        if value_refs:
            # Every value (inline data included) is reached through this list.
            list_ref = self.add_data(b"".join(b"\x00\x00\x00\x00" for _ in value_refs))
            patches[c_regf.CHILD_LIST.fields["List"].offset + c_regf.CM_KEY_NODE.fields["ValueList"].offset] = (
                "ref",
                list_ref,
            )
            list_cell = self._cells[list_ref.name]
            for index, value_ref in enumerate(value_refs):
                list_cell.patches[index * 4] = ("ref", value_ref)
        sub_refs = [self.add_key(child) for child in spec.subkeys]
        struct.SubKeyCounts[0] = len(sub_refs)
        if sub_refs:
            index_ref = self._add_hash_index(sub_refs)
            patches[c_regf.CM_KEY_NODE.fields["SubKeyLists"].offset] = ("ref", index_ref)

        cell = Cell(_pad(struct.dumps() + name_blob), patches)
        name = self._unique("nk")
        self._cells[name] = cell
        self._names[name] = spec.name

        ref = CellRef(name)
        if parent_ref is not None:
            cell.patches[c_regf.CM_KEY_NODE.fields["Parent"].offset] = ("ref", parent_ref)
        for child_ref in sub_refs:
            self._cells[child_ref.name].patches[c_regf.CM_KEY_NODE.fields["Parent"].offset] = ("ref", ref)
        return ref

    def _add_hash_index(self, refs: list[CellRef]) -> CellRef:
        payload = b"lh" + c_regf.uint16.dumps(len(refs))
        entries = b""
        for ref in refs:
            entries += c_regf.uint32.dumps(0) + c_regf.uint32.dumps(_hashname(self._names[ref.name]))
        name = self._unique("lh")
        cell = Cell(_pad(payload + entries))
        for index, ref in enumerate(refs):
            cell.patches[4 + index * c_regf.CM_HASH_INDEX.size] = ("ref", ref)
        self._cells[name] = cell
        return CellRef(name)

    def build(self, root: KeySpec) -> bytes:
        root_ref = self.add_key(root)
        layout = self._layout()
        root_offset = layout[root_ref.name]

        # Group cell names by the page the allocator placed them on.
        pages: dict[int, list[str]] = {}
        for name, offset in layout.items():
            pages.setdefault(offset // PAGE, []).append(name)
        page_count = max(pages) + 1
        hbin_size = page_count * PAGE

        hbins = bytearray()
        for page_index in range(page_count):
            chunk = bytearray()
            for name in pages.get(page_index, []):
                cell = self._cells[name]
                blob = bytearray(cell.payload)
                for patch_offset, patch in cell.patches.items():
                    kind, ref = patch
                    assert kind == "ref"
                    blob[patch_offset : patch_offset + 4] = c_regf.uint32.dumps(layout[ref.name])
                chunk += c_regf.int32.dumps(-(len(blob) + 4)) + blob

            free_size = PAGE - len(c_regf._HBIN) - len(chunk)
            if free_size >= 4:
                chunk += c_regf.int32.dumps(free_size) + b"\x00" * (free_size - 4)

            hbin_struct = c_regf._HBIN(b"\x00" * c_regf._HBIN.size)
            hbin_struct.Signature = HBIN_SIGNATURE
            hbin_struct.FileOffset = page_index * PAGE
            hbin_struct.Size = PAGE
            hbins += hbin_struct.dumps() + chunk

        header = c_regf._HBASE_BLOCK(b"\x00" * c_regf._HBASE_BLOCK.size)
        header.Signature = HBASE_SIGNATURE
        header.Major = 1
        header.Minor = 5
        header.Type = 0
        header.Format = 1
        header.RootCell = root_offset
        header.Length = hbin_size
        header.Cluster = 1
        header.FileName = self.filename
        header_blob = bytearray(header.dumps())
        checksum = 0
        for index in range(0, 508, 4):
            checksum ^= c_regf.uint32(bytes(header_blob[index : index + 4]))
        header.CheckSum = checksum
        header_blob = bytearray(header.dumps())

        return bytes(header_blob) + bytes(hbins)

    def _layout(self) -> dict[str, int]:
        # Allocate hive-relative cell offsets one hbin page at a time. Each page
        # reserves its 32-byte hbin header and a cell never spans a boundary, so
        # a cell that does not fit spills to the start of the next page.
        offsets = {}
        page_index = 0
        cursor = len(c_regf._HBIN)
        for name, cell in self._cells.items():
            cell_size = 4 + len(cell.payload)
            if cursor + cell_size > PAGE:
                page_index += 1
                cursor = len(c_regf._HBIN)
            offsets[name] = page_index * PAGE + cursor
            cursor += cell_size
        return offsets


def link_value(target: str) -> ValueSpec:
    return ValueSpec("SymbolicLinkValue", REG_LINK, target.encode("utf-16-le") + b"\x00\x00")


def string_value(name: str, value: str) -> ValueSpec:
    return ValueSpec(name, REG_SZ, value.encode("utf-16-le") + b"\x00\x00")


def _hashname(name: str) -> int:
    name_hash = 0
    for char in name.upper():
        name_hash = (name_hash * 37 + ord(char)) & 0xFFFFFFFF
    return name_hash


def build_hive(spec: KeySpec, filename: str = "BUILDER") -> BytesIO:
    return BytesIO(HiveBuilder(filename).build(spec))
