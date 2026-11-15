"""Build a minimal synthetic SYSTEM hive for BAM/DAM attribution tests.

The hive is serialized in the on-disk REGF format so ``dissect.regf`` can read
it back unchanged.  It deliberately contains malformed and edge-case records
(unknown trailing bytes, invalid FILETIMEs, a malformed SID, short binaries);
it is fabricated test data, not an image of a real machine.

Usage:
    python bam_dam_attribution/fixtures/build_fixture_hive.py [output_path]
"""

from __future__ import annotations

import datetime as dt
import struct
import sys
from pathlib import Path

REG_DWORD = 0x4
REG_BINARY = 0x3
HBASE_SIZE = 0x1000
HBIN_SIZE = 0x1000
HBIN_HEADER = 0x20
NO_OFFSET = 0xFFFFFFFF


def align8(value: int) -> int:
    return (value + 7) & ~7


def cell_size(payload: bytes) -> int:
    """Total on-disk cell size, including the leading 4-byte size field."""
    return align8(4 + len(payload))


def filetime(year: int, month: int, day: int, hour: int = 0) -> int:
    epoch = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    moment = dt.datetime(year, month, day, hour, tzinfo=dt.timezone.utc)
    return int((moment - epoch).total_seconds() * 10_000_000)


def bam_record(head: int, timestamp: int, tail: bytes = b"") -> bytes:
    """24-byte BAM/DAM payload: head QWORD + FILETIME QWORD (+ unknown tail)."""
    return struct.pack("<QQ", head, timestamp) + tail


class Node:
    """Logical registry key, independent of cell offsets."""

    def __init__(self, name: str, last_write: int):
        self.name = name
        self.last_write = last_write
        self.children: list[Node] = []
        self.values: list[tuple[str, int, bytes]] = []
        self.offset = NO_OFFSET
        self.parent_offset = NO_OFFSET
        self.subkey_list_offset = NO_OFFSET
        self.value_list_offset = NO_OFFSET

    def add_child(self, node: Node) -> Node:
        self.children.append(node)
        return node

    def add_value(self, name: str, data_type: int, data: bytes) -> None:
        self.values.append((name, data_type, data))


class Slot:
    """A cell whose cross-references are resolved after bin packing."""

    def __init__(self, kind: str, payload: bytes, refs: dict[int, int] | None = None):
        self.kind = kind
        self.payload = bytearray(payload)
        self.refs = refs or {}  # byte offset inside payload -> placeholder id
        self.placeholder = 0
        self.offset = NO_OFFSET

    def resolve(self, mapping: dict[int, int]) -> None:
        for at, placeholder in self.refs.items():
            if placeholder == NO_OFFSET:
                struct.pack_into("<I", self.payload, at, NO_OFFSET)
            else:
                struct.pack_into("<I", self.payload, at, mapping[placeholder])


class HiveWriter:
    def __init__(self) -> None:
        self.slots: list[Slot] = []
        self._next_placeholder = 1
        self.security_placeholder = 0
        self.bin_count = 1

    def _add(self, kind: str, payload: bytes, refs: dict[int, int] | None = None) -> Slot:
        slot = Slot(kind, payload, refs)
        slot.placeholder = self._next_placeholder
        self._next_placeholder += 1
        self.slots.append(slot)
        return slot

    def add_security(self) -> int:
        descriptor = bytes.fromhex(
            "010004801400000020000000000000001400000002001c00"
            "0100000000001400ff010f0001010000000000050a000000"
        )
        payload = struct.pack("<2sHIIII", b"sk", 0, NO_OFFSET, NO_OFFSET, 0, len(descriptor))
        payload += descriptor
        slot = self._add("sk", payload)
        self.security_placeholder = slot.placeholder
        return slot.placeholder

    def add_data(self, blob: bytes) -> tuple[int, int, bool]:
        if len(blob) <= 4:
            return struct.unpack("<I", blob.ljust(4, b"\x00"))[0], len(blob), True
        return self._add("data", blob).placeholder, len(blob), False

    def add_value(self, name: str, data_type: int, blob: bytes) -> int:
        name_blob = name.encode("utf-16-le")
        data_ref, data_len, inline = self.add_data(blob)
        refs = {} if inline else {8: data_ref}
        payload = struct.pack(
            "<2sHIIIHH",
            b"vk",
            len(name_blob),
            data_len | (0x80000000 if inline else 0),
            data_ref if inline else 0,
            data_type,
            0,
            0,
        )
        return self._add("vk", payload + name_blob, refs).placeholder

    def add_value_list(self, value_placeholders: list[int]) -> int:
        payload = b"".join(struct.pack("<I", 0) for _ in value_placeholders)
        refs = {index * 4: ph for index, ph in enumerate(value_placeholders)}
        return self._add("value_list", payload, refs).placeholder

    def add_index(self, child_placeholders: list[int]) -> int:
        payload = struct.pack("<2sH", b"li", len(child_placeholders))
        payload += b"\x00" * (4 * len(child_placeholders))
        refs = {4 + index * 4: ph for index, ph in enumerate(child_placeholders)}
        return self._add("li", payload, refs).placeholder

    def add_nk(self, node: Node, parent_ph: int, is_root: bool = False) -> int:
        name_blob = node.name.encode("utf-16-le")
        refs = {0x10: parent_ph, 0x1C: node.subkey_list_offset, 0x28: node.value_list_offset, 0x2C: self.security_placeholder}
        flags = 0x4 if is_root else 0  # HIVE_ENTRY terminates parent-chain walks
        payload = struct.pack(
            "<2sHQIIIIIIIIIIIIIIIHH",
            b"nk",
            flags,
            node.last_write,
            0,
            0,  # Parent (ref)
            len(node.children),
            0,
            0,  # SubKeyList (ref)
            NO_OFFSET,
            len(node.values),
            0,  # ValueList (ref)
            0,  # Security (ref)
            NO_OFFSET,
            len(node.name),
            0,
            len(node.name),
            0x1000,
            0,
            len(name_blob),
            0,
        )
        slot = self._add("nk", payload + name_blob, refs)
        node.offset = slot.placeholder
        return slot.placeholder

    # ---- layout ----------------------------------------------------------
    def build(self, root: Node) -> bytes:
        self.add_security()
        root_ph = self._collect(root, parent_ph=None, is_root=True)
        # Root NK parent points at itself; HIVE_ENTRY stops parent-chain walks.
        self._slot(root_ph).refs[0x10] = root_ph
        mapping = self._pack()
        for slot in self.slots:
            slot.resolve(mapping)
        return self._assemble(root, mapping)

    def _slot(self, placeholder: int) -> Slot:
        return next(slot for slot in self.slots if slot.placeholder == placeholder)

    def _collect(self, node: Node, parent_ph: int | None, is_root: bool = False) -> int:
        child_placeholders = [self._collect(child, None) for child in node.children]
        value_placeholders = [self.add_value(name, data_type, blob) for name, data_type, blob in node.values]
        node.value_list_offset = self.add_value_list(value_placeholders) if value_placeholders else NO_OFFSET
        node.subkey_list_offset = self.add_index(child_placeholders) if child_placeholders else NO_OFFSET
        effective_parent = parent_ph if parent_ph is not None else NO_OFFSET
        nk_ph = self.add_nk(node, effective_parent, is_root=is_root)
        node.offset = nk_ph
        # Children now reference this NK as their parent.
        for child, child_ph in zip(node.children, child_placeholders):
            self._slot(child_ph).refs[0x10] = nk_ph
        return nk_ph

    def _pack(self) -> dict[int, int]:
        mapping: dict[int, int] = {}
        bin_index = 0
        cursor = HBIN_HEADER
        for slot in self.slots:
            size = cell_size(bytes(slot.payload))
            # A bin spans [header, 0x1000); keep every cell fully inside it.
            if cursor + size > HBIN_SIZE:
                bin_index += 1
                cursor = HBIN_HEADER
            offset = bin_index * HBIN_SIZE + cursor
            mapping[slot.placeholder] = offset
            slot.offset = offset
            cursor += size
        self.bin_count = max(1, bin_index + 1)
        return mapping

    def _assemble(self, root: Node, mapping: dict[int, int]) -> bytes:
        highest_bin = max((slot.offset // HBIN_SIZE for slot in self.slots), default=0)
        self.bin_count = highest_bin + 1
        bins_size = self.bin_count * HBIN_SIZE
        total_size = HBASE_SIZE + bins_size
        image = bytearray(total_size)
        base = bytearray(HBASE_SIZE)
        root_offset = mapping[root.offset]
        struct.pack_into("<I", base, 0, 0x66676572)
        struct.pack_into("<I", base, 4, 1)
        struct.pack_into("<I", base, 8, 1)
        struct.pack_into("<Q", base, 0x0C, filetime(2026, 11, 1, 9))
        struct.pack_into("<I", base, 0x14, 1)
        struct.pack_into("<I", base, 0x18, 3)
        struct.pack_into("<I", base, 0x24, root_offset)
        struct.pack_into("<I", base, 0x28, bins_size)
        struct.pack_into("<I", base, 0x2C, 1)
        filename = "SYSTEM_fixture".encode("utf-16-le")
        base[0x30 : 0x30 + len(filename)] = filename
        checksum = 0
        for index in range(0, 0x1FC, 4):
            checksum ^= struct.unpack_from("<I", base, index)[0]
        struct.pack_into("<I", base, 0x1FC, checksum)
        image[0:HBASE_SIZE] = base

        for index in range(self.bin_count):
            pos = HBASE_SIZE + index * HBIN_SIZE
            image[pos : pos + HBIN_HEADER] = self._hbin_header(index)

        for slot in self.slots:
            payload = bytes(slot.payload)
            record_size = cell_size(payload)
            at = HBASE_SIZE + slot.offset
            struct.pack_into("<i", image, at, -record_size)
            image[at + 4 : at + 4 + len(payload)] = payload

        # Fill the unused tail of every hbin with one positive-size free cell.
        for index in range(self.bin_count):
            bin_start = index * HBIN_SIZE
            bin_slots = [
                slot for slot in self.slots if bin_start <= slot.offset < bin_start + HBIN_SIZE
            ]
            used = max(
                (slot.offset - bin_start + cell_size(bytes(slot.payload)) for slot in bin_slots),
                default=HBIN_HEADER,
            )
            free_size = HBIN_SIZE - used
            if free_size >= 4:
                # Absolute file position = base block + global cell offset.
                free_cell_offset = bin_start + used
                free_at = HBASE_SIZE + free_cell_offset
                struct.pack_into("<i", image, free_at, free_size)
        return bytes(image)

    def _hbin_header(self, bin_index: int) -> bytes:
        header = bytearray(HBIN_HEADER)
        struct.pack_into("<I", header, 0, 0x6E696268)
        struct.pack_into("<I", header, 4, bin_index * HBIN_SIZE)
        struct.pack_into("<I", header, 8, HBIN_SIZE)
        struct.pack_into("<Q", header, 0x18, filetime(2026, 11, 1, 9))
        return bytes(header)


def build_tree() -> Node:
    sid_a = "S-1-5-21-1111111111-2222222222-3333333333-1001"
    sid_b = "S-1-5-21-1111111111-2222222222-3333333333-1002"
    sid_c = "S-1-5-21-1111111111-2222222222-3333333333-1003"
    shared = r"\Device\HarddiskVolume3\Program Files\SharedApp\app.exe"
    cmd = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe"
    lw = filetime(2026, 10, 7, 12)

    root = Node("CMI-CreateHive-{00000000-0000-0000-0000-000000000000}", filetime(2026, 10, 7, 12))
    for control_set in ("ControlSet001", "ControlSet002"):
        cs_node = root.add_child(Node(control_set, lw))
        services = cs_node.add_child(Node("Services", lw))
        for service_name in ("bam", "dam"):
            if control_set == "ControlSet002" and service_name == "dam":
                continue
            service = services.add_child(Node(service_name, lw))
            user_settings = service.add_child(Node("UserSettings", lw))
            for sid_name, values in _leaf_specs(control_set, service_name, sid_a, sid_b, sid_c, shared, cmd):
                sid_node = user_settings.add_child(Node(sid_name, lw))
                for program_path, blob in values:
                    sid_node.add_value(program_path, REG_BINARY, blob)
    select = root.add_child(Node("Select", lw))
    for name, value in (("Current", 1), ("Default", 1), ("Failed", 0), ("LastKnownGood", 1)):
        select.add_value(name, REG_DWORD, struct.pack("<I", value))
    return root


def _leaf_specs(control_set, service_name, sid_a, sid_b, sid_c, shared, cmd):
    if control_set == "ControlSet002":
        return [(sid_a, [(shared, bam_record(1, filetime(2026, 9, 1, 8)))])]
    if service_name == "dam":
        return [(sid_a, [(shared, bam_record(2, filetime(2026, 10, 3, 14), tail=b"\xde\xad"))])]
    return [
        (
            sid_a,
            [
                (shared, bam_record(1, filetime(2026, 10, 1, 8))),
                (cmd, bam_record(1, filetime(2026, 10, 2, 9), tail=b"\xaa\xbb\xcc\xdd")),
            ],
        ),
        (sid_b, [(shared, bam_record(1, filetime(2026, 10, 5, 10)))]),
        (
            "S-1-5-21-BAD-SID",
            [(r"\Device\HarddiskVolume3\Tools\weird.exe", bam_record(1, filetime(2026, 10, 6, 11)))],
        ),
        (
            sid_c,
            [
                (r"\Device\HarddiskVolume3\Tools\zero.exe", bam_record(1, 0)),
                (r"\Device\HarddiskVolume3\Tools\future.exe", bam_record(1, filetime(2101, 1, 1))),
                (r"\Device\HarddiskVolume3\Tools\short.exe", b"\x01\x00\x00\x00"),
            ],
        ),
    ]


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("bam_dam_attribution/fixtures/SYSTEM_fixture")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(HiveWriter().build(build_tree()))
    print(f"wrote {target} ({target.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
