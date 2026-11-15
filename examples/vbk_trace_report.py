"""Demonstrate traceable VBK metadata reading on a small two-bank structure.

The script builds an in-memory VBK-like layout with two banks and walks several
meta blobs with :class:`~dissect.archive.vbk.trace.TracedMetaBlob`:

- a legitimate directory whose properties cross the bank boundary;
- a second directory with its own valid page;
- a faulty reference that points at that second directory's page;
- a cycle, a missing page and a truncated page.

For every property it prints the exact bank, page and file offset the bytes came
from and reads those bytes back from the backing file to prove provenance. A
parseable page owned by another directory is never borrowed as evidence.

Run it with::

    python examples/vbk_trace_report.py
"""

from __future__ import annotations

import io
import struct

from dissect.archive.vbk.c_vbk import PAGE_SIZE, c_vbk
from dissect.archive.vbk.trace import (
    PageAddress,
    PageOwnership,
    TracedMetaBlob,
    TracedPropertiesDictionary,
)

PROP_TYPES = c_vbk.PropertyType


class BufferView(io.RawIOBase):
    """A readable binary view over a mutable bytearray without copying it."""

    def __init__(self, buffer: bytearray):
        self._buffer = buffer
        self._pos = 0

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        else:
            self._pos = len(self._buffer) + offset
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunk = self._buffer[self._pos :]
            self._pos = len(self._buffer)
        else:
            chunk = self._buffer[self._pos : self._pos + size]
            self._pos += len(chunk)
        return bytes(chunk)


class FakeBank:
    """An in-memory bank with the same header/data-page layout as a real bank."""

    def __init__(self, offset: int, data_pages: int, populated_pages: int | None = None):
        self.offset = offset
        self.page_count = populated_pages if populated_pages is not None else data_pages
        self.size = PAGE_SIZE + data_pages * PAGE_SIZE


class FakeSlot:
    def __init__(self, vbk: FakeVBK, banks: list[FakeBank]):
        self.vbk = vbk
        self.banks = banks

    def page(self, page: int) -> memoryview:
        bank = self.banks[page >> 32]
        in_bank = page & 0xFFFFFFFF
        offset = bank.offset + PAGE_SIZE + in_bank * PAGE_SIZE
        return memoryview(self.vbk.buf[offset : offset + PAGE_SIZE])


class FakeVBK:
    def __init__(self, buffer: bytearray, banks: list[FakeBank]):
        self.fh = BufferView(buffer)
        self.slot = FakeSlot(self, banks)


def encode_property(prop_type: PROP_TYPES, name: str, value: object) -> bytes:
    out = struct.pack("<i", int(prop_type))
    name_bytes = name.encode("utf-8")
    out += struct.pack("<I", len(name_bytes)) + name_bytes
    if prop_type == PROP_TYPES.UInt32:
        out += struct.pack("<I", value)
    elif prop_type == PROP_TYPES.UInt64:
        out += struct.pack("<Q", value)
    elif prop_type == PROP_TYPES.Boolean:
        out += struct.pack("<I", int(value))
    elif prop_type == PROP_TYPES.AString:
        raw = value.encode("utf-8")
        out += struct.pack("<I", len(raw)) + raw
    elif prop_type == PROP_TYPES.Binary:
        out += struct.pack("<I", len(value)) + value
    else:
        raise ValueError(f"Unsupported property type {prop_type}")
    return out


def encode_properties(properties: list[tuple[PROP_TYPES, str, object]]) -> bytes:
    return b"".join(encode_property(*prop) for prop in properties) + struct.pack("<i", int(PROP_TYPES.End))


class TwoBankMetadata:
    """Construct the two-bank demonstration layout in memory."""

    GOOD_ROOT = (0 << 32) | 0
    GOOD_MID = (0 << 32) | 1
    GOOD_TAIL = (1 << 32) | 0

    FOREIGN_BLOB_ROOT = (1 << 32) | 1
    BORROW_ROOT = (0 << 32) | 2

    CYCLE_ROOT = (0 << 32) | 3
    CYCLE_LOOP_TARGET = (0 << 32) | 6
    MISSING_ROOT = (0 << 32) | 5
    MISSING_TARGET = (0 << 32) | 9
    SELF_ROOT = (0 << 32) | 7
    TRUNCATED_ROOT = (1 << 32) | 2

    def __init__(self):
        bank0 = FakeBank(0, data_pages=10, populated_pages=8)
        bank1 = FakeBank(bank0.size, data_pages=3, populated_pages=3)
        self.banks = [bank0, bank1]

        truncated_end = self._page_offset(self.TRUNCATED_ROOT) + 128
        self.buf = bytearray(b"\x00" * truncated_end)
        for bank in self.banks:
            header_at = bank.offset + PAGE_SIZE - 2
            self.buf[header_at : header_at + 2] = struct.pack("<H", bank.page_count)

        self.vbk = FakeVBK(self.buf, self.banks)
        self.slot = self.vbk.slot
        self.ownership = PageOwnership()

        self._build_foreign_blob()
        self._build_good_blob()
        self._build_broken_blobs()

    def _page_offset(self, composite: int) -> int:
        bank = self.banks[composite >> 32]
        return bank.offset + PAGE_SIZE + (composite & 0xFFFFFFFF) * PAGE_SIZE

    def _write_page(self, composite: int, next_page: int, payload: bytes, header_size: int = 8) -> None:
        offset = self._page_offset(composite)
        header = struct.pack("<qi", next_page, 0) if header_size == 12 else struct.pack("<q", next_page)
        self.buf[offset : offset + len(header) + len(payload)] = header + payload

    def _write_blob(self, chain: list[int], payload: bytes, label: str) -> None:
        cursor = 0
        for index, composite in enumerate(chain):
            header_size = len(c_vbk.MetaBlobHeader) if index == 0 else 8
            chunk = payload[cursor : cursor + PAGE_SIZE - header_size]
            cursor += len(chunk)
            next_page = chain[index + 1] if index + 1 < len(chain) else -1
            self._write_page(composite, next_page, chunk, header_size)
        for composite in chain:
            self.ownership.claim(PageAddress.decode(composite), label)

    def _build_foreign_blob(self) -> None:
        payload = encode_properties(
            [
                (PROP_TYPES.AString, "DirectoryB", "legitimate-evidence"),
                (PROP_TYPES.UInt32, "ValidPage", 0x42),
            ]
        )
        self._write_blob([self.FOREIGN_BLOB_ROOT], payload, label="directory-B")

    def _build_good_blob(self) -> None:
        first_capacity = PAGE_SIZE - len(c_vbk.MetaBlobHeader)
        second_capacity = PAGE_SIZE - 8
        prefix = encode_property(PROP_TYPES.UInt32, "NodeId", 7)
        host_header = 4 + 4 + len("Host") + 4
        host_value = "H" * (first_capacity + second_capacity - len(prefix) - host_header + 24)
        self.good_payload = encode_properties(
            [
                (PROP_TYPES.UInt32, "NodeId", 7),
                (PROP_TYPES.AString, "Host", host_value),
                (PROP_TYPES.UInt64, "SnapshotSize", 0x1122334455667788),
                (PROP_TYPES.Boolean, "Consistent", True),
            ]
        )
        self._write_blob([self.GOOD_ROOT, self.GOOD_MID, self.GOOD_TAIL], self.good_payload, label="directory-A")

    def _build_broken_blobs(self) -> None:
        self._write_page(self.BORROW_ROOT, self.FOREIGN_BLOB_ROOT, b"borrower-prefix")
        self._write_page(self.CYCLE_ROOT, self.CYCLE_LOOP_TARGET, b"cycle-a")
        self._write_page(self.CYCLE_LOOP_TARGET, self.CYCLE_ROOT, b"cycle-b")
        self._write_page(self.MISSING_ROOT, self.MISSING_TARGET, b"points-nowhere")
        self._write_page(self.SELF_ROOT, self.SELF_ROOT, b"self-loop")

        offset = self._page_offset(self.TRUNCATED_ROOT)
        short = struct.pack("<qi", -1, 0) + b"truncated"
        self.buf[offset : offset + len(short)] = short


def report_chain(title: str, blob: TracedMetaBlob) -> None:
    print(f"\n=== {title} (root composite page {blob.root}) ===")
    for source in blob.sources:
        print(
            f"  page #{source.index}: bank={source.address.bank} in_bank_page={source.address.page}"
            f" file_offset={source.file_offset:#x} next_page={source.next_page}"
        )
    if blob.complete:
        print("  status: COMPLETE - chain ended on a -1 pointer")
    else:
        bp = blob.breakpoint
        target = bp.referenced_address
        target_text = f"bank={target.bank} page={target.page}" if target else "end-of-chain"
        print(f"  status: INCOMPLETE - {bp.fault.value} at chain position {bp.chain_index}")
        print(f"  breakpoint reference: raw={bp.referenced} ({target_text})")
        print(f"  reason: {bp.message}")
        if bp.owner:
            print(f"  page already owned by: {bp.owner}")
        print("  retained partial pages are not marked complete and cannot be used as attributes")


def report_properties(meta: TwoBankMetadata) -> None:
    props = TracedPropertiesDictionary(meta.slot, meta.GOOD_ROOT, meta.ownership, "directory-A")
    print("\n=== Trusted directory-A properties (cross-bank blob) ===")
    print(f"  blob complete: {props.complete}")
    fh = meta.vbk.fh
    for name, prop in props.items():
        fragments = prop.value_range.fragments(props.blob)
        locations = ", ".join(
            f"bank={source.address.bank}/page={source.address.page}@0x{offset:x}[{length}]"
            for source, offset, length in fragments
        )
        read_back = prop.value_range.read_back(props.blob, fh)
        value = prop.value if not isinstance(prop.value, str) or len(prop.value) <= 24 else f"{prop.value[:24]}..."
        print(f"  {name} = {value!r}")
        print(f"      value bytes: {locations}")
        encoded_value = encode_property(prop.type, name, prop.value)[-len(read_back) :]
        print(f"      read-back matches encoded value: {read_back == encoded_value}")

    host = props["Host"]
    banks = {source.address.bank for source, _, _ in host.value_range.fragments(props.blob)}
    print(f"  Host attribute spans banks: {sorted(banks)} (single attribute crossing the bank boundary)")


def main() -> None:
    meta = TwoBankMetadata()
    print("VBK traceability demonstration")
    print(f"page size: {PAGE_SIZE} bytes; banks: {len(meta.banks)}")
    print("composite page = (bank << 32) | in_bank_page")

    report_chain(
        "Legitimate cross-bank directory",
        TracedMetaBlob(meta.slot, meta.GOOD_ROOT, meta.ownership, "directory-A"),
    )
    report_properties(meta)

    report_chain(
        "Second directory's own valid blob",
        TracedMetaBlob(meta.slot, meta.FOREIGN_BLOB_ROOT, meta.ownership, "directory-B"),
    )
    report_chain(
        "Faulty reference into the second directory's page",
        TracedMetaBlob(meta.slot, meta.BORROW_ROOT, meta.ownership, "directory-C"),
    )
    report_chain("Two-page cycle", TracedMetaBlob(meta.slot, meta.CYCLE_ROOT, PageOwnership(), "cycle"))
    report_chain("Self reference", TracedMetaBlob(meta.slot, meta.SELF_ROOT, PageOwnership(), "self"))
    report_chain("Missing page", TracedMetaBlob(meta.slot, meta.MISSING_ROOT, PageOwnership(), "missing"))
    report_chain("Truncated page", TracedMetaBlob(meta.slot, meta.TRUNCATED_ROOT, PageOwnership(), "truncated"))

    print("\n=== Ownership registry ===")
    for composite in sorted(meta.ownership.claimed()):
        address = PageAddress.decode(composite)
        print(f"  bank={address.bank} page={address.page} -> {meta.ownership.owner_of(address)}")
    print("\nConclusion: foreign, cyclic, missing and truncated references keep their breakpoints;")
    print("only fully validated chains expose attributes, and every byte is read back to its source.")


if __name__ == "__main__":
    main()
