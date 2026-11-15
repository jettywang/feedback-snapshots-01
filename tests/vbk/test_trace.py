from __future__ import annotations

import io
import struct

import pytest

from dissect.archive.vbk.c_vbk import PAGE_SIZE, c_vbk
from dissect.archive.vbk.trace import (
    ChainFault,
    PageAddress,
    PageOwnership,
    TracedMetaBlob,
    TracedPropertiesDictionary,
)

PROP_TYPES = c_vbk.PropertyType


class FakeBank:
    """An in-memory bank backed by a byte buffer, with the same layout as a real bank."""

    def __init__(self, vbk: FakeVBK, offset: int, data_pages: int, populated_pages: int | None = None):
        self.vbk = vbk
        self.offset = offset
        self.page_count = populated_pages if populated_pages is not None else data_pages
        # One bank header page plus the data page slots, matching the real layout.
        self.header_size = PAGE_SIZE
        self.size = self.header_size + data_pages * PAGE_SIZE


class FakeSlot:
    """An in-memory snapshot slot exposing the bits used by the trace reader."""

    def __init__(self, vbk: FakeVBK, banks: list[FakeBank]):
        self.vbk = vbk
        self.banks = banks

    def page(self, page: int) -> memoryview:
        bank = self.banks[page >> 32]
        in_bank = page & 0xFFFFFFFF
        offset = bank.offset + PAGE_SIZE + in_bank * PAGE_SIZE
        return memoryview(self.vbk.buf[offset : offset + PAGE_SIZE])


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


class FakeVBK:
    def __init__(self, buffer: bytearray, banks: list[FakeBank]):
        self.fh = BufferView(buffer)
        self.slot = FakeSlot(self, banks)


def encode_property(prop_type: PROP_TYPES, name: str, value: object) -> bytes:
    """Encode one property record exactly as it appears in a meta blob payload."""
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
    elif prop_type == PROP_TYPES.WString:
        raw = value.encode("utf-16-le")
        out += struct.pack("<I", len(raw)) + raw
    elif prop_type == PROP_TYPES.Binary:
        out += struct.pack("<I", len(value)) + value
    else:
        raise ValueError(f"Unsupported property type {prop_type}")
    return out


def encode_properties(properties: list[tuple[PROP_TYPES, str, object]]) -> bytes:
    return b"".join(encode_property(*prop) for prop in properties) + struct.pack("<i", int(PROP_TYPES.End))


class SyntheticMetadata:
    """A small, two-bank VBK metadata layout built entirely in memory."""

    # Composite page numbers: high 32 bits = bank, low 32 bits = in-bank page.
    GOOD_ROOT = (0 << 32) | 0
    GOOD_MID = (0 << 32) | 1
    GOOD_TAIL = (1 << 32) | 0

    FOREIGN_BLOB_ROOT = (1 << 32) | 1
    BORROW_ROOT = (0 << 32) | 2

    CYCLE_ROOT = (0 << 32) | 3
    CYCLE_SECOND = (0 << 32) | 4
    MISSING_ROOT = (0 << 32) | 5
    # Bank 0 holds 8 pages (indices 0-7); this target is beyond that range.
    MISSING_TARGET = (0 << 32) | 9
    SELF_ROOT = (0 << 32) | 7
    CYCLE_LOOP_TARGET = (0 << 32) | 6
    # The truncated page lives in bank 1 after its two populated pages.
    TRUNCATED_ROOT = (1 << 32) | 2

    def __init__(self) -> None:
        self.banks: list[FakeBank] = []
        self._build_banks()
        # Size the full backing buffer up front, including the 128 byte stub of
        # the truncated third page in bank 1, so later writes never reallocate.
        truncated_end = self._page_offset(self.TRUNCATED_ROOT) + 128
        self.buf = bytearray(b"\x00" * truncated_end)
        for bank in self.banks:
            header_at = bank.offset + bank.header_size - 2
            self.buf[header_at : header_at + 2] = struct.pack("<H", bank.page_count)
        self.vbk = FakeVBK(self.buf, self.banks)
        self.slot = self.vbk.slot
        self.ownership = PageOwnership()

        # The foreign blob is a fully parseable, legitimate blob owned by directory B.
        self.foreign_payload = encode_properties(
            [
                (PROP_TYPES.AString, "DirectoryB", "legitimate-evidence"),
                (PROP_TYPES.UInt32, "ValidPage", 0x42),
            ]
        )
        self._write_blob([self.FOREIGN_BLOB_ROOT], self.foreign_payload, label="directory-B")

        self.good_payload = self._build_good_blob()
        self._build_broken_blobs()

    def _build_banks(self) -> None:
        # Bank 0 spans 10 data page slots (8 populated); bank 1 spans 3 slots,
        # but its third page is only partially written to emulate truncation.
        bank0_slots, bank1_pages = 10, 3
        bank0 = FakeBank(self, 0, bank0_slots, populated_pages=8)
        bank1_offset = bank0.size
        # Bank 1 spans three page slots and reports three pages, but the third
        # page is only partially backed by the buffer to emulate truncation.
        bank1 = FakeBank(self, bank1_offset, bank1_pages, bank1_pages)
        self.banks.extend([bank0, bank1])

    def _page_offset(self, composite: int) -> int:
        bank = self.banks[composite >> 32]
        return bank.offset + bank.header_size + (composite & 0xFFFFFFFF) * PAGE_SIZE

    def _write_page(self, composite: int, next_page: int, payload: bytes, header_size: int = 8) -> None:
        offset = self._page_offset(composite)
        if header_size == len(c_vbk.MetaBlobHeader):
            header = struct.pack("<qi", next_page, 0)
        else:
            header = struct.pack("<q", next_page)
        content = header + payload
        if len(content) > PAGE_SIZE:
            raise ValueError("page content overflow")
        self.buf[offset : offset + len(content)] = content

    def _write_blob(self, chain: list[int], payload: bytes, label: str) -> None:
        """Split a payload over the given pages and link them together."""
        cursor = 0
        for index, composite in enumerate(chain):
            header_size = len(c_vbk.MetaBlobHeader) if index == 0 else 8
            capacity = PAGE_SIZE - header_size
            chunk = payload[cursor : cursor + capacity]
            cursor += len(chunk)
            next_page = chain[index + 1] if index + 1 < len(chain) else -1
            self._write_page(composite, next_page, chunk, header_size)

        # Pre-register ownership so later borrow attempts are detected.
        for composite in chain:
            self.ownership.claim(PageAddress.decode(composite), label)

        if cursor != len(payload):
            raise ValueError("payload did not fit in the supplied chain")

    def _build_good_blob(self) -> bytes:
        # Size the Host value so it starts in the second page (bank 0) and ends
        # in the third page (bank 1), proving a single attribute can cross banks.
        first_capacity = PAGE_SIZE - len(c_vbk.MetaBlobHeader)
        second_capacity = PAGE_SIZE - 8
        prefix = encode_property(PROP_TYPES.UInt32, "NodeId", 7)
        host_record_header = 4 + 4 + len("Host") + 4
        remaining_in_second = first_capacity + second_capacity - len(prefix) - host_record_header
        boundary_value = "H" * (remaining_in_second + 24)
        properties = [
            (PROP_TYPES.UInt32, "NodeId", 7),
            (PROP_TYPES.AString, "Host", boundary_value),
            (PROP_TYPES.UInt64, "SnapshotSize", 0x1122334455667788),
            (PROP_TYPES.Boolean, "Consistent", True),
        ]
        payload = encode_properties(properties)
        self._write_blob([self.GOOD_ROOT, self.GOOD_MID, self.GOOD_TAIL], payload, label="directory-A")
        return payload

    def _build_broken_blobs(self) -> None:
        # Borrowing blob: points into the foreign blob's page, which parses fine
        # but belongs to directory B.
        self._write_page(self.BORROW_ROOT, self.FOREIGN_BLOB_ROOT, b"borrower-prefix")

        # Genuine two-page cycle between two distinct fresh pages.
        cycle_a = self.CYCLE_ROOT
        cycle_b = self.CYCLE_LOOP_TARGET
        self._write_page(cycle_a, cycle_b, b"cycle-a")
        self._write_page(cycle_b, cycle_a, b"cycle-b")

        # Missing page: points at an unpopulated page beyond the bank data area.
        missing_target = self.MISSING_TARGET
        self._write_page(self.MISSING_ROOT, missing_target, b"points-nowhere")

        # Truncated page: the target sits at the very end of the buffer and is short.
        target_offset = self._page_offset(self.TRUNCATED_ROOT)
        self.buf.extend(b"\x00" * 128)
        short = struct.pack("<qi", -1, 0) + b"truncated"
        self.buf[target_offset : target_offset + len(short)] = short

        # Self reference: the page points at itself, so no progress is made.
        self._write_page(self.SELF_ROOT, self.SELF_ROOT, b"self-loop")


@pytest.fixture()
def metadata() -> SyntheticMetadata:
    return SyntheticMetadata()


def test_page_address_splits_bank_and_page() -> None:
    address = PageAddress.decode((2 << 32) | 123)
    assert address.bank == 2
    assert address.page == 123
    assert address.encode() == (2 << 32) | 123


def test_cross_bank_blob_is_complete(metadata: SyntheticMetadata) -> None:
    blob = TracedMetaBlob(metadata.slot, metadata.GOOD_ROOT, metadata.ownership, "directory-A")

    assert blob.complete
    assert [source.address.bank for source in blob.sources] == [0, 0, 1]
    assert [source.address.page for source in blob.sources] == [0, 1, 0]
    logical = blob.logical_data()
    # The physical pages are zero padded to their capacity; the real payload is
    # the exact prefix, after which only padding bytes remain.
    assert logical.startswith(metadata.good_payload)
    assert set(logical[len(metadata.good_payload) :]) == {0}


def test_each_property_reads_back_original_bytes(metadata: SyntheticMetadata) -> None:
    props = TracedPropertiesDictionary(metadata.slot, metadata.GOOD_ROOT, metadata.ownership, "directory-A")
    assert props.complete
    assert props.value("NodeId") == 7
    assert props.value("SnapshotSize") == 0x1122334455667788
    assert props.value("Consistent") is True

    fh = metadata.vbk.fh
    for name in ("NodeId", "Host", "SnapshotSize", "Consistent"):
        prop = props[name]
        raw_name = prop.name_range.read_back(blob=props.blob, fh=fh)
        raw_value = prop.value_range.read_back(blob=props.blob, fh=fh)
        assert raw_name == name.encode("utf-8")
        # The read-back value bytes must match the encoded record bytes.
        encoded = encode_property(prop.type, prop.name, prop.value)
        assert raw_value in encoded

    # The cross-bank Host property must be backed by pages in both banks.
    host = props["Host"]
    fragment_banks = {source.address.bank for source, _, _ in host.value_range.fragments(props.blob)}
    assert fragment_banks == {0, 1}


def test_foreign_page_is_rejected_even_though_it_parses(metadata: SyntheticMetadata) -> None:
    # First confirm the referenced page is independently parseable evidence.
    foreign = TracedMetaBlob(metadata.slot, metadata.FOREIGN_BLOB_ROOT, metadata.ownership, "directory-B")
    assert foreign.complete

    borrower = TracedMetaBlob(metadata.slot, metadata.BORROW_ROOT, metadata.ownership, "directory-C")
    assert not borrower.complete
    assert borrower.breakpoint.fault == ChainFault.FOREIGN_PAGE
    assert borrower.breakpoint.owner == "directory-B"
    assert borrower.breakpoint.referenced_address.bank == 1
    # Only the borrower's own page is retained; the foreign page is never absorbed.
    assert [source.address.value for source in borrower.sources] == [metadata.BORROW_ROOT]

    props = TracedPropertiesDictionary(metadata.slot, metadata.BORROW_ROOT, metadata.ownership, "directory-C")
    assert not props.complete
    assert len(props) == 0
    assert props.breakpoint.fault == ChainFault.FOREIGN_PAGE


def test_valid_pages_cannot_be_borrowed_for_missing_evidence(metadata: SyntheticMetadata) -> None:
    # Walk directory-A first so all its pages are claimed.
    good = TracedMetaBlob(metadata.slot, metadata.GOOD_ROOT, metadata.ownership, "directory-A")
    assert good.complete

    # A second directory that references one of those pages must not inherit them.
    stealer = TracedMetaBlob(metadata.slot, metadata.BORROW_ROOT, metadata.ownership, "directory-D")
    assert stealer.breakpoint.fault == ChainFault.FOREIGN_PAGE
    assert metadata.ownership.owner_of(PageAddress.decode(metadata.GOOD_TAIL)) == "directory-A"


def test_cycle_reports_concrete_breakpoint(metadata: SyntheticMetadata) -> None:
    blob = TracedMetaBlob(metadata.slot, metadata.CYCLE_ROOT, PageOwnership(), "cycle")
    assert not blob.complete
    assert blob.breakpoint.fault == ChainFault.CYCLE
    assert blob.breakpoint.referenced == metadata.CYCLE_ROOT
    assert blob.breakpoint.chain_index == 2
    # The partial prefix is preserved, but never marked complete.
    assert len(blob.sources) == 2


def test_self_reference_is_no_progress(metadata: SyntheticMetadata) -> None:
    blob = TracedMetaBlob(metadata.slot, metadata.SELF_ROOT, PageOwnership(), "self")
    assert not blob.complete
    assert blob.breakpoint.fault == ChainFault.NO_PROGRESS


def test_missing_page_is_reported(metadata: SyntheticMetadata) -> None:
    blob = TracedMetaBlob(metadata.slot, metadata.MISSING_ROOT, PageOwnership(), "missing")
    assert not blob.complete
    assert blob.breakpoint.fault == ChainFault.MISSING_PAGE
    assert blob.breakpoint.referenced_address.page == 9


def test_truncated_page_is_reported(metadata: SyntheticMetadata) -> None:
    blob = TracedMetaBlob(metadata.slot, metadata.TRUNCATED_ROOT, PageOwnership(), "truncated")
    assert not blob.complete
    assert blob.breakpoint.fault == ChainFault.SHORT_PAGE
    assert len(blob.sources) == 0


def test_out_of_range_bank_is_reported(metadata: SyntheticMetadata) -> None:
    bad_bank_root = (9 << 32) | 0
    blob = TracedMetaBlob(metadata.slot, bad_bank_root, PageOwnership(), "bad-bank")
    assert not blob.complete
    assert blob.breakpoint.fault == ChainFault.OUT_OF_RANGE
    assert blob.breakpoint.referenced_address.bank == 9
