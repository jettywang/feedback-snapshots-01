"""Traceable reading of VBK metadata.

This module adds provenance to metadata reads. Every byte that contributes to a
directory property can be traced back to the exact :class:`SnapshotSlot`,
:class:`Bank` and page (file offset) it was read from.

A 64 bit page number is split in two parts:

- the high 32 bits identify the bank (``page >> 32``);
- the low 32 bits identify the page inside that bank (``page & 0xFFFFFFFF``).

Cross-bank references are legal, but a page may only be part of one meta blob
chain. A reference into a page already claimed by another blob is reported as a
:class:`ChainFault.FOREIGN_PAGE` breakpoint, even when the referenced page parses
perfectly well on its own: parseable bytes from another directory are never
treated as trusted evidence.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.archive.vbk.c_vbk import PAGE_SIZE, c_vbk

if TYPE_CHECKING:
    from dissect.archive.vbk.vbk import SnapshotSlot

# Number of bytes reserved for the next-page pointer on every page.
PAGE_LINK_SIZE = 8
# The first page additionally carries the 4 byte MetaBlobHeader.Unk0 field.
FIRST_PAGE_HEADER_SIZE = len(c_vbk.MetaBlobHeader)


class VBKTraceError(Exception):
    """Raised when traced property payloads cannot be parsed."""


class ChainFault(Enum):
    """Reason why a meta blob chain could not be fully traversed."""

    FOREIGN_PAGE = "foreign_page"
    OUT_OF_RANGE = "out_of_range"
    MISSING_PAGE = "missing_page"
    SHORT_PAGE = "short_page"
    CYCLE = "cycle"
    NO_PROGRESS = "no_progress"


@dataclass(frozen=True)
class PageAddress:
    """A decoded 64 bit page number.

    Args:
        bank: The bank index, taken from the high 32 bits of the page number.
        page: The page inside the bank, taken from the low 32 bits.
        value: The original signed 64 bit page number.
    """

    bank: int
    page: int
    value: int

    @classmethod
    def decode(cls, value: int) -> PageAddress:
        """Split a composite page number into its bank and in-bank page parts."""
        return cls(bank=value >> 32, page=value & 0xFFFFFFFF, value=value)

    def encode(self) -> int:
        """Return the composite 64 bit page number."""
        return self.value

    def __repr__(self) -> str:
        return f"<PageAddress bank={self.bank} page={self.page} value={self.value}>"


@dataclass(frozen=True)
class PageSource:
    """The physical origin of one page of a meta blob.

    Args:
        address: The decoded bank/page address.
        bank_offset: The file offset of the bank containing the page.
        file_offset: The file offset at which the page content starts.
        length: The number of readable page bytes (``PAGE_SIZE`` unless truncated).
        index: The zero based position of the page in its blob chain.
        next_page: The raw, signed next-page pointer stored in the page.
    """

    address: PageAddress
    bank_offset: int
    file_offset: int
    length: int
    index: int
    next_page: int

    def read_back(self, fh: BinaryIO) -> bytes:
        """Read the exact original bytes of this page back from the file."""
        fh.seek(self.file_offset)
        return fh.read(self.length)


@dataclass(frozen=True)
class BlobSpan:
    """The contribution of one page to the logical payload of a meta blob.

    Args:
        source: The physical origin of the page.
        payload_offset: The offset within the page where the payload starts.
        payload_length: The number of payload bytes contributed by the page.
        logical_offset: The offset of the payload in the concatenated blob data.
    """

    source: PageSource
    payload_offset: int
    payload_length: int
    logical_offset: int


@dataclass(frozen=True)
class ChainBreakpoint:
    """The exact point where traversal of a meta blob chain stopped.

    Args:
        fault: The kind of reference failure.
        chain_index: The zero based chain position that could not be reached.
        source: The page containing the bad reference, or ``None`` for a bad root.
        referenced: The raw signed page number of the failed reference.
        message: A human readable explanation of the failure.
        owner: The blob that already owns the referenced page, if any.
    """

    fault: ChainFault
    chain_index: int
    source: PageSource | None
    referenced: int
    message: str
    owner: str | None = None

    @property
    def referenced_address(self) -> PageAddress | None:
        """The decoded bank/page parts of the failed reference, when decodable."""
        if self.referenced < 0:
            return None
        return PageAddress.decode(self.referenced)


class PageOwnership:
    """Registry of which meta blob owns which page.

    A physical page can only contribute to a single blob chain. The registry is
    what prevents the valid pages of one directory from being borrowed to fill a
    gap in another directory's evidence.
    """

    def __init__(self) -> None:
        self._owners: dict[int, str] = {}

    @staticmethod
    def _key(address: PageAddress) -> int:
        return address.bank << 32 | address.page

    def owner_of(self, address: PageAddress) -> str | None:
        """Return the label of the blob owning the page, if any."""
        return self._owners.get(self._key(address))

    def claim(self, address: PageAddress, owner: str) -> bool:
        """Claim a page for a blob.

        Returns ``True`` when the page was free and is now owned by ``owner``,
        ``False`` when another blob already owns it.
        """
        key = self._key(address)
        existing = self._owners.get(key)
        if existing is not None and existing != owner:
            return False
        self._owners[key] = owner
        return True

    def claimed(self) -> frozenset[int]:
        """Return the composite page numbers currently registered."""
        return frozenset(self._owners)


@dataclass(frozen=True)
class ByteRange:
    """A byte range in the logical payload of a meta blob."""

    logical_offset: int
    length: int

    def fragments(self, blob: TracedMetaBlob) -> list[tuple[PageSource, int, int]]:
        """Resolve the range to ``(source, file_offset, length)`` fragments."""
        return blob.resolve_range(self.logical_offset, self.length)

    def read_back(self, blob: TracedMetaBlob, fh: BinaryIO) -> bytes:
        """Read the original bytes backing this range back from the file."""
        result = bytearray()
        for _, file_offset, length in self.fragments(blob):
            fh.seek(file_offset)
            result.extend(fh.read(length))
        return bytes(result)


@dataclass
class TracedProperty:
    """A parsed directory property with byte-level provenance.

    Args:
        name: The property name.
        type: The property type.
        value: The decoded property value.
        name_range: The logical blob range holding the property name.
        value_range: The logical blob range holding the raw property value.
    """

    name: str
    type: c_vbk.PropertyType
    value: Any
    name_range: ByteRange
    value_range: ByteRange


class TracedMetaBlob:
    """A meta blob read with full chain validation and provenance.

    Unlike :class:`~dissect.archive.vbk.vbk.MetaBlob`, every next-page reference
    is validated for range, ownership and forward progress. Traversal stops at
    the first failure and records a :class:`ChainBreakpoint`; partially read
    blobs are never reported as complete and never absorb foreign pages.

    Args:
        slot: The snapshot slot containing the blob.
        root: The signed 64 bit page number of the blob's first page.
        ownership: The shared page ownership registry.
        label: A stable label identifying this blob in the ownership registry.
    """

    def __init__(
        self,
        slot: SnapshotSlot,
        root: int,
        ownership: PageOwnership | None = None,
        label: str | None = None,
    ):
        self.slot = slot
        self.root = root
        self.ownership = ownership or PageOwnership()
        self.label = label or f"blob@{root}"

        self.sources: list[PageSource] = []
        self.spans: list[BlobSpan] = []
        self.breakpoint: ChainBreakpoint | None = None
        self._seen: set[int] = set()
        self._logical_length = 0

        self._walk()

    def __repr__(self) -> str:
        status = "complete" if self.complete else f"breakpoint={self.breakpoint.fault.value}"
        return f"<TracedMetaBlob root={self.root} pages={len(self.sources)} {status}>"

    @property
    def complete(self) -> bool:
        """Whether the full chain was traversed and ended on a ``-1`` pointer."""
        return self.breakpoint is None

    def _fail(
        self,
        fault: ChainFault,
        index: int,
        source: PageSource | None,
        value: int,
        message: str,
        owner: str | None = None,
    ) -> None:
        self.breakpoint = ChainBreakpoint(fault, index, source, value, message, owner)

    def _validate_reference(self, value: int, index: int, source: PageSource | None) -> PageAddress | None:
        """Validate one next-page reference and decode its bank/page parts."""
        if value < 0 and value != -1:
            self._fail(
                ChainFault.OUT_OF_RANGE,
                index,
                source,
                value,
                f"Negative page reference {value} is not a valid page",
            )
            return None

        address = PageAddress.decode(value)

        if not 0 <= address.bank < len(self.slot.banks):
            self._fail(
                ChainFault.OUT_OF_RANGE,
                index,
                source,
                value,
                f"Bank {address.bank} does not exist (slot has {len(self.slot.banks)} banks)",
            )
            return None

        bank = self.slot.banks[address.bank]
        data_area = bank.size - PAGE_SIZE
        if address.page < 0 or address.page * PAGE_SIZE >= data_area:
            self._fail(
                ChainFault.OUT_OF_RANGE,
                index,
                source,
                value,
                f"Page {address.page} lies outside bank {address.bank}",
            )
            return None

        page_count = getattr(bank, "page_count", data_area // PAGE_SIZE)
        if address.page >= page_count:
            self._fail(
                ChainFault.MISSING_PAGE,
                index,
                source,
                value,
                f"Page {address.page} is not populated in bank {address.bank} ({page_count} pages present)",
            )
            return None

        return address

    def _read_page(self, address: PageAddress, index: int) -> tuple[PageSource | None, memoryview | None]:
        """Read one validated page, distinguishing truncation from missing pages."""
        bank = self.slot.banks[address.bank]
        file_offset = bank.offset + PAGE_SIZE + address.page * PAGE_SIZE

        fh = self.slot.vbk.fh
        fh.seek(file_offset)
        raw = memoryview(fh.read(PAGE_SIZE))

        if len(raw) < PAGE_SIZE:
            self._fail(
                ChainFault.SHORT_PAGE,
                index,
                None,
                address.value,
                f"Truncated page {address}: expected {PAGE_SIZE} bytes, got {len(raw)}",
            )
            return None, None

        next_page = int.from_bytes(raw[:PAGE_LINK_SIZE], "little", signed=True)
        page_source = PageSource(
            address=address,
            bank_offset=bank.offset,
            file_offset=file_offset,
            length=PAGE_SIZE,
            index=index,
            next_page=next_page,
        )
        return page_source, raw

    def _walk(self) -> None:
        current = self.root
        index = 0
        previous: PageSource | None = None

        while current != -1:
            address = self._validate_reference(current, index, previous)
            if address is None:
                return

            owner = self.ownership.owner_of(address)
            if owner is not None and owner != self.label:
                self._fail(
                    ChainFault.FOREIGN_PAGE,
                    index,
                    previous,
                    current,
                    f"Page {address} is already owned by {owner!r} and cannot be borrowed by {self.label!r}",
                    owner=owner,
                )
                return

            # An immediate self pointer (page -> itself) makes no forward
            # progress. A repeat that lands on a different earlier page is a
            # genuine cycle, so distinguish the two before the repeat test.
            if (
                previous is not None
                and previous.next_page == previous.address.value
                and current == previous.address.value
            ):
                self._fail(
                    ChainFault.NO_PROGRESS,
                    index,
                    previous,
                    current,
                    f"Page {previous.address} points back to itself instead of advancing",
                )
                return

            if current in self._seen:
                self._fail(
                    ChainFault.CYCLE,
                    index,
                    previous,
                    current,
                    f"Page {address} repeats at chain position {index}",
                )
                return

            self._seen.add(current)

            if not self.ownership.claim(address, self.label):
                self._fail(
                    ChainFault.FOREIGN_PAGE,
                    index,
                    previous,
                    current,
                    f"Page {address} is already owned by another blob",
                    owner=owner,
                )
                return

            source, raw = self._read_page(address, index)
            if source is None:
                return
            self.sources.append(source)

            payload_offset = FIRST_PAGE_HEADER_SIZE if index == 0 else PAGE_LINK_SIZE
            payload_length = len(raw) - payload_offset
            self.spans.append(
                BlobSpan(
                    source=source,
                    payload_offset=payload_offset,
                    payload_length=payload_length,
                    logical_offset=self._logical_length,
                )
            )
            self._logical_length += payload_length

            previous = source
            current = source.next_page
            index += 1

    def logical_data(self) -> bytes:
        """Return the concatenated payload of all reachable pages.

        The per-page headers (8 bytes next-page pointer, plus 4 bytes on the
        first page) are excluded from the logical payload.
        """
        fh = self.slot.vbk.fh
        result = bytearray()
        for span in self.spans:
            raw = span.source.read_back(fh)
            result.extend(raw[span.payload_offset : span.payload_offset + span.payload_length])
        return bytes(result)

    def partial_data(self) -> bytes:
        """Return whatever payload was reached, even when the chain is broken."""
        return self.logical_data()

    def resolve_range(self, logical_offset: int, length: int) -> list[tuple[PageSource, int, int]]:
        """Resolve a logical payload range to physical file fragments."""
        fragments: list[tuple[PageSource, int, int]] = []
        remaining = length
        cursor = logical_offset

        while remaining > 0:
            for span in self.spans:
                end = span.logical_offset + span.payload_length
                if span.logical_offset <= cursor < end:
                    skip = cursor - span.logical_offset
                    take = min(remaining, span.payload_length - skip)
                    file_offset = span.source.file_offset + span.payload_offset + skip
                    fragments.append((span.source, file_offset, take))
                    cursor += take
                    remaining -= take
                    break
            else:
                raise IndexError(f"Logical range {logical_offset}+{length} exceeds blob payload")

        return fragments


class TracedPropertiesDictionary(Mapping):
    """A properties dictionary parsed from a fully validated meta blob.

    When the underlying chain has a breakpoint, ``complete`` is ``False`` and no
    properties are exposed: a partial blob is never presented as a complete set
    of attributes. Every exposed :class:`TracedProperty` can read its original
    bytes back through :class:`ByteRange`.
    """

    def __init__(
        self,
        slot: SnapshotSlot,
        page: int,
        ownership: PageOwnership | None = None,
        label: str | None = None,
    ):
        self.page = page
        self.blob = TracedMetaBlob(slot, page, ownership, label or f"props@{page}")
        self.complete = self.blob.complete
        self.breakpoint = self.blob.breakpoint
        self._properties: dict[str, TracedProperty] = {}

        if self.complete:
            self._parse(self.blob.logical_data())

    def __getitem__(self, key: str) -> TracedProperty:
        return self._properties[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._properties)

    def __len__(self) -> int:
        return len(self._properties)

    def value(self, name: str) -> Any:
        """Return the decoded value of a property."""
        return self._properties[name].value

    def _parse(self, data: bytes) -> None:
        buf = BytesIO(data)

        def read(size: int) -> tuple[bytes, int]:
            offset = buf.tell()
            chunk = buf.read(size)
            if len(chunk) != size:
                raise VBKTraceError(f"Truncated property record at logical offset {offset}")
            return chunk, offset

        while True:
            type_bytes, _ = read(4)
            value_type = c_vbk.PropertyType(int.from_bytes(type_bytes, "little", signed=True))
            if value_type == c_vbk.PropertyType.End:
                break

            name_length = int.from_bytes(read(4)[0], "little")
            name_bytes, name_offset = read(name_length)
            name_range = ByteRange(name_offset, name_length)
            name = name_bytes.decode("utf-8")

            if value_type == c_vbk.PropertyType.UInt32:
                raw, value_offset = read(4)
                value = int.from_bytes(raw, "little")
            elif value_type == c_vbk.PropertyType.UInt64:
                raw, value_offset = read(8)
                value = int.from_bytes(raw, "little")
            elif value_type == c_vbk.PropertyType.Boolean:
                raw, value_offset = read(4)
                value = bool(int.from_bytes(raw, "little"))
            elif value_type in (
                c_vbk.PropertyType.AString,
                c_vbk.PropertyType.WString,
                c_vbk.PropertyType.Binary,
            ):
                value_length = int.from_bytes(read(4)[0], "little")
                raw, value_offset = read(value_length)
                if value_type == c_vbk.PropertyType.AString:
                    value = raw.decode("utf-8")
                elif value_type == c_vbk.PropertyType.WString:
                    value = raw.decode("utf-16-le")
                else:
                    value = raw
            else:
                raise VBKTraceError(f"Unsupported property type: {value_type}")

            self._properties[name] = TracedProperty(
                name=name,
                type=value_type,
                value=value,
                name_range=name_range,
                value_range=ByteRange(value_offset, len(raw)),
            )
