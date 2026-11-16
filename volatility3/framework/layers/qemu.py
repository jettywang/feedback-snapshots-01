# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import dataclasses
import functools
import json
import logging
import re
import struct
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners, segmented
from volatility3.framework.symbols import intermed

vollog = logging.getLogger(__name__)


class QemuFormatException(exceptions.LayerException):
    """Thrown when a QEMU save file contains an inconsistent record."""


@dataclasses.dataclass(frozen=True)
class QemuRamPageRecord:
    """A single page record from a QEMU RAM section.

    Records are kept in file order, including records that a later record
    replaced.  ``address`` is the block-relative address after the optional
    PCI-hole relocation (for ``pc.ram`` this is the guest-physical address),
    while ``encoded_address`` is the value stored in the file and can be used
    to recompute ``address`` through
    :meth:`QemuSuspendLayer.relocate_ram_address`.  ``file_offset`` points at
    the record's payload: the page bytes, the single repeated-compression
    byte, or the XBZRLE length and delta for an unsupported record.

    ``encoding`` is one of ``QemuSuspendLayer.RAM_ENCODING_PAGE`` (a full
    page of bytes), ``QemuSuspendLayer.RAM_ENCODING_COMPRESS`` (one payload
    byte repeated across the whole page) or
    ``QemuSuspendLayer.RAM_ENCODING_XBZRLE`` (a delta encoding, which is
    retained as evidence but not decoded).  Records with an
    ``unsupported_reason`` are unresolved: they supersede earlier data for
    the same block and address, but no bytes from the earlier record remain
    readable.
    """

    index: int
    block_name: bytes
    encoded_address: int
    address: int
    file_offset: int
    stored_size: int
    encoding: str
    superseded_by: Optional[int] = None
    pci_hole_start: int = 0
    pci_hole_end: int = 0
    unsupported_reason: Optional[str] = None

    @property
    def supported(self) -> bool:
        return self.unsupported_reason is None

    @property
    def block_name_str(self) -> str:
        return self.block_name.decode("utf-8", "replace")

    @property
    def in_pc_ram(self) -> bool:
        return self.block_name == b"pc.ram"

    @property
    def superseded(self) -> bool:
        return self.superseded_by is not None

    @property
    def pci_hole(self) -> Tuple[int, int]:
        return self.pci_hole_start, self.pci_hole_end


class QemuSuspendLayer(segmented.NonLinearlySegmentedLayer):
    """A Qemu suspend-to-disk translation layer.

    RAM streams are a sequence of 8-byte, big-endian headers.  The low
    ``log2(page_size)`` bits are flags and the remaining bits are the
    block-relative page address.  A page record normally names the RAM block
    it belongs to; ``SEGMENT_FLAG_CONTINUE`` means the name is omitted and
    the block name from the previous page record is reused.  A normal page
    carries ``page_size`` bytes, while ``SEGMENT_FLAG_COMPRESS`` carries a
    single byte that fills the entire page (a repeated-byte page, not zlib).

    Only ``pc.ram`` records form the readable address space.  Records for
    other RAM blocks remain in the evidence history, keyed by block name and
    address, but never leak into ``pc.ram``.  When the same block/address
    appears again the last record wins; earlier records remain available
    through :attr:`ram_page_records` and :meth:`ram_page_history`.
    """

    RAM_ENCODING_PAGE = "page"
    RAM_ENCODING_COMPRESS = "compress"
    RAM_ENCODING_XBZRLE = "xbzrle"
    XBZRLE_LIMITATION = (
        "XBZRLE delta pages are not decoded; the page is unresolved and does "
        "not fall back to an earlier record"
    )

    QEVM_EOF = 0x00
    QEVM_SECTION_START = 0x01
    QEVM_SECTION_PART = 0x02
    QEVM_SECTION_END = 0x03
    QEVM_SECTION_FULL = 0x04
    QEVM_SUBSECTION = 0x05
    QEVM_VMDESCRIPTION = 0x06
    QEVM_CONFIGURATION = 0x07
    QEVM_SECTION_FOOTER = 0x7E
    HASH_PTE_SIZE_64 = 16

    SEGMENT_FLAG_COMPRESS = 0x02
    SEGMENT_FLAG_MEM_SIZE = 0x04
    SEGMENT_FLAG_PAGE = 0x08
    SEGMENT_FLAG_EOS = 0x10
    SEGMENT_FLAG_CONTINUE = 0x20
    SEGMENT_FLAG_XBZRLE = 0x40
    SEGMENT_FLAG_HOOK = 0x80

    # See https://qemu.readthedocs.io/en/latest/devel/memory.html for more info
    #
    # At least the following values could occur for devices using > 3-4 GB RAM:
    # +--------------------------------+--------------------------------+------------+-------------+
    # | Architecture                   | Reference Code                 | Hole Start | Hole End    |
    # +--------------------------------+--------------------------------+------------+-------------+
    # | PC i440FX + PIIX "New Default" | qemu/hw/i386/pc_piix.c:98      | 0xc0000000 | 0x100000000 |
    # | PC i440FX + PIIX "Old Default" | qemu/hw/i386/pc_piix.c:98      | 0xe0000000 | 0x100000000 |
    # | PC Q35 + ICH9                  | qemu/hw/i386/pc_q35.c:141      | 0x80000000 | 0x100000000 |
    # | MicroVM                        | qemu/hw/i386/microvm.c:291     | 0xc0000000 | 0x100000000 |
    # | Xen                            | qemu/hw/i386/xen/xen-hvm.c:248 | 0xf0000000 | 0x100000000 |
    # +--------------------------------+--------------------------------+------------+-------------+
    #
    # For now, we assume that the parameter max-ram-below-4g is not set, since this parameter influences the size
    # and location of the memory gap. Deviating hole sizes could eventually be detected for Linux by e.g. scanning
    # for dmesg entries with a regex like rb'\[mem (0x[0-9a-f]{4,10})-0x[0-9a-f]{4,10}\] available for PCI devices'

    distro_re = r"(\w+[\d{1,2}\.]*)"

    pci_hole_table = {
        re.compile(r"^pc-i440fx-([23456789]|\d\d+)\.\d$"): (
            0xE0000000,
            0xC0000000,
            0x100000000,
        ),
        re.compile(r"^pc-i440fx-[01]\.\d$"): (0xE0000000, 0xE0000000, 0x100000000),
        re.compile(r"^pc-q35-\d\.\d$"): (0xB0000000, 0x80000000, 0x100000000),
        re.compile(r"^microvm$"): (0xC0000000, 0xC0000000, 0x100000000),
        re.compile(r"^xen$"): (0xF0000000, 0xF0000000, 0x100000000),
        re.compile(r"^pc-i440fx-" + distro_re + r"$"): (
            0xE0000000,
            0xC0000000,
            0x100000000,
        ),
        re.compile(r"^pc-q35-" + distro_re + r"$"): (
            0xB0000000,
            0x80000000,
            0x100000000,
        ),
    }

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._qemu_table_name = intermed.IntermediateSymbolTable.create(
            context, config_path, "generic", "qemu"
        )
        self._configuration = None
        self._architecture = None
        self._current_segment_name = b""
        self._pci_hole_start = 0
        self._pci_hole_end = 0
        self._pci_hole_minimum = 0
        self._ram_page_records: List[QemuRamPageRecord] = []
        self._ram_page_history: Dict[Tuple[bytes, int], List[QemuRamPageRecord]] = {}
        self._ram_page_winners: Dict[Tuple[bytes, int], QemuRamPageRecord] = {}
        self._ram_mem_sizes: Dict[bytes, int] = {}
        self._compressed_offsets: Set[int] = set()
        self._architecture_resolved = False
        self._segments_loaded = False
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )

    @property
    def ram_page_records(self) -> Tuple[QemuRamPageRecord, ...]:
        """All RAM page records in file order, including superseded ones."""
        return tuple(self._ram_page_records)

    @property
    def ram_mem_sizes(self) -> Mapping[bytes, int]:
        """RAM block sizes announced by MEM_SIZE records."""
        return MappingProxyType(self._ram_mem_sizes)

    def ram_page_history(
        self, block_name: bytes, address: int
    ) -> Tuple[QemuRamPageRecord, ...]:
        """Returns the records for a block/address pair in file order."""
        return tuple(self._ram_page_history.get((block_name, address), ()))

    def ram_page_winner(
        self, block_name: bytes, address: int
    ) -> Optional[QemuRamPageRecord]:
        """Returns the last record for a block/address pair, if any."""
        return self._ram_page_winners.get((block_name, address))

    def ram_page_source(
        self, offset: int, length: int = 1
    ) -> Optional[QemuRamPageRecord]:
        """Returns the page record that supplies ``offset``.

        The record is the winning ``pc.ram`` record for the single page
        containing the whole ``[offset, offset + length)`` range.  ``None``
        is returned when that range crosses a page boundary or the page is
        not readable, including when its newest record uses an unsupported
        encoding.
        """
        if length < 1:
            raise ValueError("length must be positive")
        page_size = self._configuration.get("page_size", 4096)
        start_offset = offset ^ (offset & (page_size - 1))
        if offset + length > start_offset + page_size:
            return None
        record = self._ram_page_winners.get((b"pc.ram", start_offset))
        if record is None or not record.supported:
            return None
        return record

    def ram_page_report(self) -> Tuple[Mapping[str, Any], ...]:
        """Returns one report entry per RAM page record in file order.

        ``status`` is ``readable`` for the winning supported ``pc.ram``
        record, ``superseded`` for a record replaced by a later one,
        ``unsupported`` for the winning record of an encoding that cannot be
        decoded (the page is not readable), and ``other-block`` for records
        that belong to a RAM block other than ``pc.ram``.
        """
        entries = []
        for record in self._ram_page_records:
            if record.superseded:
                status = "superseded"
            elif not record.supported:
                status = "unsupported"
            elif not record.in_pc_ram:
                status = "other-block"
            else:
                status = "readable"
            entries.append(
                MappingProxyType(
                    {
                        "record": record,
                        "status": status,
                        "readable": status == "readable",
                        "superseded_by": record.superseded_by,
                        "limitation": record.unsupported_reason,
                    }
                )
            )
        return tuple(entries)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return super().get_requirements() + [
            requirements.VersionRequirement(
                name="regex_scanner",
                component=scanners.RegExScanner,
                version=(1, 0, 0),
            ),
        ]

    @classmethod
    def _check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, name: str = ""
    ):
        header = base_layer.read(0, 8)
        if header[:4] != b"\x51\x45\x56\x4d":
            raise exceptions.LayerException(name, "No QEMU magic bytes")
        if header[4:] != b"\x00\x00\x00\x03":
            raise exceptions.LayerException(name, "Unsupported QEMU version found")
        vollog.debug("QEVM header found")

    def _read_configuration(
        self, base_layer: interfaces.layers.DataLayerInterface, name: str
    ) -> Any:
        """Reads the JSON configuration from the end of the file"""
        chunk_size = 4096
        data = b""
        for i in range(
            base_layer.maximum_address + 1, base_layer.minimum_address, -chunk_size
        ):
            # Since we're going backwards, we need to include one extra byte so the tail doesn't get chopped off
            if i != base_layer.maximum_address + 1:
                data = (base_layer.read(i, chunk_size) + data).rstrip(b"\x00")
                if b"\x00" in data:
                    last_null_byte = data.rfind(b"\x00")
                    start_of_json = data.find(b"{", last_null_byte)

                    if start_of_json >= 0:
                        data = data[start_of_json:]
                        return json.loads(data)
                    # No JSON configuration found at the end of the file, return empty dict
                    return dict()
        raise exceptions.LayerException(
            name, "Invalid JSON configuration at the end of the file"
        )

    @staticmethod
    def relocate_ram_address(
        encoded_address: int, pci_hole_start: int, pci_hole_end: int
    ) -> int:
        """Applies a PCI hole to a block-relative RAM address.

        ``encoded_address`` is the page address as stored in the RAM stream
        (without the flag bits).  The result is reproducible from the record
        alone: addresses below the hole are unchanged, and addresses at or
        above it are shifted up by ``pci_hole_end - pci_hole_start``.  A hole
        with a zero start is disabled.
        """
        if pci_hole_start and encoded_address >= pci_hole_start:
            return encoded_address + pci_hole_end - pci_hole_start
        return encoded_address

    def _read_ram_block_name(self, index: int) -> Tuple[bytes, int]:
        """Reads a length-prefixed RAM block name at ``index``."""
        base_layer = self.context.layers[self._base_layer]
        namelen = base_layer.read(index, 1)[0]
        name = base_layer.read(index + 1, namelen)
        return name, index + 1 + namelen

    def _handle_ram_mem_sizes(
        self, index: int, total_ram_bytes: int = 0
    ) -> Tuple[Dict[bytes, int], int]:
        """Reads the block-name/size pairs carried by a MEM_SIZE record.

        QEMU stores the total RAM size in the record's address field and then
        writes one ``(name length, name, block size)`` tuple per RAM block.
        There is normally no explicit terminator, so parsing stops once the
        listed sizes add up to ``total_ram_bytes``.  If that total is absent
        or inconsistent, the zero high byte of the next record header also
        acts as a zero-length name; that byte belongs to the next header and
        is deliberately not consumed.  Returns the sizes keyed by block name
        and the first unread offset.
        """
        base_layer = self.context.layers[self._base_layer]
        sizes: Dict[bytes, int] = {}
        remaining = total_ram_bytes
        while base_layer.maximum_address >= index + 8:
            if total_ram_bytes and remaining <= 0:
                break
            namelen = base_layer.read(index, 1)[0]
            if namelen == 0:
                break
            name = base_layer.read(index + 1, namelen)
            block_size = struct.unpack(">Q", base_layer.read(index + 1 + namelen, 8))[0]
            sizes[name] = block_size
            remaining -= block_size
            index += 1 + namelen + 8
        if total_ram_bytes and remaining != 0:
            listed_bytes = total_ram_bytes - remaining
            vollog.warning(
                f"QEMU MEM_SIZE record lists 0x{listed_bytes:x} bytes but its "
                f"header declares 0x{total_ram_bytes:x} bytes; the block list "
                f"may be incomplete"
            )
        self._ram_mem_sizes.update(sizes)
        return sizes, index

    def _record_ram_page(
        self,
        block_name: bytes,
        encoded_address: int,
        file_offset: int,
        stored_size: int,
        encoding: str,
        pci_hole_start: int,
        pci_hole_end: int,
        unsupported_reason: Optional[str] = None,
    ) -> QemuRamPageRecord:
        if block_name == b"pc.ram":
            # Page addresses in the RAM stream omit the PCI hole; restoring
            # it turns the block-relative address into a guest-physical one.
            address = self.relocate_ram_address(
                encoded_address, pci_hole_start, pci_hole_end
            )
        else:
            # Other RAM blocks have their own address space; the PCI hole
            # describes the guest-physical pc.ram layout only.
            address = encoded_address
            pci_hole_start, pci_hole_end = 0, 0
        record = QemuRamPageRecord(
            index=len(self._ram_page_records),
            block_name=block_name,
            encoded_address=encoded_address,
            address=address,
            file_offset=file_offset,
            stored_size=stored_size,
            encoding=encoding,
            pci_hole_start=pci_hole_start,
            pci_hole_end=pci_hole_end,
            unsupported_reason=unsupported_reason,
        )
        self._ram_page_records.append(record)

        key = (block_name, address)
        history = self._ram_page_history.setdefault(key, [])
        if history:
            previous = history[-1]
            replaced = dataclasses.replace(previous, superseded_by=record.index)
            history[-1] = replaced
            self._ram_page_records[previous.index] = replaced
        history.append(record)
        self._ram_page_winners[key] = record
        return record

    def _get_ram_segments(
        self, index: int, page_size: int
    ) -> Tuple[List[Tuple[int, int, int, int]], int]:
        """Parses one RAM section, recording every page and returning the
        readable ``pc.ram`` segments.

        A page's block name comes from the current record unless
        ``SEGMENT_FLAG_CONTINUE`` is set, in which case the name of the
        previous page record is reused.  A normal page stores ``page_size``
        bytes; ``SEGMENT_FLAG_COMPRESS`` stores a single byte repeated over
        the page.  Only the last record for each ``(block, address)`` is
        exposed, and only for ``pc.ram``.
        """
        done = False
        base_layer = self.context.layers[self._base_layer]
        pci_hole_start = self._pci_hole_start
        pci_hole_end = self._pci_hole_end

        while not done:
            # Use struct.unpack here for performance improvements
            raw_header = struct.unpack(">Q", base_layer.read(index, 8))[0]

            # Flags are stored in the n least significant bits, where n equals the bit-length of pagesize
            flags = raw_header & (page_size - 1)
            # addr equals the highest multiple of pagesize <= offset
            # (We assume that page_size is a power of 2)
            encoded_address = raw_header ^ flags
            index += 8

            if flags & self.SEGMENT_FLAG_MEM_SIZE:
                _, index = self._handle_ram_mem_sizes(index, encoded_address)
                pc_ram_size = self._ram_mem_sizes.get(b"pc.ram", encoded_address)
                if pc_ram_size < self._pci_hole_minimum:
                    # Turns off the pci_hole if it's not supposed to be there
                    vollog.debug(
                        "QEVM turning off PCI hole due to small image size: "
                        f"0x{pc_ram_size:x} < 0x{self._pci_hole_minimum:x}"
                    )
                    pci_hole_start, pci_hole_end = 0, 0
                    self._pci_hole_start, self._pci_hole_end = 0, 0

            if flags & self.SEGMENT_FLAG_XBZRLE:
                if not (flags & self.SEGMENT_FLAG_CONTINUE):
                    self._current_segment_name, index = self._read_ram_block_name(index)
                block_name = self._current_segment_name
                if base_layer.maximum_address < index + 1:
                    raise QemuFormatException(
                        self.name,
                        f"Truncated XBZRLE record for block {block_name!r} "
                        f"at 0x{encoded_address:x}",
                    )
                # XBZRLE stores a big-endian 16-bit length followed by the
                # delta stream.  The delta is not decoded; the length is only
                # used to keep following records parseable.
                delta_size = struct.unpack(">H", base_layer.read(index, 2))[0]
                vollog.warning(
                    f"{self.XBZRLE_LIMITATION} (block {block_name!r}, "
                    f"address 0x{encoded_address:x}, record "
                    f"{len(self._ram_page_records)})"
                )
                self._record_ram_page(
                    block_name,
                    encoded_address,
                    index,
                    2 + delta_size,
                    self.RAM_ENCODING_XBZRLE,
                    pci_hole_start,
                    pci_hole_end,
                    unsupported_reason=self.XBZRLE_LIMITATION,
                )
                index += 2 + delta_size
            elif flags & (self.SEGMENT_FLAG_COMPRESS | self.SEGMENT_FLAG_PAGE):
                if not (flags & self.SEGMENT_FLAG_CONTINUE):
                    self._current_segment_name, index = self._read_ram_block_name(index)
                block_name = self._current_segment_name
                if flags & self.SEGMENT_FLAG_COMPRESS:
                    self._record_ram_page(
                        block_name,
                        encoded_address,
                        index,
                        1,
                        self.RAM_ENCODING_COMPRESS,
                        pci_hole_start,
                        pci_hole_end,
                    )
                    index += 1
                else:
                    self._record_ram_page(
                        block_name,
                        encoded_address,
                        index,
                        page_size,
                        self.RAM_ENCODING_PAGE,
                        pci_hole_start,
                        pci_hole_end,
                    )
                    index += page_size

            if flags & self.SEGMENT_FLAG_HOOK:
                raise QemuFormatException(
                    self.name,
                    f"QEMU RAM hook records are not supported (record "
                    f"{len(self._ram_page_records)} at 0x{encoded_address:x})",
                )
            if flags & self.SEGMENT_FLAG_EOS:
                done = True

        return self._pc_ram_segments(page_size), index

    def _pc_ram_segments(self, page_size: int) -> List[Tuple[int, int, int, int]]:
        """Builds readable segments from the winning ``pc.ram`` records."""
        segments = []
        self._compressed_offsets = set()
        for (block_name, address), record in self._ram_page_winners.items():
            if block_name != b"pc.ram" or not record.supported:
                continue
            segments.append(
                (address, record.file_offset, page_size, record.stored_size)
            )
            if record.encoding == self.RAM_ENCODING_COMPRESS:
                self._compressed_offsets.add(record.file_offset)
        segments.sort()
        return segments

    def _load_segments(self):
        # The base class retries _load_segments whenever no segment can be
        # found.  Parse the file once so evidence and warnings are not
        # duplicated, and so an all-unresolved image still raises the normal
        # invalid-address error on read.
        if self._segments_loaded:
            return
        base_layer = self.context.layers[self._base_layer]
        self._check_header(base_layer, self.name)
        # Parsing may be retried when no readable segment exists; reset the
        # evidence state so records are not duplicated.
        self._segments = []
        self._minaddr = None
        self._maxaddr = None
        self._ram_page_records = []
        self._ram_page_history = {}
        self._ram_page_winners = {}
        self._ram_mem_sizes = {}
        self._compressed_offsets = set()
        self._pci_hole_start = 0
        self._pci_hole_end = 0
        self._pci_hole_minimum = 0
        self._architecture_resolved = False
        if not self._configuration:
            self._configuration = self._read_configuration(base_layer, self.name)
        section_byte = -1
        index = 8
        section_info = dict()
        current_section_id = -1
        while section_byte != self.QEVM_EOF and index <= base_layer.maximum_address:
            section_byte = self.context.object(
                self._qemu_table_name + constants.BANG + "unsigned char",
                offset=index,
                layer_name=self._base_layer,
            )
            index += 1
            if section_byte == self.QEVM_CONFIGURATION:
                section_len = self.context.object(
                    self._qemu_table_name + constants.BANG + "unsigned long",
                    offset=index,
                    layer_name=self._base_layer,
                )
                self._architecture = self.context.object(
                    self._qemu_table_name + constants.BANG + "string",
                    offset=index + 4,
                    layer_name=self._base_layer,
                    max_length=section_len,
                )
                index += 4 + section_len
            elif (
                section_byte == self.QEVM_SECTION_START
                or section_byte == self.QEVM_SECTION_FULL
            ):
                section_id = self.context.object(
                    self._qemu_table_name + constants.BANG + "unsigned long",
                    offset=index,
                    layer_name=self._base_layer,
                )
                current_section_id = section_id
                index += 4
                name_len = self.context.object(
                    self._qemu_table_name + constants.BANG + "unsigned char",
                    offset=index,
                    layer_name=self._base_layer,
                )
                index += 1
                name = self.context.object(
                    self._qemu_table_name + constants.BANG + "string",
                    offset=index,
                    layer_name=self._base_layer,
                    max_length=name_len,
                )
                index += name_len
                # instance_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                #                                    offset = index,
                #                                    layer_name = self._base_layer)
                index += 4
                version_id = self.context.object(
                    self._qemu_table_name + constants.BANG + "unsigned long",
                    offset=index,
                    layer_name=self._base_layer,
                )
                index += 4
                # Store section info for handling QEVM_SECTION_PARTs later on
                section_info[current_section_id] = {
                    "name": name,
                    "version_id": version_id,
                }
                # Resolve the PCI hole before any page addresses are
                # recorded, otherwise early records could not be recomputed.
                self._resolve_architecture()
                # Read additional data
                index = self.extract_data(index, name, version_id)
            elif (
                section_byte == self.QEVM_SECTION_PART
                or section_byte == self.QEVM_SECTION_END
            ):
                section_id = self.context.object(
                    self._qemu_table_name + constants.BANG + "unsigned long",
                    offset=index,
                    layer_name=self._base_layer,
                )
                current_section_id = section_id
                index += 4
                self._resolve_architecture()
                # Read additional data
                index = self.extract_data(
                    index,
                    section_info[current_section_id]["name"],
                    section_info[current_section_id]["version_id"],
                )
            elif section_byte == self.QEVM_SECTION_FOOTER:
                section_id = self.context.object(
                    self._qemu_table_name + constants.BANG + "unsigned long",
                    offset=index,
                    layer_name=self._base_layer,
                )
                index += 4
                if section_id != current_section_id:
                    raise exceptions.LayerException(
                        self._name,
                        f"QEMU section footer mismatch: {current_section_id} and {section_id}",
                    )
            elif section_byte == self.QEVM_EOF:
                pass
            else:
                raise exceptions.LayerException(
                    self._name, f"QEMU unknown section encountered: {section_byte}"
                )
        self._segments_loaded = True

    def _resolve_architecture(self) -> None:
        """Determines the architecture and PCI hole before RAM is parsed.

        The QEMU configuration section normally names the machine, but a
        save file without one still needs a usable PCI hole so stored page
        addresses can be relocated deterministically.
        """
        if self._architecture_resolved:
            return
        if not self._architecture:
            self._architecture = self._fallback_determine_architecture()
            if self._architecture is None:
                vollog.log(
                    constants.LOGLEVEL_VV,
                    "QEVM architecture could not be determined",
                )
        if self._architecture:
            for regex in self.pci_hole_table:
                if regex.match(self._architecture):
                    (
                        self._pci_hole_minimum,
                        self._pci_hole_start,
                        self._pci_hole_end,
                    ) = self.pci_hole_table[regex]
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"QEVM architecture detected as: {self._architecture}",
                    )
                    break
            else:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"QEVM unknown architecture found: {self._architecture}",
                )
        self._architecture_resolved = True

    def _fallback_determine_architecture(self) -> str:
        architecture_pattern = rb"pc-(i440fx|q35)-(\d{1,2}\.\d{1,2}|\w+[\d{1,2}\.]*)"
        default_suffix = "-2.0"
        base_layer = self.context.layers[self._base_layer]

        vollog.log(constants.LOGLEVEL_VVVV, "QEVM fallback architecture detection used")

        res = scanners.RegExScanner(architecture_pattern)
        for offset in base_layer.scan(context=self.context, scanner=res):
            line = base_layer.read(offset, 64)
            regex_results = re.search(architecture_pattern, line)
            architecture = regex_results.group().decode()
            return architecture

        # If that does not work, look in configuration JSON for devices specific to a certain architecture
        architecture = None
        for device in self._configuration.get("devices", []):
            device_name = device.get("vmsd_name", "").lower()
            if "i440fx" in device_name or "piix" in device_name:
                architecture = "pc-i440fx" + default_suffix
                break
            elif "ich9" in device_name:
                architecture = "pc-q35" + default_suffix
                break
        if architecture:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Architecture version unknown, default used: {default_suffix}",
            )
            return architecture

        # Still haven't found architecture, switch to fallback-method
        architecture_pattern = rb"Standard PC \((i440FX|Q35)"
        res = scanners.RegExScanner(architecture_pattern)
        for offset in base_layer.scan(context=self.context, scanner=res):
            line = base_layer.read(offset, 64)
            regex_results = re.search(architecture_pattern, line)
            architecture = (
                "pc-" + regex_results.groups()[0].decode().lower() + default_suffix
            )
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Architecture version unknown, default used: {default_suffix}",
            )
            return architecture

        vollog.warning("Could not determine QEMU target architecture!")
        return None

    def extract_data(self, index, name, version_id):
        if name == "ram":
            if version_id != 4:
                raise exceptions.LayerException(
                    self.name, f"QEMU unknown RAM version_id {version_id}"
                )
            segments, index = self._get_ram_segments(
                index, self._configuration.get("page_size", 4096)
            )
            # _get_ram_segments rebuilds from every winner, so a later RAM
            # section or block switch cannot leave a stale segment behind.
            self._segments = segments
        elif name == "spapr/htab":
            if version_id != 1:
                raise exceptions.LayerException(
                    f"QEMU unknown HTAB version_id {version_id}"
                )
            header = self.context.object(
                self._qemu_table_name + constants.BANG + "unsigned long",
                offset=index,
                layer_name=self._base_layer,
            )
            index += 4
            if header == 0:
                htab_index = -1
                htab_n_valid = 0
                htab_n_invalid = 0
                while htab_index != 0 and htab_n_valid != 0 and htab_n_invalid != 0:
                    htab = self.context.object(
                        self._qemu_table_name + constants.BANG + "htab",
                        offset=index,
                        layer_name=self._base_layer,
                    )
                    htab_index, htab_n_valid, htab_n_invalid = htab
                    index += 8 + (htab_n_valid * self.HASH_PTE_SIZE_64)
        elif name == "dirty-bitmap":
            index += 1
        elif name == "pbs-state":
            section_len = self.context.object(
                self._qemu_table_name + constants.BANG + "unsigned long long",
                offset=index,
                layer_name=self._base_layer,
            )
            index += 8 + section_len
        return index

    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        """Expands a stored page record into the requested bytes.

        Compressed records are a single byte that must fill the page, while
        normal records already contain the page.  The record for the page is
        looked up by its stored file offset, so a page that was first
        compressed and later written normally uses the newest encoding.
        """
        page_size = self._configuration.get("page_size", 4096)
        # start_offset equals the highest multiple of pagesize <= offset
        # (We assume that page_size is a power of 2)
        start_offset = offset ^ (offset & (page_size - 1))
        if mapped_offset in self._compressed_offsets:
            data = data * page_size
        result = data[offset - start_offset : output_length + offset - start_offset]
        return result

    @functools.lru_cache(maxsize=512)
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        return super().read(offset, length, pad)


class QemuStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            QemuSuspendLayer._check_header(context.layers[layer_name])
        except exceptions.LayerException:
            return None
        new_name = context.layers.free_layer_name("QemuSuspendLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = (
            layer_name
        )
        layer = QemuSuspendLayer(context, new_name, new_name)
        cls.stacker_slow_warning()
        return layer
