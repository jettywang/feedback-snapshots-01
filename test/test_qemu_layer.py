"""QEMU RAM page evidence and block identity tests."""

import json
import struct
from typing import Iterable, Tuple

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import physical, qemu

PAGE_SIZE = 4096
ARCHITECTURE = b"pc-i440fx-2.0"


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _name(block_name: bytes) -> bytes:
    return bytes([len(block_name)]) + block_name


def _page(byte: bytes) -> bytes:
    return byte * PAGE_SIZE


def _footer(section_id: int) -> bytes:
    return bytes([qemu.QemuSuspendLayer.QEVM_SECTION_FOOTER]) + _u32(section_id)


# QEMU writes the instance id then the version id, both 32-bit big endian.
def _section(section_byte: int, name: bytes, version: int, body: bytes) -> bytes:
    return (
        bytes([section_byte])
        + _u32(1)
        + _name(name)
        + _u32(0)
        + _u32(version)
        + body
        + _footer(1)
    )


def _mem_size(total: int, blocks: Iterable[Tuple[bytes, int]]) -> bytes:
    data = _u64(total | qemu.QemuSuspendLayer.SEGMENT_FLAG_MEM_SIZE)
    for block_name, block_size in blocks:
        data += _name(block_name) + _u64(block_size)
    return data


def _page_record(
    address: int,
    block_name: bytes,
    payload: bytes,
    *,
    compress: bool = False,
    continue_block: bool = False,
) -> bytes:
    flags = qemu.QemuSuspendLayer.SEGMENT_FLAG_COMPRESS if compress else 0
    flags |= qemu.QemuSuspendLayer.SEGMENT_FLAG_PAGE
    if continue_block:
        flags |= qemu.QemuSuspendLayer.SEGMENT_FLAG_CONTINUE
        prefix = b""
    else:
        prefix = _name(block_name)
    return _u64(address | flags) + prefix + payload


def build_image(
    records: bytes,
    *,
    architecture: bytes = ARCHITECTURE,
    ram_total: int = 0,
    blocks: Iterable[Tuple[bytes, int]] = (),
) -> bytes:
    body = b""
    if ram_total:
        body += _mem_size(ram_total, blocks)
    body += records + _u64(qemu.QemuSuspendLayer.SEGMENT_FLAG_EOS)

    data = bytearray(b"QEVM\x00\x00\x00\x03")
    data += bytes([qemu.QemuSuspendLayer.QEVM_CONFIGURATION])
    data += _u32(len(architecture)) + architecture
    data += _section(qemu.QemuSuspendLayer.QEVM_SECTION_FULL, b"ram", 4, body)
    data += bytes([qemu.QemuSuspendLayer.QEVM_EOF])
    data += b"\x00" * 8 + json.dumps({"page_size": PAGE_SIZE}).encode()
    return bytes(data)


def load_layer(data: bytes) -> qemu.QemuSuspendLayer:
    context = contexts.Context()
    context.config["qemu.base_layer"] = "memory"
    context.layers.add_layer(
        physical.BufferDataLayer(context, "memory", "memory", data)
    )
    return qemu.QemuSuspendLayer(context, "qemu", "qemu")


def page_update_image() -> bytes:
    """Two updates of one page plus a block switch, with CONTINUE records."""
    records = b""
    # Record 0: first version of page 0x1000 in pc.ram.
    records += _page_record(0x1000, b"pc.ram", _page(b"A"))
    # Record 1: unrelated page, still in pc.ram.
    records += _page_record(0x2000, b"pc.ram", _page(b"B"))
    # Record 2: second update of page 0x1000, supersedes record 0.
    records += _page_record(0x1000, b"pc.ram", _page(b"C"))
    # Record 3: block switch to otherram at the same address.
    records += _page_record(0x1000, b"otherram", _page(b"D"))
    # Record 4: CONTINUE keeps otherram and must not leak into pc.ram.
    records += _page_record(0x2000, b"otherram", _page(b"E"), continue_block=True)
    # Record 5: compressed pc.ram page (one byte repeated over the page).
    records += _page_record(0x3000, b"pc.ram", b"Z", compress=True)
    return build_image(records)


def test_repeated_page_last_record_wins() -> None:
    data = page_update_image()
    layer = load_layer(data)

    assert layer.read(0x1000, 8) == b"CCCCCCCC"
    assert layer.read(0x2000, 8) == b"BBBBBBBB"
    assert layer.read(0x3000, 8) == b"ZZZZZZZZ"
    assert layer.read(0x3000 + PAGE_SIZE - 1, 1) == b"Z"

    source = layer.ram_page_source(0x1000)
    assert source is not None
    assert source.index == 2
    assert source.block_name == b"pc.ram"
    assert source.encoding == layer.RAM_ENCODING_PAGE
    assert data[source.file_offset : source.file_offset + 2] == b"CC"


def test_superseded_records_are_reported_but_not_forgotten() -> None:
    layer = load_layer(page_update_image())
    history = layer.ram_page_history(b"pc.ram", 0x1000)

    assert [record.index for record in history] == [0, 2]
    assert history[0].superseded_by == 2
    assert history[0].file_offset != history[1].file_offset
    assert layer.ram_page_winner(b"pc.ram", 0x1000) is history[1]

    report = layer.ram_page_report()
    assert [entry["status"] for entry in report] == [
        "superseded",
        "readable",
        "readable",
        "other-block",
        "other-block",
        "readable",
    ]
    assert report[0]["superseded_by"] == 2


def test_other_blocks_do_not_enter_pc_ram() -> None:
    layer = load_layer(page_update_image())

    # The otherram page at 0x1000 is newer than the pc.ram page at the same
    # address, but it must not replace it.
    assert layer.read(0x1000, 8) == b"CCCCCCCC"

    # otherram records are still visible as evidence.
    assert len(layer.ram_page_history(b"otherram", 0x1000)) == 1
    assert layer.ram_page_winner(b"otherram", 0x2000).encoding == "page"

    # The CONTINUE record after the block switch stayed in otherram.
    assert layer.ram_page_source(0x2000).block_name == b"pc.ram"
    assert layer.ram_page_winner(b"otherram", 0x2000).encoding == "page"
    # The PCI hole only describes pc.ram, so other blocks are not relocated.
    other = layer.ram_page_winner(b"otherram", 0x1000)
    assert other.pci_hole == (0, 0)
    assert other.address == other.encoded_address

    # Only pc.ram contributes segments.
    assert all(segment[0] in (0x1000, 0x2000, 0x3000) for segment in layer._segments)


def test_compress_means_one_byte_repeated_over_the_page() -> None:
    layer = load_layer(page_update_image())
    record = layer.ram_page_source(0x3000)

    assert record is not None
    assert record.encoding == layer.RAM_ENCODING_COMPRESS
    assert record.stored_size == 1
    assert layer.read(0x3000, PAGE_SIZE) == b"Z" * PAGE_SIZE


def test_compressed_page_replaced_by_normal_page() -> None:
    records = _page_record(0x1000, b"pc.ram", b"Q", compress=True)
    records += _page_record(0x1000, b"pc.ram", _page(b"R"))
    layer = load_layer(build_image(records))

    assert layer.read(0x1000, 4) == b"RRRR"
    assert layer.ram_page_source(0x1000).encoding == layer.RAM_ENCODING_PAGE


def test_unsupported_delta_does_not_revive_older_page() -> None:
    records = _page_record(0x1000, b"pc.ram", _page(b"A"))
    delta = b"delta-bytes"
    flags = (
        qemu.QemuSuspendLayer.SEGMENT_FLAG_PAGE
        | qemu.QemuSuspendLayer.SEGMENT_FLAG_XBZRLE
        | qemu.QemuSuspendLayer.SEGMENT_FLAG_CONTINUE
    )
    records += _u64(0x1000 | flags) + struct.pack(">H", len(delta)) + delta
    layer = load_layer(build_image(records))

    history = layer.ram_page_history(b"pc.ram", 0x1000)
    assert len(history) == 2
    assert history[0].superseded_by == 1
    assert history[1].encoding == layer.RAM_ENCODING_XBZRLE
    assert history[1].unsupported_reason == layer.XBZRLE_LIMITATION
    assert layer.ram_page_source(0x1000) is None
    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(0x1000, 4)


def test_pci_hole_relocation_is_recomputable() -> None:
    # pc.ram large enough that the i440fx hole applies.  The hole start
    # (0xC0000000) and end (0x100000000) come from pci_hole_table.
    total = 0x100000000
    records = _page_record(0x1000, b"pc.ram", _page(b"L"))
    records += _page_record(0xC0000000, b"pc.ram", _page(b"H"), continue_block=True)
    layer = load_layer(
        build_image(records, ram_total=total, blocks=[(b"pc.ram", total)])
    )

    low = layer.ram_page_winner(b"pc.ram", 0x1000)
    high = layer.ram_page_winner(b"pc.ram", 0x100000000)
    assert low is not None and high is not None
    assert low.pci_hole == (0xC0000000, 0x100000000)
    assert low.address == 0x1000
    assert high.encoded_address == 0xC0000000
    assert high.address == 0x100000000

    for record in (low, high):
        assert (
            qemu.QemuSuspendLayer.relocate_ram_address(
                record.encoded_address, *record.pci_hole
            )
            == record.address
        )

    assert layer.read(0x1000, 4) == b"LLLL"
    assert layer.read(0x100000000, 4) == b"HHHH"
