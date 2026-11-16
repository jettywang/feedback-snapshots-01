"""Read-only page table explanations for the Intel translation layers.

These tests build tiny page tables by hand inside a buffer-backed physical
layer so that every entry value, entry location and permission bit is known.
"""

import struct

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import intel, physical

PRESENT = 0x1
RW = 0x2
PSE = 0x80
NX = 1 << 63

PAGE = 0x1000


def _qword(buffer, address, value):
    buffer[address : address + 8] = struct.pack("<Q", value)


def _dword(buffer, address, value):
    buffer[address : address + 4] = struct.pack("<I", value)


def _make_intel32e_layer(buffer, cr3=0x1000):
    context = contexts.Context()
    context.layers.add_layer(
        physical.BufferDataLayer(context, "memory", "memory", bytes(buffer))
    )
    config_path = "intel32e_test"
    context.config[config_path + ".memory_layer"] = "memory"
    context.config[config_path + ".page_map_offset"] = cr3
    layer = intel.Intel32e(context, config_path, "virt")
    context.layers.add_layer(layer)
    return layer


def _va_4level(pml4_idx, pdpt_idx, pd_idx, pt_idx, offset):
    return (
        (pml4_idx << 39)
        | (pdpt_idx << 30)
        | (pd_idx << 21)
        | (pt_idx << 12)
        | offset
    )


@pytest.fixture
def intel32e_tables():
    """PML4/PDPT/PD/PT at 0x1000/0x2000/0x3000/0x4000, data page at 0x5000."""
    buffer = bytearray(0x6000)
    virtual = _va_4level(1, 2, 3, 4, 0xABC)
    return buffer, virtual


def test_explain_leaf_writable_but_upper_level_readonly(intel32e_tables):
    buffer, virtual = intel32e_tables
    # Upper levels clear the read/write bit; only the leaf PTE allows writes.
    _qword(buffer, 0x1000 + 1 * 8, 0x2000 | PRESENT)
    _qword(buffer, 0x2000 + 2 * 8, 0x3000 | PRESENT)
    _qword(buffer, 0x3000 + 3 * 8, 0x4000 | PRESENT)
    _qword(buffer, 0x4000 + 4 * 8, 0x5000 | PRESENT | RW)
    buffer[0x5ABC] = 0x7B

    layer = _make_intel32e_layer(buffer)
    explanation = layer.explain(virtual)

    assert explanation.status == intel.EXPLAIN_STATUS_MAPPED
    assert explanation.large_page is False
    assert explanation.page_size == PAGE
    assert explanation.physical_address == 0x5ABC
    # The explanation must point at the same bytes as the read interface.
    assert layer.read(virtual, 1) == b"\x7b"

    # Write is denied by an upper-level entry despite the writable leaf.
    assert explanation.permissions.writable is False
    assert "page map layer 4" in explanation.permissions.write_basis
    # No entry sets NX, so execute is allowed.
    assert explanation.permissions.executable is True

    [root, pml4, pdpt, pd, pt] = explanation.walk
    assert root.level_name == "page map"
    assert root.entry_location is None
    for record, location, table, index in [
        (pml4, 0x1008, 0x1000, 1),
        (pdpt, 0x2010, 0x2000, 2),
        (pd, 0x3018, 0x3000, 3),
        (pt, 0x4020, 0x4000, 4),
    ]:
        assert record.entry_index == index
        assert record.table_location == table
        assert record.entry_location == location
        # Raw value matches the bytes stored at the reported location.
        (stored,) = struct.unpack(
            "<Q", bytes(buffer[location : location + 8])
        )
        assert record.entry_value == stored
        assert record.present is True
    assert pml4.writable_bit is False
    assert pt.writable_bit is True


def test_explain_leaf_nx_denies_execution_but_allows_write(intel32e_tables):
    buffer, virtual = intel32e_tables
    _qword(buffer, 0x1000 + 1 * 8, 0x2000 | PRESENT | RW)
    _qword(buffer, 0x2000 + 2 * 8, 0x3000 | PRESENT | RW)
    _qword(buffer, 0x3000 + 3 * 8, 0x4000 | PRESENT | RW)
    _qword(buffer, 0x4000 + 4 * 8, 0x5000 | PRESENT | RW | NX)

    layer = _make_intel32e_layer(buffer)
    explanation = layer.explain(virtual)

    assert explanation.status == intel.EXPLAIN_STATUS_MAPPED
    assert explanation.permissions.writable is True
    assert explanation.permissions.executable is False
    assert "page table" in explanation.permissions.execute_basis
    assert explanation.physical_address == 0x5ABC


def test_explain_large_page_terminates_walk_early(intel32e_tables):
    buffer, virtual = intel32e_tables
    frame_offset = virtual & 0x1FFFFF
    frame_base = 0x600000
    # Extend the buffer so the whole 2 MiB frame backing the large page fits.
    buffer.extend(b"\x00" * (frame_base + 0x200000 - len(buffer)))
    _qword(buffer, 0x1000 + 1 * 8, 0x2000 | PRESENT)
    _qword(buffer, 0x2000 + 2 * 8, 0x3000 | PRESENT)
    # 2 MiB page: PSE set, writable leaf pointing at the large frame.
    _qword(
        buffer,
        0x3000 + 3 * 8,
        frame_base | PRESENT | RW | PSE,
    )
    buffer[frame_base + frame_offset] = 0x9C

    layer = _make_intel32e_layer(buffer)
    explanation = layer.explain(virtual)

    assert explanation.status == intel.EXPLAIN_STATUS_MAPPED
    assert explanation.large_page is True
    assert explanation.page_size == 0x200000
    assert explanation.physical_address == frame_base + frame_offset
    assert layer.read(virtual, 1) == b"\x9c"

    # Walk ends at the page directory: no page table entry is consulted.
    level_names = [record.level_name for record in explanation.walk]
    assert level_names == [
        "page map",
        "page map layer 4",
        "page directory pointer",
        "page directory",
    ]
    leaf = explanation.walk[-1]
    assert leaf.large_page is True
    # The upper-level read-only restriction still governs the large page.
    assert explanation.permissions.writable is False
    assert explanation.permissions.executable is True


def test_explain_mid_walk_missing_entry_keeps_confirmed_path(intel32e_tables):
    buffer, virtual = intel32e_tables
    _qword(buffer, 0x1000 + 1 * 8, 0x2000 | PRESENT | RW)
    _qword(buffer, 0x2000 + 2 * 8, 0x3000 | PRESENT | RW)
    # Give the page directory a second, distinct entry so the framework's
    # all-duplicate table heuristic does not discard the whole table.
    _qword(buffer, 0x3000 + 9 * 8, 0x7000 | PRESENT)
    # The target page directory entry is absent: translation stops here.
    _qword(buffer, 0x3000 + 3 * 8, 0)

    layer = _make_intel32e_layer(buffer)
    explanation = layer.explain(virtual)

    assert explanation.status == intel.EXPLAIN_STATUS_NOT_PRESENT
    assert explanation.physical_address is None
    assert explanation.page_size is None
    assert explanation.permissions is None
    assert explanation.incomplete_reason is not None
    assert "page directory" in explanation.incomplete_reason

    # Entries confirmed before the missing one are retained verbatim.
    level_names = [record.level_name for record in explanation.walk]
    assert level_names == [
        "page map",
        "page map layer 4",
        "page directory pointer",
        "page directory",
    ]
    missing = explanation.walk[-1]
    assert missing.entry_value == 0
    assert missing.present is False
    assert missing.entry_location == 0x3000 + 3 * 8

    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(virtual, 1)


def test_explain_unreadable_table_does_not_report_denials(intel32e_tables):
    buffer, virtual = intel32e_tables
    unreadable_table = 0x90000000
    # PML4 is present and read-only but points at an unreadable PDPT.
    _qword(
        buffer,
        0x1000 + 1 * 8,
        unreadable_table | PRESENT,
    )

    layer = _make_intel32e_layer(buffer)
    explanation = layer.explain(virtual)

    assert explanation.status == intel.EXPLAIN_STATUS_UNREADABLE_TABLE
    assert explanation.physical_address is None
    assert explanation.permissions is not None
    # The read-only PML4 is a confirmed write denial.
    assert explanation.permissions.writable is False
    # Execute was never disproven: unreadable levels mean "unknown", not NX.
    assert explanation.permissions.executable is None
    assert "could not be inspected" in explanation.permissions.execute_basis

    unread = explanation.walk[-1]
    assert unread.entry_value is None
    assert unread.present is None
    assert unread.table_location == unreadable_table
    assert unread.entry_location == unreadable_table + 2 * 8

    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(virtual, 1)


def test_explain_unreadable_table_without_confirmed_denial(intel32e_tables):
    buffer, virtual = intel32e_tables
    unreadable_table = 0x90000000
    _qword(
        buffer,
        0x1000 + 1 * 8,
        unreadable_table | PRESENT | RW,
    )

    layer = _make_intel32e_layer(buffer)
    explanation = layer.explain(virtual)

    assert explanation.status == intel.EXPLAIN_STATUS_UNREADABLE_TABLE
    # No readable entry denies anything, so neither verdict is conclusive.
    assert explanation.permissions.writable is None
    assert explanation.permissions.executable is None
    assert "could not be inspected" in explanation.permissions.write_basis


def test_explain_32bit_non_pae_has_no_execute_information():
    # Two-level 32-bit paging with 4-byte entries: no NX bit exists.
    buffer = bytearray(0x4000)
    virtual = (1 << 22) | (2 << 12) | 0x123
    _dword(buffer, 0x1000 + 1 * 4, 0x2000 | PRESENT | RW)
    _dword(buffer, 0x2000 + 2 * 4, 0x3000 | PRESENT | RW)
    buffer[0x3123] = 0x55

    context = contexts.Context()
    context.layers.add_layer(
        physical.BufferDataLayer(context, "memory", "memory", bytes(buffer))
    )
    config_path = "intel_test"
    context.config[config_path + ".memory_layer"] = "memory"
    context.config[config_path + ".page_map_offset"] = 0x1000
    layer = intel.Intel(context, config_path, "virt32")

    explanation = layer.explain(virtual)

    assert explanation.status == intel.EXPLAIN_STATUS_MAPPED
    assert explanation.physical_address == 0x3123
    assert layer.read(virtual, 1) == b"\x55"
    assert explanation.permissions.writable is True
    assert explanation.permissions.executable is None
    assert "no-execute bit" in explanation.permissions.execute_basis
    assert all(
        record.execute_disabled_bit is None for record in explanation.walk
    )


def test_explain_32bit_pse_large_page():
    # A PSE entry in the page directory maps a whole 4 MiB frame.
    frame_base = 0x800000
    buffer = bytearray(frame_base + 0x400000)
    virtual = (1 << 22) | 0x4567
    _dword(buffer, 0x1000 + 1 * 4, frame_base | PRESENT | RW | PSE)
    frame_offset = virtual & 0x3FFFFF
    buffer[frame_base + frame_offset] = 0xC3

    context = contexts.Context()
    context.layers.add_layer(
        physical.BufferDataLayer(context, "memory", "memory", bytes(buffer))
    )
    config_path = "intel_pse_test"
    context.config[config_path + ".memory_layer"] = "memory"
    context.config[config_path + ".page_map_offset"] = 0x1000
    layer = intel.Intel(context, config_path, "virt32pse")

    explanation = layer.explain(virtual)

    assert explanation.status == intel.EXPLAIN_STATUS_MAPPED
    assert explanation.large_page is True
    assert explanation.page_size == 0x400000
    assert explanation.physical_address == frame_base + frame_offset
    assert layer.read(virtual, 1) == b"\xc3"
    assert len(explanation.walk) == 2
