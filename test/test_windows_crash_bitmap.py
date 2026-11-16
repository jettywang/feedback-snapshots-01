"""Bitmap page mapping regressions for the Windows crash dump layers.

A bitmap dump (DumpType 5) stores one bit per physical page. Only a set bit
has a page appended to the file: a cleared bit is a hole and must not consume
any of the following file pages. These tests build complete synthetic dumps
in memory, run them through the real layer construction entry (the crash
dump stacker) for both header layouts, and assert the header fields, the
segment translation, sequential and cross-hole reads, and the failure of a
variant that computes file positions directly from the physical page number.
"""

import struct

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import crash, physical

PAGE_SIZE = 0x1000
PAGE_SIGNATURE = b"PAGE"
SUMMARY_SIGNATURE = b"DUMP"
HEADER_SIGNATURE = crash.WindowsCrashDump32Layer.SIGNATURE
DUMP_TYPE_BITMAP = 0x5
DIRECTORY_TABLE_BASE = 0x00123000

# 32- and 64-bit main headers differ in size and in the DumpType offset.
HEADER_PAGES = {32: 1, 64: 2}
VALID_DUMP = {
    32: crash.WindowsCrashDump32Layer.VALIDDUMP,
    64: crash.WindowsCrashDump64Layer.VALIDDUMP,
}
DUMP_TYPE_OFFSET = {32: 3976, 64: 3992}
EXPECTED_LAYER = {
    32: crash.WindowsCrashDump32Layer,
    64: crash.WindowsCrashDump64Layer,
}

# Short bitmap exercising, in order, an all-ones word, an all-zero word, a
# mixed word with internal holes, and set bits continued across the following
# word boundary. The mixed word's highest set bit (page 69) is followed by a
# mapped first bit in the next word, so the run crosses that word boundary.
RICH_BITMAP_WORDS = [
    0xFFFFFFFF,
    0x00000000,
    0b10111111,
    0xFFFFFFFF,
    0xFFFFFFFF,
]

# Bitmap whose final mapped run reaches the very last bit, so the closing of
# the trailing segment cannot rely on a later zero word.
TRAILING_BITMAP_WORDS = [0b101, 0x80000000]


def present_pages(bitmap_words):
    """Physical page numbers whose bitmap bit is set, in bit order."""
    pages = []
    for word_index, word in enumerate(bitmap_words):
        for bit_index in range(32):
            if word & (1 << bit_index):
                pages.append(word_index * 32 + bit_index)
    return pages


def page_marker(page_frame_number):
    """Distinct, self-describing contents for one saved physical page."""
    return (
        PAGE_SIGNATURE
        + struct.pack("<I", page_frame_number)
        + bytes([page_frame_number & 0xFF]) * (PAGE_SIZE - 8)
    )


def build_bitmap_dump(bitness, bitmap_words):
    """Assemble a complete bitmap crash dump as a single byte string."""
    header_pages = HEADER_PAGES[bitness]
    summary_offset = header_pages * PAGE_SIZE
    header_size = summary_offset + PAGE_SIZE
    data_offset = header_size
    bitmap_size = len(bitmap_words) * 32
    mapped_pages = present_pages(bitmap_words)

    main_header = bytearray(header_pages * PAGE_SIZE)
    struct.pack_into("<II", main_header, 0, HEADER_SIGNATURE, VALID_DUMP[bitness])
    if bitness == 32:
        struct.pack_into("<I", main_header, 16, DIRECTORY_TABLE_BASE)
    else:
        struct.pack_into("<Q", main_header, 16, DIRECTORY_TABLE_BASE)
    struct.pack_into("<I", main_header, DUMP_TYPE_OFFSET[bitness], DUMP_TYPE_BITMAP)

    summary_header = bytearray(PAGE_SIZE)
    summary_header[0:4] = SUMMARY_SIGNATURE
    summary_header[4:8] = SUMMARY_SIGNATURE
    struct.pack_into(
        "<QQQ",
        summary_header,
        32,
        header_size,
        len(mapped_pages),
        bitmap_size,
    )
    for word_index, word in enumerate(bitmap_words):
        struct.pack_into("<I", summary_header, 56 + word_index * 4, word)

    page_data = bytearray()
    for page_frame_number in mapped_pages:
        page_data += page_marker(page_frame_number)

    blob = bytes(main_header) + bytes(summary_header) + bytes(page_data)
    return blob, {
        "header_pages": header_pages,
        "summary_offset": summary_offset,
        "header_size": header_size,
        "data_offset": data_offset,
        "bitmap_size": bitmap_size,
        "mapped_pages": mapped_pages,
    }


def stack_crash_layer(blob):
    """Construct the crash layer through the real stacker entry point."""
    context = contexts.Context()
    context.layers.add_layer(
        physical.BufferDataLayer(context, "base_config", "base", blob)
    )
    layer = crash.WindowsCrashDumpStacker.stack(context, "base")
    assert layer is not None
    context.layers.add_layer(layer)
    return context, layer


@pytest.mark.parametrize("bitness", [32, 64], ids=["32bit", "64bit"])
def test_bitmap_header_and_file_layout(bitness):
    blob, layout = build_bitmap_dump(bitness, RICH_BITMAP_WORDS)
    context, layer = stack_crash_layer(blob)

    assert isinstance(layer, EXPECTED_LAYER[bitness])
    header = layer.get_header()
    assert int(header.DumpType) == DUMP_TYPE_BITMAP
    assert int(header.DirectoryTableBase) == DIRECTORY_TABLE_BASE

    summary = layer.get_summary_header()
    assert int(summary.HeaderSize) == layout["header_size"]
    assert int(summary.Pages) == len(layout["mapped_pages"])
    assert int(summary.BitmapSize) == layout["bitmap_size"]

    # The summary header starts after the main header pages, which are the
    # only structural difference between the 32- and 64-bit layouts.
    assert summary.vol.offset == layout["summary_offset"]
    assert layout["header_size"] - layout["summary_offset"] == PAGE_SIZE

    # Only set bits consume file pages: the data region is exactly
    # Pages * page size, regardless of how many physical pages are holes.
    actual_data_length = len(blob) - layout["data_offset"]
    assert actual_data_length == int(summary.Pages) * PAGE_SIZE
    assert actual_data_length == len(layout["mapped_pages"]) * PAGE_SIZE

    assert context.layers[layer.name] is layer


@pytest.mark.parametrize("bitness", [32, 64], ids=["32bit", "64bit"])
def test_bitmap_segments_skip_holes(bitness):
    blob, layout = build_bitmap_dump(bitness, RICH_BITMAP_WORDS)
    _, layer = stack_crash_layer(blob)

    # (physical start page, file offset, length) derived independently of
    # the layer's own iteration logic. The mixed word 0b10111111 maps pages
    # 64..69 and 71; page 69 continues across the following word boundary,
    # merging with page 70, while page 71 starts a segment that the next
    # all-ones word extends from page 96 onwards.
    expected_segments = [
        (0, layout["header_size"], 32 * PAGE_SIZE),
        (64, layout["header_size"] + 32 * PAGE_SIZE, 6 * PAGE_SIZE),
        (71, layout["header_size"] + 38 * PAGE_SIZE, PAGE_SIZE),
        (96, layout["header_size"] + 39 * PAGE_SIZE, 64 * PAGE_SIZE),
    ]
    actual_segments = [
        (start // PAGE_SIZE, mapped_offset, length)
        for start, mapped_offset, length, _mapped_length in layer._segments
    ]
    assert actual_segments == expected_segments

    # Every mapped page resolves to a unique file slot with no gaps between
    # successive saved pages, even across word boundaries.
    mapped_pages = layout["mapped_pages"]
    previous_file_offset = None
    for file_index, page_frame_number in enumerate(mapped_pages):
        file_offset, mapped_layer = layer.translate(page_frame_number * PAGE_SIZE)
        assert mapped_layer == "base"
        assert file_offset == layout["data_offset"] + file_index * PAGE_SIZE
        if previous_file_offset is not None:
            assert file_offset - previous_file_offset == PAGE_SIZE
        previous_file_offset = file_offset

    # Cleared bits, including the all-zero word, are not valid addresses.
    for hole_page in (32, 70, 72):
        assert not layer.is_valid(hole_page * PAGE_SIZE, PAGE_SIZE)
        with pytest.raises(exceptions.InvalidAddressException):
            layer.read(hole_page * PAGE_SIZE, PAGE_SIZE)


@pytest.mark.parametrize("bitness", [32, 64], ids=["32bit", "64bit"])
def test_sequential_and_cross_hole_reads(bitness):
    blob, layout = build_bitmap_dump(bitness, RICH_BITMAP_WORDS)
    _, layer = stack_crash_layer(blob)

    # Sequential reads of every saved page return its own marker rather than
    # the marker of a neighbouring physical page.
    for page_frame_number in layout["mapped_pages"]:
        data = layer.read(page_frame_number * PAGE_SIZE, PAGE_SIZE)
        assert data == page_marker(page_frame_number)
        assert struct.unpack("<I", data[4:8])[0] == page_frame_number

    # A read spanning the all-zero word (pages 32..63) cannot be satisfied.
    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(31 * PAGE_SIZE, 2 * PAGE_SIZE)

    # A read starting inside a mapped page and entering a hole fails on the
    # hole rather than silently returning the next saved page. Page 69 is
    # mapped while page 70 is cleared at the mixed/fast-word boundary.
    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(69 * PAGE_SIZE + PAGE_SIZE // 2, PAGE_SIZE)

    # Padded reads skip holes with zero fill while keeping mapped data:
    # page 31 is present, pages 32..63 (the all-zero word) are absent, and
    # page 64 is the first present page after the hole.
    padded = layer.read(31 * PAGE_SIZE, 34 * PAGE_SIZE, pad=True)
    assert len(padded) == 34 * PAGE_SIZE
    assert padded[:PAGE_SIZE] == page_marker(31)
    assert padded[PAGE_SIZE : 33 * PAGE_SIZE] == b"\x00" * (32 * PAGE_SIZE)
    assert padded[33 * PAGE_SIZE :] == page_marker(64)

    # ignore_errors mappings report only the present pieces around a hole.
    # Pages 68..69 belong to one cross-word segment, page 70 is a single-page
    # hole, and page 71 is its own segment; page 96 lies outside the range.
    mappings = list(layer.mapping(68 * PAGE_SIZE, 4 * PAGE_SIZE, ignore_errors=True))
    assert [(offset // PAGE_SIZE, length) for offset, length, *_ in mappings] == [
        (68, 2 * PAGE_SIZE),
        (71, PAGE_SIZE),
    ]


@pytest.mark.parametrize("bitness", [32, 64], ids=["32bit", "64bit"])
def test_naive_physical_page_file_position_fails(bitness):
    blob, layout = build_bitmap_dump(bitness, RICH_BITMAP_WORDS)
    context, layer = stack_crash_layer(blob)

    # A late present page sits far beyond the compacted data region when
    # located naively: physical page 159 is only the 101st saved page.
    late_page = layout["mapped_pages"][-1]
    assert late_page > len(layout["mapped_pages"])
    translated_offset, _ = layer.translate(late_page * PAGE_SIZE)
    naive_offset = layout["data_offset"] + late_page * PAGE_SIZE
    assert naive_offset != translated_offset
    assert naive_offset >= len(blob)
    with pytest.raises(exceptions.InvalidAddressException):
        context.layers.read("base", naive_offset, PAGE_SIZE)

    # For an earlier page the naive offset stays inside the file but lands on
    # another page's marker, proving hole compaction rather than truncation.
    shifted_page = 69
    shifted_index = layout["mapped_pages"].index(shifted_page)
    correct_offset = layout["data_offset"] + shifted_index * PAGE_SIZE
    wrong_offset = layout["data_offset"] + shifted_page * PAGE_SIZE
    assert wrong_offset != correct_offset
    assert wrong_offset + PAGE_SIZE <= len(blob)
    wrong_data = context.layers.read("base", wrong_offset, 8)
    assert struct.unpack("<I", wrong_data[4:8])[0] != shifted_page
    assert layer.read(shifted_page * PAGE_SIZE, 8) == page_marker(shifted_page)[:8]


@pytest.mark.parametrize("bitness", [32, 64], ids=["32bit", "64bit"])
def test_trailing_bitmap_run_closed_at_last_bit(bitness):
    blob, layout = build_bitmap_dump(bitness, TRAILING_BITMAP_WORDS)
    _, layer = stack_crash_layer(blob)

    summary = layer.get_summary_header()
    assert int(summary.Pages) == 3
    assert int(summary.BitmapSize) == 64

    expected_segments = [
        (0, layout["header_size"], PAGE_SIZE),
        (2, layout["header_size"] + PAGE_SIZE, PAGE_SIZE),
        (63, layout["header_size"] + 2 * PAGE_SIZE, PAGE_SIZE),
    ]
    actual_segments = [
        (start // PAGE_SIZE, mapped_offset, length)
        for start, mapped_offset, length, _mapped_length in layer._segments
    ]
    assert actual_segments == expected_segments

    for page_frame_number in layout["mapped_pages"]:
        assert (
            layer.read(page_frame_number * PAGE_SIZE, 8)
            == page_marker(page_frame_number)[:8]
        )
    assert not layer.is_valid(3 * PAGE_SIZE, PAGE_SIZE)
