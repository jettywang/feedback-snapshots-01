"""MSF stream isolation regressions.

Each test builds a synthetic (but structurally valid) MSF 2.0 container and
checks that stream layers expose exactly the bytes a stream's own declaration
describes.  Corruptions always leave the outer MSF header valid so the failure
has to be attributed by the directory parser or by the stream mapping itself.
"""

import math
import struct
from typing import List, Optional, Sequence, Tuple

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import msf, physical

PAGE_SIZE = 0x100
MAGIC = b"Microsoft C/C++ program database 2.00\r\n\x1aJG"
HEADER_SIZE = 60
ENTRY_SIZE = 4
ABSENT = 0xFFFFFFFF

StreamSpec = Optional[Tuple[int, List[int]]]


def page_bytes(page: int, page_size: int = PAGE_SIZE) -> bytes:
    """Deterministic per-page contents distinct from every other page."""
    return bytes(((page * 7) + offset) & 0xFF for offset in range(page_size))


def declared_bytes(spec: StreamSpec, page_size: int = PAGE_SIZE) -> bytes:
    """The logical bytes a stream declares, built from its own page list."""
    if spec is None:
        return b""
    size, pages = spec
    if size in (0, ABSENT):
        return b""
    return b"".join(page_bytes(page, page_size) for page in pages)[:size]


def build_msf(
    streams: Sequence[StreamSpec],
    *,
    page_size: int = PAGE_SIZE,
    stream_info_size: Optional[int] = None,
    directory_pages: Optional[List[int]] = None,
    page_map_pages: Optional[List[int]] = None,
    num_pages: Optional[int] = None,
    truncate_base_to: Optional[int] = None,
) -> Tuple[bytes, dict]:
    """Builds an MSF 2.0 container and returns the image plus layout metadata."""
    directory = bytearray(struct.pack("<I", len(streams)))
    for spec in streams:
        directory += struct.pack("<I", ABSENT if spec is None else spec[0])
    for spec in streams:
        if spec is None or spec[0] in (0, ABSENT):
            continue
        for page in spec[1]:
            directory += struct.pack("<I", page)

    if stream_info_size is None:
        stream_info_size = len(directory)
    directory = bytes(directory[:stream_info_size]).ljust(stream_info_size, b"\x00")

    directory_page_count = max(1, math.ceil(stream_info_size / page_size))
    if directory_pages is None:
        directory_pages = list(range(3, 3 + directory_page_count))
    else:
        directory_pages = list(directory_pages)
    if len(directory_pages) != directory_page_count:
        raise ValueError("directory_pages does not match the directory size")

    page_map_entries = max(1, math.ceil(directory_page_count * ENTRY_SIZE / page_size))
    if page_map_pages is None:
        page_map_pages = [1]
    else:
        page_map_pages = list(page_map_pages)
    if len(page_map_pages) != page_map_entries:
        raise ValueError("page_map_pages does not match the directory page count")

    stream_pages = [
        page
        for spec in streams
        if spec is not None and spec[0] not in (0, ABSENT)
        for page in spec[1]
    ]
    reserved = [0] + page_map_pages + directory_pages
    if set(reserved) & set(stream_pages):
        raise ValueError("directory/page-map pages overlap stream pages")
    used_pages = reserved + stream_pages
    if num_pages is None:
        num_pages = max(used_pages) + 1
    if max(used_pages) >= num_pages:
        raise ValueError("num_pages does not cover all referenced pages")

    image = bytearray()
    for page in range(num_pages):
        image += page_bytes(page, page_size)

    image[0:len(MAGIC)] = MAGIC
    image[len(MAGIC):44] = b"\x00" * (44 - len(MAGIC))
    struct.pack_into("<i", image, 44, page_size)
    struct.pack_into("<H", image, 48, 0)
    struct.pack_into("<H", image, 50, num_pages & 0xFFFF)
    struct.pack_into("<i", image, 52, stream_info_size)
    struct.pack_into("<I", image, 56, page_map_pages[0])

    # Header array: pages holding the directory's page-number list.
    for index, page in enumerate(page_map_pages):
        struct.pack_into("<I", image, HEADER_SIZE + index * ENTRY_SIZE, page)

    # Page map: the physical page numbers of the directory pages.
    page_map = b"".join(struct.pack("<I", page) for page in directory_pages)
    for index, page in enumerate(page_map_pages):
        start = page * page_size
        chunk = page_map[index * page_size:(index + 1) * page_size]
        image[start:start + page_size] = chunk.ljust(page_size, b"\x00")

    # Directory contents, split across the directory pages.
    for index, page in enumerate(directory_pages):
        start = page * page_size
        chunk = directory[index * page_size:(index + 1) * page_size]
        image[start:start + page_size] = chunk.ljust(page_size, b"\x00")

    image = bytes(image)
    if truncate_base_to is not None:
        image = image[:truncate_base_to]

    # Byte offset of each stream's declared-size field / page-list entries.
    stream_size_offsets = [ENTRY_SIZE * (index + 1) for index in range(len(streams))]
    page_list_offsets: List[List[int]] = []
    cursor = ENTRY_SIZE * (len(streams) + 1)
    for spec in streams:
        if spec is None or spec[0] in (0, ABSENT):
            page_list_offsets.append([])
            continue
        count = math.ceil(spec[0] / page_size)
        page_list_offsets.append(
            [cursor + index * ENTRY_SIZE for index in range(count)]
        )
        cursor += count * ENTRY_SIZE

    metadata = {
        "page_size": page_size,
        "directory_page_count": directory_page_count,
        "directory_pages": directory_pages,
        "stream_info_size": stream_info_size,
        "stream_size_offsets": stream_size_offsets,
        "page_list_offsets": page_list_offsets,
        "page_map_pages": page_map_pages,
    }
    return image, metadata


def patch_directory_u32(
    image: bytes, metadata: dict, directory_offset: int, value: int
) -> bytes:
    """Rewrites one directory entry in place (leaving the header untouched)."""
    page_size = metadata["page_size"]
    page_index, page_offset = divmod(directory_offset, page_size)
    image_offset = metadata["directory_pages"][page_index] * page_size + page_offset
    patched = bytearray(image)
    struct.pack_into("<I", patched, image_offset, value)
    return bytes(patched)


def mount(image: bytes) -> Tuple[contexts.Context, msf.PdbMultiStreamFormat]:
    context = contexts.Context()
    context.layers.add_layer(physical.BufferDataLayer(context, "base", "base", image))
    context.config["msf.base_layer"] = "base"
    layer = msf.PdbMultiStreamFormat(context, "msf", "msf")
    context.layers.add_layer(layer)
    return context, layer


def mounted_streams(
    streams: Sequence[StreamSpec], **kwargs
) -> Tuple[contexts.Context, msf.PdbMultiStreamFormat, dict]:
    image, metadata = build_msf(streams, **kwargs)
    context, layer = mount(image)
    layer.read_streams()
    return context, layer, metadata


# Streams are deliberately non-contiguous, cross page boundaries, share a
# physical page and include an empty (size 0) and a deleted (0xFFFFFFFF) stream.
LAYOUT: List[StreamSpec] = [
    (0x1A0, [21, 4]),          # 0: two pages, second partially used
    (0x1A0, [4, 21]),          # 1: same two pages in the opposite order
    (0x400, [33, 9, 30, 41]),  # 2: exactly four pages, non-contiguous
    (0, [40]),                 # 3: empty stream (page list ignored)
    (0x80, [21]),              # 4: shares a page with stream 0 and 1
    (ABSENT, []),              # 5: deleted stream
    (0x100, [9]),              # 6: borrows a middle page from stream 2
]


def test_stream_directory_spans_pages():
    # Enough streams that the directory itself is larger than one page: the
    # header page-number array then has to be read in one piece, and the
    # directory's own page list spans several directory pages.
    specs: List[StreamSpec] = list(LAYOUT)
    specs += [(0x20, [70 + index]) for index in range(60)]
    context, layer, metadata = mounted_streams(
        specs, directory_pages=[60, 61, 62]
    )
    assert metadata["directory_page_count"] > 1
    assert metadata["stream_info_size"] > metadata["page_size"]
    for index, spec in enumerate(specs):
        if spec is None or spec[0] in (0, ABSENT):
            continue
        stream = layer.get_stream(index)
        assert stream.read(0, stream.maximum_address) == declared_bytes(spec)


def test_each_stream_yields_its_own_declared_bytes():
    context, layer, _ = mounted_streams(LAYOUT)
    for index, spec in enumerate(LAYOUT):
        layer_name = f"msf_stream{index}"
        if spec is None or spec[0] in (0, ABSENT):
            assert layer.get_stream(index) is None
            assert layer_name not in context.layers
            continue
        stream = layer.get_stream(index)
        assert stream is not None
        assert stream.maximum_address == spec[0]
        assert stream.read(0, spec[0]) == declared_bytes(spec)


def test_empty_and_absent_streams_are_distinct_from_missing_ones():
    _, layer, _ = mounted_streams(LAYOUT)
    assert layer.get_stream(3) is None  # size 0
    assert layer.get_stream(5) is None  # size 0xFFFFFFFF
    with pytest.raises(msf.PDBFormatException, match="Stream not present"):
        layer.get_stream(len(LAYOUT))
    with pytest.raises(msf.PDBFormatException, match="Stream not present"):
        layer.get_stream(-1)


def slice_cases(size: int) -> dict:
    """Deterministic slices, all fully contained in a stream of ``size`` bytes."""
    after_page = min(PAGE_SIZE, size)
    return {
        "first-byte": (0, min(1, size)),
        "early": (min(1, max(0, size - 1)), min(5, size - min(1, max(0, size - 1)))),
        "before-page-boundary": (
            max(0, min(PAGE_SIZE - 1, size - 1)),
            min(2, size - max(0, min(PAGE_SIZE - 1, size - 1))),
        ),
        "after-page-boundary": (
            min(after_page, max(0, size - 1)),
            min(3, max(0, size - min(after_page, max(0, size - 1)))),
        ),
        "middle-third": (size // 3, max(1, size // 3)),
        "tail": (max(0, size - 7), min(7, size)),
    }


SLICE_CASES = [
    "first-byte",
    "early",
    "before-page-boundary",
    "after-page-boundary",
    "middle-third",
    "tail",
]


@pytest.mark.parametrize(
    "index",
    [
        pytest.param(0, id="partial-second-page"),
        pytest.param(1, id="reversed-pages"),
        pytest.param(2, id="three-pages"),
        pytest.param(4, id="shared-small"),
        pytest.param(6, id="shared-middle-page"),
    ],
)
@pytest.mark.parametrize("case", SLICE_CASES)
def test_random_slices_stay_within_the_stream(index, case):
    _, layer, _ = mounted_streams(LAYOUT)
    spec = LAYOUT[index]
    expected = declared_bytes(spec)
    offset, length = slice_cases(len(expected))[case]
    assert 0 <= offset and offset + length <= len(expected)
    stream = layer.get_stream(index)
    assert stream.read(offset, length) == expected[offset:offset + length]


def test_sequential_reads_match_one_shot_reads():
    _, layer, _ = mounted_streams(LAYOUT)
    for index, spec in enumerate(LAYOUT):
        if spec is None or spec[0] in (0, ABSENT):
            continue
        expected = declared_bytes(spec)
        stream = layer.get_stream(index)
        collected = b""
        for offset in range(0, len(expected), 13):
            collected += stream.read(offset, min(13, len(expected) - offset))
        assert collected == expected


def test_shared_physical_page_does_not_merge_streams():
    _, layer, _ = mounted_streams(LAYOUT)
    first = layer.get_stream(0)
    second = layer.get_stream(1)
    shared = layer.get_stream(4)
    # All three touch physical page 21, but expose the order and length each
    # stream declared, not the union of the pages involved.
    assert first.read(0, first.maximum_address) == declared_bytes(LAYOUT[0])
    assert second.read(0, second.maximum_address) == declared_bytes(LAYOUT[1])
    assert shared.read(0, shared.maximum_address) == declared_bytes(LAYOUT[4])
    assert first.read(0, first.maximum_address) != second.read(
        0, second.maximum_address
    )


@pytest.mark.parametrize("index", [0, 1, 2, 4, 6])
def test_overrun_is_attributed_to_the_stream(index):
    _, layer, _ = mounted_streams(LAYOUT)
    stream = layer.get_stream(index)
    size = stream.maximum_address
    assert not stream.is_valid(0, size + 1)
    assert not stream.is_valid(size, 1)
    with pytest.raises(exceptions.InvalidAddressException) as excinfo:
        stream.read(0, size + 1)
    assert excinfo.value.layer_name == stream.name
    assert excinfo.value.invalid_address == size
    with pytest.raises(exceptions.InvalidAddressException):
        stream.read(size, 1)


def test_directory_truncation_is_rejected_before_any_stream_is_built():
    # One trailing page-number entry removed: the last stream's declared size
    # no longer agrees with the page list that remains.
    truncated_size = (
        ENTRY_SIZE * (len(LAYOUT) + 1)
        + ENTRY_SIZE * sum(
            math.ceil(spec[0] / PAGE_SIZE)
            for spec in LAYOUT
            if spec is not None and spec[0] not in (0, ABSENT)
        )
        - ENTRY_SIZE
    )
    image, _ = build_msf(LAYOUT, stream_info_size=truncated_size)
    context, layer = mount(image)
    with pytest.raises(msf.PDBFormatException, match="stream directory"):
        layer.read_streams()
    assert layer._streams == {}
    assert [name for name in context.layers if name.startswith("msf_stream")] == []


def test_truncated_directory_cannot_reach_into_the_next_stream():
    # Declare the second stream one page larger so its page list would consume
    # the third stream's page numbers.
    specs = [list(spec) if spec is not None else None for spec in LAYOUT]
    specs[1][0] = LAYOUT[1][0] + PAGE_SIZE
    image, _ = build_msf(specs)
    context, layer = mount(image)
    with pytest.raises(msf.PDBFormatException, match="directory"):
        layer.read_streams()
    assert layer._streams == {}


def test_declared_size_smaller_than_page_list_is_rejected():
    specs = [list(spec) if spec is not None else None for spec in LAYOUT]
    specs[0][0] = LAYOUT[0][0] - PAGE_SIZE
    image, _ = build_msf(specs)
    _, layer = mount(image)
    with pytest.raises(msf.PDBFormatException, match="disagree"):
        layer.read_streams()


def test_zero_padded_directory_tail_is_accepted_but_never_borrowed():
    specs = list(LAYOUT)
    exact_size = (
        ENTRY_SIZE * (len(specs) + 1)
        + ENTRY_SIZE * sum(
            math.ceil(spec[0] / PAGE_SIZE)
            for spec in specs
            if spec is not None and spec[0] not in (0, ABSENT)
        )
    )
    context, layer, _ = mounted_streams(specs, stream_info_size=exact_size + 8)
    for index, spec in enumerate(specs):
        if spec is None or spec[0] in (0, ABSENT):
            continue
        stream = layer.get_stream(index)
        assert stream.read(0, stream.maximum_address) == declared_bytes(spec)

    # Non-zero trailing bytes are treated as a disagreement, not as extra
    # page numbers for the last stream.
    image, metadata = build_msf(specs, stream_info_size=exact_size + 8)
    last_directory_offset = exact_size + 4
    image = patch_directory_u32(image, metadata, last_directory_offset, 77)
    _, broken = mount(image)
    with pytest.raises(msf.PDBFormatException, match="disagree"):
        broken.read_streams()


def test_truncated_base_layer_directory_has_a_clear_owner():
    image, metadata = build_msf(LAYOUT)
    last_directory_page = metadata["directory_pages"][-1]
    image = image[:last_directory_page * PAGE_SIZE + 10]
    context, layer = mount(image)
    with pytest.raises(msf.PDBFormatException, match="outside the base layer"):
        layer.read_streams()


def test_out_of_range_stream_page_fails_at_stream_mapping():
    image, metadata = build_msf(LAYOUT)
    # Corrupt only stream 2's second page number; the outer header stays valid.
    directory_offset = metadata["page_list_offsets"][2][1]
    image = patch_directory_u32(image, metadata, directory_offset, 0xDEADBEEF)
    context, layer = mount(image)
    layer.read_streams()

    broken = layer.get_stream(2)
    assert broken is not None
    assert not broken.is_valid(0, broken.maximum_address)
    with pytest.raises(exceptions.InvalidAddressException) as excinfo:
        broken.read(0, broken.maximum_address)
    assert excinfo.value.layer_name == "msf_stream2"

    # Unrelated streams remain readable, including the one sharing pages with it.
    for index in (0, 1, 4, 6):
        stream = layer.get_stream(index)
        assert stream.read(0, stream.maximum_address) == declared_bytes(LAYOUT[index])


def test_length_contradiction_never_takes_neighbouring_page_numbers():
    image, metadata = build_msf(LAYOUT)
    # Inflate stream 6's declared size by two pages.  The directory is an exact
    # fit, so its page list cannot absorb the extra entries taken from later
    # streams; parsing must reject it instead of re-slicing the directory.
    directory_offset = metadata["stream_size_offsets"][6]
    image = patch_directory_u32(image, metadata, directory_offset, PAGE_SIZE * 3)
    context, layer = mount(image)
    with pytest.raises(msf.PDBFormatException, match="Stream page lists"):
        layer.read_streams()
    assert layer._streams == {}

    # The shared stream 4 is still intact when parsed on its own.
    _, clean_layer, _ = mounted_streams(LAYOUT)
    shared = clean_layer.get_stream(4)
    assert shared.read(0, shared.maximum_address) == declared_bytes(LAYOUT[4])


def test_padded_read_of_broken_stream_does_not_splice_other_streams():
    image, metadata = build_msf(LAYOUT)
    directory_offset = metadata["page_list_offsets"][2][1]
    image = patch_directory_u32(image, metadata, directory_offset, 0xDEADBEEF)
    context, layer = mount(image)
    layer.read_streams()

    broken = layer.get_stream(2)
    padded = broken.read(0, broken.maximum_address, pad=True)
    # The first page is still the stream's own; the missing page is zeroed
    # rather than filled from physical page 30 or any neighbouring stream.
    assert padded[:PAGE_SIZE] == page_bytes(33)
    assert padded[PAGE_SIZE:] == b"\x00" * (broken.maximum_address - PAGE_SIZE)


def test_stream_mapping_does_not_wrap_short_page_lists():
    image, _ = build_msf(LAYOUT)
    context, layer = mount(image)
    layer.read_streams()
    pdb = layer

    context.config["msf.short.base_layer"] = "msf"
    context.config["msf.short.pages"] = [21]
    context.config["msf.short.maximum_size"] = PAGE_SIZE + 1
    with pytest.raises(msf.PDBFormatException, match="page numbers were supplied"):
        msf.PdbMSFStream(context, "msf.short", "short")

    context.config["msf.zero.base_layer"] = "msf"
    context.config["msf.zero.pages"] = [21]
    context.config["msf.zero.maximum_size"] = 0
    with pytest.raises(msf.PDBFormatException, match="page numbers were supplied"):
        msf.PdbMSFStream(context, "msf.zero", "zero")


def test_directory_page_number_outside_container_is_rejected():
    image, metadata = build_msf(LAYOUT)
    # Point the header's page-map entry at a page beyond the base layer.  The
    # directory itself cannot be located, so this must fail during setup.
    bad_page = len(image) // PAGE_SIZE + 5
    header_byte = HEADER_SIZE
    patched = bytearray(image[: header_byte + ENTRY_SIZE])
    struct.pack_into("<I", patched, header_byte, bad_page)
    patched += image[header_byte + ENTRY_SIZE :]
    context, layer = mount(bytes(patched))
    with pytest.raises(msf.PDBFormatException, match="outside the base layer"):
        layer.read_streams()


def test_negative_stream_page_number_is_rejected_at_mapping():
    image, metadata = build_msf(LAYOUT)
    directory_offset = metadata["page_list_offsets"][4][0]
    image = patch_directory_u32(image, metadata, directory_offset, 0xFFFFFFF0)
    context, layer = mount(image)
    layer.read_streams()

    broken = layer.get_stream(4)
    assert not broken.is_valid(0, broken.maximum_address)
    with pytest.raises(exceptions.InvalidAddressException) as excinfo:
        broken.read(0, broken.maximum_address)
    assert excinfo.value.layer_name == "msf_stream4"


def test_header_remains_valid_for_corrupt_stream_fixtures():
    image, _ = build_msf(LAYOUT)
    assert image.startswith(MAGIC)
    struct.unpack_from("<i", image, 44)[0] == PAGE_SIZE
    # A valid header means corruption is only reported by stream-level parsing.
    context, layer = mount(image)
    assert layer._version == "MSF_HDR"
