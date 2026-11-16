"""Structural regression tests for the VMSS/VMSN metadata reader.

The synthetic metadata below is produced by an independent encoder in this
file, and the expected address mappings come from a fixed layout table, so
the reader under test never generates its own expected answers.
"""

import struct

import pytest

from volatility3.framework import contexts
from volatility3.framework.layers import physical, vmware

PAGE_SIZE = 0x1000

# Independent layout table: (physical page number, VMEM page, size in pages).
# Physical regions are discontiguous, sorted by PPN (a format invariant), and
# their VMEM offsets are deliberately not monotonic.
REGION_LAYOUT = (
    (0x003, 0x040, 0x10),
    (0x042, 0x000, 0x20),
    (0x100, 0x030, 0x08),
)

EXPECTED_SEGMENTS = tuple(
    (ppn * PAGE_SIZE, vmem * PAGE_SIZE, pages * PAGE_SIZE, pages * PAGE_SIZE)
    for ppn, vmem, pages in REGION_LAYOUT
)

MAGICS = {0: b"\xd0\xbe\xd2\xbe", 1: b"\xd1\xba\xd1\xba"}
EXTENDED_WIDTHS = {0: 4, 1: 8}

HEADER = struct.Struct("<4sII")
GROUP = struct.Struct("<64sQQ")
TAG_LOCATION = HEADER.size + GROUP.size


def _tag_prefix(data_len_bits, name, indices=()):
    flags = (len(indices) << 6) | data_len_bits
    encoded = struct.pack("BB", flags, len(name)) + name
    for index in indices:
        encoded += struct.pack("<I", index)
    return encoded


def _regular_tag(name, value, width, indices=()):
    return _tag_prefix(width, name, indices) + value.to_bytes(width, "little")


def _extended_tag(name, data, width):
    payload = (
        len(data).to_bytes(width, "little")
        + b"\x00" * width
        + b"\x00\x00"
        + data
    )
    return _tag_prefix(62, name) + payload


def _meminfo_payload():
    return bytes((index * 7 + 1) & 0xFF for index in range(0x30))


def _tag_table(version, region_widths=(4, 8, 4)):
    """Returns an ordered list of (label, blob) tags describing REGION_LAYOUT."""
    tags = [
        (("memInfo", None), _extended_tag(b"memInfo", _meminfo_payload(), EXTENDED_WIDTHS[version])),
        (("regionsCount", None), _regular_tag(b"regionsCount", len(REGION_LAYOUT), 4)),
    ]
    ppn_width, mapped_width, size_width = region_widths
    for index, (ppn, mapped, pages) in enumerate(REGION_LAYOUT):
        tags.append((("regionPPN", index), _regular_tag(b"regionPPN", ppn, ppn_width, (index,))))
        tags.append((("regionPageNum", index), _regular_tag(b"regionPageNum", mapped, mapped_width, (index,))))
        tags.append((("regionSize", index), _regular_tag(b"regionSize", pages, size_width, (index,))))
    return tags


def _meta_file(version, tag_blobs):
    return (
        HEADER.pack(MAGICS[version], 0, 1)
        + GROUP.pack(b"memory", TAG_LOCATION, 0)
        + b"".join(tag_blobs)
        + b"\x00\x00"
    )


def _region_bytes(index, pages):
    return bytes([0xA0 + index]) * (pages * PAGE_SIZE)


def _vmem_image():
    end = max(vmem + pages for _, vmem, pages in REGION_LAYOUT)
    image = bytearray(end * PAGE_SIZE)
    for index, (_, vmem, pages) in enumerate(REGION_LAYOUT):
        image[vmem * PAGE_SIZE : (vmem + pages) * PAGE_SIZE] = _region_bytes(index, pages)
    return bytes(image)


def _make_layer(meta, vmem):
    context = contexts.Context()
    context.layers.add_layer(
        physical.BufferDataLayer(context, "vmem_layer", "vmem_layer", vmem)
    )
    context.layers.add_layer(
        physical.BufferDataLayer(context, "meta_layer", "meta_layer", meta)
    )
    context.config["test_vmware.base_layer"] = "vmem_layer"
    context.config["test_vmware.meta_layer"] = "meta_layer"
    return vmware.VmwareLayer(context, "test_vmware", "test_vmware")


@pytest.mark.parametrize("version", [0, 1], ids=["version0-32bit", "version1-64bit"])
@pytest.mark.parametrize(
    "region_widths", [(4, 8, 4), (8, 4, 8)], ids=["widths-484", "widths-848"]
)
def test_tag_length_encodings(version, region_widths):
    """Both version widths and mixed regular tag widths map to the same regions."""
    tags = _tag_table(version, region_widths)
    layer = _make_layer(_meta_file(version, [blob for _, blob in tags]), _vmem_image())
    assert tuple(layer._segments) == EXPECTED_SEGMENTS
    for index, (ppn, _, pages) in enumerate(REGION_LAYOUT):
        assert layer.read(ppn * PAGE_SIZE, pages * PAGE_SIZE) == _region_bytes(
            index, pages
        )


def test_tag_order_independence():
    """Reordering well-formed tags must not change the resulting segments."""
    version = 1
    tags = [blob for _, blob in _tag_table(version)]
    reference = _make_layer(_meta_file(version, tags), _vmem_image())
    for reordered in (list(reversed(tags)), tags[3:] + tags[:3]):
        layer = _make_layer(_meta_file(version, reordered), _vmem_image())
        assert tuple(layer._segments) == tuple(reference._segments)
        assert tuple(layer._segments) == EXPECTED_SEGMENTS


def test_conflicting_duplicate_tag_fails():
    """A repeated tag with a different value fails at the duplicate's offset."""
    version = 1
    blobs = [blob for _, blob in _tag_table(version)]
    duplicate_offset = TAG_LOCATION + sum(len(blob) for blob in blobs)
    blobs.append(_regular_tag(b"regionSize", 0x70, 4, (1,)))
    with pytest.raises(vmware.VmwareFormatException) as excinfo:
        _make_layer(_meta_file(version, blobs), _vmem_image())
    assert "regionSize" in str(excinfo.value)
    assert hex(duplicate_offset) in str(excinfo.value)


def test_identical_duplicate_tag_tolerated():
    """A repeated tag with the same value does not change the mapping."""
    version = 1
    blobs = [blob for _, blob in _tag_table(version)]
    blobs.append(_regular_tag(b"regionSize", REGION_LAYOUT[1][2], 4, (1,)))
    layer = _make_layer(_meta_file(version, blobs), _vmem_image())
    assert tuple(layer._segments) == EXPECTED_SEGMENTS


@pytest.mark.parametrize("missing", ["regionPPN", "regionPageNum", "regionSize"])
def test_missing_region_entry_fails(missing):
    """A region missing any of its tags fails naming the tag and the region."""
    version = 0
    blobs = [
        blob
        for (name, index), blob in _tag_table(version)
        if not (name == missing and index == 2)
    ]
    with pytest.raises(vmware.VmwareFormatException) as excinfo:
        _make_layer(_meta_file(version, blobs), _vmem_image())
    assert missing in str(excinfo.value)
    assert "region 2" in str(excinfo.value)


def test_missing_regions_count_fails():
    version = 1
    blobs = [blob for (name, _), blob in _tag_table(version) if name != "regionsCount"]
    with pytest.raises(vmware.VmwareFormatException, match="regionsCount"):
        _make_layer(_meta_file(version, blobs), _vmem_image())


def test_extended_data_length_out_of_bounds():
    """An extended tag declaring more data than remains fails at its offset."""
    version = 1
    width = EXTENDED_WIDTHS[version]
    payload = (
        (0x1000).to_bytes(width, "little") + b"\x00" * width + b"\x00\x00" + b"\x11" * 0x10
    )
    tag = _tag_prefix(62, b"memInfo") + payload
    blobs = [tag] + [blob for _, blob in _tag_table(version)]
    with pytest.raises(vmware.VmwareFormatException) as excinfo:
        _make_layer(_meta_file(version, blobs), _vmem_image())
    assert "memInfo" in str(excinfo.value)
    assert hex(TAG_LOCATION) in str(excinfo.value)


def test_32bit_length_in_64bit_file_detected():
    """A version-1 file whose extended tag uses a 32-bit length is rejected."""
    version = 1
    data = b"\x01" + b"\x00" * 0x1F
    payload = len(data).to_bytes(4, "little") + data
    tag = _tag_prefix(62, b"memInfo") + payload
    blobs = [tag] + [blob for _, blob in _tag_table(version)]
    with pytest.raises(vmware.VmwareFormatException, match="memInfo"):
        _make_layer(_meta_file(version, blobs), _vmem_image())


def test_64bit_length_in_32bit_file_detected():
    """A version-0 file whose extended tag uses a 64-bit length is rejected."""
    version = 0
    data = b"\xAA" * 0x20 + b"\x00\x00" + b"\xBB" * 6
    payload = len(data).to_bytes(8, "little") + b"\x00" * 8 + b"\x00\x00" + data
    tag = _tag_prefix(62, b"memInfo") + payload
    blobs = [tag] + [blob for _, blob in _tag_table(version)]
    with pytest.raises(vmware.VmwareFormatException, match="regionsCount"):
        _make_layer(_meta_file(version, blobs), _vmem_image())
