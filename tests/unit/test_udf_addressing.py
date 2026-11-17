"""
Directed mutation tests for UDF file addressing.

Every test starts from a valid UDF image built in-process (no external
tools, deterministic contents, so the mutation samples are reproducible in
any normal process), locates the addressing structures by parsing, flips
exactly one addressing decision, fixes the descriptor tag CRC/checksum, and
then checks the outcome against an independent partition-to-byte model that
computes the expected bytes straight from the raw image.

The addressing structures under test are the ones that jointly decide where
file data comes from: the File Identifier ICB (which File Entry to use),
the ICB tag flags (which allocation descriptor layout is in use), the
partition reference number, the logical block number (position), and the
logical lengths (extent_length / info_len).

Currently supported layouts: short ADs, long ADs (partition 0 only), and
inline data.  Extended ADs (flags type 2) and non-zero partition references
are not supported and must be rejected explicitly; in particular a non-zero
partition reference must never silently fall back to partition 0.
"""

import io
import os
import struct
import sys

import pytest

prefix = '.'
for i in range(0, 3):
    if os.path.isdir(os.path.join(prefix, 'pycdlib')):
        sys.path.insert(0, prefix)
        break
    else:
        prefix = '../' + prefix

import pycdlib
import pycdlib.pycdlibexception
import pycdlib.udf

LOGICAL_BLOCK_SIZE = 2048

# Byte offsets within a UDF File Entry (ECMA-167 4/14.9); the fixed header
# is 176 bytes, after which the allocation descriptors start.
FE_HEADER_SIZE = struct.calcsize(pycdlib.udf.UDFFileEntry.FMT)
FE_ICB_FLAGS_OFFSET = 16 + 18  # desc tag, then flags at the end of the ICB tag
FE_INFO_LEN_OFFSET = 56
FE_LEN_ALLOC_DESCS_OFFSET = 172

# Byte offsets within a UDF Descriptor Tag (ECMA-167 3/7.2).
TAG_CHECKSUM_OFFSET = 4
TAG_DESC_CRC_OFFSET = 8
TAG_DESC_CRC_LENGTH_OFFSET = 10

# Byte offsets within a UDF File Identifier Descriptor (ECMA-167 4/14.4).
FID_HEADER_SIZE = struct.calcsize(pycdlib.udf.UDFFileIdentifierDescriptor.FMT)
FID_LEN_FI_OFFSET = 19
FID_ICB_OFFSET = 20
FID_LEN_IMPL_USE_OFFSET = 36

# Byte offsets within a UDF File Set Descriptor (ECMA-167 4/14.1) and within
# a long_ad (ECMA-167 4/14.14.2).
FSD_ROOT_DIR_ICB_OFFSET = struct.calcsize('<16s12sHHLLLL64s128s64s32s32s32s')
LONG_AD_LOG_BLOCK_NUM_OFFSET = 4
LONG_AD_PART_REF_OFFSET = 8


def _content(seed, length):
    # type: (int, int) -> bytes
    """Deterministic, position-dependent file contents."""
    return bytes(((i * 31 + seed) & 0xFF) for i in range(length))


def _build_image(entries):
    # type: (list) -> bytearray
    """Build a valid UDF image in-process; entries are (path, content) with
    a content of None meaning a directory."""
    iso = pycdlib.PyCdlib()
    iso.new(udf='2.60')
    for path, content in entries:
        if content is None:
            iso.add_directory(udf_path=path)
        else:
            iso.add_fp(io.BytesIO(content), len(content), udf_path=path)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return bytearray(out.getvalue())


def _open(image):
    # type: (bytearray) -> pycdlib.PyCdlib
    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(bytes(image)))
    return iso


def _locate(image, udf_path):
    # type: (bytearray, str) -> tuple
    """Parse a valid image and return (part_start, file_entry_extent,
    info_len, alloc_descs) for the file at udf_path, where alloc_descs is a
    list of (kind, extent_length, log_block_num, offset) tuples."""
    iso = _open(image)
    part_start = iso.udf_main_descs.partitions[0].part_start_location
    entry = iso.udf_root
    for comp in udf_path.strip('/').split('/'):
        entry = entry.fi_descs[os.fsencode(comp)].file_entry
    descs = []
    for desc in entry.alloc_descs:
        if isinstance(desc, pycdlib.udf.UDFInlineAD):
            kind = 'inline'
        elif isinstance(desc, pycdlib.udf.UDFLongAD):
            kind = 'long'
        else:
            kind = 'short'
        descs.append((kind, desc.extent_length, desc.log_block_num, desc.offset))
    result = (part_start, entry.orig_extent_loc, entry.info_len, descs)
    iso.close()
    return result


def _root_dir_data(image):
    # type: (bytearray) -> tuple
    """Return (absolute_extent, length) of the root directory data."""
    iso = _open(image)
    part_start = iso.udf_main_descs.partitions[0].part_start_location
    desc = iso.udf_root.alloc_descs[0]
    result = (part_start + desc.log_block_num, desc.extent_length)
    iso.close()
    return result


def _retag_at(image, off):
    # type: (bytearray, int) -> None
    """Recompute the descriptor tag CRC and checksum in place after a
    mutation, so the descriptor stays well-formed."""
    crc_length = struct.unpack_from('<H', image, off + TAG_DESC_CRC_LENGTH_OFFSET)[0]
    crc = pycdlib.udf.crc_ccitt(bytes(image[off + 16:off + 16 + crc_length]))
    struct.pack_into('<H', image, off + TAG_DESC_CRC_OFFSET, crc)
    image[off + TAG_CHECKSUM_OFFSET] = 0
    image[off + TAG_CHECKSUM_OFFSET] = pycdlib.udf._compute_csum(bytes(image[off:off + 16]))


def _retag(image, extent):
    # type: (bytearray, int) -> None
    """Recompute the tag of a descriptor that starts at an extent boundary."""
    _retag_at(image, extent * LOGICAL_BLOCK_SIZE)


def _model_read(image, part_start, descs, info_len):
    # type: (bytearray, int, list, int) -> bytes
    """The independent partition-to-byte model: turn (partition start,
    allocation descriptors, logical length) into the expected file bytes by
    reading them straight out of the raw image."""
    out = bytearray()
    for kind, extent_length, log_block_num, offset in descs:
        if kind == 'inline':
            abs_extent = log_block_num  # already absolute for inline data
        else:
            abs_extent = part_start + log_block_num
        start = abs_extent * LOGICAL_BLOCK_SIZE + offset
        out += image[start:start + extent_length]
    return bytes(out[:info_len])


def _extract(image, udf_path):
    # type: (bytearray, str) -> bytes
    iso = _open(image)
    out = io.BytesIO()
    iso.get_file_from_iso_fp(out, udf_path=udf_path)
    iso.close()
    return out.getvalue()


def _find_file_ident(image, dir_abs_extent, dir_length, name):
    # type: (bytearray, int, int, bytes) -> int
    """Walk the File Identifier Descriptors of a directory in the raw image
    and return the byte offset of the one named `name`."""
    off = dir_abs_extent * LOGICAL_BLOCK_SIZE
    end = off + dir_length
    while off < end:
        len_fi = image[off + FID_LEN_FI_OFFSET]
        len_impl_use = struct.unpack_from('<H', image, off + FID_LEN_IMPL_USE_OFFSET)[0]
        fi_start = off + FID_HEADER_SIZE + len_impl_use
        fi = bytes(image[fi_start:fi_start + len_fi])
        if len_fi > 0 and fi[1:] == name:
            return off
        size = FID_HEADER_SIZE + len_impl_use + len_fi
        off += size + (4 - size % 4) % 4
    raise AssertionError('File Identifier %r not found' % (name,))


def _mutate_short_ad_to_long_ad(image, fe_extent, extent_length, log_block_num, part_ref_num):
    # type: (bytearray, int, int, int, int) -> None
    """Rewrite a File Entry that uses one short AD so it uses one long AD
    covering the same extent."""
    off = fe_extent * LOGICAL_BLOCK_SIZE
    flags = struct.unpack_from('<H', image, off + FE_ICB_FLAGS_OFFSET)[0]
    struct.pack_into('<H', image, off + FE_ICB_FLAGS_OFFSET, (flags & ~0x7) | 1)
    struct.pack_into('<L', image, off + FE_LEN_ALLOC_DESCS_OFFSET, 16)
    struct.pack_into('<LLH6s', image, off + FE_HEADER_SIZE,
                     extent_length, log_block_num, part_ref_num, b'\x00' * 6)
    # The descriptor CRC covers the fixed header plus the allocation
    # descriptors, and the long AD is 8 bytes longer than the short AD.
    struct.pack_into('<H', image, off + TAG_DESC_CRC_LENGTH_OFFSET,
                     FE_HEADER_SIZE - 16 + 16)
    _retag(image, fe_extent)


# Baseline: short ADs, recorded extents

def test_short_ad_baseline_full_extraction_and_cross_extent_slices():
    content = _content(7, 5000)
    image = _build_image([('/foo', content)])
    part_start, fe_extent, info_len, descs = _locate(image, '/foo')
    assert [d[0] for d in descs] == ['short']

    model = _model_read(image, part_start, descs, info_len)
    assert model == content

    # Full extraction matches the partition-to-byte model exactly.
    got = _extract(image, '/foo')
    assert got == model

    # Slices that cross 2048-byte extent boundaries also match the model.
    for start in (0, 2040, 2048, 4090):
        assert got[start:start + 20] == \
            _model_read(image, part_start, [(descs[0][0], 20, descs[0][2], start)], 20)


def test_short_ad_recorded_extent_type_is_zero():
    image = _build_image([('/foo', _content(7, 100))])
    iso = _open(image)
    desc = iso.udf_root.fi_descs[b'foo'].file_entry.alloc_descs[0]
    assert desc.extent_type == 0
    iso.close()


# Recorded vs. unrecorded extents

def test_short_ad_parse_unrecorded_extent_type_preserved():
    ad = pycdlib.udf.UDFShortAD()
    ad.parse(struct.pack('<LL', 100 | (1 << 30), 5))
    assert ad.extent_type == 1
    assert ad.extent_length == 100
    # The type bits survive a parse/record round-trip.
    assert ad.record() == struct.pack('<LL', 100 | (1 << 30), 5)


def test_short_ad_unrecorded_extent_on_media():
    content = _content(11, 100)
    image = _build_image([('/foo', content)])
    part_start, fe_extent, info_len, descs = _locate(image, '/foo')

    # Flip the extent type bits to 1 (allocated but not recorded).
    off = fe_extent * LOGICAL_BLOCK_SIZE + FE_HEADER_SIZE
    struct.pack_into('<L', image, off, 100 | (1 << 30))
    _retag(image, fe_extent)

    iso = _open(image)
    desc = iso.udf_root.fi_descs[b'foo'].file_entry.alloc_descs[0]
    assert desc.extent_type == 1
    assert desc.extent_length == 100
    iso.close()

    # The type bits do not change where the data comes from.
    assert _extract(image, '/foo') == _model_read(image, part_start, descs, info_len)


# Long ADs and the partition reference

def test_long_ad_layout_partition_zero():
    content = _content(13, 100)
    image = _build_image([('/foo', content)])
    part_start, fe_extent, info_len, descs = _locate(image, '/foo')
    log_block_num = descs[0][2]

    _mutate_short_ad_to_long_ad(image, fe_extent, 100, log_block_num, 0)

    new_descs = _locate(image, '/foo')[3]
    assert [d[0] for d in new_descs] == ['long']
    assert _extract(image, '/foo') == _model_read(image, part_start, new_descs, info_len)
    assert _extract(image, '/foo') == content


def test_long_ad_other_partition_rejected_and_decoy_not_returned():
    content = _content(17, 100)
    image = _build_image([('/foo', content)])
    part_start, fe_extent, info_len, descs = _locate(image, '/foo')
    log_block_num = descs[0][2]

    # Place decoy bytes where an implementation that silently falls back to
    # partition 0 would read them from.
    decoy = b'D' * 100
    start = (part_start + log_block_num) * LOGICAL_BLOCK_SIZE
    image[start:start + 100] = decoy

    _mutate_short_ad_to_long_ad(image, fe_extent, 100, log_block_num, 1)

    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open(image)
    assert str(excinfo.value) == ('UDF file allocation descriptor references '
                                  'partition 1, but only partition 0 is supported')


def test_file_ident_icb_other_partition_rejected():
    content = _content(19, 100)
    image = _build_image([('/foo', content)])
    dir_extent, dir_length = _root_dir_data(image)
    fid_off = _find_file_ident(image, dir_extent, dir_length, b'foo')

    struct.pack_into('<H', image, fid_off + FID_ICB_OFFSET + LONG_AD_PART_REF_OFFSET, 1)
    _retag_at(image, fid_off)

    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open(image)
    assert str(excinfo.value) == ('UDF File Identifier ICB references '
                                  'partition 1, but only partition 0 is supported')


def test_root_dir_icb_other_partition_rejected():
    content = _content(23, 100)
    image = _build_image([('/foo', content)])
    part_start = _locate(image, '/foo')[0]

    off = part_start * LOGICAL_BLOCK_SIZE + FSD_ROOT_DIR_ICB_OFFSET
    struct.pack_into('<H', image, off + LONG_AD_PART_REF_OFFSET, 1)
    _retag(image, part_start)

    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open(image)
    assert str(excinfo.value) == ('File Set Descriptor root directory ICB references '
                                  'partition 1, but only partition 0 is supported')


# Inline data

def test_inline_layout_file_data():
    content = _content(29, 100)
    image = _build_image([('/foo', content)])
    part_start, fe_extent, info_len, descs = _locate(image, '/foo')

    # Move the data inside the File Entry and switch to the inline layout.
    off = fe_extent * LOGICAL_BLOCK_SIZE
    flags = struct.unpack_from('<H', image, off + FE_ICB_FLAGS_OFFSET)[0]
    struct.pack_into('<H', image, off + FE_ICB_FLAGS_OFFSET, (flags & ~0x7) | 3)
    struct.pack_into('<L', image, off + FE_LEN_ALLOC_DESCS_OFFSET, len(content))
    image[off + FE_HEADER_SIZE:off + FE_HEADER_SIZE + len(content)] = content
    struct.pack_into('<H', image, off + TAG_DESC_CRC_LENGTH_OFFSET,
                     FE_HEADER_SIZE - 16 + len(content))
    _retag(image, fe_extent)

    new_descs = _locate(image, '/foo')[3]
    assert [d[0] for d in new_descs] == ['inline']
    # The model finds the data inside the File Entry itself: the inline
    # logical block number is already an absolute extent.
    assert new_descs[0][2] == fe_extent
    assert new_descs[0][3] == FE_HEADER_SIZE
    assert _extract(image, '/foo') == _model_read(image, part_start, new_descs, info_len)
    assert _extract(image, '/foo') == content


def test_inline_layout_directory_data():
    content = _content(31, 10)
    image = _build_image([('/dir1', None), ('/dir1/foo', content)])
    part_start, fe_extent, info_len, descs = _locate(image, '/dir1')
    dir_data_abs = part_start + descs[0][2]
    dir_data_len = descs[0][1]

    # Move the directory data inside the directory's File Entry.
    off = fe_extent * LOGICAL_BLOCK_SIZE
    dirdata = bytes(image[dir_data_abs * LOGICAL_BLOCK_SIZE:
                        dir_data_abs * LOGICAL_BLOCK_SIZE + dir_data_len])
    flags = struct.unpack_from('<H', image, off + FE_ICB_FLAGS_OFFSET)[0]
    struct.pack_into('<H', image, off + FE_ICB_FLAGS_OFFSET, (flags & ~0x7) | 3)
    struct.pack_into('<L', image, off + FE_LEN_ALLOC_DESCS_OFFSET, dir_data_len)
    image[off + FE_HEADER_SIZE:off + FE_HEADER_SIZE + dir_data_len] = dirdata
    struct.pack_into('<H', image, off + TAG_DESC_CRC_LENGTH_OFFSET,
                     FE_HEADER_SIZE - 16 + dir_data_len)
    _retag(image, fe_extent)

    iso = _open(image)
    assert b'foo' in iso.udf_root.fi_descs[b'dir1'].file_entry.fi_descs
    iso.close()
    assert _extract(image, '/dir1/foo') == content


# Unsupported layouts must be stated explicitly

def test_extended_ad_layout_explicitly_unsupported():
    content = _content(37, 100)
    image = _build_image([('/foo', content)])
    part_start, fe_extent, info_len, descs = _locate(image, '/foo')

    off = fe_extent * LOGICAL_BLOCK_SIZE
    flags = struct.unpack_from('<H', image, off + FE_ICB_FLAGS_OFFSET)[0]
    struct.pack_into('<H', image, off + FE_ICB_FLAGS_OFFSET, (flags & ~0x7) | 2)
    _retag(image, fe_extent)

    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInternalError) as excinfo:
        _open(image)
    assert str(excinfo.value) == 'UDF Allocation Descriptor of type 2 (Extended) not yet supported'


# Mutating the ICB, the position, and the logical length

def test_icb_relocation_changes_data_source():
    content_foo = _content(41, 100)
    content_bar = _content(43, 100)
    image = _build_image([('/foo', content_foo), ('/bar', content_bar)])
    part_start, bar_fe_extent, bar_info_len, bar_descs = _locate(image, '/bar')
    dir_extent, dir_length = _root_dir_data(image)

    # Point /foo's File Identifier ICB at /bar's File Entry.
    fid_off = _find_file_ident(image, dir_extent, dir_length, b'foo')
    struct.pack_into('<L', image, fid_off + FID_ICB_OFFSET + LONG_AD_LOG_BLOCK_NUM_OFFSET,
                     bar_fe_extent - part_start)
    _retag_at(image, fid_off)

    assert _extract(image, '/foo') == content_bar
    assert _extract(image, '/bar') == content_bar


def test_position_mutation_follows_alloc_desc():
    content_foo = _content(47, 100)
    content_bar = _content(53, 100)
    image = _build_image([('/foo', content_foo), ('/bar', content_bar)])
    part_start, fe_extent, info_len, descs = _locate(image, '/foo')
    bar_lbn = _locate(image, '/bar')[3][0][2]

    # /foo's original data stays in place as a decoy; the allocation
    # descriptor now points at /bar's extent.
    off = fe_extent * LOGICAL_BLOCK_SIZE + FE_HEADER_SIZE + 4
    struct.pack_into('<L', image, off, bar_lbn)
    _retag(image, fe_extent)

    got = _extract(image, '/foo')
    assert got == content_bar
    assert got != content_foo


def test_multi_extent_allocation_cross_extent_slices():
    content = _content(59, 5000)
    image = _build_image([('/foo', content)])
    part_start, fe_extent, info_len, descs = _locate(image, '/foo')
    log_block_num = descs[0][2]

    # Split the single 5000-byte short AD into two adjacent short ADs.
    off = fe_extent * LOGICAL_BLOCK_SIZE
    struct.pack_into('<L', image, off + FE_LEN_ALLOC_DESCS_OFFSET, 16)
    struct.pack_into('<LL', image, off + FE_HEADER_SIZE, 2048, log_block_num)
    struct.pack_into('<LL', image, off + FE_HEADER_SIZE + 8, 5000 - 2048, log_block_num + 1)
    struct.pack_into('<H', image, off + TAG_DESC_CRC_LENGTH_OFFSET,
                     FE_HEADER_SIZE - 16 + 16)
    _retag(image, fe_extent)

    new_descs = _locate(image, '/foo')[3]
    assert [d[0] for d in new_descs] == ['short', 'short']

    # The model concatenates the per-descriptor slices across the extent
    # boundary, and full extraction matches it.
    model = _model_read(image, part_start, new_descs, info_len)
    assert model == content
    assert _extract(image, '/foo') == model
    got = _extract(image, '/foo')
    assert got[2040:2060] == model[2040:2060]


def test_truncated_length_empty_range_and_wrong_partition_are_distinct():
    content = _content(61, 5000)
    image = _build_image([('/foo', content), ('/empty', b'')])
    part_start, fe_extent, info_len, descs = _locate(image, '/foo')

    # Legal empty range: a zero-length file extracts as zero bytes.
    empty = _extract(image, '/empty')
    assert empty == b''

    # Truncated logical length: only the prefix comes back.
    truncated_image = bytearray(image)
    off = fe_extent * LOGICAL_BLOCK_SIZE
    struct.pack_into('<Q', truncated_image, off + FE_INFO_LEN_OFFSET, 2000)
    _retag(truncated_image, fe_extent)
    truncated = _extract(truncated_image, '/foo')
    assert truncated == content[:2000]

    # Wrong partition: an explicit error, not data.
    wrong_part_image = bytearray(image)
    _mutate_short_ad_to_long_ad(wrong_part_image, fe_extent, 5000, descs[0][2], 1)
    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO):
        _open(wrong_part_image)

    # The three outcomes are all different from each other and from the
    # full data.
    assert truncated != empty
    assert truncated != content
    assert empty != content
