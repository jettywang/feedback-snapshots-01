# -*- coding: utf-8 -*-

import io
import os
import sys
import struct

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pycdlib
import pycdlib.pycdlibexception

# Logical block size used by every image built here.
BLOCK = 2048
# Directory record fixed header: '<BBLLLL7sBBBHHB' is 33 bytes, then the
# file identifier, padded to an even total length.
DR_FMT = '<BBLLLL7sBBBHHB'
MULTI_EXTENT_FLAG = 1 << 7
DIRECTORY_FLAG = 1 << 1


def _swab32(value):
    return struct.unpack('>L', struct.pack('<L', value))[0]


def _swab16(value):
    return struct.unpack('>H', struct.pack('<H', value))[0]


def _make_dr(extent_location, data_length, flags, identifier, seqnum=1):
    # type: (int, int, int, bytes, int) -> bytes
    """Build a raw ISO9660 directory record with the given fields."""
    record = struct.pack(DR_FMT, 0, 0,
                         extent_location, _swab32(extent_location),
                         data_length, _swab32(data_length),
                         b'\x00' * 7, flags, 0, 0,
                         seqnum, _swab16(seqnum), len(identifier))
    record += identifier
    if len(record) % 2:
        record += b'\x00'
    # Fill in the record length now that the total size is known.
    return struct.pack('<B', len(record)) + record[1:]


def _base_iso_bytes():
    # type: () -> bytearray
    """
    Build a small, in-memory ISO with three one-block files BIG/OTHER/MORE.
    The byte-level tests rewrite its root directory extent (23) to arrange
    multi-extent chains without needing a multi-gigabyte source file.
    """
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=1)
    for name, fill in (('/BIG.TAR;1', b'A'), ('/OTHER.;1', b'B'),
                       ('/MORE.;1', b'C')):
        iso.add_fp(io.BytesIO(fill * BLOCK), BLOCK, iso_path=name)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return bytearray(out.getvalue())


def _iso_with_root_records(records):
    # type: (list) -> bytes
    """Return an ISO image whose root directory extent holds the given records."""
    blob = _base_iso_bytes()
    dot = _make_dr(23, BLOCK, DIRECTORY_FLAG, b'\x00')
    dotdot = _make_dr(23, BLOCK, DIRECTORY_FLAG, b'\x01')
    directory = dot + dotdot + b''.join(records)
    assert len(directory) <= BLOCK
    directory += b'\x00' * (BLOCK - len(directory))
    start = 23 * BLOCK
    blob[start:start + BLOCK] = directory
    return bytes(blob)


def _open(image):
    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(image))
    return iso


def _seg(extent, flags, identifier=b'BIG.TAR;1', length=BLOCK, seqnum=1):
    return _make_dr(extent, length, flags, identifier, seqnum=seqnum)


def _continuation(extent, **kwargs):
    return _seg(extent, MULTI_EXTENT_FLAG, **kwargs)


def _final(extent, **kwargs):
    return _seg(extent, 0, **kwargs)


# The base image places data at extents 24 (A), 25 (C), 26 (B).
SEG1_EXT = 24
SEG2_EXT = 26
SEG3_EXT = 25
OTHER_EXT = 26


def _marked_three_segment_records():
    # A marked three-segment chain: seg1 and seg2 carry the continuation flag,
    # seg3 clears it and ends the file.
    return [
        _continuation(SEG1_EXT),
        _continuation(SEG2_EXT),
        _final(SEG3_EXT),
        _seg(OTHER_EXT, 0, identifier=b'OTHER.;1'),
    ]


def _expected_three_segment_contents():
    return b'A' * BLOCK + b'B' * BLOCK + b'C' * BLOCK


def test_multiextent_marked_three_segments_full_extraction():
    # A valid marked three-segment chain is read back in record order, with
    # the unrelated OTHER file left alone after the chain terminates.
    image = _iso_with_root_records(_marked_three_segment_records())
    iso = _open(image)

    head = iso.pvd.root_dir_record.children[2]
    walked = []
    current = head
    while current is not None:
        walked.append((current.extent_location(), current.data_length,
                       current.file_flags))
        current = current.data_continuation
    assert walked == [
        (SEG1_EXT, BLOCK, MULTI_EXTENT_FLAG),
        (SEG2_EXT, BLOCK, MULTI_EXTENT_FLAG),
        (SEG3_EXT, BLOCK, 0),
    ]

    out = io.BytesIO()
    iso.get_file_from_iso_fp(out, iso_path='/BIG.TAR;1')
    assert out.getvalue() == _expected_three_segment_contents()
    iso.close()


def test_multiextent_streaming_matches_full_extraction():
    # Ordinary extraction and streaming must interpret the chain identically.
    image = _iso_with_root_records(_marked_three_segment_records())
    iso = _open(image)

    extracted = io.BytesIO()
    iso.get_file_from_iso_fp(extracted, iso_path='/BIG.TAR;1')

    with iso.open_file_from_iso(iso_path='/BIG.TAR;1') as stream:
        assert stream.length() == 3 * BLOCK
        assert stream.read() == extracted.getvalue()
    iso.close()


def test_multiextent_streaming_cross_segment_short_reads():
    # Reads smaller than a segment must cross segment boundaries seamlessly.
    image = _iso_with_root_records(_marked_three_segment_records())
    iso = _open(image)
    expected = _expected_three_segment_contents()

    with iso.open_file_from_iso(iso_path='/BIG.TAR;1') as stream:
        # Straddle the seg1 -> seg2 boundary.
        stream.seek(BLOCK - 8)
        assert stream.read(16) == b'A' * 8 + b'B' * 8
        # Straddle the seg2 -> seg3 boundary.
        stream.seek(2 * BLOCK - 6)
        assert stream.read(12) == b'B' * 6 + b'C' * 6
        # A read spanning all three segments in one call.
        stream.seek(BLOCK - 4)
        assert stream.read(BLOCK + 8) == b'A' * 4 + b'B' * BLOCK + b'C' * 4
        # Byte-by-byte walking reproduces the whole file.
        stream.seek(0)
        pieces = []
        while True:
            chunk = stream.read(37)
            if not chunk:
                break
            pieces.append(chunk)
        assert b''.join(pieces) == expected
    iso.close()


def test_multiextent_streaming_seek_backwards_and_end_relative():
    # Seeking backwards must re-enter an earlier segment; end-relative seeks
    # land in the final segment rather than past the data.
    image = _iso_with_root_records(_marked_three_segment_records())
    iso = _open(image)

    with iso.open_file_from_iso(iso_path='/BIG.TAR;1') as stream:
        stream.seek(2 * BLOCK + 10)
        assert stream.read(4) == b'C' * 4
        # Backwards seek all the way into segment 1.
        assert stream.seek(0) == 0
        assert stream.read(4) == b'A' * 4
        # Relative backwards seek across the seg2/seg3 boundary.
        stream.seek(2 * BLOCK)
        assert stream.seek(-10, 1) == 2 * BLOCK - 10
        assert stream.read(10) == b'B' * 10
        # End-relative seek lands inside the final segment.
        assert stream.seek(-8, 2) == 3 * BLOCK - 8
        assert stream.read(8) == b'C' * 8
    iso.close()


def test_multiextent_streaming_readinto_crosses_segments():
    image = _iso_with_root_records(_marked_three_segment_records())
    iso = _open(image)
    expected = _expected_three_segment_contents()

    with iso.open_file_from_iso(iso_path='/BIG.TAR;1') as stream:
        stream.seek(BLOCK - 8)
        buffer = bytearray(16)
        assert stream.readinto(buffer) == 16
        assert bytes(buffer) == b'A' * 8 + b'B' * 8
        # Drain the rest through readinto in odd-sized buffers.
        collected = [bytes(buffer)]
        while True:
            buffer = bytearray(101)
            count = stream.readinto(buffer)
            if count == 0:
                break
            collected.append(bytes(buffer[:count]))
        assert b''.join(collected) == expected[BLOCK - 8:]
    iso.close()


def test_multiextent_legal_zero_length_final_record():
    # A zero-length final record is legal: it ends the chain and contributes
    # no bytes, so the file content is exactly the two preceding segments.
    records = [
        _continuation(SEG1_EXT),
        _continuation(SEG2_EXT),
        _final(SEG3_EXT, length=0),
        _seg(OTHER_EXT, 0, identifier=b'OTHER.;1'),
    ]
    iso = _open(_iso_with_root_records(records))

    extracted = io.BytesIO()
    iso.get_file_from_iso_fp(extracted, iso_path='/BIG.TAR;1')
    expected = b'A' * BLOCK + b'B' * BLOCK
    assert extracted.getvalue() == expected

    with iso.open_file_from_iso(iso_path='/BIG.TAR;1') as stream:
        assert stream.length() == 2 * BLOCK
        assert stream.read() == expected
        assert stream.seek(0, 2) == 2 * BLOCK
    iso.close()


def test_multiextent_rejects_intervening_different_file():
    # The continuation chain is interrupted by a different file; the parser
    # must name the broken record instead of stitching the later BIG records
    # onto whatever comes next.
    records = [
        _continuation(SEG1_EXT),
        _seg(OTHER_EXT, 0, identifier=b'OTHER.;1'),
        _continuation(SEG2_EXT),
        _final(SEG3_EXT),
    ]
    iso = pycdlib.PyCdlib()
    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        iso.open_fp(io.BytesIO(_iso_with_root_records(records)))
    message = str(excinfo.value)
    assert 'BIG.TAR;1' in message
    assert 'OTHER.;1' in message
    assert 'broken' in message


def test_multiextent_rejects_conflicting_duplicate_name():
    # Two unrelated files with the same name (neither marked as a
    # continuation) cannot be silently concatenated.
    records = [
        _final(SEG1_EXT),
        _seg(OTHER_EXT, 0, identifier=b'OTHER.;1'),
        _final(SEG3_EXT),
    ]
    iso = pycdlib.PyCdlib()
    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        iso.open_fp(io.BytesIO(_iso_with_root_records(records)))
    message = str(excinfo.value)
    assert 'BIG.TAR;1' in message
    assert 'continuation' in message


def test_multiextent_rejects_missing_final_record():
    # The directory ends while the last record still carries the continuation
    # flag.  This is a truncated chain, distinct from a legal zero-length final
    # record, and must be rejected rather than zero-filled.
    records = [
        _continuation(SEG1_EXT),
        _continuation(SEG2_EXT),
    ]
    iso = pycdlib.PyCdlib()
    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        iso.open_fp(io.BytesIO(_iso_with_root_records(records)))
    message = str(excinfo.value)
    assert 'BIG.TAR;1' in message
    assert 'missing its final directory record' in message


def test_multiextent_rejects_zero_length_nonfinal_record():
    # A zero-length record in the middle of a chain cannot be a segment, since
    # only the final record is allowed to carry no data.
    records = [
        _continuation(SEG1_EXT),
        _continuation(SEG2_EXT, length=0),
        _final(SEG3_EXT),
    ]
    iso = pycdlib.PyCdlib()
    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        iso.open_fp(io.BytesIO(_iso_with_root_records(records)))
    assert 'zero data length' in str(excinfo.value)


def test_multiextent_rejects_sequence_number_mismatch():
    records = [
        _continuation(SEG1_EXT, seqnum=1),
        _continuation(SEG2_EXT, seqnum=2),
        _final(SEG3_EXT, seqnum=2),
    ]
    iso = pycdlib.PyCdlib()
    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        iso.open_fp(io.BytesIO(_iso_with_root_records(records)))
    message = str(excinfo.value)
    assert 'sequence numbers' in message
    assert '1 != 2' in message


def test_multiextent_rejects_continuation_followed_by_directory():
    records = [
        _continuation(SEG1_EXT),
        _seg(OTHER_EXT, DIRECTORY_FLAG, identifier=b'SUBDIR.;1'),
    ]
    iso = pycdlib.PyCdlib()
    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        iso.open_fp(io.BytesIO(_iso_with_root_records(records)))
    message = str(excinfo.value)
    assert 'BIG.TAR;1' in message
    assert 'directory' in message


def test_multiextent_rejects_truncated_final_extent():
    # The final directory record points its data past the end of the image.
    # The parser must refuse instead of shrinking the length and returning a
    # zero-filled tail, which would hide the missing data.
    records = [
        _continuation(SEG1_EXT),
        _continuation(SEG2_EXT),
        _final(999),
    ]
    iso = pycdlib.PyCdlib()
    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        iso.open_fp(io.BytesIO(_iso_with_root_records(records)))
    message = str(excinfo.value)
    assert 'BIG.TAR;1' in message
    assert 'extends past the end of the ISO' in message


def test_multiextent_ordinary_files_still_read_in_order():
    # The chain hardening must not disturb ordinary single-extent files, which
    # keep reading in their original on-disk order.
    image = _base_iso_bytes()
    iso = _open(image)
    for path, fill in (('/BIG.TAR;1', b'A'), ('/MORE.;1', b'C'),
                       ('/OTHER.;1', b'B')):
        out = io.BytesIO()
        iso.get_file_from_iso_fp(out, iso_path=path)
        assert out.getvalue() == fill * BLOCK
        with iso.open_file_from_iso(iso_path=path) as stream:
            assert stream.length() == BLOCK
            assert stream.read() == fill * BLOCK
    iso.close()


@pytest.mark.slow
def test_multiextent_streaming_mastered_shared_inode(tmpdir):
    # A file above the per-record 0xfffff800 limit is mastered as a single
    # shared Inode whose directory records carry data_extent_offset.  The
    # streaming reader must walk that chain the same way extraction does.
    sparse = os.path.join(str(tmpdir), 'sparse.bin')
    image_path = os.path.join(str(tmpdir), 'multi.iso')
    size = 0xfffff800 * 2 + BLOCK
    with open(sparse, 'wb') as outfp:
        outfp.truncate(size)

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    data_fp = open(sparse, 'rb')
    iso.add_fp(data_fp, size, iso_path='/BIG.TAR;1')
    iso.write(image_path)
    iso.close()
    data_fp.close()

    reopened = pycdlib.PyCdlib()
    reopened.open(image_path)

    head = reopened.pvd.root_dir_record.children[2]
    flags = []
    current = head
    while current is not None:
        flags.append(current.file_flags)
        current = current.data_continuation
    assert flags == [MULTI_EXTENT_FLAG, MULTI_EXTENT_FLAG, 0]

    with reopened.open_file_from_iso(iso_path='/BIG.TAR;1') as stream:
        assert stream.length() == size
        # Cross the first and second chunk boundaries with short reads.
        stream.seek(0xfffff800 - 4)
        assert len(stream.read(8)) == 8
        stream.seek(0xfffff800 * 2 - 4)
        assert len(stream.read(12)) == 12
        # A backwards seek into the first chunk still resolves to real data.
        stream.seek(0)
        assert stream.tell() == 0
        assert len(stream.read(16)) == 16
        # End-relative seek lands inside the one-block final chunk.
        assert stream.seek(-BLOCK, 2) == size - BLOCK
    reopened.close()


def _joliet_broken_chain_image():
    # Build a Joliet ISO and mark the first file's sole record as a
    # continuation while leaving the different-name second record next, so
    # the Joliet (SVD) walker hits the same broken-chain validation.
    iso = pycdlib.PyCdlib()
    iso.new(joliet=3)
    iso.add_fp(io.BytesIO(b'A' * BLOCK), BLOCK,
               iso_path='/BIG.;1', joliet_path='/big')
    iso.add_fp(io.BytesIO(b'B' * BLOCK), BLOCK,
               iso_path='/OTHER.;1', joliet_path='/other')
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()

    blob = bytearray(out.getvalue())
    # The Supplementary Volume Descriptor lives at sector 17; its root
    # directory record starts at offset 156, with the extent location at +2.
    svd = blob[17 * BLOCK:18 * BLOCK]
    joliet_root_extent = struct.unpack('<L', svd[156 + 2:156 + 6])[0]

    # Locate the first non-dot record (the '/big' entry) and set its file
    # flags byte (fixed-header offset 25) to the continuation flag.
    offset = joliet_root_extent * BLOCK + 2 * 34
    record_length = blob[offset]
    assert blob[offset + 33:offset + 35] == b'\x00b'
    blob[offset + 25] = MULTI_EXTENT_FLAG
    assert record_length > 0
    return bytes(blob)


def test_multiextent_joliet_broken_chain_rejected():
    iso = pycdlib.PyCdlib()
    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        iso.open_fp(io.BytesIO(_joliet_broken_chain_image()))
    message = str(excinfo.value)
    # The Joliet UCS-2 name is rendered readably (not as escaped bytes).
    assert 'big' in message
    assert 'other' in message
    assert 'broken' in message


def test_multiextent_chain_straddles_directory_block_boundary(tmpdir):
    # A multi-extent chain whose continuation record is the last directory
    # record in one directory block and whose final record is the first record
    # of the next block.  The parser's last-record state must survive the
    # zero padding between the blocks rather than treating the final record
    # as a new file.
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=1)
    for index in range(60):
        name = '/F%02d.;1' % index
        iso.add_fp(io.BytesIO(bytes([65 + index % 26]) * 16), 16, iso_path=name)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()

    blob = bytearray(out.getvalue())
    probe = pycdlib.PyCdlib()
    probe.open_fp(io.BytesIO(bytes(blob)))
    root = probe.pvd.root_dir_record
    root_extent = root.extent_location()
    locations = {
        child.file_identifier(): child.extent_location()
        for child in root.children
        if not child.is_dot() and not child.is_dotdot()
    }
    probe.close()

    # With 60 records the first directory block ends on F48 (dir offset 1988);
    # the continuation block begins directly with F49 at offset 0.  Rename
    # both to the same identifier and mark F48 as a continuation.
    f48_abs = root_extent * BLOCK + 1988
    f49_abs = (root_extent + 1) * BLOCK
    assert blob[f48_abs] == 40 and blob[f49_abs] == 40
    blob[f48_abs:f48_abs + 40] = _make_dr(locations[b'F48.;1'], 16,
                                          MULTI_EXTENT_FLAG, b'X48.;1')
    blob[f49_abs:f49_abs + 40] = _make_dr(locations[b'F49.;1'], 16, 0,
                                          b'X48.;1')

    reopened = pycdlib.PyCdlib()
    reopened.open_fp(io.BytesIO(bytes(blob)))

    extracted = io.BytesIO()
    reopened.get_file_from_iso_fp(extracted, iso_path='/X48.;1')
    expected = extracted.getvalue()
    assert len(expected) == 32

    with reopened.open_file_from_iso(iso_path='/X48.;1') as stream:
        assert stream.length() == 32
        assert stream.read() == expected
        # Seek to a position inside the first block, then read across the
        # directory-block boundary into the final segment.
        stream.seek(10)
        assert stream.read(12) == expected[10:22]
    reopened.close()
