# -*- coding: utf-8 -*-
"""
Tests for hardening the Rock Ridge Continuation Entry (CE) chain and the
CL/PL/RE relocated-directory links against malformed images.

Every fixture here is built with pycdlib itself and then perturbed at the byte
level, so the tests need no external ISO authoring tool.  Each malformed image
must fail with a bounded, descriptive PyCdlibInvalidISO error (never an
uncaught KeyError or an unbounded loop), while the healthy parts of the same
image -- normal paths, file contents, and an untouched neighboring directory --
remain fully inspectable.
"""

import io
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pycdlib
from pycdlib import pycdlibexception
from pycdlib import rockridge
from pycdlib.pycdlib import _find_dr_record_by_name

LBS = 2048


def _ce_record_bytes(block, offset, length):
    """Serialize a CE record pointing at an arbitrary media-byte range."""
    ce = rockridge.RRCERecord()
    ce.new()
    ce.update_extent(block)
    ce.update_offset(offset)
    ce.update_len(length)
    return ce.record()


def _cl_record_bytes(extent):
    cl = rockridge.RRCLRecord()
    cl.new()
    cl.set_log_block_num(extent)
    return cl.record()


def _pl_record_bytes(extent):
    pl = rockridge.RRPLRecord()
    pl.new()
    pl.set_log_block_num(extent)
    return pl.record()


def _find_susp(data, signature, su_len):
    """Return absolute offsets of well-formed SUSP records with this signature."""
    return [i for i in range(len(data) - su_len)
            if data[i:i + 2] == signature and data[i + 2] == su_len and data[i + 3] == 1]


def _ce_fields(data, offset):
    block, _block_be, area_off, _off_be, length, _len_be = \
        struct.unpack_from('<LLLLLL', data, offset + 4)
    return block, area_off, length


def _open_fp(data):
    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(bytes(data)))
    return iso


def _shared_ce_image():
    """
    Build an image whose two long Rock Ridge names spill into two distinct,
    adjacent continuation areas inside one shared CE block (block 24).
    """
    iso = pycdlib.PyCdlib()
    iso.new(rock_ridge='1.09')
    iso.add_fp(io.BytesIO(b'a'), 1, iso_path='/A.;1', rr_name='a' * 200)
    iso.add_fp(io.BytesIO(b'b'), 1, iso_path='/B.;1', rr_name='b' * 200)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return bytearray(out.getvalue())


def _chained_ce_image():
    """Build an image whose single symlink spans several chained CE areas."""
    target = '/'.join(['c' * 200] * 20)
    iso = pycdlib.PyCdlib()
    iso.new(rock_ridge='1.09')
    iso.add_symlink('/LINK.;1', 'link', target)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return bytearray(out.getvalue()), target


def _deep_relocation_image():
    """
    Build an image deep enough to force a relocated directory (CL/PL/RE plus
    /rr_moved), with a real file at the leaf and an untouched neighbor tree.
    """
    iso = pycdlib.PyCdlib()
    iso.new(rock_ridge='1.12')
    parts = []
    for i in range(10):
        parts.append('dir%d' % i)
        iso.add_directory(iso_path='/' + '/'.join(p.upper() for p in parts),
                          rr_name=parts[-1])
    leaf = '/' + '/'.join(parts)
    iso.add_fp(io.BytesIO(b'hello\n'), len(b'hello\n'),
               iso_path='/' + '/'.join(p.upper() for p in parts) + '/FILE.TXT;1',
               rr_name='file.txt')
    iso.add_directory(iso_path='/NEIGHBOR', rr_name='neighbor')
    iso.add_fp(io.BytesIO(b'nb\n'), len(b'nb\n'),
               iso_path='/NEIGHBOR/NB.TXT;1', rr_name='nb.txt')
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return bytearray(out.getvalue()), leaf


def test_shared_continuation_areas_still_parse():
    # Two records sharing one CE block must not be mistaken for a loop: the
    # loop-detection set is local to each record's own chain, and identical
    # ranges registered by distinct records are accepted by the block tracker.
    data = _shared_ce_image()
    iso = _open_fp(data)
    first = iso.get_record(rr_path='/' + 'a' * 200)
    second = iso.get_record(rr_path='/' + 'b' * 200)
    assert first.rock_ridge.name() == b'a' * 200
    assert second.rock_ridge.name() == b'b' * 200
    first_area = first.rock_ridge.ce_areas[0]
    second_area = second.rock_ridge.ce_areas[0]
    assert first_area.extent_location() == second_area.extent_location()
    assert first_area.offset != second_area.offset
    iso.close()


def test_chained_continuation_round_trip_content():
    data, target = _chained_ce_image()
    iso = _open_fp(data)
    rec = iso.get_record(rr_path='/link')
    assert len(rec.rock_ridge.ce_areas) > 1
    assert rec.rock_ridge.symlink_path() == target.encode('utf-8')
    iso.close()


def test_ce_pointing_past_end_of_iso_is_rejected():
    data = _shared_ce_image()
    ce_off = _find_susp(data, b'CE', rockridge.RRCERecord.length())[0]
    data[ce_off:ce_off + 28] = _ce_record_bytes(999999, 0, 89)
    with pytest.raises(pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open_fp(data)
    assert 'extends past the end of the ISO' in str(excinfo.value)


def test_ce_spilling_past_its_block_is_rejected():
    data = _shared_ce_image()
    ce_off = _find_susp(data, b'CE', rockridge.RRCERecord.length())[0]
    data[ce_off:ce_off + 28] = _ce_record_bytes(24, 2000, 89)
    with pytest.raises(pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open_fp(data)
    assert 'does not fit inside a' in str(excinfo.value)


def test_ce_zero_length_is_rejected():
    data = _shared_ce_image()
    ce_off = _find_susp(data, b'CE', rockridge.RRCERecord.length())[0]
    data[ce_off:ce_off + 28] = _ce_record_bytes(24, 0, 0)
    with pytest.raises(pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open_fp(data)
    assert 'invalid length 0' in str(excinfo.value)


def test_ce_huge_length_is_rejected_without_large_allocation():
    # A 4GB-declared area must be rejected against the 2048-byte block geometry
    # before any buffer of that size is ever allocated.
    import tracemalloc

    data = _shared_ce_image()
    ce_off = _find_susp(data, b'CE', rockridge.RRCERecord.length())[0]
    data[ce_off:ce_off + 28] = _ce_record_bytes(24, 0, 0xFFFFFFFF)

    tracemalloc.start()
    try:
        with pytest.raises(pycdlibexception.PyCdlibInvalidISO) as excinfo:
            _open_fp(data)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert 'does not fit inside a' in str(excinfo.value)
    assert peak < 64 * 1024 * 1024


def test_ce_loop_with_varying_declared_length_is_rejected():
    # The old guard keyed on the full (block, offset, length) tuple, so a loop
    # that returned to the same location with a different length spun forever.
    # Pointing the first area's linking CE back at its own (block, offset) with
    # a bogus length must still be detected.
    data, _target = _chained_ce_image()
    link = 24 * LBS + LBS - rockridge.RRCERecord.length()
    assert link in _find_susp(data, b'CE', rockridge.RRCERecord.length())
    data[link:link + 28] = _ce_record_bytes(24, 0, 500)
    with pytest.raises(pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open_fp(data)
    assert 'form a loop at block 24 offset 0' in str(excinfo.value)


def test_overlapping_continuation_areas_are_rejected():
    # A second record whose CE claims bytes already owned by another record
    # must not swallow the neighbor's continuation into its own name.
    data = _shared_ce_image()
    target = None
    for off in _find_susp(data, b'CE', rockridge.RRCERecord.length()):
        if _ce_fields(data, off) == (24, 89, 89):
            target = off
            break
    assert target is not None
    data[target:target + 28] = _ce_record_bytes(24, 40, 89)
    with pytest.raises(pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open_fp(data)
    assert 'Overlapping CE regions on the ISO' in str(excinfo.value)


def test_deep_relocation_walks_and_keeps_content():
    data, leaf = _deep_relocation_image()
    iso = _open_fp(data)
    seen = [d for d, _dl, _fl in iso.walk(rr_path='/')]
    assert seen[0] == '/'
    assert leaf in seen
    leaf_file = iso.get_record(rr_path=leaf + '/file.txt')
    with iso.open_file_from_iso(rr_path=leaf + '/file.txt') as infp:
        assert infp.read() == b'hello\n'
    assert leaf_file.get_data_length() == len(b'hello\n')
    # The neighbor directory and its contents are intact.
    with iso.open_file_from_iso(rr_path='/neighbor/nb.txt') as infp:
        assert infp.read() == b'nb\n'
    iso.close()


def test_dangling_child_link_is_rejected_not_keyerror():
    data, _leaf = _deep_relocation_image()
    cl_off = _find_susp(data, b'CL', rockridge.RRCLRecord.length())[0]
    data[cl_off:cl_off + 12] = _cl_record_bytes(999999)
    with pytest.raises(pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open_fp(data)
    assert 'Child Link points at non-directory extent 999999' in str(excinfo.value)


def test_child_link_pointing_at_a_file_is_rejected():
    good, leaf = _deep_relocation_image()
    iso = _open_fp(good)
    file_extent = iso.get_record(rr_path=leaf + '/file.txt').extent_location()
    iso.close()

    data = bytearray(good)
    cl_off = _find_susp(data, b'CL', rockridge.RRCLRecord.length())[0]
    data[cl_off:cl_off + 12] = _cl_record_bytes(file_extent)
    with pytest.raises(pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open_fp(data)
    assert 'Child Link points at non-directory extent' in str(excinfo.value)


def test_parent_link_loop_is_bounded_during_path_build():
    good, _leaf = _deep_relocation_image()
    iso = _open_fp(good)
    moved = iso.get_record(iso_path='/RR_MOVED')
    relocated_extent = [c.extent_location() for c in moved.children
                        if not c.is_dot() and not c.is_dotdot()][0]
    iso.close()

    data = bytearray(good)
    pl_off = _find_susp(data, b'PL', rockridge.RRPLRecord.length())[0]
    data[pl_off:pl_off + 12] = _pl_record_bytes(relocated_extent)

    iso = _open_fp(data)
    moved = iso.get_record(iso_path='/RR_MOVED')
    target = [c for c in moved.children if not c.is_dot() and not c.is_dotdot()][0]
    # The corrupt branch stops with a clear reason instead of looping, while
    # the healthy neighbor directory is still reachable.
    with pytest.raises(pycdlibexception.PyCdlibInvalidISO) as excinfo:
        iso.full_path_from_dirrecord(target, rockridge=True)
    assert 'Parent Link records form a loop' in str(excinfo.value)
    with pytest.raises(pycdlibexception.PyCdlibInvalidISO):
        for _ in iso.walk(rr_path='/'):
            pass
    with iso.open_file_from_iso(rr_path='/neighbor/nb.txt') as infp:
        assert infp.read() == b'nb\n'
    iso.close()


def test_child_link_lookup_cycle_is_bounded():
    # A relocated lookup follows at most one CL per path component.  A corrupt
    # link graph that points a placeholder back at itself must therefore
    # terminate with a bounded error rather than spin: either the repeated
    # target guard fires, or name resolution fails cleanly on the next
    # component.  The point being guaranteed is that the call always returns.
    good, _leaf = _deep_relocation_image()
    iso = _open_fp(good)

    def _holders(record, acc):
        for child in record.children:
            if child.rock_ridge is not None and child.rock_ridge.child_link_record_exists():
                acc.append(child)
            if child.is_dir():
                _holders(child, acc)
        return acc

    holder = _holders(iso.pvd.root_directory_record(), [])[0]
    holder.rock_ridge.cl_to_moved_dr = holder

    path = b'/dir0/dir1/dir2/dir3/dir4/dir5/dir6/dir7'
    with pytest.raises(pycdlibexception.PyCdlibException):
        _find_dr_record_by_name(iso.pvd, path, 'utf-8')
    iso.close()
