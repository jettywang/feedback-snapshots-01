# -*- coding: utf-8 -*-
"""
Tests for the read-only namespace difference report (pycdlib.namespacediff).

The fixture ISO is deliberately tiny but exercises every distinction the
report exists to surface:
  * one logical file hard-linked across ISO9660, Joliet, Rock Ridge and UDF;
  * an extra in-namespace hard link to the same allocation;
  * a display path whose names resolve to independent, byte-identical copies;
  * a display path whose names resolve to independent, different payloads;
  * a name present in some namespaces but absent from others.
"""

import io
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
# tests/ so `from test_common import *` resolves.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pycdlib
from pycdlib import namespacediff

from test_common import *  # noqa: F401,F403


SHARED_BYTES = b'shared payload\n'
DUP_BYTES = b'identical copy\n'


def build_hybrid_iso(path):
    """Build the small RR + Joliet + UDF hybrid medium used by these tests."""
    iso = pycdlib.PyCdlib()
    iso.new(joliet=3, rock_ridge='1.12', udf='2.60')

    # One allocation linked from every namespace: all four views are hard
    # links to a single inode.
    iso.add_fp(io.BytesIO(SHARED_BYTES), len(SHARED_BYTES),
               iso_path='/SHARED.;1', rr_name='shared',
               joliet_path='/shared', udf_path='/shared')

    # A second ISO9660/Rock Ridge name for the same inode (an in-namespace
    # hard link).  Joliet and UDF do not get this name.
    iso.add_hard_link(iso_old_path='/SHARED.;1',
                      iso_new_path='/LINK.;1', rr_name='link')

    # Same display path '/dup' in every namespace, but each add_fp is a
    # separate allocation carrying byte-identical content.
    iso.add_fp(io.BytesIO(DUP_BYTES), len(DUP_BYTES),
               iso_path='/DUP.;1', rr_name='dup')
    iso.add_fp(io.BytesIO(DUP_BYTES), len(DUP_BYTES),
               joliet_path='/dup')
    iso.add_fp(io.BytesIO(DUP_BYTES), len(DUP_BYTES),
               udf_path='/dup')

    # Same display path '/split' but genuinely different payloads per
    # namespace, so equal paths must not imply equal data.
    iso.add_fp(io.BytesIO(b'iso payload\n'), 12,
               iso_path='/SPLIT.;1', rr_name='split')
    iso.add_fp(io.BytesIO(b'joliet payload!\n'), 16,
               joliet_path='/split')
    iso.add_fp(io.BytesIO(b'udf payload data\n'), 17,
               udf_path='/split')

    iso.write(path)
    iso.close()
    return path


@pytest.fixture()
def hybrid_iso(tmpdir):
    return build_hybrid_iso(str(tmpdir.join('hybrid.iso')))


def open_report(path):
    iso = pycdlib.PyCdlib()
    iso.open(path)
    return iso, namespacediff.build_report(iso)


def comparison_by_path(report, path):
    matches = [c for c in report.comparisons if c.path == path]
    assert len(matches) == 1
    return matches[0]


def entries_by_path(report, path):
    return {ns: entry
            for ns, result in report.namespaces.items()
            for entry in result.entries if entry.path == path}


def test_all_four_namespaces_are_enumerated(hybrid_iso):
    iso, report = open_report(hybrid_iso)
    assert set(report.namespaces) == {'iso9660', 'rockridge', 'joliet', 'udf'}
    for result in report.namespaces.values():
        assert result.available is True
        assert result.error is None
        assert len(result.entries) > 0
    iso.close()


def test_hard_links_share_one_identity(hybrid_iso):
    iso, report = open_report(hybrid_iso)
    shared = entries_by_path(report, '/shared')
    # Rock Ridge, Joliet and UDF spell it '/shared'; ISO9660 uses 8.3.
    assert set(shared) == {'rockridge', 'joliet', 'udf'}
    identities = {entry.identity for entry in shared.values()}
    assert len(identities) == 1

    # The additional hard link resolves to that exact same inode.
    link_rr = entries_by_path(report, '/link')['rockridge']
    shared_iso = entries_by_path(report, '/SHARED.;1')['iso9660']
    assert link_rr.identity == shared_iso.identity
    assert link_rr.data_ranges == shared_iso.data_ranges

    comparison = comparison_by_path(report, '/shared')
    assert comparison.relation == 'hard-link'
    iso.close()


def test_independent_identical_copies_are_not_hard_links(hybrid_iso):
    iso, report = open_report(hybrid_iso)
    dup = entries_by_path(report, '/dup')
    assert set(dup) == {'rockridge', 'joliet', 'udf'}
    identities = {entry.identity for entry in dup.values()}
    # Independent inodes...
    assert len(identities) == 3
    # ...but one content digest, and distinct data extents.
    comparison = comparison_by_path(report, '/dup')
    assert len(comparison.digests) == 1
    assert comparison.relation == 'same-content-copy'
    ranges = [tuple((r.extent, r.length) for r in e.data_ranges)
              for e in dup.values()]
    assert len(set(ranges)) == 3
    iso.close()


def test_same_path_different_payloads_is_data_source_difference(hybrid_iso):
    iso, report = open_report(hybrid_iso)
    split = entries_by_path(report, '/split')
    assert set(split) == {'rockridge', 'joliet', 'udf'}
    comparison = comparison_by_path(report, '/split')
    assert comparison.relation == 'different-content'
    assert len(comparison.digests) == 3
    assert 'Data-source difference' in comparison.explanation
    iso.close()


def test_name_mapping_difference_is_reported_not_hidden(hybrid_iso):
    iso, report = open_report(hybrid_iso)
    # '/link' exists only in the ISO9660/Rock Ridge tree.
    comparison = comparison_by_path(report, '/link')
    assert 'joliet' in comparison.missing_in
    assert 'udf' in comparison.missing_in
    assert 'Name-mapping difference' in comparison.explanation
    iso.close()


def test_record_locations_and_data_ranges_are_populated(hybrid_iso):
    iso, report = open_report(hybrid_iso)
    with open(hybrid_iso, 'rb') as fp:
        disk = fp.read()
    block_size = report.block_size
    for result in report.namespaces.values():
        for entry in result.entries:
            loc = entry.record_location
            assert loc.extent >= 0 and loc.length > 0
            offset = loc.extent * block_size + loc.offset
            if result.namespace == 'udf':
                # UDF File Identifier Descriptors start with tag ident 257.
                import struct
                assert struct.unpack_from('<H', disk, offset)[0] == 257
            else:
                # ISO9660-style records start with their own length byte.
                assert disk[offset] == loc.length
            for data_range in entry.data_ranges:
                assert data_range.length >= 0
    iso.close()


def test_raw_names_are_preserved_per_namespace(hybrid_iso):
    iso, report = open_report(hybrid_iso)
    iso_entry = entries_by_path(report, '/SHARED.;1')['iso9660']
    rr_entry = entries_by_path(report, '/shared')['rockridge']
    joliet_entry = entries_by_path(report, '/shared')['joliet']
    udf_entry = entries_by_path(report, '/shared')['udf']
    assert iso_entry.raw_name == b'SHARED.;1'
    assert rr_entry.raw_name == b'shared'
    assert joliet_entry.raw_name == b'\x00s\x00h\x00a\x00r\x00e\x00d'
    assert udf_entry.raw_name == b'shared'
    iso.close()


def test_corrupt_namespace_does_not_swallow_other_views(tmpdir):
    source = str(tmpdir.join('clean.iso'))
    build_hybrid_iso(source)
    damaged = str(tmpdir.join('damaged.iso'))
    shutil.copy(source, damaged)

    iso = pycdlib.PyCdlib()
    iso.open(damaged)
    joliet_extent = iso.joliet_vd.root_directory_record().extent_location()
    iso.close()

    # Corrupt the Joliet root directory block: make the first real file
    # record declare an impossible file identifier length.
    block_size = 2048
    with open(damaged, 'r+b') as fp:
        fp.seek(joliet_extent * block_size)
        block = bytearray(fp.read(block_size))
        offsets, cursor = [], 0
        while cursor < block_size and block[cursor] != 0:
            offsets.append(cursor)
            cursor += block[cursor]
        block[offsets[2] + 32] = 250  # len_fi field of the first real record
        fp.seek(joliet_extent * block_size)
        fp.write(bytes(block))

    iso = pycdlib.PyCdlib()
    iso.open(damaged)
    report = namespacediff.build_report(iso)

    assert report.namespaces['joliet'].error is not None
    # The other three views must still yield their full findings.
    for healthy in ('iso9660', 'rockridge', 'udf'):
        result = report.namespaces[healthy]
        assert result.error is None
        assert len(result.entries) > 0
    # Correlation still runs on whatever survived.
    assert len(report.comparisons) > 0
    iso.close()


def test_report_is_read_only(hybrid_iso):
    before = open(hybrid_iso, 'rb').read()
    iso = pycdlib.PyCdlib()
    iso.open(hybrid_iso)
    namespacediff.build_report(iso)
    iso.close()
    assert open(hybrid_iso, 'rb').read() == before


def test_render_text_mentions_every_relation(hybrid_iso):
    iso, report = open_report(hybrid_iso)
    text = namespacediff.render_text(report)
    assert 'hard-link' in text
    assert 'same-content-copy' in text
    assert 'different-content' in text
    assert 'Name-mapping difference' in text
    iso.close()
