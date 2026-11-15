"""
Tests for the reusable, chunk-level record-number candidate index.

These tests build small synthetic EVTX images by hand so that pathological
layouts that real logs rarely contain can be exercised deterministically:
overlapping header-advertised ranges, duplicate record numbers,
non-monotonic numbering, and truncated chunks.  The synthetic builder only
emits the structures the parser reads; checksums and slack space are left
zero, matching how carved/partial evidence often arrives.
"""
import struct

import Evtx.Evtx as evtx
import Evtx.Index as e_index
from Evtx.Evtx import CHUNK_SIZE

HEADER_SIZE = 0x1000
CHUNK_HEADER_SIZE = 0x200
RECORD_MAGIC = 0x00002A2A


def build_record(record_num, body=b"\x00" * 8):
    """
    Build one record blob.  A record begins with magic/size/record_num/
    timestamp and ends with a copy of the size at size-4.
    """
    # magic(4) size(4) record_num(8) timestamp(8) ... size2(4)
    size = 4 + 4 + 8 + 8 + len(body) + 4
    head = struct.pack("<IIQ", RECORD_MAGIC, size, record_num)
    head += struct.pack("<Q", 0)  # timestamp
    return head + body + struct.pack("<I", size)


def build_chunk(records, log_first, log_last, file_first=None, file_last=None):
    """
    Build a full 64KiB chunk around the given record blobs.

    The advertised log/file record ranges are supplied by the caller on
    purpose, so tests can make the header lie about the true contents.
    """
    blob = bytearray(CHUNK_SIZE)
    offset = CHUNK_HEADER_SIZE
    for record in records:
        blob[offset : offset + len(record)] = record
        offset += len(record)
    next_record_offset = offset  # chunk-relative offset just past the records

    ff = file_first if file_first is not None else log_first
    fl = file_last if file_last is not None else log_last
    blob[0:8] = b"ElfChnk\x00"
    struct.pack_into("<QQQQ", blob, 0x8, ff, fl, log_first, log_last)
    struct.pack_into("<I", blob, 0x28, CHUNK_HEADER_SIZE)  # header_size
    struct.pack_into("<I", blob, 0x2C, 0)  # last_record_offset
    struct.pack_into("<I", blob, 0x30, next_record_offset)
    return bytes(blob)


def build_evtx(chunks, chunk_count=None, truncate_to=None):
    """
    Assemble a file header plus the given chunk blobs.

    Args:
      chunks: list of chunk byte strings.
      chunk_count: value to write into the file header (defaults to len(chunks)).
      truncate_to: when set, the final buffer is cut to this many bytes to
        simulate a partially written trailing chunk.
    """
    out = bytearray(HEADER_SIZE)
    header = b"ElfFile\x00"
    header += struct.pack("<QQQ", 0, 0, 1)  # oldest, current chunk, next record
    header += struct.pack("<I", HEADER_SIZE)  # header_size
    header += struct.pack("<HH", 1, 3)  # minor, major version
    # header_chunk_size is consumed as a raw byte offset, so write 0x1000.
    header += struct.pack("<H", HEADER_SIZE)
    header += struct.pack("<H", chunk_count if chunk_count is not None else len(chunks))
    out[0 : len(header)] = header
    for chunk in chunks:
        out += chunk
    if truncate_to is not None:
        out = out[:truncate_to]
    return bytes(out)


def make_overlap_image():
    """
    Two active chunks whose advertised ranges overlap and that both contain a
    physical record numbered 7.  The header range of chunk 1 also claims a
    number it does not physically hold.
    """
    chunk0 = build_chunk([build_record(5), build_record(7)], log_first=5, log_last=7)
    chunk1 = build_chunk([build_record(7), build_record(9)], log_first=7, log_last=11)
    return build_evtx([chunk0, chunk1])


def make_non_monotonic_image():
    # Within one chunk, record numbers descend: 10 then 6 then 12.
    chunk0 = build_chunk(
        [build_record(10), build_record(6), build_record(12)], log_first=6, log_last=12
    )
    return build_evtx([chunk0])


def make_truncated_image(cut_record=False):
    """
    One full active chunk plus a trailing chunk that does not fit in the file.
    The file header only declares the first chunk, so the tail is discovered
    best-effort.
    """
    chunk0 = build_chunk([build_record(1), build_record(2)], log_first=1, log_last=2)
    if cut_record:
        # record 3 is complete; the following record 4 is cut mid-way.  The
        # tail buffer is sized so it ends inside record 4's declared length.
        good = build_record(3)
        bad = build_record(4, body=b"\x00" * 64)
        tail_len = CHUNK_HEADER_SIZE + len(good) + 16
        tail = bytearray(tail_len)
        tail[0:8] = b"ElfChnk\x00"
        struct.pack_into("<I", tail, 0x30, CHUNK_HEADER_SIZE + len(good) + len(bad))
        tail[CHUNK_HEADER_SIZE : CHUNK_HEADER_SIZE + len(good)] = good
        tail[CHUNK_HEADER_SIZE + len(good) :] = bad[:16]
        tail_chunk = bytes(tail)
    else:
        tail_chunk = build_chunk([build_record(3)], log_first=3, log_last=3)[: CHUNK_HEADER_SIZE + 40]
    return build_evtx([chunk0, tail_chunk], chunk_count=1)


# ---------------------------------------------------------------------------
# correctness against the physical ground truth on real, well-formed files
# ---------------------------------------------------------------------------


def brute_force_offsets(buf):
    fh = evtx.FileHeader(buf, 0x0)
    truth = {}
    record_count = 0
    for chunk in fh.chunks():
        for record in chunk.records():
            truth.setdefault(record.record_num(), []).append(record.offset())
            record_count += 1
    return truth, record_count


def test_index_matches_physical_scan(system, security):
    for buf in (system, security):
        fh = evtx.FileHeader(buf, 0x0)
        idx = fh.index()
        truth, record_count = brute_force_offsets(buf)

        assert idx.stats()["records_scanned"] == record_count
        for num, offsets in truth.items():
            assert [c.record_offset for c in idx.candidates(num)] == offsets
            assert [r.offset() for r in idx.get_records(num)] == offsets
            assert fh.get_record(num).offset() == offsets[0]
        assert len(idx.record_numbers()) == len(truth)
        # healthy fixtures produce no structural diagnostics
        assert all(len(v) == 0 for v in idx.diagnostics().values())


def test_unknown_record_number(system):
    fh = evtx.FileHeader(system, 0x0)
    idx = fh.index()
    missing = max(idx.record_numbers()) + 999
    assert idx.candidates(missing) == ()
    assert idx.get_records(missing) == ()
    assert idx.get_record(missing) is None
    assert fh.get_record(missing) is None


# ---------------------------------------------------------------------------
# counting reads: one build scan, candidate-only repeated queries
# ---------------------------------------------------------------------------


def test_repeated_queries_do_not_rescan(monkeypatch, security):
    fh = evtx.FileHeader(security, 0x0)
    constructed = {"records": 0}
    original_init = evtx.Record.__init__

    def counting_init(self, *args, **kwargs):
        constructed["records"] += 1
        return original_init(self, *args, **kwargs)

    monkeypatch.setattr(evtx.Record, "__init__", counting_init)

    # first use builds the index with a single full physical scan: every
    # physical record is constructed once (plus one end-of-records terminator
    # per chunk, which the walk probes but does not index).
    idx = fh.index()
    build_constructs = constructed["records"]
    assert build_constructs >= idx.stats()["records_scanned"]
    assert build_constructs <= idx.stats()["records_scanned"] + idx.stats()["chunks_scanned"]
    assert build_constructs > 0

    targets = list(idx.record_numbers())[:25]
    constructed["records"] = 0
    for _ in range(5):
        for num in targets:
            records = fh.get_records(num)
            assert records and all(r.record_num() == num for r in records)

    # each query materializes only its candidates; the build counters are frozen.
    frozen = dict(idx.stats())
    assert constructed["records"] == len(targets) * 5
    assert idx.stats() == frozen


def test_indexed_query_touches_fewer_records_than_brute_force(security):
    buf = security
    fh = evtx.FileHeader(buf, 0x0)
    idx = fh.index()
    target = sorted(idx.record_numbers())[len(idx.record_numbers()) // 2]

    # brute force cost: inspect every record across every active chunk.
    inspected_brute = 0
    found_brute = []
    for chunk in fh.chunks():
        for record in chunk.records():
            inspected_brute += 1
            if record.record_num() == target:
                found_brute.append(record.offset())

    # indexed cost: only the candidate record(s) are materialized.
    candidates = idx.candidates(target)
    assert [c.record_offset for c in candidates] == found_brute
    assert len(candidates) < inspected_brute


# ---------------------------------------------------------------------------
# overlapping ranges, duplicates and non-monotonic numbering
# ---------------------------------------------------------------------------


def test_overlapping_ranges_and_duplicate_locations():
    buf = make_overlap_image()
    fh = evtx.FileHeader(buf, 0x0)
    idx = fh.index()

    # both physical copies of record 7 are retained, at distinct offsets.
    locations = idx.candidates(7)
    assert len(locations) == 2
    assert locations[0].record_offset != locations[1].record_offset
    assert [r.offset() for r in idx.get_records(7)] == [loc.record_offset for loc in locations]

    # legacy single-result contract: first physical hit, never None.
    legacy = fh.get_record(7)
    assert legacy.offset() == locations[0].record_offset

    # number 11 is advertised by the header but physically absent: the index
    # trusts the records, so it must not invent a hit.
    assert idx.candidates(11) == ()
    assert fh.get_record(11) is None

    diagnostics = idx.diagnostics()
    overlap_nums = {o.record_num for o in diagnostics["overlapping_ranges"]}
    assert 7 in overlap_nums
    dup_nums = {d.record_num for d in diagnostics["duplicate_records"]}
    assert dup_nums == {7}
    # each duplicate diagnostic preserves both physical locations.
    duplicate = next(d for d in diagnostics["duplicate_records"] if d.record_num == 7)
    assert [loc.record_offset for loc in duplicate.locations] == [
        loc.record_offset for loc in locations
    ]


def test_non_monotonic_numbering_is_diagnosed_not_dropped():
    buf = make_non_monotonic_image()
    fh = evtx.FileHeader(buf, 0x0)
    idx = fh.index()

    assert sorted(idx.record_numbers()) == [6, 10, 12]
    for num in (6, 10, 12):
        assert idx.get_record(num).record_num() == num

    violations = idx.diagnostics()["non_monotonic_records"]
    assert len(violations) == 1
    assert violations[0].previous_record_num == 10
    assert violations[0].record_num == 6


# ---------------------------------------------------------------------------
# truncated chunks
# ---------------------------------------------------------------------------


def test_truncated_trailing_chunk_is_best_effort_indexed():
    buf = make_truncated_image()
    fh = evtx.FileHeader(buf, 0x0)
    idx = fh.index()

    # the fully written active chunk is complete.
    assert idx.get_record(1).record_num() == 1
    assert idx.get_record(2).record_num() == 2
    # the readable record inside the cut trailing chunk is still reachable.
    assert idx.get_record(3).record_num() == 3

    truncated = idx.diagnostics()["truncated_chunks"]
    assert len(truncated) == 1
    assert truncated[0].chunk_index == 1


def test_cut_record_inside_chunk_is_reported_and_prefix_kept():
    buf = make_truncated_image(cut_record=True)
    fh = evtx.FileHeader(buf, 0x0)
    idx = fh.index()

    assert idx.get_record(3).record_num() == 3
    # record 4's bytes run past EOF; it must not materialize.
    assert idx.candidates(4) == ()
    truncated = idx.diagnostics()["truncated_chunks"]
    assert len(truncated) == 1
    assert truncated[0].chunk_index == 1


def test_unreadable_chunk_header_is_handled(tmp_path):
    # header claims two chunks but only a handful of bytes of the tail exist.
    chunk0 = build_chunk([build_record(1)], log_first=1, log_last=1)
    buf = bytearray(build_evtx([chunk0], chunk_count=2))
    buf += b"\x00" * 12  # not enough to even read a chunk header
    fh = evtx.FileHeader(bytes(buf), 0x0)
    idx = fh.index()
    assert idx.get_record(1) is not None
    truncated = idx.diagnostics()["truncated_chunks"]
    assert any(t.chunk_index == 1 for t in truncated)


# ---------------------------------------------------------------------------
# the index belongs to one open view, never shared by path
# ---------------------------------------------------------------------------


def test_index_is_per_view_not_keyed_by_path(tmp_path):
    image_a = make_overlap_image()
    image_b = build_evtx([build_chunk([build_record(100)], log_first=100, log_last=100)])
    path = tmp_path / "same_name.evtx"

    # open the same path twice with different contents; views must not share.
    path.write_bytes(image_a)
    with evtx.Evtx(str(path)) as log_a:
        idx_a = log_a.index()
        assert len(idx_a.candidates(7)) == 2
        path.write_bytes(image_b)
        with evtx.Evtx(str(path)) as log_b:
            idx_b = log_b.index()
            assert idx_b is not idx_a
            assert idx_b.candidates(7) == ()
            assert idx_b.get_record(100).record_num() == 100
            # the first view still reflects its own buffer contents.
            assert len(idx_a.candidates(7)) == 2


def test_lazy_build_and_caching(system):
    fh = evtx.FileHeader(system, 0x0)
    assert fh._record_index is None
    idx = fh.index()
    assert idx.is_built()
    assert fh.index() is idx
    # candidates() on a fresh index triggers the build lazily.
    fresh = evtx.FileHeader(system, 0x0)
    fresh_idx = e_index.RecordIndex(fresh)
    assert not fresh_idx.is_built()
    known = sorted(fresh_idx.record_numbers())[0]  # builds on demand
    assert fresh_idx.candidates(known)
    assert fresh_idx.is_built()
