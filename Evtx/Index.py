#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
A reusable, block-level candidate index of the records contained in a
single open EVTX file view.

The EVTX file and chunk headers advertise a record-number *range* for every
chunk.  Those values are written by the logger and are not treated as ground
truth here: a real evidence file can advertise overlapping ranges, repeat a
record number in more than one physical location, number its records
non-monotonically, or be truncated mid-chunk.  This index therefore derives
its contents by physically walking every record in the active chunks (plus a
best-effort scan of a truncated trailing chunk) and remembering the physical
location of each record number.

The index is an attribute of the open file view (the mmap-backed buffer).  It
is never keyed by path name, so opening two different evidence copies that
happen to share a path never shares an index between them.
"""
from __future__ import absolute_import

import logging
from collections import namedtuple

from .BinaryParser import OverrunBufferException, ParseException
from .Evtx import CHUNK_SIZE, ChunkHeader, Record

logger = logging.getLogger(__name__)


class RecordLocation(namedtuple("RecordLocation", [
        "chunk_index", "chunk_offset", "record_offset", "record_num"])):
    """
    The physical location of a single record inside the file view.

    A record number may map to more than one RecordLocation; each entry keeps
    its own physical position so that duplicate record numbers are never
    collapsed into a single hit.

    Attributes:
      chunk_index (int): zero-based ordinal of the containing chunk.
      chunk_offset (int): absolute file offset of the chunk header.
      record_offset (int): absolute file offset of the record.
      record_num (int): the record number read from the record itself.
    """

    __slots__ = ()

    def materialize(self, buf):
        """
        Build the Record object that lives at this location.

        Args:
          buf (mmap or bytes): the buffer backing the owning file view.

        Returns:
          Record: the record at this physical location.
        """
        chunk = ChunkHeader(buf, self.chunk_offset)
        return Record(buf, self.record_offset, chunk)


# Diagnostics describing structural irregularities observed while indexing.
OverlappingRange = namedtuple("OverlappingRange", ["left_chunk", "right_chunk", "record_num"])
DuplicateRecord = namedtuple("DuplicateRecord", ["record_num", "locations"])
NonMonotonicRecord = namedtuple(
    "NonMonotonicRecord", ["chunk_index", "previous_record_num", "record_num", "record_offset"]
)
TruncatedChunk = namedtuple("TruncatedChunk", ["chunk_index", "chunk_offset", "reason"])


class RecordIndex(object):
    """
    A chunk-level candidate index of one open EVTX file view.

    Build once with `build()` (or via the `index()` accessor on Evtx/FileHeader,
    which does so lazily) and then query repeatedly with `candidates()` /
    `get_records()`.  The first build walks the records once; subsequent
    lookups only touch the candidate chunks and never rescan the whole file.

    The index stores physical locations, not parsed records, so duplicate
    record numbers in different chunks are all reachable.
    """

    def __init__(self, file_header):
        """
        Args:
          file_header (FileHeader): the header of the buffer to index.  The
            index binds to this view's buffer and does not outlive it.
        """
        self._file_header = file_header
        self._buf = file_header._buf
        # record_num -> list[RecordLocation], in physical (scan) order.
        self._locations = {}
        # chunk_index -> list[RecordLocation]
        self._by_chunk = {}
        self._overlapping_ranges = []
        self._duplicates = []
        self._non_monotonic = []
        self._truncated_chunks = []
        self._built = False
        # Work counters, useful for explaining query cost.
        self.chunks_scanned = 0
        self.records_scanned = 0
        self.truncated_chunks_seen = 0

    def build(self):
        """
        Physically walk every record and populate the index.

        Header-advertised ranges are only cross-checked (reported as
        diagnostics); they never decide which records belong where.  Safe to
        call more than once: a repeat call rebuilds from scratch.

        Returns:
          RecordIndex: this index, now populated.
        """
        self._locations = {}
        self._by_chunk = {}
        self._overlapping_ranges = []
        self._duplicates = []
        self._non_monotonic = []
        self._truncated_chunks = []
        self.chunks_scanned = 0
        self.records_scanned = 0
        self.truncated_chunks_seen = 0

        active_chunks = list(self._file_header.chunks())
        self._index_chunks(active_chunks, start_index=0)

        # A chunk header slot that starts but does not contain a complete
        # 64KiB chunk inside the buffer is a truncated trailing chunk.  It is
        # beyond the header-declared count, so it is indexed best-effort rather
        # than silently ignored.
        tail_offset = self._tail_chunk_offset(len(active_chunks))
        if tail_offset is not None and tail_offset < len(self._buf):
            self._index_truncated_chunk(len(active_chunks), tail_offset)

        self._record_overlapping_ranges(active_chunks)
        self._record_duplicates()
        self._built = True
        return self

    def _tail_chunk_offset(self, active_count):
        base = self._file_header._offset + self._file_header.header_chunk_size()
        offset = base + active_count * CHUNK_SIZE
        if offset >= len(self._buf):
            return None
        return offset

    def _index_chunks(self, chunks, start_index):
        for i, chunk in enumerate(chunks):
            self._index_chunk(chunk, start_index + i)

    def _index_truncated_chunk(self, chunk_index, chunk_offset):
        # A slot shorter than a full chunk is truncated even when every byte it
        # does contain happens to parse (e.g. a cleanly cut record prefix).
        if len(self._buf) - chunk_offset < CHUNK_SIZE:
            self._mark_truncated(chunk_index, chunk_offset, "chunk extends past end of file")
        try:
            chunk = ChunkHeader(self._buf, chunk_offset)
        except OverrunBufferException as exc:
            self._mark_truncated(chunk_index, chunk_offset, str(exc))
            return
        self._index_chunk(chunk, chunk_index)

    def _index_chunk(self, chunk, chunk_index):
        """
        Walk the records of one chunk, tolerating truncated/garbage tails.

        Records are followed physically until the chunk's next-record offset or
        an unreadable/invalid record is reached.  An invalid record at or beyond
        the boundary is the ordinary end-of-records terminator (this is how
        `ChunkHeader.records` stops) and is not an error.  A failure strictly
        inside the advertised record area, or a chunk header that itself cannot
        be read fully, is reported as a truncated chunk while the records that
        were readable remain indexed.
        """
        chunk_offset = chunk.offset()
        self.chunks_scanned += 1
        self._by_chunk.setdefault(chunk_index, [])

        try:
            data_end = chunk_offset + chunk.next_record_offset()
        except OverrunBufferException as exc:
            self._mark_truncated(chunk_index, chunk_offset, str(exc))
            return

        previous_num = None
        try:
            record = chunk.first_record()
        except (ParseException, OverrunBufferException) as exc:
            # An unreadable first record inside an otherwise-present chunk is a
            # truncation/corruption signal; an empty slot simply has no records.
            if self._is_within_record_area(chunk_offset, data_end):
                self._mark_truncated(chunk_index, chunk_offset, str(exc))
            return

        while record._offset < data_end and record.length() > 0:
            # A record whose declared size runs past the readable buffer is a
            # torn, truncated record: index nothing for it and stop the walk.
            if record._offset + record.length() > len(self._buf):
                self._mark_truncated(
                    chunk_index,
                    chunk_offset,
                    "record at {} extends past end of file".format(hex(record._offset)),
                )
                return

            num = record.record_num()
            location = RecordLocation(chunk_index, chunk_offset, record.offset(), num)
            self._locations.setdefault(num, []).append(location)
            self._by_chunk[chunk_index].append(location)
            self.records_scanned += 1

            if previous_num is not None and num < previous_num:
                self._non_monotonic.append(
                    NonMonotonicRecord(chunk_index, previous_num, num, record.offset())
                )
            previous_num = num

            next_offset = record._offset + record.length()
            if next_offset >= data_end:
                # Normal end of the record area; do not parse the slack space.
                break
            try:
                record = Record(self._buf, next_offset, chunk)
            except (ParseException, OverrunBufferException) as exc:
                self._mark_truncated(chunk_index, chunk_offset, str(exc))
                return

    @staticmethod
    def _is_within_record_area(chunk_offset, data_end):
        # The record area starts at the fixed 0x200 header size.
        return data_end > chunk_offset + 0x200

    def _mark_truncated(self, chunk_index, chunk_offset, reason):
        if not any(t.chunk_index == chunk_index for t in self._truncated_chunks):
            self._truncated_chunks.append(TruncatedChunk(chunk_index, chunk_offset, reason))
            self.truncated_chunks_seen += 1

    def _record_overlapping_ranges(self, chunks):
        """
        Cross-check the header-advertised log ranges, without trusting them.

        Two populated chunks whose advertised log ranges share a record number
        are reported.  Empty/uninitialized slots advertise zero ranges and are
        not meaningful overlaps.
        """
        spans = []
        for i, chunk in enumerate(chunks):
            try:
                first = chunk.log_first_record_number()
                last = chunk.log_last_record_number()
            except OverrunBufferException:
                continue
            if first == 0 and last == 0:
                continue
            spans.append((i, first, last))

        for left in range(len(spans)):
            left_index, left_first, left_last = spans[left]
            for right in range(left + 1, len(spans)):
                right_index, right_first, right_last = spans[right]
                low = max(left_first, right_first)
                high = min(left_last, right_last)
                for num in range(low, high + 1):
                    self._overlapping_ranges.append(
                        OverlappingRange(left_index, right_index, num)
                    )

    def _record_duplicates(self):
        for num, locations in self._locations.items():
            if len(locations) > 1:
                self._duplicates.append(DuplicateRecord(num, tuple(locations)))
        self._duplicates.sort(key=lambda d: d.record_num)

    def _ensure_built(self):
        if not self._built:
            self.build()

    def candidates(self, record_num):
        """
        Return every physical location that holds the given record number.

        The header ranges are not used to prune candidates; only the physically
        derived index is consulted, so an untruthful header cannot hide a hit.

        Args:
          record_num (int): the record number to look up.

        Returns:
          tuple[RecordLocation]: all matching locations, in physical order;
            an empty tuple when the number is unknown.
        """
        self._ensure_built()
        return tuple(self._locations.get(record_num, ()))

    def get_records(self, record_num):
        """
        Materialize every record sharing the given record number.

        Args:
          record_num (int): the record number to look up.

        Returns:
          tuple[Record]: all matching records, in physical (scan) order.
        """
        self._ensure_built()
        return tuple(location.materialize(self._buf) for location in self._locations.get(record_num, ()))

    def get_record(self, record_num):
        """
        Return a single record for the given number, preserving the legacy
        single-result contract.

        When more than one physical record shares the number, the first one in
        physical (scan) order is returned; use `get_records()` to reach the
        rest.  Returns None when the number is unknown, matching the legacy
        `FileHeader.get_record` behavior.
        """
        records = self.get_records(record_num)
        if not records:
            return None
        return records[0]

    def is_built(self):
        return self._built

    def record_numbers(self):
        """
        Returns:
          tuple[int]: all distinct record numbers physically observed.
        """
        self._ensure_built()
        return tuple(sorted(self._locations))

    def chunk_count_indexed(self):
        self._ensure_built()
        return len(self._by_chunk)

    def diagnostics(self):
        """
        Return the structural irregularities observed while indexing.

        Returns:
          dict with keys `overlapping_ranges`, `duplicate_records`,
          `non_monotonic_records`, and `truncated_chunks`, each mapping to a
          tuple of the corresponding diagnostic namedtuples.
        """
        self._ensure_built()
        return {
            "overlapping_ranges": tuple(self._overlapping_ranges),
            "duplicate_records": tuple(self._duplicates),
            "non_monotonic_records": tuple(self._non_monotonic),
            "truncated_chunks": tuple(self._truncated_chunks),
        }

    def stats(self):
        """
        Return counters describing the work performed by the initial build.

        These do not change on later queries, which is the point of reusing
        the index: one full physical scan, then candidate-only lookups.
        """
        self._ensure_built()
        return {
            "chunks_scanned": self.chunks_scanned,
            "records_scanned": self.records_scanned,
            "truncated_chunks_seen": self.truncated_chunks_seen,
            "distinct_record_numbers": len(self._locations),
        }
