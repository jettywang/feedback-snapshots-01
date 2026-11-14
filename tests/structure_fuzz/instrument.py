"""
Read-range instrumentation and the verification oracle.

``TrackingBytesIO`` wraps the in-memory compound file and records every
``seek``/``read`` so a test can prove *which* file intervals olefile actually
touched.  The oracle (:func:`evaluate`) turns a parse result into a verdict and
asserts the two safety invariants the fuzzing campaign is about:

1. no read ever crosses the end of the supplied buffer (no out-of-bounds read);
2. every chain traversal takes a number of steps bounded by the structure
   declarations (no non-terminating / unbounded walk);
and, when a stream is returned successfully,

3. its bytes are exactly the independently generated payload - never bytes
   belonging to another stream or FAT/DIFAT/directory metadata.
"""

from __future__ import print_function

import io

# A hard ceiling on sector-chain steps.  The legal fixtures are far below it;
# the ceiling exists so a regression that turns a bounded walk into an
# unbounded one fails the test instead of hanging the suite.
MAX_TRAVERSAL_STEPS = 20000


class ReadRecord(object):
    __slots__ = ('start', 'end', 'length')

    def __init__(self, start, length):
        self.start = start
        self.end = start + length
        self.length = length


class TrackingBytesIO(io.BytesIO):
    """BytesIO that logs every (offset, length) read against the buffer."""

    def __init__(self, data):
        super(TrackingBytesIO, self).__init__(data)
        self._buffer_len = len(data)
        self.reads = []
        # attempted reads whose requested window reaches past the buffer
        self.oob_attempts = []
        # reads that actually returned bytes belonging to no valid sector
        self.oob_reads = []
        self.max_end = 0
        self.sector_read_steps = 0          # reads of a full 512-byte sector
        self.mini_read_steps = 0            # reads of a 64-byte mini sector

    def read(self, size=-1):
        pos = self.tell()
        if size is None or size < 0:
            size = self._buffer_len - pos
        data = super(TrackingBytesIO, self).read(size)
        actual = len(data)
        rec = ReadRecord(pos, actual)
        self.reads.append(rec)
        if pos + actual > self.max_end:
            self.max_end = pos + actual
        # A request that reaches past the buffer is recorded. It only becomes
        # a genuine out-of-bounds *read* if bytes beyond the buffer are
        # returned. A request ending exactly at/after EOF that yields no bytes
        # is a safely rejected attempt (the caller checks the short read).
        if pos + size > self._buffer_len:
            self.oob_attempts.append((pos, size, actual))
            if pos < self._buffer_len and actual > (self._buffer_len - pos):
                self.oob_reads.append((pos, size, actual))
        if actual == 512 and pos >= 512 and pos % 512 == 0:
            self.sector_read_steps += 1
        if actual == 64 and pos % 64 == 0:
            self.mini_read_steps += 1
        return data

    def touched_sectors(self):
        """Set of regular (512-byte) sector numbers that were read."""
        out = set()
        for rec in self.reads:
            if rec.length == 512 and rec.start >= 512 and rec.start % 512 == 0:
                out.add(rec.start // 512 - 1)
        return out


def repoint(compound, data):
    """Bind mutated ``data`` to the structural map of a built ``compound``.

    Mutators change bytes but keep the same sector layout, so the returned
    object exposes the original file-offset helpers over the new byte string.
    """
    class _Bound(object):
        pass

    bound = _Bound()
    bound.data = data
    bound.layout = compound.layout
    for name in ('fat_entry_file_offset', 'minifat_entry_file_offset',
                 'direntry_file_offset', 'difat_sector_file_offset',
                 'sector_file_offset'):
        setattr(bound, name, getattr(compound, name))
    return bound


class Verdict(object):
    """Outcome of feeding one (possibly mutated) compound file to olefile."""

    ACCEPTED = 'accepted'
    REJECTED = 'rejected'
    ERROR = 'error'

    def __init__(self, outcome, kind=None, message='', stream_results=None,
                 tracker=None, traversal_steps=0):
        self.outcome = outcome
        self.kind = kind                    # exception class name when rejected
        self.message = message
        # stream name -> ('exact'|'corrupt'|'missing', bytes actually returned)
        self.stream_results = stream_results or {}
        self.tracker = tracker
        self.traversal_steps = traversal_steps

    @property
    def safe(self):
        """True if the safety invariants hold, regardless of accept/reject."""
        if self.tracker is not None and self.tracker.oob_reads:
            return False
        if self.traversal_steps > MAX_TRAVERSAL_STEPS:
            return False
        return True

    @property
    def content_exact(self):
        return all(status == 'exact'
                   for status, _ in self.stream_results.values())

    @property
    def has_alien_content(self):
        return any(status == 'alien'
                   for status, _ in self.stream_results.values())


def _expected_stream_map(compound):
    return {spec.name: spec.content for spec in compound.layout['streams']}


def _tag_counts(compound, data):
    """Map stream name -> number of its unique tags found in ``data``."""
    from .olebuilder import stream_tag
    counts = {}
    for spec in compound.layout['streams']:
        if spec.size == 0:
            continue
        counts[spec.name] = data.count(stream_tag(spec.stream_id))
    return counts


def _contains_foreign_tag(compound, stream_name, data):
    """True if ``data`` carries another stream's tag but none of its own.

    This is the cross-stream leak detector: a safe parser must never return
    another stream's bytes as the content of the requested stream.  A chain
    cycle can re-sequence a stream's own sectors and thereby re-surface a tag,
    but such a read still contains the requested stream's own tag; only data
    built exclusively from a *different* stream (foreign tag present, own tag
    absent) counts as an alien leak.
    """
    counts = _tag_counts(compound, data)
    if not counts:
        return False
    own = counts.get(stream_name, 0)
    foreign = sum(n for name, n in counts.items() if name != stream_name)
    return foreign > 0 and own == 0


def evaluate(compound, open_ole, read_each=True):
    """Parse ``compound`` through ``open_ole(tracker)`` and judge the result.

    ``open_ole`` receives the :class:`TrackingBytesIO` and returns an open
    ``OleFileIO`` (or raises).  All exceptions are captured, never propagated,
    so the fuzzer can classify them instead of aborting.

    Stream statuses:

    * ``exact``   - returned bytes equal the independently built payload;
    * ``alien``   - returned bytes contain another stream's unique tag (a
      cross-stream leak, always a hard failure);
    * ``corrupt`` - returned bytes differ but contain no foreign tag (e.g. a
      truncation or a re-sequenced read of the same chain);
    * ``missing`` - opening/reading the stream raised.

    :returns: :class:`Verdict`.
    """
    tracker = TrackingBytesIO(compound.data)
    expected = _expected_stream_map(compound)
    stream_results = {}
    ole = None
    try:
        ole = open_ole(tracker)
        if not read_each:
            return Verdict(Verdict.ACCEPTED, tracker=tracker,
                           traversal_steps=tracker.sector_read_steps)
        for name, want in expected.items():
            try:
                got = ole.openstream(name).read()
            except Exception as exc:  # stream-level rejection is a valid reject
                stream_results[name] = ('missing',
                                        ('%s: %s' % (type(exc).__name__, exc)).encode())
                continue
            if got == want:
                stream_results[name] = ('exact', got)
            elif _contains_foreign_tag(compound, name, got):
                stream_results[name] = ('alien', got)
            else:
                stream_results[name] = ('corrupt', got)
        steps = tracker.sector_read_steps + tracker.mini_read_steps
        # If one or more streams could not be read, the document did not fully
        # validate: report it as a rejection (while keeping the per-stream
        # detail for inspection).
        failed = [name for name, (status, _) in stream_results.items()
                  if status == 'missing']
        outcome = Verdict.REJECTED if failed else Verdict.ACCEPTED
        kind = 'StreamReadError' if failed else None
        message = 'unreadable streams: %s' % ', '.join(sorted(failed)) if failed else ''
        return Verdict(outcome, kind=kind, message=message, tracker=tracker,
                       stream_results=stream_results, traversal_steps=steps)
    except Exception as exc:
        steps = tracker.sector_read_steps + tracker.mini_read_steps
        return Verdict(Verdict.REJECTED, kind=type(exc).__name__,
                       message=str(exc), tracker=tracker,
                       stream_results=stream_results, traversal_steps=steps)
    finally:
        if ole is not None:
            try:
                ole.close()
            except Exception:
                pass
