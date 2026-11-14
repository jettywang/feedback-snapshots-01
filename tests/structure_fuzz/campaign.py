"""
Fixed-seed fuzzing campaign and the reference/positive-control readers.

The campaign is deliberately small and fully deterministic: a fixed set of
seeds and the registered structure-aware mutators produce a bounded number of
cases.  No external corpus, fuzzing engine or network access is required.

Two readers are exercised against every case:

* :func:`open_olefile_default` - olefile as shipped, default tolerance
  (``raise_defects=DEFECT_FATAL``);
* :func:`open_olefile_strict` - olefile in its security-oriented mode
  (``raise_defects=DEFECT_INCORRECT``).

A deliberately *buggy* reader (:class:`BuggyReferenceReader`) provides the
positive control: it performs an unbounded chain walk and reads past the end
of the buffer, proving that the instrumentation/oracle really fails on the two
classes of defect the campaign targets.
"""

from __future__ import print_function

import olefile

from .instrument import (TrackingBytesIO, Verdict, evaluate,
                         MAX_TRAVERSAL_STEPS, repoint)
from .olebuilder import standard_seed
from .mutators import ALL_MUTATORS, Rng
from . import reducer


# Fixed seed list: small on purpose, default run stays under a second of work.
DEFAULT_SEEDS = (1, 2, 3, 5, 8, 13, 21, 34)


def open_olefile_default(tracker):
    return olefile.OleFileIO(tracker)


def open_olefile_strict(tracker):
    return olefile.OleFileIO(tracker, raise_defects=olefile.DEFECT_INCORRECT)


def run_campaign(seeds=DEFAULT_SEEDS, force_difat=False, mutators=ALL_MUTATORS,
                 readers=(open_olefile_default, open_olefile_strict)):
    """Run every (mutator, seed, reader) combination and collect verdicts.

    :returns: list of dicts, one per case, with keys: seed, mutator, reader,
        description, verdict.
    """
    base = standard_seed(seed=seeds[0], force_difat=force_difat)
    results = []
    for mutator in mutators:
        for seed in seeds:
            mutated, description = mutator(base, Rng(seed))
            compound = repoint(base, mutated)
            for reader in readers:
                verdict = evaluate(compound, reader)
                results.append({
                    'seed': seed,
                    'mutator': mutator.__name__,
                    'reader': reader.__name__,
                    'description': description,
                    'verdict': verdict,
                })
    return results


# ----------------------------------------------------------------------------
# Positive control: a reader that is intentionally unsafe.  It must be caught.
# ----------------------------------------------------------------------------

class UnsafeTrackingBytesIO(TrackingBytesIO):
    """A deliberately vulnerable stream: reads past EOF return fake bytes.

    Real ``BytesIO`` objects clamp at EOF, so this subclass models a parser
    that performs an unchecked out-of-bounds read and hands back memory that
    does not belong to the file.  The instrumentation must flag it.
    """

    def read(self, size=-1):
        pos = self.tell()
        if size is None or size < 0:
            size = self._buffer_len - pos
        data = super(UnsafeTrackingBytesIO, self).read(size)
        if pos + size > self._buffer_len:
            overflow = pos + size - self._buffer_len
            fake = b'\xDE\xAD\xBE\xEF' * ((overflow // 4) + 1)
            data = data + fake[:overflow]
            self.oob_reads.append((pos, size, len(data)))
            self.max_end = max(self.max_end, pos + len(data))
        return data


class BuggyReferenceReader(object):
    """Stand-in parser with two planted vulnerabilities.

    * ``read_past_end`` walks a chain without bounds checking and reads past
      the end of the buffer (out-of-bounds read, via
      :class:`UnsafeTrackingBytesIO`);
    * ``non_terminating`` follows a self-referencing chain forever, capped here
      only so the test process survives, while still exceeding the allowed
      traversal budget.
    """

    def __init__(self, data, mode='read_past_end', cap=MAX_TRAVERSAL_STEPS + 5):
        tracker_cls = UnsafeTrackingBytesIO if mode == 'read_past_end' \
            else TrackingBytesIO
        self.tracker = tracker_cls(data)
        self.mode = mode
        self.cap = cap
        self.steps = 0

    def run(self):
        if self.mode == 'read_past_end':
            # issue a full-sector read that starts at the end of the buffer:
            # an unambiguous out-of-bounds read that a safe parser rejects.
            self.tracker.seek(self.tracker._buffer_len)
            self.tracker.read(512)
            return Verdict(Verdict.ACCEPTED, tracker=self.tracker,
                           traversal_steps=self.tracker.sector_read_steps)
        # non-terminating walk: keep seeking to the same sector repeatedly
        self.tracker.seek(512)
        while self.steps < self.cap:
            self.tracker.read(512)
            self.tracker.seek(512)
            self.steps += 1
        return Verdict(Verdict.ACCEPTED, tracker=self.tracker,
                       traversal_steps=self.steps)


def positive_control_demo(compound):
    """Run both planted bugs and return their (expected unsafe) verdicts."""
    oob = BuggyReferenceReader(compound.data, mode='read_past_end').run()
    hang = BuggyReferenceReader(compound.data, mode='non_terminating').run()
    return oob, hang


def minimize_case(mutator, seed, reader, force_difat=False):
    """Convenience wrapper around :func:`reducer.minimize`."""
    def evaluate_fn(compound):
        return evaluate(compound, reader)
    return reducer.minimize(mutator, seed, evaluate_fn, force_difat=force_difat)
