"""
Standalone runner for the structure-aware fuzzing campaign.

Usage::

    python -m tests.structure_fuzz                # default fixed-seed campaign
    python -m tests.structure_fuzz --difat        # include the large DIFAT fixture
    python -m tests.structure_fuzz --seeds 1 2 3  # custom fixed seeds

Exits non-zero if any case violates a safety invariant (out-of-bounds read,
unbounded traversal, or cross-stream content leak).  No external corpus or
fuzzing engine is required.
"""

from __future__ import print_function

import argparse
import sys

from .campaign import (run_campaign, positive_control_demo,
                       open_olefile_default, open_olefile_strict, DEFAULT_SEEDS)
from .instrument import Verdict, MAX_TRAVERSAL_STEPS, repoint
from .mutators import ALL_MUTATORS
from .olebuilder import standard_seed


def main(argv=None):
    parser = argparse.ArgumentParser(description='olefile structure-aware fuzzing')
    parser.add_argument('--seeds', type=int, nargs='*', default=list(DEFAULT_SEEDS),
                        help='fixed RNG seeds (default: %(default)s)')
    parser.add_argument('--difat', action='store_true',
                        help='also mutate a real >109-FAT-sector DIFAT fixture')
    args = parser.parse_args(argv)

    # positive control first: prove the oracle catches planted defects
    compound = standard_seed(seed=1)
    oob, hang = positive_control_demo(compound)
    assert not oob.safe and oob.tracker.oob_reads, 'OOB oracle failed to fire'
    assert not hang.safe and hang.traversal_steps > MAX_TRAVERSAL_STEPS, \
        'non-termination oracle failed to fire'
    print('[positive control] OOB and non-termination detectors both fired OK')

    results = run_campaign(seeds=args.seeds)
    totals = {'accepted': 0, 'rejected': 0, 'error': 0}
    unsafe = []
    alien = []
    for case in results:
        verdict = case['verdict']
        totals[verdict.outcome] = totals.get(verdict.outcome, 0) + 1
        if not verdict.safe:
            unsafe.append(case)
        if verdict.has_alien_content:
            alien.append(case)

    print('[campaign] %d cases across %d mutators x %d seeds x 2 readers'
          % (len(results), len(ALL_MUTATORS), len(args.seeds)))
    print('           outcomes: %s' % totals)
    print('           max traversal steps: %d (budget %d)'
          % (max(c['verdict'].traversal_steps for c in results),
             MAX_TRAVERSAL_STEPS))

    if args.difat:
        from .mutators import mutate_difat_chain, Rng
        from .instrument import evaluate
        base = standard_seed(seed=1, force_difat=True)
        difat_unsafe = 0
        for seed in args.seeds[:4]:
            mutated, _ = mutate_difat_chain(base, Rng(seed))
            for reader in (open_olefile_default, open_olefile_strict):
                verdict = evaluate(repoint(base, mutated), reader)
                if not verdict.safe or verdict.has_alien_content:
                    difat_unsafe += 1
        print('[difat]     %d DIFAT-chain cases, unsafe: %d'
              % (len(args.seeds[:4]) * 2, difat_unsafe))
        if difat_unsafe:
            unsafe.append('difat')

    if unsafe or alien:
        print('FAIL: %d unsafe cases, %d cross-stream leaks'
              % (len(unsafe), len(alien)))
        return 1
    print('PASS: no out-of-bounds reads, no unbounded traversal, no leaks')
    return 0


if __name__ == '__main__':
    sys.exit(main())
