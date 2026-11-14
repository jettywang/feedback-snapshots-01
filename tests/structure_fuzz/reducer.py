"""
Minimization of a failing mutated file to the fewest possible sectors.

The reducer keeps applying a defect mutator to progressively smaller legal
base fixtures (fewer streams, shorter payloads) while the *class* of the
observed verdict stays the same, returning the smallest compound file that
still triggers it.  This mirrors delta-debugging but shrinks at the structural
level (whole sectors / streams) rather than at the byte level.
"""

from __future__ import print_function

from .olebuilder import StreamSpec, build_compound_file, MINI_CUTOFF
from .mutators import Rng
from .instrument import repoint


# Stream sets from richest to poorest; the reducer walks down the list.
_SHRINK_STREAMS = [
    [StreamSpec('FatStream', 4731, 1), StreamSpec('MiniOne', 64, 2),
     StreamSpec('MiniTwo', 65, 3), StreamSpec('MiniThree', 200, 4),
     StreamSpec('AtCutoff', MINI_CUTOFF, 5)],
    [StreamSpec('FatStream', 4097, 1), StreamSpec('MiniOne', 65, 2)],
    [StreamSpec('FatStream', 4096 + 1, 1), StreamSpec('MiniOne', 64, 2)],
    [StreamSpec('FatStream', 4096, 1)],
    [StreamSpec('MiniOne', 65, 2)],
    [StreamSpec('MiniOne', 1, 2)],
]


def _classify(verdict):
    """Coarse outcome signature used to decide if a shrink kept the defect."""
    if verdict.outcome != 'accepted':
        return (verdict.outcome, verdict.kind)
    statuses = tuple(sorted((name, status) for name, (status, _)
                            in verdict.stream_results.items()))
    return (verdict.outcome, statuses)


def minimize(mutator, seed, evaluate_fn, force_difat=False):
    """Find the smallest fixture on which ``mutator`` keeps the same verdict.

    :param mutator: one of the functions in :mod:`mutators`.
    :param seed: fixed RNG seed (kept constant across shrink attempts).
    :param evaluate_fn: callable taking a :class:`CompoundFile`-like object and
        returning a :class:`instrument.Verdict`.
    :returns: tuple ``(smallest_compound, mutated_data, description, verdict,
        attempts)``.
    """
    rng = Rng(seed)
    base = build_compound_file(list(_SHRINK_STREAMS[0]), force_difat=force_difat)
    mutated, desc = mutator(base, Rng(seed))
    target = _classify(evaluate_fn(repoint(base, mutated)))
    best = (base, mutated, desc)
    attempts = 1
    for streams in _SHRINK_STREAMS[1:]:
        try:
            candidate = build_compound_file(list(streams), force_difat=force_difat)
            cand_mutated, cand_desc = mutator(candidate, Rng(seed))
        except Exception:
            # mutator not applicable to this shape (e.g. no mini chain): skip
            attempts += 1
            continue
        verdict = evaluate_fn(repoint(candidate, cand_mutated))
        attempts += 1
        if _classify(verdict) == target:
            best = (candidate, cand_mutated, cand_desc)
    compound, mutated, desc = best
    return compound, mutated, desc, evaluate_fn(repoint(compound, mutated)), attempts

