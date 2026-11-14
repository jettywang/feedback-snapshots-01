"""
Small-scale, structure-aware fuzzing for olefile.

These tests build minimal, independently verifiable OLE/CFB files and mutate
one structural element at a time (FAT/DIFAT/MiniFAT chain terminators, system
sector markers, mini-sector boundaries and declared counts/sizes).  For every
case they assert that olefile:

* never reads outside the supplied buffer (no out-of-bounds read) and never
  walks a chain beyond a budget derived from the declarations (no
  non-terminating traversal);
* never returns another stream's bytes as the requested stream's content;
* either returns the exact expected payload or rejects the file.

A positive control with two deliberately planted defects proves the oracle
actually flags OOB reads and unbounded walks.  A sector-reorder test proves
that legal layout changes preserve stream digests.  Everything uses fixed
seeds and tiny in-memory fixtures: no external corpus or fuzzing engine.
"""

from __future__ import print_function

import hashlib
import os
import struct
import sys
import unittest

# Make the repository importable regardless of the pytest working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.normpath(os.path.join(_HERE, '..', '..'))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tests.structure_fuzz import campaign  # noqa: E402
from tests.structure_fuzz.campaign import (  # noqa: E402
    run_campaign, positive_control_demo, open_olefile_default,
    open_olefile_strict, minimize_case, DEFAULT_SEEDS)
from tests.structure_fuzz.instrument import (  # noqa: E402
    evaluate, Verdict, MAX_TRAVERSAL_STEPS, repoint)
from tests.structure_fuzz.mutators import (  # noqa: E402
    ALL_MUTATORS, Rng, mutate_fat_link, mutate_difat_chain)
from tests.structure_fuzz.olebuilder import (  # noqa: E402
    standard_seed, build_compound_file, StreamSpec, ENDOFCHAIN, FREESECT,
    FATSECT, DIFSECT, SECTOR_SIZE, MINI_SECTOR_SIZE, MINI_CUTOFF)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


class TestIndependentBuilder(unittest.TestCase):
    """The hand-built fixtures must be valid and independently verifiable."""

    def _assert_fixture(self, compound):
        # structural sanity, independent of olefile:
        self.assertGreaterEqual(compound.layout['nb_sectors'], 4)
        # FAT length covers every sector and metadata sectors are marked:
        fat = compound.layout['fat']
        self.assertEqual(len(fat), compound.layout['nb_sectors'])
        for sid in compound.layout['fat_sector_ids']:
            self.assertEqual(fat[sid], FATSECT)
        for sid in compound.layout['difat_sector_ids']:
            self.assertEqual(fat[sid], DIFSECT)
        # every declared stream round-trips byte-for-byte through olefile:
        verdict = evaluate(compound, open_olefile_default)
        self.assertEqual(verdict.outcome, Verdict.ACCEPTED)
        self.assertTrue(verdict.content_exact, verdict.stream_results)
        self.assertTrue(verdict.safe)
        self.assertFalse(verdict.has_alien_content)
        # nothing read beyond the buffer, obviously for a valid file:
        self.assertEqual(verdict.tracker.oob_reads, [])
        self.assertLessEqual(verdict.tracker.max_end, len(compound.data))

    def test_standard_seed_is_valid(self):
        self._assert_fixture(standard_seed(seed=1))

    def test_fixture_covers_mini_boundaries_and_cutoff(self):
        compound = standard_seed(seed=1)
        by_name = {s.name: s for s in compound.layout['streams']}
        # exactly one mini sector, a crossing, a partial last sector, cutoff:
        self.assertEqual(by_name['MiniOne'].size, MINI_SECTOR_SIZE)
        self.assertEqual(by_name['MiniTwo'].size, MINI_SECTOR_SIZE + 1)
        self.assertEqual(by_name['AtCutoff'].size, MINI_CUTOFF)
        self.assertFalse(by_name['AtCutoff'].mini)   # == cutoff routes to FAT
        self.assertTrue(by_name['MiniOne'].mini)
        # FAT stream spans several sectors with a non-trivial chain:
        self.assertGreaterEqual(len(by_name['FatStream'].chain), 9)

    def test_difat_fixture_is_valid_and_traversed(self):
        compound = standard_seed(seed=1, force_difat=True)
        self.assertGreater(compound.layout['num_fat_sectors'], 109)
        self.assertEqual(len(compound.layout['difat_sector_ids']),
                         compound.layout['num_difat_sectors'])
        self.assertGreaterEqual(compound.layout['num_difat_sectors'], 1)
        self._assert_fixture(compound)

    def test_tiny_fixtures_shapes(self):
        # smallest meaningful shapes still parse exactly:
        for streams in ([StreamSpec('S', 1, 1)],
                        [StreamSpec('S', MINI_CUTOFF, 1)],
                        [StreamSpec('S', MINI_CUTOFF + 1, 1)]):
            self._assert_fixture(build_compound_file(list(streams)))

    def test_zero_length_stream_is_exact(self):
        # an empty stream (ENDOFCHAIN start, zero size) alongside a mini stream
        compound = build_compound_file(
            [StreamSpec('Empty', 0, 9), StreamSpec('Mini', 65, 2)])
        verdict = evaluate(compound, open_olefile_default)
        self.assertEqual(verdict.outcome, Verdict.ACCEPTED)
        self.assertTrue(verdict.content_exact)
        self.assertEqual(verdict.stream_results['Empty'][1], b'')


class TestSafetyInvariants(unittest.TestCase):
    """Every mutated case: no OOB read, bounded walk, no foreign stream bytes."""

    def test_default_and_strict_readers_are_safe(self):
        results = run_campaign()
        self.assertEqual(len(results),
                         len(ALL_MUTATORS) * len(DEFAULT_SEEDS) * 2)
        n_accepted = n_rejected = 0
        for case in results:
            verdict = case['verdict']
            # hard safety invariants, independent of accept/reject:
            self.assertTrue(
                verdict.safe,
                msg='unsafe case %r: oob=%r steps=%d'
                    % (case['description'],
                       verdict.tracker.oob_reads[:3],
                       verdict.traversal_steps))
            self.assertEqual(verdict.tracker.oob_reads, [],
                             msg='OOB read in %r' % case['description'])
            self.assertLessEqual(verdict.traversal_steps,
                                 MAX_TRAVERSAL_STEPS)
            # structural bound: a bounded walk cannot revisit more sectors than
            # the file actually declares (the global budget above is the
            # backstop; this ties the step count to this fixture's declaration)
            self.assertLessEqual(
                verdict.tracker.sector_read_steps,
                standard_seed().layout['nb_sectors']
                + len(standard_seed().layout['fat_sector_ids']))
            self.assertFalse(verdict.has_alien_content,
                             msg='foreign stream bytes in %r'
                                 % case['description'])
            if verdict.outcome == Verdict.REJECTED:
                n_rejected += 1
                # a rejection must not have consumed bytes past EOF:
                self.assertLessEqual(verdict.tracker.max_end,
                                     len(standard_seed().data))
            else:
                n_accepted += 1
        # the campaign must actually exercise both outcomes, otherwise it would
        # not be probing anything meaningful:
        self.assertGreater(n_rejected, 0)
        self.assertGreater(n_accepted, 0)

    def test_difat_chain_mutations_are_safe(self):
        # DIFAT chain defects on a real (large, >109-FAT-sector) fixture:
        base = standard_seed(seed=1, force_difat=True)
        for seed in DEFAULT_SEEDS[:4]:
            mutated, _desc = mutate_difat_chain(base, Rng(seed))
            compound = repoint(base, mutated)
            for reader in (open_olefile_default, open_olefile_strict):
                verdict = evaluate(compound, reader)
                self.assertTrue(verdict.safe)
                self.assertEqual(verdict.tracker.oob_reads, [])
                self.assertFalse(verdict.has_alien_content)

    def test_traversal_step_count_is_bounded_by_declaration(self):
        # for a valid file the number of full-sector reads cannot exceed the
        # total number of sectors actually present:
        compound = standard_seed(seed=1)
        verdict = evaluate(compound, open_olefile_default)
        self.assertLessEqual(
            verdict.tracker.sector_read_steps,
            compound.layout['nb_sectors'] + len(compound.layout['fat_sector_ids']))


class TestControlledDefectProvesOracle(unittest.TestCase):
    """A controlled chain-boundary defect must be detected; positive control."""

    def test_planted_oob_and_nontermination_are_flagged(self):
        compound = standard_seed(seed=1)
        oob_verdict, hang_verdict = positive_control_demo(compound)
        # the buggy out-of-bounds reader must trip the OOB invariant:
        self.assertTrue(oob_verdict.tracker.oob_reads)
        self.assertFalse(oob_verdict.safe)
        # the buggy non-terminating reader must exceed the traversal budget:
        self.assertGreater(hang_verdict.traversal_steps, MAX_TRAVERSAL_STEPS)
        self.assertFalse(hang_verdict.safe)

    def test_known_chain_boundary_defect_is_handled_safely(self):
        # One controlled, explicitly constructed chain-boundary defect: the
        # first interior link of the long FAT chain is replaced by the FATSECT
        # system marker, which is illegal at that position. Strict mode must
        # reject it; tolerant mode must never read past EOF or leak streams.
        base = standard_seed(seed=1)
        chain = base.layout['stream_fat_chains']['FatStream']
        self.assertGreaterEqual(len(chain), 3)
        buf = bytearray(base.data)
        target = chain[0]
        struct.pack_into('<I', buf, base.fat_entry_file_offset(target), FATSECT)
        mutated = bytes(buf)
        compound = repoint(base, mutated)
        strict = evaluate(compound, open_olefile_strict)
        tolerant = evaluate(compound, open_olefile_default)
        # strict, security-oriented mode must reject the broken chain:
        self.assertEqual(strict.outcome, Verdict.REJECTED)
        # both modes stay within the buffer and do not leak other streams:
        for verdict in (strict, tolerant):
            self.assertTrue(verdict.safe)
            self.assertEqual(verdict.tracker.oob_reads, [])
            self.assertFalse(verdict.has_alien_content)
        # and the same defect fed to a buggy reader would be caught:
        planted = campaign.BuggyReferenceReader(mutated, mode='read_past_end').run()
        self.assertFalse(planted.safe)


class TestSectorReorderInvariance(unittest.TestCase):
    """Legal sector reordering must leave every stream digest unchanged."""

    @staticmethod
    def _reorder_fat_sectors(compound):
        """Return a new compound file with data sectors permuted.

        Only regular *data* sectors are permuted; FAT/MiniFAT/directory sectors
        keep their roles.  Because FAT entry *N* describes sector *N*, moving a
        sector means moving its FAT entry too, so the whole FAT table is
        rebuilt under the permutation (markers preserved, regular pointers
        remapped).  Directory start sectors and the header DIFAT array are
        remapped as well.  The result stays a fully legal CFB file, merely with
        an intentionally non-contiguous layout.
        """
        layout = compound.layout
        data_sectors = set()
        for chain in layout['stream_fat_chains'].values():
            data_sectors.update(chain)
        data_sectors.update(layout['root_chain'])
        ordered = sorted(data_sectors)
        old_to_new = dict(zip(ordered, reversed(ordered)))

        def remap(sid):
            return old_to_new.get(sid, sid)

        # 1) move the sector bytes (metadata sectors keep their positions)
        original = [compound.data[SECTOR_SIZE * (i + 1):
                                  SECTOR_SIZE * (i + 2)]
                    for i in range(layout['nb_sectors'])]
        moved = list(original)
        for old, new in old_to_new.items():
            moved[new] = original[old]
        buf = bytearray(compound.data[:SECTOR_SIZE] + b''.join(moved))

        # 2) rebuild the FAT table under the permutation
        markers = {ENDOFCHAIN, FREESECT, FATSECT, DIFSECT}
        new_fat = [FREESECT] * len(layout['fat'])
        for old_index, value in enumerate(layout['fat']):
            new_index = remap(old_index)
            new_fat[new_index] = value if value in markers else remap(value)

        def fat_off(index):
            fat_sect = layout['fat_sector_ids'][index // 128]
            return SECTOR_SIZE * (fat_sect + 1) + 4 * (index % 128)

        for index, value in enumerate(new_fat):
            struct.pack_into('<I', buf, fat_off(index), value)

        # 3) remap start sectors inside the (stationary) directory sectors
        def direntry_off(sid):
            sect = layout['directory_sector_ids'][sid // 4]
            return SECTOR_SIZE * (sect + 1) + 128 * (sid % 4)

        struct.pack_into('<I', buf, direntry_off(0) + 116,
                         remap(layout['root_first_sect']))
        for sid, spec in enumerate(layout['streams'], start=1):
            if not spec.mini:
                struct.pack_into('<I', buf, direntry_off(sid) + 116,
                                 remap(spec.first_sect))

        # 4) header DIFAT array and directory/MiniFAT start sectors
        for k, old_fat_id in enumerate(layout['fat_sector_ids'][:109]):
            struct.pack_into('<I', buf, 0x4C + 4 * k, remap(old_fat_id))
        struct.pack_into('<I', buf, 0x30,
                         remap(layout['directory_sector_ids'][0]))
        if layout['minifat_sector_ids']:
            struct.pack_into('<I', buf, 0x3C,
                             remap(layout['minifat_sector_ids'][0]))
        return bytes(buf)

    def test_digests_unchanged_after_reorder(self):
        compound = standard_seed(seed=1)
        reordered = self._reorder_fat_sectors(compound)
        self.assertNotEqual(reordered, compound.data)  # layout really changed

        before = evaluate(compound, open_olefile_default)
        after_obj = repoint(compound, reordered)
        after = evaluate(after_obj, open_olefile_default)
        self.assertTrue(after.content_exact)
        for spec in compound.layout['streams']:
            self.assertEqual(
                _digest(before.stream_results[spec.name][1]),
                _digest(after.stream_results[spec.name][1]),
                msg='digest changed for stream %r after legal reorder'
                    % spec.name)

    def test_reorder_preserves_mini_streams_too(self):
        # mini streams live inside the root container; reordering container
        # sectors must not disturb their (MiniFAT-relative) contents:
        compound = standard_seed(seed=1)
        reordered = self._reorder_fat_sectors(compound)
        after = evaluate(repoint(compound, reordered),
                         open_olefile_default)
        for spec in compound.layout['streams']:
            if spec.mini:
                status, payload = after.stream_results[spec.name]
                self.assertEqual(status, 'exact')
                self.assertEqual(payload, spec.content)


class TestMinimizationAndDeterminism(unittest.TestCase):
    def test_minimized_case_uses_fewer_or_equal_sectors(self):
        compound, mutated, desc, verdict, attempts = minimize_case(
            mutate_fat_link, seed=2, reader=open_olefile_strict)
        # minimization must retain a safe outcome and shrink the fixture:
        self.assertTrue(verdict.safe)
        self.assertLessEqual(compound.layout['nb_sectors'],
                             standard_seed().layout['nb_sectors'])
        self.assertGreater(attempts, 1)
        # the minimal file still triggers a rejection in strict mode:
        self.assertEqual(verdict.outcome, Verdict.REJECTED)

    def test_fixed_seeds_are_reproducible(self):
        first = run_campaign(seeds=(7,))
        second = run_campaign(seeds=(7,))
        sig1 = [(c['mutator'], c['description'], c['verdict'].outcome,
                 c['verdict'].kind) for c in first]
        sig2 = [(c['mutator'], c['description'], c['verdict'].outcome,
                 c['verdict'].kind) for c in second]
        self.assertEqual(sig1, sig2)

    def test_rng_is_deterministic(self):
        self.assertEqual([Rng(42).next_u32() for _ in range(5)],
                         [Rng(42).next_u32() for _ in range(5)])


if __name__ == '__main__':
    unittest.main()
