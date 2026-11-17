#-------------------------------------------------------------------------------
# elftools tests: restricted static binding analysis
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import binding_fixtures as bf
from binding_analysis import BindingAnalyzer, Certainty, Outcome
from binding_analysis.report import render_text


class BindingTestBase(unittest.TestCase):
    """Builds the short synthetic ELF set shared by the tests.

    Load order: app, liboverride.so, libseat.so, libver.so, libsym.so
    """
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='binding-test-')
        add = cls.dir

        bf.build_elf(
            os.path.join(add, 'app'), soname='app',
            needed=['liboverride.so', 'libseat.so', 'libver.so', 'libsym.so'],
            symbols=[
                bf.sym('adjust'),                            # contested
                bf.sym('firmware'),                          # protected target
                bf.sym('weak_hook', bind='WEAK'),            # no provider
                bf.sym('query', version='VER_2'),            # versioned ref
                bf.sym('totally_absent'),                    # no provider
            ],
            verneeds=[('libver.so', ['VER_2'])])

        bf.build_elf(
            os.path.join(add, 'liboverride.so'), soname='liboverride.so',
            symbols=[
                bf.sym('adjust', defined=True),              # interposer
                bf.sym('firmware', defined=True),            # tries to override
            ])

        bf.build_elf(
            os.path.join(add, 'libseat.so'), soname='libseat.so',
            symbols=[
                bf.sym('adjust', defined=True),              # loses to override
                bf.sym('firmware', defined=True, vis='PROTECTED'),
                bf.sym('firmware'),                          # self ref: pinned
                bf.sym('probe', defined=True, vis='HIDDEN'),
                bf.sym('probe'),                             # self ref: pinned
            ])

        bf.build_elf(
            os.path.join(add, 'libver.so'), soname='libver.so',
            symbols=[
                bf.sym('query', defined=True, version='VER_2'),
                bf.sym('query', defined=True, version='VER_1',
                       version_hidden=True),
            ],
            verdefs=['VER_1', 'VER_2'])

        bf.build_elf(
            os.path.join(add, 'libsym.so'), soname='libsym.so',
            flags=bf.DF_SYMBOLIC,
            symbols=[
                bf.sym('adjust', defined=True),              # symbolic: self wins
                bf.sym('adjust'),                            # self ref: pinned
            ])

        cls.paths = [os.path.join(add, name) for name in (
            'app', 'liboverride.so', 'libseat.so', 'libver.so', 'libsym.so')]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def analyze(self, paths=None, **kwargs):
        analyzer = BindingAnalyzer(paths or self.paths, **kwargs)
        return analyzer.analyze()

    @staticmethod
    def find(report, module, symbol):
        for res in report.resolutions:
            if res.module == module and res.symbol.name == symbol:
                return res
        raise AssertionError('no resolution for %s:%s' % (module, symbol))


class TestInterposition(BindingTestBase):
    def test_plain_override(self):
        report = self.analyze()
        res = self.find(report, 'app', 'adjust')
        self.assertEqual(res.outcome, Outcome.CONTESTED)
        self.assertEqual(res.certainty, Certainty.MULTIPLE_CANDIDATES)
        self.assertTrue(res.replaceable)
        # liboverride.so precedes libseat.so in the load order.
        self.assertEqual(res.winner.module, 'liboverride.so')
        self.assertEqual([c.module for c in res.candidates],
                         ['liboverride.so', 'libseat.so', 'libsym.so'])
        # Every candidate carries real symbol evidence.
        for candidate in res.candidates:
            self.assertTrue(candidate.defined)
            self.assertGreater(candidate.index, 0)

    def test_order_decides_winner(self):
        report = self.analyze(paths=[
            self.paths[0], self.paths[2], self.paths[1]] + self.paths[3:])
        res = self.find(report, 'app', 'adjust')
        self.assertEqual(res.winner.module, 'libseat.so')

    def test_unique_provider(self):
        report = self.analyze()
        res = self.find(report, 'app', 'query')
        self.assertEqual(res.outcome, Outcome.UNIQUE_PROVIDER)
        self.assertEqual(res.certainty, Certainty.DEFINITE)
        self.assertFalse(res.replaceable)
        self.assertEqual(res.winner.module, 'libver.so')
        self.assertEqual(res.winner.version, 'VER_2')


class TestProtectedAndHidden(BindingTestBase):
    def test_protected_self_reference_pinned(self):
        report = self.analyze()
        res = self.find(report, 'libseat.so', 'firmware')
        self.assertEqual(res.outcome, Outcome.PINNED_LOCAL)
        self.assertEqual(res.certainty, Certainty.DEFINITE)
        self.assertFalse(res.replaceable)
        self.assertEqual(res.winner.module, 'libseat.so')
        self.assertEqual(res.winner.visibility, 'STV_PROTECTED')

    def test_protected_visible_to_others(self):
        # Another module's reference to a protected symbol still goes
        # through normal scope lookup; liboverride.so wins for app's ref.
        report = self.analyze()
        res = self.find(report, 'app', 'firmware')
        self.assertEqual(res.outcome, Outcome.CONTESTED)
        self.assertEqual(res.winner.module, 'liboverride.so')
        self.assertEqual([c.module for c in res.candidates],
                         ['liboverride.so', 'libseat.so'])

    def test_hidden_self_reference_pinned(self):
        report = self.analyze()
        res = self.find(report, 'libseat.so', 'probe')
        self.assertEqual(res.outcome, Outcome.PINNED_LOCAL)
        self.assertFalse(res.replaceable)
        self.assertEqual(res.winner.visibility, 'STV_HIDDEN')

    def test_hidden_not_exported(self):
        # libseat.so's hidden 'probe' must not appear as a candidate for
        # other modules.
        report = self.analyze()
        for res in report.resolutions:
            if res.module == 'libseat.so':
                continue
            for candidate in res.candidates:
                self.assertNotEqual(candidate.visibility, 'STV_HIDDEN')


class TestSymbolic(BindingTestBase):
    def test_df_symbolic_pins_self_reference(self):
        report = self.analyze()
        res = self.find(report, 'libsym.so', 'adjust')
        self.assertEqual(res.outcome, Outcome.PINNED_LOCAL)
        self.assertFalse(res.replaceable)
        self.assertEqual(res.winner.module, 'libsym.so')
        self.assertTrue(any('DF_SYMBOLIC' in n for n in res.notes))

    def test_deepbind_caller_declared(self):
        # RTLD_DEEPBIND is a dlopen() flag, not an ELF bit, so the caller
        # declares it; its self-first lookup effect is then modeled.
        path = os.path.join(self.dir, 'libdeep.so')
        bf.build_elf(path, soname='libdeep.so',
                     symbols=[bf.sym('adjust', defined=True), bf.sym('adjust')])
        report = self.analyze(paths=[self.paths[1], path],
                              deepbind_modules={'libdeep.so'})
        res = self.find(report, 'libdeep.so', 'adjust')
        self.assertEqual(res.outcome, Outcome.PINNED_LOCAL)
        self.assertFalse(res.replaceable)
        self.assertEqual(res.winner.module, 'libdeep.so')
        self.assertTrue(any('RTLD_DEEPBIND' in n for n in res.notes))
        # Without the caller hint the same reference is interposable.
        report = self.analyze(paths=[self.paths[1], path])
        res = self.find(report, 'libdeep.so', 'adjust')
        self.assertEqual(res.outcome, Outcome.CONTESTED)
        self.assertEqual(res.winner.module, 'liboverride.so')


class TestWeakAndMissing(BindingTestBase):
    def test_unresolved_weak(self):
        report = self.analyze()
        res = self.find(report, 'app', 'weak_hook')
        self.assertEqual(res.outcome, Outcome.UNRESOLVED_WEAK)
        self.assertEqual(res.certainty, Certainty.POLICY_DEPENDENT)
        self.assertIsNone(res.replaceable)
        self.assertIsNone(res.winner)
        self.assertEqual(res.candidates, [])

    def test_unresolved_strong(self):
        report = self.analyze()
        res = self.find(report, 'app', 'totally_absent')
        self.assertEqual(res.outcome, Outcome.UNRESOLVED_STRONG)
        self.assertEqual(res.certainty, Certainty.POLICY_DEPENDENT)
        self.assertIsNone(res.replaceable)

    def test_missing_needed_reported(self):
        report = self.analyze()
        self.assertFalse(any('libver.so' in n for n in report.scope_notes))
        # Drop libver.so from the set: its DT_NEEDED entry becomes unmodeled.
        report = self.analyze(paths=[p for p in self.paths
                                     if 'libver' not in p])
        self.assertTrue(any('libver.so' in n for n in report.scope_notes))
        res = self.find(report, 'app', 'query')
        self.assertEqual(res.outcome, Outcome.UNRESOLVED_STRONG)


class TestVersioning(BindingTestBase):
    def test_versioned_ref_binds_named_version(self):
        report = self.analyze()
        res = self.find(report, 'app', 'query')
        self.assertEqual(res.winner.version, 'VER_2')
        self.assertFalse(res.winner.version_hidden)
        # The hidden VER_1 definition was rejected by the version rules.
        self.assertTrue(any('rejected by version rules' in n
                            for n in res.notes))

    def test_unversioned_ref_ignores_hidden_version(self):
        path = os.path.join(self.dir, 'libu.so')
        bf.build_elf(path, soname='libu.so',
                     symbols=[bf.sym('query')])  # unversioned ref
        report = self.analyze(paths=[path, self.paths[3]])
        res = self.find(report, 'libu.so', 'query')
        self.assertEqual(res.outcome, Outcome.UNIQUE_PROVIDER)
        self.assertEqual(res.winner.version, 'VER_2')

    def test_versioned_ref_unversioned_provider(self):
        # A versioned reference accepts an unversioned definition from a
        # module that has no version definitions at all.
        path = os.path.join(self.dir, 'libplain.so')
        bf.build_elf(path, soname='libplain.so',
                     symbols=[bf.sym('query', defined=True)])
        report = self.analyze(paths=[self.paths[0], path])
        res = self.find(report, 'app', 'query')
        self.assertEqual(res.winner.module, 'libplain.so')

    def test_versioned_ref_rejects_unversioned_def_in_versioned_module(self):
        path = os.path.join(self.dir, 'libmix.so')
        bf.build_elf(
            path, soname='libmix.so',
            symbols=[bf.sym('query', defined=True),          # unversioned
                     bf.sym('other', defined=True, version='VER_9')],
            verdefs=['VER_9'])
        report = self.analyze(paths=[self.paths[0], path])
        res = self.find(report, 'app', 'query')
        self.assertEqual(res.outcome, Outcome.UNRESOLVED_STRONG)


class TestReport(BindingTestBase):
    def test_render_text_mentions_evidence(self):
        report = self.analyze()
        text = render_text(report)
        self.assertIn('import adjust', text)
        self.assertIn('liboverride.so', text)
        self.assertIn('STV_PROTECTED', text)
        self.assertIn('unresolved-weak', text)
        self.assertIn('multiple-candidates', text)


if __name__ == '__main__':
    unittest.main()
