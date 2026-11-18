#-------------------------------------------------------------------------------
# elftools tests
#
# Tests for the offline ELF dependency-search model.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import os
import unittest

from elftools.common.exceptions import ELFError
from elftools.elf.dependency import (
    DependencyGraph,
    DependencyNode,
    NotFoundReason,
    PathSource,
    ResolutionStatus,
    SearchPolicy,
    SecureExecution,
    SkipReason,
    StepOutcome,
    resolve_dependencies,
)
from elftools.elf.elffile import ELFFile


def _three_tier_graph():
    """ app -> libA (RPATH), app -> libB (RUNPATH); both need libfoo.so. """
    return DependencyGraph(
        'app',
        [
            DependencyNode(
                key='app', origin='/opt/app/bin',
                needed=('libA.so', 'libB.so'), rpath='/opt/app/rpath'),
            DependencyNode(
                key='libA', origin='/opt/vendor/a/lib',
                needed=('libfoo.so',), rpath='/opt/vendor/a/rpath'),
            DependencyNode(
                key='libB', origin='/opt/vendor/b/lib',
                needed=('libfoo.so',), runpath='/opt/vendor/b/runpath'),
        ],
        {'candidate-a/libA.so': 'libA', 'candidate-b/libB.so': 'libB'},
    )


def _known_candidates():
    return {
        ('/opt/app/rpath', 'libA.so'): 'candidate-a/libA.so',
        ('/opt/app/rpath', 'libB.so'): 'candidate-b/libB.so',
        ('/opt/vendor/a/rpath', 'libfoo.so'): 'candidate-a/libfoo.so',
        ('/opt/vendor/b/runpath', 'libfoo.so'): 'candidate-b/libfoo.so',
    }


class _RecordingResolver:
    def __init__(self, candidates=None):
        self.candidates = candidates or {}
        self.calls = []

    def __call__(self, library, directory):
        self.calls.append((library, directory))
        return self.candidates.get((directory, library))


def _edge(result, requester, library):
    return next(
        resolution for resolution in result.resolutions
        if resolution.requester == requester and resolution.library == library)


class TestDependencySearchPolicies(unittest.TestCase):
    def test_three_tier_same_name_resolves_per_policy(self):
        """ The same libfoo.so request must reach different candidates. """
        result = resolve_dependencies(
            _three_tier_graph(), _RecordingResolver(_known_candidates()),
            policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)

        liba = _edge(result, 'libA', 'libfoo.so')
        libb = _edge(result, 'libB', 'libfoo.so')
        self.assertEqual(liba.candidate, 'candidate-a/libfoo.so')
        self.assertEqual(libb.candidate, 'candidate-b/libfoo.so')
        self.assertEqual(liba.status, ResolutionStatus.CANDIDATE_ONLY)
        self.assertFalse(liba.runtime_library_confirmed)

        # libB has RUNPATH, so app's inherited RPATH is still searched as a
        # transitive path; libB's own RUNPATH is searched afterwards.
        self.assertEqual(
            [(step.source, step.outcome, step.reason) for step in libb.steps],
            [
                (PathSource.INHERITED_RPATH, StepOutcome.MISS, None),
                (PathSource.OBJECT_RUNPATH, StepOutcome.HIT, None),
            ])
        self.assertEqual(
            [(step.source, step.outcome) for step in liba.steps],
            [(PathSource.OBJECT_RPATH, StepOutcome.HIT)])

    def test_rpath_only_ignores_runpath(self):
        result = resolve_dependencies(
            _three_tier_graph(), _RecordingResolver(_known_candidates()),
            policy='rpath-only',
            secure_execution=SecureExecution.DISABLED)
        libb = _edge(result, 'libB', 'libfoo.so')
        self.assertEqual(libb.candidate, None)
        self.assertEqual(
            [step.source for step in libb.steps],
            [PathSource.INHERITED_RPATH])
        self.assertEqual(libb.not_found_reason, NotFoundReason.NO_CANDIDATE)

    def test_runpath_only_does_not_inherit_rpath(self):
        graph = DependencyGraph(
            'app',
            [
                DependencyNode(
                    key='app', origin='/opt/app/bin',
                    needed=('libA.so', 'libB.so'),
                    runpath='/opt/shared/runpath'),
                DependencyNode(
                    key='libA', origin='/opt/vendor/a/lib',
                    needed=('libfoo.so',), rpath='/opt/vendor/a/rpath'),
                DependencyNode(
                    key='libB', origin='/opt/vendor/b/lib',
                    needed=('libfoo.so',), runpath='/opt/vendor/b/runpath'),
            ],
            {'candidate-a/libA.so': 'libA', 'candidate-b/libB.so': 'libB'})
        result = resolve_dependencies(
            graph,
            _RecordingResolver({
                ('/opt/shared/runpath', 'libA.so'): 'candidate-a/libA.so',
                ('/opt/shared/runpath', 'libB.so'): 'candidate-b/libB.so',
                ('/opt/vendor/b/runpath', 'libfoo.so'):
                    'candidate-b/libfoo.so',
            }),
            policy='runpath-only',
            secure_execution=SecureExecution.DISABLED)
        liba = _edge(result, 'libA', 'libfoo.so')
        self.assertEqual(liba.status, ResolutionStatus.NOT_FOUND)
        self.assertEqual(liba.steps, ())
        self.assertEqual(liba.not_found_reason, NotFoundReason.NO_SEARCH_PATH)

        libb = _edge(result, 'libB', 'libfoo.so')
        self.assertEqual(libb.candidate, 'candidate-b/libfoo.so')

    def test_relative_rpath_follows_requester_origin(self):
        graph = DependencyGraph('app', [
            DependencyNode(
                key='app', origin='/srv/app/bin', needed=('libA.so',),
                rpath='../lib'),
            DependencyNode(key='libA', origin='/srv/a/lib',
                           needed=('libz.so',), rpath='$ORIGIN/../../z'),
        ])
        resolver = _RecordingResolver(
            {('/srv/app/lib', 'libA.so'): 'libA'})
        resolve_dependencies(
            graph, resolver, policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED,
            working_directory='/srv/app/bin')
        # "libz.so" is searched after "libA"'s own RPATH entry, which uses the
        # owner origin, not the requester origin.
        self.assertEqual(
            resolver.calls,
            [('libA.so', '/srv/app/lib'),
             ('libz.so', '/srv/z'),
             ('libz.so', '/srv/app/lib')])

    def test_runpath_suppresses_only_same_object_rpath(self):
        graph = DependencyGraph('app', [
            DependencyNode(
                key='app', origin='/srv/app/bin', needed=('libA.so',),
                rpath='/srv/app/rpath'),
            DependencyNode(
                key='libA', origin='/srv/a/lib', needed=('libfoo.so',),
                rpath='/srv/a/rpath', runpath='/srv/a/runpath'),
        ])
        resolver = _RecordingResolver({
            ('/srv/app/rpath', 'libA.so'): 'libA',
        })
        result = resolve_dependencies(
            graph, resolver, policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)
        libfoo = _edge(result, 'libA', 'libfoo.so')
        self.assertEqual(
            [(step.source, step.outcome, step.reason) for step in libfoo.steps],
            [
                (PathSource.OBJECT_RPATH, StepOutcome.SKIPPED,
                 SkipReason.RPATH_SUPPRESSED_BY_RUNPATH),
                (PathSource.INHERITED_RPATH, StepOutcome.MISS, None),
                (PathSource.OBJECT_RUNPATH, StepOutcome.MISS, None),
            ])
        self.assertEqual(
            [step.directory for step in libfoo.steps],
            ['/srv/a/rpath', '/srv/app/rpath', '/srv/a/runpath'])

    def test_ancestor_runpath_suppresses_inherited_ancestor_rpath(self):
        graph = DependencyGraph('app', [
            DependencyNode(
                key='app', origin='/srv/app/bin', needed=('libA.so',),
                rpath='/srv/app/rpath', runpath='/srv/app/runpath'),
            DependencyNode(
                key='libA', origin='/srv/a/lib', needed=('libfoo.so',)),
        ])
        resolver = _RecordingResolver({
            ('/srv/app/runpath', 'libA.so'): 'libA',
        })
        result = resolve_dependencies(
            graph, resolver, policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)
        libfoo = _edge(result, 'libA', 'libfoo.so')
        self.assertEqual(
            [(step.source, step.outcome, step.reason)
             for step in libfoo.steps],
            [(PathSource.INHERITED_RPATH, StepOutcome.SKIPPED,
              SkipReason.RPATH_SUPPRESSED_BY_RUNPATH)])

    def test_inherited_origin_belongs_to_ancestor(self):
        graph = DependencyGraph('app', [
            DependencyNode(
                key='app', origin='/srv/app/bin', needed=('libA.so',),
                rpath='$ORIGIN/../lib'),
            DependencyNode(
                key='libA', origin='/srv/a/lib', needed=('libfoo.so',)),
        ])
        resolver = _RecordingResolver(
            {('/srv/app/lib', 'libA.so'): 'libA'})
        result = resolve_dependencies(
            graph, resolver, policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)
        libfoo = _edge(result, 'libA', 'libfoo.so')
        self.assertEqual(
            [(step.owner, step.owner_origin, step.resolved_directory)
             for step in libfoo.steps],
            [('app', '/srv/app/bin', '/srv/app/lib')])

    def test_secure_execution_disables_origin(self):
        graph = DependencyGraph('app', [
            DependencyNode(
                key='app', origin='/srv/app/bin', needed=('libfoo.so',),
                runpath='$ORIGIN/lib'),
        ])
        resolver = _RecordingResolver(
            {('/srv/app/bin/lib', 'libfoo.so'): 'should-not-be-used'})
        result = resolve_dependencies(
            graph, resolver, policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.ENABLED)
        libfoo = result.resolutions[0]
        self.assertEqual(libfoo.status, ResolutionStatus.NOT_FOUND)
        self.assertIsNone(libfoo.candidate)
        self.assertEqual(libfoo.not_found_reason, NotFoundReason.ALL_PATHS_SKIPPED)
        self.assertEqual(resolver.calls, [])
        self.assertEqual(libfoo.steps[0].reason,
                         SkipReason.ORIGIN_DISABLED_SECURE)


class TestDependencyGraphValidation(unittest.TestCase):
    def test_duplicate_node_is_rejected(self):
        node = DependencyNode(key='app', origin='/srv/app')
        with self.assertRaises(ELFError):
            DependencyGraph('app', [node, node])

    def test_missing_root_is_rejected(self):
        with self.assertRaises(ELFError):
            DependencyGraph('missing', [])

    def test_candidate_mapping_must_reference_a_node(self):
        with self.assertRaises(ELFError):
            DependencyGraph(
                'app',
                [DependencyNode(key='app', origin='/srv/app')],
                {'candidate/lib.so': 'missing'})

    def test_origin_must_be_absolute(self):
        with self.assertRaises(ELFError):
            DependencyNode(key='app', origin='relative/dir')

    def test_needed_string_is_rejected(self):
        with self.assertRaises(ELFError):
            DependencyNode(key='app', origin='/srv/app', needed='liba.so')


class TestDependencySearchErrors(unittest.TestCase):
    def test_unknown_policy_is_rejected_before_lookup(self):
        resolver = _RecordingResolver()
        for policy in ('glibc-latest', '', None, object()):
            with self.subTest(policy=policy):
                with self.assertRaises(ELFError):
                    resolve_dependencies(
                        _three_tier_graph(), resolver,
                        policy=policy, secure_execution=False)
        self.assertEqual(resolver.calls, [])

    def test_secure_execution_must_be_explicit(self):
        for value in ('disabled', 0, None):
            with self.subTest(value=value):
                with self.assertRaises(ELFError):
                    resolve_dependencies(
                        _three_tier_graph(), _RecordingResolver(),
                        policy=SearchPolicy.GLIBC, secure_execution=value)

    def test_missing_candidate_is_not_a_hit(self):
        resolver = _RecordingResolver(
            {('/opt/app/rpath', 'libA.so'): 'candidate-a/libA.so',
             ('/opt/app/rpath', 'libB.so'): 'candidate-b/libB.so'})
        result = resolve_dependencies(
            _three_tier_graph(), resolver, policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)
        liba = _edge(result, 'libA', 'libfoo.so')
        self.assertEqual(liba.status, ResolutionStatus.NOT_FOUND)
        self.assertIsNone(liba.candidate)
        self.assertFalse(liba.runtime_library_confirmed)
        self.assertEqual(liba.not_found_reason, NotFoundReason.NO_CANDIDATE)
        self.assertIn(('libA', 'libfoo.so'), result.unresolved)

    def test_resolver_returning_empty_string_is_rejected(self):
        graph = DependencyGraph('app', [
            DependencyNode(key='app', origin='/srv/app', needed=('x.so',),
                           runpath='/srv/lib'),
        ])
        with self.assertRaises(ELFError):
            resolve_dependencies(
                graph, lambda library, directory: '',
                policy=SearchPolicy.GLIBC,
                secure_execution=SecureExecution.DISABLED)

    def test_no_search_path_reason(self):
        graph = DependencyGraph('app', [
            DependencyNode(key='app', origin='/srv/app', needed=('x.so',)),
        ])
        result = resolve_dependencies(
            graph, _RecordingResolver(), policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)
        self.assertEqual(result.resolutions[0].not_found_reason,
                         NotFoundReason.NO_SEARCH_PATH)

    def test_relative_entry_without_working_directory_is_skipped(self):
        graph = DependencyGraph('app', [
            DependencyNode(key='app', origin='/srv/app', needed=('x.so',),
                           runpath='lib'),
        ])
        resolver = _RecordingResolver()
        result = resolve_dependencies(
            graph, resolver, policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)
        self.assertEqual(resolver.calls, [])
        self.assertEqual(result.resolutions[0].steps[0].reason,
                         SkipReason.RELATIVE_WITHOUT_WORKING_DIRECTORY)

    def test_unsupported_token_is_reported(self):
        graph = DependencyGraph('app', [
            DependencyNode(key='app', origin='/srv/app', needed=('x.so',),
                           runpath='$LIB/platform'),
        ])
        resolver = _RecordingResolver()
        result = resolve_dependencies(
            graph, resolver, policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)
        self.assertEqual(result.resolutions[0].steps[0].reason,
                         SkipReason.UNSUPPORTED_TOKEN)

    def test_direct_path_needed_is_not_modelled(self):
        graph = DependencyGraph('app', [
            DependencyNode(key='app', origin='/srv/app', needed=('/tmp/x.so',)),
        ])
        resolver = _RecordingResolver()
        result = resolve_dependencies(
            graph, resolver, policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)
        self.assertEqual(result.resolutions[0].not_found_reason,
                         NotFoundReason.DIRECT_PATH_NOT_MODELLED)
        self.assertEqual(resolver.calls, [])


class TestDependencyTrace(unittest.TestCase):
    def test_trace_contains_order_and_provenance(self):
        result = resolve_dependencies(
            _three_tier_graph(), _RecordingResolver(_known_candidates()),
            policy=SearchPolicy.GLIBC,
            secure_execution=SecureExecution.DISABLED)
        trace = result.format_trace()
        self.assertIn('not a run-time loader resolution', trace)
        self.assertIn('1. inherited-rpath owner=app', trace)
        self.assertIn('2. object-runpath owner=libB', trace)
        self.assertIn('candidate=candidate-b/libfoo.so', trace)
        self.assertLess(trace.index('libA -> libfoo.so'),
                        trace.index('libB -> libfoo.so'))


class TestDependencyNodeFromELFFile(unittest.TestCase):
    def test_reads_runpath_and_needed(self):
        path = os.path.join('test', 'testfiles_for_readelf', 'dt_flags.so.elf')
        with open(path, 'rb') as stream:
            node = DependencyNode.from_elffile(ELFFile(stream), 'dt_flags.so')
        self.assertEqual(node.needed, ('libc.so.6',))
        self.assertEqual(node.runpath, '$ORIGIN/lib')
        self.assertIsNone(node.rpath)
        self.assertEqual(node.origin, None)

    def test_reads_needed_without_section_headers(self):
        path = os.path.join(
            'test', 'testfiles_for_unittests', 'aarch64_super_stripped.elf')
        with open(path, 'rb') as stream:
            node = DependencyNode.from_elffile(ELFFile(stream), 'aarch64.elf')
        self.assertEqual(node.needed, ('libc.so.6',))


if __name__ == '__main__':
    unittest.main()
