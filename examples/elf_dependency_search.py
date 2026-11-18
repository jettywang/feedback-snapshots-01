#!/usr/bin/env python
#-------------------------------------------------------------------------------
# elftools example: elf_dependency_search.py
#
# Model the loader's DT_NEEDED search order without consulting a host loader.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
""" Show why the same library name can reach different candidates.

    The three-tier graph below is entirely caller-supplied.  Candidates are
    resolved by a dictionary-backed resolver; no host environment, loader
    cache, or filesystem is read.  Every probe is printed with its order,
    source, owning object, and expanded directory.

    Run it directly for the built-in graph, or with ``--test ELF`` to inspect
    one real object's dynamic tags:
"""

import sys

from elftools.elf.dependency import (
    DependencyGraph,
    DependencyNode,
    ResolutionStatus,
    SearchPolicy,
    SecureExecution,
    resolve_dependencies,
)
from elftools.elf.elffile import ELFFile


def build_graph():
    return DependencyGraph(
        'app',
        [
            # app has an RPATH and no RUNPATH, so its RPATH is inherited.
            DependencyNode(
                key='app', origin='/opt/app/bin',
                needed=('libA.so', 'libB.so'), rpath='/opt/app/rpath'),
            # libA has its own RPATH; libfoo.so is found there.
            DependencyNode(
                key='libA', origin='/opt/vendor/a/lib',
                needed=('libfoo.so',), rpath='/opt/vendor/a/rpath'),
            # libB has both tags: its RUNPATH suppresses its own RPATH, but
            # app's inherited RPATH is still searched first.
            DependencyNode(
                key='libB', origin='/opt/vendor/b/lib',
                needed=('libfoo.so',), rpath='/opt/vendor/b/rpath',
                runpath='/opt/vendor/b/runpath'),
        ],
        {
            'candidate-a/libA.so': 'libA',
            'candidate-b/libB.so': 'libB',
        },
    )


CANDIDATES = {
    ('/opt/app/rpath', 'libA.so'): 'candidate-a/libA.so',
    ('/opt/app/rpath', 'libB.so'): 'candidate-b/libB.so',
    ('/opt/vendor/a/rpath', 'libfoo.so'): 'candidate-a/libfoo.so',
    ('/opt/vendor/b/runpath', 'libfoo.so'): 'candidate-b/libfoo.so',
}


def resolver(library, directory):
    """ A caller-owned candidate resolver over a fixed in-memory mapping. """
    return CANDIDATES.get((directory, library))


def show_three_tier():
    result = resolve_dependencies(
        build_graph(), resolver,
        policy=SearchPolicy.GLIBC,
        secure_execution=SecureExecution.DISABLED)

    print(result.format_trace())
    print()
    for resolution in result.resolutions:
        if resolution.library != 'libfoo.so':
            continue
        line = f'{resolution.requester}: libfoo.so -> '
        if resolution.status is ResolutionStatus.CANDIDATE_ONLY:
            print(line + resolution.candidate)
        else:
            print(line + 'no candidate (' +
                  resolution.not_found_reason.value + ')')


def show_elf(path):
    with open(path, 'rb') as stream:
        node = DependencyNode.from_elffile(ELFFile(stream), path)
    print(f'object: {path}')
    print(f'origin: {node.origin or "(caller must supply)"}')
    print(f'needed: {list(node.needed)}')
    print(f'rpath: {node.rpath!r}')
    print(f'runpath: {node.runpath!r}')


if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == '--test':
        show_three_tier()
    elif len(sys.argv) >= 2:
        show_elf(sys.argv[1])
    else:
        show_three_tier()
