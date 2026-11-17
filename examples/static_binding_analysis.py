#-------------------------------------------------------------------------------
# elftools example: static_binding_analysis.py
#
# Demonstrates the restricted static binding analysis in binding_analysis/:
# given an explicitly provided, ordered set of ELF modules, decide for every
# imported dynamic symbol whether another module in the set can take over
# the binding.
#
# The demo builds a short synthetic ELF set (no compiler, no loader, no host
# libraries involved) and shows:
#   * a plain interposition ("adjust" overridden by an earlier module),
#   * a protected definition ("firmware" pinned inside libseat.so),
#   * an unresolved weak reference ("weak_hook" with no provider),
# with the actual symbol-table evidence behind every candidate.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import os
import sys
import tempfile

# For running from a source checkout without installing.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test'))

import binding_fixtures as bf
from binding_analysis import BindingAnalyzer
from binding_analysis.report import render_text


def build_demo_set(directory):
    """Create the demo modules inside `directory`; return load-order paths."""
    def path(name):
        return os.path.join(directory, name)

    bf.build_elf(
        path('app'), soname='app',
        needed=['liboverride.so', 'libseat.so', 'libver.so', 'libsym.so'],
        symbols=[
            bf.sym('adjust'),                 # provided by two libraries
            bf.sym('firmware'),               # protected inside libseat.so
            bf.sym('weak_hook', bind='WEAK'), # no provider anywhere
            bf.sym('query', version='VER_2'), # versioned reference
            bf.sym('totally_absent'),         # strong ref, no provider
        ],
        verneeds=[('libver.so', ['VER_2'])])

    bf.build_elf(
        path('liboverride.so'), soname='liboverride.so',
        symbols=[bf.sym('adjust', defined=True),
                 bf.sym('firmware', defined=True)])

    bf.build_elf(
        path('libseat.so'), soname='libseat.so',
        symbols=[bf.sym('adjust', defined=True),
                 bf.sym('firmware', defined=True, vis='PROTECTED'),
                 bf.sym('firmware'),  # self reference: pinned by PROTECTED
                 bf.sym('probe', defined=True, vis='HIDDEN'),
                 bf.sym('probe')])    # self reference: pinned by HIDDEN

    bf.build_elf(
        path('libver.so'), soname='libver.so',
        symbols=[bf.sym('query', defined=True, version='VER_2'),
                 bf.sym('query', defined=True, version='VER_1',
                        version_hidden=True)],
        verdefs=['VER_1', 'VER_2'])

    bf.build_elf(
        path('libsym.so'), soname='libsym.so', flags=bf.DF_SYMBOLIC,
        symbols=[bf.sym('adjust', defined=True),
                 bf.sym('adjust')])  # self reference: pinned by DF_SYMBOLIC

    return [path(name) for name in (
        'app', 'liboverride.so', 'libseat.so', 'libver.so', 'libsym.so')]


def main():
    with tempfile.TemporaryDirectory(prefix='binding-demo-') as directory:
        paths = build_demo_set(directory)
        print('Load order (caller-provided):')
        for p in paths:
            print('  %s' % os.path.basename(p))
        print()
        report = BindingAnalyzer(paths).analyze()
        print(render_text(report))


if __name__ == '__main__':
    main()
