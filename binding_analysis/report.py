#-------------------------------------------------------------------------------
# binding_analysis: restricted static binding analysis built on pyelftools
#
# This code is in the public domain
#-------------------------------------------------------------------------------
"""Human-readable rendering of a binding AnalysisReport."""

from __future__ import annotations

from .resolver import AnalysisReport, Certainty, Outcome

_REPLACEABLE_TEXT = {
    True: 'yes - another module can take over this import',
    False: 'no - statically pinned',
    None: 'undecided - depends on unmodeled loading policy',
}


def render_text(report: AnalysisReport) -> str:
    lines = []
    if report.scope_notes:
        lines.append('Scope notes:')
        for note in report.scope_notes:
            lines.append('  ! %s' % note)
        lines.append('')
    current_module = None
    for res in report.resolutions:
        if res.module != current_module:
            current_module = res.module
            lines.append('Module %s' % current_module)
        lines.append('  import %s (%s)' % (
            res.symbol.name, res.symbol.describe().split(': ', 1)[1]))
        lines.append('    outcome:    %s [%s]' % (
            res.outcome.value, res.certainty.value))
        lines.append('    replaceable: %s' % _REPLACEABLE_TEXT[res.replaceable])
        if res.winner is not None:
            lines.append('    winner:      %s' % res.winner.describe())
        if res.candidates:
            lines.append('    candidates:')
            for candidate in res.candidates:
                marker = ' (winner)' if candidate is res.winner else ''
                lines.append('      - %s%s' % (candidate.describe(), marker))
        for note in res.notes:
            lines.append('    note: %s' % note)
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'
