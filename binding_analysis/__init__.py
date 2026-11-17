#-------------------------------------------------------------------------------
# binding_analysis: restricted static binding analysis built on pyelftools
#
# This code is in the public domain
#-------------------------------------------------------------------------------
"""Restricted static analysis of ELF dynamic symbol binding.

Given an explicitly provided, ordered set of ELF modules, decide for every
imported (undefined) dynamic symbol whether another module in the set can
take over the binding. Purely static: nothing is loaded, executed, or
borrowed from the host.
"""

from .model import LoadedModule, SymbolEvidence
from .resolver import (
    AnalysisReport, BindingAnalyzer, Certainty, Outcome, Resolution)

__all__ = [
    'AnalysisReport', 'BindingAnalyzer', 'Certainty', 'LoadedModule',
    'Outcome', 'Resolution', 'SymbolEvidence',
]
