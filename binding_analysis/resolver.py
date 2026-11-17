#-------------------------------------------------------------------------------
# binding_analysis: restricted static binding analysis built on pyelftools
#
# This code is in the public domain
#-------------------------------------------------------------------------------
"""Restricted static resolution of dynamic symbol imports.

The model is deliberately restricted:

* The module set and its load order are provided explicitly by the caller;
  the analyzer never discovers dependencies on its own and never loads or
  executes anything.
* Scope lookup follows the given order (first definition wins), with the
  documented ELF exceptions: DF_SYMBOLIC and caller-declared RTLD_DEEPBIND
  search the referencing module first, and STV_PROTECTED / STV_HIDDEN /
  STV_INTERNAL definitions pin references issued by the defining module.
* GNU symbol versioning is honored: versioned references require a matching
  non-hidden version definition, or an unversioned definition in a module
  that carries no version definitions at all; unversioned references ignore
  hidden (non-default) versions.
* Anything the static model cannot decide (no provider inside the modeled
  set, weak references left unresolved, missing DT_NEEDED modules) is
  reported as POLICY_DEPENDENT instead of being guessed.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .model import LOCAL_VISIBILITIES, LoadedModule, SymbolEvidence


class Certainty(enum.Enum):
    DEFINITE = 'definite'
    MULTIPLE_CANDIDATES = 'multiple-candidates'
    POLICY_DEPENDENT = 'policy-dependent'


class Outcome(enum.Enum):
    PINNED_LOCAL = 'pinned-local'          # protected/hidden/symbolic self-bind
    UNIQUE_PROVIDER = 'unique-provider'    # exactly one candidate in scope
    CONTESTED = 'contested'                # several modules provide the symbol
    UNRESOLVED_WEAK = 'unresolved-weak'    # weak ref, no provider: binds to 0
    UNRESOLVED_STRONG = 'unresolved-strong'  # no provider in the modeled set


@dataclass
class Resolution:
    """Binding decision for one undefined dynamic symbol of one module."""
    module: str
    symbol: SymbolEvidence
    outcome: Outcome
    certainty: Certainty
    # True  -> another module can/does take over this import
    # False -> statically pinned
    # None  -> cannot be decided under the modeled policy
    replaceable: bool | None
    winner: SymbolEvidence | None
    candidates: list[SymbolEvidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class AnalysisReport:
    resolutions: list[Resolution]
    scope_notes: list[str]

    def for_module(self, name: str) -> list[Resolution]:
        return [r for r in self.resolutions if r.module == name]


class BindingAnalyzer:
    """Resolve imports of an explicitly ordered set of ELF modules."""

    def __init__(self, paths, deepbind_modules=()):
        self.modules = [LoadedModule.from_path(p) for p in paths]
        deepbind = set(deepbind_modules)
        for module in self.modules:
            if module.name in deepbind or module.path in deepbind:
                module.deepbind = True
        self.scope_notes = []
        known = {m.name for m in self.modules}
        for module in self.modules:
            for dep in module.needed:
                if dep not in known:
                    self.scope_notes.append(
                        '%s: DT_NEEDED %s is not in the provided module set; '
                        'symbols it may define are unmodeled'
                        % (module.name, dep))

    def analyze(self) -> AnalysisReport:
        resolutions = []
        for module in self.modules:
            for ref in module.refs:
                resolutions.append(self.resolve(module, ref))
        return AnalysisReport(resolutions, list(self.scope_notes))

    def resolve(self, module: LoadedModule,
                ref: SymbolEvidence) -> Resolution:
        notes = list(module.notes)
        self_defs = module.defs.get(ref.name, [])

        # 1. Definitions that pin the reference inside the defining module.
        for definition in self_defs:
            if definition.visibility in LOCAL_VISIBILITIES:
                return Resolution(
                    module.name, ref, Outcome.PINNED_LOCAL,
                    Certainty.DEFINITE, False, definition, [definition],
                    notes + ['%s definition is not exported; the reference '
                             'cannot be interposed' % definition.visibility])
        for definition in self_defs:
            if definition.visibility == 'STV_PROTECTED':
                return Resolution(
                    module.name, ref, Outcome.PINNED_LOCAL,
                    Certainty.DEFINITE, False, definition, [definition],
                    notes + ['STV_PROTECTED definitions cannot be interposed '
                             'for references issued by the defining module'])
        if (module.symbolic or module.deepbind) and self_defs:
            definition = self_defs[0]
            reason = ('DF_SYMBOLIC' if module.symbolic
                      else 'RTLD_DEEPBIND (caller-declared)')
            if module.deepbind:
                notes.append('RTLD_DEEPBIND is a dlopen-time flag; only its '
                             'self-first lookup effect is modeled, dlopen '
                             'group scoping is not')
            return Resolution(
                module.name, ref, Outcome.PINNED_LOCAL,
                Certainty.DEFINITE, False, definition, [definition],
                notes + ['%s: own definitions are searched first' % reason])

        # 2. Scope search in caller-provided load order.
        candidates = []
        rejected = []
        for other in self.modules:
            for definition in other.defs.get(ref.name, []):
                if definition.visibility in LOCAL_VISIBILITIES:
                    continue
                if _version_matches(ref, definition, other):
                    candidates.append(definition)
                else:
                    rejected.append(definition)
        if rejected:
            notes.append('%d definition(s) rejected by version rules: %s'
                         % (len(rejected),
                            ', '.join('%s (version %s)' % (d.module, d.version)
                                      for d in rejected)))

        # 3. Classify.
        if not candidates:
            if ref.binding == 'STB_WEAK':
                return Resolution(
                    module.name, ref, Outcome.UNRESOLVED_WEAK,
                    Certainty.POLICY_DEPENDENT, None, None, [],
                    notes + ['no provider in the modeled set; a weak '
                             'reference binds to 0 unless runtime policy '
                             '(e.g. LD_DYNAMIC_WEAK, later dlopen) supplies '
                             'a definition'])
            return Resolution(
                module.name, ref, Outcome.UNRESOLVED_STRONG,
                Certainty.POLICY_DEPENDENT, None, None, [],
                notes + ['no provider in the modeled set; resolution depends '
                         'on modules outside the provided load order'])
        if len({c.module for c in candidates}) == 1 and len(candidates) == 1:
            return Resolution(
                module.name, ref, Outcome.UNIQUE_PROVIDER,
                Certainty.DEFINITE, False, candidates[0], candidates, notes)
        winner = candidates[0]
        contested_notes = notes + [
            'winner follows the caller-provided load order; any module '
            'defining the symbol earlier in that order takes over the import']
        return Resolution(
            module.name, ref, Outcome.CONTESTED,
            Certainty.MULTIPLE_CANDIDATES, True, winner, candidates,
            contested_notes)


def _version_matches(ref: SymbolEvidence, definition: SymbolEvidence,
                     def_module: LoadedModule) -> bool:
    """Restricted GNU version matching between a reference and a definition."""
    if ref.version is None:
        # Unversioned reference: matches unversioned definitions and default
        # (non-hidden) versions only.
        return definition.version is None or not definition.version_hidden
    # Versioned reference.
    if definition.version is not None:
        return (definition.version == ref.version
                and not definition.version_hidden)
    # Unversioned definition satisfies a versioned reference only when the
    # defining module carries no version definitions at all.
    return not def_module.has_verdefs
