#-------------------------------------------------------------------------------
# elftools: elf/dependency.py
#
# Offline dependency-search model for ELF review.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
""" Reproducible, offline search for the libraries named by ``DT_NEEDED``.

The dynamic loader is intentionally not consulted.  The caller supplies the
candidate resolver and, where needed, the target working directory; this module
only models the search order described by the selected :class:`SearchPolicy`.
A successful lookup therefore means that the *supplied resolver* offered a
candidate in one of the modelled directories.  It does not prove that a host
loader, loader cache, ``LD_PRELOAD``, symbol versioning, or the actual run-time
environment would select that file.

Paths are target paths and are manipulated with :mod:`posixpath` only.  No host
environment variables, loader cache, default library directories, or
filesystem entries are read.
"""
from __future__ import annotations

import posixpath
import re
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, cast

from ..common.exceptions import ELFError
from .dynamic import Dynamic

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping

    from .elffile import ELFFile


__all__ = [
    'CandidateResolver',
    'DependencyGraph',
    'DependencyNode',
    'DependencyResolution',
    'DependencySearch',
    'GraphResolution',
    'NotFoundReason',
    'PathSource',
    'ResolutionStatus',
    'SearchPolicy',
    'SearchStep',
    'SecureExecution',
    'SkipReason',
    'StepOutcome',
    'resolve_dependencies',
]


class SearchPolicy(Enum):
    """ Supported models of the RPATH/RUNPATH search order.

        Every policy starts at the object that owns the ``DT_NEEDED`` edge and
        stops after the entries described below.  ``LD_LIBRARY_PATH``, the
        loader cache, and system default directories are not modelled.

        ``GLIBC``
            DT_RUNPATH is used for the object's direct dependencies only and is
            never inherited.  DT_RPATH is used for the object's own
            dependencies and is inherited by descendants, nearest ancestor
            first.  If an object has both tags, its DT_RUNPATH suppresses its
            own DT_RPATH for that object and for its descendants.  A child's
            RUNPATH affects only the child's own RPATH entry.

        ``RPATH_ONLY``
            DT_RUNPATH is ignored.  DT_RPATH is used for the object and is
            inherited by all of its descendants.

        ``RUNPATH_ONLY``
            DT_RPATH is ignored.  DT_RUNPATH is used for the object's direct
            dependencies only and is not inherited.
    """
    GLIBC = 'glibc'
    RPATH_ONLY = 'rpath-only'
    RUNPATH_ONLY = 'runpath-only'


class SecureExecution(Enum):
    """ Caller-selected secure-execution model.

        ``ENABLED`` models the protected-execution rule that disables
        ``$ORIGIN`` expansion.  This module never decides the mode itself from
        environment variables, file ownership, or any host state.
    """
    DISABLED = 'disabled'
    ENABLED = 'enabled'


class PathSource(Enum):
    """ Provenance of a directory entry in the search order. """
    OBJECT_RPATH = 'object-rpath'
    INHERITED_RPATH = 'inherited-rpath'
    OBJECT_RUNPATH = 'object-runpath'


class StepOutcome(Enum):
    """ Result of one ordered search step. """
    HIT = 'hit'
    MISS = 'miss'
    SKIPPED = 'skipped'


class SkipReason(Enum):
    """ Why a directory entry was not passed to the resolver. """
    RPATH_SUPPRESSED_BY_RUNPATH = 'rpath-suppressed-by-runpath'
    ORIGIN_DISABLED_SECURE = 'origin-disabled-in-secure-execution'
    ORIGIN_UNAVAILABLE = 'origin-unavailable'
    UNSUPPORTED_TOKEN = 'unsupported-dynamic-token'
    EMPTY_DIRECTORY = 'empty-directory'
    RELATIVE_WITHOUT_WORKING_DIRECTORY = 'relative-without-working-directory'


class ResolutionStatus(Enum):
    """ A hit is a candidate only, never a confirmed run-time file. """
    CANDIDATE_ONLY = 'candidate-only'
    NOT_FOUND = 'not-found'


class NotFoundReason(Enum):
    """ Why no candidate was returned. """
    NO_SEARCH_PATH = 'no-search-path'
    ALL_PATHS_SKIPPED = 'all-paths-skipped'
    NO_CANDIDATE = 'no-candidate'
    DIRECT_PATH_NOT_MODELLED = 'direct-path-not-modelled'


class CandidateResolver(Protocol):
    """ Caller-provided candidate lookup.

        ``resolver(library, directory)`` returns a caller-defined candidate
        identifier (normally a path) if that directory contains a usable
        candidate, or ``None`` otherwise.  The resolver may implement any
        access policy, container view, or virtual filesystem.  This module only
        calls it with directories produced by the selected policy.
    """
    def __call__(self, library: str, directory: str, /) -> str | None: ...


@dataclass(frozen=True)
class SearchStep:
    """ One ordered directory probe, or one explicitly skipped entry.

        ``owner`` is the object whose RPATH/RUNPATH supplied the entry, and
        ``owner_origin`` is the origin used to expand ``$ORIGIN`` in it.  For
        inherited RPATH, the origin therefore belongs to the ancestor that
        defined the path, not to the requesting object.
    """
    order: int
    requester: str
    library: str
    source: PathSource
    owner: str
    owner_origin: str | None
    directory: str
    resolved_directory: str | None
    outcome: StepOutcome
    reason: SkipReason | None = None
    candidate: str | None = None


@dataclass(frozen=True)
class DependencyResolution:
    """ Candidate search for one ``requester -> library`` DT_NEEDED edge. """
    requester: str
    library: str
    status: ResolutionStatus
    candidate: str | None
    steps: tuple[SearchStep, ...]
    not_found_reason: NotFoundReason | None = None

    @property
    def runtime_library_confirmed(self) -> bool:
        """ Always ``False``; candidate discovery is not run-time resolution. """
        return False


@dataclass(frozen=True)
class GraphResolution:
    """ Ordered results for every modelled DT_NEEDED edge in a graph. """
    root: str
    policy: SearchPolicy
    secure_execution: SecureExecution
    resolutions: tuple[DependencyResolution, ...]
    loaded_objects: tuple[str, ...]
    external_candidates: tuple[str, ...]
    unresolved: tuple[tuple[str, str], ...]

    @property
    def runtime_library_confirmed(self) -> bool:
        """ Always ``False``; see :class:`DependencyResolution`. """
        return False

    def format_trace(self) -> str:
        """ Render this result as a deterministic, review-friendly trace.

            ``$`` is a dynamic-loader metacharacter, so the text spells it as
            ``[ORIGIN]`` to make the source of an expansion unambiguous.
        """
        lines = [
            'candidate search only; not a run-time loader resolution',
            f'root: {self.root}',
            f'policy: {self.policy.value}',
            f'secure-execution: {self.secure_execution.value}',
            '',
        ]
        for result in self.resolutions:
            if result.status is ResolutionStatus.CANDIDATE_ONLY:
                lines.append(
                    f'{result.requester} -> {result.library}: candidate '
                    f'{result.candidate}')
            else:
                reason = result.not_found_reason
                lines.append(
                    f'{result.requester} -> {result.library}: not found '
                    f'({reason.value if reason else "unknown"})')
            for step in result.steps:
                resolved = step.resolved_directory or '-'
                directory = _ORIGIN_RE.sub('[ORIGIN]', step.directory)
                directory = directory.replace('$', '\\$')
                detail = (
                    f'  {step.order}. {step.source.value} '
                    f'owner={step.owner} '
                    f'owner-origin={step.owner_origin or "-"} '
                    f'dir={directory} -> {resolved} '
                    f'{step.outcome.value}')
                if step.reason is not None:
                    detail += f' reason={step.reason.value}'
                if step.candidate is not None:
                    detail += f' candidate={step.candidate}'
                lines.append(detail)
            lines.append('')

        lines.append(
            'loaded objects: '
            + (', '.join(self.loaded_objects) if self.loaded_objects else '-'))
        lines.append(
            'external candidates (dependencies not modelled): '
            + (', '.join(self.external_candidates)
               if self.external_candidates else '-'))
        lines.append(
            'unresolved edges: '
            + (', '.join(f'{requester} -> {library}'
                         for requester, library in self.unresolved)
               if self.unresolved else '-'))
        return '\n'.join(lines)


@dataclass(frozen=True)
class DependencyNode:
    """ Caller-supplied metadata for one ELF object in the dependency graph.

        ``key`` is the object identity used by the graph and by resolver return
        values.  ``origin`` is the target directory used for ``$ORIGIN`` and
        must be absolute.  Both are caller data; neither is inferred from the
        host environment.
    """
    key: str
    origin: str | None = None
    needed: tuple[str, ...] = ()
    rpath: str | None = None
    runpath: str | None = None
    soname: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise ELFError('DependencyNode key must be a non-empty string')
        if self.origin is not None:
            if not isinstance(self.origin, str) or not self.origin.startswith('/'):
                raise ELFError('DependencyNode origin must be an absolute path')
        if not isinstance(self.needed, tuple):
            if isinstance(self.needed, str):
                raise ELFError('DependencyNode needed must be a sequence of names')
            object.__setattr__(self, 'needed', tuple(self.needed))
        for name in self.needed:
            if not isinstance(name, str) or not name:
                raise ELFError('DependencyNode needed entries must be non-empty strings')
        for field_name in ('rpath', 'runpath', 'soname'):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise ELFError(f'DependencyNode {field_name} must be a string or None')
        if self.origin is not None:
            normalized = posixpath.normpath(self.origin)
            if normalized != self.origin:
                object.__setattr__(self, 'origin', normalized)

    @classmethod
    def from_elffile(
        cls,
        elffile: ELFFile,
        key: str,
        origin: str | None = None,
    ) -> DependencyNode:
        """ Read ``DT_NEEDED``, ``DT_RPATH``, ``DT_RUNPATH`` and ``DT_SONAME``.

            Only the ELF dynamic tags are consulted.  ``origin`` is supplied by
            the caller.  If it is omitted and ``key`` is an absolute path, the
            objective directory of ``key`` is used; no host path is resolved.
            Passing a relative or bare ``key`` without ``origin`` leaves
            ``origin`` unset, so ``$ORIGIN`` entries will be reported as
            skipped rather than resolved against the host.
        """
        segment = next(elffile.iter_segments(type='PT_DYNAMIC'), None)
        if segment is not None:
            dynamic = cast(Dynamic, segment)
        else:
            section = elffile.get_section_by_name('.dynamic')
            if section is None:
                raise ELFError('ELF object has no dynamic table')
            dynamic = cast(Dynamic, section)

        needed: list[str] = []
        rpath = None
        runpath = None
        soname = None
        for tag in dynamic.iter_tags():
            # DynamicTag installs these attributes only for handled tags.
            tag_values = cast(Any, tag)
            tag_name = tag.entry.d_tag
            if tag_name == 'DT_NEEDED':
                needed.append(tag_values.needed)
            elif tag_name == 'DT_RPATH' and rpath is None:
                rpath = tag_values.rpath
            elif tag_name == 'DT_RUNPATH' and runpath is None:
                runpath = tag_values.runpath
            elif tag_name == 'DT_SONAME' and soname is None:
                soname = tag_values.soname

        if origin is None:
            directory = posixpath.dirname(key)
            if directory.startswith('/'):
                origin = directory

        return cls(
            key=key,
            origin=origin,
            needed=tuple(needed),
            rpath=rpath,
            runpath=runpath,
            soname=soname,
        )


class DependencyGraph:
    """ A caller-supplied graph of ELF objects keyed by node identity.

        ``node_for_candidate`` maps the values returned by the resolver to graph
        node keys.  Without such a mapping, a resolver result is still reported
        as an external candidate, but its own dependencies cannot be modelled.
    """
    def __init__(
        self,
        root: str,
        nodes: Iterable[DependencyNode],
        node_for_candidate: Mapping[str, str] | None = None,
    ) -> None:
        self.root = root
        self._nodes: dict[str, DependencyNode] = {}
        for node in nodes:
            if node.key in self._nodes:
                raise ELFError(f'Duplicate dependency node: {node.key!r}')
            self._nodes[node.key] = node
        if root not in self._nodes:
            raise ELFError(f'Dependency graph root is missing: {root!r}')
        self._node_for_candidate = dict(node_for_candidate or {})
        for candidate, key in self._node_for_candidate.items():
            if key not in self._nodes:
                raise ELFError(
                    f'Candidate mapping refers to missing node: {key!r}')

    def __contains__(self, key: object) -> bool:
        return key in self._nodes

    def __iter__(self) -> Iterator[str]:
        return iter(self._nodes)

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def nodes(self) -> Mapping[str, DependencyNode]:
        """ Read-only view of the graph's nodes. """
        return self._nodes

    def get(self, key: str) -> DependencyNode:
        """ Return a node by key, raising a descriptive error if absent. """
        try:
            return self._nodes[key]
        except KeyError:
            raise ELFError(f'Dependency node is missing: {key!r}') from None

    def node_key_for_candidate(self, candidate: str) -> str | None:
        """ Map a resolver candidate to a graph node key, if modelled. """
        return self._node_for_candidate.get(candidate)


@dataclass(frozen=True)
class _PathEntry:
    raw: str
    source: PathSource
    owner: str
    owner_origin: str | None
    skip_reason: SkipReason | None = None


_ORIGIN_RE = re.compile(r'\$(?:\{ORIGIN\}|ORIGIN(?![A-Za-z0-9_]))')
_DYNAMIC_TOKEN_RE = re.compile(r'\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)')


def _coerce_policy(policy: SearchPolicy | str) -> SearchPolicy:
    if isinstance(policy, SearchPolicy):
        return policy
    if isinstance(policy, str):
        try:
            return SearchPolicy(policy)
        except ValueError:
            pass
    raise ELFError(
        f'Unsupported dependency search policy: {policy!r}; '
        f'expected one of {[candidate.value for candidate in SearchPolicy]}')


def _coerce_secure_execution(
    secure_execution: SecureExecution | bool,
) -> SecureExecution:
    if isinstance(secure_execution, SecureExecution):
        return secure_execution
    if isinstance(secure_execution, bool):
        return SecureExecution.ENABLED if secure_execution else SecureExecution.DISABLED
    raise ELFError(
        f'Unsupported secure-execution setting: {secure_execution!r}; '
        'expected SecureExecution or bool')


class DependencySearch:
    """ Resolve a :class:`DependencyGraph` using an explicit search policy.

        ``policy`` and ``secure_execution`` are required keyword arguments so a
        caller cannot accidentally inherit a host loader's policy or security
        mode.  No implicit directory, loader cache, or environment variable is
        added.  Relative RPATH/RUNPATH entries require an explicit absolute
        ``working_directory``; without one they are skipped, not resolved
        against the host process directory.
    """
    def __init__(
        self,
        graph: DependencyGraph,
        resolver: CandidateResolver,
        *,
        policy: SearchPolicy | str,
        secure_execution: SecureExecution | bool,
        working_directory: str | None = None,
    ) -> None:
        if working_directory is not None and not working_directory.startswith('/'):
            raise ELFError('working_directory must be an absolute target path')
        self.graph = graph
        self.resolver = resolver
        self.policy = _coerce_policy(policy)
        self.secure_execution = _coerce_secure_execution(secure_execution)
        self.working_directory = working_directory

    def resolve(self) -> GraphResolution:
        """ Resolve all reachable DT_NEEDED edges in deterministic BFS order. """
        queue: deque[tuple[str, tuple[str, ...]]] = deque(
            [(self.graph.root, (self.graph.root,))])
        loaded: list[str] = []
        loaded_set: set[str] = set()
        resolutions: list[DependencyResolution] = []
        external: list[str] = []
        external_set: set[str] = set()
        unresolved: list[tuple[str, str]] = []

        while queue:
            key, chain = queue.popleft()
            if key in loaded_set:
                continue
            loaded.append(key)
            loaded_set.add(key)

            for library in self.graph.get(key).needed:
                result = self._resolve_edge(key, chain, library)
                resolutions.append(result)
                candidate = result.candidate
                if candidate is None:
                    unresolved.append((key, library))
                    continue
                node_key = self.graph.node_key_for_candidate(candidate)
                if node_key is None and candidate in self.graph:
                    node_key = candidate
                if node_key is not None:
                    if node_key not in loaded_set:
                        queue.append((node_key, chain + (node_key,)))
                elif candidate not in external_set:
                    external.append(candidate)
                    external_set.add(candidate)

        return GraphResolution(
            root=self.graph.root,
            policy=self.policy,
            secure_execution=self.secure_execution,
            resolutions=tuple(resolutions),
            loaded_objects=tuple(loaded),
            external_candidates=tuple(external),
            unresolved=tuple(unresolved),
        )

    def _resolve_edge(
        self,
        requester: str,
        chain: tuple[str, ...],
        library: str,
    ) -> DependencyResolution:
        if '/' in library:
            return DependencyResolution(
                requester=requester,
                library=library,
                status=ResolutionStatus.NOT_FOUND,
                candidate=None,
                steps=(),
                not_found_reason=NotFoundReason.DIRECT_PATH_NOT_MODELLED,
            )

        steps: list[SearchStep] = []
        for entry in self._ordered_entries(requester, chain):
            order = len(steps) + 1
            if entry.skip_reason is not None:
                steps.append(self._step(
                    order, requester, library, entry, None,
                    StepOutcome.SKIPPED, reason=entry.skip_reason))
                continue

            resolved, reason = self._expand_entry(entry)
            if reason is not None:
                steps.append(self._step(
                    order, requester, library, entry, None,
                    StepOutcome.SKIPPED, reason=reason))
                continue
            assert resolved is not None

            candidate = self.resolver(library, resolved)
            if candidate is not None:
                if not isinstance(candidate, str) or not candidate:
                    raise ELFError(
                        f'Candidate resolver returned an invalid candidate for '
                        f'{library!r} in {resolved!r}: {candidate!r}')
                steps.append(self._step(
                    order, requester, library, entry, resolved,
                    StepOutcome.HIT, candidate=candidate))
                return DependencyResolution(
                    requester=requester,
                    library=library,
                    status=ResolutionStatus.CANDIDATE_ONLY,
                    candidate=candidate,
                    steps=tuple(steps),
                )
            steps.append(self._step(
                order, requester, library, entry, resolved, StepOutcome.MISS))

        if not steps:
            not_found_reason = NotFoundReason.NO_SEARCH_PATH
        elif all(step.outcome is StepOutcome.SKIPPED for step in steps):
            not_found_reason = NotFoundReason.ALL_PATHS_SKIPPED
        else:
            not_found_reason = NotFoundReason.NO_CANDIDATE

        return DependencyResolution(
            requester=requester,
            library=library,
            status=ResolutionStatus.NOT_FOUND,
            candidate=None,
            steps=tuple(steps),
            not_found_reason=not_found_reason,
        )

    def _ordered_entries(
        self,
        requester: str,
        chain: tuple[str, ...],
    ) -> Iterator[_PathEntry]:
        node = self.graph.get(requester)
        ancestors = [self.graph.get(key) for key in reversed(chain[:-1])]

        if self.policy is SearchPolicy.RUNPATH_ONLY:
            yield from self._split_entries(
                node.runpath, PathSource.OBJECT_RUNPATH, node)
            return

        if self.policy is SearchPolicy.RPATH_ONLY:
            yield from self._split_entries(
                node.rpath, PathSource.OBJECT_RPATH, node)
            for ancestor in ancestors:
                yield from self._split_entries(
                    ancestor.rpath, PathSource.INHERITED_RPATH, ancestor)
            return

        if node.runpath is not None and node.rpath is not None:
            yield _PathEntry(
                node.rpath, PathSource.OBJECT_RPATH, node.key, node.origin,
                SkipReason.RPATH_SUPPRESSED_BY_RUNPATH)
        elif node.runpath is None:
            yield from self._split_entries(
                node.rpath, PathSource.OBJECT_RPATH, node)

        for ancestor in ancestors:
            if ancestor.runpath is not None and ancestor.rpath is not None:
                yield _PathEntry(
                    ancestor.rpath, PathSource.INHERITED_RPATH,
                    ancestor.key, ancestor.origin,
                    SkipReason.RPATH_SUPPRESSED_BY_RUNPATH)
            elif ancestor.runpath is None:
                yield from self._split_entries(
                    ancestor.rpath, PathSource.INHERITED_RPATH, ancestor)

        yield from self._split_entries(
            node.runpath, PathSource.OBJECT_RUNPATH, node)

    @staticmethod
    def _split_entries(
        value: str | None,
        source: PathSource,
        owner: DependencyNode,
    ) -> Iterator[_PathEntry]:
        if value is None:
            return
        for raw in value.split(':'):
            yield _PathEntry(raw, source, owner.key, owner.origin)

    def _expand_entry(self, entry: _PathEntry) -> tuple[str | None, SkipReason | None]:
        raw = entry.raw
        if raw == '':
            return None, SkipReason.EMPTY_DIRECTORY

        token_scan = raw
        if _ORIGIN_RE.search(raw):
            if self.secure_execution is SecureExecution.ENABLED:
                return None, SkipReason.ORIGIN_DISABLED_SECURE
            if entry.owner_origin is None:
                return None, SkipReason.ORIGIN_UNAVAILABLE
            expanded = _ORIGIN_RE.sub(entry.owner_origin, raw)
            token_scan = _ORIGIN_RE.sub('', raw)
        else:
            expanded = raw

        if _DYNAMIC_TOKEN_RE.search(token_scan):
            return None, SkipReason.UNSUPPORTED_TOKEN

        if not expanded.startswith('/'):
            if self.working_directory is None:
                return None, SkipReason.RELATIVE_WITHOUT_WORKING_DIRECTORY
            expanded = posixpath.join(self.working_directory, expanded)

        return posixpath.normpath(expanded), None

    @staticmethod
    def _step(
        order: int,
        requester: str,
        library: str,
        entry: _PathEntry,
        resolved: str | None,
        outcome: StepOutcome,
        *,
        reason: SkipReason | None = None,
        candidate: str | None = None,
    ) -> SearchStep:
        return SearchStep(
            order=order,
            requester=requester,
            library=library,
            source=entry.source,
            owner=entry.owner,
            owner_origin=entry.owner_origin,
            directory=entry.raw,
            resolved_directory=resolved,
            outcome=outcome,
            reason=reason,
            candidate=candidate,
        )


def resolve_dependencies(
    graph: DependencyGraph,
    resolver: CandidateResolver,
    *,
    policy: SearchPolicy | str,
    secure_execution: SecureExecution | bool,
    working_directory: str | None = None,
) -> GraphResolution:
    """ Resolve ``graph`` with an explicitly supplied policy and security mode.

        Unknown policies and unknown secure-execution values raise
        :class:`~elftools.common.exceptions.ELFError` before any resolver call.
        A result marked ``CANDIDATE_ONLY`` is not a claim about the library an
        actual loader would use.
    """
    return DependencySearch(
        graph,
        resolver,
        policy=policy,
        secure_execution=secure_execution,
        working_directory=working_directory,
    ).resolve()
