#-------------------------------------------------------------------------------
# elftools: dwarf/provenance.py
#
# Explicit provenance for DWARF attributes that may be inherited through
# DW_AT_abstract_origin and DW_AT_specification references.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
"""Resolve DWARF attributes without collapsing away where they came from.

A debugging information entry often does not contain every attribute needed to
describe the entity it represents.  A concrete inlined instance, for example,
normally gets its name from its ``DW_AT_abstract_origin``, and that abstract
instance may in turn get declaration information from a ``DW_AT_specification``
reference.  A definition can also be split across compilation units, or a
reference can point into an already bound supplementary debug object.

The resolver in this module follows those references one attribute at a time.
It returns a :class:`ResolvedAttribute` carrying both the effective value and
the exact chain of DIE references that produced it.  DIEs themselves are never
modified, and unresolved situations are represented explicitly rather than
being hidden behind the first value found.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from .die import AttributeValue, DIE
    from .dwarfinfo import DWARFInfo


__all__ = [
    'AttributeCandidate',
    'AttributeProvenance',
    'DIEAttributeResolver',
    'DIEIdentity',
    'DIEProvenanceResolver',
    'ProvenanceResolver',
    'ProvenanceResult',
    'ProvenanceStatus',
    'ReferenceLink',
    'ResolvedAttribute',
    'UnitIdentity',
    'attribute_provenance',
    'get_attribute_provenance',
    'get_unit_identity',
    'resolve_attribute',
    'resolve_attribute_provenance',
    'resolve_attributes',
    'resolve_die_attribute',
]


# The order is significant: a direct attribute wins over anything inherited,
# and an abstract instance is more specific than the declaration reached
# through its specification.
LINK_PRECEDENCE = ('DW_AT_abstract_origin', 'DW_AT_specification')
_ABSTRACT_ORIGIN = 'DW_AT_abstract_origin'
_SPECIFICATION = 'DW_AT_specification'

_REFERENCE_FORMS = frozenset({
    'DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8',
    'DW_FORM_ref', 'DW_FORM_ref_udata', 'DW_FORM_ref_addr',
    'DW_FORM_ref_sig8', 'DW_FORM_ref_sup4', 'DW_FORM_ref_sup8',
    'DW_FORM_GNU_ref_alt',
})

# DWARF 5 section 2.13.2: these attributes of the referenced declaration do
# not apply to the referring entry.  They are structural/marking attributes,
# not information that completes the declaration.
_NOT_INHERITED_FROM_SPECIFICATION = frozenset({
    'DW_AT_declaration',
    'DW_AT_sibling',
})


class ProvenanceStatus(StrEnum):
    """Outcome of resolving one attribute.

    ``DIRECT`` and ``INHERITED`` are the resolved outcomes.  The remaining
    values are explicit unresolved outcomes and are never replaced with a
    value from a different reference chain.
    """

    DIRECT = 'direct'
    INHERITED = 'inherited'
    MISSING = 'missing'
    BROKEN_REFERENCE = 'broken_reference'
    CYCLE = 'cycle'
    CONFLICT = 'conflict'

    # Descriptive aliases for consumers that spell the resolved outcomes out.
    RESOLVED_DIRECT = 'direct'
    RESOLVED_INHERITED = 'inherited'
    UNRESOLVED_MISSING = 'missing'
    UNRESOLVED_BROKEN_REFERENCE = 'broken_reference'
    UNRESOLVED_CYCLE = 'cycle'
    UNRESOLVED_CONFLICT = 'conflict'

    @property
    def is_resolved(self) -> bool:
        return self in (ProvenanceStatus.DIRECT, ProvenanceStatus.INHERITED)

    @property
    def is_unresolved(self) -> bool:
        return not self.is_resolved


@dataclass(frozen=True)
class UnitIdentity:
    """Identity of one compile or type unit.

    ``kind`` is ``"CU"`` or ``"TU"``.  ``container_id`` keeps units from
    different ``DWARFInfo`` objects (including a primary file and its bound
    supplementary debug object) distinct even when they have the same offset.
    The container object itself is retained for callers but not included in
    equality, hashing, or repr.
    """

    kind: str
    unit_offset: int
    section: str | None
    is_supplementary: bool
    container_id: int = field(default=0, repr=False)
    dwarfinfo: DWARFInfo | Any = field(
        default=None, compare=False, hash=False, repr=False)

    @property
    def unit_kind(self) -> str:
        return 'compile_unit' if self.kind == 'CU' else 'type_unit'

    @property
    def cu_offset(self) -> int:
        return self.unit_offset

    @property
    def tu_offset(self) -> int:
        return self.unit_offset

    @property
    def unit_type(self) -> str:
        return self.kind

    @property
    def identity(self) -> tuple[str, int, int]:
        """Compact tuple distinguishing container, kind, and unit offset."""
        return (self.kind, self.container_id, self.unit_offset)

    @property
    def label(self) -> str:
        """Human-readable unit label for reports."""
        suffix = ' (supplementary)' if self.is_supplementary else ''
        return (
            f'{self.kind} 0x{self.unit_offset:x} in '
            f'{self.section or "unknown section"}{suffix}')

    def __str__(self) -> str:
        return self.label


@dataclass(frozen=True)
class DIEIdentity:
    """Stable location of a DIE, including the identity of its unit."""

    unit: UnitIdentity
    offset: int

    @property
    def unit_offset(self) -> int:
        return self.unit.unit_offset

    @property
    def cu_offset(self) -> int:
        return self.unit.unit_offset

    @property
    def tu_offset(self) -> int:
        return self.unit.unit_offset

    @property
    def kind(self) -> str:
        return self.unit.kind

    @property
    def is_supplementary(self) -> bool:
        return self.unit.is_supplementary

    @property
    def section(self) -> str | None:
        return self.unit.section

    @property
    def label(self) -> str:
        return f'{self.unit.label}, DIE 0x{self.offset:x}'

    def __str__(self) -> str:
        return self.label


@dataclass(frozen=True)
class ReferenceLink:
    """One reference traversed while resolving an attribute."""

    attribute: str
    form: str
    raw_value: Any
    source: DIEIdentity
    target: DIEIdentity | None
    error: str | None = None

    @property
    def kind(self) -> str:
        if self.attribute == _ABSTRACT_ORIGIN:
            return 'abstract_origin'
        if self.attribute == _SPECIFICATION:
            return 'specification'
        return 'reference'

    @property
    def source_die(self) -> DIEIdentity:
        return self.source

    @property
    def target_die(self) -> DIEIdentity | None:
        return self.target

    @property
    def source_unit(self) -> UnitIdentity:
        return self.source.unit

    @property
    def target_unit(self) -> UnitIdentity | None:
        return self.target.unit if self.target is not None else None


@dataclass(frozen=True)
class AttributeCandidate:
    """A branch explored while resolving an attribute.

    Candidates preserve the chain explored even when that branch did not win
    or could not be resolved.  This is what keeps a missing reference, a
    conflict, or a cycle visible to the caller.
    """

    status: ProvenanceStatus
    value: Any
    source: DIEIdentity | None
    chain: tuple[ReferenceLink, ...]
    reason: str | None = None
    candidates: tuple[AttributeCandidate, ...] = ()

    @property
    def is_resolved(self) -> bool:
        return self.status.is_resolved

    @property
    def reference_chain(self) -> tuple[ReferenceLink, ...]:
        return self.chain


@dataclass(frozen=True)
class ResolvedAttribute:
    """The effective value of an attribute together with its provenance.

    ``chain`` is the chain adopted for ``value``.  For a direct attribute it
    is empty.  ``candidates`` contains every top-level branch that was
    examined, including branches that were shadowed by a direct value or that
    ended in a missing reference, conflict, or cycle.
    """

    name: str
    status: ProvenanceStatus
    value: Any
    root: DIEIdentity
    source: DIEIdentity | None = None
    chain: tuple[ReferenceLink, ...] = ()
    attribute: AttributeValue | None = None
    candidates: tuple[AttributeCandidate, ...] = ()
    reason: str | None = None

    @property
    def is_resolved(self) -> bool:
        return self.status.is_resolved

    @property
    def is_direct(self) -> bool:
        return self.status == ProvenanceStatus.DIRECT

    @property
    def is_inherited(self) -> bool:
        return self.status == ProvenanceStatus.INHERITED

    @property
    def source_die(self) -> DIEIdentity | None:
        return self.source

    @property
    def source_unit(self) -> UnitIdentity | None:
        return self.source.unit if self.source is not None else None

    @property
    def reference_chain(self) -> tuple[ReferenceLink, ...]:
        return self.chain

    @property
    def provenance(self) -> tuple[ReferenceLink, ...]:
        return self.chain

    @property
    def adopted_chain(self) -> tuple[ReferenceLink, ...]:
        return self.chain

    @property
    def alternatives(self) -> tuple[AttributeCandidate, ...]:
        return self.candidates

    @property
    def origin(self) -> str:
        """Short description of where the value came from.

        ``"direct"`` for a directly present attribute, otherwise the first
        reference attribute followed (for example ``"DW_AT_abstract_origin"``).
        For unresolved results the status value is returned.
        """
        if self.status == ProvenanceStatus.DIRECT:
            return 'direct'
        if self.chain:
            return self.chain[0].attribute
        return self.status.value

    @property
    def source_kind(self) -> str:
        if self.status == ProvenanceStatus.DIRECT:
            return 'direct'
        if self.chain:
            return self.chain[0].kind
        return self.status.value

    @property
    def unresolved_candidates(self) -> tuple[AttributeCandidate, ...]:
        """Failed branches, including branches shadowed by a direct value."""
        return tuple(
            failure
            for candidate in self.candidates
            for failure in _all_failures(candidate))

    @property
    def has_unresolved_branches(self) -> bool:
        return bool(self.unresolved_candidates)


# Friendly names for consumers that prefer the broader terms.
AttributeProvenance = ResolvedAttribute
ProvenanceResult = ResolvedAttribute


def _all_failures(candidate: AttributeCandidate) -> Iterator[AttributeCandidate]:
    """Yield the candidate and every failed candidate nested under it."""
    if candidate.status.is_unresolved:
        yield candidate
    for nested in candidate.candidates:
        yield from _all_failures(nested)


class DIEProvenanceResolver:
    """Resolve attributes across abstract-origin and specification chains.

    The resolver is read-only with respect to DIEs.  It can be reused for many
    queries and can optionally be given a custom reference resolver, which is
    useful for consumers that supply their own DIE repository.
    """

    def __init__(
        self,
        dwarfinfo: DWARFInfo | None = None,
        *,
        reference_resolver: Callable[[DIE, str], DIE] | None = None,
    ) -> None:
        self._dwarfinfo = dwarfinfo
        self._reference_resolver = reference_resolver

    # -- public API ---------------------------------------------------

    def resolve(self, die: DIE, name: str) -> ResolvedAttribute:
        """Resolve one attribute of ``die``.

        Returns a result for every outcome; this method does not raise for a
        missing attribute, an unresolvable reference, a conflict, or a cycle.
        """
        root = self.identify(die)
        return self._resolve_from(
            die=die,
            name=name,
            root=root,
            chain=(),
            visiting=frozenset({root}),
        )

    def resolve_many(
        self,
        die: DIE,
        names: Iterable[str] | None = None,
        *,
        include_links: bool = False,
    ) -> dict[str, ResolvedAttribute]:
        """Resolve several attributes, or all reachable attributes.

        When ``names`` is None, attribute names reachable through the
        reference graph are used.  The reference attributes themselves are
        omitted unless ``include_links`` is true.
        """
        if names is None:
            names = self.attribute_names(die, include_links=include_links)
        return {name: self.resolve(die, name) for name in names}

    def attribute_names(
        self,
        die: DIE,
        *,
        include_links: bool = False,
    ) -> tuple[str, ...]:
        """Return names available directly or through referenced DIEs.

        The order follows the root DIE's attribute order and then the
        reference graph in precedence order.  The traversal is cycle-safe.
        """
        names: list[str] = []
        seen_names: set[str] = set()
        seen_dies: set[DIEIdentity] = set()

        def add_name(name: str) -> None:
            if name in seen_names:
                return
            if not include_links and name in LINK_PRECEDENCE:
                return
            seen_names.add(name)
            names.append(name)

        def visit(current: DIE) -> None:
            identity = self.identify(current)
            if identity in seen_dies:
                return
            seen_dies.add(identity)
            for attr_name in current.attributes:
                add_name(str(attr_name))
            for link_name in LINK_PRECEDENCE:
                attr = current.attributes.get(link_name)
                if attr is None:
                    continue
                target, _ = self._target_for(current, link_name, attr)
                if target is not None:
                    visit(target)

        visit(die)
        return tuple(names)

    def identify(self, die: DIE) -> DIEIdentity:
        """Return the unit-aware identity of ``die``."""
        return DIEIdentity(unit=self.unit_identity(die), offset=die.offset)

    def unit_identity(self, die: DIE) -> UnitIdentity:
        """Return the identity of the compile/type unit owning ``die``."""
        return self._unit_identity_for_die(die)

    # -- resolution ---------------------------------------------------

    def _resolve_from(
        self,
        die: DIE,
        name: str,
        root: DIEIdentity,
        chain: tuple[ReferenceLink, ...],
        visiting: frozenset[DIEIdentity],
    ) -> ResolvedAttribute:
        here = self.identify(die)
        direct_attr = die.attributes.get(name)

        if direct_attr is not None:
            status = ProvenanceStatus.DIRECT if not chain else ProvenanceStatus.INHERITED
            candidates = self._branches(
                die=die,
                name=name,
                root=root,
                chain=chain,
                visiting=visiting,
            )
            if candidates:
                reason = 'direct attribute shadows inherited candidates'
            else:
                reason = None
            return ResolvedAttribute(
                name=name,
                status=status,
                value=direct_attr.value,
                root=root,
                source=here,
                chain=chain,
                attribute=direct_attr,
                candidates=candidates,
                reason=reason,
            )

        branches = self._branches(
            die=die,
            name=name,
            root=root,
            chain=chain,
            visiting=visiting,
        )
        if not branches:
            return ResolvedAttribute(
                name=name,
                status=ProvenanceStatus.MISSING,
                value=None,
                root=root,
                chain=chain,
                reason='attribute is not present in the DIE or any reachable declaration',
            )

        return self._combine(name=name, root=root, branches=branches)

    def _branches(
        self,
        die: DIE,
        name: str,
        root: DIEIdentity,
        chain: tuple[ReferenceLink, ...],
        visiting: frozenset[DIEIdentity],
    ) -> tuple[AttributeCandidate, ...]:
        candidates: list[AttributeCandidate] = []
        for link_name in LINK_PRECEDENCE:
            attr = die.attributes.get(link_name)
            if attr is None:
                continue
            target, error = self._target_for(die, link_name, attr)
            link = ReferenceLink(
                attribute=link_name,
                form=attr.form,
                raw_value=attr.raw_value,
                source=self.identify(die),
                target=self.identify(target) if target is not None else None,
                error=error,
            )
            next_chain = chain + (link,)

            if error is not None or target is None:
                candidates.append(AttributeCandidate(
                    status=ProvenanceStatus.BROKEN_REFERENCE,
                    value=None,
                    source=None,
                    chain=next_chain,
                    reason=error or 'reference has no target',
                ))
                continue

            target_identity = self.identify(target)
            if target_identity in visiting:
                candidates.append(AttributeCandidate(
                    status=ProvenanceStatus.CYCLE,
                    value=None,
                    source=target_identity,
                    chain=next_chain,
                    reason=(
                        f'{link_name} closes a reference cycle at '
                        f'unit 0x{target_identity.unit.unit_offset:x}, '
                        f'DIE 0x{target_identity.offset:x}'
                    ),
                ))
                continue

            if (link_name == _SPECIFICATION
                    and name in _NOT_INHERITED_FROM_SPECIFICATION):
                candidates.append(AttributeCandidate(
                    status=ProvenanceStatus.MISSING,
                    value=None,
                    source=target_identity,
                    chain=next_chain,
                    reason=(
                        f'{name} is not inherited through '
                        f'{_SPECIFICATION}'
                    ),
                ))
                continue

            result = self._resolve_from(
                die=target,
                name=name,
                root=root,
                chain=next_chain,
                visiting=visiting | {target_identity},
            )
            candidates.append(self._candidate_from_result(result))
        return tuple(candidates)

    def _combine(
        self,
        name: str,
        root: DIEIdentity,
        branches: tuple[AttributeCandidate, ...],
    ) -> ResolvedAttribute:
        # A broken reference or a cycle is never hidden behind a value from
        # another branch.  The caller needs to know the graph was incomplete.
        for failing_status in (
            ProvenanceStatus.CYCLE,
            ProvenanceStatus.BROKEN_REFERENCE,
            ProvenanceStatus.CONFLICT,
        ):
            failures = [
                failure
                for branch in branches
                for failure in _all_failures(branch)
                if failure.status == failing_status
            ]
            if failures:
                adopted = failures[0]
                return ResolvedAttribute(
                    name=name,
                    status=failing_status,
                    value=None,
                    root=root,
                    source=adopted.source,
                    chain=adopted.chain,
                    candidates=branches,
                    reason=self._aggregate_reason(failing_status, failures),
                )

        values = [b for b in branches if b.status.is_resolved]
        if not values:
            return ResolvedAttribute(
                name=name,
                status=ProvenanceStatus.MISSING,
                value=None,
                root=root,
                candidates=branches,
                reason='attribute is not present in any reachable declaration',
            )

        first = values[0]
        for other in values[1:]:
            if other.value != first.value:
                return ResolvedAttribute(
                    name=name,
                    status=ProvenanceStatus.CONFLICT,
                    value=None,
                    root=root,
                    candidates=branches,
                    reason=(
                        'inherited references provide conflicting values; '
                        'no value was chosen'
                    ),
                )

        return ResolvedAttribute(
            name=name,
            status=ProvenanceStatus.INHERITED,
            value=first.value,
            root=root,
            source=first.source,
            chain=first.chain,
            candidates=branches,
            reason='inherited through ' + ', '.join(
                link.attribute for link in first.chain),
        )

    def _candidate_from_result(
        self, result: ResolvedAttribute,
    ) -> AttributeCandidate:
        return AttributeCandidate(
            status=result.status,
            value=result.value,
            source=result.source,
            chain=result.chain,
            reason=result.reason,
            candidates=result.candidates,
        )

    @staticmethod
    def _aggregate_reason(
        status: ProvenanceStatus,
        failures: list[AttributeCandidate],
    ) -> str:
        label = {
            ProvenanceStatus.CYCLE: 'reference cycle',
            ProvenanceStatus.BROKEN_REFERENCE: 'broken reference',
            ProvenanceStatus.CONFLICT: 'conflicting inherited values',
        }[status]
        details = '; '.join(dict.fromkeys(
            failure.reason for failure in failures if failure.reason))
        return f'{label} prevents resolution' + (f': {details}' if details else '')

    # -- reference and identity helpers -------------------------------

    def _target_for(
        self,
        die: DIE,
        name: str,
        attr: AttributeValue,
    ) -> tuple[DIE | None, str | None]:
        if attr.form not in _REFERENCE_FORMS:
            return None, (
                f'{name} has non-reference form {attr.form}; '
                'cannot follow it as a DIE reference'
            )
        try:
            if self._reference_resolver is not None:
                target = self._reference_resolver(die, name)
            else:
                target = die.get_DIE_from_attribute(name)
        except Exception as exc:  # reference lookups report failure as data
            return None, self._describe_failure(exc)
        if target is None:
            return None, f'{name} reference resolved to no DIE'
        return target, None

    @staticmethod
    def _describe_failure(exc: Exception) -> str:
        # A malformed or externally supplied reference becomes an unresolved
        # result with its diagnostic, not an exception escaping the report.
        return f'{type(exc).__name__}: {exc}'

    def _unit_identity_for_die(self, die: DIE) -> UnitIdentity:
        cu = getattr(die, 'cu', None)
        dwarfinfo = getattr(die, 'dwarfinfo', None)
        if dwarfinfo is None and cu is not None:
            dwarfinfo = getattr(cu, 'dwarfinfo', None)
        if self._dwarfinfo is None and dwarfinfo is not None:
            self._dwarfinfo = dwarfinfo

        # TypeUnit has both cu_offset and tu_offset; CompileUnit only the
        # former.
        is_tu = cu is not None and hasattr(cu, 'tu_offset')
        if is_tu:
            kind = 'TU'
            unit_offset = int(getattr(cu, 'tu_offset', 0))
            section = self._section_name(dwarfinfo, 'debug_types_sec',
                                         '.debug_types')
        else:
            kind = 'CU'
            unit_offset = int(getattr(cu, 'cu_offset', 0))
            section = self._section_name(dwarfinfo, 'debug_info_sec',
                                         '.debug_info')

        primary = self._dwarfinfo
        supplementary = (
            getattr(primary, 'supplementary_dwarfinfo', None)
            if primary is not None else None)
        primary_of = getattr(dwarfinfo, 'primary_dwarfinfo', None)
        is_supplementary = bool(
            dwarfinfo is not None and (
                (supplementary is not None and dwarfinfo is supplementary)
                or primary_of is not None))
        if dwarfinfo is not None:
            container_id = id(dwarfinfo)
        elif cu is not None:
            container_id = id(cu)
        else:
            container_id = 0

        return UnitIdentity(
            kind=kind,
            unit_offset=unit_offset,
            section=section,
            is_supplementary=is_supplementary,
            container_id=container_id,
            dwarfinfo=dwarfinfo,
        )

    @staticmethod
    def _section_name(
        dwarfinfo: DWARFInfo | None,
        attribute: str,
        fallback: str,
    ) -> str:
        section = getattr(dwarfinfo, attribute, None) if dwarfinfo else None
        return getattr(section, 'name', None) or fallback


# Shorter aliases for consumers and older drafts.
DIEAttributeResolver = DIEProvenanceResolver
ProvenanceResolver = DIEProvenanceResolver


def get_unit_identity(die: DIE, dwarfinfo: DWARFInfo | None = None) -> UnitIdentity:
    """Convenience wrapper returning the unit identity for ``die``."""
    return DIEProvenanceResolver(dwarfinfo).unit_identity(die)


def resolve_attribute(
    die: DIE,
    name: str,
    dwarfinfo: DWARFInfo | None = None,
) -> ResolvedAttribute:
    """Resolve one attribute of ``die`` with explicit provenance."""
    return DIEProvenanceResolver(dwarfinfo).resolve(die, name)


def resolve_attributes(
    die: DIE,
    names: Iterable[str] | None = None,
    dwarfinfo: DWARFInfo | None = None,
) -> dict[str, ResolvedAttribute]:
    """Resolve several attributes, or every reachable attribute."""
    return DIEProvenanceResolver(dwarfinfo).resolve_many(die, names)


def get_attribute_provenance(
    die: DIE,
    name: str,
    dwarfinfo: DWARFInfo | None = None,
) -> ResolvedAttribute:
    """Alias for :func:`resolve_attribute`."""
    return resolve_attribute(die, name, dwarfinfo)


# Additional spellings kept as small, direct aliases.  They all return the
# same ResolvedAttribute and never mutate the DIE.
attribute_provenance = resolve_attribute
resolve_attribute_provenance = resolve_attribute
resolve_die_attribute = resolve_attribute
