#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Read-only ASN.1 schema ambiguity precheck.

This module walks an already-constructed pyasn1 schema graph and reports the
places where a single wire tag could be routed to more than one security
field *before* any network substrate is decoded. It is deliberately
side-effect free:

* it never instantiates a component value (no ``setComponent*``, no
  :class:`~pyasn1.type.base.SimpleAsn1Type` value construction) and never
  mutates a schema object, so the input schema is returned untouched;
* it does not rely on the eagerly built
  :class:`~pyasn1.type.tagmap.TagMap` /
  :class:`~pyasn1.type.namedtype.NamedTypes` ambiguity tables. Some of those
  tables are :class:`~pyasn1.type.namedtype.NamedTypes.PostponedError`
  placeholders for a schema that is still being assembled (recursive types),
  so the analysis computes wire tags directly from each field's
  :class:`~pyasn1.type.tag.TagSet`.

Two kinds of findings are produced. A :class:`TagConflict` is a *deterministic*
ambiguity: two concrete fields of the analysed schema both accept the same
on-the-wire tag in the same decoding window. An :class:`OpenTypeFinding` marks
a field whose target cannot be decided from the schema alone (``ANY`` / an
``ANY DEFINED BY`` open type); such a field is reported as needing runtime
context and is never classified as safe.

Minimal BER evidence that demonstrates each deterministic conflict, plus a
relabelled control encoding, is built separately in
:mod:`pyasn1.type.schema.precheck_evidence` so the analysis core stays
read-only.
"""
from pyasn1.type import base
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

__all__ = ['Finding', 'TagConflict', 'OpenTypeFinding', 'SchemaPrecheck',
           'precheck']


#: Severity marker for a tag that maps to more than one concrete field.
SEVERITY_CONFLICT = 'tag-conflict'

#: Severity marker for an open type that needs runtime governing context.
SEVERITY_OPEN_TYPE = 'open-type-context-required'


def _wireSignature(tagSet):
    """Return the on-the-wire identity carried by a TagSet.

    A BER decoder matches a field by the ordered ``(tag class, tag id)``
    pairs of every tag in the TagSet. Implicit tagging replaces the trailing
    tag and explicit tagging appends one, so the full tuple distinguishes an
    implicitly tagged scalar from an explicitly wrapped one even when the
    outermost ``(class, id)`` pair happens to coincide.
    """
    return tuple((singleTag.tagClass, singleTag.tagId)
                 for singleTag in tagSet.superTags)


def _renderSignature(signature):
    """Render a wire signature the same way Tag repr exposes a tag."""
    return '-'.join('[%s:%s]' % (tagClass, tagId)
                    for tagClass, tagId in signature)


def _tagKind(fieldType):
    """Describe how a field's outermost tag was applied, for the rationale."""
    superTags = fieldType.tagSet.superTags
    if not superTags:
        return 'untagged'
    if _isExplicit(fieldType):
        return 'explicit'
    if len(superTags) == 1 and superTags[0].tagClass != tag.tagClassUniversal:
        return 'implicit'
    return 'universal'


def _isExplicit(fieldType):
    """Detect an explicitly tagged type, which keeps a constructed wrapper.

    Explicit tagging appends a constructed tag, so the trailing super tag has
    the constructed format while the base (universal) tag is still present in
    the TagSet. Implicit tagging overwrites the trailing tag instead and does
    not add a level.
    """
    superTags = fieldType.tagSet.superTags
    if len(superTags) < 2:
        return False
    return superTags[-1].tagFormat == tag.tagFormatConstructed


class Finding(object):
    """Base class for a single precheck observation.

    Findings are immutable descriptions; they never hold a live component
    value, only schema references and dotted field paths.
    """

    severity = None

    def __init__(self, path, rationale):
        self._path = path
        self._rationale = rationale

    @property
    def path(self):
        """Dotted field path from the precheck root to the finding."""
        return self._path

    @property
    def rationale(self):
        """Human-readable explanation of why the finding was raised."""
        return self._rationale

    def _relocate(self, prefix):
        clone = self.__class__.__new__(self.__class__)
        clone.__dict__.update(self.__dict__)
        if prefix:
            clone._path = prefix + ('.' + self._path if self._path else '')
        return clone

    def _rebase(self, basePath):
        """Return a copy with the owning type's edge path stripped.

        The memo stores each type's findings relative to that type so they can
        be relocated onto another edge on a later shared reuse. An empty
        ``basePath`` (the precheck root) leaves paths untouched.
        """
        clone = self.__class__.__new__(self.__class__)
        clone.__dict__.update(self.__dict__)
        if basePath and self._path == basePath:
            clone._path = ''
        elif basePath and self._path.startswith(basePath + '.'):
            clone._path = self._path[len(basePath) + 1:]
        return clone

    def __repr__(self):
        return '<%s path=%r>' % (self.__class__.__name__, self._path)


class TagConflict(Finding):
    """A deterministic collision: one wire tag, several concrete fields.

    Attributes
    ----------
    fieldPaths: :py:class:`tuple` of :py:class:`str`
        Full dotted paths of every field that accepts :attr:`wireSignature`
        in the same decoding window.
    wireSignature: :py:class:`tuple` of :py:class:`tuple`
        Ordered ``(tag class, tag id)`` pairs the conflicting fields share on
        the wire.
    containerKind: :py:class:`str`
        ``"SEQUENCE"``, ``"SET"`` or ``"CHOICE"`` -- the constructed type in
        which the ambiguity is visible.
    tagKinds: :py:class:`tuple` of :py:class:`str`
        Per-field description of how the shared tag was produced (universal,
        implicit, explicit, untagged), supporting the rationale.
    """

    severity = SEVERITY_CONFLICT

    def __init__(self, path, fieldPaths, wireSignature, containerKind,
                 tagKinds, rationale):
        Finding.__init__(self, path, rationale)
        self._fieldPaths = tuple(fieldPaths)
        self._wireSignature = wireSignature
        self._containerKind = containerKind
        self._tagKinds = tuple(tagKinds)

    @property
    def fieldPaths(self):
        return self._fieldPaths

    @property
    def wireSignature(self):
        return self._wireSignature

    @property
    def renderedTag(self):
        return _renderSignature(self._wireSignature)

    @property
    def containerKind(self):
        return self._containerKind

    @property
    def tagKinds(self):
        return self._tagKinds

    def _relocate(self, prefix):
        clone = Finding._relocate(self, prefix)
        if prefix:
            clone._fieldPaths = tuple(
                prefix + ('.' + fieldPath if fieldPath else '')
                for fieldPath in self._fieldPaths)
        return clone

    def _rebase(self, basePath):
        clone = Finding._rebase(self, basePath)
        if basePath:
            clone._fieldPaths = tuple(
                self._stripBase(fieldPath, basePath)
                for fieldPath in self._fieldPaths)
        return clone

    @staticmethod
    def _stripBase(fieldPath, basePath):
        if fieldPath == basePath:
            return ''
        if fieldPath.startswith(basePath + '.'):
            return fieldPath[len(basePath) + 1:]
        return fieldPath


class OpenTypeFinding(Finding):
    """An open/``ANY`` field whose concrete type is not statically decidable.

    Attributes
    ----------
    governingField: :py:class:`str` or :py:class:`None`
        Name of the sibling field that selects the concrete type at runtime
        for an ``ANY DEFINED BY`` clause, or :py:data:`None` for a bare
        ``ANY`` with no governing component.
    isCollection: :py:class:`bool`
        :py:data:`True` for ``SEQUENCE OF ANY`` / ``SET OF ANY`` containers.
    """

    severity = SEVERITY_OPEN_TYPE

    def __init__(self, path, rationale, governingField=None, isCollection=False):
        Finding.__init__(self, path, rationale)
        self._governingField = governingField
        self._isCollection = isCollection

    @property
    def governingField(self):
        return self._governingField

    @property
    def isCollection(self):
        return self._isCollection


class _Alternative(object):
    """A field alternative resolved to its on-the-wire tag identity."""

    __slots__ = ('path', 'fieldType', 'signature', 'isOpen')

    def __init__(self, path, fieldType, signature, isOpen):
        self.path = path
        self.fieldType = fieldType
        self.signature = signature
        self.isOpen = isOpen


def _makeAlternative(path, fieldType, signature, isOpen):
    return _Alternative(path, fieldType, signature, isOpen)


class SchemaPrecheck(object):
    """Analyse a schema graph for tag-routing ambiguities without decoding.

    Parameters
    ----------
    rootType: :class:`~pyasn1.type.base.Asn1Type`
        The schema object (typically a :class:`~pyasn1.type.univ.Sequence`,
        :class:`~pyasn1.type.univ.Set` or :class:`~pyasn1.type.univ.Choice`)
        to analyse.

    Notes
    -----
    The prechecker treats object identity, not value equality, as the graph
    edge identity. A type that is *shared* by several parents (the normal,
    legal way to reuse a named type) is analysed once and its findings
    relocated onto each parent path. Only an edge that leads back to an
    ancestor of the current depth-first walk terminates the recursion, so a
    genuinely recursive schema is bounded while shared, acyclic types never
    raise a false cycle.
    """

    def __init__(self, rootType):
        if not isinstance(rootType, base.Asn1Type):
            raise TypeError('SchemaPrecheck expects an ASN.1 type, got %r'
                            % (rootType,))
        self._root = rootType
        self._findings = []
        self._analysed = False
        # id() -> findings computed for a fully analysed shared type.
        self._memo = {}
        # ids of the types on the current DFS path: the real cycle guard.
        self._onPath = set()

    # -- public entry points ------------------------------------------------

    def run(self):
        """Run the analysis and return the list of findings.

        Returns
        -------
        : :py:class:`list` of :class:`Finding`
            Deterministic :class:`TagConflict` findings first, then
            :class:`OpenTypeFinding` findings. Calling :meth:`run` more than
            once re-runs the walk and never accumulates duplicates.
        """
        self._findings = []
        self._analysed = True
        self._memo = {}
        self._onPath = set()
        self._walk(self._root, self._root.__class__.__name__)
        self._findings.sort(key=lambda item: (item.severity, item.path))
        return list(self._findings)

    @property
    def conflicts(self):
        """Subset of :meth:`run` results that are deterministic conflicts."""
        if not self._analysed:
            self.run()
        return [item for item in self._findings
                if isinstance(item, TagConflict)]

    @property
    def openTypes(self):
        """Subset of findings that need runtime governing context."""
        if not self._analysed:
            self.run()
        return [item for item in self._findings
                if isinstance(item, OpenTypeFinding)]

    @property
    def isStaticallyUnambiguous(self):
        """True only when no deterministic conflict was found.

        Open types do not make this False on their own: they are not safe,
        but neither are they a static collision, so callers must inspect
        :attr:`openTypes` separately rather than treating them as resolved.
        """
        if not self._analysed:
            self.run()
        return not self.conflicts

    # -- graph walk ---------------------------------------------------------

    def _walk(self, asn1Type, edgePath):
        """Analyse one node reached along the ``edgePath`` edge.

        The memo holds each type's findings with paths relative to that type
        itself (its own findings start with ``""``, a field ``f`` with
        ``"f"``). On first visit those local findings are relocated once by
        ``edgePath`` and emitted globally. On a shared reuse the same local
        findings are relocated onto the new edge, so a legal shared type is
        reported under every parent but a path is never prefixed twice.
        """
        typeId = id(asn1Type)

        if typeId in self._onPath:
            # Back edge: a genuinely recursive reference. Stop descending so
            # the walk terminates; the referenced type is analysed on its own
            # first visit and no cycle finding is fabricated for it.
            return

        if typeId in self._memo:
            # Legal sharing: the same type object reused by several parents.
            for localFinding in self._memo[typeId]:
                self._findings.append(localFinding._relocate(edgePath))
            return

        self._onPath.add(typeId)
        localFindings = self._collectLocalFindings(asn1Type, edgePath)
        self._onPath.discard(typeId)

        # Re-base to paths relative to this type for future shared reuse.
        self._memo[typeId] = [
            finding._rebase(edgePath) for finding in localFindings]
        self._findings.extend(localFindings)

    def _collectLocalFindings(self, asn1Type, edgePath):
        componentType = getattr(asn1Type, 'componentType', None)
        localFindings = []

        if isinstance(asn1Type, (univ.Sequence, univ.Set, univ.Choice)):
            if componentType and isinstance(componentType,
                                            namedtype.NamedTypes):
                localFindings.extend(
                    self._analyseConstructed(asn1Type, componentType,
                                             edgePath))

        elif isinstance(asn1Type, univ.SequenceOfAndSetOfBase):
            if isinstance(componentType, base.Asn1Type):
                self._walk(componentType, self._join(edgePath, '<element>'))

        return localFindings

    @staticmethod
    def _join(prefix, name):
        return prefix + '.' + name if prefix else name

    # -- constructed-type analysis -----------------------------------------

    def _analyseConstructed(self, asn1Type, namedTypes, containerPath):
        findings = []
        fields = namedTypes.namedTypes
        alternativesByPosition = []

        for position, namedTypeObject in enumerate(fields):
            fieldPath = self._join(containerPath, namedTypeObject.name)
            fieldType = namedTypeObject.asn1Object
            alternatives = self._fieldAlternatives(fieldType, fieldPath)
            alternativesByPosition.append(
                (position, namedTypeObject, fieldType, alternatives))

            # Recurse: child findings are emitted globally at absolute paths.
            self._walk(fieldType, fieldPath)

            if namedTypeObject.openType is not None:
                findings.append(self._openTypeFinding(
                    fieldPath, namedTypeObject, fieldType))
            elif self._containsBareAny(fieldType):
                findings.append(OpenTypeFinding(
                    fieldPath,
                    'field is or contains an untagged ANY, which accepts any '
                    'wire tag; its concrete type can only be chosen from '
                    'runtime context',
                    isCollection=isinstance(
                        fieldType, univ.SequenceOfAndSetOfBase)))

        if isinstance(asn1Type, univ.Choice):
            findings.extend(self._conflictsForUnordered(
                alternativesByPosition, containerPath, 'CHOICE'))
        elif isinstance(asn1Type, univ.Set):
            findings.extend(self._conflictsForUnordered(
                alternativesByPosition, containerPath, 'SET'))
        else:
            findings.extend(self._conflictsForSequence(
                alternativesByPosition, containerPath))
        return findings

    def _conflictsForUnordered(self, alternativeGroups, containerPath,
                               containerKind):
        # SET and CHOICE have no positional ordering to fall back on: every
        # field is a candidate for the same position, so a shared tag is an
        # unambiguous routing collision.
        signatureIndex = {}
        for _position, _namedType, _fieldType, alternatives in \
                alternativeGroups:
            for alternative in alternatives:
                if alternative.isOpen:
                    continue
                signatureIndex.setdefault(
                    alternative.signature, []).append(alternative)

        findings = []
        for signature, members in signatureIndex.items():
            ownerPaths = self._distinctOwnerPaths(members)
            if len(ownerPaths) < 2:
                # Same signature twice inside one (nested untagged CHOICE)
                # field is reported by that nested CHOICE, not duplicated here.
                continue
            findings.append(self._buildConflict(
                containerPath, ownerPaths, signature, containerKind, members))
        return findings

    def _conflictsForSequence(self, alternativeGroups, containerPath):
        findings = []
        positions = len(alternativeGroups)
        # A run of optional/defaulted fields opens overlapping windows that
        # converge on the same field set; report each (tag, field-set) pair
        # once instead of once per anchor.
        reported = set()
        for anchor in range(positions):
            _position, namedTypeObject, _fieldType, _alternatives = \
                alternativeGroups[anchor]
            if not (namedTypeObject.isOptional or
                    namedTypeObject.isDefaulted):
                # A mandatory field is an ordering anchor: the decoder always
                # consumes it at its own position, so a later field can never
                # be mistaken for it. Only an optional/defaulted anchor opens
                # a window over the following fields.
                continue

            reachable = self._sequenceWindow(alternativeGroups, anchor)
            signatureIndex = {}
            for alternative in reachable:
                if alternative.isOpen:
                    continue
                signatureIndex.setdefault(
                    alternative.signature, []).append(alternative)

            for signature, members in signatureIndex.items():
                ownerPaths = self._distinctOwnerPaths(members)
                if len(ownerPaths) < 2:
                    continue
                dedupeKey = (signature, tuple(ownerPaths))
                if dedupeKey in reported:
                    continue
                reported.add(dedupeKey)
                findings.append(self._buildConflict(
                    containerPath, ownerPaths, signature, 'SEQUENCE', members,
                    anchor=namedTypeObject.name))
        return findings

    @staticmethod
    def _sequenceWindow(alternativeGroups, anchor):
        """Alternatives reachable when the field at ``anchor`` is skipped.

        The window starts at the optional/defaulted anchor and runs through
        every following optional/defaulted field up to and including the next
        mandatory field. A mandatory field terminates the window because, once
        reached, it is consumed by position and cannot be back-matched.
        """
        window = []
        for _position, namedTypeObject, _fieldType, alternatives in \
                alternativeGroups[anchor:]:
            window.extend(alternatives)
            if not (namedTypeObject.isOptional or
                    namedTypeObject.isDefaulted):
                break
        return window

    @staticmethod
    def _distinctOwnerPaths(members):
        seen = []
        for alternative in members:
            if alternative.path not in seen:
                seen.append(alternative.path)
        return seen

    def _buildConflict(self, containerPath, ownerPaths, signature,
                       containerKind, members, anchor=None):
        kindByPath = {}
        for alternative in members:
            kindByPath[alternative.path] = _tagKind(alternative.fieldType)
        tagKinds = tuple(kindByPath[owner] for owner in ownerPaths)
        rendered = _renderSignature(signature)
        if containerKind == 'SEQUENCE':
            rationale = (
                'wire tag %s is accepted by fields %s in the same SEQUENCE '
                'decoding window opened by optional/defaulted field "%s"; '
                'if "%s" is absent on the wire the decoder cannot tell which '
                'field owns this tag (tag production: %s)' % (
                    rendered, ', '.join(ownerPaths), anchor, anchor,
                    ', '.join(tagKinds)))
        else:
            rationale = (
                'wire tag %s is accepted by more than one %s alternative %s; '
                '%s components are selected by tag with no positional '
                'fallback, so the routing is not unique (tag production: %s)'
                % (rendered, containerKind, ', '.join(ownerPaths),
                   containerKind, ', '.join(tagKinds)))
        return TagConflict(containerPath, ownerPaths, signature,
                           containerKind, tagKinds, rationale)

    # -- field-level wire identity ------------------------------------------

    def _fieldAlternatives(self, fieldType, fieldPath):
        """Resolve a field to the wire tags it can present.

        An untagged CHOICE is transparent: its own TagSet is empty and the
        decoder sees its alternatives, so it is flattened recursively. Every
        other type (including a *tagged* CHOICE) presents exactly one fixed
        wire signature.
        """
        if isinstance(fieldType, univ.Choice) and not fieldType.tagSet:
            componentType = getattr(fieldType, 'componentType', None)
            if not (componentType and
                    isinstance(componentType, namedtype.NamedTypes)):
                return []
            flattened = []
            for inner in componentType.namedTypes:
                innerPath = fieldPath + '.' + inner.name
                flattened.extend(self._fieldAlternatives(
                    inner.asn1Object, innerPath))
            return flattened

        if self._isBareAny(fieldType):
            return [_makeAlternative(fieldPath, fieldType, (), True)]

        return [_makeAlternative(
            fieldPath, fieldType, _wireSignature(fieldType.tagSet), False)]

    @staticmethod
    def _isBareAny(fieldType):
        # Any.typeId reuses the OctetString id, so identity is checked by
        # class rather than typeId.
        return isinstance(fieldType, univ.Any) and not fieldType.tagSet

    def _containsBareAny(self, fieldType):
        """Whether a field is ANY or a SEQUENCE/SET OF ANY element type."""
        if self._isBareAny(fieldType):
            return True
        if isinstance(fieldType, univ.SequenceOfAndSetOfBase):
            componentType = getattr(fieldType, 'componentType', None)
            if isinstance(componentType, base.Asn1Type):
                return self._isBareAny(componentType)
        return False

    @staticmethod
    def _openTypeFinding(fieldPath, namedTypeObject, fieldType):
        openType = namedTypeObject.openType
        isCollection = isinstance(fieldType, univ.SequenceOfAndSetOfBase)
        if openType is not None:
            rationale = (
                'open type "%s" is governed at runtime by sibling field '
                '"%s"; its concrete schema cannot be selected until that '
                'governing value is decoded, so it must not be treated as '
                'statically safe' % (namedTypeObject.name, openType.name))
            return OpenTypeFinding(fieldPath, rationale,
                                   governingField=openType.name,
                                   isCollection=isCollection)
        return OpenTypeFinding(
            fieldPath,
            'field needs runtime context to choose its concrete type',
            isCollection=isCollection)


def precheck(rootType):
    """Convenience wrapper returning :meth:`SchemaPrecheck.run` results."""
    return SchemaPrecheck(rootType).run()
