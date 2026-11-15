#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Minimal BER evidence for deterministic :class:`TagConflict` findings.

The read-only analysis in :mod:`pyasn1.type.schema.precheck` never builds a
value. This module is the only place bytes are produced: given a conflict it
constructs the smallest BER substrate whose tag the two conflicting fields
both claim, decodes it to show why the choice is not unique, and then builds a
relabelled control in which one field is given a distinct legal tag so the
same payload routes deterministically.

Everything here works on *cloned* schema objects and locally synthesised
values. The original schema passed to the prechecker is never mutated, and no
component of an existing schema value is instantiated.
"""
from pyasn1.type import base
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1.type.schema.precheck import TagConflict
from pyasn1.type.schema.precheck import _wireSignature

__all__ = ['ConflictEvidence', 'build_evidence', 'build_all_evidence']


# Minimal, DER-valid content octets keyed by the base universal tag id.
# Every entry decodes on its own and is the shortest possible value for the
# type, so the surrounding TLV stays minimal regardless of tagging.
_MINIMAL_CONTENT = {
    0x01: b'\x00',   # BOOLEAN FALSE
    0x02: b'\x00',   # INTEGER 0
    0x03: b'\x00',   # BIT STRING, zero unused bits, empty
    0x04: b'',      # OCTET STRING ''
    0x05: b'',      # NULL
    0x06: b'\x00',   # OBJECT IDENTIFIER 0.0
    0x0a: b'\x00',   # ENUMERATED 0
    0x0c: b'',      # UTF8String ''
    0x13: b'',      # PrintableString ''
    0x16: b'',      # IA5String ''
    0x10: b'',      # SEQUENCE (empty)
    0x11: b'',      # SET (empty)
}


def _identifierOctets(tagClass, tagFormat, tagId, forceConstructed=False):
    """Encode a single BER identifier octet (or multi-octet high tag)."""
    first = tagClass | tagFormat
    if forceConstructed:
        first |= tag.tagFormatConstructed
    if tagId < 0x1f:
        return bytes((first | tagId,))
    octets = [tagId & 0x7f]
    tagId >>= 7
    while tagId:
        octets.append(0x80 | (tagId & 0x7f))
        tagId >>= 7
    octets.reverse()
    return bytes((first | 0x1f,)) + bytes(octets)


def _lengthOctets(length):
    """Encode a definite BER length."""
    if length < 0x80:
        return bytes((length,))
    body = []
    while length:
        body.append(length & 0xff)
        length >>= 8
    body.reverse()
    return bytes((0x80 | len(body),)) + bytes(body)


def _wrap(signature, content, innermostFormat=tag.tagFormatSimple):
    """Wrap ``content`` in every tag of a wire signature.

    BER emits the innermost (base universal) TLV first and each explicit
    wrapper around it, so the signature is walked in its stored order. The
    first (innermost) tag uses the leaf's format; every later explicit tag is
    emitted constructed.
    """
    payload = content
    for depth, (tagClass, tagId) in enumerate(signature):
        if depth == 0:
            identifier = _identifierOctets(
                tagClass, innermostFormat, tagId)
        else:
            identifier = _identifierOctets(
                tagClass, tag.tagFormatConstructed, tagId,
                forceConstructed=True)
        payload = identifier + _lengthOctets(len(payload)) + payload
    return payload


def _encodeLeafTlv(fieldType):
    """Build a minimal, decodable TLV for one concrete leaf field."""
    # Choice subclasses Set; handle an untagged transparent CHOICE first.
    if isinstance(fieldType, univ.Choice) and not fieldType.tagSet:
        return _encodeMemberValue(fieldType)
    signature = _leafSignature(fieldType)
    if isinstance(fieldType, (univ.Sequence, univ.Set)):
        # A constructed leaf must itself contain its mandatory members.
        body = b''
        componentType = getattr(fieldType, 'componentType', None)
        if isinstance(componentType, namedtype.NamedTypes):
            for nested in componentType.namedTypes:
                if nested.isOptional or nested.isDefaulted:
                    continue
                member = _encodeLeafTlv(nested.asn1Object)
                if member is not None:
                    body += member
        return _wrap(signature, body, _innermostFormat(fieldType))
    return _wrap(signature, _minimalContentFor(fieldType),
                 _innermostFormat(fieldType))


def _innermostFormat(fieldType):
    """Format bit of the innermost on-the-wire tag for a field.

    Explicit tagging appends constructed wrappers but leaves the base tag's
    format untouched, so the innermost (first emitted) tag's format is read
    from the base universal tag rather than the outermost super tag.
    """
    baseTag = fieldType.tagSet.baseTag
    if baseTag:
        return baseTag.tagFormat
    superTags = fieldType.tagSet.superTags
    if superTags:
        return superTags[0].tagFormat
    return tag.tagFormatSimple


def _minimalContentFor(fieldType):
    """Shortest valid content octets for a field's base universal type."""
    baseTag = fieldType.tagSet.baseTag
    if baseTag:
        tagId = baseTag.tagId
        if tagId in _MINIMAL_CONTENT:
            return _MINIMAL_CONTENT[tagId]
        if baseTag.tagFormat == tag.tagFormatConstructed:
            return b''
    return b''


def _leafSignature(fieldType):
    """The wire signature a leaf field actually presents."""
    return _wireSignature(fieldType.tagSet)


class ConflictEvidence(object):
    """Demonstration bytes and decode outcome for one :class:`TagConflict`.

    Attributes
    ----------
    conflict: :class:`TagConflict`
        The finding this evidence explains.
    ambiguousEncoding: :py:class:`bytes`
        Minimal BER substrate carrying the shared tag inside the enclosing
        constructed type.
    ambiguousHex: :py:class:`str`
        Hexadecimal rendering of :attr:`ambiguousEncoding`.
    decodeOutcome: :py:class:`str`
        What the BER decoder does with :attr:`ambiguousEncoding` against the
        original schema: ``"raises"`` (with the error text) or the field the
        decoder settled on, illustrating the non-unique choice.
    controlEncoding: :py:class:`bytes`
        A complete, DER-valid value built on a cloned schema where every
        field sharing the conflict tag -- except one untouched reference --
        is given a distinct legal tag, so the bytes route deterministically.
    controlHex: :py:class:`str`
        Hexadecimal rendering of :attr:`controlEncoding`.
    controlOutcome: :py:class:`str`
        The uniquely selected field(s) when decoding
        :attr:`controlEncoding`, or a ``"control not synthesised"`` note when
        a mandatory open ``ANY`` makes a complete value impossible to build
        statically.
    relabelledSchema:
        The cloned, retagged schema the control is decoded against; the
        original prechecked schema is never modified.
    """

    def __init__(self, conflict, ambiguousEncoding, decodeOutcome,
                 controlEncoding, controlOutcome, relabelledSchema):
        self.conflict = conflict
        self.ambiguousEncoding = ambiguousEncoding
        self.ambiguousHex = ambiguousEncoding.hex()
        self.decodeOutcome = decodeOutcome
        self.controlEncoding = controlEncoding
        self.controlHex = controlEncoding.hex()
        self.controlOutcome = controlOutcome
        self.relabelledSchema = relabelledSchema

    def __repr__(self):
        return ('<ConflictEvidence %s ambiguous=%s control=%s>'
                % (self.conflict.path, self.ambiguousHex, self.controlHex))


def _containerTag(containerKind):
    if containerKind == 'SET':
        return 0x31
    if containerKind == 'CHOICE':
        return None
    return 0x30


def _decodeOutcome(schema, substrate):
    # Imported lazily so the static analysis package does not pull a codec for
    # callers that only want the read-only report.
    from pyasn1.codec.ber import decoder

    try:
        decoded, _rest = decoder.decode(substrate, asn1Spec=schema)
    except Exception as exc:  # intentional: any failure proves ambiguity
        return 'raises: %s: %s' % (type(exc).__name__, str(exc).splitlines()[0])

    chosen = _selectedField(decoded)
    return 'decoded into field "%s" without distinguishing the alternative' \
        % chosen


def _selectedField(decoded):
    if isinstance(decoded, univ.Choice):
        try:
            return decoded.getName()
        except Exception:
            return '<unknown>'
    names = []
    componentType = getattr(decoded, 'componentType', None)
    if componentType and isinstance(componentType, namedtype.NamedTypes):
        for idx, namedTypeObject in enumerate(componentType.namedTypes):
            component = decoded.getComponentByPosition(
                idx, instantiate=False)
            from pyasn1.type.base import noValue
            if component is not noValue and getattr(
                    component, 'isValue', False):
                names.append(namedTypeObject.name)
    return ', '.join(names) if names else '<unknown>'


def _resolveFieldTypes(schema, conflict):
    """Map each conflicting field path to its concrete schema field type."""
    resolved = []
    for fieldPath in conflict.fieldPaths:
        fieldType = _followPath(schema, fieldPath.split('.'))
        fieldType = _resolveToLeaf(fieldType, conflict.wireSignature)
        resolved.append((fieldPath, fieldType))
    return resolved


def _resolveToLeaf(fieldType, wireSignature):
    """Step through transparent (untagged) CHOICE wrappers to a real leaf.

    A flattened CHOICE field presents several signatures; pick the
    alternative whose on-the-wire identity is the one the conflict reports.
    """
    while (isinstance(fieldType, univ.Choice) and not fieldType.tagSet):
        componentType = getattr(fieldType, 'componentType', None)
        if not (componentType and
                isinstance(componentType, namedtype.NamedTypes)):
            break
        chosen = None
        for inner in componentType.namedTypes:
            candidate = _resolveToLeaf(inner.asn1Object, wireSignature)
            if _leafSignature(candidate) == wireSignature:
                chosen = candidate
                break
        if chosen is None:
            chosen = componentType.namedTypes[0].asn1Object
        fieldType = chosen
    return fieldType


def _followPath(schema, pathParts):
    # The first part is the root type's own name; drop it.
    parts = list(pathParts)
    if parts and parts[0] == schema.__class__.__name__:
        parts = parts[1:]
    current = schema
    for part in parts:
        if part == '<element>':
            current = current.componentType
            continue
        componentType = getattr(current, 'componentType', None)
        if isinstance(componentType, namedtype.NamedTypes):
            current = componentType[part].asn1Object
    return current


def _buildAmbiguous(conflict, fieldType):
    """Minimal substrate whose tag every conflicting field accepts."""
    member = _encodeLeafTlv(fieldType)
    containerTag = _containerTag(conflict.containerKind)
    if containerTag is None:
        # Untagged CHOICE: the member TLV is the whole encoding.
        return member
    return bytes((containerTag, len(member))) + member


def _buildControl(schema, conflict, resolvedFields):
    """Relabel one field with a distinct legal tag, then encode a full value.

    Unlike the ambiguous substrate (which deliberately carries only the
    colliding member), the control is a complete, DER-valid value: every
    mandatory component is emitted, the retagged field uses a tag the other
    field does not claim, and nested constructed types on the path to the
    conflict are filled recursively, so the decoder routes each member
    deterministically.
    """
    relabelledSchema, targetPath = _relabelField(schema, resolvedFields)

    relativeParts = _relativePathParts(relabelledSchema, targetPath)
    substrate = _encodeRootValue(
        relabelledSchema, relativeParts, conflict.containerKind)

    blocking = _mandatoryOpenType(relabelledSchema)
    if blocking is not None:
        # A mandatory open ANY has no statically known value, so no complete
        # control value can be synthesised. Report this rather than emit a
        # substrate that fails on an unrelated required component.
        outcome = (
            'control not synthesised: mandatory open type "%s" needs a '
            'runtime value; provide it to build a complete encoding'
            % blocking)
        return substrate, outcome, relabelledSchema

    from pyasn1.codec.ber import decoder
    try:
        decoded, _rest = decoder.decode(substrate, asn1Spec=relabelledSchema)
        outcome = 'uniquely decoded into field(s) "%s"' % _selectedField(decoded)
    except Exception as exc:
        outcome = 'control decode raised %s: %s' % (
            type(exc).__name__, str(exc).splitlines()[0])
    return substrate, outcome, relabelledSchema


def _mandatoryOpenType(constructedType):
    """Name of a mandatory open ANY member that blocks a complete control."""
    componentType = getattr(constructedType, 'componentType', None)
    if not isinstance(componentType, namedtype.NamedTypes):
        return None
    from pyasn1.type.schema.precheck import SchemaPrecheck
    for namedTypeObject in componentType.namedTypes:
        if namedTypeObject.isOptional or namedTypeObject.isDefaulted:
            continue
        fieldType = namedTypeObject.asn1Object
        if SchemaPrecheck._isBareAny(fieldType):
            return namedTypeObject.name
        if isinstance(fieldType, (univ.Sequence, univ.Set, univ.Choice)):
            nested = _mandatoryOpenType(fieldType)
            if nested is not None:
                return namedTypeObject.name + '.' + nested
    return None


def _relativePathParts(schema, targetPath):
    """Drop the root type name from a dotted conflict field path."""
    parts = targetPath.split('.')
    if parts and parts[0] == schema.__class__.__name__:
        parts = parts[1:]
    return parts


def _encodeRootValue(schema, relativeParts, containerKind):
    """Encode a valid root value, descending to the retagged field."""
    if containerKind == 'CHOICE':
        # A CHOICE carries exactly one selected alternative, even when the
        # conflict is at the top level: follow the path to the retagged leaf
        # rather than enumerating every alternative.
        return _encodePathMember(schema, relativeParts)
    if isinstance(schema, univ.SequenceOfAndSetOfBase):
        # A SEQUENCE OF / SET OF control carries one relabelled element so
        # the retagged element type is visible in the substrate.
        componentType = getattr(schema, 'componentType', None)
        element = _encodeMemberValue(componentType) \
            if isinstance(componentType, base.Asn1Type) else b''
        element = element or b''
        return _wrap(_leafSignature(schema), element,
                     _innermostFormat(schema))
    body = _encodeConstructedBody(schema, relativeParts)
    signature = _leafSignature(schema)
    return _wrap(signature, body, _innermostFormat(schema))


def _encodeConstructedBody(constructedType, remainingPath):
    """Encode the mandatory members of a constructed type.

    When a member lies on ``remainingPath`` (the route to the retagged
    field), the descent continues into it; every other mandatory member gets
    a standalone minimal value. Optional/default members and open ANY members
    are omitted, matching a value that simply does not carry them.
    """
    componentType = getattr(constructedType, 'componentType', None)
    if not isinstance(componentType, namedtype.NamedTypes):
        return b''

    nextName = remainingPath[0] if remainingPath else None
    deeper = remainingPath[1:] if remainingPath else []
    body = b''
    for namedTypeObject in componentType.namedTypes:
        if namedTypeObject.isOptional or namedTypeObject.isDefaulted:
            continue
        fieldType = namedTypeObject.asn1Object
        if namedTypeObject.name == nextName:
            # ``deeper`` is already the path relative to this member, so one
            # call handles both constructed types and transparent CHOICEs.
            member = _encodePathMember(fieldType, deeper)
        else:
            member = _encodeMemberValue(fieldType)
        if member is not None:
            body += member
    return body


def _encodePathMember(fieldType, pathBelow):
    """Encode a member on the route to the retagged field.

    ``pathBelow`` is the field path relative to ``fieldType`` itself: an
    empty tuple means ``fieldType`` is the retagged leaf, otherwise its first
    element names the next component to enter.
    """
    # Choice subclasses Set, so it must be tested before the Sequence/Set
    # branch or an untagged CHOICE would be iterated as a record.
    if isinstance(fieldType, univ.Choice) and not fieldType.tagSet:
        # An untagged CHOICE is transparent and carries exactly one member.
        componentType = getattr(fieldType, 'componentType', None)
        if pathBelow and isinstance(componentType, namedtype.NamedTypes) \
                and pathBelow[0] in componentType:
            alternative = componentType[pathBelow[0]].asn1Object
            return _encodePathMember(alternative, pathBelow[1:])
        return _encodeMemberValue(fieldType)
    if isinstance(fieldType, (univ.Sequence, univ.Set)):
        body = _encodeConstructedBody(fieldType, list(pathBelow))
        return _wrap(_leafSignature(fieldType), body,
                     _innermostFormat(fieldType))
    # The retagged leaf (or a path terminal): encode its own minimal TLV.
    return _encodeMemberValue(fieldType)


def _encodeMemberValue(fieldType):
    """Minimal TLV for a concrete (non-open) container member.

    Returns :py:data:`None` for an open ``ANY`` member, whose value the
    control cannot synthesise and which the relabelled schema leaves out.
    """
    from pyasn1.type.schema.precheck import SchemaPrecheck
    if SchemaPrecheck._isBareAny(fieldType):
        return None
    if isinstance(fieldType, univ.Choice) and not fieldType.tagSet:
        componentType = getattr(fieldType, 'componentType', None)
        if not (componentType and
                isinstance(componentType, namedtype.NamedTypes)):
            return None
        fieldType = componentType.namedTypes[0].asn1Object
    return _encodeLeafTlv(fieldType)


def _relabelField(schema, resolvedFields):
    """Clone the schema and disambiguate every field sharing the conflict tag.

    The first colliding field keeps its original wire tag as the reference;
    every other field in the schema presenting the same wire signature --
    including fields that belong to a neighbouring ambiguity window -- gets a
    fresh context tag, so the control cannot retain a second same-tagged
    field. The replacement preserves each field's tagging mode: implicit
    fields get an implicit tag and explicit fields an explicit wrapper.
    """
    referencePath = resolvedFields[0][0]
    referenceType = resolvedFields[0][1]
    collidingSignature = _leafSignature(referenceType)

    usedTagIds = set()
    for _path, fieldType in resolvedFields:
        for singleTag in fieldType.tagSet.superTags:
            if singleTag.tagClass == tag.tagClassContext:
                usedTagIds.add(singleTag.tagId)

    relabelled = schema
    for targetPath, targetType in _iterMatchingFields(
            schema, collidingSignature):
        if targetPath == referencePath:
            continue
        newTagId = 0
        while newTagId in usedTagIds:
            newTagId += 1
        usedTagIds.add(newTagId)

        explicit = _isExplicitlyTagged(targetType)
        if explicit:
            newTag = tag.Tag(tag.tagClassContext,
                             tag.tagFormatConstructed, newTagId)
        else:
            newTag = tag.Tag(tag.tagClassContext,
                             tag.tagFormatSimple, newTagId)

        parts = _relativePathParts(relabelled, targetPath)
        relabelled = _rebuild(relabelled, parts, newTag, explicit)

    return relabelled, referencePath


def _iterMatchingFields(schema, wireSignature):
    """Yield (dotted path, field type) for every field with the signature."""
    matches = []

    def join(prefix, name):
        return prefix + '.' + name if prefix else name

    def walk(node, prefix):
        componentType = getattr(node, 'componentType', None)
        if isinstance(node, (univ.Sequence, univ.Set, univ.Choice)) and \
                isinstance(componentType, namedtype.NamedTypes):
            nodePrefix = prefix or node.__class__.__name__
            for namedTypeObject in componentType.namedTypes:
                fieldPath = join(nodePrefix, namedTypeObject.name)
                fieldType = namedTypeObject.asn1Object
                if isinstance(fieldType, univ.Choice) and \
                        not fieldType.tagSet:
                    # Transparent CHOICE: descend without matching the wrapper.
                    walk(fieldType, fieldPath)
                else:
                    if _leafSignature(fieldType) == wireSignature:
                        matches.append((fieldPath, fieldType))
                    walk(fieldType, fieldPath)
        elif isinstance(node, univ.SequenceOfAndSetOfBase) and \
                isinstance(componentType, base.Asn1Type):
            elementPrefix = join(prefix or node.__class__.__name__,
                                 '<element>')
            walk(componentType, elementPrefix)

    walk(schema, '')
    return matches


def _isExplicitlyTagged(fieldType):
    superTags = fieldType.tagSet.superTags
    return (len(superTags) >= 2 and
            superTags[-1].tagFormat == tag.tagFormatConstructed and
            superTags[-1].tagClass != tag.tagClassUniversal)


def _rebuild(current, parts, newTag, explicit):
    if not parts:
        return _retag(current, newTag, explicit)
    head, rest = parts[0], parts[1:]
    componentType = getattr(current, 'componentType', None)
    if isinstance(current, univ.SequenceOfAndSetOfBase):
        if head == '<element>' and isinstance(componentType, base.Asn1Type):
            return current.clone(
                componentType=_rebuild(componentType, rest, newTag,
                                       explicit))
        return current
    if not isinstance(componentType, namedtype.NamedTypes):
        return current
    newNamedTypes = []
    for namedTypeObject in componentType.namedTypes:
        childType = namedTypeObject.asn1Object
        if namedTypeObject.name == head:
            childType = _rebuild(childType, rest, newTag, explicit)
        # Preserve the OPTIONAL/DEFAULT wrapper class: the SEQUENCE ambiguity
        # windows are computed from isOptional/isDefaulted at construction.
        newNamedTypes.append(namedTypeObject.__class__(
            namedTypeObject.name, childType,
            openType=namedTypeObject.openType))
    return current.clone(componentType=namedtype.NamedTypes(*newNamedTypes))


def _retag(fieldType, newTag, explicit):
    """Apply a distinct tag, matching the field's original tagging mode.

    The control must keep the same number of wire levels as the original
    field, so an explicit retag *replaces* the trailing explicit super tag
    rather than appending another wrapper.
    """
    if explicit:
        baseTagSet = fieldType.tagSet[:-1]
        return fieldType.clone(tagSet=baseTagSet.tagExplicitly(newTag))
    return fieldType.clone(tagSet=fieldType.tagSet.tagImplicitly(newTag))


def build_evidence(schema, conflict):
    """Construct :class:`ConflictEvidence` for a single conflict.

    Parameters
    ----------
    schema: :class:`~pyasn1.type.base.Asn1Type`
        The same root schema object that was prechecked.
    conflict: :class:`TagConflict`
        A deterministic conflict returned by the prechecker.
    """
    if not isinstance(conflict, TagConflict):
        raise TypeError('build_evidence expects a TagConflict finding')

    resolvedFields = _resolveFieldTypes(schema, conflict)
    representativeType = resolvedFields[0][1]
    ambiguous = _buildAmbiguous(conflict, representativeType)
    ambiguousOutcome = _decodeOutcome(schema, ambiguous)
    control, controlOutcome, relabelledSchema = _buildControl(
        schema, conflict, resolvedFields)
    return ConflictEvidence(
        conflict, ambiguous, ambiguousOutcome, control, controlOutcome,
        relabelledSchema)


def build_all_evidence(schema, findings):
    """Build evidence for every :class:`TagConflict` in ``findings``."""
    return [build_evidence(schema, finding)
            for finding in findings if isinstance(finding, TagConflict)]
