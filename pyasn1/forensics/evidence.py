#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Structured forensic evidence for one schema-driven interpretation.

A :class:`FieldEvidence` record keeps two things deliberately apart:

* the *transmitted* facts taken from the schema-neutral
  :class:`~pyasn1.forensics.raw.RawNode` (byte span, raw tag, content octets,
  whether anything was on the wire at all), and
* the *meaning assigned by one explicit schema* (the field name, the chosen
  CHOICE alternative, implicit/explicit tagging, the decoded Python value and
  the pyasn1 type that produced it).

Omitted DEFAULT and OPTIONAL components are recorded with an explicit
``presence`` state and are never described as on-wire bytes.  An ``ANY`` whose
governing type id is unknown is left as raw TLV octets: this layer never
guesses a type for it.
"""
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1.forensics.raw import ForensicError

__all__ = [
    'PRESENT', 'ABSENT_OPTIONAL', 'DEFAULT_INJECTED', 'OPEN_UNRESOLVED',
    'TagEvidence', 'ValueEvidence', 'FieldEvidence', 'Interpretation',
    'ForensicError',
]

#: The component's TLV was present in the transmitted substrate.
PRESENT = 'present'
#: An OPTIONAL component had no TLV on the wire.
ABSENT_OPTIONAL = 'absent-optional'
#: A DEFAULT component had no TLV on the wire; the value is the schema default.
DEFAULT_INJECTED = 'default-injected'
#: An ANY/open type whose governing id maps to no known type; not interpreted.
OPEN_UNRESOLVED = 'open-unresolved'

_TAG_CATEGORY = {
    tag.tagCategoryImplicit: 'implicit',
    tag.tagCategoryExplicit: 'explicit',
    tag.tagCategoryUntagged: 'untagged',
}
_TAG_FORMAT = {
    tag.tagFormatSimple: 'primitive',
    tag.tagFormatConstructed: 'constructed',
}


class TagEvidence(object):
    """The tag chain a schema assigns to a field."""

    def __init__(self, tag_set):
        self.tags = []
        for a_tag in tag_set:
            tag_class, tag_format, tag_number = tuple(a_tag)
            self.tags.append({
                'tagClass': _class_name(tag_class),
                'tagClassCode': tag_class,
                'format': _TAG_FORMAT.get(tag_format, tag_format),
                'tagNumber': tag_number,
            })

    def to_dict(self):
        return list(self.tags)


class ValueEvidence(object):
    """The decoded value, kept in full and never truncated.

    Integer and enumerated values retain their arbitrary-precision magnitude;
    octet/bit strings keep every byte; only the presentation is added on top.
    """

    def __init__(self, kind, value, detail=None):
        self.kind = kind
        self.value = value
        self.detail = detail or {}

    def to_dict(self):
        out = {'kind': self.kind, 'value': self.value}
        out.update(self.detail)
        return out


class FieldEvidence(object):
    """One field of one schema-driven interpretation."""

    def __init__(self, path, name, schema_type, presence, tag_evidence,
                 tag_category, raw_path=None, value=None, default_value=None,
                 choice_branch=None, open_type=None, unresolved=False,
                 raw_hex=None, children=None):
        self.path = path
        self.name = name
        self.schema_type = schema_type
        self.presence = presence
        self.tag = tag_evidence
        self.tag_category = tag_category
        self.raw_path = raw_path
        self.value = value
        self.default_value = default_value
        self.choice_branch = choice_branch
        self.open_type = open_type
        self.unresolved = unresolved
        self.raw_hex = raw_hex
        self.children = children or []

    def to_dict(self):
        out = {
            'path': self.path,
            'fieldName': self.name,
            'schemaType': self.schema_type,
            'presence': self.presence,
            'tagCategory': self.tag_category,
            'assignedTag': self.tag.to_dict(),
            'choiceBranch': self.choice_branch,
            'openType': self.open_type,
            'unresolvedAny': self.unresolved,
            'rawPath': self.raw_path,
            'rawTlvHex': self.raw_hex,
            'value': self.value.to_dict() if self.value is not None else None,
            'defaultValue': self.default_value,
            'children': [child.to_dict() for child in self.children],
        }
        return out


class Interpretation(object):
    """The full field tree produced by applying one schema to one substrate."""

    def __init__(self, schema_name, root, fields, decode_error=None,
                 decoded=None):
        self.schema_name = schema_name
        self.root_raw_path = root.path if root is not None else None
        self.fields = fields
        self.decode_error = decode_error
        # Retained for whole-tree encoding reconstruction; not serialised.
        self.decoded = decoded

    def to_dict(self):
        return {
            'schemaName': self.schema_name,
            'rootRawPath': self.root_raw_path,
            'decodeError': self.decode_error,
            'fields': [field.to_dict() for field in self.fields],
        }


def _class_name(tag_class):
    return {
        tag.tagClassUniversal: 'universal',
        tag.tagClassApplication: 'application',
        tag.tagClassContext: 'context',
        tag.tagClassPrivate: 'private',
    }.get(tag_class, tag_class)


def _scalar_value(asn1_object):
    """Extract a full-fidelity value for a primitive pyasn1 object.

    Classification follows the class hierarchy (``isinstance``) rather than the
    mutable ``typeId`` slot, so a user subclass that renumbers ``typeId`` is
    still recognised by its universal ASN.1 type.  Most-specific types are
    tested first (ENUMERATED before INTEGER, ANY before OCTET STRING).
    """
    python_type = type(asn1_object).__name__
    if isinstance(asn1_object, univ.Enumerated):
        return ValueEvidence(
            'enumerated', int(asn1_object), {'pythonType': python_type})
    if isinstance(asn1_object, univ.Boolean):
        return ValueEvidence(
            'boolean', bool(asn1_object), {'pythonType': python_type})
    if isinstance(asn1_object, univ.Integer):
        return ValueEvidence(
            'integer', int(asn1_object), {'pythonType': python_type})
    if isinstance(asn1_object, univ.ObjectIdentifier):
        arcs = tuple(int(arc) for arc in asn1_object.asTuple())
        return ValueEvidence(
            'object-identifier', '.'.join(str(arc) for arc in arcs),
            {'arcs': list(arcs), 'pythonType': python_type})
    if isinstance(asn1_object, univ.Null):
        return ValueEvidence('null', None, {'pythonType': python_type})
    if isinstance(asn1_object, univ.Any):
        octets = bytes(asn1_object.asOctets())
        return ValueEvidence(
            'any-raw', octets.hex(),
            {'lengthOctets': len(octets), 'pythonType': python_type})
    if isinstance(asn1_object, univ.BitString):
        octets = bytes(asn1_object.asOctets())
        return ValueEvidence(
            'bit-string', octets.hex(),
            {'lengthOctets': len(octets), 'pythonType': python_type})
    if isinstance(asn1_object, univ.OctetString):
        octets = bytes(asn1_object.asOctets())
        return ValueEvidence(
            'octet-string', octets.hex(),
            {'lengthOctets': len(octets), 'pythonType': python_type})
    # Character and useful string types: keep the decoded text plus the class.
    try:
        text = str(asn1_object)
    except Exception:
        text = None
    return ValueEvidence(
        'other', text, {'pythonType': type(asn1_object).__name__})


def _tag_category(asn1_object):
    base_tags = type(asn1_object).tagSet
    effective = asn1_object.effectiveTagSet
    if effective == base_tags:
        return _TAG_CATEGORY[tag.tagCategoryUntagged]
    # An explicit tag stacks a constructed outer tag over the base tag.
    if len(effective) > len(base_tags):
        return _TAG_CATEGORY[tag.tagCategoryExplicit]
    return _TAG_CATEGORY[tag.tagCategoryImplicit]


def _default_value(named_type, schema_component):
    if not isinstance(named_type, namedtype.DefaultedNamedType):
        return None
    if schema_component.hasValue():
        return _scalar_or_repr(schema_component)
    return None


def _scalar_or_repr(schema_component):
    try:
        value_evidence = _scalar_value(schema_component)
        return value_evidence.to_dict()
    except Exception:
        return {'kind': 'schema-default', 'value': repr(schema_component)}


def _open_type_info(named_type):
    if named_type is None or named_type.openType is None:
        return None
    open_type = named_type.openType
    keys = []
    for key in open_type.keys():
        try:
            keys.append(str(key))
        except Exception:
            keys.append(repr(key))
    return {
        'governingField': open_type.name,
        'knownTypeIds': keys,
    }


class _Cursor(object):
    """Position over the ordered children of a RawNode."""

    def __init__(self, raw_node):
        self.raw_node = raw_node
        self.index = 0

    def take(self):
        if self.index >= len(self.raw_node.children):
            raise ForensicError(
                'Schema expects more components than the %d TLV(s) under %s'
                % (len(self.raw_node.children), self.raw_node.path or 'root'))
        node = self.raw_node.children[self.index]
        self.index += 1
        return node

    def expect_exhausted(self):
        if self.index != len(self.raw_node.children):
            raise ForensicError(
                '%d TLV(s) under %s were not claimed by the schema'
                % (len(self.raw_node.children) - self.index,
                   self.raw_node.path or 'root'))


def _join(path, segment):
    return segment if not path else path + '.' + segment


def _is_container(asn1_object):
    return isinstance(
        asn1_object,
        (univ.Sequence, univ.Set, univ.SequenceOf, univ.SetOf))


def _build_field(asn1_object, named_type, raw_node, path, name,
                 choice_branch):
    tag_evidence = TagEvidence(asn1_object.effectiveTagSet)
    category = _tag_category(asn1_object)
    open_type = _open_type_info(named_type)
    raw_hex = raw_node.tlv_octets.hex() if raw_node is not None else None

    # ANY / open type: if the decoder left it as Any, do not guess a type.
    if isinstance(asn1_object, univ.Any):
        field = FieldEvidence(
            path=path, name=name, schema_type=type(asn1_object).__name__,
            presence=OPEN_UNRESOLVED, tag_evidence=tag_evidence,
            tag_category=category, raw_path=raw_node.path,
            value=_scalar_value(asn1_object), open_type=open_type,
            unresolved=True, raw_hex=raw_hex)
        return field

    value = None
    children = []
    if _is_container(asn1_object):
        children = _walk_container(asn1_object, raw_node, path)
    elif isinstance(asn1_object, univ.Choice):
        children = _walk_choice(asn1_object, raw_node, path)
    else:
        value = _scalar_value(asn1_object)

    field = FieldEvidence(
        path=path, name=name, schema_type=type(asn1_object).__name__,
        presence=PRESENT, tag_evidence=tag_evidence,
        tag_category=category, raw_path=raw_node.path, value=value,
        choice_branch=choice_branch, open_type=open_type, raw_hex=raw_hex,
        children=children)
    return field


def _unwrap_explicit(asn1_object, raw_node):
    """Return the content RawNode behind an explicit-tag wrapper, if any."""
    if _tag_category(asn1_object) == 'explicit' and raw_node is not None:
        if len(raw_node.children) != 1:
            raise ForensicError(
                'Explicit tag at %s must wrap exactly one TLV, got %d'
                % (raw_node.path, len(raw_node.children)))
        return raw_node.children[0]
    return raw_node


def _walk_container(asn1_object, raw_node, path):
    fields = []
    # Sequence/Set carry named types and are subclasses of the *Of family, so
    # test the named-type containers first.
    is_of = not isinstance(asn1_object, (univ.Sequence, univ.Set)) and \
        isinstance(asn1_object, (univ.SequenceOf, univ.SetOf))

    if is_of:
        cursor = _Cursor(raw_node)
        for position in range(len(asn1_object)):
            component = asn1_object.getComponentByPosition(position)
            child_raw = cursor.take()
            child_raw = _unwrap_explicit(component, child_raw)
            fields.append(_build_field(
                component, None, child_raw,
                _join(path, str(position)), '[%d]' % position, None))
        cursor.expect_exhausted()
        return fields

    named_types = asn1_object.componentType
    cursor = _Cursor(raw_node)
    for position in range(len(named_types)):
        named_type = named_types[position]
        field_name = named_types.getNameByPosition(position)
        component = asn1_object.getComponentByPosition(
            position, instantiate=False)
        field_path = _join(path, field_name)

        if component is univ.noValue:
            presence = (
                DEFAULT_INJECTED
                if isinstance(named_type, namedtype.DefaultedNamedType)
                else ABSENT_OPTIONAL)
            schema_component = named_types.getTypeByPosition(position)
            field = FieldEvidence(
                path=field_path, name=field_name,
                schema_type=type(schema_component).__name__,
                presence=presence,
                tag_evidence=TagEvidence(
                    schema_component.effectiveTagSet),
                tag_category=_tag_category(schema_component),
                raw_path=None,
                default_value=_default_value(named_type, schema_component))
            fields.append(field)
            continue

        child_raw = cursor.take()
        child_raw = _unwrap_explicit(component, child_raw)
        fields.append(_build_field(
            component, named_type, child_raw, field_path, field_name, None))
    cursor.expect_exhausted()
    return fields


def _walk_choice(asn1_object, raw_node, path):
    fields = []
    named_types = asn1_object.componentType
    for position in range(len(named_types)):
        component = asn1_object.getComponentByPosition(
            position, instantiate=False)
        if component is univ.noValue:
            continue
        branch_name = named_types.getNameByPosition(position)
        named_type = named_types[position]
        content_raw = _unwrap_explicit(component, raw_node)
        fields.append(_build_field(
            component, named_type, content_raw,
            _join(path, branch_name), branch_name, branch_name))
    return fields


def build_interpretation(schema_name, decoded, root_node, decode_error=None):
    """Build an :class:`Interpretation` from a decoded object and raw tree."""
    fields = []
    if decoded is not None:
        if isinstance(decoded, univ.Choice):
            fields = _walk_choice(decoded, root_node, '')
        elif _is_container(decoded):
            fields = _walk_container(decoded, root_node, '')
        else:
            fields = [_build_field(decoded, None, root_node, '',
                                   type(decoded).__name__, None)]
    return Interpretation(schema_name, root_node, fields, decode_error,
                          decoded=decoded)
