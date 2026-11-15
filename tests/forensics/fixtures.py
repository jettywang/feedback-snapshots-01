#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
"""Small security-message fixtures for the forensic dual-schema tests.

Every fixture is built from explicit, self-contained schemas and encoded with
the DER encoder so that the wire bytes are known.  Three mechanisms produce
genuine interpretation divergence over the *same* bytes -- implicit tagging,
DEFAULT handling and open/ANY typing -- and one control pair is semantically
equivalent but constructed differently.
"""
from pyasn1.codec.der import encoder
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ

_CTX = tag.tagClassContext


def _implicit(number, base_type, constructed=False):
    fmt = tag.tagFormatConstructed if constructed else tag.tagFormatSimple
    return base_type().subtype(
        implicitTag=tag.Tag(_CTX, fmt, number))


def _implicit_default(number, value):
    return univ.Integer(value).subtype(
        implicitTag=tag.Tag(_CTX, tag.tagFormatSimple, number))


# ---------------------------------------------------------------------------
# Mechanism 1: implicit tagging -- one context tag, two primitive meanings.
# ---------------------------------------------------------------------------
class IntegerPermission(univ.Sequence):
    """[1] IMPLICIT INTEGER readPermission."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('readPermission', _implicit(1, univ.Integer)))


class BooleanAdmin(univ.Sequence):
    """[1] IMPLICIT BOOLEAN isAdmin -- same tag, different base type."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('isAdmin', _implicit(1, univ.Boolean)))


class EnumeratedClearance(univ.Sequence):
    """[1] IMPLICIT ENUMERATED clearanceLevel -- same octets as INTEGER."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('clearanceLevel',
                            _implicit(1, univ.Enumerated)))


# ---------------------------------------------------------------------------
# Mechanism 2: DEFAULT handling -- an omitted field is not on the wire.
# ---------------------------------------------------------------------------
class VersionDefaultZero(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType(
            'version', _implicit_default(0, 0)),
        namedtype.NamedType('permissions', _implicit(1, univ.Integer)))


class VersionDefaultThree(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType(
            'version', _implicit_default(0, 3)),
        namedtype.NamedType('permissions', _implicit(1, univ.Integer)))


class VersionOptional(univ.Sequence):
    """The same field declared OPTIONAL instead of DEFAULT."""

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('version', _implicit(0, univ.Integer)),
        namedtype.NamedType('permissions', _implicit(1, univ.Integer)))


# ---------------------------------------------------------------------------
# Mechanism 3: open/ANY typing governed by an OBJECT IDENTIFIER.
# ---------------------------------------------------------------------------
class RightsDetailed(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('read', univ.Integer()),
        namedtype.NamedType('write', univ.Integer()))


class RightsCompact(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('level', univ.Integer()),
        namedtype.NamedType('flags', univ.Integer()))


OID_DETAILED = univ.ObjectIdentifier('1.2.3.4')
OID_COMPACT = univ.ObjectIdentifier('1.2.3.5')
OID_UNKNOWN = univ.ObjectIdentifier('1.2.3.9')

# Inner content: SEQUENCE { INTEGER 1, INTEGER 2 }.
RIGHTS_CONTENT = bytes.fromhex('3006020101020102')


class EnvelopeDetailed(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('typeId', univ.ObjectIdentifier()),
        namedtype.NamedType(
            'content', univ.Any(),
            openType=opentype.OpenType(
                'typeId', {OID_DETAILED: RightsDetailed()})))


class EnvelopeCompact(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('typeId', univ.ObjectIdentifier()),
        namedtype.NamedType(
            'content', univ.Any(),
            openType=opentype.OpenType(
                'typeId', {OID_COMPACT: RightsCompact()})))


class EnvelopeUntyped(univ.Sequence):
    """No type-id map at all: content can never be guessed."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('typeId', univ.ObjectIdentifier()),
        namedtype.NamedType(
            'content', univ.Any(),
            openType=opentype.OpenType('typeId', {})))


# ---------------------------------------------------------------------------
# Control: same permission values, different construction.
# ---------------------------------------------------------------------------
class PermissionRecord(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('read', _implicit(0, univ.Integer)),
        namedtype.NamedType('write', _implicit(1, univ.Integer)))


class PermissionRecordSet(univ.Set):
    """Same named fields and values, SET instead of SEQUENCE."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('read', _implicit(0, univ.Integer)),
        namedtype.NamedType('write', _implicit(1, univ.Integer)))


def _encode_default_message():
    msg = VersionDefaultZero()
    msg.setComponentByName('permissions', 7)
    return encoder.encode(msg)


def _encode_implicit_message():
    msg = IntegerPermission()
    msg.setComponentByName('readPermission', 7)
    return encoder.encode(msg)


def _encode_envelope(type_id):
    msg = EnvelopeDetailed()
    msg.setComponentByName('typeId', type_id)
    msg.setComponentByName('content', univ.Any(RIGHTS_CONTENT))
    return encoder.encode(msg)


def _encode_record(container):
    msg = container()
    msg.setComponentByName('read', 1)
    msg.setComponentByName('write', 0)
    return encoder.encode(msg)


#: Pre-encoded substrates shared across tests.
IMPLICIT_WIRE = _encode_implicit_message()
DEFAULT_WIRE = _encode_default_message()
ENVELOPE_DETAILED_WIRE = _encode_envelope(OID_DETAILED)
ENVELOPE_UNKNOWN_WIRE = _encode_envelope(OID_UNKNOWN)
CONTROL_SEQUENCE_WIRE = _encode_record(PermissionRecord)
CONTROL_SET_WIRE = _encode_record(PermissionRecordSet)

# A large integer and a full byte-range octet string for precision tests.
BIG_INTEGER = (1 << 256) + 0xABCDEF
FULL_OCTETS = bytes(bytearray(range(256)))
