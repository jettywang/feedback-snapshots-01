"""Provenance-tracking registry for ANY DEFINED BY open-type maps.

The module-level maps consumed by :class:`pyasn1.type.opentype.OpenType`
are plain :class:`dict` objects that modules mutate with ``update()`` at
import time.  A silent ``dict.update`` of an already registered OID makes
the resolved schema depend on import order, which is ambiguous for a
long-running process that imports functionality lazily.

:class:`GuardedRegistry` is a drop-in dict replacement.  It keeps every
existing mapping behaviour (so explicit ``map[oid] = spec`` and
``map.update(...)`` call sites keep working) while additionally recording
the provenance of each registration and flagging *incompatible*
overrides.  Equivalent aliases - a second registration whose schema
decodes the same wire type - are allowed to coexist.

The class is dependency free and never emits warnings or raises on its
own; callers decide what to do with :meth:`incompatible_overrides`.
"""

from pyasn1.type import univ

__all__ = ['GuardedRegistry', 'schema_fingerprint', 'schemas_equivalent']


def schema_fingerprint(spec):
    """Stable structural identity of an ASN.1 schema instance.

    Two specs with the same concrete pyasn1 type, tag set and base tag set
    decode the same bytes identically, so a re-registration of one with the
    other is an equivalent alias rather than a conflict.  Class identity is
    deliberately *not* used: subclasses that only differ in name (for
    example ``Classification(ESSSecurityLabel)``) share one wire schema.
    """
    tag_set = getattr(spec, 'tagSet', None)
    base_tag_set = getattr(spec, 'baseTagSet', None)
    return (
        type(spec).__name__ if tag_set is None else spec.typeId,
        None if tag_set is None else repr(tag_set),
        None if base_tag_set is None else repr(base_tag_set),
    )


def schemas_equivalent(left, right):
    """Return True when both schemas impose the same decoding contract."""
    if left is right:
        return True
    return schema_fingerprint(left) == schema_fingerprint(right)


class GuardedRegistry(dict):
    """Dict-compatible open-type registry with conflict provenance.

    Each key maps to the active schema, exactly like a plain dict, while
    ``provenance`` keeps every (schema, source) pair ever registered and
    ``incompatible_overrides`` records clashing wire schemas together with
    the sources that installed them.
    """

    def __init__(self, *args, **kwargs):
        self.provenance = {}
        self.incompatible_overrides = {}
        super().__init__()
        if args or kwargs:
            self.update(*args, **kwargs)

    def register(self, key, spec, source=None):
        existing = self.get(key)
        record = (schema_fingerprint(spec), source)
        history = self.provenance.setdefault(key, [])
        if record not in history:
            history.append(record)
        if existing is not None and not schemas_equivalent(existing, spec):
            clash = self.incompatible_overrides.setdefault(key, [])
            entry = {
                'existing': schema_fingerprint(existing),
                'incoming': schema_fingerprint(spec),
                'source': source,
            }
            if entry not in clash:
                clash.append(entry)
        dict.__setitem__(self, key, spec)

    def __setitem__(self, key, value):
        self.register(key, value, source=None)

    def update(self, *args, **kwargs):
        source = kwargs.pop('__source__', None)
        if args:
            if len(args) > 1:
                raise TypeError('update expected at most 1 argument')
            other = args[0]
            if hasattr(other, 'items'):
                iterable = other.items()
            else:
                iterable = other
            for key, spec in iterable:
                self.register(key, spec, source=source)
        for key, spec in kwargs.items():
            self.register(key, spec, source=source)

    def setdefault(self, key, default=None):
        if key not in self:
            self.register(key, default, source=None)
        return self[key]


# A schema used by the controlled-conflict test.  Integer and OctetString
# carry different universal tags, so they can never be equivalent aliases.
CONFLICT_WITNESS_OID = univ.ObjectIdentifier('1.3.6.1.4.1.99999.77.1')
