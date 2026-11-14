# dictionary.py
#
# Copyright 2002,2005,2007,2016 Wichert Akkerman <wichert@wiggy.net>
"""
RADIUS uses dictionaries to define the attributes that can
be used in packets. The Dictionary class stores the attribute
definitions from one or more dictionary files in the FreeRADIUS format.

Dictionary files are text files with one command per line.
Comments are specified by starting with a # character, and empty
lines are ignored.

The commands supported are:

``ATTRIBUTE <attribute> <code> <type> [<vendor>|<flags>]``
  Define an attribute and its data type. The code is decimal, or
  hexadecimal with a ``0x`` prefix (octal with ``0o``), and
  ``<tlv code>.<code>`` for a sub-attribute of a TLV.

``VALUE <attribute> <valuename> <value>``
  Define a named value of an attribute.

``VENDOR <name> <id> [format=<t>,<l>]``
  Define a vendor and its ID. Only the RFC 2865 format ``format=1,1`` (the
  default) is supported, the attributes of vendors with another format
  are skipped.

``BEGIN-VENDOR <name> [format=<attribute>]``
  Begin the definition of the attributes of a vendor. The attributes of a
  block with a ``format=`` option are extended vendor-specific attributes
  (RFC 6929) and are skipped.

``END-VENDOR <name>``
  End the definition of the attributes of a vendor.

``$INCLUDE <filename>``
  Read another dictionary file. A relative file name is relative to the
  directory of the current file, or to the current working directory if
  the dictionary is read from a file-like object.

``$INCLUDE- <filename>``
  Like ``$INCLUDE``, but a file that doesn't exist is ignored.

Other commands are ignored.

The attribute flags are a comma separated list of:

``has_tag``
  The attribute is tagged (RFC 2868).

``encrypt=1``
  User-Password encryption (RFC 2865 section 5.2). It is not applied
  automatically, see :meth:`pyrad.packet.AuthPacket.PwCrypt` and
  :meth:`pyrad.packet.AuthPacket.PwDecrypt`.

``encrypt=2``
  Salt encryption (RFC 2868 section 3.5), applied automatically.

``encrypt=3``
  Ascend-Send-Secret encryption. Accepted, but not applied.

The FreeRADIUS flags ``secret``, ``virtual`` and ``concat`` are accepted
and ignored.

FreeRADIUS dictionaries also define attributes that pyrad cannot encode or
decode. These are skipped with a warning, so that the FreeRADIUS dictionary
files can be read as they are:

- attributes of the data types ``vsa``, ``extended``, ``long-extended``,
  ``evs`` (the RFC 6929 extended attributes), ``ipv4prefix``,
  ``combo-ip``, ``bool``, ``uint16`` and ``uint32``, and their
  sub-attributes
- attributes with the ``array`` flag
- TLVs nested more than one level deep
- attributes of vendors with a format other than ``format=1,1``
  (``VENDOR``)
- vendor attributes in a ``BEGIN-VENDOR`` block with a ``format=``
  option, which are extended vendor-specific attributes (RFC 6929)

VALUE definitions for skipped attributes are ignored, and VALUE definitions
for unknown attributes are ignored with a warning. Received attributes
that were skipped are decoded as undefined attributes.

Strict loading
--------------

A :class:`Dictionary` created with ``strict=True`` (or a strict
:meth:`Dictionary.ReadDictionary` call) merges dictionary files without
letting a later definition change how the same wire bytes are interpreted.

A new ATTRIBUTE must not contradict an earlier one. It conflicts, and
raises :class:`DictionaryConflictError`, when:

- an attribute name is bound to another vendor/code or TLV parent path,
- a vendor/code (the key of the attribute in a packet), including a
  ``(vendor, code)`` or TLV ``(parent, code)`` key, is already defined
  with another data type, ``encrypt`` or ``has_tag`` option, or
- the data type, ``encrypt`` flag, ``has_tag`` flag or TLV parent of the
  same attribute differs.

Definitions with the same meaning are accepted: an exact duplicate, and
an alias, which is another name for an attribute with the identical key,
type, flags and TLV parent. An alias resolves to the same
:class:`Attribute` object. Likewise a VENDOR may be repeated with the same
id and format, and a VALUE may add another name for the same encoded
value; giving an existing VALUE name another encoded value conflicts.

Every strict :meth:`~Dictionary.ReadDictionary` call is an atomic
transaction, including its ``$INCLUDE`` files and the deferred VALUE
definitions resolved at the end of the load. Any failure rolls the whole
call back, restoring the previous vendors, attributes and bidirectional
index, so no index entry can be left pointing at a half-loaded object.
The error carries the file and line of both conflicting definitions.

The data types currently supported, and the Python values used for them in
packets:

.. list-table::
   :header-rows: 1
   :widths: 15 40 45

   * - type
     - description
     - Python value
   * - string
     - UTF-8 string
     - :class:`str` or :class:`bytes`, at most 253 octets encoded; a
       received value which is not valid UTF-8 is returned as
       :class:`bytes`
   * - ipaddr
     - IPv4 address
     - :class:`str`, e.g. ``'192.0.2.1'``
   * - date
     - 32 bits UNIX timestamp
     - :class:`int`
   * - octets
     - arbitrary binary data
     - :class:`bytes`; a value starting with ``0x`` is decoded from hex
   * - abinary
     - Ascend binary filter
     - Ascend filter :class:`str`, e.g. ``'family=ipv4 action=accept
       direction=in'``; received values are returned as :class:`bytes`
   * - ipv6addr
     - 16 octets in network byte order
     - :class:`str` or :class:`ipaddress.IPv6Address`; received values
       are returned as :class:`str`
   * - ipv6prefix
     - up to 18 octets in network byte order
     - :class:`str` ``'address/length'``, e.g. ``'2001:db8::/32'``
   * - integer
     - 32 bits unsigned number
     - :class:`int`
   * - signed
     - 32 bits signed number
     - :class:`int`
   * - short
     - 16 bits unsigned number
     - :class:`int`
   * - byte
     - 8 bits unsigned number
     - :class:`int`
   * - integer64
     - 64 bits unsigned number
     - :class:`int`
   * - tlv
     - nested type-length-value
     - set the sub-attributes by their names; reading the TLV returns a
       :class:`dict` mapping sub-attribute names to lists of values
   * - ifid
     - 8 octets IPv6 interface identifier
     - :class:`str` ``'hhhh:hhhh:hhhh:hhhh'``, ``h`` being a hex digit
   * - ether
     - 6 octets Ethernet MAC address
     - :class:`str` ``'hh:hh:hh:hh:hh:hh'``, ``h`` being a hex digit,
       upper or lowercase
"""
import logging
import struct

from pyrad import bidict
from pyrad import tools
from pyrad import dictfile
from copy import copy

__docformat__ = "restructuredtext en"

logger = logging.getLogger('pyrad')


DATATYPES = frozenset(['string', 'ipaddr', 'integer', 'date', 'octets',
                       'abinary', 'ipv6addr', 'ipv6prefix', 'short', 'byte',
                       'signed', 'ifid', 'ether', 'tlv', 'integer64'])

# FreeRADIUS data types which pyrad does not support. Attributes of these
# types are skipped with a warning instead of failing the parse.
UNSUPPORTED_DATATYPES = frozenset(['vsa', 'extended', 'long-extended', 'evs',
                                   'ipv4prefix', 'combo-ip', 'bool', 'uint16',
                                   'uint32'])

# Attribute flags; a fifth ATTRIBUTE column that contains one of them is a
# list of flags instead of a vendor name.
ATTRIBUTE_FLAGS = frozenset(['has_tag', 'encrypt', 'secret', 'array',
                             'virtual', 'concat'])


class ParseError(Exception):
    """A dictionary file can't be parsed.

    Raised for syntax errors and recursive includes. Note that it is not a
    subclass of :exc:`ValueError`.

    :ivar msg: error message
    :vartype msg: str
    :ivar file: name of the dictionary file, or ``''``
    :vartype file: str
    :ivar line: line number on which the error occurred, or -1
    :vartype line: int
    """

    def __init__(self, msg=None, **data):
        self.msg = msg
        self.file = data.get('file', '')
        self.line = data.get('line', -1)

    def __str__(self):
        str = ''
        if self.file:
            str += self.file
        if self.line > -1:
            str += '(%d)' % self.line
        if self.file or self.line > -1:
            str += ': '
        str += 'Parse error'
        if self.msg:
            str += ': %s' % self.msg

        return str


def _format_location(file, line):
    """Render a (file, line) definition location for an error message."""
    loc = file or ''
    if line > -1:
        loc += '(%d)' % line
    return loc or '<unknown>'


class DictionaryConflictError(ParseError):
    """Two dictionary definitions disagree on the same wire data.

    Raised only by a strict :class:`Dictionary` (``strict=True``) when a
    newly read definition cannot be merged with an earlier one without
    changing how the same wire bytes are interpreted. It is a subclass of
    :exc:`ParseError`, so code handling :exc:`ParseError` keeps working.

    In addition to the location of the conflicting definition (``file`` and
    ``line``) the location of the earlier definition is available as
    :attr:`other_file` and :attr:`other_line`.

    :ivar other_file: name of the file of the earlier definition, or ``''``
    :vartype other_file: str
    :ivar other_line: line number of the earlier definition, or -1
    :vartype other_line: int
    """

    def __init__(self, msg=None, other_file='', other_line=-1, **data):
        ParseError.__init__(self, msg, **data)
        self.other_file = other_file
        self.other_line = other_line

    def __str__(self):
        text = ParseError.__str__(self)
        text += '; previous definition at %s' % _format_location(
            self.other_file, self.other_line)
        return text


class Attribute(object):
    """The definition of an attribute in a :class:`Dictionary`.

    Raises :exc:`ValueError` for an unsupported data type.

    :ivar name: name of the attribute
    :vartype name: str
    :ivar code: attribute code, for a sub-attribute its code in the TLV
    :vartype code: int
    :ivar type: data type, e.g. ``'string'``
    :vartype type: str
    :ivar vendor: name of the vendor, ``''`` for a standard attribute
    :vartype vendor: str
    :ivar encrypt: encryption method of the ``encrypt=`` flag, 0 for none
    :vartype encrypt: int
    :ivar has_tag: the attribute is tagged (RFC 2868)
    :vartype has_tag: bool
    :ivar values: named values, mapping the name to the encoded value
    :vartype values: pyrad.bidict.BiDict
    :ivar sub_attributes: names of the sub-attributes of a TLV by their
        code
    :vartype sub_attributes: dict[int, str]
    :ivar parent: the TLV of a sub-attribute, else None
    :vartype parent: Attribute or None
    :ivar is_sub_attribute: the attribute is a sub-attribute of a TLV
    :vartype is_sub_attribute: bool
    :ivar file: name of the dictionary file defining the attribute, or ``''``
    :vartype file: str
    :ivar line: line number of the definition, or -1
    :vartype line: int
    """

    def __init__(self, name, code, datatype, is_sub_attribute=False, vendor='', values=None,
                 encrypt=0, has_tag=False, file='', line=-1):
        if datatype not in DATATYPES:
            raise ValueError('Invalid data type')
        self.name = name
        self.code = code
        self.type = datatype
        self.vendor = vendor
        self.encrypt = encrypt
        self.has_tag = has_tag
        self.values = bidict.BiDict()
        self.sub_attributes = {}
        self.parent = None
        self.is_sub_attribute = is_sub_attribute
        self.file = file
        self.line = line
        # (file, line) of a VALUE definition, by value name
        self._value_origins = {}
        if values:
            for (key, value) in values.items():
                self.values.Add(key, value)


class Dictionary:
    """RADIUS dictionary.

    Stores the vendors, attributes and their values defined in RADIUS
    dictionary files. ``Dictionary(path, *more)`` reads the files in
    order, see :meth:`ReadDictionary`. ``dictionary['User-Name']`` returns
    the :class:`Attribute` of that name and ``'User-Name' in dictionary``
    checks whether it is defined.

    With ``strict=True`` the dictionary is loaded strictly: every
    :meth:`ReadDictionary` call is an all-or-nothing transaction, and a
    definition that would make the same name, vendor/code, TLV parent path
    or type options mean something different than an earlier definition
    raises :class:`DictionaryConflictError` instead of silently overriding
    it. A failed load leaves the dictionary exactly as it was before the
    call. Definitions with the same meaning, including an alias (another
    name for the exact same attribute) and another VALUE name for the same
    encoded value, remain allowed.

    :ivar attributes: attributes by name
    :vartype attributes: dict[str, Attribute]
    :ivar attrindex: attribute names and the keys of the attributes in a
        packet: the code, ``(vendor, code)`` for a vendor attribute,
        ``(tlv code, code)`` for a sub-attribute and
        ``(vendor, tlv code, code)`` for a sub-attribute of a vendor TLV,
        with the vendor ID as vendor
    :vartype attrindex: pyrad.bidict.BiDict
    :ivar vendors: vendor names and IDs, ``''`` is vendor 0
    :vartype vendors: pyrad.bidict.BiDict
    :ivar skipped_attributes: names of the attributes that were skipped
        because pyrad does not support them; using them raises a
        :exc:`KeyError`
    :vartype skipped_attributes: set[str]
    :ivar strict: conflicting definitions raise
        :class:`DictionaryConflictError` instead of overriding earlier ones,
        and a failed :meth:`ReadDictionary` rolls back completely
    :vartype strict: bool
    """

    def __init__(self, dict=None, *dicts, strict=False):
        """
        :param dict: path of a dictionary file or file-like object to read
        :type  dict: str or io.TextIOBase
        :param dicts: further dictionary files to read
        :type  dicts: str or io.TextIOBase
        :param strict: reject conflicting definitions and make each load
            atomic; see the class description
        :type  strict: bool
        """
        self.vendors = bidict.BiDict()
        self.vendors.Add('', 0)
        self.attrindex = bidict.BiDict()
        self.attributes = {}
        self.defer_parse = []
        self.skipped_attributes = set()
        # vendors whose attribute format is not the RFC 2865 one
        self._unsupported_vendors = set()
        # TLVs by (vendor code, attribute code), kept across ReadDictionary
        # calls so that sub-attributes can be defined in another file
        self._tlvs = {}
        # (vendor code, attribute code) of skipped top-level attributes,
        # whose sub-attributes are skipped as well
        self._skipped_codes = set()
        # (file, line) of a VENDOR definition, by vendor name
        self._vendor_origins = {'': ('', -1)}
        self.strict = strict

        if dict:
            self.ReadDictionary(dict)

        for i in dicts:
            self.ReadDictionary(i)

    def __len__(self):
        return len(self.attributes)

    def __getitem__(self, key):
        return self.attributes[key]

    def __contains__(self, key):
        return key in self.attributes

    has_key = __contains__

    def __SkipAttribute(self, state, name, reason):
        self.skipped_attributes.add(name)
        state['skipped'].append(reason)
        logger.debug('%s(%d): skipping attribute %s: %s',
                     state['file'], state['line'], name, reason)

    def _snapshot(self):
        """Return a snapshot of every piece of mergeable dictionary state.

        Used to roll a strict load back when it fails. The index and vendor
        maps are copied with their own (immutable) keys and values, while
        :class:`Attribute` objects are shared: a restore keeps the original
        objects and re-links the TLV parent pointers and the TLV registry
        back onto them, so no index entry can end up pointing at a different
        object than the restored dictionary.
        """
        vendors = bidict.BiDict()
        vendors.forward = self.vendors.forward.copy()
        vendors.backward = self.vendors.backward.copy()
        attrindex = bidict.BiDict()
        attrindex.forward = self.attrindex.forward.copy()
        attrindex.backward = self.attrindex.backward.copy()

        def clone_bidict(source):
            cloned = bidict.BiDict()
            cloned.forward = source.forward.copy()
            cloned.backward = source.backward.copy()
            return cloned

        # per-attribute mutable maps, restored onto the same objects so a
        # VALUE or sub-attribute added by a failed load does not survive
        attr_state = {
            name: (clone_bidict(attrdef.values),
                   attrdef.sub_attributes.copy(),
                   attrdef._value_origins.copy())
            for (name, attrdef) in self.attributes.items()
        }
        return {
            'vendors': vendors,
            'attrindex': attrindex,
            'attributes': self.attributes.copy(),
            'attr_state': attr_state,
            'defer_parse': self.defer_parse.copy(),
            'skipped_attributes': self.skipped_attributes.copy(),
            '_unsupported_vendors': self._unsupported_vendors.copy(),
            '_tlvs': self._tlvs.copy(),
            '_skipped_codes': self._skipped_codes.copy(),
            '_vendor_origins': self._vendor_origins.copy(),
        }

    def _restore(self, snapshot):
        """Restore the dictionary to a snapshot taken before a load."""
        self.vendors = snapshot['vendors']
        self.attrindex = snapshot['attrindex']
        self.attributes = snapshot['attributes']
        self.defer_parse = snapshot['defer_parse']
        self.skipped_attributes = snapshot['skipped_attributes']
        self._unsupported_vendors = snapshot['_unsupported_vendors']
        self._tlvs = snapshot['_tlvs']
        self._skipped_codes = snapshot['_skipped_codes']
        self._vendor_origins = snapshot['_vendor_origins']

        # restore the per-attribute VALUE and sub-attribute maps
        for (name, attrdef) in self.attributes.items():
            (values, sub_attributes, value_origins) = snapshot['attr_state'][name]
            attrdef.values = values
            attrdef.sub_attributes = sub_attributes
            attrdef._value_origins = value_origins

        # the TLV registry and the sub-attribute parent pointers must refer
        # to the same restored Attribute objects as ``attributes``
        for (key, tlv) in list(self._tlvs.items()):
            restored = self.attributes.get(tlv.name)
            if restored is not None:
                self._tlvs[key] = restored
        for attrdef in self.attributes.values():
            if attrdef.is_sub_attribute and attrdef.parent is not None:
                attrdef.parent = self.attributes[attrdef.parent.name]

    @staticmethod
    def _same_definition(existing, datatype, vendor, encrypt, has_tag, parent):
        """Whether a new attribute defines the exact same meaning as an
        existing one, in which case it is a harmless duplicate or alias.
        """
        return (existing.type == datatype
                and existing.vendor == vendor
                and existing.encrypt == encrypt
                and existing.has_tag == has_tag
                and existing.parent is parent)

    def _conflict(self, state, msg, other):
        """Raise a DictionaryConflictError naming both definitions.

        :param other: the earlier :class:`Attribute`, or a ``(file, line)``
            tuple for definitions that are not attributes
        """
        if isinstance(other, Attribute):
            other_file = other.file
            other_line = other.line
        else:
            (other_file, other_line) = other
        raise DictionaryConflictError(
            msg, file=state['file'], line=state['line'],
            other_file=other_file, other_line=other_line)

    def _check_attribute(self, state, name, key, datatype, vendor,
                         encrypt, has_tag, parent):
        """Validate an attribute definition against earlier ones in strict
        mode.

        Returns the existing :class:`Attribute` when the new definition is
        an allowed duplicate or alias (the caller registers the name without
        building a second object), or ``None`` for a genuinely new
        attribute. Raises :class:`DictionaryConflictError` on a real
        conflict.
        """
        existing_by_name = self.attributes.get(name)
        existing_by_key = None
        if self.attrindex.HasBackward(key):
            existing_by_key = self.attributes[self.attrindex.GetBackward(key)]

        if existing_by_name is not None \
                and self.attrindex.HasForward(name) \
                and self.attrindex.GetForward(name) != key:
            self._conflict(
                state,
                'attribute %s is already defined with key %r, not key %r'
                % (name, self.attrindex.GetForward(name), key),
                existing_by_name)

        if existing_by_name is not None \
                and existing_by_key is not None \
                and existing_by_name is not existing_by_key:
            self._conflict(
                state,
                'key %r is already defined as %s, not as %s'
                % (key, existing_by_key.name, name),
                existing_by_key)

        existing = existing_by_name if existing_by_name is not None \
            else existing_by_key
        if existing is None:
            return None

        if not self._same_definition(existing, datatype, vendor, encrypt,
                                     has_tag, parent):
            self._conflict(
                state,
                'attribute %s conflicts with %s on key %r: different type, '
                'flags or TLV parent'
                % (name, existing.name, key),
                existing)
        return existing

    def __ParseAttribute(self, state, tokens):
        if len(tokens) not in [4, 5]:
            raise ParseError(
                'Incorrect number of tokens for attribute definition',
                file=state['file'],
                line=state['line'])

        vendor = state['vendor']
        has_tag = False
        encrypt = 0
        array = False
        if len(tokens) >= 5:
            def keyval(o):
                kv = o.split('=')
                if len(kv) == 2:
                    return (kv[0], kv[1])
                else:
                    return (kv[0], None)
            options = [keyval(o) for o in tokens[4].split(',')]
            is_flags = any(key in ATTRIBUTE_FLAGS for (key, val) in options)
            if self.vendors.HasForward(tokens[4]) and \
                    not any(key in ('has_tag', 'encrypt')
                            for (key, val) in options):
                vendor = tokens[4]
            elif not is_flags:
                raise ParseError('Unknown vendor ' + tokens[4],
                                 file=state['file'],
                                 line=state['line'])
            for (key, val) in options if is_flags else []:
                if key == 'has_tag':
                    has_tag = True
                elif key == 'encrypt':
                    if val not in ['1', '2', '3']:
                        raise ParseError(
                                'Illegal attribute encryption: %s' % val,
                                file=state['file'],
                                line=state['line'])
                    encrypt = int(val)
                elif key == 'array':
                    array = True

        (attribute, code, datatype) = tokens[1:4]

        codes = code.split('.')

        # Codes can be sent as hex, or octal or decimal string representations.
        tmp = []
        try:
            for c in codes:
                if c.startswith('0x'):
                    tmp.append(int(c, 16))
                elif c.startswith('0o'):
                    tmp.append(int(c, 8))
                else:
                    tmp.append(int(c, 10))
        except ValueError:
            raise ParseError('Illegal attribute code: ' + code,
                             file=state['file'],
                             line=state['line'])
        codes = tmp

        datatype = datatype.split("[")[0]

        if datatype not in DATATYPES and datatype not in UNSUPPORTED_DATATYPES:
            raise ParseError('Illegal type: ' + datatype,
                             file=state['file'],
                             line=state['line'])

        vendor_code = self.vendors.GetForward(vendor)
        if len(codes) > 1 and (vendor_code, codes[0]) in self._skipped_codes:
            return self.__SkipAttribute(
                state, attribute, 'sub-attribute of unsupported attribute')
        if state['vendor_format']:
            return self.__SkipAttribute(
                state, attribute, 'extended vendor-specific attribute')
        if vendor in self._unsupported_vendors:
            return self.__SkipAttribute(state, attribute, 'vendor format')
        if datatype in UNSUPPORTED_DATATYPES:
            if len(codes) == 1:
                self._skipped_codes.add((vendor_code, codes[0]))
                self._tlvs.pop((vendor_code, codes[0]), None)
            return self.__SkipAttribute(state, attribute,
                                        'data type ' + datatype)
        if array:
            return self.__SkipAttribute(state, attribute, 'array flag')
        if len(codes) > 2 or (len(codes) == 2 and datatype == 'tlv'):
            return self.__SkipAttribute(state, attribute, 'nested TLV')

        is_sub_attribute = (len(codes) > 1)
        if len(codes) == 2:
            code = int(codes[1])
            parent_code = int(codes[0])
            parent = self._tlvs.get((vendor_code, parent_code))
            if parent is None:
                raise ParseError(
                    'Sub-attribute %s of unknown TLV %d' % (attribute,
                                                            parent_code),
                    file=state['file'],
                    line=state['line'])
        else:
            code = int(codes[0])
            parent_code = None

        if vendor:
            if is_sub_attribute:
                key = (vendor_code, parent_code, code)
            else:
                key = (vendor_code, code)
        else:
            if is_sub_attribute:
                key = (parent_code, code)
            else:
                key = code

        if state['strict']:
            existing = self._check_attribute(
                state, attribute, key, datatype, vendor, encrypt,
                has_tag, parent if is_sub_attribute else None)
            if existing is not None:
                # an exact duplicate or a legal alias of an existing
                # attribute: never create a second object for the same wire
                # definition
                if existing.name != attribute:
                    self.attrindex.Add(attribute, key)
                    self.attributes[attribute] = existing
                    if is_sub_attribute:
                        parent.sub_attributes[code] = attribute
                return

        attrdef = Attribute(attribute, code, datatype, is_sub_attribute,
                            vendor, encrypt=encrypt, has_tag=has_tag,
                            file=state['file'], line=state['line'])
        self.attrindex.Add(attribute, key)
        self.attributes[attribute] = attrdef
        if is_sub_attribute:
            # save sub attribute in parent tlv and update their parent field
            parent.sub_attributes[code] = attribute
            attrdef.parent = parent
        else:
            # a (re)defined top-level attribute replaces a skipped attribute
            # or TLV with the same code
            self._skipped_codes.discard((vendor_code, code))
            if datatype == 'tlv':
                self._tlvs[(vendor_code, code)] = attrdef
            else:
                self._tlvs.pop((vendor_code, code), None)

    def __ParseValue(self, state, tokens, defer):
        if len(tokens) != 4:
            raise ParseError('Incorrect number of tokens for value definition',
                             file=state['file'],
                             line=state['line'])

        (attr, key, value) = tokens[1:]

        if attr in self.skipped_attributes and attr not in self.attributes:
            return

        try:
            adef = self.attributes[attr]
        except KeyError:
            if defer:
                self.defer_parse.append((copy(state), copy(tokens)))
                return
            # FreeRADIUS dictionaries contain a few of these, so warn
            # instead of failing the parse
            logger.warning('%s(%d): ignoring value defined for unknown '
                           'attribute %s', state['file'], state['line'], attr)
            return

        try:
            if adef.type in ['integer', 'signed', 'short', 'byte',
                             'integer64', 'date']:
                value = int(value, 0)
            value = tools.EncodeAttr(adef.type, value)
        except (ValueError, TypeError, struct.error) as e:
            raise ParseError('Illegal value %s for attribute %s: %s'
                             % (tokens[3], attr, e),
                             file=state['file'],
                             line=state['line'])

        if state['strict'] and adef.values.HasForward(key) \
                and adef.values.GetForward(key) != value:
            self._conflict(
                state,
                'value %s of attribute %s redefined with another encoded '
                'value' % (key, attr),
                adef._value_origins[key])

        adef.values.Add(key, value)
        adef._value_origins[key] = (state['file'], state['line'])

    def __ParseVendor(self, state, tokens):
        if len(tokens) not in [3, 4]:
            raise ParseError(
                    'Incorrect number of tokens for vendor definition',
                    file=state['file'],
                    line=state['line'])

        (vendorname, vendor) = tokens[1:3]

        # the default format is the RFC 2865 one (1,1), which is supported
        new_supported = True
        # pyrad only encodes the RFC 2865 vendor attribute format (1 octet
        # type, 1 octet length), attributes of vendors with another format
        # are skipped
        if len(tokens) == 4:
            fmt = tokens[3].split('=')
            if fmt[0] != 'format':
                raise ParseError(
                        "Unknown option '%s' for vendor definition" % (fmt[0]),
                        file=state['file'],
                        line=state['line'])
            try:
                fmtargs = fmt[1].split(',')
                # ",c": WiMAX continuation octet
                continuation = len(fmtargs) == 3 and fmtargs[2] == 'c'
                if continuation:
                    fmtargs = fmtargs[:2]
                (token, length) = tuple(int(a) for a in fmtargs)
            except ValueError:
                raise ParseError(
                        'Syntax error in vendor specification',
                        file=state['file'],
                        line=state['line'])
            if token not in [1, 2, 4] or length not in [0, 1, 2]:
                raise ParseError(
                    'Unknown vendor format specification %s' % (fmt[1]),
                    file=state['file'],
                    line=state['line'])
            new_supported = (token, length, continuation) == (1, 1, False)

        try:
            vendor_code = int(vendor, 0)
        except ValueError:
            raise ParseError('Illegal vendor code: ' + vendor,
                             file=state['file'],
                             line=state['line'])

        if state['strict']:
            currently_supported = vendorname not in self._unsupported_vendors
            if vendorname in self._vendor_origins:
                existing_code = self.vendors.GetForward(vendorname)
                if existing_code != vendor_code:
                    self._conflict(
                        state,
                        'vendor %s redefined with another id (%d instead of '
                        '%d)' % (vendorname, vendor_code, existing_code),
                        self._vendor_origins[vendorname])
                if currently_supported != new_supported:
                    self._conflict(
                        state,
                        'vendor %s redefined with a different attribute '
                        'format' % vendorname,
                        self._vendor_origins[vendorname])
            if self.vendors.HasBackward(vendor_code) and \
                    self.vendors.GetBackward(vendor_code) != vendorname:
                self._conflict(
                    state,
                    'vendor id %d is already defined as %s' %
                    (vendor_code, self.vendors.GetBackward(vendor_code)),
                    self._vendor_origins[
                        self.vendors.GetBackward(vendor_code)])

        if new_supported:
            self._unsupported_vendors.discard(vendorname)
        else:
            self._unsupported_vendors.add(vendorname)
        self.vendors.Add(vendorname, vendor_code)
        self._vendor_origins[vendorname] = (state['file'], state['line'])

    def __ParseBeginVendor(self, state, tokens):
        if len(tokens) not in [2, 3]:
            raise ParseError(
                    'Incorrect number of tokens for begin-vendor statement',
                    file=state['file'],
                    line=state['line'])

        # BEGIN-VENDOR <vendor> format=<Extended-Vendor-Specific attribute>
        # defines extended vendor-specific attributes (RFC 6929), which are
        # skipped
        vendor_format = None
        if len(tokens) == 3:
            if not tokens[2].startswith('format='):
                raise ParseError(
                        "Unknown option '%s' for begin-vendor statement" %
                        tokens[2],
                        file=state['file'],
                        line=state['line'])
            vendor_format = tokens[2][len('format='):]

        vendor = tokens[1]

        if not self.vendors.HasForward(vendor):
            raise ParseError(
                    'Unknown vendor %s in begin-vendor statement' % vendor,
                    file=state['file'],
                    line=state['line'])

        state['vendor'] = vendor
        state['vendor_format'] = vendor_format

    def __ParseEndVendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                'Incorrect number of tokens for end-vendor statement',
                file=state['file'],
                line=state['line'])

        vendor = tokens[1]

        if state['vendor'] != vendor:
            raise ParseError(
                    'Ending non-open vendor ' + vendor,
                    file=state['file'],
                    line=state['line'])
        state['vendor'] = ''
        state['vendor_format'] = None

    def ReadDictionary(self, file):
        """Read a dictionary file.

        Its definitions are merged into the dictionary. In the default,
        lenient mode later definitions replace earlier ones. Unsupported
        attributes are skipped, listed in ``skipped_attributes``, and
        reported with one warning on the ``pyrad`` logger.

        In strict mode (``strict=True``) the call is atomic: a definition
        conflicting with an earlier one raises
        :class:`DictionaryConflictError`, and any other parse failure rolls
        the whole call back, leaving the previously loaded dictionary
        intact. Definitions with the same meaning (including legal aliases)
        are accepted.

        :param file: path of a dictionary file or a file-like object
        :type  file: str or io.TextIOBase
        :raises ParseError: for a syntax error or a recursive include
        :raises DictionaryConflictError: in strict mode, for a definition
            that changes the meaning of an existing one
        :raises OSError: if a file can't be opened
        """

        fil = dictfile.DictFile(file)

        state = {}
        state['vendor'] = ''
        state['vendor_format'] = None
        state['skipped'] = []
        state['strict'] = self.strict
        snapshot = self._snapshot() if self.strict else None
        try:
            self.defer_parse = []
            for line in fil:
                state['file'] = fil.File()
                state['line'] = fil.Line()
                line = line.split('#', 1)[0].strip()

                tokens = line.split()
                if not tokens:
                    continue

                key = tokens[0].upper()
                if key == 'ATTRIBUTE':
                    self.__ParseAttribute(state, tokens)
                elif key == 'VALUE':
                    self.__ParseValue(state, tokens, True)
                elif key == 'VENDOR':
                    self.__ParseVendor(state, tokens)
                elif key == 'BEGIN-VENDOR':
                    self.__ParseBeginVendor(state, tokens)
                elif key == 'END-VENDOR':
                    self.__ParseEndVendor(state, tokens)

            for deferred_state, tokens in self.defer_parse:
                key = tokens[0].upper()
                if key == 'VALUE':
                    self.__ParseValue(deferred_state, tokens, False)
            self.defer_parse = []
        except BaseException:
            if self.strict:
                self._restore(snapshot)
            raise

        if state['skipped']:
            reasons = sorted(set(state['skipped']))
            logger.warning('Skipped %d unsupported dictionary attributes (%s)',
                           len(state['skipped']), ', '.join(reasons))
