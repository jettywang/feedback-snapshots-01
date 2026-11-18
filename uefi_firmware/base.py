'''Base provides basic firmware object structures.
'''


import os
import ctypes

from .utils import dump_data, sguid, blue, utf8_decode_safe, is_erased, \
    limit_nesting, set_lazy_parsing, lazy_parsing


class BaseObject(object):
    '''A base object can be used to access direct content.'''


# How much of an object has been parsed. An index holds objects in the
# unexpanded state: their headers are known, but the compressed payload has
# not been decoded. A failed object keeps the bytes it was parsed from.
PARSE_PARSED = "parsed"
PARSE_UNEXPANDED = "unexpanded"
PARSE_EXPANDED = "expanded"
PARSE_FAILED = "failed"
PARSE_OPAQUE = "opaque"


class FirmwareObject(object):
    '''A pseudo-abstract type providing common firmware member facilities.'''
    def __init__(self):
        self.data = None
        self._name = None
        self.attrs = None
        self.guid = None

    @property
    def parse_state(self):
        '''How much of this object has been parsed, see PARSE_* above.

        A branch that a caller expanded reports 'parsed', the same as one the
        full parser decoded. The distinction between the two is internal, so
        comparing an expanded index with the full parser's tree matches.
        '''
        state = getattr(self, "_parse_state", PARSE_PARSED)
        if state == PARSE_EXPANDED:
            return PARSE_PARSED
        return state

    @property
    def unexpanded(self):
        '''Whether this object is a known wrapper whose payload is still
        compressed.'''
        return self.parse_state == PARSE_UNEXPANDED

    @property
    def deferred(self):
        '''An alias for unexpanded, for callers that describe a branch as
        deferred until it is accessed.'''
        return self.unexpanded

    @property
    def expanded(self):
        '''Whether the payload of this object has been decoded.'''
        return self.parse_state in (PARSE_PARSED, PARSE_EXPANDED)

    @property
    def failed(self):
        '''Whether the last attempt to parse this object failed.'''
        return self.parse_state == PARSE_FAILED

    @property
    def opaque(self):
        '''Whether this object is a wrapper of a kind the parser does not
        know, so only its raw material is available.'''
        return self.parse_state == PARSE_OPAQUE

    @property
    def parse_error(self):
        '''Why the last parse or expansion of this object failed, if it did.'''
        return getattr(self, "_failure", None)

    @property
    def error(self):
        '''An alias for parse_error.'''
        return self.parse_error

    @property
    def parse_status(self):
        '''An alias for parse_state.'''
        return self.parse_state

    @property
    def wrapper(self):
        '''The kind of wrapper this object is, when it defers a payload.'''
        return getattr(self, "_wrapper", None)

    @property
    def wrapper_known(self):
        '''Whether the parser knows how to transform this wrapper.

        An unknown GUID-defined section keeps its material, so a caller can
        recognize it as an unhandled wrapper rather than an empty subtree.
        '''
        return getattr(self, "_wrapper_known", True)

    @property
    def compression_kind(self):
        '''The compression method of a deferred wrapper, when known.'''
        return getattr(self, "_compression", None)

    @property
    def raw_data(self):
        '''The bytes this object was parsed from.

        A deferred or failed object keeps its original material, so a caller
        can decide how to process it without asking the parser to decode it.
        '''
        raw = getattr(self, "_raw_data", None)
        if raw is None:
            raw = getattr(self, "_data", None)
        if raw is not None:
            return raw
        if hasattr(self, "data") and isinstance(self.data, bytes):
            return self.data
        return b""

    @property
    def raw(self):
        '''An alias for raw_data.'''
        return self.raw_data

    @property
    def material(self):
        '''An alias for raw_data, the input bytes kept for this object.'''
        return self.raw_data

    def index_children(self):
        '''Return the children known without expanding this object.

        A deferred branch has no children until it is accessed, so the index
        lists the wrapper itself instead of decoding what it holds.
        '''
        if self.unexpanded or self.opaque:
            return []
        return [child for child in self.objects if child is not None]

    def expand(self):
        '''Decode and parse this object if it is deferred.

        Objects that are not deferred are returned unchanged. An expanded
        object is cached, so calling this again does no work, and a branch
        that failed to decode is not decoded again either.

        Only this object's own wrapper is transformed. Compressed wrappers
        below it stay deferred until they are expanded themselves.
        '''
        if not self.unexpanded:
            return self
        if getattr(self, "_expanding", False):
            return self
        self._expanding = True
        previous = set_lazy_parsing(True)
        try:
            self._expand_payload()
            if self._parse_state == PARSE_UNEXPANDED:
                # The payload was decoded without reporting a failure or an
                # unknown wrapper, so this branch is now ordinary parsed data.
                self._parse_state = PARSE_EXPANDED
        except Exception as error:
            # A malformed payload fails this branch, not the parse that
            # reached it. Keep the material and the failure for the caller.
            self._parse_state = PARSE_FAILED
            self._failure = "%s: %s" % (type(error).__name__, str(error))
        finally:
            set_lazy_parsing(previous)
            self._expanding = False
        return self

    @limit_nesting(None)
    def expand_all(self):
        '''Expand this object and every deferred branch below it.

        This yields the same structure the full parser builds, without
        changing how any existing object was parsed. All expansions share
        one decompression budget, like the full parser's.
        '''
        self._expand_all()
        return self

    def _expand_all(self):
        self.expand()
        for child in self.index_children():
            child._expand_all()

    def index_tree(self):
        '''Return the structural index of this object and its children.

        Each entry keeps "_self" pointing at the object, so a caller can
        expand the branch it is interested in. The entry's "state" says
        whether that branch is unexpanded, expanded, failed or opaque.
        '''
        return self.to_index()

    def iter_unexpanded(self):
        '''Yield the deferred branches at or below this object.'''
        if self.unexpanded:
            yield self
            return
        for child in self.index_children():
            for branch in child.iter_unexpanded():
                yield branch

    def _expand_payload(self):
        '''Run the transformation a deferred object needs.

        Subclasses that defer work override this. The default only clears the
        deferred state, which is right for a wrapper with nothing to decode.
        '''

    def to_index(self):
        '''Return this object as a structural index.

        The index reports the known wrapper, how much of the object has been
        parsed, and its children. Deferred branches are listed without being
        decoded; call 'expand' on an entry's "_self" to decode it. The
        entries also keep that object reference, so 'to_index_json' leaves it
        out for a JSON-serializable copy.
        '''
        children = []
        for child in self.index_children():
            children.append(child.to_index())
        index = {
            '_self': self,
            'type': self.type_label,
            'label': self.label,
            'guid': self.guid_label,
            'state': self.parse_state,
            'status': self.parse_state,
            'wrapper': self.wrapper,
            'wrapperKnown': self.wrapper_known,
            'compression': self.compression_kind,
            'size': len(self.raw_data),
            'children': children,
        }
        if self.parse_state == PARSE_UNEXPANDED:
            # A caller can see that the branch exists and what holds it,
            # without this entry claiming to be an empty subtree.
            index['unexpanded'] = True
            index['rawSize'] = len(self.raw_data)
        if self.failed:
            index['error'] = self.parse_error or 'parse failed'
        if self.opaque:
            # There is no known transformation for this wrapper. Its input
            # bytes are the material a caller has to work with.
            index['rawSize'] = len(self.raw_data)
            index['opaque'] = True
        return index

    def index_dict(self):
        '''An alias for to_index.'''
        return self.to_index()

    def to_index_json(self):
        '''Return to_index output that json can serialize.

        Each entry's "_self" is a Python object, so it is left out here. Use
        to_index when the caller needs to expand a branch from its entry.
        '''
        index = self.to_index()
        self._drop_index_self(index)
        return index

    def _drop_index_self(self, index):
        index.pop('_self', None)
        for child in index['children']:
            self._drop_index_self(child)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        if isinstance(name, bytes):
            name = utf8_decode_safe(name)
        self._name = name

    @property
    def content(self):
        '''The object content is the 'data' stream.'''
        if hasattr(self, "data") and self.data is not None:
            return self.data
        return ""

    @property
    def objects(self):
        '''Objects are the child firmware objects found via 'processing'.'''
        return []

    @property
    def label(self):
        '''An overload for an object 'name'.'''
        if hasattr(self, "name") and self.name is not None:
            if self.name is None:
                return ""
            return self.name
        return ""

    @property
    def guid_label(self):
        '''A string representation of an optional 'guid' field.'''
        if not hasattr(self, "guid") or self.guid is None:
            return ""
        return sguid(self.guid)

    @property
    def type_label(self):
        '''The string representation of the object's class name.'''
        return self.__class__.__name__

    @property
    def attrs_label(self):
        '''An overload for the 'attrs' field.'''
        if hasattr(self, "attrs") and self.attrs is not None:
            return self.attrs
        return {}

    def info(self, include_content=False):
        '''Firmwae objects define a common interface for information.

        This defines: label, guid, type, content, attrs-- as common between
        most firmware objects.

        Args:
            include_content (Optional[bool]): Include a pointer to the 'data'
            or content stream.

        Return:
            dict: Return a pointer to this object "_self" and the defines listed
                above with an optional pointer to the data stream.
        '''
        return {
            "_self": self,
            "label": self.label,
            "guid": self.guid_label,
            "type": self.type_label,
            "content": self.content if include_content else "",
            "attrs": self.attrs_label
        }

    def iterate_objects(self, include_content=False):
        '''Flatten this object's children into a list.

        This mis-named as an interation. Each object within the children list
        is recursively 'iterated', meaning its 'iterate_objects' method is
        called. The object is represented via the 'info' method. Access to the
        object is possible via the "_self" key.

        The output list does not include this object but each entry sets a
        "_parent" key with a pointer to this object.

        Return:
            list: flattened list of firmware objects.
        '''
        objects = []
        for _object in self.objects:
            if _object is None:
                continue
            _info = _object.info(include_content)
            if _object.unexpanded:
                # Traversal that reports an index leaves the branch closed,
                # and says so, instead of decoding it just to list children.
                _info["objects"] = []
                _info["unexpanded"] = True
            else:
                _info["objects"] = _object.iterate_objects(include_content)
            for _object in _info["objects"]:
                _object["parent"] = _info
            objects.append(_info)
        return objects


class StructuredObject(object):
    def __init__(self):
        self.fields = []

    def parse_structure(self, data, structure):
        '''Construct an instance object of the provided structure.'''
        struct_instance = structure()
        struct_size = ctypes.sizeof(struct_instance)

        # data may be a memoryview over a larger buffer; copy only the header.
        struct_data = bytes(data[:struct_size])
        struct_length = min(len(struct_data), struct_size)
        ctypes.memmove(
            ctypes.addressof(struct_instance), struct_data, struct_length)
        self.structure = struct_instance
        self.structure_data = struct_data
        self.structure_fields = [field[0] for field in structure._fields_]
        self.structure_size = struct_size

    def show_structure(self):
        for field in self.fields:
            print("%s: %s" % (field, getattr(self.structure, field, None)))


class RawObject(FirmwareObject, BaseObject):

    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def build(self, generate_checksum, debug=False):
        return self.data

    def showinfo(self, ts='', index=None):
        print("%s%s size= %d " % (
            ts, blue("RawObject:"), len(self.data)
        ))

    def to_dict(self):
        return {
            'size': len(self.data),
        }

    def dump(self, parent='', index=0):
        path = os.path.join(parent, "object-%s.raw" % (str(index)))
        dump_data(path, self.data)


class PaddingObject(RawObject):
    '''Data between parsed objects, such as the gap between two volumes.

    Padding is usually erased flash. It is only shown and dumped when it
    holds something else, since vendors sometimes store data there.
    '''

    def __init__(self, data, offset):
        RawObject.__init__(self, data)
        self.offset = offset

    @property
    def erased(self):
        return is_erased(self.data)

    def process(self):
        return True

    def showinfo(self, ts='', index=None):
        if self.erased:
            return
        print("%s%s offset= 0x%x, size= 0x%x (%d bytes)" % (
            ts, blue("Padding:"), self.offset, self.size, self.size
        ))

    def dump(self, parent='', index=None):
        if self.erased:
            return
        path = os.path.join(parent, "padding-0x%x.raw" % self.offset)
        dump_data(path, self.data)


class AutoRawObject(RawObject):
    '''A RawObject that applies AutoParser logic for embedded object discovery.
    '''

    def __init__(self, data, offset=0):
        self.object = None
        self.data = data
        # Where data starts in the input file, when that is known.
        self.offset = offset
        # The end of a volume in data that failed to process, see AutoParser.
        self.failed_end = 0

    @property
    def objects(self):
        if self.object is not None:
            return [self.object]
        return []

    def process(self):
        from . import AutoParser
        parser = AutoParser(self.data, base=self.offset)
        # A nested object is part of the parse that reached it, so it stays
        # in index mode when the caller asked for one.
        if lazy_parsing():
            self.object = parser.index()
        else:
            self.object = parser.parse()
        self.failed_end = parser.failed_end
        return self.object is not None

    def index_children(self):
        '''Return the managed object, or an empty list if there is none.'''
        if self.object is None:
            return []
        return [self.object]

    def showinfo(self, ts='', index=None):
        if self.object is None:
            print("%s%s size= %d " % (
                ts, blue("RawObject:"), len(self.data)
            ))
            return
        self.object.showinfo(ts)

    def to_dict(self):
        return {
            'size': len(self.data),
        }

    def dump(self, parent='', index=None):
        if self.object is None:
            path = os.path.join(parent, "object.raw")
            dump_data(path, self.data)
            return
        self.object.dump(parent)
