'''UEFI Firmware parser utils.
'''
from . import uefi
from .uefi import MultiVolumeContainer

from .misc import checker
from .base import FirmwareObject, RawObject, AutoRawObject
from .utils import limit_nesting, nesting_limit_reached, \
    search_firmware_volumes, set_lazy_parsing


class AutoParser(object):
    '''Automatically detect the file format type.

    The UEFI Firmware module supports several types of file formats:
      - UEFI Firmware Volumes
      - (U)EFI Capsule Updates
      - UEFI Firmware Files
      - Dell "PFS" Files
      - Intel ME Modules
      - Flash Descriptors and Regions

    If the input file format is unknown the AutoParser can attempt to discover
    the type by applying basic checks for known headers.
    '''

    def __init__(self, data, search=True, base=0, lazy=False):
        '''Create an AutoParser instance.

        Args:
            data (binary): The entire input file contents.
            search (Optional[bool]): Allow brute-force discovery of volumes.
            base (Optional[int]): The offset of data in the input file, when
                it follows other objects.
            lazy (Optional[bool]): Make parse() build the index instead of
                decoding every compressed branch. The default, False, is the
                full parser.
        '''
        self.data_type = 'unknown'
        self.constructor = None
        self.firmware = None
        self.base = base
        self.offset = 0
        self.default_lazy = bool(lazy)
        # Which entry built self.firmware: a full parse or an index.
        self._lazy_mode = None
        # The end of a volume that was found but failed to process. Its bytes,
        # and any volume inside them, have already been parsed once.
        self.failed_end = 0

        if search:
            self.offset = 0
            while data[self.offset:self.offset + 1024] == b'\xFF' * 1024:
                self.offset += 1024
            if self.offset > 0:
                data = data[self.offset:]
        self.data = data

        for tester in checker.TESTERS:
            if tester().match(data[:tester.header_size]):
                self.data_type = tester().name
                self.constructor = tester().parser

    def type(self):
        '''Return the discovered file format type.

        If the type could not be matched, 'unknown' is returned.

        Return:
            string: Name of the file format type.
        '''
        return self.data_type

    @limit_nesting(None)
    def parse(self, lazy=None):
        '''Call the 'process' method for the discovered type using the input
        file contents. If the file type's parser returns False indicating a
        failure or exception while parsing this will return None.

        Args:
            lazy (Optional[bool]): Build the structure index instead, leaving
                compressed branches unexpanded. This is the same as 'index'.
                When omitted, the parser's 'lazy' setting applies; the
                default is the full parse.

        Return:
            object: The associated file object upon success, otherwise None.
        '''
        if lazy is None:
            lazy = self.default_lazy
        return self._parse(lazy=bool(lazy))

    @limit_nesting(None)
    def index(self):
        '''Build an index of the discovered type without decoding every
        compressed branch.

        The returned object has the same shape as the one 'parse' returns.
        Compressed and unknown GUID-defined wrappers are listed with their
        raw material and an 'unexpanded' state; call 'expand' on one of them
        to decode just that branch, or 'expand_all' on the result to get the
        structure 'parse' would have given.

        Return:
            object: The associated file object upon success, otherwise None.
        '''
        return self._parse(lazy=True)

    def build_index(self):
        '''An alias for index.'''
        return self.index()

    def _parse(self, lazy):
        if self.constructor is None:
            return None
        if self.firmware is not None:
            if not lazy and self._lazy_mode:
                # This instance built an index first. The full entry still
                # gives a fully decoded tree.
                self.firmware.expand_all()
                self._lazy_mode = False
            return self.firmware

        # Instantiate an instance of the firmware object
        self.firmware = self.constructor(self.data)
        self._lazy_mode = bool(lazy)
        refused = nesting_limit_reached()
        previous = set_lazy_parsing(lazy)
        try:
            status = self.firmware.process()
        finally:
            set_lazy_parsing(previous)
        if not status:
            # Parsing failed, remove the object reference. A volume the
            # nesting limit refused was not parsed, so a caller nearer the
            # top may still parse it.
            if isinstance(self.firmware, uefi.FirmwareVolume) and not refused:
                self.failed_end = self.offset + self.firmware.size
            self.firmware = None
            return None

        if self.base > 0 and isinstance(self.firmware, uefi.FirmwareVolume):
            # Volumes are named by offset, and each one found after the
            # first would otherwise be named 0 and dump to the same path.
            self.firmware.name = hex(self.base + self.offset)

        objs = [self.firmware]
        size = self.firmware.size
        if size <= 0:
            # Without the object's extent, the trailing data would be parsed
            # again from the same offset.
            return self.firmware

        tried = 0
        previous = set_lazy_parsing(lazy)
        try:
            while size < len(self.data):
                raw = AutoRawObject(
                    self.data[size:], offset=self.base + self.offset + size)
                if not raw.process() or raw.object.size <= 0:
                    # An object that covers no bytes would be found again
                    # here. Parsing a volume that failed again would double
                    # the work at each level of nesting.
                    tried = raw.failed_end
                    break
                size += raw.object.size
                objs.append(raw.object)

            mfc = MultiVolumeContainer(self.data[size:], start=tried)
            if mfc.has_indexes():
                # Headers were discovered, attempt to process.
                if mfc.process():
                    size += mfc.size
                    # Add the base (first) firmware volume
                    objs = objs + mfc.objects
        finally:
            set_lazy_parsing(previous)

        if size < len(self.data):
            objs.append(RawObject(self.data[size:]))

        if self.offset > 0:
            objs = [RawObject(b'\xFF' * self.offset)] + objs

        if len(objs) == 1:
            return objs[0]
        return MultiObject(objs)


class MultiObject(FirmwareObject):
    def __init__(self, objs):
        self.objs = objs

    @property
    def size(self):
        return sum([obj.size for obj in self.objs])

    @property
    def objects(self):
        return self.objs

    def index_children(self):
        return [obj for obj in self.objs if obj is not None]

    def showinfo(self, ts='', index=None):
        for i in range(len(self.objs)):
            self.objs[i].showinfo(ts, i)

    def to_dict(self):
        def get_fvs(multi_object):
            volumes = []
            for i in range(len(multi_object.objs)):
                obj = multi_object.objs[i]
                if type(obj) is uefi.FirmwareVolume:
                    volumes.append(obj.to_dict())
                if type(obj) is MultiObject:
                    volumes.extend(get_fvs(obj))
            return volumes
        volumes = get_fvs(self)

        return { 'regions': [
            {
                'type': 'bios',
                'data': { 'firmwareVolumes': volumes },
            }
        ] }

    def dump(self, parent='', index=None):
        for i in range(len(self.objs)):
            self.objs[i].dump(parent, i)


__title__ = "uefi_firmware"
try:
    from ._version import version as __version__
except ImportError:
    __version__ = "0.1.0+unknown"
__author__ = "UEFI Firmware Parser developers"
__license__ = "MIT"
