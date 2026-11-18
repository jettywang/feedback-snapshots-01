""" Parse a ppt (MS PowerPoint 97-2003) file

Based on olefile, parse the ppt-specific info

Code much influenced by olevba._extract_vba but much more object-oriented
(possibly slightly excessively so)

Currently quite narrowly focused on extracting VBA from ppt files, no slides or
stuff, but built to be extended to parsing more/all of the file. For better
"understanding" of ppt files, see module ppt_record_parser, which will probably
replace this module some time soon.

References:
* https://msdn.microsoft.com/en-us/library/dd921564%28v=office.12%29.aspx
  and links there-in

WARNING!
Before thinking about understanding or even extending this module, please keep
in mind that module ppt_record_parser has a better "understanding" of the ppt
file structure and will replace this module some time soon!

"""

# === LICENSE =================================================================
# TODO


#------------------------------------------------------------------------------
# TODO:
# - make stream optional in PptUnexpectedData
# - can speed-up by using less bigger struct.parse calls?
# - license
# - make buffered stream from output of iterative_decompress
# - maybe can merge the 2 decorators into 1? (with_opened_main_stream)
# - REPLACE THIS MODULE with ppt_record_parser


# CHANGELOG:
# 2016-05-04 v0.01 CH: - start parsing "Current User" stream
# 2016-07-20 v0.50 SL: - added Python 3 support
# 2016-09-13       PL: - fixed olefile import for Python 2+3
#                      - fixed format strings for Python 2.6 (issue #75)
# 2017-04-23 v0.51 PL: - fixed absolute imports and issue #101
# 2018-09-11 v0.54 PL: - olefile is now a dependency

__version__ = '0.54'


# --- IMPORTS ------------------------------------------------------------------

import sys
import logging
import struct
import traceback
import os
import zlib

# IMPORTANT: it should be possible to run oletools directly as scripts
# in any directory without installing them with pip or setup.py.
# In that case, relative imports are NOT usable.
# And to enable Python 2+3 compatibility, we need to use absolute imports,
# so we add the oletools parent folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
# print('_thismodule_dir = %r' % _thismodule_dir)
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
# print('_parent_dir = %r' % _thirdparty_dir)
if not _parent_dir in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile


# TODO: this is a temporary fix until all logging features are unified in oletools
def get_logger(name, level=logging.CRITICAL+1):
    """
    Create a suitable logger object for this module.
    The goal is not to change settings of the root logger, to avoid getting
    other modules' logs on the screen.
    If a logger exists with same name, reuse it. (Else it would have duplicate
    handlers and messages would be doubled.)
    The level is set to CRITICAL+1 by default, to avoid any logging.
    """
    # First, test if there is already a logger with the same name, else it
    # will generate duplicate messages (due to duplicate handlers):
    if name in logging.Logger.manager.loggerDict:
        #NOTE: another less intrusive but more "hackish" solution would be to
        # use getLogger then test if its effective level is not default.
        logger = logging.getLogger(name)
        # make sure level is OK:
        logger.setLevel(level)
        return logger
    # get a new logger:
    logger = logging.getLogger(name)
    # only add a NullHandler for this logger, it is up to the application
    # to configure its own logging:
    logger.addHandler(logging.NullHandler())
    logger.setLevel(level)
    return logger




# a global logger object used for debugging:
log = get_logger('ppt')


def enable_logging():
    """
    Enable logging for this module (disabled by default).
    This will set the module-specific logger level to NOTSET, which
    means the main application controls the actual logging level.
    """
    log.setLevel(logging.NOTSET)


#--- CONSTANTS ----------------------------------------------------------------

# name of main stream
MAIN_STREAM_NAME = 'PowerPoint Document'

# URL and message to report issues:
URL_OLEVBA_ISSUES = 'https://bitbucket.org/decalage/oletools/issues'
MSG_OLEVBA_ISSUES = 'Please report this issue on %s' % URL_OLEVBA_ISSUES


# === EXCEPTIONS ==============================================================


class PptUnexpectedData(Exception):
    """ raise by PptParser if some field's value is not as expected """
    def __init__(self, stream, field_name, found_value, expected_value):
        self.msg = \
            'In stream "{0}" for field "{1}" found value "{2}" but expected {3}!' \
            .format(stream, field_name, found_value, expected_value)
        super(PptUnexpectedData, self).__init__(self.msg)


# === HELPERS =================================================================

def read_1(stream):
    """ read 1 byte from stream """
    return struct.unpack('<B', stream.read(1))[0]


def read_2(stream):
    """ read 2 byte (short) from stream """
    return struct.unpack('<H', stream.read(2))[0]


def read_4(stream):
    """ read 4 byte (long) from stream """
    return struct.unpack('<L', stream.read(4))[0]


def check_value(name, value, expected):
    """ simplify verification of values in extract_from """
    if isinstance(expected, (list, tuple)):
        if value not in expected:
            exp_str = '[' + ' OR '.join('{0:04X}'.format(val)
                                        for val in expected) + ']'
            raise PptUnexpectedData(
                'Current User', name,
                '{0:04X}'.format(value), exp_str)
    elif expected != value:
        raise PptUnexpectedData(
            'Current User', name,
            '{0:04X}'.format(value), '{0:04X}'.format(expected))


# === STRUCTS =================================================================

class RecordHeader(object):
    """ a record header, at start of many types found in ppt files

    https://msdn.microsoft.com/en-us/library/dd926377%28v=office.12%29.aspx
    https://msdn.microsoft.com/en-us/library/dd948895%28v=office.12%29.aspx
    """

    def __init__(self):
        self.rec_ver = None
        self.rec_instance = None
        self.rec_type = None
        self.rec_len = None

    @classmethod
    def extract_from(clz, stream):
        """ reads 8 byte from stream """
        #log.debug('parsing RecordHeader from stream')
        obj = clz()
        # first half byte is version, next 3 half bytes are instance
        version_instance, = struct.unpack('<H', stream.read(2))
        obj.rec_instance, obj.rec_ver = divmod(version_instance, 2**4)
        obj.rec_type, = struct.unpack('<H', stream.read(2))
        obj.rec_len, = struct.unpack('<L', stream.read(4))
        #log.debug('type is {0:04X}, instance {1:04X}, version {2:04X},len {3}'
        #          .format(obj.rec_type, obj.rec_instance, obj.rec_ver,
        #                  obj.rec_len))
        return obj

    @classmethod
    def generate(clz, rec_type, rec_len=None, rec_instance=0, rec_ver=0):
        """ generate a record header string given values

        length of result depends on rec_len being given or not
        """
        if rec_type is None:
            raise ValueError('RECORD_TYPE not set!')
        version_instance = rec_ver + 2**4 * rec_instance
        if rec_len is None:
            return struct.pack('<HH', version_instance, rec_type)
        else:
            return struct.pack('<HHL', version_instance, rec_type, rec_len)


class PptType(object):
    """ base class of data types found in ppt ole files

    starts with a RecordHeader, has a extract_from and a check_validity method
    """

    RECORD_TYPE = None      # must be specified in subclasses
    RECORD_INSTANCE = 0x0   # can be overwritten in subclasses
    RECORD_VERSION = 0x000  # can be overwritten in subclasses

    @classmethod
    def extract_from(clz, stream):
        raise NotImplementedError('abstract base function!')

    def __init__(self, stream_name=MAIN_STREAM_NAME):
        self.stream_name = stream_name
        self.rec_head = None

    def read_rec_head(self, stream):
        self.rec_head = RecordHeader.extract_from(stream)

    def check_validity(self):
        """ check validity of data

        replaces 'raise PptUnexpectedData' so caller can get all the errors
        (not just the first) whenever she wishes.

        to be overwritten in subclasses

        :returns: list of PptUnexpectedData
        """
        raise NotImplementedError('abstract base function!')

    def check_value(self, name, value, expected):
        """ simplify verification of values: check value equals/is in expected

        :returns: list of PptUnexpectedData exceptions
        """
        if isinstance(expected, (list, tuple)):
            if value not in expected:
                clz_name = self.__class__.__name__
                exp_str = '[' + ' OR '.join('{0:04X}'.format(val)
                                            for val in expected) + ']'
                return [PptUnexpectedData(
                    self.stream_name, clz_name + '.' + name,
                    '{0:04X}'.format(value), exp_str), ]
        elif expected != value:
            clz_name = self.__class__.__name__
            return [PptUnexpectedData(
                self.stream_name, clz_name + '.' + name,
                '{0:04X}'.format(value), '{0:04X}'.format(expected)), ]
        return []

    def check_range(self, name, value, expect_lower, expect_upper):
        """ simplify verification of values: check value is in given range

        expect_lower or expected_upper can be given as None to check only one
        boundary. If value equals one of the boundaries, that is also an error
        (boundaries form an open interval)

        :returns: list of PptUnexpectedData exceptions
        """

        is_err = False
        if expect_upper is None and expect_lower is None:
            raise ValueError('need at least one non-None boundary!')
        if expect_lower is not None:
            if value <= expect_lower:
                is_err = True
        if expect_upper is not None:
            if value >= expect_upper:
                is_err = True

        if is_err:
            clz_name = self.__class__.__name__
            if expect_lower is None:
                expect_str = '< {0:04X}'.format(expect_upper)
            elif expect_upper is None:
                expect_str = '> {0:04X}'.format(expect_lower)
            else:
                expect_str = 'within ({0:04X}, {1:04X})'.format(expect_lower,
                                                                expect_upper)
            return [PptUnexpectedData(self.stream_name, clz_name + '.' + name,
                                      '{0:04X}'.format(value), expect_str), ]
        else:
            return []

    def check_rec_head(self, length=None):
        """ to be called by check_validity to check the self.rec_head

        uses self.RECORD_... constants, (not quite that constant for DummyType)
        """

        errs = []
        errs.extend(self.check_value('rec_head.recVer', self.rec_head.rec_ver,
                                     self.RECORD_VERSION))
        errs.extend(self.check_value('rec_head.recInstance',
                                     self.rec_head.rec_instance,
                                     self.RECORD_INSTANCE))
        if self.RECORD_TYPE is None:
            raise NotImplementedError('RECORD_TYPE not specified!')
        errs.extend(self.check_value('rec_head.recType',
                                     self.rec_head.rec_type,
                                     self.RECORD_TYPE))
        if length is not None:
            errs.extend(self.check_value('rec_head.recLen',
                                         self.rec_head.rec_len, length))
        return errs

    @classmethod
    def generate_pattern(clz, rec_len=None):
        """ call RecordHeader.generate with values for this type """
        return RecordHeader.generate(clz.RECORD_TYPE, rec_len,
                                     clz.RECORD_INSTANCE, clz.RECORD_VERSION)


class CurrentUserAtom(PptType):
    """ An atom record that specifies information about the last user to modify
    the file and where the most recent user edit is located. This is the only
    record in the Current User Stream (section 2.1.1).

    https://msdn.microsoft.com/en-us/library/dd948895%28v=office.12%29.aspx
    """

    # allowed values for header_token
    HEADER_TOKEN_ENCRYPT = 0xF3D1C4DF
    HEADER_TOKEN_NOCRYPT = 0xE391C05F

    # allowed values for rel_version
    REL_VERSION_CAN_USE = 0x00000008
    REL_VERSION_NO_USE = 0x00000009

    # required values
    RECORD_TYPE = 0x0FF6
    SIZE = 0x14
    DOC_FILE_VERSION = 0x03F4
    MAJOR_VERSION = 0x03
    MINOR_VERSION = 0x00

    def __init__(self):
        super(CurrentUserAtom, self).__init__(stream_name='Current User')
        self.rec_head = None
        self.size = None
        self.header_token = None
        self.offset_to_current_edit = None
        self.len_user_name = None
        self.doc_file_version = None
        self.major_version = None
        self.minor_version = None
        self.ansi_user_name = None
        self.unicode_user_name = None
        self.rel_version = None

    def is_encrypted(self):
        return self.header_token == self.HEADER_TOKEN_ENCRYPT

    @classmethod
    def extract_from(clz, stream):
        """ create instance with info from stream """

        obj = clz()

        # parse record header
        obj.rec_head = RecordHeader.extract_from(stream)

        obj.size, = struct.unpack('<L', stream.read(4))
        obj.header_token, = struct.unpack('<L', stream.read(4))
        obj.offset_to_current_edit, = struct.unpack('<L', stream.read(4))
        obj.len_user_name, = struct.unpack('<H', stream.read(2))
        obj.doc_file_version, = struct.unpack('<H', stream.read(2))
        obj.major_version, = struct.unpack('<B', stream.read(1))
        obj.minor_version, = struct.unpack('<B', stream.read(1))
        stream.read(2)    # unused
        obj.ansi_user_name = stream.read(obj.len_user_name)
        obj.rel_version, = struct.unpack('<L', stream.read(4))
        obj.unicode_user_name = stream.read(2 * obj.len_user_name)

        return obj

    def check_validity(self):
        errs = self.check_rec_head()
        errs.extend(self.check_value('size', self.size, self.SIZE))
        errs.extend(self.check_value('headerToken', self.header_token,
                                     [self.HEADER_TOKEN_ENCRYPT,
                                      self.HEADER_TOKEN_NOCRYPT]))
        errs.extend(self.check_range('lenUserName', self.len_user_name, None,
                                     256))
        errs.extend(self.check_value('docFileVersion', self.doc_file_version,
                                     self.DOC_FILE_VERSION))
        errs.extend(self.check_value('majorVersion', self.major_version,
                                     self.MAJOR_VERSION))
        errs.extend(self.check_value('minorVersion', self.minor_version,
                                     self.MINOR_VERSION))
        errs.extend(self.check_value('relVersion', self.rel_version,
                                     [self.REL_VERSION_CAN_USE,
                                      self.REL_VERSION_NO_USE]))
        return errs


class UserEditAtom(PptType):
    """ An atom record that specifies information about a user edit

    https://msdn.microsoft.com/en-us/library/dd945746%28v=office.12%29.aspx
    """

    RECORD_TYPE = 0x0FF5
    MINOR_VERSION = 0x00
    MAJOR_VERSION = 0x03

    def __init__(self):
        super(UserEditAtom, self).__init__()
        self.rec_head = None
        self.last_slide_id_ref = None
        self.version = None
        self.minor_version = None
        self.major_version = None
        self.offset_last_edit = None
        self.offset_persist_directory = None
        self.doc_persist_id_ref = None
        self.persist_id_seed = None
        self.last_view = None
        self.encrypt_session_persist_id_ref = None

    @classmethod
    def extract_from(clz, stream, is_encrypted):
        """ extract info from given stream (already positioned correctly!) """

        log.debug('extract UserEditAtom from stream')

        obj = clz()
        obj.start = stream.tell()

        # parse record header
        obj.rec_head = RecordHeader.extract_from(stream)

        obj.last_slide_id_ref, = struct.unpack('<L', stream.read(4))
        obj.version, = struct.unpack('<H', stream.read(2))
        obj.minor_version, = struct.unpack('<B', stream.read(1))
        obj.major_version, = struct.unpack('<B', stream.read(1))
        obj.offset_last_edit, = struct.unpack('<L', stream.read(4))
        obj.offset_persist_directory, = struct.unpack('<L', stream.read(4))
        obj.doc_persist_id_ref, = struct.unpack('<L', stream.read(4))
        obj.persist_id_seed, = struct.unpack('<L', stream.read(4))
        # (can only check once have the PersistDirectoryAtom)
        obj.last_view, = struct.unpack('<H', stream.read(2))
        stream.read(2)   # unused
        if is_encrypted:
            obj.encrypt_session_persist_id_ref, = \
                struct.unpack('<L', stream.read(4))
        else:   # this entry may be there or may not
            obj.encrypt_session_persist_id_ref = None

        return obj

    def check_validity(self, offset=None):
        errs = self.check_rec_head()
        errs.extend(self.check_value('minorVersion', self.minor_version,
                                     self.MINOR_VERSION))
        errs.extend(self.check_value('majorVersion', self.major_version,
                                     self.MAJOR_VERSION))
        if offset is not None:
            if self.offset_last_edit >= offset:
                errs.append(PptUnexpectedData(
                    'PowerPoint Document', 'UserEditAtom.offsetLastEdit',
                    self.offset_last_edit, '< {0}'.format(offset)))
            if self.offset_persist_directory >= offset or \
                    self.offset_persist_directory <= self.offset_last_edit or \
                    self.offset_persist_directory < 8:
                errs.append(PptUnexpectedData(
                    'PowerPoint Document',
                    'UserEditAtom.offsetPersistDirectory',
                    self.offset_last_edit,
                    'in ({0}, {1})'.format(self.offset_last_edit, offset)))
        errs.extend(self.check_value('docPersistIdRef',
                                     self.doc_persist_id_ref, 1))
        return errs

        # TODO: offer to check persist_id_seed given PersistDirectoryAtom)


class DummyType(PptType):
    """ a type that is found in ppt documents we are not interested in

    instead of parsing many uninteresting types, we just read their
    RecordHeader and set the RECORD_... values on an instance- (instead of
    class-) level

    used to skip over uninteresting types in e.g. DocumentContainer
    """

    def __init__(self, type_name, record_type, rec_ver=0, rec_instance=0,
                 rec_len=None):
        super(DummyType, self).__init__()
        self.type_name = type_name
        self.RECORD_TYPE = record_type
        self.RECORD_VERSION = rec_ver
        self.RECORD_INSTANCE = rec_instance
        self.record_length = rec_len

    def extract_from(self, stream):
        """ extract record header and just skip as many bytes as header says

        Since this requires RECORD_... values set in constructor, this is NOT
        a classmethod like all the other extract_from!

        Otherwise this tries to be compatible with other extract_from methods
        (e.g. returns self)
        """
        self.read_rec_head(stream)
        log.debug('skipping over {0} Byte for type {1}'
                  .format(self.rec_head.rec_len, self.type_name))
        log.debug('start at pos {0}'.format(stream.tell()))
        stream.seek(self.rec_head.rec_len, os.SEEK_CUR)
        log.debug('now at pos {0}'.format(stream.tell()))
        return self

    def check_validity(self):
        return self.check_rec_head(self.record_length)


class PptRawRecord(PptType):
    """ a record that is skipped but whose boundaries are still tracked

    Used for records a container does not interpret. Keeping start and end
    offsets makes it possible to verify that parsing never leaves the parent
    record and that unknown records are skipped, not scanned.
    """

    def __init__(self, rec_head, start, end, expected=None):
        super(PptRawRecord, self).__init__()
        self.rec_head = rec_head
        self.start = start
        self.end = end
        self.expected = expected

    def check_validity(self):
        errs = []
        if self.end - self.start != 8 + self.rec_head.rec_len:
            errs.append(PptUnexpectedData(
                self.stream_name, 'PptRawRecord.recLen',
                self.end - self.start - 8, self.rec_head.rec_len))
        if self.expected is not None:
            exp_type, exp_ver, exp_inst, exp_len = self.expected
            errs.extend(self.check_value('rh.recType', self.rec_head.rec_type,
                                         exp_type))
            errs.extend(self.check_value('rh.recVer', self.rec_head.rec_ver,
                                         exp_ver))
            errs.extend(self.check_value('rh.recInstance',
                                         self.rec_head.rec_instance,
                                         exp_inst))
            if exp_len is not None:
                errs.extend(self.check_value('rh.recLen',
                                             self.rec_head.rec_len, exp_len))
        return errs

    def _type_str(self):
        return 'PptRawRecord type 0x{0:04x}'.format(self.rec_head.rec_type)


def parse_bounded_children(stream, end_pos, known_types, fast_fail=True):
    """ parse child records strictly inside [current pos, end_pos)

    Every child must have a complete 8-byte header and must end at or before
    end_pos. Unknown types are returned as PptRawRecord and skipped using
    their declared length. There is no signature search: a child only exists
    if the parent's own record boundaries reach it.
    """
    children = []
    while stream.tell() < end_pos:
        start = stream.tell()
        if end_pos - start < 8:
            err = PptUnexpectedData(
                MAIN_STREAM_NAME, 'child record header',
                '{0} bytes left'.format(end_pos - start), '>= 8')
            if fast_fail:
                raise err
            log.warning(str(err))
            break
        rec_head = RecordHeader.extract_from(stream)
        child_end = stream.tell() + rec_head.rec_len
        if child_end > end_pos:
            err = PptUnexpectedData(
                MAIN_STREAM_NAME,
                'child record 0x{0:04x} end'.format(rec_head.rec_type),
                child_end, '<= {0}'.format(end_pos))
            if fast_fail:
                raise err
            log.warning(str(err))
            break
        clz = known_types.get(rec_head.rec_type)
        if clz is None:
            stream.seek(child_end, os.SEEK_SET)
            children.append(PptRawRecord(rec_head, start, child_end))
        else:
            stream.seek(start, os.SEEK_SET)
            child = clz.extract_from(stream)
            if stream.tell() != child_end:
                err = PptUnexpectedData(
                    MAIN_STREAM_NAME,
                    'child record 0x{0:04x} end'.format(rec_head.rec_type),
                    stream.tell(), child_end)
                if fast_fail:
                    raise err
                log.warning(str(err))
                stream.seek(child_end, os.SEEK_SET)
            children.append(child)
    if stream.tell() != end_pos:
        err = PptUnexpectedData(
            MAIN_STREAM_NAME, 'container end', stream.tell(), end_pos)
        if fast_fail:
            raise err
        log.warning(str(err))
    return children


class PersistDirectoryAtom(PptType):
    """ one part of a persist object directory with unique persist object id

    contains PersistDirectoryEntry objects

    https://msdn.microsoft.com/en-us/library/dd952680%28v=office.12%29.aspx
    """

    RECORD_TYPE = 0x1772

    def __init__(self):
        super(PersistDirectoryAtom, self).__init__()
        self.rg_persist_dir_entry = None    # actually, this will be an array
        self.stream_offset = None

    @classmethod
    def extract_from(clz, stream):
        """ create and return object with data from given stream """

        log.debug("Extracting a PersistDirectoryAtom from stream")
        obj = clz()

        # remember own offset for checking validity
        obj.stream_offset = stream.tell()
        obj.start = obj.stream_offset

        # parse record header
        obj.read_rec_head(stream)

        # read directory entries from list until reach size for this object
        curr_pos = stream.tell()
        stop_pos = curr_pos + obj.rec_head.rec_len
        log.debug('start reading at pos {0}, read until {1}'
                  .format(curr_pos, stop_pos))
        obj.rg_persist_dir_entry = []

        while curr_pos < stop_pos:
            if stop_pos - curr_pos < 4:
                raise ValueError(
                    'PersistDirectoryAtom entry header crosses record end '
                    '({0} bytes left)'.format(stop_pos - curr_pos))
            if stop_pos - curr_pos < 8:
                # a 4-byte entry header plus at least one 4-byte offset
                raise ValueError(
                    'PersistDirectoryAtom cannot hold another entry '
                    '({0} bytes left)'.format(stop_pos - curr_pos))
            new_entry = PersistDirectoryEntry.extract_from(
                stream, stop_pos)
            obj.rg_persist_dir_entry.append(new_entry)
            curr_pos = stream.tell()
            log.debug('at pos {0}'.format(curr_pos))
        if curr_pos != stop_pos:
            raise ValueError('PersistDirectoryAtom overran record end '
                             '({0} != {1})'.format(curr_pos, stop_pos))
        obj.end = curr_pos
        return obj

    def check_validity(self, user_edit_last_offset=None,
                       persist_dir_end=None):
        errs = self.check_rec_head()
        if persist_dir_end is None:
            persist_dir_end = self.stream_offset
        for entry in self.rg_persist_dir_entry:
            errs.extend(entry.check_validity(user_edit_last_offset,
                                             persist_dir_end))
        return errs


class PersistDirectoryEntry(object):
    """ an entry contained in a PersistDirectoryAtom.rg_persist_dir_entry

    A structure that specifies a compressed table of sequential persist object
    identifiers and stream offsets to associated persist objects.

    NOT a subclass of PptType because has no RecordHeader

    https://msdn.microsoft.com/en-us/library/dd947347%28v=office.12%29.aspx
    """

    def __init__(self):
        self.persist_id = None
        self.c_persist = None
        self.rg_persist_offset = None

    @classmethod
    def extract_from(clz, stream, end_pos=None):
        # take a 4-byte (=32bit) number, divide into 20bit and 12 bit)
        log.debug("Extracting a PersistDirectoryEntry from stream")
        obj = clz()
        obj.start = stream.tell()

        # persistId (20 bits): An unsigned integer that specifies a starting
        # persist object identifier. It MUST be less than or equal to 0xFFFFE.
        # The first entry in rgPersistOffset is associated with persistId. The
        # next entry, if present, is associated with persistId plus 1. Each
        # entry in rgPersistOffset is associated with a persist object
        # identifier in this manner, with the final entry associated with
        # persistId + cPersist - 1.

        # cPersist (12 bits): An unsigned integer that specifies the count of
        # items in rgPersistOffset. It MUST be greater than or equal to 0x001.
        raw = stream.read(4)
        if len(raw) != 4:
            raise ValueError('PersistDirectoryEntry header truncated')
        temp, = struct.unpack('<L', raw)
        obj.c_persist, obj.persist_id = divmod(temp, 2**20)
        log.debug('temp is 0x{0:04X} --> id is {1}, reading {2} offsets'
                  .format(temp, obj.persist_id, obj.c_persist))
        if obj.c_persist == 0:
            raise ValueError('PersistDirectoryEntry with cPersist == 0')
        if end_pos is not None and \
                stream.tell() + 4 * obj.c_persist > end_pos:
            raise ValueError(
                'PersistDirectoryEntry declares {0} offsets but only {1} '
                'bytes remain in PersistDirectoryAtom'
                .format(obj.c_persist, end_pos - stream.tell()))

        # rgPersistOffset (variable): An array of PersistOffsetEntry (section
        # 2.3.6) that specifies stream offsets to persist objects. The count of
        # items in the array is specified by cPersist. The value of each item
        # MUST be greater than or equal to offsetLastEdit in the corresponding
        # user edit and MUST be less than the offset, in bytes, of the
        # corresponding persist object directory.
        # PersistOffsetEntry: An unsigned 4-byte integer that specifies an
        # offset, in bytes, from the beginning of the PowerPoint Document
        # Stream (section 2.1.2) to a persist object.
        obj.rg_persist_offset = []
        obj.offset_positions = []
        for _ in range(obj.c_persist):
            pos = stream.tell()
            raw_offset = stream.read(4)
            if len(raw_offset) != 4:
                raise ValueError('PersistDirectoryEntry offset truncated')
            obj.rg_persist_offset.append(struct.unpack('<L', raw_offset)[0])
            obj.offset_positions.append(pos)
        log.debug('offsets are: {0}'.format(obj.rg_persist_offset))
        return obj

    def check_validity(self, user_edit_last_offset=None,
                       persist_obj_dir_offset=None):
        errs = []
        if self.persist_id > 0xFFFFE:  # (--> == 0xFFFFF since 20bit)
            errs.append(PptUnexpectedData(
                MAIN_STREAM_NAME, 'PersistDirectoryEntry.persist_id',
                self.persist_id, '< 0xFFFFE (dec: {0})'.format(0xFFFFE)))
        if self.c_persist == 0:
            errs.append(PptUnexpectedData(
                MAIN_STREAM_NAME, 'PersistDirectoryEntry.c_persist',
                self.c_persist, '> 0'))
        if user_edit_last_offset is not None \
                and min(self.rg_persist_offset) < user_edit_last_offset:
            errs.append(PptUnexpectedData(
                MAIN_STREAM_NAME, 'PersistDirectoryEntry.rg_persist_offset',
                min(self.rg_persist_offset),
                '> UserEdit.offsetLastEdit ({0})'
                .format(user_edit_last_offset)))
        if persist_obj_dir_offset is not None \
                and max(self.rg_persist_offset) >= persist_obj_dir_offset:
            errs.append(PptUnexpectedData(
                MAIN_STREAM_NAME, 'PersistDirectoryEntry.rg_persist_offset',
                max(self.rg_persist_offset),
                '< PersistObjectDirectory offset ({0})'
                .format(persist_obj_dir_offset)))
        return errs


class DocInfoListSubContainerOrAtom(PptType):
    """ one of various types found in a DocInfoListContainer

    https://msdn.microsoft.com/en-us/library/dd921705%28v=office.12%29.aspx

    actual type of this object is defined by the recVersion field in its Record
    Head

    Similar to DummyType, RECORD_TYPE varies from instance to instance for this
    type
    """

    # RECORD_TYPE varies, is specified only in extract_from
    VALID_RECORD_TYPES = [0x1388, # self.RECORD_TYPE_PROG_TAGS, \
                          0x0414, # self.RECORD_TYPE_NORMAL_VIEW_SET_INFO_9, \
                          0x0413, # self.RECORD_TYPE_NOTES_TEXT_VIEW_INFO_9, \
                          0x0407, # self.RECORD_TYPE_OUTLINE_VIEW_INFO, \
                          0x03FA, # self.RECORD_TYPE_SLIDE_VIEW_INFO, \
                          0x0408]  # self.RECORD_TYPE_SORTER_VIEW_INFO

    def __init__(self):
        super(DocInfoListSubContainerOrAtom, self).__init__()

    @classmethod
    def extract_from(clz, stream):
        """ build instance with info read from stream """

        log.debug('Parsing DocInfoListSubContainerOrAtom from stream')

        obj = clz()
        obj.read_rec_head(stream)
        if obj.rec_head.rec_type == VBAInfoContainer.RECORD_TYPE:
            obj = VBAInfoContainer.extract_from(stream, obj.rec_head)
        else:
            log.debug('skipping over {0} Byte in DocInfoListSubContainerOrAtom'
                      .format(obj.rec_head.rec_len))
            log.debug('start at pos {0}'.format(stream.tell()))
            stream.seek(obj.rec_head.rec_len, os.SEEK_CUR)
            log.debug('now at pos {0}'.format(stream.tell()))
        return obj

    def check_validity(self):
        """ can be any of multiple types """
        return self.check_value('rh.recType', self.rec_head.rec_type,
                                self.VALID_RECORD_TYPES)


class DocInfoListContainer(PptType):
    """ information about the document and document display settings

    https://msdn.microsoft.com/en-us/library/dd926767%28v=office.12%29.aspx
    """

    RECORD_VERSION = 0xF
    RECORD_TYPE = 0x07D0

    def __init__(self):
        super(DocInfoListContainer, self).__init__()
        self.rg_child_rec = None
        self.start = None
        self.end = None

    @classmethod
    def extract_from(clz, stream):
        """ build instance with info read from stream """

        log.debug('Parsing DocInfoListContainer from stream')
        obj = clz()
        obj.start = stream.tell()
        obj.read_rec_head(stream)

        # rgChildRec (variable): An array of DocInfoListSubContainerOrAtom
        # records (section 2.4.5) that specifies information about the document
        # or how the document is displayed. The size, in bytes, of the array is
        # specified by rh.recLen
        end_pos = stream.tell() + obj.rec_head.rec_len
        obj.end = end_pos
        obj.rg_child_rec = parse_bounded_children(
            stream, end_pos,
            {VBAInfoContainer.RECORD_TYPE: VBAInfoContainer})
        return obj

    def check_validity(self):
        errs = self.check_rec_head()
        if self.rg_child_rec is None:
            return errs
        for obj in self.rg_child_rec:
            errs.extend(obj.check_validity())
        return errs

    def iter_vba_info(self):
        """ yield VBAInfoContainer children, never searching outside bounds """
        for child in self.rg_child_rec or ():
            if isinstance(child, VBAInfoContainer):
                yield child


class DocumentContainer(PptType):
    """ a DocumentContainer record

    https://msdn.microsoft.com/en-us/library/dd947357%28v=office.12%29.aspx

    Children are parsed strictly inside rh.recLen. Unknown children are kept
    as PptRawRecord and skipped by their declared length; nothing is recovered
    by searching for a nearby signature.
    """

    RECORD_TYPE = 0x03E8
    RECORD_VERSION = 0xF

    # expected (type, ver, instance, len) for children parsed as raw bytes.
    # None length means "variable". These are assertions, not scan hints: a
    # mismatching header is reported and the bytes are still skipped by the
    # declared length.
    KNOWN_CHILD_SIGNATURES = {
        0x03E9: (0x03E9, 0x1, 0x0, 0x28),
        0x0409: (0x0409, 0xF, 0x0, None),
        0x03F2: (0x03F2, 0xF, 0x0, None),
        0x07E4: (0x07E4, 0xF, 0x5, None),
        0x040B: (0x040B, 0xF, 0x0, None),
        0x0FF0: (0x0FF0, 0xF, (0, 1), None),
        0x03EA: (0x03EA, 0x0, 0x0, 0x0),
    }

    # types with dedicated Python classes; everything else is skipped raw
    KNOWN_CHILDREN = {
        0x03E9: 'document_atom',
        0x0409: 'ex_obj_list',
        0x03F2: 'document_text_info',
        0x07E4: 'sound_collection',
        0x040B: 'drawing_group',
        0x0FF0: 'master_list',
        0x07D0: 'doc_info_list',
        0x03EA: 'end_document',
    }

    def __init__(self):
        super(DocumentContainer, self).__init__()
        self.start = None
        self.end = None
        self.children = None
        self.document_atom = None
        self.ex_obj_list = None
        self.document_text_info = None
        self.sound_collection = None
        self.drawing_group = None
        self.master_list = None
        self.doc_info_list = None
        self.slide_hf = None
        self.notes_hf = None
        self.slide_list = None
        self.notes_list = None
        self.slide_show_doc_info = None
        self.named_shows = None
        self.summary = None
        self.doc_routing_slip = None
        self.print_options = None
        self.rt_custom_table_styles_1 = None
        self.end_document = None
        self.rt_custom_table_styles_2 = None

    @classmethod
    def extract_from(clz, stream, fast_fail=True):
        """ create object with values from given stream

        stream is assumed to be positioned correctly.

        The container's declared rh.recLen is the only authority for its
        children. A child that does not fit is an error, not a new parse
        candidate.
        """
        log.debug('Parsing DocumentContainer from stream')
        obj = clz()
        obj.start = stream.tell()
        obj.read_rec_head(stream)
        end_pos = stream.tell() + obj.rec_head.rec_len
        obj.end = end_pos

        known = {0x07D0: DocInfoListContainer}
        children = []
        while stream.tell() < end_pos:
            child_start = stream.tell()
            if end_pos - child_start < 8:
                err = PptUnexpectedData(
                    MAIN_STREAM_NAME, 'DocumentContainer child header',
                    end_pos - child_start, '>= 8')
                if fast_fail:
                    raise err
                log.warning(str(err))
                break
            rec_head = RecordHeader.extract_from(stream)
            child_end = stream.tell() + rec_head.rec_len
            if child_end > end_pos:
                err = PptUnexpectedData(
                    MAIN_STREAM_NAME,
                    'DocumentContainer child 0x{0:04x} end'
                    .format(rec_head.rec_type),
                    child_end, '<= {0}'.format(end_pos))
                if fast_fail:
                    raise err
                log.warning(str(err))
                break

            child = None
            clz = known.get(rec_head.rec_type)
            if clz is not None:
                stream.seek(child_start, os.SEEK_SET)
                child = clz.extract_from(stream)
                if stream.tell() != child_end:
                    err = PptUnexpectedData(
                        MAIN_STREAM_NAME,
                        'DocumentContainer child 0x{0:04x} end'
                        .format(rec_head.rec_type),
                        stream.tell(), child_end)
                    if fast_fail:
                        raise err
                    log.warning(str(err))
                    stream.seek(child_end, os.SEEK_SET)
            else:
                stream.seek(child_end, os.SEEK_SET)
                expected = obj.KNOWN_CHILD_SIGNATURES.get(
                    rec_head.rec_type)
                child = PptRawRecord(rec_head, child_start, child_end,
                                     expected)

            children.append(child)
            attr = obj.KNOWN_CHILDREN.get(rec_head.rec_type)
            if attr is not None and getattr(obj, attr) is None:
                setattr(obj, attr, child)
        if stream.tell() != end_pos:
            err = PptUnexpectedData(
                MAIN_STREAM_NAME, 'DocumentContainer end',
                stream.tell(), end_pos)
            if fast_fail:
                raise err
            log.warning(str(err))

        obj.children = children
        return obj

    def check_validity(self):
        """ check all values in object for valid values """
        errs = self.check_rec_head()
        if self.children is None:
            return errs
        for child in self.children:
            errs.extend(child.check_validity())
        return errs


class VBAInfoContainer(PptType):
    """ A container record that specifies VBA information for the document.

    https://msdn.microsoft.com/en-us/library/dd952168%28v=office.12%29.aspx
    """

    RECORD_TYPE = 0x03FF
    RECORD_VERSION = 0xF
    RECORD_INSTANCE = 0x001
    RECORD_LENGTH = 0x14

    def __init__(self):
        super(VBAInfoContainer, self).__init__()
        self.vba_info_atom = None

    @classmethod
    def extract_from(clz, stream, rec_head=None):
        """ since can determine this type only after reading header, it is arg
        """
        log.debug('parsing VBAInfoContainer')
        obj = clz()
        obj.start = stream.tell()
        if rec_head is None:
            obj.read_rec_head(stream)
        else:
            log.debug('skip parsing of RecordHeader')
            obj.rec_head = rec_head
        obj.vba_info_atom = VBAInfoAtom.extract_from(stream)
        obj.end = stream.tell()
        return obj

    def check_validity(self):
        errs = self.check_rec_head(length=self.RECORD_LENGTH)
        errs.extend(self.vba_info_atom.check_validity())
        return errs


class VBAInfoAtom(PptType):
    """ An atom record that specifies a reference to the VBA project storage.

    https://msdn.microsoft.com/en-us/library/dd948874%28v=office.12%29.aspx
    """

    RECORD_TYPE = 0x0400
    RECORD_VERSION = 0x2
    RECORD_LENGTH = 0x0C

    def __init__(self):
        super(VBAInfoAtom, self).__init__()
        self.persist_id_ref = None
        self.f_has_macros = None
        self.version = None

    @classmethod
    def extract_from(clz, stream):
        log.debug('parsing VBAInfoAtom')
        obj = clz()
        obj.start = stream.tell()
        obj.read_rec_head(stream)

        # persistIdRef (4 bytes): A PersistIdRef (section 2.2.21) that
        # specifies the value to look up in the persist object directory to
        # find the offset of a VbaProjectStg record (section 2.10.40).
        obj.persist_id_ref = read_4(stream)

        # fHasMacros (4 bytes): An unsigned integer that specifies whether the
        # VBA project storage contains data. It MUST be 0 (empty vba storage)
        # or 1 (vba storage contains data)
        obj.f_has_macros = read_4(stream)

        # version (4 bytes): An unsigned integer that specifies the VBA runtime
        # version that generated the VBA project storage. It MUST be
        # 0x00000002.
        obj.version = read_4(stream)
        obj.end = stream.tell()

        return obj

    def check_validity(self):

        errs = self.check_rec_head(length=self.RECORD_LENGTH)

        # must be 0 or 1:
        errs.extend(self.check_range('fHasMacros', self.f_has_macros, None, 2))
        errs.extend(self.check_value('version', self.version, 2))
        return errs


class ExternalObjectStorage(PptType):
    """ storage for compressed/uncompressed OLE/VBA/ActiveX control data

    Matches types ExOleObjStgCompressedAtom, ExOleObjStgUncompressedAtom,
    VbaProjectStgCompressedAtom, VbaProjectStgUncompressedAtom,
    ExControlStgUncompressedAtom, ExControlStgCompressedAtom

    Difference between compressed and uncompressed: RecordHeader.rec_instance
    is 0 or 1, first variable after RecordHeader is decompressed_size

    Data is not read at first, only its offset in the stream and size is saved

    e.g.
    https://msdn.microsoft.com/en-us/library/dd952169%28v=office.12%29.aspx
    """

    RECORD_TYPE = 0x1011
    RECORD_INSTANCE_COMPRESSED = 1
    RECORD_INSTANCE_UNCOMPRESSED = 0

    def __init__(self, is_compressed=None):
        super(ExternalObjectStorage, self).__init__()
        if is_compressed is None:
            self.RECORD_INSTANCE = None   # otherwise defaults to 0
        elif is_compressed:
            self.RECORD_INSTANCE = self.RECORD_INSTANCE_COMPRESSED
            self.is_compressed = True
        else:
            self.RECORD_INSTANCE = self.RECORD_INSTANCE_UNCOMPRESSED
            self.is_compressed = False
        self.uncompressed_size = None
        self.data_offset = None
        self.data_size = None

    def extract_from(self, stream):
        """ not a classmethod because of is_compressed attrib

        see also: DummyType
        """
        log.debug('Parsing ExternalObjectStorage (compressed={0}) from stream'
                  .format(self.is_compressed))
        self.read_rec_head(stream)
        self.data_size = self.rec_head.rec_len
        if self.is_compressed:
            self.uncompressed_size = read_4(stream)
            self.data_size -= 4
        self.data_offset = stream.tell()

    def check_validity(self):
        errs = self.check_rec_head()
        if self.data_size is not None and self.data_size < 0:
            errs.append(PptUnexpectedData(
                MAIN_STREAM_NAME,
                '{0}.data_size'.format(self.__class__.__name__),
                self.data_size, '>= 0'))
        if self.is_compressed and self.uncompressed_size is not None:
            if self.uncompressed_size < 0:
                errs.append(PptUnexpectedData(
                    MAIN_STREAM_NAME,
                    '{0}.uncompressed_size'.format(self.__class__.__name__),
                    self.uncompressed_size, '>= 0'))
        return errs


class ExternalObjectStorageUncompressed(ExternalObjectStorage):
    """ subclass of ExternalObjectStorage for uncompressed objects """
    RECORD_INSTANCE = ExternalObjectStorage.RECORD_INSTANCE_UNCOMPRESSED

    def __init__(self):
        super(ExternalObjectStorageUncompressed, self).__init__(False)

    @classmethod
    def extract_from(clz, stream):
        """ note the usage of super here: call instance method of super class!
        """
        obj = clz()
        super(ExternalObjectStorageUncompressed, obj).extract_from(stream)
        return obj


class ExternalObjectStorageCompressed(ExternalObjectStorage):
    """ subclass of ExternalObjectStorage for compressed objects """
    RECORD_INSTANCE = ExternalObjectStorage.RECORD_INSTANCE_COMPRESSED

    def __init__(self):
        super(ExternalObjectStorageCompressed, self).__init__(True)

    @classmethod
    def extract_from(clz, stream):
        """ note the usage of super here: call instance method of super class!
        """
        obj = clz()
        super(ExternalObjectStorageCompressed, obj).extract_from(stream)
        return obj


# === PptParser ===============================================================

def with_opened_main_stream(func):
    """ a decorator that can open and close the default stream for func

    to be applied only to functions in PptParser that read from default stream
    (:py:data:`MAIN_STREAM_NAME`)

    Decorated functions need to accept args (self, stream, ...)
    """

    def wrapped(self, *args, **kwargs):
        # remember who opened the stream so that function also closes it
        stream_opened_by_me = False
        try:
            # open stream if required
            if self._open_main_stream is None:
                log.debug('opening stream {0!r} for {1}'
                          .format(MAIN_STREAM_NAME, func.__name__))
                self._open_main_stream = self.ole.openstream(MAIN_STREAM_NAME)
                stream_opened_by_me = True

            # run wrapped function
            return func(self, self._open_main_stream, *args, **kwargs)

        # error handling
        except Exception:
            if self.fast_fail:
                raise
            else:
                self._log_exception()
        finally:
            # ensure stream is closed by the one who opened it (even if error)
            if stream_opened_by_me:
                log.debug('closing stream {0!r} after {1}'
                          .format(MAIN_STREAM_NAME, func.__name__))
                self._open_main_stream.close()
                self._open_main_stream = None
    return wrapped


def generator_with_opened_main_stream(func):
    """ same as with_opened_main_stream but with yield instead of return """

    def wrapped(self, *args, **kwargs):
        # remember who opened the stream so that function also closes it
        stream_opened_by_me = False
        try:
            # open stream if required
            if self._open_main_stream is None:
                log.debug('opening stream {0!r} for {1}'
                          .format(MAIN_STREAM_NAME, func.__name__))
                self._open_main_stream = self.ole.openstream(MAIN_STREAM_NAME)
                stream_opened_by_me = True

            # run actual function
            for result in func(self, self._open_main_stream, *args, **kwargs):
                yield result

        # error handling
        except Exception:
            if self.fast_fail:
                raise
            else:
                self._log_exception()
        finally:
            # ensure stream is closed by the one who opened it (even if error)
            if stream_opened_by_me:
                log.debug('closing stream {0!r} after {1}'
                          .format(MAIN_STREAM_NAME, func.__name__))
                self._open_main_stream.close()
                self._open_main_stream = None
    return wrapped


class PptParser(object):
    """ Parser for PowerPoint 97-2003 specific data structures

    requires an OleFileIO
    """

    def __init__(self, ole, fast_fail=False):
        """ constructor

        :param ole: OleFileIO or anything that OleFileIO constructor accepts
        :param bool fast_fail: if True, all unexpected data will raise a
                               PptUnexpectedData; if False will only log error
        """
        if isinstance(ole, olefile.OleFileIO):
            log.debug('using open OleFileIO')
            self.ole = ole
        else:
            log.debug('Opening file {0}'.format(ole))
            self.ole = olefile.OleFileIO(ole)

        self.fast_fail = fast_fail

        self.current_user_atom = None
        self.newest_user_edit = None
        self.user_edits = []
        self.document_persist_obj = None
        self.persist_object_directory = None

        # basic compatibility check: root directory structure is
        # [['\x05DocumentSummaryInformation'],
        #  ['\x05SummaryInformation'],
        #  ['Current User'],
        #  ['PowerPoint Document']]
        root_streams = self.ole.listdir()
        #for stream in root_streams:
        #    log.debug('found root stream {0!r}'.format(stream))
        if any(len(stream) != 1 for stream in root_streams):
            self._fail('root', 'listdir', root_streams, 'len = 1')
        root_streams = [stream[0].lower() for stream in root_streams]
        if not 'current user' in root_streams:
            self._fail('root', 'listdir', root_streams, 'Current User')
        if not MAIN_STREAM_NAME.lower() in root_streams:
            self._fail('root', 'listdir', root_streams, MAIN_STREAM_NAME)

        self._open_main_stream = None

    def _log_exception(self, msg=None):
        """ log an exception instead of raising it

        call in one of 2 ways:
            try:
                if fail():
                    self._log_exception('this is the message')
            except:
                self._log_exception()   # only possible in except clause
        """
        if msg is not None:
            stack = traceback.extract_stack()[:-1]
        else:
            _, exc, trace = sys.exc_info()
            stack = traceback.extract_tb(trace)
            msg = str(exc)
        log.error(msg)

        for i_entry, entry in enumerate(traceback.format_list(stack)):
            for line in entry.splitlines():
                log.debug('trace {0}: {1}'.format(i_entry, line))

    def _fail(self, *args):
        """ depending on self.fast_fail raise PptUnexpectedData or just log err

        args as for PptUnexpectedData
        """
        if self.fast_fail:
            raise PptUnexpectedData(*args)
        else:
            self._log_exception(PptUnexpectedData(*args).msg)

    def parse_current_user(self):
        """ parse the CurrentUserAtom record from stream 'Current User'

        Structure described in
        https://msdn.microsoft.com/en-us/library/dd948895%28v=office.12%29.aspx
        """

        if self.current_user_atom is not None:
            log.warning('re-reading and overwriting '
                        'previously read current_user_atom')

        log.debug('parsing "Current User"')

        stream = None
        try:
            log.debug('opening stream "Current User"')
            stream = self.ole.openstream('Current User')
            self.current_user_atom = CurrentUserAtom.extract_from(stream)
        except Exception:
            if self.fast_fail:
                raise
            else:
                self._log_exception()
        finally:
            if stream is not None:
                log.debug('closing stream "Current User"')
                stream.close()

    @with_opened_main_stream
    def parse_persist_object_directory(self, stream, stream_size=None):
        """ Part 1: Construct the persist object directory

        Returns the ordered list of user edits, newest first. The merged
        per-id mapping is exposed as self.persist_object_directory.

        The edit chain is followed strictly through offsetLastEdit. Every
        edit must move backwards and end at offset 0; a dangling, forward or
        sideways pointer is an error and is never repaired by searching the
        stream for a UserEditAtom signature.
        """
        if self.persist_object_directory is not None:
            log.warning('re-reading and overwriting '
                        'previously read persist_object_directory')

        if stream_size is None:
            stream_size = self._main_stream_size(stream)

        # Step 1: Read the CurrentUserAtom record (section 2.3.2) from the
        # Current User Stream (section 2.1.1). All seek operations in the steps
        # that follow this step are in the PowerPoint Document Stream.
        if self.current_user_atom is None:
            self.parse_current_user()
        if self.current_user_atom is None:
            raise ValueError('cannot read Current User atom')

        offset = self.current_user_atom.offset_to_current_edit
        is_encrypted = self.current_user_atom.is_encrypted()

        edits = []
        seen_offsets = set()
        while offset != 0:
            self._check_stream_offset(offset, stream_size, 'UserEditAtom')
            if offset in seen_offsets:
                raise ValueError('cycle in UserEditAtom.offsetLastEdit chain '
                                 'at offset {0}'.format(offset))
            seen_offsets.add(offset)

            stream.seek(offset, os.SEEK_SET)
            user_edit = UserEditAtom.extract_from(stream, is_encrypted)
            user_edit.offset = offset
            user_edit.record_end = stream.tell()
            if user_edit.rec_head.rec_type != UserEditAtom.RECORD_TYPE:
                raise PptUnexpectedData(
                    MAIN_STREAM_NAME, 'UserEditAtom.recType',
                    user_edit.rec_head.rec_type, UserEditAtom.RECORD_TYPE)
            if user_edit.record_end > stream_size:
                raise ValueError('UserEditAtom at {0} leaves the stream'
                                 .format(offset))
            if user_edit.record_end != offset + 8 + \
                    user_edit.rec_head.rec_len:
                raise PptUnexpectedData(
                    MAIN_STREAM_NAME, 'UserEditAtom.recLen',
                    user_edit.rec_head.rec_len,
                    user_edit.record_end - offset - 8)
            if user_edit.rec_head.rec_len not in (0x1c, 0x20):
                raise PptUnexpectedData(
                    MAIN_STREAM_NAME, 'UserEditAtom.recLen',
                    user_edit.rec_head.rec_len, '0x1c or 0x20')
            if user_edit.doc_persist_id_ref != 1:
                # [MS-PPT] 2.3.3: docPersistIdRef MUST identify the
                # DocumentContainer. Rejecting here keeps a wrong mapping from
                # being mistaken for a legal document object.
                raise PptUnexpectedData(
                    MAIN_STREAM_NAME, 'UserEditAtom.docPersistIdRef',
                    user_edit.doc_persist_id_ref, 1)

            if user_edit.offset_last_edit >= offset:
                raise PptUnexpectedData(
                    MAIN_STREAM_NAME, 'UserEditAtom.offsetLastEdit',
                    user_edit.offset_last_edit,
                    '< {0}'.format(offset))
            if user_edit.offset_persist_directory >= offset or \
                    user_edit.offset_persist_directory <= \
                    user_edit.offset_last_edit:
                raise PptUnexpectedData(
                    MAIN_STREAM_NAME,
                    'UserEditAtom.offsetPersistDirectory',
                    user_edit.offset_persist_directory,
                    'in ({0}, {1})'.format(user_edit.offset_last_edit,
                                           offset))

            # Step 5: read this edit's persist directory, bounded by the
            # record's own position in the stream.
            self._check_stream_offset(user_edit.offset_persist_directory,
                                      stream_size, 'PersistDirectoryAtom')
            stream.seek(user_edit.offset_persist_directory, os.SEEK_SET)
            persist_dir_atom = PersistDirectoryAtom.extract_from(stream)
            persist_atom_end = stream.tell()
            if persist_atom_end > stream_size:
                raise ValueError('PersistDirectoryAtom at {0} leaves stream'
                                 .format(user_edit.offset_persist_directory))
            if persist_dir_atom.rec_head.rec_type != \
                    PersistDirectoryAtom.RECORD_TYPE:
                raise PptUnexpectedData(
                    MAIN_STREAM_NAME, 'PersistDirectoryAtom.recType',
                    persist_dir_atom.rec_head.rec_type,
                    PersistDirectoryAtom.RECORD_TYPE)

            # Offsets in this directory must lie between this edit's
            # offsetLastEdit and this edit's own start offset. Use
            # offsetLastEdit (not the current edit offset): the newest edit
            # normally has offsetLastEdit == 0 and points at the original
            # document objects.
            errs = persist_dir_atom.check_validity(
                user_edit.offset_last_edit, persist_dir_atom.stream_offset)
            if errs:
                if self.fast_fail:
                    raise errs[0]
                for err in errs:
                    log.warning('PersistDirectoryAtom.check_validity: {0}'
                                .format(err))

            user_edit.persist_directory = persist_dir_atom
            edits.append(user_edit)
            offset = user_edit.offset_last_edit

        # Spec order: add pairs starting with the directory closest to the
        # beginning of the stream; newer directories are added last and win.
        self.persist_object_directory = {}
        for user_edit in reversed(edits):
            for entry in user_edit.persist_directory.rg_persist_dir_entry:
                for count, persist_offset in enumerate(
                        entry.rg_persist_offset):
                    self.persist_object_directory[
                        entry.persist_id + count] = persist_offset

        self.user_edits = edits
        self.newest_user_edit = edits[0] if edits else None
        return edits

    @staticmethod
    def _check_stream_offset(offset, stream_size, what, allow_zero=False):
        lower = 0 if allow_zero else 8
        if offset < lower or offset + 8 > stream_size:
            raise PptUnexpectedData(
                MAIN_STREAM_NAME, '{0} offset'.format(what), offset,
                'in [{0}, {1})'.format(lower, stream_size - 8))

    def _main_stream_size(self, stream):
        pos = stream.tell()
        try:
            stream.seek(0, os.SEEK_END)
            return stream.tell()
        finally:
            stream.seek(pos, os.SEEK_SET)

    def resolve_persist_ref(self, persist_id, stream=None):
        """ resolve persist id via the live directory only

        Returns (offset, record_header). A missing id is an error: callers
        must not search the stream for a matching signature. The record at the
        returned offset must have a header that lies inside the stream.

        If stream is given, use it (caller already opened the main stream);
        otherwise open the main stream for the lookup.
        """
        if stream is not None:
            return self._resolve_persist_ref(stream, persist_id)
        return self._resolve_persist_ref_opened(persist_id)

    @with_opened_main_stream
    def _resolve_persist_ref_opened(self, stream, persist_id):
        return self._resolve_persist_ref(stream, persist_id)

    def _resolve_persist_ref(self, stream, persist_id):
        if self.persist_object_directory is None:
            self.parse_persist_object_directory()    # pylint: disable=no-value-for-parameter
        try:
            offset = self.persist_object_directory[persist_id]
        except KeyError:
            raise PptUnexpectedData(
                MAIN_STREAM_NAME, 'persist id', persist_id,
                'present in live persist directory')
        stream_size = self._main_stream_size(stream)
        self._check_stream_offset(offset, stream_size, 'persist object',
                                  allow_zero=True)
        stream.seek(offset, os.SEEK_SET)
        rec_head = RecordHeader.extract_from(stream)
        end = stream.tell() + rec_head.rec_len
        if end > stream_size:
            raise ValueError('persist object {0} at {1} leaves stream'
                             .format(persist_id, offset))
        # rewind so caller can parse the record body
        stream.seek(offset, os.SEEK_SET)
        return offset, rec_head

    def resolve_persist_record(self, persist_id, expected_type, stream=None):
        """ resolve persist id and require the record to have expected_type

        This is the only supported way to follow a PersistIdRef. It never
        scans for a signature; a wrong record type is reported, not repaired.
        """
        if stream is None:
            return self._resolve_persist_record_opened(persist_id,
                                                       expected_type)
        return self._resolve_persist_record(stream, persist_id,
                                            expected_type)

    @with_opened_main_stream
    def _resolve_persist_record_opened(self, stream, persist_id,
                                       expected_type):
        return self._resolve_persist_record(stream, persist_id,
                                            expected_type)

    def _resolve_persist_record(self, stream, persist_id, expected_type):
        offset, rec_head = self._resolve_persist_ref(stream, persist_id)
        if rec_head.rec_type != expected_type:
            raise PptUnexpectedData(
                MAIN_STREAM_NAME, 'persist object {0} type'.format(persist_id),
                rec_head.rec_type, expected_type)
        stream.seek(offset, os.SEEK_SET)
        return offset, rec_head

    def iter_vba_infos(self, stream=None):
        """ yield VBAInfoContainer records owned by the document object

        This is the structural counterpart to search_vba_info: only children
        inside the referenced DocumentContainer/DocInfoList are considered.
        """
        if stream is None:
            for info in self._iter_vba_infos_opened():
                yield info
            return
        for info in self._iter_vba_infos(stream):
            yield info

    @generator_with_opened_main_stream
    def _iter_vba_infos_opened(self, stream):
        for info in self._iter_vba_infos(stream):
            yield info

    def _iter_vba_infos(self, stream):
        if self.current_user_atom is None:
            self.parse_current_user()
        if self.current_user_atom is not None and \
                self.current_user_atom.is_encrypted():
            # The document stream is encrypted: its persist objects cannot be
            # interpreted as plain records, so there is nothing to yield.
            return
        if self.document_persist_obj is None:
            self.parse_document_persist_object()
        doc = self.document_persist_obj
        if doc is None or doc.doc_info_list is None:
            return
        for info in doc.doc_info_list.iter_vba_info():
            info.persist_id_ref = info.vba_info_atom.persist_id_ref
            info.owner_offset = getattr(info, 'start', doc.offset)
            info.document_offset = doc.offset
            yield info

    def iter_vba_storages(self, stream=None):
        """ resolve VBA storages through the persist directory, strictly

        Each VBAInfoAtom.persistIdRef must point, via the live directory, to
        an ExternalObjectStorage record. Missing ids and wrong record types
        raise instead of falling back to a byte-pattern search.
        """
        if stream is None:
            for storage in self._iter_vba_storages_opened():
                yield storage
            return
        for storage in self._iter_vba_storages(stream):
            yield storage

    @generator_with_opened_main_stream
    def _iter_vba_storages_opened(self, stream):
        for storage in self._iter_vba_storages(stream):
            yield storage

    def _iter_vba_storages(self, stream):
        seen = set()
        # parse the document graph first: _iter_vba_infos may open/close its
        # own main stream, which would invalidate the stream we were given.
        if self.document_persist_obj is None:
            self.parse_document_persist_object()
        for info in self._iter_vba_infos(stream):
            if info.vba_info_atom.f_has_macros == 0:
                # no VBA project storage is referenced (persistIdRef may be 0)
                continue
            persist_id = info.vba_info_atom.persist_id_ref
            if persist_id in seen:
                continue
            seen.add(persist_id)
            offset, rec_head = self._resolve_persist_record(
                stream, persist_id, ExternalObjectStorage.RECORD_TYPE)
            if rec_head.rec_instance == \
                    ExternalObjectStorage.RECORD_INSTANCE_COMPRESSED:
                clz = ExternalObjectStorageCompressed
            elif rec_head.rec_instance == \
                    ExternalObjectStorage.RECORD_INSTANCE_UNCOMPRESSED:
                clz = ExternalObjectStorageUncompressed
            else:
                raise PptUnexpectedData(
                    MAIN_STREAM_NAME,
                    'storage {0} recInstance'.format(persist_id),
                    rec_head.rec_instance, '0 or 1')
            stream.seek(offset, os.SEEK_SET)
            storage = clz.extract_from(stream)
            storage.offset = offset
            storage.persist_id_ref = persist_id
            storage.owner_offset = info.owner_offset
            errs = storage.check_validity()
            if errs:
                raise errs[0]
            if storage.is_compressed:
                if storage.uncompressed_size < 0:
                    raise ValueError('negative uncompressed size')
                if storage.data_size < 0:
                    raise ValueError('negative compressed size')
            yield storage

    @with_opened_main_stream
    def parse_document_persist_object(self, stream):
        """ Part 2: Identify the document persist object """
        if self.document_persist_obj is not None:
            log.warning('re-reading and overwriting '
                        'previously read document_persist_object')

        # Step 1:  Read the docPersistIdRef field of the UserEditAtom record
        # first identified in step 3 of Part 1, that is, the UserEditAtom
        # record closest to the end of the stream.
        if self.persist_object_directory is None:
            self.parse_persist_object_directory()    # pylint: disable=no-value-for-parameter

        # Step 2: Lookup the value of the docPersistIdRef field in the persist
        # object directory constructed in step 8 of Part 1 to find the stream
        # offset of a persist object.
        if self.newest_user_edit is None:
            raise ValueError('no user edit; cannot resolve document object')
        newest_ref = self.newest_user_edit.doc_persist_id_ref
        offset, rec_head = self.resolve_persist_ref(newest_ref, stream)
        log.debug('newest user edit ID is {0}, offset is {1}'
                  .format(newest_ref, offset))

        # Step 3:  Seek to the stream offset specified in step 2.
        log.debug('seek to {0}'.format(offset))
        stream.seek(offset, os.SEEK_SET)

        # Step 4: Read the DocumentContainer record at the current offset.
        # Let this record be a live record. The referenced record must really
        # be a DocumentContainer; a valid record of another type is not an
        # acceptable target.
        if rec_head.rec_type != DocumentContainer.RECORD_TYPE:
            raise PptUnexpectedData(
                MAIN_STREAM_NAME, 'document persist object type',
                rec_head.rec_type, DocumentContainer.RECORD_TYPE)
        self.document_persist_obj = DocumentContainer.extract_from(
            stream, fast_fail=self.fast_fail)
        self.document_persist_obj.offset = offset
        self.document_persist_obj.record_end = stream.tell()

        log.debug('checking validity')
        errs = self.document_persist_obj.check_validity()
        if errs:
            log.warning('check_validity found {0} issues'.format(len(errs)))
        for err in errs:
            log.warning('check_validity(document_persist_obj): {0}'
                        .format(err))
        if errs and self.fast_fail:
            raise errs[0]

    #--------------------------------------------------------------------------
    # 2nd attempt: do not parse whole structure but search through stream and
    # yield results as they become available
    # Keep in mind that after every yield the stream position may be anything!

    @generator_with_opened_main_stream
    def search_pattern(self, stream, pattern):
        """ search for pattern in stream, return indices """

        BUF_SIZE = 1024

        pattern_len = len(pattern)
        log.debug('pattern length is {0}'.format(pattern_len))
        if pattern_len > BUF_SIZE:
            raise ValueError('need buf > pattern to search!')

        n_reads = 0
        while True:
            start_pos = stream.tell()
            n_reads += 1
            #log.debug('read {0} starting from {1}'
            #          .format(BUF_SIZE, start_pos))
            buf = stream.read(BUF_SIZE)
            idx = buf.find(pattern)
            while idx != -1:
                log.debug('found pattern at index {0}'.format(start_pos+idx))
                yield start_pos + idx
                idx = buf.find(pattern, idx+1)

            if len(buf) == BUF_SIZE:
                # move back a bit to avoid splitting of pattern through buf
                stream.seek(start_pos + BUF_SIZE - pattern_len, os.SEEK_SET)
            else:
                log.debug('reached end of buf (read {0}<{1}) after {2} reads'
                          .format(len(buf), BUF_SIZE, n_reads))
                break

    @generator_with_opened_main_stream
    def search_vba_info(self, stream):
        """ search through stream for VBAInfoContainer, alternative to parse...

        quick-and-dirty: do not parse everything, just look for right bytes

        "quick" here means quick to program. Runtime now is linear is document
        size (--> for big documents the other method might be faster)

        .. seealso:: search_vba_storage
        """

        log.debug('looking for VBA info containers')

        pattern = VBAInfoContainer.generate_pattern(
                                rec_len=VBAInfoContainer.RECORD_LENGTH) \
                + VBAInfoAtom.generate_pattern(
                                rec_len=VBAInfoAtom.RECORD_LENGTH)

        # try parse
        for idx in self.search_pattern(pattern):    # pylint: disable=no-value-for-parameter
            # assume that in stream at idx there is a VBAInfoContainer
            stream.seek(idx)
            log.debug('extracting at idx {0}'.format(idx))
            try:
                container = VBAInfoContainer.extract_from(stream)
            except Exception:
                self._log_exception()
                continue

            errs = container.check_validity()
            if errs:
                log.warning('check_validity found {0} issues'
                            .format(len(errs)))
            else:
                log.debug('container is ok')
                atom = container.vba_info_atom
                log.debug('persist id ref is {0}, has_macros {1}, version {2}'
                          .format(atom.persist_id_ref, atom.f_has_macros,
                                  atom.version))
                yield container
            for err in errs:
                log.warning('check_validity(VBAInfoContainer): {0}'
                            .format(err))
            if errs and self.fast_fail:
                raise errs[0]

    @generator_with_opened_main_stream
    def search_vba_storage(self, stream):
        """ search through stream for VBAProjectStg, alternative to parse...

        quick-and-dirty: do not parse everything, just look for right bytes

        "quick" here means quick to program. Runtime now is linear is document
        size (--> for big documents the other method might be faster)

        The storages found could also contain (instead of VBA data): ActiveX
        data or general OLE data

        yields results as it finds them

        .. seealso:: :py:meth:`search_vba_info`
        """

        log.debug('looking for VBA storage objects')
        for obj_type in (ExternalObjectStorageUncompressed,
                         ExternalObjectStorageCompressed):
            # re-position stream at start
            stream.seek(0, os.SEEK_SET)

            pattern = obj_type.generate_pattern()

            # try parse
            for idx in self.search_pattern(pattern):    # pylint: disable=no-value-for-parameter
                # assume a ExternalObjectStorage in stream at idx
                stream.seek(idx)
                log.debug('extracting at idx {0}'.format(idx))
                try:
                    storage = obj_type.extract_from(stream)
                except Exception:
                    self._log_exception()
                    continue

                errs = storage.check_validity()
                if errs:
                    log.warning('check_validity found {0} issues'
                                .format(len(errs)))
                else:
                    log.debug('storage is ok; compressed={0}, size={1}, '
                              'size_decomp={2}'
                              .format(storage.is_compressed,
                                      storage.rec_head.rec_len,
                                      storage.uncompressed_size))
                    yield storage
                for err in errs:
                    log.warning('check_validity({0}): {1}'
                                .format(obj_type.__name__, err))
                if errs and self.fast_fail:
                    raise errs[0]

    @with_opened_main_stream
    def decompress_vba_storage(self, stream, storage):
        """ return decompressed data from search_vba_storage """

        log.debug('decompressing storage for VBA OLE data stream ')

        # decompress iteratively; a zlib.decompress of all data
        # failed with Error -5 (incomplete or truncated stream)
        stream.seek(storage.data_offset, os.SEEK_SET)
        decomp, n_read, err = \
            iterative_decompress(stream, storage.data_size)
        log.debug('decompressed {0} to {1} bytes; found err: {2}'
                  .format(n_read, len(decomp), err))
        if err is not None:
            raise err
        # A wrong uncompressedSize declaration is an error: returning partial
        # or padded data would silently attribute bytes to the wrong object.
        if len(decomp) != storage.uncompressed_size:
            raise ValueError(
                'decompressed storage has size {0} != declared {1}'.format(
                    len(decomp), storage.uncompressed_size))
        return decomp

        ## create OleFileIO from decompressed data
        #ole = olefile.OleFileIO(decomp)
        #root_streams = [entry[0].lower() for entry in ole.listdir()]
        #for required in 'project', 'projectwm', 'vba':
        #    if required not in root_streams:
        #        raise ValueError('storage seems to not be a VBA storage '
        #                         '({0} not found in root streams)'
        #                         .format(required))
        #log.debug('tests succeeded')
        #return ole

    @with_opened_main_stream
    def read_vba_storage_data(self, stream, storage):
        """ return data pointed to by uncompressed storage """

        log.debug('reading uncompressed VBA OLE data stream: '
                  '{0} bytes starting at {1}'
                  .format(storage.data_size, storage.data_offset))
        stream.seek(storage.data_offset, os.SEEK_SET)
        data = stream.read(storage.data_size)
        if len(data) != storage.data_size:
            raise ValueError('uncompressed storage truncated: {0} != {1}'
                             .format(len(data), storage.data_size))
        return data

    @generator_with_opened_main_stream
    def iter_vba_data(self, stream):
        """ yield VBA storage data reached through the persist graph

        Unlike search_vba_info/search_vba_storage, this does not scan the
        stream for record signatures. A VBAInfoAtom whose persistIdRef is
        missing or points at the wrong record type raises; it is never
        repaired by a nearby signature.
        """
        infos = list(self._iter_vba_infos(stream))
        n_infos = len(infos)
        n_macros = sum(1 for info in infos
                       if info.vba_info_atom.f_has_macros > 0)

        n_storages = 0
        n_compressed = 0
        for storage in self._iter_vba_storages(stream):
            n_storages += 1
            if storage.is_compressed:
                n_compressed += 1
                yield self.decompress_vba_storage(storage)    # pylint: disable=no-value-for-parameter
            else:
                yield self.read_vba_storage_data(storage)    # pylint: disable=no-value-for-parameter

        log.info('found {0} infos ({1} with macros) and {2} storages '
                 '({3} compressed)'
                 .format(n_infos, n_macros, n_storages, n_compressed))


def iterative_decompress(stream, size, chunk_size=4096):
    """ decompress data from stream chunk-wise """

    decompressor = zlib.decompressobj()
    n_read = 0
    decomp = b''
    return_err = None

    try:
        while n_read < size:
            n_new = min(size-n_read, chunk_size)
            decomp += decompressor.decompress(stream.read(n_new))
            n_read += n_new
    except zlib.error as err:
        return_err = err

    return decomp, n_read, return_err


if __name__ == '__main__':
    print('nothing here to run!')
