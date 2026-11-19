""" Parse xls up to some point

Read storages, (sub-)streams, records from xls file
"""
#
# === LICENSE ==================================================================

# xls_parser is copyright (c) 2014-2019 Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#------------------------------------------------------------------------------
# CHANGELOG:
# 2017-11-02 v0.1 CH: - first version
# 2017-11-02 v0.2 CH: - move some code to record_base.py
#                        (to avoid copy-and-paste in ppt_parser.py)
# 2019-01-30 v0.54 PL: - fixed import to avoid mixing installed oletools
#                        and dev version

__version__ = '0.54'

# -----------------------------------------------------------------------------
#  TODO:
#  - parse more record types (ExternName, ...)
#  - check what bad stuff can be in other storages: Embedded ("MBD..."), Linked
#    ("LNK..."), "MsoDataStore" and OleStream ('\001Ole')
#
# -----------------------------------------------------------------------------
#  REFERENCES:
#  - [MS-XLS]: Excel Binary File Format (.xls) Structure Specification
#    https://msdn.microsoft.com/en-us/library/office/cc313154(v=office.14).aspx
#  - Understanding the Excel .xls Binary File Format
#    https://msdn.microsoft.com/en-us/library/office/gg615597(v=office.14).aspx
#
# -- IMPORTS ------------------------------------------------------------------

import sys
import os.path
from struct import unpack
import logging

# little hack to allow absolute imports even if oletools is not installed.
# Copied from olevba.py
PARENT_DIR = os.path.normpath(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)
del PARENT_DIR
from oletools import record_base


# === PYTHON 2+3 SUPPORT ======================================================

if sys.version_info[0] >= 3:
    unichr = chr

###############################################################################
# Helpers
###############################################################################


def is_xls(filename):
    """
    determine whether a given file is an excel ole file

    returns True if given file is an ole file and contains a Workbook stream

    todo: could further check that workbook stream starts with a globals
    substream.
    See also: oleid.OleID.check_excel
    """
    xls_file = None
    try:
        xls_file = XlsFile(filename)
        for stream in xls_file.iter_streams():
            if isinstance(stream, WorkbookStream):
                return True
    except Exception:
        logging.debug('Ignoring exception in is_xls, assume is not xls',
                      exc_info=True)
    finally:
        if xls_file is not None:
            xls_file.close()
    return False


def read_unicode(data, start_idx, n_chars):
    """ read a unicode string from a XLUnicodeStringNoCch structure """
    # first bit 0x0 --> only low-bytes are saved, all high bytes are 0
    # first bit 0x1 --> 2 bytes per character
    low_bytes_only = (ord(data[start_idx:start_idx+1]) == 0)
    if low_bytes_only:
        end_idx = start_idx + 1 + n_chars
        return data[start_idx+1:end_idx].decode('ascii'), end_idx
    else:
        return read_unicode_2byte(data, start_idx+1, n_chars)


def read_unicode_2byte(data, start_idx, n_chars):
    """ read a unicode string with characters encoded by 2 bytes """
    end_idx = start_idx + n_chars * 2
    if n_chars < 256:  # faster version, long format string for unpack
        unichars = (unichr(val) for val in
                    unpack('<' + 'H'*n_chars, data[start_idx:end_idx]))
    else:              # slower version but less memory-extensive
        unichars = (unichr(unpack('<H', data[data_idx:data_idx+2])[0])
                    for data_idx in range(start_idx, end_idx, 2))
    return u''.join(unichars), end_idx


###############################################################################
# File, Storage, Stream
###############################################################################

class XlsFile(record_base.OleRecordFile):
    """ An xls file has most streams made up of records """

    @classmethod
    def stream_class_for_name(cls, stream_name):
        """ helper for iter_streams """
        if stream_name == 'Workbook':
            return WorkbookStream
        return XlsStream


class XlsStream(record_base.OleRecordStream):
    """ most streams in xls file consist of records """

    def read_record_head(self):
        """ read first few bytes of record to determine size and type

        returns (type, size, other) where other is None
        """
        rec_type, rec_size = unpack('<HH', self.stream.read(4))
        return rec_type, rec_size, None

    @classmethod
    def record_class_for_type(cls, rec_type):
        """ determine a class for given record type

        returns (clz, force_read)
        """
        return XlsRecord, False


class WorkbookStream(XlsStream):
    """ Stream in excel file that holds most info """

    @classmethod
    def record_class_for_type(cls, rec_type):
        """ determine a class for given record type

        returns (clz, force_read)
        """
        if rec_type == XlsRecordBof.TYPE:
            return XlsRecordBof, True
        elif rec_type == XlsRecordEof.TYPE:
            return XlsRecordEof, False
        elif rec_type == XlsRecordSupBook.TYPE:
            return XlsRecordSupBook, True
        elif rec_type == XlsRecordBoundSheet.TYPE:
            return XlsRecordBoundSheet, True
        elif rec_type == XlsRecordExternSheet.TYPE:
            return XlsRecordExternSheet, True
        elif rec_type == XlsRecordExternName.TYPE:
            return XlsRecordExternName, True
        elif rec_type in XlsRecordFormula.FORMULA_TYPES:
            return XlsRecordFormula, True
        elif rec_type == XlsRecordShrFmla.TYPE:
            return XlsRecordShrFmla, True
        elif rec_type == XlsRecordArray.TYPE:
            return XlsRecordArray, True
        elif rec_type == XlsRecordName.TYPE:
            return XlsRecordName, True
        else:
            return XlsRecord, False


class XlsbStream(record_base.OleRecordStream):
    """ binary stream of an xlsb file, usually have a record structure """

    HIGH_BIT_MASK = 0b10000000
    LOW7_BIT_MASK = 0b01111111

    def read_record_head(self):
        """ read first few bytes of record to determine size and type

        returns (type, size, other) where other is None
        """
        val = ord(self.stream.read(1))
        if val & self.HIGH_BIT_MASK:    # high bit of the low byte is 1
            val2 = ord(self.stream.read(1))         # need another byte
            # combine 7 low bits of each byte
            rec_type = (val & self.LOW7_BIT_MASK) + \
                       ((val2 & self.LOW7_BIT_MASK) << 7)
        else:
            rec_type = val

        rec_size = 0
        shift = 0
        for _ in range(4):      # rec_size needs up to 4 byte
            val = ord(self.stream.read(1))
            rec_size += (val & self.LOW7_BIT_MASK) << shift
            shift += 7
            if (val & self.HIGH_BIT_MASK) == 0:   # high-bit is 0 --> done
                break
        return rec_type, rec_size, None

    @classmethod
    def record_class_for_type(cls, rec_type):
        """ determine a class for given record type

        returns (clz, force_read)
        """
        if rec_type == XlsbBeginSupBook.TYPE:
            return XlsbBeginSupBook, True
        elif rec_type == XlsbBundleSh.TYPE:
            return XlsbBundleSh, True
        elif rec_type == XlsbSupBookSrc.TYPE:
            return XlsbSupBookSrc, True
        elif rec_type == XlsbExternSheet.TYPE:
            return XlsbExternSheet, True
        elif rec_type == XlsbName.TYPE:
            return XlsbName, True
        elif rec_type in XlsbFormula.FORMULA_TYPES:
            return XlsbFormula, True
        elif rec_type == XlsbShrFmla.TYPE:
            return XlsbShrFmla, True
        elif rec_type == XlsbArrFmla.TYPE:
            return XlsbArrFmla, True
        elif rec_type == XlsbRowHdr.TYPE:
            return XlsbRowHdr, True
        else:
            return XlsbRecord, False


###############################################################################
# RECORDS
###############################################################################

# records that appear often but do not need their own XlsRecord subclass (yet)
FREQUENT_RECORDS = dict([
    ( 156, 'BuiltInFnGroupCount'),
    (2147, 'BookExt'),
    ( 442, 'CodeName'),
    (  66, 'CodePage'),
    (4195, 'Dat'),
    (2154, 'DataLabExt'),
    (2155, 'DataLabExtContents'),
    ( 215, 'DBCell'),
    ( 220, 'DbOrParmQry'),
    (2051, 'DBQueryExt'),
    (2166, 'DConn'),
    (  35, 'ExternName'),
    (  23, 'ExternSheet'),
    ( 255, 'ExtSST'),
    (2052, 'ExtString'),
    (2151, 'FeatHdr'),
    (  91, 'FileSharing'),
    (1054, 'Format'),
    (  49, 'Font'),
    (2199, 'GUIDTypeLib'),
    ( 440, 'HLink'),
    ( 225, 'InterfaceHdr'),
    ( 226, 'InterfaceEnd'),
    ( 523, 'Index'),
    (  24, 'Lbl'),
    ( 193, 'Mms'),
    (  93, 'Obj'),
    (4135, 'ObjectLink'),
    (2058, 'OleDbConn'),
    ( 222, 'OleObjectSize'),
    (2214, 'RichTextStream'),
    (2146, 'SheetExt'),
    (1212, 'ShrFmla'),
    (2060, 'SxViewExt'),
    (2136, 'SxViewLink'),
    (2049, 'WebPub'),
    ( 224, 'XF (formatting)'),
    (2173, 'XFExt (formatting)'),
    ( 659, 'Style'),
    (2194, 'StyleExt')
])

#: records found in xlsb binary parts
FREQUENT_RECORDS_XLSB = dict([
    (588, 'BrtEndSupBook'),
    (667, 'BrtSupAddin'),
    (355, 'BrtSupBookSrc'),
    (586, 'BrtSupNameBits'),
    (584, 'BrtSupNameBool'),
    (587, 'BrtSupNameEnd'),
    (581, 'BrtSupNameErr'),
    (585, 'BrtSupNameFmla'),
    (583, 'BrtSupNameNil'),
    (580, 'BrtSupNameNum'),
    (582, 'BrtSupNameSt'),
    (577, 'BrtSupNameStart'),
    (579, 'BrtSupNameValueEnd'),
    (578, 'BrtSupNameValueStart'),
    (358, 'BrtSupSame'),
    (357, 'BrtSupSelf'),
    (359, 'BrtSupTabs'),
])


class XlsRecord(record_base.OleRecordBase):
    """ basic building block of data in workbook stream """

    #: max size of a record in xls stream (does not apply to xlsb)
    MAX_SIZE = 8224

    def _type_str(self):
        """ simplification for subclasses to create their own __str__ """
        try:
            return FREQUENT_RECORDS[self.type]
        except KeyError:
            return 'XlsRecord type {0}'.format(self.type)


class XlsRecordBof(XlsRecord):
    """ record found at beginning of substreams """
    TYPE = 2057
    SIZE = 16
    # types of substreams
    DOCTYPES = dict([(0x5, 'workbook'), (0x10, 'dialog/worksheet'),
                     (0x20, 'chart'), (0x40, 'macro')])

    def finish_constructing(self, _):
        if self.data is None:
            self.doctype = None
            return
        # parse data (only doctype, ignore rest)
        self.doctype = unpack('<H', self.data[2:4])[0]

    def _type_str(self):
        return 'BOF Record ({0} substream)'.format(
            self.DOCTYPES[self.doctype] if self.doctype in self.DOCTYPES
            else 'unknown')


class XlsRecordEof(XlsRecord):
    """ record found at end of substreams """
    TYPE = 10
    SIZE = 0

    def _type_str(self):
        return 'EOF Record'


class XlsRecordSupBook(XlsRecord):
    """ The SupBook record specifies a supporting link

    "... The collection of records specifies the contents of an external
    workbook, DDE data source, or OLE data source." (MS-XLS, paragraph 2.4.271)
    """

    TYPE = 430

    LINK_TYPE_UNKNOWN = 'unknown'
    LINK_TYPE_SELF = 'self-referencing'
    LINK_TYPE_ADDIN = 'addin-referencing'
    LINK_TYPE_UNUSED = 'unused'
    LINK_TYPE_SAMESHEET = 'same-sheet'
    LINK_TYPE_OLE_DDE = 'ole/dde data source'
    LINK_TYPE_EXTERNAL = 'external workbook'

    def finish_constructing(self, _):
        """Finish constructing this record; called at end of constructor."""
        # set defaults
        self.ctab = None
        self.cch = None
        self.virt_path = None
        self.support_link_type = self.LINK_TYPE_UNKNOWN
        if self.data is None:
            return

        # parse data
        if self.size < 4:
            raise ValueError('not enough data (size is {0} but need >= 4)'
                             .format(self.size))
        self.ctab, self.cch = unpack('<HH', self.data[:4])
        if 0 < self.cch <= 0xff:
            # this is the length of virt_path
            self.virt_path, _ = read_unicode(self.data, 4, self.cch)
        else:
            self.virt_path, _ = u'', 4
        # ignore variable rgst

        if self.cch == 0x401:    # ctab is undefined and to be ignored
            self.support_link_type = self.LINK_TYPE_SELF
        elif self.ctab == 0x1 and self.cch == 0x3A01:
            self.support_link_type = self.LINK_TYPE_ADDIN
            # next records must be ExternName with all add-in functions
        elif self.virt_path == u'\u0020':   # space ; ctab can be anything
            self.support_link_type = self.LINK_TYPE_UNUSED
        elif self.virt_path == u'\u0000':
            self.support_link_type = self.LINK_TYPE_SAMESHEET
        elif self.ctab == 0x0 and self.virt_path:
            self.support_link_type = self.LINK_TYPE_OLE_DDE
        elif self.ctab > 0 and self.virt_path:
            self.support_link_type = self.LINK_TYPE_EXTERNAL

    def _type_str(self):
        return 'SupBook Record ({0})'.format(self.support_link_type)


class XlsRecordBoundSheet(XlsRecord):
    """ BOUNDSHEET record: offset of a sheet substream and its name """

    TYPE = 133

    def finish_constructing(self, _):
        self.offset = None
        self.visibility = None
        self.sheet_type = None
        self.name = u''
        if self.data is None or len(self.data) < 8:
            return
        self.offset, self.visibility, self.sheet_type, cch, flags = \
            unpack('<iBBBB', self.data[:8])
        pos = 8
        if cch == 0:
            return
        if flags & 0x01:
            if pos + 2 * cch > len(self.data):
                return
            self.name, _ = read_unicode_2byte(self.data, pos, cch)
        else:
            self.name = self.data[pos:pos + cch].decode('latin-1')


class XlsRecordExternSheet(XlsRecord):
    """ EXTERNSHEET record: ordered XTI entries used by 3-D references """

    TYPE = 23

    def finish_constructing(self, _):
        self.entries = []
        self.truncated = False
        if self.data is None or len(self.data) < 2:
            self.truncated = True
            return
        count = unpack('<H', self.data[0:2])[0]
        pos = 2
        for _ in range(count):
            if pos + 6 > len(self.data):
                self.truncated = True
                break
            supbook, first, last = unpack('<HHH', self.data[pos:pos + 6])
            self.entries.append((supbook, first, last))
            pos += 6


class XlsRecordExternName(XlsRecord):
    """ EXTERNNAME record: a name within the preceding SUPBOOK """

    TYPE = 35

    def finish_constructing(self, _):
        self.name = u''
        self.builtin = False
        self.truncated = False
        if self.data is None or len(self.data) < 7:
            self.truncated = True
            return
        self.options = unpack('<H', self.data[0:2])[0]
        # BIFF8: 2 bytes options + 4 bytes unused + XLUnicodeString (1-byte cch)
        cch = self.data[6]
        if cch == 0:
            return
        if 7 + cch > len(self.data):
            self.truncated = True
            return
        flags = self.data[7]
        pos = 8
        if flags & 0x01:
            if pos + 2 * cch > len(self.data):
                self.truncated = True
                return
            self.name, _ = read_unicode_2byte(self.data, pos, cch)
        else:
            self.name = self.data[pos:pos + cch].decode('latin-1')


class XlsRecordFormula(XlsRecord):
    """ FORMULA record (BIFF8), keeps the token stream for reference analysis """

    FORMULA_TYPES = (0x0006, 0x0206, 0x0406)
    TYPE = None

    def finish_constructing(self, _):
        self.row = None
        self.col = None
        self.cce = None
        self.rgce = b''
        self.truncated = False
        if self.data is None or len(self.data) < 22:
            self.truncated = True
            return
        self.row, self.col, self.xf = unpack('<HHH', self.data[0:6])
        self.flags = unpack('<H', self.data[14:16])[0]
        self.cce = unpack('<H', self.data[20:22])[0]
        end = 22 + self.cce
        if end > len(self.data):
            self.truncated = True
            self.rgce = self.data[22:]
        else:
            self.rgce = self.data[22:end]


class XlsRecordArray(XlsRecord):
    """ ARRAY record: formula for a range of cells """

    TYPE = 0x0221

    def finish_constructing(self, _):
        self.range = None
        self.cce = None
        self.rgce = b''
        self.truncated = False
        if self.data is None or len(self.data) < 14:
            self.truncated = True
            return
        # row1, row2, col1, col2, flags then 5 reserved bytes
        self.range = (unpack('<H', self.data[0:2])[0],
                      unpack('<H', self.data[2:4])[0],
                      self.data[4], self.data[5])
        self.cce = unpack('<H', self.data[12:14])[0]
        self.rgce = self.data[14:14 + self.cce]
        if len(self.rgce) != self.cce:
            self.truncated = True


class XlsRecordShrFmla(XlsRecord):
    """ SHRFMLA record: formula shared by a cell range """

    TYPE = 0x04BC

    def finish_constructing(self, _):
        self.range = None
        self.cce = None
        self.rgce = b''
        self.truncated = False
        if self.data is None or len(self.data) < 12:
            self.truncated = True
            return
        # row1, row2, col1, col2, nfmlas then tokslen
        self.range = (unpack('<H', self.data[0:2])[0],
                      unpack('<H', self.data[2:4])[0],
                      self.data[4], self.data[5])
        self.nfmlas = self.data[6]
        self.cce = unpack('<H', self.data[10:12])[0]
        self.rgce = self.data[12:12 + self.cce]
        if len(self.rgce) != self.cce:
            self.truncated = True


class XlsRecordName(XlsRecord):
    """ NAME record, including a defined name's token stream """

    TYPE = 24      # 0x0018

    def finish_constructing(self, _):
        self.name = u''
        self.scope = None
        self.cce = None
        self.rgce = b''
        self.truncated = False
        if self.data is None or len(self.data) < 15:
            self.truncated = True
            return
        self.options = unpack('<H', self.data[0:2])[0]
        self.name_len = self.data[3]
        self.cce = unpack('<H', self.data[4:6])[0]
        self.scope = unpack('<H', self.data[8:10])[0]
        cch = self.name_len
        if cch:
            if 14 + cch > len(self.data):
                self.truncated = True
                return
            flags = self.data[14]
            pos = 15
            if flags & 0x01:
                if pos + 2 * cch > len(self.data):
                    self.truncated = True
                    return
                self.name, name_end = read_unicode_2byte(
                    self.data, pos, cch)
            else:
                name_end = pos + cch
                self.name = self.data[pos:name_end].decode('latin-1')
            self.rgce = self.data[name_end:name_end + self.cce]
        else:
            self.rgce = self.data[14:14 + self.cce]
        if len(self.rgce) != self.cce:
            self.truncated = True


class XlsbRecord(record_base.OleRecordBase):
    """ like an xls record, but from binary part of xlsb file

    has no MAX_SIZE and types have different meanings
    """

    MAX_SIZE = None

    def _type_str(self):
        """ simplification for subclasses to create their own __str__ """
        try:
            return FREQUENT_RECORDS_XLSB[self.type]
        except KeyError:
            return 'XlsbRecord type {0}'.format(self.type)


class XlsbBeginSupBook(XlsbRecord):
    """ Record beginning an external link in xlsb file

    contains information about the link itself (e.g. for DDE the link is
    string1 + ' ' + string2)
    """

    TYPE = 360
    LINK_TYPE_WORKBOOK = 'workbook'
    LINK_TYPE_DDE = 'DDE'
    LINK_TYPE_OLE = 'OLE'
    LINK_TYPE_UNEXPECTED = 'unexpected'
    LINK_TYPE_UNKNOWN = 'unknown'

    def finish_constructing(self, _):
        self.link_type = self.LINK_TYPE_UNKNOWN
        self.string1 = ''
        self.string2 = ''
        if self.data is None:
            return
        self.sbt = unpack('<H', self.data[0:2])[0]
        if self.sbt == 0:
            self.link_type = self.LINK_TYPE_WORKBOOK
        elif self.sbt == 1:
            self.link_type = self.LINK_TYPE_DDE
        elif self.sbt == 2:
            self.link_type = self.LINK_TYPE_OLE
        else:
            logging.warning('Unexpected link type {0} encountered'
                            .format(self.data[0]))
            self.link_type = self.LINK_TYPE_UNEXPECTED

        start_idx = 2
        n_chars = unpack('<I', self.data[start_idx:start_idx+4])[0]
        if n_chars == 0xFFFFFFFF:
            logging.warning('Max string length 0xFFFFFFF is not allowed')
        elif self.size < n_chars*2 + start_idx+4:
            logging.warning('Impossible string length {0} for data length {1}'
                            .format(n_chars, self.size))
        else:
            self.string1, start_idx = read_unicode_2byte(self.data,
                                                         start_idx+4, n_chars)

        n_chars = unpack('<I', self.data[start_idx:start_idx+4])[0]
        if n_chars == 0xFFFFFFFF:
            logging.warning('Max string length 0xFFFFFFF is not allowed')
        elif self.size < n_chars*2 + start_idx+4:
            logging.warning('Impossible string length {0} for data length {1}'
                            .format(n_chars, self.size) + ' for string2')
        else:
            self.string2, _ = read_unicode_2byte(self.data, start_idx+4,
                                                 n_chars)

    def _type_str(self):
        return 'XlsbBeginSupBook Record ({0}, "{1}", "{2}")' \
               .format(self.link_type, self.string1, self.string2)


class XlsbBundleSh(XlsbRecord):
    """ sheet declaration (name and relationship id) in workbook.bin """

    TYPE = 0x009C

    def finish_constructing(self, _):
        self.hidden = None
        self.tab_id = None
        self.rel_id = u''
        self.name = u''
        if self.data is None or len(self.data) < 12:
            return
        self.hidden, self.tab_id = unpack('<II', self.data[0:8])
        cch = unpack('<I', self.data[8:12])[0]
        if cch and 12 + 2 * cch <= len(self.data):
            self.rel_id = self.data[12:12 + 2 * cch].decode('utf-16-le')
        pos = 12 + 2 * cch if cch else 12
        if pos + 4 > len(self.data):
            return
        name_len = unpack('<I', self.data[pos:pos + 4])[0]
        pos += 4
        if name_len and pos + 2 * name_len <= len(self.data):
            self.name = self.data[pos:pos + 2 * name_len].decode('utf-16-le')


class XlsbSupBookSrc(XlsbRecord):
    """ relationship id of an external link part in workbook.bin """

    TYPE = 0x0163

    def finish_constructing(self, _):
        self.rel_id = u''
        if self.data is None or len(self.data) < 4:
            return
        cch = unpack('<I', self.data[0:4])[0]
        if cch and 4 + 2 * cch <= len(self.data):
            self.rel_id = self.data[4:4 + 2 * cch].decode('utf-16-le')


class XlsbExternSheet(XlsbRecord):
    """ XTI table for 3-D references in workbook.bin """

    TYPE = 0x016A

    def finish_constructing(self, _):
        self.entries = []
        if self.data is None or len(self.data) < 4:
            return
        count = unpack('<I', self.data[0:4])[0]
        pos = 4
        for _ in range(count):
            if pos + 12 > len(self.data):
                break
            supbook, first, last = unpack('<Iii', self.data[pos:pos + 12])
            self.entries.append((supbook, first, last))
            pos += 12


class XlsbRowHdr(XlsbRecord):
    """ row header; used to derive the row of a following formula cell """

    TYPE = 0x0000

    def finish_constructing(self, _):
        self.row = None
        if self.data is not None and len(self.data) >= 4:
            self.row = unpack('<I', self.data[0:4])[0]


class XlsbFormula(XlsbRecord):
    """ formula cell (BrtFmlaNum/String/Bool/Error) """

    FORMULA_TYPES = (0x0008, 0x0009, 0x000A, 0x000B)
    TYPE = None

    def finish_constructing(self, _):
        self.col = None
        self.row = None
        self.cce = None
        self.rgce = b''
        self.truncated = False
        if self.data is None or len(self.data) < 12:
            self.truncated = True
            return
        self.col = unpack('<I', self.data[0:4])[0]
        # cell: col(4) + style(3) + fPhShow(1)
        pos = 8
        if self.type == 0x0009:           # BrtFmlaNum
            pos += 10                      # value(8) + reserved(2)
        elif self.type == 0x000A:         # BrtFmlaBool
            pos += 3                       # value(1) + reserved(2)
        elif self.type == 0x000B:         # BrtFmlaError
            pos += 3
        elif self.type == 0x0008:         # BrtFmlaString
            if pos + 4 > len(self.data):
                self.truncated = True
                return
            cch = unpack('<I', self.data[pos:pos + 4])[0]
            pos += 4 + 2 * cch + 2         # string + reserved(2)
        if pos + 4 > len(self.data):
            self.truncated = True
            return
        self.cce = unpack('<I', self.data[pos:pos + 4])[0]
        pos += 4
        end = pos + self.cce
        if end > len(self.data):
            self.truncated = True
            self.rgce = self.data[pos:]
        else:
            self.rgce = self.data[pos:end]


class XlsbShrFmla(XlsbRecord):
    """ shared formula over a range (BrtShrFmla) """

    TYPE = 0x01AB

    def finish_constructing(self, _):
        self.range = None
        self.cce = None
        self.rgce = b''
        self.truncated = False
        if self.data is None or len(self.data) < 20:
            self.truncated = True
            return
        r1, r2, c1, c2 = unpack('<IIII', self.data[0:16])
        self.range = (r1, r2, c1, c2)
        self.cce = unpack('<I', self.data[16:20])[0]
        end = 20 + self.cce
        self.rgce = self.data[20:end]
        if len(self.rgce) != self.cce:
            self.truncated = True


class XlsbArrFmla(XlsbRecord):
    """ array formula over a range (BrtArrFmla) """

    TYPE = 0x01AA

    def finish_constructing(self, _):
        self.range = None
        self.cce = None
        self.rgce = b''
        self.truncated = False
        if self.data is None or len(self.data) < 21:
            self.truncated = True
            return
        r1, r2, c1, c2 = unpack('<IIII', self.data[:16])
        self.range = (r1, r2, c1, c2)
        self.always_calc = self.data[16]
        self.cce = unpack('<I', self.data[17:21])[0]
        end = 21 + self.cce
        self.rgce = self.data[21:end]
        if len(self.rgce) != self.cce:
            self.truncated = True


class XlsbName(XlsbRecord):
    """ defined name with a token stream (BrtName) """

    TYPE = 0x0027

    def finish_constructing(self, _):
        self.name = u''
        self.scope = None
        self.rgce = b''
        self.truncated = False
        if self.data is None or len(self.data) < 9:
            self.truncated = True
            return
        # flags(4) chKey(1) itab(4)
        self.scope = unpack('<I', self.data[5:9])[0]
        pos = 9
        if pos + 4 > len(self.data):
            self.truncated = True
            return
        cch = unpack('<I', self.data[pos:pos + 4])[0]
        pos += 4
        if cch and pos + 2 * cch <= len(self.data):
            self.name = self.data[pos:pos + 2 * cch].decode('utf-16-le')
            pos += 2 * cch
        # remaining: cce(4) rgce, cb(4), rgcb, comment
        if pos + 4 > len(self.data):
            self.truncated = True
            return
        cce = unpack('<I', self.data[pos:pos + 4])[0]
        pos += 4
        self.rgce = self.data[pos:pos + cce]
        if len(self.rgce) != cce:
            self.truncated = True


###############################################################################
# XLSB Binary Parts
###############################################################################


def parse_xlsb_part(file_stream, _, filename):
    """ Excel xlsb files also have bin files with record structure. iter! """
    xlsb_stream = None
    try:
        xlsb_stream = XlsbStream(file_stream, file_stream.size, filename,
                                 record_base.STGTY_STREAM)
        for record in xlsb_stream.iter_records():
            yield record
    except Exception:
        raise
    finally:
        if xlsb_stream is not None:
            xlsb_stream.close()


###############################################################################
# TESTING
###############################################################################


if __name__ == '__main__':
    sys.exit(record_base.test(sys.argv[1:], XlsFile, WorkbookStream))
