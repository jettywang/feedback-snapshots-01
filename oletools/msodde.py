#!/usr/bin/env python
"""
msodde.py

msodde is a script to parse MS Office documents
(e.g. Word, Excel, RTF), to detect and extract DDE links.

Supported formats:
- Word 97-2003 (.doc, .dot), Word 2007+ (.docx, .dotx, .docm, .dotm)
- Excel 97-2003 (.xls), Excel 2007+ (.xlsx, .xlsm, .xlsb)
- RTF
- CSV (exported from / imported into Excel)
- XML (exported from Word 2003, Word 2007+, Excel 2003, (Excel 2007+?)

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

msodde is part of the python-oletools package:
http://www.decalage.info/python/oletools
"""

# === LICENSE =================================================================

# msodde is copyright (c) 2017-2019 Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# -- IMPORTS ------------------------------------------------------------------

from __future__ import print_function

import argparse
import os
import sys
import re
import csv
from collections import namedtuple

import olefile

# IMPORTANT: it should be possible to run oletools directly as scripts
# in any directory without installing them with pip or setup.py.
# In that case, relative imports are NOT usable.
# And to enable Python 2+3 compatibility, we need to use absolute imports,
# so we add the oletools parent folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
# print('_thismodule_dir = %r' % _thismodule_dir)
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
# print('_parent_dir = %r' % _thirdparty_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from oletools import ooxml
from oletools import xls_parser
from oletools import rtfobj
from oletools.ppt_record_parser import is_ppt
from oletools import crypto
from oletools.common.io_encoding import ensure_stdout_handles_unicode
from oletools.common.log_helper import log_helper

# -----------------------------------------------------------------------------
# CHANGELOG:
# 2017-10-18 v0.52 PL: - first version
# 2017-10-20       PL: - fixed issue #202 (handling empty xml tags)
# 2017-10-23       ES: - add check for fldSimple codes
# 2017-10-24       ES: - group tags and track begin/end tags to keep DDE
#                        strings together
# 2017-10-25       CH: - add json output
# 2017-10-25       CH: - parse doc
#                  PL: - added logging
# 2017-11-10       CH: - added field blacklist and corresponding cmd line args
# 2017-11-23       CH: - added support for xlsx files
# 2017-11-24       CH: - added support for xls files
# 2017-11-29       CH: - added support for xlsb files
# 2017-11-29       PL: - added support for RTF files (issue #223)
# 2017-12-07       CH: - ensure rtf file is closed
# 2018-01-05       CH: - add CSV
# 2018-01-11       PL: - fixed issue #242 (apply unquote to fldSimple tags)
# 2018-01-10       CH: - add single-xml files (Word 2003/2007+ / Excel 2003)
# 2018-03-21       CH: - added detection for various CSV formulas (issue #259)
# 2018-09-11 v0.54 PL: - olefile is now a dependency
# 2018-10-25       CH: - detect encryption and raise error if detected
# 2019-03-25       CH: - added decryption of password-protected files
# 2019-07-17 v0.55 CH: - fixed issue #267, unicode error on Python 2
# 2026-11-19           - parse Word fields with a state stack: instructions
#                        split over several runs are reassembled, field
#                        results and nested fields are never mixed into the
#                        enclosing instruction, and fields without an end
#                        marker are reported as incomplete instead of being
#                        extended with following text


__version__ = '0.60.2'

# -----------------------------------------------------------------------------
# TODO: field codes can be in headers/footers/comments - parse these
# TODO: generalize behaviour for xlsx: find all external links (maybe rename
#       command line flag for "blacklist" to "find all suspicious" or so)
# TODO: Test with more interesting (real-world?) samples: xls, xlsx, xlsb, docx
# TODO: Think about finding all external "connections" of documents, not just
#       DDE-Links
# TODO: avoid reading complete rtf file data into memory

# -----------------------------------------------------------------------------
# REFERENCES:


# === PYTHON 2+3 SUPPORT ======================================================

# (nothing needed here at the moment; kept for consistency with other modules)

# === CONSTANTS ==============================================================


NS_WORD = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
NS_WORD_2003 = 'http://schemas.microsoft.com/office/word/2003/wordml'
NO_QUOTES = False
# XML tag for 'w:instrText'
TAG_W_INSTRTEXT = ['{%s}instrText' % ns for ns in (NS_WORD, NS_WORD_2003)]
TAG_W_FLDSIMPLE = ['{%s}fldSimple' % ns for ns in (NS_WORD, NS_WORD_2003)]
TAG_W_FLDCHAR = ['{%s}fldChar' % ns for ns in (NS_WORD, NS_WORD_2003)]
TAG_W_P = ["{%s}p" % ns for ns in (NS_WORD, NS_WORD_2003)]
TAG_W_R = ["{%s}r" % ns for ns in (NS_WORD, NS_WORD_2003)]
TAG_W_T = ["{%s}t" % ns for ns in (NS_WORD, NS_WORD_2003)]
ATTR_W_INSTR = ['{%s}instr' % ns for ns in (NS_WORD, NS_WORD_2003)]
ATTR_W_FLDCHARTYPE = ['{%s}fldCharType' % ns for ns in (NS_WORD, NS_WORD_2003)]
LOCATIONS = ('word/document.xml', 'word/endnotes.xml', 'word/footnotes.xml',
             'word/header1.xml', 'word/footer1.xml', 'word/header2.xml',
             'word/footer2.xml', 'word/comments.xml')

# list of acceptable, harmless field instructions for blacklist field mode
# c.f. http://officeopenxml.com/WPfieldInstructions.php or the official
# standard ISO-29500-1:2016 / ECMA-376 paragraphs 17.16.4, 17.16.5, 17.16.23
# https://www.iso.org/standard/71691.html (neither mentions DDE[AUTO]).
# Format: (command, n_required_args, n_optional_args,
#          switches_with_args, switches_without_args, format_switches)
FIELD_BLACKLIST = (
    # date and time:
    ('CREATEDATE', 0, 0, '', 'hs',  'datetime'),
    ('DATE',       0, 0, '', 'hls', 'datetime'),
    ('EDITTIME',   0, 0, '', '',    'numeric'),
    ('PRINTDATE',  0, 0, '', 'hs',  'datetime'),
    ('SAVEDATE',   0, 0, '', 'hs',  'datetime'),
    ('TIME',       0, 0, '', '',    'datetime'),
    # exclude document automation (we hate the "auto" in "automation")
    # (COMPARE, DOCVARIABLE, GOTOBUTTON, IF, MACROBUTTON, PRINT)
    # document information
    ('AUTHOR',      0, 1, '', '',   'string'),
    ('COMMENTS',    0, 1, '', '',   'string'),
    ('DOCPROPERTY', 1, 0, '', '',   'string/numeric/datetime'),
    ('FILENAME',    0, 0, '', 'p',  'string'),
    ('FILESIZE',    0, 0, '', 'km', 'numeric'),
    ('KEYWORDS',    0, 1, '', '',   'string'),
    ('LASTSAVEDBY', 0, 0, '', '',   'string'),
    ('NUMCHARS',    0, 0, '', '',   'numeric'),
    ('NUMPAGES',    0, 0, '', '',   'numeric'),
    ('NUMWORDS',    0, 0, '', '',   'numeric'),
    ('SUBJECT',     0, 1, '', '',   'string'),
    ('TEMPLATE',    0, 0, '', 'p',  'string'),
    ('TITLE',       0, 1, '', '',   'string'),
    # equations and formulas
    # exlude '=' formulae because they have different syntax (and can be bad)
    ('ADVANCE', 0, 0, 'dlruxy', '', ''),
    ('SYMBOL',  1, 0, 'fs', 'ahju', ''),
    # form fields
    ('FORMCHECKBOX', 0, 0, '', '', ''),
    ('FORMDROPDOWN', 0, 0, '', '', ''),
    ('FORMTEXT', 0, 0, '', '', ''),
    # index and tables
    ('INDEX', 0, 0, 'bcdefghklpsz', 'ry', ''),
    # exlude RD since that imports data from other files
    ('TA',  0, 0, 'clrs', 'bi', ''),
    ('TC',  1, 0, 'fl', 'n', ''),
    ('TOA', 0, 0, 'bcdegls', 'fhp', ''),
    ('TOC', 0, 0, 'abcdflnopst', 'huwxz', ''),
    ('XE',  1, 0, 'frty', 'bi', ''),
    # links and references
    # exclude AUTOTEXT and AUTOTEXTLIST since we do not like stuff with 'AUTO'
    ('BIBLIOGRAPHY', 0, 0, 'lfm', '', ''),
    ('CITATION', 1, 0, 'lfspvm', 'nty', ''),
    # exclude HYPERLINK since we are allergic to URLs
    # exclude INCLUDEPICTURE and INCLUDETEXT (other file or maybe even URL?)
    # exclude LINK and REF (could reference other files)
    ('NOTEREF', 1, 0, '', 'fhp', ''),
    ('PAGEREF', 1, 0, '', 'hp', ''),
    ('QUOTE', 1, 0, '', '', 'datetime'),
    ('STYLEREF', 1, 0, '', 'lnprtw', ''),
    # exclude all Mail Merge commands since they import data from other files
    # (ADDRESSBLOCK, ASK, COMPARE, DATABASE, FILLIN, GREETINGLINE, IF,
    #  MERGEFIELD, MERGEREC, MERGESEQ, NEXT, NEXTIF, SET, SKIPIF)
    # Numbering
    ('LISTNUM',      0, 1, 'ls', '', ''),
    ('PAGE',         0, 0, '', '', 'numeric'),
    ('REVNUM',       0, 0, '', '', ''),
    ('SECTION',      0, 0, '', '', 'numeric'),
    ('SECTIONPAGES', 0, 0, '', '', 'numeric'),
    ('SEQ',          1, 1, 'rs', 'chn', 'numeric'),
    # user information
    ('USERADDRESS', 0, 1, '', '', 'string'),
    ('USERINITIALS', 0, 1, '', '', 'string'),
    ('USERNAME', 0, 1, '', '', 'string'),
)

FIELD_DDE_REGEX = re.compile(r'^\s*dde(auto)?\s+', re.I)

#: field kinds as reported by :py:class:`FieldInfo`
FIELD_KIND_COMPLEX = 'complex'
FIELD_KIND_SIMPLE = 'simple'
FIELD_KIND_OLE = 'ole'

#: A piece of a field instruction. ``position`` is the position of the XML
#: element (or the byte offset in an OLE stream) that carried the text.
FieldFragment = namedtuple('FieldFragment', 'position text')

#: Description of a single field found in a document.
#:
#: ``part`` is the package part containing the field (e.g. ``word/document.xml``
#: or ``word/header1.xml``), ``position`` is the position of the field begin in
#: that part, ``parent`` is the position of the enclosing field if the field is
#: nested, and ``depth`` is the nesting depth (0 for a top-level field).
#: ``fragments`` preserves the individual instruction pieces in document order.
#: ``separate_position`` and ``end_position`` locate the separator and end
#: markers (either XML element positions or OLE stream offsets). ``complete``
#: is false if the end marker was missing.
_FieldInfoBase = namedtuple(
    'FieldInfo',
    'part position parent depth kind instruction result fragments complete '
    'separate_position end_position')


class FieldInfo(_FieldInfoBase):
    """ A Word field including its provenance. See FieldInfo namedtuple. """
    __slots__ = ()

    @property
    def is_dde(self):
        """ Whether this field's instruction is a DDE/DDEAUTO command. """
        return bool(FIELD_DDE_REGEX.match(self.instruction))


# filter modes
FIELD_FILTER_DDE = 'only dde'
FIELD_FILTER_BLACKLIST = 'exclude blacklisted'
FIELD_FILTER_ALL = 'keep all'
FIELD_FILTER_DEFAULT = FIELD_FILTER_BLACKLIST


# banner to be printed at program start
BANNER = """msodde %s - http://decalage.info/python/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues
""" % __version__

# === LOGGING =================================================================

DEFAULT_LOG_LEVEL = "warning"  # Default log level

# a global logger object used for debugging:
logger = log_helper.get_or_create_silent_logger('msodde')


# === ARGUMENT PARSING =======================================================

class ArgParserWithBanner(argparse.ArgumentParser):
    """ Print banner before showing any error """
    def error(self, message):
        print(BANNER)
        super(ArgParserWithBanner, self).error(message)


def existing_file(filename):
    """ called by argument parser to see whether given file exists """
    if not os.path.exists(filename):
        raise argparse.ArgumentTypeError('File {0} does not exist.'
                                         .format(filename))
    return filename


def process_args(cmd_line_args=None):
    """ parse command line arguments (given ones or per default sys.argv) """
    parser = ArgParserWithBanner(description='A python tool to detect and '
                                 'extract DDE links in MS Office files')
    parser.add_argument("filepath", help="path of the file to be analyzed",
                        type=existing_file, metavar='FILE')
    parser.add_argument('-j', "--json", action='store_true',
                        help="Output in json format. Do not use with -ldebug")
    parser.add_argument("--nounquote", help="don't unquote values",
                        action='store_true')
    parser.add_argument('-l', '--loglevel', dest="loglevel", action="store",
                        default=DEFAULT_LOG_LEVEL,
                        help="logging level debug/info/warning/error/critical "
                             "(default=%(default)s)")
    parser.add_argument("-p", "--password", type=str, action='append',
                        help='if encrypted office files are encountered, try '
                             'decryption with this password. May be repeated.')
    parser.add_argument("--decrypted_dir", dest='decrypted_dir', type=str,
                        default=None,
                        help='store the decrypted file to this folder.')
    filter_group = parser.add_argument_group(
        title='Filter which OpenXML field commands are returned',
        description='Only applies to OpenXML (e.g. docx) and rtf, not to OLE '
                    '(e.g. .doc). These options are mutually exclusive, last '
                    'option found on command line overwrites earlier ones.')
    filter_group.add_argument('-d', '--dde-only', action='store_const',
                              dest='field_filter_mode', const=FIELD_FILTER_DDE,
                              help='Return only DDE and DDEAUTO fields')
    filter_group.add_argument('-f', '--filter', action='store_const',
                              dest='field_filter_mode',
                              const=FIELD_FILTER_BLACKLIST,
                              help='Return all fields except harmless ones')
    filter_group.add_argument('-a', '--all-fields', action='store_const',
                              dest='field_filter_mode', const=FIELD_FILTER_ALL,
                              help='Return all fields, irrespective of their '
                                   'contents')
    parser.set_defaults(field_filter_mode=FIELD_FILTER_DEFAULT)

    return parser.parse_args(cmd_line_args)


# === FUNCTIONS ==============================================================

# from [MS-DOC], section 2.8.25 (PlcFld):
# A field consists of two parts: field instructions and, optionally, a result.
# All fields MUST begin with Unicode character 0x0013 with sprmCFSpec applied
# with a value of 1. This is the field begin character. All fields MUST end
# with a Unicode character 0x0015 with sprmCFSpec applied with a value of 1.
# This is the field end character. If the field has a result, then there MUST
# be a Unicode character 0x0014 with sprmCFSpec applied with a value of 1
# somewhere between the field begin character and the field end character. This
# is the field separator. The field result is the content between the field
# separator and the field end character. The field instructions are the content
# between the field begin character and the field separator, if one is present,
# or between the field begin character and the field end character if no
# separator is present. The field begin character, field end character, and
# field separator are collectively referred to as field characters.


def process_doc_field(data):
    """ check if field instructions start with DDE

    expects unicode input, returns unicode output (empty if not dde) """
    logger.debug(u'processing field \'{0}\''.format(data))

    if data.lstrip().lower().startswith(u'dde'):
        return data
    if data.lstrip().lower().startswith(u'\x00d\x00d\x00e\x00'):
        return data
    return u''


OLE_FIELD_START = 0x13
OLE_FIELD_SEP = 0x14
OLE_FIELD_END = 0x15
OLE_FIELD_MAX_SIZE = 1000   # max field size to analyze, rest is ignored
FIELD_RESULT_MAX_SIZE = 1000  # max amount of field result text kept per field


class _MutableField(object):
    """ A field while it is still being parsed.

    The public representation is :py:class:`FieldInfo`; this class only exists
    because fields are parsed in several steps (begin, instruction fragments,
    separator, result, end) and need to be filled while the parse advances.

    Instruction and result text are kept as positioned fragments. Positions are
    element numbers (XML) or stream offsets (OLE). This also allows truncating
    an unterminated field at its last paragraph boundary: text from following
    paragraphs must not be attributed to it.
    """

    def __init__(self, part, position, parent, depth, kind, as_bytes=False,
                 unquote_instruction=False):
        self.part = part
        self.position = position
        self.parent = parent
        self.depth = depth
        self.kind = kind
        self.separate_position = None
        self.utf16 = False
        self._as_bytes = as_bytes
        self._unquote = unquote_instruction
        # fragments are [position, text]; adjacent OLE bytes are merged
        self._instruction_fragments = []
        self._result_fragments = []
        self._in_result = kind in (FIELD_KIND_SIMPLE, )
        self._instruction_closed = False
        self._instruction_too_big = False
        self._instruction_length = 0
        self._result_length = 0
        self._boundary = None

    def _decoded(self, data):
        """ decode collected OLE bytes; text parts are already unicode """
        if isinstance(data, (bytes, bytearray)):
            return decode_field_instruction(bytes(data), self.utf16)
        return u''.join(data)

    def _append(self, fragments, position, text):
        """ append to a fragment list, merging adjacent OLE bytes """
        if self._as_bytes and fragments and \
                fragments[-1][0] + len(fragments[-1][1]) == position:
            fragments[-1][1] += text
        else:
            fragments.append([position, text])

    def add_instruction(self, position, text):
        """ add one instruction fragment (XML element or attribute) """
        if not text or self._instruction_closed:
            return
        self._append(self._instruction_fragments, position, text)
        self._instruction_length += len(text)

    def close_instruction(self):
        """ stop collecting instruction text (e.g. at a paragraph mark) """
        self._instruction_closed = True

    def note_boundary(self, position):
        """ remember the first paragraph boundary inside this field """
        if self._boundary is None:
            self._boundary = position

    def add_instruction_char(self, position, char):
        """ add a single character of instruction text (OLE stream) """
        if self._in_result:
            self.add_result_char(position, char)
            return
        if self._instruction_closed or self._instruction_too_big:
            return
        if self._instruction_length >= OLE_FIELD_MAX_SIZE:
            logger.debug('field exceeds max size of {0}. Ignore rest'
                         .format(OLE_FIELD_MAX_SIZE))
            self._instruction_too_big = True
            return
        self._append(self._instruction_fragments, position, char)
        self._instruction_length += len(char)

    def add_result_char(self, position, char):
        """ keep a bounded amount of the field result for reporting """
        if self._result_length < FIELD_RESULT_MAX_SIZE:
            self._append(self._result_fragments, position, char)
            self._result_length += len(char)

    def add_result(self, position, text):
        """ add (a piece of) the field result text """
        if not text or self._as_bytes:
            return
        room = FIELD_RESULT_MAX_SIZE - self._result_length
        if room > 0:
            self._append(self._result_fragments, position, text[:room])
            self._result_length += min(room, len(text))

    def set_separator(self, position):
        """ mark the begin of the field result """
        self.separate_position = position
        self._in_result = True
        self._instruction_closed = True

    @property
    def in_result(self):
        """ whether following text belongs to the field result """
        return self._in_result

    def finish(self, end_position, complete):
        """ convert this field to its public, immutable representation """
        instruction_fragments = self._instruction_fragments
        result_fragments = self._result_fragments
        if not complete and self._boundary is not None:
            # Unterminated: only keep what was collected before the first
            # paragraph boundary. Later paragraphs are unrelated text.
            instruction_fragments = [fragment for fragment in
                                     instruction_fragments
                                     if fragment[0] < self._boundary]
            result_fragments = [fragment for fragment in result_fragments
                                if fragment[0] < self._boundary]
            if self.separate_position is not None and \
                    self.separate_position >= self._boundary:
                self.separate_position = None
        fragments = tuple(FieldFragment(position, self._decoded(text))
                          for position, text in instruction_fragments)
        instruction = self._decoded(
            u''.join(text for _, text in instruction_fragments)
            if not self._as_bytes else
            b''.join(text for _, text in instruction_fragments))
        if self._unquote:
            # QUOTE fields encode their text as character codes. Unquoting
            # must see the complete instruction, not individual fragments.
            instruction = unquote(instruction)
        result = self._decoded(
            u''.join(text for _, text in result_fragments)
            if not self._as_bytes else
            b''.join(text for _, text in result_fragments))
        return FieldInfo(part=self.part,
                         position=self.position,
                         parent=self.parent,
                         depth=self.depth,
                         kind=self.kind,
                         instruction=instruction,
                         result=result,
                         fragments=fragments,
                         complete=complete,
                         separate_position=self.separate_position,
                         end_position=end_position)


class _OleFieldCollector(object):
    """ Stack-based parser for the field characters in a Word OLE stream.

    The stream is parsed byte-wise, so field positions are offsets into the
    original stream. Word may store text as UTF-16LE; in that case the field
    characters are followed by a NUL byte, which is skipped. Whether the
    collected bytes are UTF-16LE or 8-bit text is decided when they are
    decoded, so unrelated binary stream data is never decoded as text.
    """

    def __init__(self, part=None):
        self.part = part
        self.fields = []
        self._stack = []

    def _start_field(self, position, utf16):
        parent = self._stack[-1].position if self._stack else None
        field = _MutableField(self.part, position, parent, len(self._stack),
                              FIELD_KIND_OLE, as_bytes=True)
        # Per field, the collected bytes may still turn out to be 8-bit text
        # (a document can mix both encodings). ``utf16`` is only a hint.
        field.utf16 = utf16
        self._stack.append(field)

    def _end_field(self, position):
        # UTF-16LE field markers are followed by a NUL byte; the end marker
        # is still taken from the position of the 0x15 byte itself.
        if not self._stack:
            logger.debug('found field end at position {0} without begin'
                         .format(position))
            return
        field = self._stack.pop()
        self.fields.append(field.finish(position, True))

    def parse(self, data):
        """ parse OLE stream bytes, return list of FieldInfo

        The stream is always parsed byte-wise so that positions refer to the
        original stream. Word may store text as UTF-16LE, and one document may
        even mix 8-bit and UTF-16LE text. A NUL byte after a field character
        belongs to the field character, not to the text; likewise, the NULs
        between the characters of UTF-16LE text are not part of the text. Both
        are skipped, so the collected bytes are the actual characters.
        """
        if isinstance(data, str):
            data = data.encode('latin-1', 'replace')
        data = bytearray(data)
        # A UTF-16LE stream continues with NUL after every character. Detect
        # it from the stream; the actual encoding is confirmed per field when
        # the instruction is decoded.
        utf16 = data.count(b'\x00') * 2 >= len(data) or \
            b'\x13\x00' in bytes(data)
        skip_nul = False
        for position, char in enumerate(data):
            if skip_nul:
                skip_nul = False
                if char == 0:
                    continue
            if char == OLE_FIELD_START:
                self._start_field(position, utf16)
                skip_nul = utf16
            elif char == OLE_FIELD_SEP:
                if not self._stack:
                    logger.debug('found field separator at position {0} '
                                 'without begin'.format(position))
                elif self._stack[-1].in_result:
                    logger.debug('unexpected field: has multiple separators!')
                else:
                    self._stack[-1].set_separator(position)
                skip_nul = utf16
            elif char == OLE_FIELD_END:
                self._end_field(position)
                skip_nul = utf16
            elif self._stack:
                field = self._stack[-1]
                if char in (10, 13):
                    # Remember the first paragraph boundary; an unterminated
                    # field is truncated there in finish(). Text from a
                    # following paragraph is never appended, even if it is
                    # collected before the field gets closed.
                    field.note_boundary(position)
                    if not field.in_result:
                        field.close_instruction()
                    continue
                if field.in_result:
                    field.add_result_char(position, bytes((char, )))
                else:
                    field.add_instruction_char(position, bytes((char, )))

        # Fields that never got an end marker are reported as incomplete. Do
        # not append anything that follows them: their instruction is exactly
        # the text collected between begin and (missing) end.
        while self._stack:
            field = self._stack.pop()
            finished = field.finish(None, False)
            if _looks_like_field_instruction(finished.instruction):
                logger.warning('Incomplete field in stream %r starting at '
                               'position %d: missing field end',
                               self.part, field.position)
            self.fields.append(finished)

        self.fields.sort(key=lambda item: item.position)
        # OLE streams contain binary data besides the text; some byte pairs
        # look like field characters. Drop implausible fields and derive the
        # nesting from the remaining markers only.
        plausible = [field for field in self.fields
                     if _looks_like_field_instruction(field.instruction)]
        for dropped in set(id(field) for field in self.fields) - \
                set(id(field) for field in plausible):
            logger.debug('Ignoring implausible field in stream %r', self.part)
        return _recompute_nesting(plausible)


def _looks_like_field_instruction(instruction):
    """ heuristic: a real field instruction is printable text

    Used for OLE streams, which mix document text with binary data. A field
    instruction starts with a command word (letters) or an '=' formula, which
    distinguishes it from stray bytes that happen to look like field
    characters. The check is otherwise permissive so unusual but genuine
    fields survive.
    """
    text = instruction.strip()
    if not text:
        return False
    if not (text[0].isalpha() or text[0] == u'='):
        return False
    printable = sum(1 for char in text
                    if char.isprintable() or char in u'\t\r\n ')
    return printable * 10 >= len(text) * 9


def _recompute_nesting(fields):
    """ derive ``parent`` and ``depth`` from begin/end markers

    ``fields`` must be sorted by begin position. An unterminated field does not
    enclose later fields: without an end marker its extent is unknown, so it
    remains at depth 0 and the markers after it form top-level fields.
    """
    stack = []
    result = []
    for field in fields:
        while stack and stack[-1].end_position is not None and \
                stack[-1].end_position <= field.position:
            stack.pop()
        parent = stack[-1].position if stack else None
        result.append(field._replace(parent=parent, depth=len(stack)))
        if field.complete:
            stack.append(field)
    return result


def decode_field_instruction(data, utf16=False):
    """ decode raw instruction bytes from a Word OLE stream

    Word stores text either as UTF-16LE or as 8-bit characters, depending on
    the document, and one document may even mix both. Only the text collected
    from a field region is decoded here, so unrelated binary stream data
    neither influences the detection nor the output.

    :param bytes data: collected instruction or result bytes
    :param bool utf16: prefer UTF-16LE; the data is inspected to confirm it
    """
    if not data:
        return u''
    if utf16 and len(data) % 2 == 0:
        # If the text was 8-bit after all, it would not contain a NUL after
        # most characters. Only trust the hint when the bytes support it.
        if data.count(b'\x00') * 2 >= len(data):
            return data.decode('utf-16le', 'replace')
    if not utf16 and len(data) % 2 == 0 and data[:1] != b'\x00' and \
            data.count(b'\x00') * 2 >= len(data):
        return data.decode('utf-16le', 'replace')
    return data.decode('latin-1')


def process_doc_stream_fields(stream, part=None):
    """ find all fields in a single Word OLE stream

    Returns a list of :py:class:`FieldInfo` in document order. Fields that
    are not terminated are returned with ``complete=False`` and without the
    text of any following paragraph.

    :param stream: file-like object opened in binary mode
    :param part: name of the stream, stored in the FieldInfo for reference
    """
    return _OleFieldCollector(part).parse(stream.read())


def process_doc_stream(stream):
    """ find dde links in single word ole stream

    since word ole file stream are subclasses of io.BytesIO, they are buffered,
    so reading char-wise is not that bad performance-wise """

    fields = process_doc_stream_fields(stream)
    result_parts = []
    for field in fields:
        new_result = process_doc_field(field.instruction)
        if new_result:
            result_parts.append(new_result)

    logger.debug('Checked stream, found {0} fields ({1} dde links)'
                 .format(len(fields), len(result_parts)))
    return result_parts


def process_doc_fields(ole):
    """ find all fields in a Word 97-2003 OLE file

    Returns a list of :py:class:`FieldInfo` in stream order. The stream name
    is used as ``part`` so that extraction results can be traced back to the
    original stream.
    """
    all_fields = []
    for sid, direntry in enumerate(ole.direntries):
        is_orphan = direntry is None
        if is_orphan:
            # this direntry is not part of the tree --> unused or orphan
            direntry = ole._load_direntry(sid)
        is_stream = direntry.entry_type == olefile.STGTY_STREAM
        logger.debug('direntry {:2d} {}: {}'
                     .format(sid, '[orphan]' if is_orphan else direntry.name,
                             'is stream of size {}'.format(direntry.size)
                             if is_stream else
                             'no stream ({})'.format(direntry.entry_type)))
        if is_stream:
            new_fields = process_doc_stream_fields(
                ole._open(direntry.isectStart, direntry.size),
                part=direntry.name)
            if new_fields:
                logger.debug("stream %r: %r" % (direntry.name, new_fields))
            all_fields.extend(new_fields)
    return all_fields


def process_doc(ole):
    """
    find dde links in word ole (.doc/.dot) file

    Checks whether files is ppt and returns empty immediately in that case
    (ppt files cannot contain DDE-links to my knowledge)

    like process_xml, returns a concatenated unicode string of dde links or
    empty if none were found. dde-links will still begin with the dde[auto] key
    word (possibly after some whitespace)
    """
    logger.debug('process_doc')
    links = []
    for field in process_doc_fields(ole):
        new_result = process_doc_field(field.instruction)
        if new_result:
            links.append(new_result)

    # mimic behaviour of process_docx: combine links to single text string
    return u'\n'.join(links)


def process_xls(filepath):
    """ find dde links in excel ole file """

    result = []
    xls_file = None
    try:
        xls_file = xls_parser.XlsFile(filepath)
        for stream in xls_file.iter_streams():
            if not isinstance(stream, xls_parser.WorkbookStream):
                continue
            for record in stream.iter_records():
                if not isinstance(record, xls_parser.XlsRecordSupBook):
                    continue
                if record.support_link_type in (
                        xls_parser.XlsRecordSupBook.LINK_TYPE_OLE_DDE,
                        xls_parser.XlsRecordSupBook.LINK_TYPE_EXTERNAL):
                    result.append(record.virt_path.replace(u'\u0003', u' '))
        return u'\n'.join(result)
    finally:
        if xls_file is not None:
            xls_file.close()


class _DocxFieldCollector(object):
    """ Stack-based parser for WordprocessingML complex and simple fields.

    WordprocessingML splits a field over several runs: a ``w:fldChar`` begin
    marker, one or more ``w:instrText`` elements with the instruction, an
    optional ``w:fldChar`` separator, the display result, and a ``w:fldChar``
    end marker. Fields may be nested. Only ``w:instrText`` contributes to the
    instruction; text in the result region (``w:t``) or in another field's
    instruction can never end up in the instruction of the enclosing field.
    """

    def __init__(self, part):
        self.part = part
        self.fields = []
        self._stack = []
        self._position = 0

    def next_position(self):
        """ return the position of the next element in the current part """
        self._position += 1
        return self._position

    def _start_field(self, position, kind):
        parent = self._stack[-1].position if self._stack else None
        field = _MutableField(self.part, position, parent, len(self._stack),
                              kind, unquote_instruction=True)
        self._stack.append(field)
        return field

    def _append_field(self, field, end_position, complete):
        if not complete:
            logger.warning('Incomplete field in part %r at position %d: '
                           'missing field end', self.part, field.position)
        self.fields.append(field.finish(end_position, complete))

    def begin(self, position):
        """ handle a w:fldChar begin marker """
        self._start_field(position, FIELD_KIND_COMPLEX)

    def separate(self, position):
        """ handle a w:fldChar separate marker """
        if not self._stack:
            logger.warning('Field separator without field begin in part %r '
                           'at position %d', self.part, position)
        elif self._stack[-1].in_result:
            logger.warning('Field has multiple separators in part %r at '
                           'position %d', self.part, position)
        else:
            self._stack[-1].set_separator(position)

    def end(self, position):
        """ handle a w:fldChar end marker """
        if not self._stack:
            logger.warning('Field end without field begin in part %r at '
                           'position %d', self.part, position)
            return
        self._append_field(self._stack.pop(), position, True)

    def instruction(self, position, text):
        """ add an instruction fragment to the innermost open field """
        if self._stack and text:
            self._stack[-1].add_instruction(position, text)

    def result_text(self, position, text):
        """ add display text to the result of the innermost open field

        Text between begin and separator is part of the instruction region, not
        a field result; some producers omit the separator for fields without a
        result. Such text is ignored so it cannot be mistaken for an
        instruction fragment either.
        """
        if not self._stack:
            return
        field = self._stack[-1]
        if field.in_result:
            field.add_result(position, text)

    def paragraph_boundary(self, position):
        """ note a paragraph end for all open fields """
        for field in self._stack:
            field.note_boundary(position)

    def simple_begin(self, position, instruction):
        """ handle the start of a w:fldSimple element """
        field = self._start_field(position, FIELD_KIND_SIMPLE)
        if instruction is not None:
            field.add_instruction(position, instruction)
        # the instruction attribute is complete; children are the result
        field.set_separator(position)

    def simple_end(self, position):
        """ handle the end of a w:fldSimple element """
        self._append_field(self._stack.pop(), position, True)

    def finish(self):
        """ close fields left open at the end of a part, mark them incomplete

        Text that follows an unterminated field is deliberately not appended:
        without an end marker there is no way to tell where the field would
        have ended, so the reported instruction is exactly what was collected.
        """
        while self._stack:
            self._append_field(self._stack.pop(), None, False)
        # nested fields are closed before their parents; present them in
        # document order, which is the order of their begin markers
        self.fields.sort(key=lambda item: item.position)
        return self.fields


def process_docx_fields(filepath):
    """ find all fields (DDE and others) in a Word 2007+ file

    Returns a list of :py:class:`FieldInfo` in document order. Each item keeps
    the package part, the element position, the enclosing field position, the
    nesting depth and the completeness of the field. Instruction fragments
    split over several runs are concatenated; field results and nested-field
    instructions are never mixed into the enclosing instruction.
    """
    parser = ooxml.XmlParser(filepath)
    all_fields = []
    for part, handle in parser.iter_files():
        collector = _DocxFieldCollector(part)
        # positions of all currently open elements, so that end events can
        # refer to the element's start position; works with any XML backend
        open_positions = []
        try:
            for event, elem in ooxml.ET.iterparse(handle,
                                                  events=('start', 'end')):
                if event == 'start':
                    position = collector.next_position()
                    open_positions.append(position)
                    if elem.tag in TAG_W_FLDCHAR:
                        fld_type = elem.attrib.get(ATTR_W_FLDCHARTYPE[0]) or \
                                   elem.attrib.get(ATTR_W_FLDCHARTYPE[1])
                        if fld_type == 'begin':
                            collector.begin(position)
                        elif fld_type == 'separate':
                            collector.separate(position)
                        elif fld_type == 'end':
                            collector.end(position)
                        else:
                            logger.debug('Ignoring unknown fldCharType %r',
                                         fld_type)
                    elif elem.tag in TAG_W_FLDSIMPLE:
                        instr = elem.attrib.get(ATTR_W_INSTR[0]) or \
                                elem.attrib.get(ATTR_W_INSTR[1])
                        collector.simple_begin(position, instr)
                    continue

                # end event: children are complete, so text can be read
                position = open_positions.pop()
                if elem.tag in TAG_W_INSTRTEXT:
                    collector.instruction(position, elem.text)
                elif elem.tag in TAG_W_T:
                    collector.result_text(position, elem.text)
                elif elem.tag in TAG_W_FLDSIMPLE:
                    collector.simple_end(position)
                elif elem.tag in TAG_W_P:
                    # the boundary is after all paragraph children, so field
                    # content inside this paragraph is before it
                    collector.paragraph_boundary(collector.next_position())
                # keep memory usage low for large documents
                elem.clear()
        except ooxml.ET.ParseError as err:
            parser.subfiles_no_xml.add(part)
            log = logger.warning if part is None or part.endswith('.xml') \
                else logger.debug
            log('  xml-parsing for {0} failed ({1}).'.format(part, err))

        all_fields.extend(collector.finish())
    return all_fields


def process_docx(filepath, field_filter_mode=None):
    """ find dde-links (and other fields) in Word 2007+ files """
    return filter_field_instructions(process_docx_fields(filepath),
                                     field_filter_mode)


def filter_field_instructions(fields, field_filter_mode):
    """ apply the command-line field filter to a list of FieldInfo """
    logger.debug('filtering with mode "{0}"'.format(field_filter_mode))
    if field_filter_mode in (FIELD_FILTER_ALL, None):
        clean_fields = list(fields)
    elif field_filter_mode == FIELD_FILTER_DDE:
        clean_fields = [field for field in fields if field.is_dde]
    elif field_filter_mode == FIELD_FILTER_BLACKLIST:
        # check if fields are acceptable and should not be returned
        clean_fields = [field for field in fields
                        if not field_is_blacklisted(
                            field.instruction.strip())]
    else:
        raise ValueError('Unexpected field_filter_mode: "{0}"'
                         .format(field_filter_mode))

    return u'\n'.join(field.instruction for field in clean_fields)


def unquote(field):
    """ remove the QUOTE field wrapper, expanding numeric character codes

    ``QUOTE`` fields contain the displayed text as arguments; e.g.
    ``QUOTE 65 66`` displays ``AB``. Only the first word (the field command)
    is removed, the rest is concatenated. Non-numeric words are kept as they
    are. This is intentionally lenient: msodde reports fields, it does not
    validate them.
    """
    if "QUOTE" not in field or NO_QUOTES:
        return field
    # split into components
    parts = field.strip().split(" ")
    ddestr = ""
    for part in parts[1:]:
        try:
            character = chr(int(part))
        except ValueError:
            character = part
        ddestr += character
    return ddestr


# "static variables" for field_is_blacklisted:
FIELD_WORD_REGEX = re.compile(r'"[^"]*"|\S+')
FIELD_BLACKLIST_CMDS = tuple(field[0].lower() for field in FIELD_BLACKLIST)
FIELD_SWITCH_REGEX = re.compile(r'^\\[\w#*@]$')


def field_is_blacklisted(contents):
    """ Check if given field contents matches any in FIELD_BLACKLIST

    A complete parser of field contents would be really complicated, so this
    function has to make a trade-off. There may be valid constructs that this
    simple parser cannot comprehend. Most arguments are not tested for validity
    since that would make this test much more complicated. However, if this
    parser accepts some field contents, then office is very likely to not
    complain about it, either.
    """

    # split contents into "words", (e.g. 'bla' or '\s' or '"a b c"' or '""')
    words = FIELD_WORD_REGEX.findall(contents)
    if not words:
        return False

    # check if first word is one of the commands on our blacklist
    try:
        index = FIELD_BLACKLIST_CMDS.index(words[0].lower())
    except ValueError:    # first word is no blacklisted command
        return False
    logger.debug(u'trying to match "{0}" to blacklist command {1}'
                 .format(contents, FIELD_BLACKLIST[index]))
    _, nargs_required, nargs_optional, sw_with_arg, sw_solo, sw_format \
        = FIELD_BLACKLIST[index]

    # check number of args
    nargs = 0
    for word in words[1:]:
        if word[0] == '\\':  # note: words can never be empty, but can be '""'
            break
        nargs += 1
    if nargs < nargs_required:
        logger.debug(u'too few args: found {0}, but need at least {1} in "{2}"'
                     .format(nargs, nargs_required, contents))
        return False
    if nargs > nargs_required + nargs_optional:
        logger.debug(u'too many args: found {0}, but need at most {1}+{2} in '
                     u'"{3}"'
                     .format(nargs, nargs_required, nargs_optional, contents))
        return False

    # check switches
    expect_arg = False
    arg_choices = []
    for word in words[1+nargs:]:
        if expect_arg:            # this is an argument for the last switch
            if arg_choices and (word not in arg_choices):
                logger.debug(u'Found invalid switch argument "{0}" in "{1}"'
                             .format(word, contents))
                return False
            expect_arg = False
            arg_choices = []   # in general, do not enforce choices
            continue           # "no further questions, your honor"
        elif not FIELD_SWITCH_REGEX.match(word):
            logger.debug(u'expected switch, found "{0}" in "{1}"'
                         .format(word, contents))
            return False
        # we want a switch and we got a valid one
        switch = word[1]

        if switch in sw_solo:
            pass
        elif switch in sw_with_arg:
            expect_arg = True     # next word is interpreted as arg, not switch
        elif switch == '#' and 'numeric' in sw_format:
            expect_arg = True     # next word is numeric format
        elif switch == '@' and 'datetime' in sw_format:
            expect_arg = True     # next word is date/time format
        elif switch == '*':
            expect_arg = True     # next word is format argument
            arg_choices += ['CHARFORMAT', 'MERGEFORMAT']  # always allowed
            if 'string' in sw_format:
                arg_choices += ['Caps', 'FirstCap', 'Lower', 'Upper']
            if 'numeric' in sw_format:
                arg_choices = []  # too many choices to list them here
        else:
            logger.debug(u'unexpected switch {0} in "{1}"'
                         .format(switch, contents))
            return False

    # if nothing went wrong sofar, the contents seems to match the blacklist
    return True


def process_xlsx(filepath):
    """ process an OOXML excel file (e.g. .xlsx or .xlsb or .xlsm) """
    dde_links = []
    parser = ooxml.XmlParser(filepath)
    for subfilename, elem, _ in parser.iter_xml():
        tag = elem.tag.lower()
        if tag == 'ddelink' or tag.endswith('}ddelink'):
            # we have found a dde link. Try to get more info about it
            link_info = []
            if 'ddeService' in elem.attrib:
                link_info.append(elem.attrib['ddeService'])
            if 'ddeTopic' in elem.attrib:
                link_info.append(elem.attrib['ddeTopic'])
            dde_links.append(u' '.join(link_info))
            logger.debug('Found tag "%s" in file %s: %s' % (tag, subfilename, repr(link_info)))

    # binary parts, e.g. contained in .xlsb
    for subfile, content_type, handle in parser.iter_non_xml():
        try:
            logger.info('Parsing non-xml subfile {0} with content type {1}'
                        .format(subfile, content_type))
            for record in xls_parser.parse_xlsb_part(handle, content_type,
                                                     subfile):
                logger.debug('{0}: {1}'.format(subfile, record))
                if isinstance(record, xls_parser.XlsbBeginSupBook) and \
                        record.link_type == \
                        xls_parser.XlsbBeginSupBook.LINK_TYPE_DDE:
                    dde_links.append(record.string1 + ' ' + record.string2)
        except Exception as exc:
            if content_type.startswith('application/vnd.ms-excel.') or \
               content_type.startswith('application/vnd.ms-office.'):  # pylint: disable=bad-indentation
                # should really be able to parse these either as xml or records
                log_func = logger.warning
            elif content_type.startswith('image/') or content_type == \
                    'application/vnd.openxmlformats-officedocument.' + \
                    'spreadsheetml.printerSettings':
                # understandable that these are not record-base
                log_func = logger.debug
            else:   # default
                log_func = logger.info
            log_func('Failed to parse {0} of content type {1} ("{2}")'
                     .format(subfile, content_type, str(exc)))
            # in any case: continue with next

    return u'\n'.join(dde_links)


class RtfFieldParser(rtfobj.RtfParser):
    """
    Specialized RTF parser to extract fields such as DDEAUTO
    """

    def __init__(self, data):
        super(RtfFieldParser, self).__init__(data)
        # list of RtfObjects found
        self.fields = []

    def open_destination(self, destination):
        if destination.cword == b'fldinst':
            logger.debug('*** Start field data at index %Xh'
                         % destination.start)

    def close_destination(self, destination):
        if destination.cword == b'fldinst':
            logger.debug('*** Close field data at index %Xh' % self.index)
            logger.debug('Field text: %r' % destination.data)
            # remove extra spaces and newline chars:
            field_clean = destination.data.translate(None, b'\r\n').strip()
            logger.debug('Cleaned Field text: %r' % field_clean)
            self.fields.append(field_clean)

    def control_symbol(self, matchobject):
        # required to handle control symbols such as '\\'
        # inject the symbol as-is in the text:
        # TODO: handle special symbols properly
        self.current_destination.data += matchobject.group()[1:2]


RTF_START = b'\x7b\x5c\x72\x74'   # == b'{\rt' but does not mess up auto-indent


def process_rtf(file_handle, field_filter_mode=None):
    """ find dde links or other fields in rtf file """
    all_fields = []
    data = RTF_START + file_handle.read()   # read complete file into memory!
    file_handle.close()
    rtfparser = RtfFieldParser(data)
    rtfparser.parse()
    all_fields = [field.decode('ascii') for field in rtfparser.fields]
    # apply field command filter
    logger.debug('found {1} fields, filtering with mode "{0}"'
                 .format(field_filter_mode, len(all_fields)))
    if field_filter_mode in (FIELD_FILTER_ALL, None):
        clean_fields = all_fields
    elif field_filter_mode == FIELD_FILTER_DDE:
        clean_fields = [field for field in all_fields
                        if FIELD_DDE_REGEX.match(field)]
    elif field_filter_mode == FIELD_FILTER_BLACKLIST:
        # check if fields are acceptable and should not be returned
        clean_fields = [field for field in all_fields
                        if not field_is_blacklisted(field.strip())]
    else:
        raise ValueError('Unexpected field_filter_mode: "{0}"'
                         .format(field_filter_mode))

    return u'\n'.join(clean_fields)


# threshold when to consider a csv file "small"; also used as sniffing size
CSV_SMALL_THRESH = 1024

# format of dde link: program-name | arguments ! unimportant
# can be enclosed in "", prefixed with + or = or - or cmds like @SUM(...)
CSV_DDE_FORMAT = re.compile(r'\s*"?[=+-@](.+)\|(.+)!(.*)\s*')

# allowed delimiters (python sniffer would use nearly any char). Taken from
# https://data-gov.tw.rpi.edu/wiki/CSV_files_use_delimiters_other_than_commas
CSV_DELIMITERS = ',\t ;|^'


def process_csv(filepath):
    """ find dde in csv text

    finds text parts like =cmd|'/k ..\\..\\..\\Windows\\System32\\calc.exe'! or
    =MSEXCEL|'\\..\\..\\..\\Windows\\System32\\regsvr32 [...]

    Hoping here that the :py:class:`csv.Sniffer` determines quote and delimiter
    chars the same way that excel does. Tested to some extend in unittests.

    This can only find DDE-links, no other "suspicious" constructs (yet).

    Cannot deal with unicode files yet (need more than just use uopen()).
    """
    results = []
    if sys.version_info.major <= 2:
        open_arg = dict(mode='rb')
    else:
        open_arg = dict(newline='')
    with open(filepath, **open_arg) as file_handle:
        # TODO: here we should not assume this is a file on disk, filepath can be a file object
        results, dialect = process_csv_dialect(file_handle, CSV_DELIMITERS)
        is_small = file_handle.tell() < CSV_SMALL_THRESH

        if is_small and not results:
            # easy to mis-sniff small files. Try different delimiters
            logger.debug('small file, no results; try all delimiters')
            file_handle.seek(0)
            other_delim = CSV_DELIMITERS.replace(dialect.delimiter, '')
            for delim in other_delim:
                try:
                    file_handle.seek(0)
                    results, _ = process_csv_dialect(file_handle, delim)
                except csv.Error:   # e.g. sniffing fails
                    logger.debug('failed to csv-parse with delimiter {0!r}'
                                 .format(delim))

        if is_small and not results:
            # try whole file as single cell, since sniffing fails in this case
            logger.debug('last attempt: take whole file as single unquoted '
                         'cell')
            file_handle.seek(0)
            match = CSV_DDE_FORMAT.match(file_handle.read(CSV_SMALL_THRESH))
            if match:
                results.append(u' '.join(match.groups()[:2]))

    return u'\n'.join(results)


def process_csv_dialect(file_handle, delimiters):
    """ helper for process_csv: process with a specific csv dialect """
    # determine dialect = delimiter chars, quote chars, ...
    dialect = csv.Sniffer().sniff(file_handle.read(CSV_SMALL_THRESH),
                                  delimiters=delimiters)
    dialect.strict = False     # microsoft is never strict
    logger.debug('sniffed csv dialect with delimiter {0!r} '
                 'and quote char {1!r}'
                 .format(dialect.delimiter, dialect.quotechar))

    # rewind file handle to start
    file_handle.seek(0)

    # loop over all csv rows and columns
    results = []
    reader = csv.reader(file_handle, dialect)
    for row in reader:
        for cell in row:
            # check if cell matches
            match = CSV_DDE_FORMAT.match(cell)
            if match:
                results.append(u' '.join(match.groups()[:2]))
    return results, dialect


#: format of dde formula in excel xml files
XML_DDE_FORMAT = CSV_DDE_FORMAT


def process_excel_xml(filepath):
    """ find dde links in xml files created with excel 2003 or excel 2007+

    TODO: did not manage to create dde-link in the 2007+-xml-format. Find out
          whether this is possible at all. If so, extend this function
    """
    dde_links = []
    parser = ooxml.XmlParser(filepath)
    for _, elem, _ in parser.iter_xml():
        tag = elem.tag.lower()
        if tag != 'cell' and not tag.endswith('}cell'):
            continue   # we are only interested in cells
        formula = None
        for key in elem.keys():
            if key.lower() == 'formula' or key.lower().endswith('}formula'):
                formula = elem.get(key)
                break
        if formula is None:
            continue
        logger.debug(u'found cell with formula {0}'.format(formula))
        match = re.match(XML_DDE_FORMAT, formula)
        if match:
            dde_links.append(u' '.join(match.groups()[:2]))
    return u'\n'.join(dde_links)


def process_file(filepath, field_filter_mode=None):
    """ decides which of the process_* functions to call """
    if olefile.isOleFile(filepath):
        logger.debug('Is OLE. Checking streams to see whether this is xls')
        if xls_parser.is_xls(filepath):
            logger.debug('Process file as excel 2003 (xls)')
            return process_xls(filepath)
        if is_ppt(filepath):
            logger.debug('is ppt - cannot have DDE')
            return u''
        logger.debug('Process file as word 2003 (doc)')
        with olefile.OleFileIO(filepath, path_encoding=None) as ole:
            return process_doc(ole)

    with open(filepath, 'rb') as file_handle:
        # TODO: here we should not assume this is a file on disk, filepath can be a file object
        if file_handle.read(4) == RTF_START:
            logger.debug('Process file as rtf')
            return process_rtf(file_handle, field_filter_mode)

    try:
        doctype = ooxml.get_type(filepath)
        logger.debug('Detected file type: {0}'.format(doctype))
    except Exception as exc:
        logger.debug('Exception trying to xml-parse file: {0}'.format(exc))
        doctype = None

    if doctype == ooxml.DOCTYPE_EXCEL:
        logger.debug('Process file as excel 2007+ (xlsx)')
        return process_xlsx(filepath)
    if doctype in (ooxml.DOCTYPE_EXCEL_XML, ooxml.DOCTYPE_EXCEL_XML2003):
        logger.debug('Process file as xml from excel 2003/2007+')
        return process_excel_xml(filepath)
    if doctype in (ooxml.DOCTYPE_WORD_XML, ooxml.DOCTYPE_WORD_XML2003):
        logger.debug('Process file as xml from word 2003/2007+')
        return process_docx(filepath)
    if doctype is None:
        logger.debug('Process file as csv')
        return process_csv(filepath)
    # could be docx; if not: this is the old default code path
    logger.debug('Process file as word 2007+ (docx)')
    return process_docx(filepath, field_filter_mode)


# === MAIN =================================================================


def process_maybe_encrypted(filepath, passwords=None, decrypted_dir=None, crypto_nesting=0,
                            **kwargs):
    """
    Process a file that might be encrypted.

    Calls :py:func:`process_file` and if that fails tries to decrypt and
    process the result. Based on recommendation in module doc string of
    :py:mod:`oletools.crypto`.

    :param str filepath: path to file on disc.
    :param passwords: list of passwords (str) to try for decryption or None
    :param decrypted_dir: folder to store the decrypted file in case you want
                               to preserve it
    :param int crypto_nesting: How many decryption layers were already used to
                               get the given file.
    :param kwargs: same as :py:func:`process_file`
    :returns: same as :py:func:`process_file`
    """
    # TODO: here filepath may also be a file in memory, it's not necessarily on disk
    result = u''
    try:
        result = process_file(filepath, **kwargs)
        if not crypto.is_encrypted(filepath):
            return result
    except Exception:
        logger.debug('Ignoring exception:', exc_info=True)
        if not crypto.is_encrypted(filepath):
            raise

    # we reach this point only if file is encrypted
    # check if this is an encrypted file in an encrypted file in an ...
    if crypto_nesting >= crypto.MAX_NESTING_DEPTH:
        raise crypto.MaxCryptoNestingReached(crypto_nesting, filepath)

    decrypted_file = None
    if passwords is None:
        passwords = crypto.DEFAULT_PASSWORDS
    else:
        passwords = list(passwords) + crypto.DEFAULT_PASSWORDS
    try:
        logger.debug('Trying to decrypt file')
        decrypted_file, correct_password = crypto.decrypt(filepath, passwords, decrypted_dir)
        if correct_password:
            logger.info(f"The correct password is: {correct_password}")
        if not decrypted_file:
            logger.error('Decrypt failed, run with debug output to get details')
            raise crypto.WrongEncryptionPassword(filepath)
        logger.info('Analyze decrypted file')
        result = process_maybe_encrypted(decrypted_file, passwords, decrypted_dir,
                                         crypto_nesting+1, **kwargs)
    finally:     # clean up
        try:     # (maybe file was not yet created)
            os.unlink(decrypted_file)
        except Exception:
            logger.debug('Ignoring exception closing decrypted file:',
                         exc_info=True)
    return result


def main(cmd_line_args=None):
    """ Main function, called if this file is called as a script

    Optional argument: command line arguments to be forwarded to ArgumentParser
    in process_args. Per default (cmd_line_args=None), sys.argv is used. Option
    mainly added for unit-testing
    """
    args = process_args(cmd_line_args)

    # Setup logging to the console:
    # here we use stdout instead of stderr by default, so that the output
    # can be redirected properly.
    log_helper.enable_logging(args.json, args.loglevel, stream=sys.stdout)

    if args.nounquote:
        global NO_QUOTES
        NO_QUOTES = True

    logger.print_str(BANNER)
    logger.print_str('Opening file: %s' % args.filepath)

    text = ''
    return_code = 1
    try:
        text = process_maybe_encrypted(
            args.filepath, args.password, args.decrypted_dir,
            field_filter_mode=args.field_filter_mode)
        return_code = 0
    except Exception as exc:
        logger.exception(str(exc))

    logger.print_str('DDE Links:')
    for link in text.splitlines():
        logger.print_str(text, type='dde-link')

    log_helper.end_logging()

    return return_code


if __name__ == '__main__':
    sys.exit(main())
