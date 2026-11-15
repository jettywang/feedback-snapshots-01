"""
olefile (formerly OleFileIO_PL)

Module to read/write Microsoft OLE2 files (also called Structured Storage or
Microsoft Compound Document File Format), such as Microsoft Office 97-2003
documents, Image Composer and FlashPix files, Outlook messages, ...
This version is compatible with Python 2.7 and 3.5+

Project website: https://www.decalage.info/olefile

olefile is copyright (c) 2005-2023 Philippe Lagadec (https://www.decalage.info)

olefile is based on the OleFileIO module from the PIL library v1.1.7
See: http://www.pythonware.com/products/pil/index.htm
and http://svn.effbot.org/public/tags/pil-1.1.7/PIL/OleFileIO.py

The Python Imaging Library (PIL) is
    Copyright (c) 1997-2009 by Secret Labs AB
    Copyright (c) 1995-2009 by Fredrik Lundh

See source code and LICENSE.txt for information on usage and redistribution.
"""

from .olefile import *
# import metadata not covered by *:
from .olefile import __version__, __author__, __date__, __all__ as _olefile_all

# Read-only OLENativeStream (Ole10Native) support, see olefile/ole_native.py
from .ole_native import (
    OLE10NATIVE_STREAM_NAME,
    OLE10NATIVE_FORMAT_LINKED,
    OLE10NATIVE_FORMAT_EMBEDDED,
    OLE10NATIVE_PACKAGE_CLSID,
    Ole10Native,
    Ole10NativeStream,
    OleNativeStream,
    Ole10NativeIssue,
    OleNative,
    parse_ole10native,
    parse_ole10native_dict,
    parse_ole10native_stream,
    open_ole10native,
    find_ole10native_streams,
    iter_ole10native,
)

__all__ = list(_olefile_all) + [
    'OLE10NATIVE_STREAM_NAME',
    'OLE10NATIVE_FORMAT_LINKED',
    'OLE10NATIVE_FORMAT_EMBEDDED',
    'OLE10NATIVE_PACKAGE_CLSID',
    'Ole10Native',
    'Ole10NativeStream',
    'OleNativeStream',
    'Ole10NativeIssue',
    'OleNative',
    'parse_ole10native',
    'parse_ole10native_dict',
    'parse_ole10native_stream',
    'open_ole10native',
    'find_ole10native_streams',
    'iter_ole10native',
]


