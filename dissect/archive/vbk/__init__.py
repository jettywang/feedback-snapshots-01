from __future__ import annotations

from dissect.archive.exception import Error, FileNotFoundError, IsADirectoryError, NotADirectoryError
from dissect.archive.vbk.trace import (
    ByteRange,
    ChainBreakpoint,
    ChainFault,
    PageAddress,
    PageOwnership,
    PageSource,
    TracedMetaBlob,
    TracedPropertiesDictionary,
    TracedProperty,
)
from dissect.archive.vbk.vbk import VBK, DirItem, MetaBlob, SnapshotSlot, VBKError

__all__ = [
    "ByteRange",
    "ChainBreakpoint",
    "ChainFault",
    "DirItem",
    "Error",
    "FileNotFoundError",
    "IsADirectoryError",
    "MetaBlob",
    "NotADirectoryError",
    "PageAddress",
    "PageOwnership",
    "PageSource",
    "SnapshotSlot",
    "TracedMetaBlob",
    "TracedPropertiesDictionary",
    "TracedProperty",
    "VBK",
    "VBKError",
]
