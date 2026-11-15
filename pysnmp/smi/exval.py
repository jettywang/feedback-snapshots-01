#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
from pysnmp.proto import rfc1905

noSuchObject = rfc1905.noSuchObject  # noqa: N816
noSuchInstance = rfc1905.noSuchInstance  # noqa: N816
endOfMibView = endOfMib = rfc1905.endOfMibView  # noqa: N816


def is_mib_exception_value(value):
    """Return True for SNMPv2 SMI exception values (endOfMibView etc.)."""
    tagSet = getattr(value, "tagSet", None)  # noqa: N816
    return tagSet in (
        rfc1905.endOfMibView.tagSet,
        rfc1905.noSuchObject.tagSet,
        rfc1905.noSuchInstance.tagSet,
    )
