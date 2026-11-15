#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2024 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
XML output encoding contract for forensic EVTX rendering.

The BinXML values parsed from an EVTX file are evidence and must not be
silently altered.  Some values cannot be represented directly in a well
formed XML document, however:

  - C0 control characters other than the XML whitespace set
    (``\\t``, ``\\n``, ``\\r``), and
  - lone UTF-16 surrogate code points (``U+D800`` .. ``U+DFFF``), which
    are never valid Unicode scalar values and therefore never legal XML
    characters (see https://www.w3.org/TR/xml/#charsets and
    https://www.w3.org/TR/xml11/#charsets).

Two explicit output modes are supported:

  - :data:`STRICT_MODE` (``"strict"``): the first offending value raises
    :class:`InvalidXmlCharacterError` carrying the field location, the
    reason, the offending code point and the unaltered original value.
    Nothing is deleted or rewritten.
  - :data:`DISPLAY_MODE` (``"display"``): a well formed, standard parser
    readable document is produced.  Each unrepresentable code point is
    replaced by a unique, self describing marker token, and every
    replacement is recorded in an anomaly ledger so that:

      * the display rendering can never be mistaken for, or flow back
        into, the original evidence (the markers are not legal BinXML
        data and the ledger keeps the raw value alongside), and
      * two different raw values can never collapse into an
        indistinguishable report: the marker carries the anomaly index
        and code point, and the ledger holds the raw value.

Ordinary XML markup characters (``&``, ``<``, ``>``, ``"``) are escaped
with their standard entities, and non-BMP characters (for example
emoji) are emitted as numeric character references and round trip
losslessly.
"""
from __future__ import absolute_import

import enum
import xml.sax.saxutils

STRICT_MODE = "strict"
DISPLAY_MODE = "display"

#: marker emitted in display mode; formatted with the anomaly index and
#: the hexadecimal code point of the unrepresentable character.
DISPLAY_MARKER = "EVTX-INVALID-CHAR-{index:04d}-U+{codepoint:04X}"

#: namespace used by the display mode anomaly ledger wrapper.
ANOMALIES_NAMESPACE = "http://schemas.mandiant.com/2024/evtx/display-anomalies"

# https://www.w3.org/TR/xml/#NT-Char
#   Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD]
#          | [#x10000-#x10FFFF]
_TAB = 0x9
_LINE_FEED = 0xA
_CARRIAGE_RETURN = 0xD
_SPACE = 0x20
_SURROGATE_START = 0xD800
_SURROGATE_END = 0xDFFF
_MAX_SCALAR = 0x10FFFF


class AnomalyReason(enum.Enum):
    """why a particular code point cannot be represented in XML."""

    CONTROL_CHARACTER = "control-character"
    LONE_SURROGATE = "lone-utf16-surrogate"


class InvalidXmlCharacterError(ValueError):
    """
    raised in strict mode when a value cannot be represented in XML.

    the original value is attached unchanged so callers can report on it
    without re-reading the record.
    """

    def __init__(self, field, reason, codepoint, original, offset=None):
        self.field = field
        self.reason = reason
        self.codepoint = codepoint
        self.original = original
        self.offset = offset
        super(InvalidXmlCharacterError, self).__init__(
            "invalid XML character U+{:04X} in {}: {} (original value {!r})".format(
                codepoint, field, reason.value, original
            )
        )


def classify_codepoint(codepoint):
    """
    decide whether a code point is legal in an XML 1.0 document.

    Args:
      codepoint (int): a Unicode code point (lone surrogates included).

    Returns:
      AnomalyReason: the reason the code point is not representable,
        or ``None`` when the code point is a legal XML character.
    """
    if _SURROGATE_START <= codepoint <= _SURROGATE_END:
        return AnomalyReason.LONE_SURROGATE
    if codepoint < _SPACE and codepoint not in (_TAB, _LINE_FEED, _CARRIAGE_RETURN):
        return AnomalyReason.CONTROL_CHARACTER
    if codepoint == 0xFFFE or codepoint == 0xFFFF or codepoint > _MAX_SCALAR:
        return AnomalyReason.CONTROL_CHARACTER
    return None


class Anomaly(object):
    """
    a single unrepresentable code point recorded during display rendering.

    Attributes:
      index (int): zero based position of the anomaly within the record.
      field (str): the BinXML field location (element text, attribute...).
      reason (AnomalyReason): why the code point is not representable.
      codepoint (int): the offending Unicode code point.
      original (str): the complete, unaltered value that contained it.
      offset (int|None): offset of the source node within the record,
        when available.
      marker (str): the token substituted for the code point in the
        display rendering.
    """

    def __init__(self, index, field, reason, codepoint, original, offset=None):
        self.index = index
        self.field = field
        self.reason = reason
        self.codepoint = codepoint
        self.original = original
        self.offset = offset
        self.marker = DISPLAY_MARKER.format(index=index, codepoint=codepoint)


class RenderContext(object):
    """
    carries the active output mode and, in display mode, the anomalies.

    A fresh context must be used per record so that anomaly indices and
    the ledger stay scoped to one record.
    """

    def __init__(self, mode=STRICT_MODE):
        if mode not in (STRICT_MODE, DISPLAY_MODE):
            raise ValueError("unsupported render mode: {!r}".format(mode))
        self.mode = mode
        self.anomalies = []

    def record_anomaly(self, field, reason, codepoint, original, offset=None):
        anomaly = Anomaly(len(self.anomalies), field, reason, codepoint, original, offset=offset)
        self.anomalies.append(anomaly)
        return anomaly


def _encode_invalid_chars(value, field, context, offset):
    """
    handle the code points that XML cannot express directly.

    legal characters (including the XML whitespace control characters)
    are returned untouched; nothing valid is ever rewritten or removed.
    """
    if context is None or context.mode == STRICT_MODE:
        for char in value:
            reason = classify_codepoint(ord(char))
            if reason is not None:
                raise InvalidXmlCharacterError(field, reason, ord(char), value, offset=offset)
        return value

    acc = []
    for char in value:
        codepoint = ord(char)
        reason = classify_codepoint(codepoint)
        if reason is None:
            acc.append(char)
        else:
            anomaly = context.record_anomaly(field, reason, codepoint, value, offset=offset)
            acc.append(anomaly.marker)
    return "".join(acc)


def _ascii_numeric_references(value):
    """
    encode every non-ASCII code point as a decimal numeric reference.

    numeric references are plain ASCII, so the resulting fragment is
    encoding independent and remains readable by any conforming XML
    parser; non-BMP characters round trip through the reference.
    """
    return value.encode("ascii", "xmlcharrefreplace").decode("ascii")


def encode_text(value, field, context=None, offset=None):
    """
    encode a BinXML value for an XML element text position.

    Args:
      value (str): the raw, unaltered BinXML value.
      field (str): description of the field, used in diagnostics.
      context (RenderContext|None): the active mode and anomaly ledger.
      offset (int|None): source node offset, used in diagnostics.

    Returns:
      str: the XML escaped, parser ready fragment.

    Raises:
      InvalidXmlCharacterError: in strict mode, when ``value`` contains
        a code point that XML cannot represent.
    """
    checked = _encode_invalid_chars(value, field, context, offset)
    escaped = xml.sax.saxutils.escape(checked)
    return _ascii_numeric_references(escaped)


def encode_attribute(value, field, context=None, offset=None):
    """
    encode a BinXML value for an XML attribute value position.

    unlike :func:`encode_text`, the quote character is escaped as well,
    because the rendered attributes are always double quoted.
    """
    checked = _encode_invalid_chars(value, field, context, offset)
    escaped = xml.sax.saxutils.escape(checked, {'"': "&quot;"})
    return _ascii_numeric_references(escaped)


def split_cdata(value):
    """
    split CDATA content on the ``]]>`` sequence so it stays well formed.

    the two adjacent CDATA sections reconstitute the original value when
    parsed, so no data is added or removed.
    """
    return value.replace("]]>", "]]]]><![CDATA[>")


def render_anomalies_ledger(anomalies, record_num=None):
    """
    render the display mode anomaly ledger as an XML fragment.

    every anomaly references its in-document marker and keeps the raw
    original value (base64 of the UTF-16LE bytes, the exact BinXML
    on-disk encoding), making the replacement reviewable and reversible
    against the untouched record bytes.
    """
    import base64

    acc = []
    acc.append('<evtx:Anomalies xmlns:evtx="{}"'.format(ANOMALIES_NAMESPACE))
    if record_num is not None:
        acc.append(' RecordNumber="{}"'.format(record_num))
    acc.append(">")
    for anomaly in anomalies:
        raw_utf16 = base64.b64encode(anomaly.original.encode("utf-16-le", "surrogatepass")).decode("ascii")
        acc.append(
            '<evtx:Anomaly Index="{index}" Field="{field}" Reason="{reason}" '
            'Codepoint="U+{codepoint:04X}" Marker="{marker}" '
            'OriginalUTF16LEBase64="{raw}"/>'.format(
                index=anomaly.index,
                field=encode_attribute(anomaly.field, "anomaly.field", None),
                reason=anomaly.reason.value,
                codepoint=anomaly.codepoint,
                marker=encode_attribute(anomaly.marker, "anomaly.marker", None),
                raw=raw_utf16,
            )
        )
    acc.append("</evtx:Anomalies>")
    return "".join(acc)
