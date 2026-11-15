#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
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
from __future__ import absolute_import

import re

import Evtx.Nodes as e_nodes
import Evtx.XmlEncoding as e_xml

XML_HEADER = '<?xml version="1.1" encoding="utf-8" standalone="yes" ?>\n'


class UnexpectedElementException(Exception):
    def __init__(self, msg):
        super(UnexpectedElementException, self).__init__(msg)


# ref: https://www.w3.org/TR/xml11/#charsets
# retained for compatibility; classification now lives in Evtx.XmlEncoding.
RESTRICTED_CHARS = re.compile("[\x01-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]")


def escape_attr(s):
    """
    escape the given string such that it can be placed in an XML attribute, like:

        <foo bar='$value'>

    this is the strict contract: values containing characters that XML
    cannot represent raise InvalidXmlCharacterError instead of being
    silently deleted.

    Args:
      s (str): the string to escape.

    Returns:
      str: the escaped string.
    """
    return e_xml.encode_attribute(s, field="attribute")


def escape_value(s):
    """
    escape the given string such that it can be placed in an XML value location, like:

        <foo>
          $value
        </foo>

    this is the strict contract: values containing characters that XML
    cannot represent raise InvalidXmlCharacterError instead of being
    silently deleted.

    Args:
      s (str): the string to escape.

    Returns:
      str: the escaped string.
    """
    return e_xml.encode_text(s, field="text")


# ref: https://www.w3.org/TR/xml/#NT-NameStartChar
# but we are going to require a even stricter subset.
NAME_PATTERN = re.compile(r"[a-zA-Z_][a-zA-Z_\-]*")


def validate_name(s):
    """
    ensure the given name can be used as an XML entity name, such as tag or attribute name.

    Args:
      s (str): the string to validate.

    Raises:
      RuntimeError: if the string is not suitable to be an XML name.
    """
    if not NAME_PATTERN.match(s):
        raise RuntimeError("invalid xml name: %s" % (s))
    return s


def render_root_node_with_subs(root_node, subs, context=None):
    """
    render the given root node using the given substitutions into XML.

    Args:
      root_node (e_nodes.RootNode): the node to render.
      subs (list[str]): the substitutions that maybe included in the XML.
      context (e_xml.RenderContext|None): strict/display mode plus the
        anomaly ledger used in display mode.

    Returns:
      str: the rendered XML document.
    """

    def text(value, field, node=None):
        offset = node.offset() if node is not None and hasattr(node, "offset") else None
        return e_xml.encode_text(value, field, context, offset)

    def attr(value, field, node=None):
        offset = node.offset() if node is not None and hasattr(node, "offset") else None
        return e_xml.encode_attribute(value, field, context, offset)

    def rec(node, acc, field_path, as_attribute=False):
        if isinstance(node, e_nodes.EndOfStreamNode):
            pass  # intended
        elif isinstance(node, e_nodes.OpenStartElementNode):
            tag = validate_name(node.tag_name())
            acc.append("<")
            acc.append(tag)
            for child in node.children():
                if isinstance(child, e_nodes.AttributeNode):
                    name = validate_name(child.attribute_name().string())
                    acc.append(" ")
                    acc.append(name)
                    acc.append('="')
                    rec(child.attribute_value(), acc, "{}.@{}".format(field_path, name), as_attribute=True)
                    acc.append('"')
            acc.append(">")
            for child in node.children():
                rec(child, acc, field_path + "/" + tag)
            acc.append("</")
            acc.append(tag)
            acc.append(">\n")
        elif isinstance(node, e_nodes.CloseStartElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.ValueNode):
            variant = node.children()[0]
            value = variant.string()
            field = field_path + ("/@attr" if as_attribute else "/text")
            if as_attribute:
                acc.append(attr(value, field, variant))
            else:
                acc.append(text(value, field, variant))
        elif isinstance(node, e_nodes.AttributeNode):
            pass  # intended
        elif isinstance(node, e_nodes.CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(e_xml.split_cdata(text(node.cdata(), field_path + "/cdata", node)))
            acc.append("]]>")
        elif isinstance(node, e_nodes.CharacterReferenceNode):
            acc.append(node.entity_reference())
        elif isinstance(node, e_nodes.EntityReferenceNode):
            acc.append(text(node.entity_reference(), field_path + "/entity", node))
        elif isinstance(node, e_nodes.ProcessingInstructionTargetNode):
            acc.append(text(node.processing_instruction_target(), field_path + "/pi-target", node))
        elif isinstance(node, e_nodes.ProcessingInstructionDataNode):
            acc.append(text(node.string(), field_path + "/pi-data", node))
        elif isinstance(node, e_nodes.TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, (e_nodes.NormalSubstitutionNode, e_nodes.ConditionalSubstitutionNode)):
            sub = subs[node.index()]
            kind = node.__class__.__name__
            sub_field = "{}[{} index={} type={}]".format(field_path, kind, node.index(), node.type())

            if isinstance(sub, e_nodes.BXmlTypeNode):
                sub = render_root_node(sub.root(), context=context)
            elif as_attribute:
                sub = attr(sub.string(), sub_field, sub)
            else:
                sub = text(sub.string(), sub_field, sub)

            acc.append(sub)
        elif isinstance(node, e_nodes.StreamStartNode):
            pass  # intended
        else:
            raise UnexpectedElementException(node.__class__.__name__)

    acc = []
    for c in root_node.template().children():
        rec(c, acc, "root")
    return "".join(acc)


def render_root_node(root_node, context=None):
    subs = []
    for sub in root_node.substitutions():
        if isinstance(sub, str):
            raise RuntimeError("string sub?")

        if sub is None:
            raise RuntimeError("null sub?")

        subs.append(sub)

    return render_root_node_with_subs(root_node, subs, context=context)


def evtx_record_xml_view(record, cache=None, mode=e_xml.STRICT_MODE, context=None):
    """
    render the given record into an XML document.

    in strict mode (the default), values containing characters that XML
    cannot represent raise InvalidXmlCharacterError; no character is
    ever silently deleted.  in display mode, pass
    ``mode=e_xml.DISPLAY_MODE`` (or a prebuilt :class:`RenderContext`)
    to get a parser readable rendering plus a per-record anomaly ledger;
    see :func:`evtx_record_xml_display_view`.

    Args:
      record (Evtx.Record): the record to render.
      cache: unused, kept for backwards compatibility.
      mode (str): STRICT_MODE or DISPLAY_MODE.
      context (e_xml.RenderContext|None): an explicit context, which
        overrides ``mode``.

    Returns:
      str: the rendered XML document.
    """
    if context is None:
        context = e_xml.RenderContext(mode)
    return render_root_node(record.root(), context=context)


def evtx_record_xml_display_view(record, cache=None, context=None):
    """
    render the given record into a parser readable display document.

    unrepresentable characters are replaced by unique marker tokens and
    recorded in an anomaly ledger that retains the raw UTF-16LE bytes.
    the returned document is a single root element wrapping the rendered
    event and its ledger, so standard XML parsers accept it while the
    display rendering can never be confused with the original evidence.

    Args:
      record (Evtx.Record): the record to render.
      cache: unused, kept for symmetry with evtx_record_xml_view.
      context (e_xml.RenderContext|None): an existing display context.

    Returns:
      str: the rendered XML document, wrapped in an anomaly envelope.
    """
    if context is None:
        context = e_xml.RenderContext(e_xml.DISPLAY_MODE)
    elif context.mode != e_xml.DISPLAY_MODE:
        raise ValueError("evtx_record_xml_display_view requires a display mode context")

    event_xml = render_root_node(record.root(), context=context)
    ledger = e_xml.render_anomalies_ledger(context.anomalies, record_num=record.record_num())
    return (
        '<evtx:DisplayRecord xmlns:evtx="{ns}" RecordNumber="{num}">'
        "<evtx:AnomaliesSummary>{count}</evtx:AnomaliesSummary>"
        "{ledger}"
        "<evtx:Event>{event}</evtx:Event>"
        "</evtx:DisplayRecord>"
    ).format(
        ns=e_xml.ANOMALIES_NAMESPACE,
        num=record.record_num(),
        count=len(context.anomalies),
        ledger=ledger,
        event=event_xml,
    )


def evtx_chunk_xml_view(chunk, mode=e_xml.STRICT_MODE):
    """
    Generate XML representations of the records in an EVTX chunk.

    Does not include the XML <?xml... header.
    Records are ordered by chunk.records()

    Args:
      chunk (Evtx.Chunk): the chunk to render.
      mode (str): STRICT_MODE or DISPLAY_MODE.

    Yields:
      tuple[str, Evtx.Record]: the rendered XML document and the raw record.
    """
    for record in chunk.records():
        if mode == e_xml.DISPLAY_MODE:
            record_str = evtx_record_xml_display_view(record)
        else:
            record_str = evtx_record_xml_view(record)
        yield record_str, record


def evtx_file_xml_view(file_header, mode=e_xml.STRICT_MODE):
    """
    Generate XML representations of the records in an EVTX file.

    Does not include the XML <?xml... header.
    Records are ordered by file_header.chunks(), and then by chunk.records()

    Args:
      file_header (Evtx.FileHeader): the file header to render.
      mode (str): STRICT_MODE or DISPLAY_MODE.

    Yields:
      tuple[str, Evtx.Record]: the rendered XML document and the raw record.
    """
    for chunk in file_header.chunks():
        for record_str, record in evtx_chunk_xml_view(chunk, mode=mode):
            yield record_str, record


def evtx_template_readable_view(root_node, cache=None):
    def rec(node, acc):
        if isinstance(node, e_nodes.EndOfStreamNode):
            pass  # intended
        elif isinstance(node, e_nodes.OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, e_nodes.AttributeNode):
                    acc.append(" ")
                    acc.append(child.attribute_name().string())
                    acc.append('="')
                    rec(child.attribute_value(), acc)
                    acc.append('"')
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(node.tag_name())
            acc.append(">\n")
        elif isinstance(node, e_nodes.CloseStartElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.ValueNode):
            acc.append(node.children()[0].string())
        elif isinstance(node, e_nodes.AttributeNode):
            pass  # intended
        elif isinstance(node, e_nodes.CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(node.cdata())
            acc.append("]]>")
        elif isinstance(node, e_nodes.EntityReferenceNode):
            acc.append(node.entity_reference())
        elif isinstance(node, e_nodes.ProcessingInstructionTargetNode):
            acc.append(node.processing_instruction_target())
        elif isinstance(node, e_nodes.ProcessingInstructionDataNode):
            acc.append(node.string())
        elif isinstance(node, e_nodes.TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, e_nodes.NormalSubstitutionNode):
            acc.append("[Normal Substitution(index={}, type={})]".format(node.index(), node.type()))
        elif isinstance(node, e_nodes.ConditionalSubstitutionNode):
            acc.append("[Conditional Substitution(index={}, type={})]".format(node.index(), node.type()))
        elif isinstance(node, e_nodes.StreamStartNode):
            pass  # intended

    acc = []
    for c in root_node.template().children():
        rec(c, acc)
    return "".join(acc)
