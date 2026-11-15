from __future__ import annotations

import io
import struct

import pytest

from dissect.etl import manifest
from dissect.etl.exceptions import InvalidManifestError

GUID = "{12345678-1234-1234-1234-123456789abc}"
NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events"'
NL = "&#10;"
SQ = "&#39;"
DQ = "&#34;"

# A payload that, if it were ever evaluated, would create a marker file. The
# tests assert this expression is rejected up front and the marker never exists.
PWN = "open('__MARKER__', 'w').write('pwned') or 0"


def _wrap(
    strings: str = "",
    keywords: str = "",
    templates: str = "",
    events: str = "",
    guid: str = GUID,
) -> str:
    return (
        f'<instrumentationManifest {NS}><instrumentation><events>'
        f'<provider name="P" guid="{guid}" symbol="S">'
        f"<keywords>{keywords}</keywords>"
        f"<templates>{templates}</templates>"
        f"<events>{events}</events>"
        f"</provider></events></instrumentation>"
        f"<localization><resources culture=\"en-US\"><stringTable>{strings}</stringTable>"
        f"</resources></localization></instrumentationManifest>"
    )


TEMPLATE = '<template tid="T1"><data name="f" inType="win:UInt32"/></template>'
EVENT = '<event value="1" version="0" symbol="E" template="T1"/>'
KEYWORD = '<keyword name="k" message="$(string.m1)" mask="0x1"/>'
STRING = '<string id="m1" value="v"/>'


@pytest.mark.parametrize(
    ("name", "xml"),
    [
        # Resource string id / value breaking out of the quoted dict literal.
        (
            "string_id",
            _wrap(strings=f'<string id="a{SQ},{NL}{PWN}{NL}#" value="v"/>'),
        ),
        (
            "string_value",
            _wrap(
                strings=f'<string id="m1" value="a{SQ},{NL}{PWN}{NL}#"/>',
                keywords=KEYWORD,
                templates=TEMPLATE,
                events=EVENT,
            ),
        ),
        # Keyword name / message reference.
        (
            "keyword_name",
            _wrap(
                strings=STRING,
                keywords=f'<keyword name="x{SQ},{NL}{PWN}{NL}#" message="$(string.m1)" mask="0x1"/>',
                templates=TEMPLATE,
                events=EVENT,
            ),
        ),
        (
            "keyword_message",
            _wrap(
                strings=STRING,
                keywords=f'<keyword name="k" message="$(string.{PWN})" mask="0x1"/>',
                templates=TEMPLATE,
                events=EVENT,
            ),
        ),
        # cstruct structural names: template id, field name, count expression.
        (
            "template_tid",
            _wrap(templates=f'<template tid="T1;{NL}{DQ * 3}{NL}{PWN}"></template>'),
        ),
        (
            "field_name",
            _wrap(
                templates=f'<template tid="T1"><data name="f;{NL}{DQ * 3}{NL}{PWN}" '
                f'inType="win:UInt32"/></template>'
            ),
        ),
        (
            "field_count",
            _wrap(
                templates=f'<template tid="T1"><data name="f" inType="win:UInt8" '
                f'max="1]{NL}{PWN}"/></template>'
            ),
        ),
        # Event symbol and template reference.
        (
            "event_symbol",
            _wrap(
                templates=TEMPLATE,
                events=f'<event value="1" version="0" symbol="a{SQ}),{NL}{PWN}{NL}#" template="T1"/>',
            ),
        ),
        (
            "event_template_ref",
            _wrap(
                templates=TEMPLATE,
                events=f'<event value="1" version="0" symbol="E" template="T1{NL}{PWN}{NL}#"/>',
            ),
        ),
        # Non-expression / unknown structural declarations.
        (
            "unknown_in_type",
            _wrap(templates='<template tid="T1"><data name="f" inType="win:Evil"/></template>'),
        ),
        (
            "non_numeric_mask",
            _wrap(
                strings=STRING,
                keywords=KEYWORD.replace("0x1", f"1+{PWN}"),
                templates=TEMPLATE,
                events=EVENT,
            ),
        ),
        ("bad_guid", _wrap(guid="not-a-guid")),
        (
            "dangling_message_ref",
            _wrap(strings='<string id="other" value="v"/>', keywords=KEYWORD, templates=TEMPLATE, events=EVENT),
        ),
        (
            "unknown_template_ref",
            _wrap(templates=TEMPLATE, events='<event value="1" version="0" symbol="E" template="Missing"/>'),
        ),
    ],
)
def test_malicious_manifest_rejected_before_execution(tmp_path, name, xml) -> None:
    marker = tmp_path / "marker.txt"
    xml = xml.replace("__MARKER__", str(marker))

    with pytest.raises(InvalidManifestError):
        manifest.compile_xml(GUID, xml)

    assert not marker.exists(), f"injection via {name} executed code"


@pytest.mark.parametrize(
    "expression",
    ["Count", "Count + 2", "0x4", "sizeof(uint32) * 2", "Count * 2 - 1"],
)
def test_legitimate_count_expressions_accepted(expression) -> None:
    xml = _wrap(
        templates='<template tid="T1"><data name="Count" inType="win:UInt32"/>'
        f'<data name="Arr" inType="win:UInt8" max="{expression}"/></template>',
        events='<event value="1" version="0" symbol="E" template="T1"/>',
    )
    module = manifest.compile_xml(GUID, xml)
    assert hasattr(module.c_parser, "T1")


def test_embedded_quote_is_data_not_code(tmp_path) -> None:
    marker = tmp_path / "marker.txt"
    xml = _wrap(
        strings='<string id="m1" value="it&#39;&#39; ok"/>',
        keywords=KEYWORD,
        templates=TEMPLATE,
        events=EVENT,
    )
    module = manifest.compile_xml(GUID, xml)
    assert module.STRINGS == {"m1": "it'' ok"}
    assert not marker.exists()


def test_legitimate_manifest_parses_event_values() -> None:
    xml = _wrap(
        strings='<string id="msg_kw" value="Hello world"/>',
        keywords='<keyword name="kw:One" message="$(string.msg_kw)" mask="0x1"/>',
        templates=(
            '<template tid="RichArgs">'
            '<data name="Count" inType="win:UInt32"/>'
            '<data name="Id" inType="win:UInt32"/>'
            '<data name="Flag" inType="win:Boolean"/>'
            '<data name="G" inType="win:GUID"/>'
            '<data name="Bytes" inType="win:UInt8" max="4"/>'
            '<data name="Name" inType="win:UnicodeString"/>'
            '<data name="Guids" inType="win:GUID" max="Count"/>'
            "</template>"
        ),
        events=(
            '<event value="10" version="0" symbol="Rich/Event" task="T" opcode="win:Info" '
            'level="win:Verbose" keywords="kw:One" template="RichArgs"/>'
        ),
    )
    module = manifest.compile_xml(GUID, xml)

    payload = struct.pack("<I", 2) + struct.pack("<I", 0xCAFE) + bytes([1]) + bytes(range(16))
    payload += bytes([10, 20, 30, 40]) + "alpha".encode("utf-16-le") + b"\x00\x00"
    payload += bytes(range(16)) + bytes(range(16, 32))

    record = module.c_parser.RichArgs(io.BytesIO(payload))
    values = record.__values__

    assert values["Count"] == 2
    assert values["Id"] == 0xCAFE
    assert values["Flag"] == 1
    assert values["G"] == bytes(range(16))
    assert list(values["Bytes"]) == [10, 20, 30, 40]
    assert values["Name"] == "alpha"
    # win:GUID with max=Count becomes char[16][Count]: Count*16 bytes exposed as
    # nested char items (identical layout to the original generator).
    assert b"".join(values["Guids"]) == bytes(range(32))
    assert len(values["Guids"]) == 16

    event = module.EVENTS[(10, 0)]
    assert event.symbol == "Rich/Event"
    assert module.KEYWORDS["kw:One"].message == "Hello world"


def test_numeric_template_id_normalized() -> None:
    xml = _wrap(
        templates='<template tid="0x10285ce6L"><data name="f" inType="win:UInt32"/></template>',
        events='<event value="1" version="0" symbol="E" template="0x10285ce6L"/>',
    )
    module = manifest.compile_xml(GUID, xml)
    assert hasattr(module.c_parser, "NULLx10285ce6L")
