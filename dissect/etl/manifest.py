from __future__ import annotations

import importlib
import importlib.resources
import re
import types
from collections import defaultdict
from pathlib import Path
from typing import BinaryIO
from uuid import UUID

from defusedxml import ElementTree
from dissect import cstruct
from dissect.cstruct.expression import ExpressionTokenizer

from dissect.etl.exceptions import InvalidManifestError, ManifestNotFoundError

MODPATH = "dissect.etl.manifests"

EVENTS_NS = "http://schemas.microsoft.com/win/2004/08/events"
_NS = f"{{{EVENTS_NS}}}"

# A cstruct / C identifier: the only shape that may be emitted as a structural
# name (struct, field, keyword, symbol, ...) in the generated parsing module.
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Message references are strictly of the form ``$(string.<id>)``. The id is a
# data literal (rendered quoted), so it may contain punctuation, but not quotes
# or control characters that could break out of the generated source.
MESSAGE_RE = re.compile(r"^\$\(string\.([^'\"\x00-\x1f]+)\)$")

# Sanitized replacement for the leading ``0x`` of numeric template ids, which are
# not valid cstruct identifiers as-is.
_HEX_PREFIX = "NULLx"

STRUCT_FMT = """
struct {name} {{
{fields}
}};
"""

CLASS_FMT = """
from uuid import UUID
from collections import namedtuple

from dissect import cstruct
from dissect.cstruct import BaseType, MetaType, Structure

Structure._calc_offsets = lambda _: None
Keyword = namedtuple('Keyword', ['name', 'message', 'mask'])
Task = namedtuple('Task', ['name', 'message', 'value'])
Event = namedtuple('Event', ['symbol', 'value', 'version', 'opcode', 'level', 'task', 'keywords', 'template'])


class VariableType(BaseType):
    type: MetaType
    size: int

    @classmethod
    def as_64bit(cls):
        raise NotImplementedError()

    @classmethod
    def as_32bit(cls):
        raise NotImplementedError()

    @classmethod
    def _read(cls, stream, context=None):
        return cls.type._read(stream, context)

    @classmethod
    def _read_0(cls, stream, context=None):
        return cls.type._read_0(stream, context)

    @classmethod
    def _write(cls, stream, data):
        return cls.type._write(stream, data)


class EtwPointer(VariableType):
    @classmethod
    def as_64bit(cls):
        if cls.size == 8:
            return
        cls.size = 8
        cls.type = cls.cs.uint64

    def as_32bit(cls):
        if cls.size == 4:
            return
        cls.size = 4
        cls.type = cls.cs.uint32


class UserSID_blob(VariableType):
    @classmethod
    def as_64bit(cls):
        if cls.size == 16:
            return
        cls.size = 16
        cls.type = cls.cs.char[16]

    @classmethod
    def as_32bit(cls):
        if cls.size == 8:
            return
        cls.size = 8
        cls.type = cls.cs.char[8]


PROVIDER_NAME = {provider_name!r}
PROVIDER_GUID = UUID({provider_guid!r})
PROVIDER_SYMBOL = {provider_symbol!r}

c_parser = cstruct.cstruct()
c_parser.add_custom_type("EtwPointer", EtwPointer)
c_parser.add_custom_type("UserSID_blob", UserSID_blob)
c_parser.load(\"\"\"
struct SYSTEMTIME {{
    WORD    wYear;
    WORD    wMonth;
    WORD    wDayOfWeek;
    WORD    wDay;
    WORD    wHour;
    WORD    wMinute;
    WORD    wSecond;
    WORD    wMilliseconds;
}};

struct UserSID {{
    uint8 revision;
    uint8 subAuthorityCount;
    char authority[6];
    uint32 subAuthorities[subAuthorityCount];
}};

struct SID {{
    UserSID_blob    blob;
    UserSID         sid;
}};

{templates}
\"\"\")

STRINGS = {{
{strings}
}}

KEYWORDS = {{
{keywords}
}}

EVENTS = {{
{events}
}}
"""

FIELD_MAP = {
    "Boolean": "uint8",
    "GUID": "char",
    "IPAddrV4": "uint32",
    "IPAddrV6": "char",
    "Pointer": "EtwPointer",
    "SInt8": "int8",
    "SInt16": "int16",
    "SInt32": "int32",
    "SInt64": "int64",
    "SizeT": "uint32",
    "Struct": "KAPUT",
    "String": "char",
    "SYSTEMTIME": "SYSTEMTIME",
    "SID": "SID",
    "WString": "wchar",
    "UnicodeString": "wchar",
}

# Types whose cstruct declaration always carries a fixed-size array suffix.
FIXED_SIZES = {
    "GUID": 16,
    "IPAddrV6": 16,
}

# Types whose cstruct declaration is an open-ended (null-terminated) array.
OPEN_ENDED_TYPES = {
    "String",
    "WString",
    "UnicodeString",
}

CACHE: dict[UUID, types.ModuleType] = {}

c_parser = cstruct.cstruct()


def _fail(kind: str, value: object, detail: str = "") -> None:
    """Reject a manifest value before it can reach the generated source code."""
    rendered = repr(value)
    if len(rendered) > 80:
        rendered = rendered[:77] + "..."
    message = f"Unsafe {kind} in ETW manifest: {rendered}"
    if detail:
        message = f"{message} ({detail})"
    raise InvalidManifestError(message)


def _identifier(value: str, kind: str) -> str:
    """Validate that ``value`` is a structural identifier safe to emit as code.

    Anything that is not a strict ``[A-Za-z_][A-Za-z0-9_]*`` token (quotes,
    punctuation, newlines, ...) is rejected rather than sanitized, so it can
    never break out of the generated cstruct/Python context. This is only used
    for values that become structural names (structs, cstruct fields).
    """
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        _fail(kind, value, "expected an identifier matching [A-Za-z_][A-Za-z0-9_]*")
    return value


def _data_string(value: object, kind: str) -> str:
    """Validate a value that is emitted purely as a quoted Python data literal.

    Such values (string ids, keyword names, event symbols) are never evaluated
    or used as cstruct identifiers, so they may contain punctuation. They are
    rendered with :func:`repr`, which fully escapes the contents; the only hard
    requirement is that they are finite strings without control characters that
    could smuggle a line break into the generated source.
    """
    if not isinstance(value, str):
        _fail(kind, value, "expected a string")
    if any(ord(ch) < 0x20 for ch in value):
        _fail(kind, value, "control characters are not allowed")
    return value


def _integer(value: str, kind: str) -> int:
    """Parse a manifest integer literal, rejecting arbitrary expressions."""
    if not isinstance(value, str):
        _fail(kind, value, "expected an integer literal")
    text = value.strip()
    try:
        return int(text, 0)
    except ValueError:
        _fail(kind, value, "expected an integer literal")


def _count_expression(value: str, kind: str) -> str:
    """Validate an array-count expression against cstruct's arithmetic grammar.

    cstruct evaluates counts with a tokenizer-based expression parser (no
    ``eval``). Re-tokenizing here guarantees the value only contains the
    numbers, identifiers and arithmetic operators that grammar understands,
    which cannot express calls, imports or attribute access.
    """
    if not isinstance(value, str) or not value:
        _fail(kind, value, "expected a count expression")
    try:
        ExpressionTokenizer(value).tokenize()
    except Exception as exc:
        _fail(kind, value, str(exc))
    return value


def _message_reference(value: str, string_ids: set[str], kind: str) -> str:
    """Validate a ``$(string.<id>)`` reference and resolve it to a known id."""
    if not isinstance(value, str):
        _fail(kind, value, "expected a $(string.<id>) reference")
    match = MESSAGE_RE.fullmatch(value)
    if not match:
        _fail(kind, value, "expected a $(string.<id>) reference")
    message_id = _data_string(match.group(1), kind)
    if message_id not in string_ids:
        _fail(kind, value, f"references unknown string id {message_id!r}")
    return message_id


def _template_name(value: str, kind: str = "template id") -> str:
    """Normalize a numeric template id, otherwise require a valid identifier."""
    if not isinstance(value, str) or not value:
        _fail(kind, value, "expected a template id")
    if value.startswith("0x"):
        normalized = _HEX_PREFIX + value[2:]
        return _identifier(normalized, kind)
    return _identifier(value, kind)


def _field_type(in_type: str) -> tuple[str, str]:
    """Resolve a manifest ``win:<Type>`` into a cstruct type and its type name.

    Returns the cstruct type expression together with the bare manifest type
    name, which the caller uses to apply the correct array suffix.
    """
    prefix, sep, type_name = in_type.partition(":")
    if not sep or prefix != "win":
        _fail("field inType", in_type, "expected a win:<Type> value")

    if type_name.lower() in c_parser.typedefs:
        return type_name.lower(), type_name
    if type_name not in FIELD_MAP:
        _fail("field inType", in_type, f"unsupported field type {type_name!r}")
    return FIELD_MAP[type_name], type_name


def lookup(guid: UUID) -> types.ModuleType:
    global CACHE

    try:
        return CACHE[guid]
    except KeyError:
        pass

    try:
        mod = importlib.import_module(f"{MODPATH}.{{{guid}}}")
    except ImportError:
        pass
    else:
        CACHE[guid] = mod
        return mod

    try:
        mod = compile_xml(guid, get_resource_string(f"manifests/xml/{{{guid}}}.xml"))
    except IOError:
        pass
    else:
        CACHE[guid] = mod
        return mod

    raise ManifestNotFoundError(guid)


def compile_file(guid: UUID, path: str) -> types.ModuleType:
    return compile_xml(guid, Path(path).read_text())


def compile_xml(guid: UUID, s: str) -> types.ModuleType:
    generated = generate_from_xml(s)
    # print generated
    code = compile(generated, f"<manifest {guid}>", "exec")
    module = types.ModuleType(str(guid))
    exec(code, module.__dict__)
    return module


def generate_from_file(path: str) -> str:
    return generate_from_xml(Path(path).read_text())


def generate_from_xml(s: str) -> str:
    e = ElementTree.fromstring(s)

    # The string table is collected first because keyword message references
    # must resolve to one of these ids.
    string_ids = set()
    strings = []
    for string in e.iter(f"{_NS}string"):
        string_id = _data_string(string.attrib.get("id", ""), "string id")
        string_value = string.attrib.get("value", "")
        if not isinstance(string_value, str):
            _fail("string value", string_value)
        _data_string(string_value, "string value")
        string_ids.add(string_id)
        # repr() renders the value as a quoted, fully escaped Python literal,
        # so its contents can never terminate the surrounding dict entry.
        strings.append(f"    {string_id!r}: {string_value!r},")

    keywords = []
    for keyword in e.iter(f"{_NS}keyword"):
        attr = keyword.attrib
        name = _data_string(attr.get("name", ""), "keyword name")
        message_id = _message_reference(attr.get("message", ""), string_ids, "keyword message")
        mask = _integer(attr.get("mask", ""), "keyword mask")
        keywords.append(
            f"    {name!r}: Keyword({name!r}, STRINGS[{message_id!r}], {mask!r}),"
        )

    template_names = set()
    templates = []
    for template in e.iter(f"{_NS}template"):
        sname = _template_name(template.attrib.get("tid", ""))
        if sname in template_names:
            _fail("template id", template.attrib.get("tid", ""), "duplicate template id")
        template_names.add(sname)

        fields = []
        for field in template:
            fattr = field.attrib
            fname = _identifier(fattr.get("name", ""), "field name")
            ctype, type_name = _field_type(fattr.get("inType", ""))

            line = f"{ctype} {fname}"
            # Fixed-size types (e.g. GUID -> char[16]) keep their size even when
            # a count is supplied, reproducing the original nested array shape.
            if type_name in FIXED_SIZES:
                line = f"{line}[{FIXED_SIZES[type_name]}]"
            if "max" in fattr:
                count = _count_expression(fattr["max"], "field count")
                line = f"{line}[{count}]"
            elif type_name in OPEN_ENDED_TYPES:
                line = f"{line}[]"

            fields.append(line)

        templates.append(
            STRUCT_FMT.format(
                name=sname,
                fields="\n".join([f"    {field};" for field in fields]),
            )
        )

    events = []
    for event in e.iter(f"{_NS}event"):
        attr = defaultdict(lambda: None)
        attr.update(event.attrib)

        template_ref = attr["template"]
        if not template_ref:
            continue

        template_name = _template_name(template_ref, "event template reference")
        if template_name not in template_names:
            _fail("event template reference", template_ref, "references unknown template")

        symbol = _data_string(attr.get("symbol") or "", "event symbol")
        value = _integer(attr.get("value", ""), "event value")
        version = _integer(attr.get("version", ""), "event version")
        # opcode/level/task/keywords are emitted as opaque data literals only.
        opcode = attr["opcode"]
        level = attr["level"]
        task = attr["task"]
        keyword = attr["keyword"]

        events.append(
            f"    ({value!r}, {version!r}): Event({symbol!r}, {value!r}, {version!r}, "
            f"{opcode!r}, {level!r}, {task!r}, {keyword!r}, c_parser.{template_name}),"
        )

    provider = next(e.iter(f"{_NS}provider"))
    provider_name = provider.attrib.get("name", "")
    provider_guid = provider.attrib.get("guid", "")
    try:
        # Validate the guid up front so a bad value is rejected before code
        # generation instead of surfacing as a runtime error in the module.
        UUID(provider_guid)
    except (ValueError, AttributeError, TypeError):
        _fail("provider guid", provider_guid, "expected a GUID string")
    provider_symbol = provider.attrib.get("symbol")
    if provider_symbol is not None:
        _data_string(provider_symbol, "provider symbol")

    return CLASS_FMT.format(
        provider_name=provider_name,
        provider_guid=provider_guid,
        provider_symbol=provider_symbol,
        templates="\n".join(templates),
        strings="\n".join(strings),
        keywords="\n".join(keywords),
        events="\n".join(events),
    )


def get_resource_string(path: str) -> str:
    return _get_resource_path(path).read_text()


def get_resource_stream(path: str) -> BinaryIO:
    return _get_resource_path(path).open("rb")


def _get_resource_path(path: str) -> Path:
    root = importlib.resources.files(__package__) if __package__ else Path(__file__).parent
    fpath = root.joinpath(path)

    if not fpath.exists():
        raise IOError(f"Can't find resource {path}")

    return fpath
