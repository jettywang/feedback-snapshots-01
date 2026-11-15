from __future__ import annotations

import struct
from textwrap import dedent
from unittest.mock import Mock
from uuid import UUID

import pytest

from dissect.etl import manifest
from dissect.etl.etl import Event, parse_payload
from dissect.etl.headers.utils import select_event_header
from dissect.etl.mapping import (
    BIT_MAP,
    VALUE_MAP,
    MapDefinition,
    MapEntry,
    MappedValue,
    normalize_value,
)

PROVIDER_A = UUID("11111111-1111-1111-1111-111111111111")
PROVIDER_B = UUID("22222222-2222-2222-2222-222222222222")


def make_manifest(
    guid: UUID,
    name: str,
    maps: str,
    templates: str,
    events: str,
    strings: str = "",
) -> str:
    return dedent(
        f"""\
        <instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
         <instrumentation xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events">
          <events>
           <provider name="{name}" guid="{{{guid}}}" symbol="{name.replace("-", "")}">
            <maps>
        {maps}
            </maps>
            <events>
        {events}
            </events>
            <templates>
        {templates}
            </templates>
            <strings>
        {strings}
            </strings>
           </provider>
          </events>
         </instrumentation>
        </instrumentationManifest>
        """
    )


def compile_manifest(guid: UUID, text: str) -> object:
    return manifest.compile_xml(guid, text)


def event_header_record(
    provider: UUID,
    *,
    event_id: int = 1,
    version: int = 0,
    opcode: int | None = None,
    payload: bytes = b"",
) -> bytes:
    """Build a synthetic manifest-based EventHeader with one payload field."""
    size = 0x50 + len(payload)
    header = struct.pack(
        "<HHHHIIQ",
        size,
        0xC000 | 0x13,
        0,
        0,
        0x414,
        0x2E8,
        0x1234,
    )
    header += provider.bytes
    header += struct.pack(
        "<HBBBBHQQ",
        event_id,
        version,
        0,
        0,
        event_id if opcode is None else opcode,
        0,
        0,
        0,
    )
    header += bytes(16)
    return header + payload


MAPS_TWO_PROVIDERS_A = """
    <valueMap name="SharedMap">
     <map value="0x1" message="$(string.AShared)"/>
     <map value="0x2" message="$(string.MissingA)"/>
     <map value="0x4" message="$(string.OnlyB)"/>
    </valueMap>
    <bitMap name="FlagsMap">
     <map value="0x0" message="$(string.NoFlags)"/>
     <map value="0x1" message="$(string.FlagOne)"/>
     <map value="0x4" message="$(string.FlagFour)"/>
     <map value="0x20" message="$(string.FlagTwenty)"/>
    </bitMap>
    <valueMap name="AliasMap">
     <map value="0x1" message="$(string.AliasFirst)"/>
     <map value="0x1" message="$(string.AliasSecond)"/>
    </valueMap>
"""

MAPS_TWO_PROVIDERS_B = """
    <valueMap name="SharedMap">
     <map value="0x1" message="$(string.BShared)"/>
     <map value="0x4" message="$(string.OnlyB)"/>
    </valueMap>
    <bitMap name="FlagsMap">
     <map value="0x2" message="$(string.BTwoFlag)"/>
     <map value="0x80" message="$(string.BHigh)"/>
    </bitMap>
"""

TEMPLATES_A = """
     <template tid="MappedArgs">
      <data name="Shared" inType="win:UInt32" map="SharedMap"/>
      <data name="Flags" inType="win:UInt8" map="FlagsMap"/>
      <data name="SignedFlags" inType="win:Int8" map="FlagsMap"/>
     </template>
     <template tid="AliasArgs">
      <data name="Alias" inType="win:UInt32" map="AliasMap"/>
     </template>
"""

TEMPLATES_B = """
     <template tid="MappedArgs">
      <data name="Shared" inType="win:UInt32" map="SharedMap"/>
      <data name="Flags" inType="win:UInt8" map="FlagsMap"/>
     </template>
"""

EVENTS_A = """
     <event value="1" symbol="MappedEvent" version="0" level="win:Informational" template="MappedArgs"/>
     <event value="2" symbol="AliasEvent" version="0" level="win:Informational" template="AliasArgs"/>
"""

EVENTS_B = """
     <event value="1" symbol="MappedEvent" version="0" level="win:Informational" template="MappedArgs"/>
"""

STRINGS_A = """
     <string id="AShared" value="A-One"/>
     <string id="NoFlags" value="None"/>
     <string id="FlagOne" value="First"/>
     <string id="FlagFour" value="Fourth"/>
     <string id="FlagTwenty" value="Twenty"/>
     <string id="AliasFirst" value="First alias"/>
     <string id="AliasSecond" value="Second alias"/>
"""

STRINGS_B = """
     <string id="BShared" value="B-One"/>
     <string id="OnlyB" value="B-only resource"/>
     <string id="BTwoFlag" value="B second flag"/>
     <string id="BHigh" value="B high flag"/>
"""


@pytest.fixture(scope="module")
def manifest_a() -> object:
    text = make_manifest(PROVIDER_A, "Provider-A", MAPS_TWO_PROVIDERS_A, TEMPLATES_A, EVENTS_A, STRINGS_A)
    return compile_manifest(PROVIDER_A, text)


@pytest.fixture(scope="module")
def manifest_b() -> object:
    text = make_manifest(PROVIDER_B, "Provider-B", MAPS_TWO_PROVIDERS_B, TEMPLATES_B, EVENTS_B, STRINGS_B)
    return compile_manifest(PROVIDER_B, text)


def make_event(mf: object, event_id: int, payload: bytes) -> Event:
    header = Mock()
    header.payload = payload
    header.version = 0
    header.opcode = event_id
    header.additional_header_fields.return_value = {}
    return Event(header, mf)


def test_value_map_exact_match_and_zero(manifest_a: object) -> None:
    definition = manifest_a.MAPS["SharedMap"]
    assert definition.kind == VALUE_MAP

    zero = definition.resolve(0, 32, "Shared", False)
    assert zero.matched is False
    assert zero.entries == ()
    assert zero.complete is False

    one = definition.resolve(1, 32, "Shared", False)
    assert [entry.name for entry in one.entries] == ["A-One"]
    assert one.names == ("A-One",)
    assert one.value == 1
    assert one.recomputed == 1

    unknown = definition.resolve(0x10, 32, "Shared", False)
    assert unknown.matched is False
    assert unknown.entries == ()
    assert unknown.unknown_mask == 0


def test_value_map_alias_preserves_every_entry(manifest_a: object) -> None:
    result = manifest_a.MAPS["AliasMap"].resolve(1, 32, "Alias", False)
    assert result.names == ("First alias", "Second alias")
    assert result.labels == ("First alias", "Second alias")
    assert len(result.entries) == 2
    assert result.complete is True


def test_resource_missing_keeps_identifier_without_borrowing_text(manifest_a: object, manifest_b: object) -> None:
    result_a = manifest_a.MAPS["SharedMap"].resolve(2, 32, "Shared", False)
    result_b = manifest_b.MAPS["SharedMap"].resolve(4, 32, "Shared", False)

    # Provider A references $(string.MissingA), but has no such resource of its own.
    assert result_a.names == ()
    assert result_a.identifiers == ("MissingA",)
    assert result_a.labels == ("MissingA",)
    assert result_a.entries[0].identifier == "MissingA"

    # Provider B resolves its own same-named map and resource.
    assert result_b.names == ("B-only resource",)
    assert result_b.entries[0].identifier == "OnlyB"

    # A same-named identifier is only resolved by the provider that owns the text.
    one_b = manifest_b.MAPS["SharedMap"].resolve(1, 32, "Shared", False)
    assert one_b.names == ("B-One",)
    assert one_b.identifiers == ("BShared",)


def test_same_map_name_is_provider_local(manifest_a: object, manifest_b: object) -> None:
    result_a = manifest_a.MAPS["SharedMap"].resolve(1, 32, "Shared", False)
    result_b = manifest_b.MAPS["SharedMap"].resolve(1, 32, "Shared", False)
    assert result_a.names == ("A-One",)
    assert result_b.names == ("B-One",)
    assert result_a.map.provider_guid == PROVIDER_A
    assert result_b.map.provider_guid == PROVIDER_B

    flags_a = manifest_a.MAPS["FlagsMap"].resolve(2, 8, "Flags", False)
    flags_b = manifest_b.MAPS["FlagsMap"].resolve(2, 8, "Flags", False)
    assert flags_a.names == ()
    assert flags_a.unknown_bits == (1,)
    assert flags_b.names == ("B second flag",)
    assert flags_a.map.provider_guid == PROVIDER_A
    assert flags_b.map.provider_guid == PROVIDER_B


def test_bit_map_multi_bit_keeps_unknown_bits(manifest_a: object) -> None:
    definition = manifest_a.MAPS["FlagsMap"]
    # 0b10100101: bits 0, 2, 5 and 7 set; only 0x01, 0x04 and 0x20 are defined.
    result = definition.resolve(0xA5, 8, "Flags", False)

    assert result.kind == BIT_MAP
    assert result.names == ("First", "Fourth", "Twenty")
    assert result.matched_mask == 0x25
    assert result.unknown_mask == 0x80
    assert result.unknown_bits == (7,)
    assert result.complete is False
    assert result.recomputed == 0xA5
    assert result.value == 0xA5
    # The unknown bit is still represented even though three known labels were found.
    assert "High" not in result.names


def test_bit_map_combined_entry_requires_all_of_its_bits() -> None:
    definition = MapDefinition(
        "Combined",
        BIT_MAP,
        (
            MapEntry(0x3, "pair"),
            MapEntry(0x10, "single"),
        ),
    )
    # Both bits of the combined entry are present; 0x10 is separate, 0x04 is unknown.
    result = definition.resolve(0x17, 8, "Flags", False)
    assert result.names == ("pair", "single")
    assert result.known_bits == (0, 1, 4)
    assert result.unknown_bits == (2,)
    assert result.recomputed == 0x17

    # A partial combined entry must not match.
    partial = definition.resolve(0x01, 8, "Flags", False)
    assert partial.names == ()
    assert partial.unknown_bits == (0,)


def test_bit_map_zero_is_named_default_only_at_zero(manifest_a: object) -> None:
    definition = manifest_a.MAPS["FlagsMap"]
    zero = definition.resolve(0, 8, "Flags", False)
    assert zero.names == ("None",)
    assert zero.matched_mask == 0
    assert zero.unknown_mask == 0
    assert zero.complete is True
    assert zero.recomputed == 0

    one = definition.resolve(1, 8, "Flags", False)
    assert one.names == ("First",)
    assert "None" not in one.names


@pytest.mark.parametrize("raw_value", [-1, -128])
def test_signed_field_width_normalizes_without_losing_raw(manifest_a: object, raw_value: int) -> None:
    result = manifest_a.MAPS["FlagsMap"].resolve(raw_value, 8, "SignedFlags", True)
    assert result.raw_value == raw_value
    assert result.value == raw_value & 0xFF
    assert result.signed is True
    assert result.recomputed == raw_value & 0xFF


def test_normalize_value_uses_field_width() -> None:
    assert normalize_value(-1, 8) == 0xFF
    assert normalize_value(-1, 16) == 0xFFFF
    assert normalize_value(0x1FF, 8) == 0xFF
    assert normalize_value(-1, 0) == -1


def test_event_mappings_keep_raw_values(manifest_a: object) -> None:
    # uint32 Shared, uint8 Flags, int8 SignedFlags
    event = make_event(manifest_a, 1, b"\x03\x00\x00\x00\x25\x00")

    values = event.event_values()
    assert values["Shared"] == 3
    assert values["Flags"] == 0x25
    assert values["SignedFlags"] == 0

    mappings = event.mappings
    assert set(mappings) == {"Shared", "Flags", "SignedFlags"}
    assert isinstance(mappings["Flags"], MappedValue)
    assert mappings["Flags"].raw_value == 0x25
    assert mappings["Shared"].names == ()
    assert mappings["Shared"].value == 3

    as_dict = event.mapping_results()
    assert as_dict["Flags"]["raw_value"] == 0x25
    assert as_dict["Flags"]["recomputed"] == 0x25
    assert as_dict["Flags"]["map"]["name"] == "FlagsMap"
    assert as_dict["Flags"]["map"]["provider_guid"] == str(PROVIDER_A)

    # Display labels never replace the original value used for rule evaluation.
    assert event.event_values()["Flags"] == 0x25
    assert not isinstance(event.event_values()["Flags"], str)


def test_event_with_unknown_template_has_no_mappings(manifest_a: object) -> None:
    event = make_event(manifest_a, 99, b"")
    assert event._struct is None
    assert event.mappings == {}


def test_full_record_parsing_exposes_authoritative_mappings(monkeypatch: pytest.MonkeyPatch) -> None:
    text = make_manifest(
        PROVIDER_A,
        "Provider-A",
        """
    <bitMap name="FlagsMap">
     <map value="0x1" message="$(string.FlagOne)"/>
     <map value="0x4" message="$(string.FlagFour)"/>
     <map value="0x20" message="$(string.FlagTwenty)"/>
    </bitMap>
        """,
        """
     <template tid="MappedArgs">
      <data name="Flags" inType="win:UInt8" map="FlagsMap"/>
     </template>
        """,
        """
     <event value="1" symbol="MappedEvent" version="0" level="win:Informational" template="MappedArgs"/>
        """,
        STRINGS_A,
    )
    mf = compile_manifest(PROVIDER_A, text)
    monkeypatch.setitem(manifest.CACHE, PROVIDER_A, mf)

    record = event_header_record(PROVIDER_A, event_id=1, payload=b"\xa5")
    header = select_event_header(memoryview(record), Mock(is_64bit=True))
    assert header.provider_id == PROVIDER_A

    event = parse_payload(header)
    assert event._struct is not None
    assert event.event_values()["Flags"] == 0xA5

    mapped = event.mappings["Flags"]
    assert mapped.raw_value == 0xA5
    assert mapped.names == ("First", "Fourth", "Twenty")
    assert mapped.matched_mask == 0x25
    assert mapped.unknown_mask == 0x80
    assert mapped.unknown_bits == (7,)
    assert mapped.recomputed == 0xA5

    # Repeat access is stable and does not rewrite the parsed structure.
    assert event.event_values()["Flags"] == 0xA5
    assert event.mappings["Flags"] == mapped


@pytest.mark.parametrize(
    ("raw", "expected_unknown"),
    [
        (0x1, ()),
        (0x2, ()),
        (0x3, ()),
        (0x81, ()),
        # Bits 8..31 are not defined by this provider's bitmap.
        (0x100, (8,)),
        (0x80000100, (8, 31)),
        (0xFFFFFFFF, tuple(range(8, 32))),
    ],
)
def test_real_bitmap_manifest_keeps_unknown_bits(raw: int, expected_unknown: tuple[int, ...]) -> None:
    """The repo's DWM provider defines a 32-bit bitmap with only the low eight bits."""
    from dissect.etl import manifest as manifest_module

    real = manifest_module.lookup(UUID("292a52c4-fa27-4461-b526-54a46430bd54"))
    definition = real.MAPS["DxgiRedirectionFlags"]
    result = definition.resolve(raw, 32, "dwFlags", False)

    assert result.map.provider_guid == UUID("292a52c4-fa27-4461-b526-54a46430bd54")
    assert result.raw_value == raw
    assert result.recomputed == raw
    assert result.unknown_bits == expected_unknown
    if raw == 0x100:
        assert result.matched is False
        assert result.entries == ()
        assert result.labels == ()


def test_missing_map_definition_preserves_identity() -> None:
    event = _event_with_field_maps({"Flags": ("MissingMap", 8, False)}, b"\x05")
    mapped = event.mappings["Flags"]
    assert mapped.raw_value == 5
    assert mapped.map is not None
    assert mapped.map.name == "MissingMap"
    assert mapped.map.kind is None
    assert mapped.entries == ()
    assert mapped.matched is False
    assert mapped.complete is False


class _FakeTemplate:
    """Minimal stand-in for a compiled cstruct template class."""

    def __init__(self, payload: bytes) -> None:
        self.__values__ = {"Flags": payload[0]}


def _event_with_field_maps(field_maps: dict[str, tuple[str, int | None, bool | None]], payload: bytes) -> Event:
    event_definition = Mock()
    event_definition.template = _FakeTemplate

    event_manifest = Mock()
    event_manifest.EVENTS = {(1, 0): event_definition}
    event_manifest.TEMPLATE_MAPS = {_FakeTemplate: field_maps}
    event_manifest.MAPS = {}
    event_manifest.PROVIDER_GUID = PROVIDER_A
    event_manifest.PROVIDER_NAME = "Provider-A"

    header = Mock()
    header.payload = payload
    header.version = 0
    header.opcode = 1
    header.additional_header_fields.return_value = {}
    return Event(header, event_manifest)


def test_full_records_keep_conflicting_maps_provider_local(monkeypatch: pytest.MonkeyPatch) -> None:
    """The same payload bit pattern is interpreted by each provider's own maps."""
    from dissect.etl import manifest as manifest_module

    manifest_a = compile_manifest(
        PROVIDER_A,
        make_manifest(PROVIDER_A, "Provider-A", MAPS_TWO_PROVIDERS_A, TEMPLATES_A, EVENTS_A, STRINGS_A),
    )
    manifest_b = compile_manifest(
        PROVIDER_B,
        make_manifest(PROVIDER_B, "Provider-B", MAPS_TWO_PROVIDERS_B, TEMPLATES_B, EVENTS_B, STRINGS_B),
    )
    monkeypatch.setitem(manifest_module.CACHE, PROVIDER_A, manifest_a)
    monkeypatch.setitem(manifest_module.CACHE, PROVIDER_B, manifest_b)

    # Shared=0x00000003, Flags=0xA5, SignedFlags=0x00
    payload = b"\x03\x00\x00\x00\xa5\x00"

    def parse(provider: UUID) -> Event:
        record = event_header_record(provider, event_id=1, payload=payload)
        header = select_event_header(memoryview(record), Mock(is_64bit=True))
        return parse_payload(header)

    event_a = parse(PROVIDER_A)
    event_b = parse(PROVIDER_B)

    assert event_a.provider_id() == PROVIDER_A
    assert event_b.provider_id() == PROVIDER_B

    flags_a = event_a.mappings["Flags"]
    flags_b = event_b.mappings["Flags"]

    # A defines 0x1, 0x4 and 0x20; 0x80 remains unknown.
    assert flags_a.names == ("First", "Fourth", "Twenty")
    assert flags_a.matched_mask == 0x25
    assert flags_a.unknown_mask == 0x80
    assert flags_a.recomputed == 0xA5

    # B defines 0x2 and 0x80; 0x80 matches while bits 0, 2 and 5 stay unknown.
    assert flags_b.names == ("B high flag",)
    assert flags_b.matched_mask == 0x80
    assert flags_b.unknown_mask == 0x25
    assert flags_b.unknown_bits == (0, 2, 5)
    assert flags_b.recomputed == 0xA5
    assert flags_b.map.provider_name == "Provider-B"

    # SharedMap is a valueMap: 3 is unknown in both providers, but identity differs.
    assert event_a.mappings["Shared"].matched is False
    assert event_b.mappings["Shared"].matched is False
    assert event_a.mappings["Shared"].map.provider_guid == PROVIDER_A
    assert event_b.mappings["Shared"].map.provider_guid == PROVIDER_B

    # The numeric payload used for rules is untouched in both events.
    assert event_a.event_values()["Flags"] == 0xA5
    assert event_b.event_values()["Flags"] == 0xA5


def test_real_conflicting_provider_maps_are_isolated() -> None:
    """Two real Windows providers define the same map name with different value 3 labels."""
    from dissect.etl import manifest as manifest_module

    spelling = manifest_module.lookup(UUID("d0e22efc-ac66-4b25-a72d-382736b5e940"))
    checker = manifest_module.lookup(UUID("b2fcd41f-9a40-4150-8c92-b224b7d8c8aa"))

    assert spelling.MAPS["WordlistType"].kind == VALUE_MAP
    assert checker.MAPS["WordlistType"].kind == VALUE_MAP

    result_spelling = spelling.MAPS["WordlistType"].resolve(3, 32, "WordlistType", False)
    result_checker = checker.MAPS["WordlistType"].resolve(3, 32, "WordlistType", False)

    assert result_spelling.names == ("Auto Correct",)
    assert result_checker.names == ("Accepted Suggestions",)
    assert result_spelling.map.provider_guid == UUID("d0e22efc-ac66-4b25-a72d-382736b5e940")
    assert result_checker.map.provider_guid == UUID("b2fcd41f-9a40-4150-8c92-b224b7d8c8aa")

    # Each provider also binds its own template to its own definition.
    assert spelling.TEMPLATE_MAPS[spelling.c_parser.SpellcheckingSendArgs] == {
        "WordlistType": ("WordlistType", 32, False)
    }
    assert checker.TEMPLATE_MAPS[checker.c_parser.ModifyWordlistStartArgs] == {
        "WordlistType": ("WordlistType", 32, False)
    }


def test_map_definition_lookup_is_exact_and_ordered() -> None:
    definition = MapDefinition(
        "Exact",
        VALUE_MAP,
        (
            MapEntry(1, "one"),
            MapEntry(3, "three"),
            MapEntry(1, "one again"),
        ),
    )
    assert [entry.name for entry in definition.lookup(1)] == ["one", "one again"]
    assert definition.lookup(2) == ()
    assert definition.resolve(3).names == ("three",)
    assert definition.resolve(3).complete is True
