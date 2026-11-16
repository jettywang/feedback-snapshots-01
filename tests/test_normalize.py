import hashlib
import struct
from collections.abc import Iterator
from dataclasses import replace

import pytest

from dissect.cobaltstrike.beacon import (
    BeaconConfigBlock,
    BeaconModifications,
    BeaconSetting,
    SettingsType,
    STOCK_TYPE,
    TypeFieldChange,
    iter_settings,
)
from dissect.cobaltstrike.normalize import (
    NORMALIZER_NAME,
    fix_settings_types,
    infer_type_mapping,
    normalize_config_block,
    settings_type_modifications,
)

SHORT = int(SettingsType.TYPE_SHORT)
INT = int(SettingsType.TYPE_INT)
PTR = int(SettingsType.TYPE_PTR)


def pack_setting(index: int, observed_type: int, value: bytes) -> bytes:
    return struct.pack(">HHH", index, observed_type, len(value)) + value


def block(settings: list[bytes], xorkey: bytes = b"\x69") -> BeaconConfigBlock:
    return BeaconConfigBlock(data=b"".join(settings) + b"\x00" * 8, xorkey=xorkey)


def header_types(data: bytes) -> dict[int, int]:
    return {index: observed_type for _offset, index, observed_type, _length in _headers(data)}


def _headers(data: bytes) -> Iterator[tuple[int, int, int, int]]:
    offset = 0
    while offset + 6 <= len(data):
        index, observed_type, length = struct.unpack(">HHH", data[offset : offset + 6])
        if index == 0:
            return
        yield offset, index, observed_type, length
        offset += 6 + length


def test_stock_config_is_not_modified():
    data = pack_setting(1, SHORT, b"\x00\x02") + pack_setting(3, INT, b"\x00\x00\x10\x00")
    config = block([data])

    normalized, mods = normalize_config_block(config)

    assert normalized.data == config.data
    assert mods.tags == []
    assert mods.remapped_types == {}
    assert mods.unknown_types == {}
    assert mods.type_changes == []
    assert mods.conflicts == []
    assert mods.original_sha256 == hashlib.sha256(config.data).hexdigest()
    assert mods.normalized_data == config.data
    assert mods.input_preserved is True
    assert settings_type_modifications(config) == {}


def test_remapped_types_are_normalized_with_stock_evidence():
    config = block(
        [
            pack_setting(BeaconSetting.SETTING_PROTOCOL, 5, b"\x00\x02"),
            pack_setting(BeaconSetting.SETTING_SLEEPTIME, 9, b"\x00\x00\x10\x00"),
            pack_setting(BeaconSetting.SETTING_DOMAINS, 7, b"host.example.com,/path"),
        ]
    )

    normalized, mods = normalize_config_block(config)

    # The input block itself is never mutated.
    assert config.data != normalized.data
    assert mods.original_sha256 == hashlib.sha256(config.data).hexdigest()
    assert mods.input_preserved is True

    assert mods.tags == ["remapped_types"]
    assert mods.remapped_types == {5: SHORT, 9: INT, 7: PTR}
    assert header_types(normalized.data) == {1: SHORT, 3: INT, 8: PTR}

    applied = mods.applied_changes
    assert len(applied) == 3
    assert {change.evidence for change in applied} == {"stock"}
    for change in applied:
        assert change.normalizer == NORMALIZER_NAME
        assert change.is_change is True
        assert change.applied is True
        # The originally declared type must never be reported as the normalized type number.
        assert change.original_type != change.proposed_type
        assert "stock type" in change.reason


def test_unknown_observed_type_keeps_original_bytes():
    config = block(
        [
            pack_setting(BeaconSetting.SETTING_PROTOCOL, 5, b"\x00\x02"),
            pack_setting(200, 11, b"\x01\x02"),  # unknown index, unknown observed type, len 2
        ]
    )

    inferred, unknown = infer_type_mapping(config)
    assert inferred == {5: SHORT}
    assert unknown == {11: [200]}

    normalized, mods = normalize_config_block(config)

    assert mods.unknown_types == {11: [200]}
    unknown_change = next(change for change in mods.type_changes if change.evidence == "unknown")
    assert unknown_change.proposed_type is None
    assert unknown_change.applied is False
    assert unknown_change.original_type == 11
    # Original bytes of the unconfirmed field are retained verbatim.
    offset = unknown_change.offset
    assert struct.unpack(">H", normalized.data[offset + 2 : offset + 4])[0] == 11
    # Only the confirmed mapping is part of the remap table.
    assert 11 not in mods.remapped_types
    assert mods.input_preserved is True


def test_length_only_evidence_is_labeled_as_such():
    # Index 16 (SETTING_BOF_ALLOCATOR) has no STOCK_TYPE entry, so only the length heuristic applies.
    assert BeaconSetting(16) not in STOCK_TYPE
    config = block([pack_setting(16, 30, b"\x00\x00\x01\x00")])

    normalized, mods = normalize_config_block(config)

    change = mods.type_changes[0]
    assert change.evidence == "length"
    assert change.proposed_type == INT
    assert change.applied is True
    assert header_types(normalized.data) == {16: INT}


def test_ambiguous_observed_type_without_tie_break_is_retained():
    # Index 72 legitimately allows both SHORT and INT; conflicting lengths remove the tie-break.
    config = block(
        [
            pack_setting(72, 41, b"\x00\x05"),
            pack_setting(72, 41, b"\x00\x00\x00\x05"),
        ]
    )

    inferred, unknown = infer_type_mapping(config)
    assert inferred == {}
    assert unknown == {41: [72]}

    normalized, mods = normalize_config_block(config)
    assert mods.remapped_types == {}
    assert mods.unknown_types == {41: [72]}
    assert all(observed == 41 for _offset, _index, observed, _length in _headers(normalized.data))


def test_conflicting_normalizers_are_reported_and_bytes_reverted():
    def rival_normalizer(config_block: BeaconConfigBlock, mods: BeaconModifications):
        mods.type_changes.append(
            TypeFieldChange(
                offset=0,
                index=1,
                original_type=5,
                proposed_type=INT,
                reason="rival heuristic",
                normalizer="rival",
                evidence="length",
            )
        )
        buffer = bytearray(config_block.data)
        struct.pack_into(">H", buffer, 2, INT)
        return replace(config_block, data=bytes(buffer)), mods

    config = block(
        [
            pack_setting(BeaconSetting.SETTING_PROTOCOL, 5, b"\x00\x02"),
            pack_setting(BeaconSetting.SETTING_SLEEPTIME, 9, b"\x00\x00\x10\x00"),
        ]
    )

    normalized, mods = normalize_config_block(config, normalizers=(fix_settings_types, rival_normalizer))

    assert len(mods.conflicts) == 1
    conflict = mods.conflicts[0]
    assert conflict.offset == 0
    assert conflict.proposals == {NORMALIZER_NAME: SHORT, "rival": INT}
    assert conflict.original_type == 5
    # The contested field reverts to the original bytes; the other field is still normalized.
    assert struct.unpack(">H", normalized.data[2:4])[0] == 5
    assert struct.unpack(">H", normalized.data[10:12])[0] == INT
    contested = [change for change in mods.type_changes if change.offset == 0]
    assert all(change.conflict is True and change.applied is False for change in contested)
    assert any("CONFLICT" in line for line in mods.explain())


def test_two_mappings_produce_reproducible_change_report():
    semantic = [
        (BeaconSetting.SETTING_PROTOCOL, b"\x00\x02"),
        (BeaconSetting.SETTING_SLEEPTIME, b"\x00\x00\x10\x00"),
        (BeaconSetting.SETTING_DOMAINS, b"host.example.com,/path"),
    ]
    mapping_a = {SHORT: 5, INT: 9, PTR: 7}
    mapping_b = {SHORT: 50, INT: 90, PTR: 70}

    def build(mapping):
        stock_type_for_index = {
            1: SHORT,
            3: INT,
            8: PTR,
        }
        return block(
            [
                pack_setting(index, mapping[stock_type_for_index[int(index)]], value)
                for index, value in semantic
            ]
        )

    config_a = build(mapping_a)
    config_b = build(mapping_b)

    assert hashlib.sha256(config_a.data).hexdigest() != hashlib.sha256(config_b.data).hexdigest()

    normalized_a, mods_a = normalize_config_block(config_a)
    normalized_b, mods_b = normalize_config_block(config_b)

    # Different observed enums normalize to byte-identical, thus semantically equal, configs.
    assert normalized_a.data == normalized_b.data
    values_a = [(int(s.index), int(s.type), bytes(s.value)) for s in iter_settings(normalized_a.data)]
    values_b = [(int(s.index), int(s.type), bytes(s.value)) for s in iter_settings(normalized_b.data)]
    assert values_a == values_b

    # Original input hashes remain available and distinct.
    assert mods_a.original_sha256 == hashlib.sha256(config_a.data).hexdigest()
    assert mods_b.original_sha256 == hashlib.sha256(config_b.data).hexdigest()
    assert mods_a.original_sha256 != mods_b.original_sha256

    # Re-running on the same input is reproducible.
    rerun_a, rerun_mods_a = normalize_config_block(config_a)
    assert rerun_a.data == normalized_a.data
    assert rerun_mods_a.original_sha256 == mods_a.original_sha256

    # Each report still distinguishes what the sample declared from the normalized number.
    for mods, mapping in ((mods_a, mapping_a), (mods_b, mapping_b)):
        for change in mods.applied_changes:
            assert change.original_type in mapping.values()
            assert change.original_type != change.proposed_type


def test_explain_never_presents_normalized_type_as_declared():
    config = block([pack_setting(BeaconSetting.SETTING_PROTOCOL, 5, b"\x00\x02")])
    _, mods = normalize_config_block(config)
    lines = mods.explain()
    assert any("original_type=5" in line and "normalized_type=1" in line for line in lines)
    assert any(mods.original_sha256 in line for line in lines)


def test_empty_pipeline_records_hash_without_changes():
    config = block([pack_setting(1, SHORT, b"\x00\x02")])
    normalized, mods = normalize_config_block(config, normalizers=())

    assert normalized.data == config.data
    assert mods.original_sha256 == hashlib.sha256(config.data).hexdigest()
    assert mods.type_changes == []
    assert mods.tags == []


@pytest.mark.parametrize(
    "settings,expected",
    [
        # Stock enum values: identity inference means no remap.
        ([pack_setting(1, SHORT, b"\x00\x02"), pack_setting(3, INT, b"\x00\x00\x01\x00")], {}),
        # Remapped enum inferred from known settings.
        ([pack_setting(1, 5, b"\x00\x02"), pack_setting(3, 9, b"\x00\x00\x01\x00")], {5: SHORT, 9: INT}),
    ],
)
def test_settings_type_modifications(settings, expected):
    config = block(settings)
    assert settings_type_modifications(config) == expected
