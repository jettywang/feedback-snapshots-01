from __future__ import annotations

import io
import json
import uuid
from typing import TYPE_CHECKING

import dissect.regf as package
from dissect.regf import mounted, regf
from tests._hive import build_hive, gpt_data, mbr_data, text_data

if TYPE_CHECKING:
    from typing import BinaryIO

SNAPSHOT_A = "disk-a"
SNAPSHOT_B = "disk-b"
GENUINE_GPT = uuid.UUID("1e178d94-4f79-41e9-865d-2e5b4328cd23")
OTHER_GPT = uuid.UUID("2e178d94-4f79-41e9-865d-2e5b4328cd23")


def analyze(values: list[tuple[str, bytes, int]], *, snapshot: str = SNAPSHOT_A) -> mounted.MountedDevicesAnalysis:
    hive = regf.RegistryHive(io.BytesIO(build_hive(values)))
    return mounted.analyze_mounted_devices(hive, snapshot=snapshot)


def by_name(analysis: mounted.MountedDevicesAnalysis) -> dict[str, mounted.MountedDeviceValue]:
    return {value.name: value for value in analysis.values}


def test_mbr_drive_letters_correlate_and_keep_raw_evidence() -> None:
    data = mbr_data(0x12345678, 0x100000)
    analysis = analyze(
        [
            (r"\DosDevices\C:", data, 3),
            (r"\DosDevices\D:", data, 3),
            (r"\DosDevices\E:", mbr_data(0x87654321, 0x100000), 3),
        ]
    )

    c = analysis.values[0]
    assert isinstance(c.identity, mounted.MbrVolumeIdentity)
    assert (c.identity.disk_signature, c.identity.partition_offset) == (0x12345678, 0x100000)
    assert c.raw == data
    assert c.raw_hex == data.hex()
    assert c.value_cell_offset > 0
    assert c.data_cell_offset is not None
    assert c.data_cell_offset != c.value_cell_offset
    assert "0x12345678" in c.parse_basis
    assert "0x100000" in c.parse_basis

    assert len(analysis.identities) == 2
    merged = next(record for record in analysis.identities if record.identity.kind == "mbr")
    assert merged.alias_names == (r"\DosDevices\C:", r"\DosDevices\D:")
    assert merged.identity.canonical == "mbr:12345678:0000000000100000"
    assert not analysis.conflicts


def test_gpt_partition_guid_is_little_endian() -> None:
    analysis = analyze(
        [
            (r"\??\Volume{11111111-1111-1111-1111-111111111111}", gpt_data(GENUINE_GPT), 3),
            (r"\DosDevices\C:", gpt_data(GENUINE_GPT), 3),
        ]
    )

    values = by_name(analysis)
    volume = values[r"\??\Volume{11111111-1111-1111-1111-111111111111}"]
    assert isinstance(volume.identity, mounted.GptVolumeIdentity)
    assert volume.identity.partition_guid == GENUINE_GPT
    assert volume.identity.canonical == f"gpt:{GENUINE_GPT}"
    assert volume.raw.startswith(b"DMIO:ID:")
    assert len(analysis.identities) == 1
    assert set(analysis.identities[0].alias_names) == {
        r"\??\Volume{11111111-1111-1111-1111-111111111111}",
        r"\DosDevices\C:",
    }


def test_same_drive_letter_different_snapshots_is_a_conflict() -> None:
    first = analyze([(r"\DosDevices\C:", gpt_data(GENUINE_GPT), 3)], snapshot=SNAPSHOT_A)
    second = analyze([(r"\DosDevices\C:", gpt_data(OTHER_GPT), 3)], snapshot=SNAPSHOT_B)

    correlation = mounted.correlate_mounted_devices(first, second)

    assert len(correlation.records) == 2
    assert {record.identity.canonical for record in correlation.records} == {
        f"gpt:{GENUINE_GPT}",
        f"gpt:{OTHER_GPT}",
    }
    assert len(correlation.conflicts) == 1
    conflict = correlation.conflicts[0]
    assert conflict.alias_key == "drive:C"
    assert conflict.identity_keys == (f"gpt:{GENUINE_GPT}", f"gpt:{OTHER_GPT}")
    assert {value.snapshot for value in conflict.values} == {SNAPSHOT_A, SNAPSHOT_B}


def test_same_identity_different_drive_letters_across_snapshots_is_one_record() -> None:
    first = analyze([(r"\DosDevices\C:", gpt_data(GENUINE_GPT), 3)], snapshot=SNAPSHOT_A)
    second = analyze(
        [
            (r"\DosDevices\D:", gpt_data(GENUINE_GPT), 3),
            (r"\DosDevices\E:", gpt_data(OTHER_GPT), 3),
        ],
        snapshot=SNAPSHOT_B,
    )

    correlation = mounted.correlate_mounted_devices(first, second)

    assert len(correlation.records) == 2
    record = next(record for record in correlation.records if record.identity.canonical == f"gpt:{GENUINE_GPT}")
    assert {(alias.name, alias.snapshot) for alias in record.aliases} == {
        (r"\DosDevices\C:", SNAPSHOT_A),
        (r"\DosDevices\D:", SNAPSHOT_B),
    }
    assert record.snapshots == (SNAPSHOT_A, SNAPSHOT_B)
    assert not correlation.conflicts


def test_text_reference_to_another_registry_name_resolves_to_its_identity() -> None:
    target_name = r"\DosDevices\X:"
    alias_name = r"\??\Volume{22222222-2222-2222-2222-222222222222}"
    analysis = analyze(
        [
            (alias_name, text_data(target_name), 3),
            (target_name, gpt_data(GENUINE_GPT), 3),
        ]
    )

    values = by_name(analysis)
    alias = values[alias_name]
    assert alias.kind == "gpt"
    assert alias.status == "reference"
    assert alias.identity is not None
    assert alias.identity.canonical == f"gpt:{GENUINE_GPT}"
    assert alias.reference == target_name
    assert [hop.name for hop in alias.chain] == [target_name]
    assert alias.chain[0].value_cell_offset == values[target_name].value_cell_offset
    assert alias.chain[0].raw_hex == gpt_data(GENUINE_GPT).hex()
    assert "identity taken from that value" in alias.parse_basis

    record = next(record for record in analysis.identities if record.identity.canonical == f"gpt:{GENUINE_GPT}")
    assert set(record.alias_names) == {alias_name, target_name}
    assert values[target_name].status == "binary-identity"


def test_text_reference_can_follow_a_chain() -> None:
    first = r"\??\Volume{33333333-3333-3333-3333-333333333333}"
    second = r"\??\Volume{44444444-4444-4444-4444-444444444444}"
    final = r"\DosDevices\Z:"
    analysis = analyze(
        [
            (first, text_data(second), 3),
            (second, text_data(final), 3),
            (final, mbr_data(0xAABBCCDD, 0x2000), 3),
        ]
    )

    value = by_name(analysis)[first]
    assert value.kind == "mbr"
    assert value.identity is not None
    assert value.identity.canonical == "mbr:aabbccdd:0000000000002000"
    assert [hop.name for hop in value.chain] == [second, final]
    assert value.status == "reference"


def test_text_reference_cycle_is_reported_without_identity() -> None:
    first = r"\DosDevices\C:"
    second = r"\DosDevices\D:"
    analysis = analyze(
        [
            (first, text_data(second), 3),
            (second, text_data(first), 3),
        ]
    )

    values = by_name(analysis)
    for name in (first, second):
        value = values[name]
        assert value.status == "cycle"
        assert value.identity is None
        assert value.kind == "reference"
        assert "cycle" in (value.detail or "").lower()

    assert not analysis.identities
    assert len(analysis.unresolved) == 2


def test_missing_registry_reference_is_unresolved_not_guessed() -> None:
    name = r"\DosDevices\C:"
    missing = r"\DosDevices\Q:"
    analysis = analyze([(name, text_data(missing), 3)])

    value = analysis.values[0]
    assert value.status == "unresolved"
    assert value.identity is None
    assert value.reference == missing
    assert "missing" in (value.detail or "")


def test_exact_text_path_is_not_a_confirmed_volume_identity() -> None:
    path = r"\??\SCSI#Disk&Ven_Vendor_Product#5&12345678&0&000000#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
    analysis = analyze([(r"\DosDevices\F:", text_data(path), 3)])

    value = analysis.values[0]
    assert value.kind == "text"
    assert value.status == "text-identity"
    assert not value.confirmed
    assert value.identity is not None
    assert value.identity.kind == "text"
    assert value.identity.canonical.startswith("text:")


def test_unknown_layout_is_retained_byte_for_byte() -> None:
    raw = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"
    analysis = analyze(
        [
            (r"\DosDevices\C:", raw, 3),
            (r"\DosDevices\D:", b"", 3),
            (r"\DosDevices\E:", b"DMIO:ID:" + b"\x00" * 15, 3),
        ]
    )

    values = by_name(analysis)
    for name in (r"\DosDevices\C:", r"\DosDevices\E:"):
        value = values[name]
        assert value.kind == "unknown"
        assert value.status == "unknown"
        assert value.confirmed is False
        assert value.identity is None
        assert value.raw == (raw if name.endswith("C:") else b"DMIO:ID:" + b"\x00" * 15)
        assert value.raw_hex
    assert values[r"\DosDevices\D:"].raw == b""
    assert not analysis.identities


def test_structurally_ambiguous_value_keeps_both_readings() -> None:
    ambiguous = b"\\DosDevices\\"
    analysis = analyze([(r"\DosDevices\C:", ambiguous, 3)])

    value = analysis.values[0]
    assert value.kind == "ambiguous"
    assert value.status == "ambiguous"
    assert value.identity is None
    assert value.confirmed is False
    assert value.raw == ambiguous
    assert "structurally valid" in value.parse_basis


def test_duplicate_target_name_makes_reference_ambiguous() -> None:
    target = r"\DosDevices\D:"
    analysis = analyze(
        [
            (r"\DosDevices\C:", text_data(target), 3),
            (target, gpt_data(GENUINE_GPT), 3),
            (target, mbr_data(0x12345678, 0x100000), 3),
        ]
    )

    value = by_name(analysis)[r"\DosDevices\C:"]
    assert value.status == "ambiguous"
    assert value.identity is None
    assert len(value.chain) == 2
    assert {hop.value_cell_offset for hop in value.chain} == {
        hop.value_cell_offset for hop in value.chain if hop.value_cell_offset is not None
    }
    assert value.chain[0].value_cell_offset != value.chain[1].value_cell_offset


def test_reference_resolution_is_case_insensitive_but_path_evidence_is_not_rewritten() -> None:
    alias = r"\DosDevices\c:"
    analysis = analyze(
        [
            (alias, text_data(r"\DOSDEVICES\D:"), 3),
            (r"\DosDevices\D:", mbr_data(0xDEADBEEF, 0x4000), 3),
        ]
    )

    value = by_name(analysis)[alias]
    assert value.status == "reference"
    assert value.identity is not None
    assert value.identity.canonical == "mbr:deadbeef:0000000000004000"
    assert value.reference == r"\DOSDEVICES\D:"
    assert value.chain[0].name == r"\DosDevices\D:"


def test_gpt_marker_with_nil_guid_is_unknown() -> None:
    raw = b"DMIO:ID:" + b"\x00" * 16
    analysis = analyze([(r"\DosDevices\C:", raw, 3)])

    value = analysis.values[0]
    assert value.kind == "unknown"
    assert value.identity is None
    assert value.raw == raw
    assert "nil GUID" in value.parse_basis


def test_non_binary_value_type_is_not_parsed_as_binary() -> None:
    analysis = analyze([(r"\DosDevices\C:", mbr_data(0x12345678, 0x100000), 1)])

    value = analysis.values[0]
    assert value.kind == "unknown"
    assert value.identity is None
    assert "not REG_BINARY" in value.parse_basis
    assert value.raw_hex == mbr_data(0x12345678, 0x100000).hex()


def test_similar_volume_names_do_not_merge_without_matching_bytes() -> None:
    first = r"\??\Volume{55555555-5555-5555-5555-555555555555}"
    second = r"\??\Volume{55555555-5555-5555-5555-555555555556}"
    analysis = analyze(
        [
            (first, gpt_data(GENUINE_GPT), 3),
            (second, text_data(r"\??\SCSI#Disk#1"), 3),
        ]
    )

    assert len(analysis.identities) == 2
    assert by_name(analysis)[second].identity is not None
    assert by_name(analysis)[second].identity.kind == "text"


def test_partition_offset_is_not_borrowed_from_another_value() -> None:
    first = mbr_data(0x11111111, 0x100000)
    second = mbr_data(0x11111111, 0x200000)
    analysis = analyze(
        [
            (r"\DosDevices\C:", first, 3),
            (r"\DosDevices\D:", second, 3),
        ]
    )

    values = by_name(analysis)
    assert values[r"\DosDevices\C:"].identity is not None
    assert values[r"\DosDevices\C:"].identity.canonical == "mbr:11111111:0000000000100000"
    assert values[r"\DosDevices\D:"].identity is not None
    assert values[r"\DosDevices\D:"].identity.canonical == "mbr:11111111:0000000000200000"
    assert len(analysis.identities) == 2


def test_missing_mounted_devices_key_keeps_problem() -> None:
    hive = regf.RegistryHive(io.BytesIO(build_hive([], include_mounted=False)))

    analysis = mounted.analyze_mounted_devices(hive)

    assert analysis.problems == ("MountedDevices key not found in hive",)
    assert analysis.values == ()
    assert analysis.identities == ()


def test_reference_into_ambiguous_target_stays_ambiguous() -> None:
    target = r"\DosDevices\D:"
    ambiguous = b"\\DosDevices\\"
    analysis = analyze(
        [
            (r"\DosDevices\C:", text_data(target), 3),
            (target, ambiguous, 3),
        ]
    )

    value = by_name(analysis)[r"\DosDevices\C:"]
    assert value.status == "ambiguous"
    assert value.identity is None
    assert value.chain
    assert value.chain[0].name == target
    assert "itself ambiguous" in (value.detail or "")


def test_real_system_hive_records_are_json_serializable(system_hive: BinaryIO) -> None:
    hive = regf.RegistryHive(system_hive)
    analysis = mounted.analyze_mounted_devices(hive, snapshot="SYSTEM.gz")

    payload = json.loads(json.dumps(analysis.to_dict()))
    records = payload["identities"]
    assert records
    by_kind = {record["identity"]["kind"]: record for record in records}
    assert set(by_kind) == {"gpt", "text"}
    assert by_kind["gpt"]["identity"]["canonical"] == f"gpt:{GENUINE_GPT}"
    assert {alias["name"] for alias in by_kind["gpt"]["aliases"]} == {r"\DosDevices\C:"}
    assert len(by_kind["text"]["aliases"]) == 2
    assert all(record["snapshots"] == ["SYSTEM.gz"] for record in records)
    assert not payload["conflicts"]
    assert not payload["problems"]


def test_zero_disk_signature_is_unknown() -> None:
    raw = mbr_data(0, 0x100000)
    analysis = analyze([(r"\DosDevices\C:", raw, 3)])

    value = analysis.values[0]
    assert value.kind == "unknown"
    assert value.identity is None
    assert value.raw == raw
    assert "zero disk signature" in value.parse_basis


def test_analysis_dict_keeps_offsets_and_basis_for_every_alias() -> None:
    analysis = analyze(
        [
            (r"\DosDevices\C:", gpt_data(GENUINE_GPT), 3),
            (r"\DosDevices\D:", b"\xde\xad\xbe\xef", 3),
        ]
    )

    payload = json.loads(json.dumps(analysis.to_dict()))
    for value in payload["values"]:
        assert value["raw_hex"]
        assert value["value_cell_offset"]
        assert isinstance(value["parse_basis"], str)
        assert value["parse_basis"]
    assert payload["identities"]


def test_public_package_exports_match_module() -> None:

    assert package.analyze_mounted_devices is mounted.analyze_mounted_devices
    assert package.correlate_mounted_devices is mounted.correlate_mounted_devices
    assert package.MountedDevicesAnalysis is mounted.MountedDevicesAnalysis
    assert package.MbrVolumeIdentity is mounted.MbrVolumeIdentity


def test_hive_convenience_method_is_read_only() -> None:
    hive = regf.RegistryHive(io.BytesIO(build_hive([(r"\DosDevices\C:", gpt_data(GENUINE_GPT), 3)])))

    analysis = hive.mounted_devices(snapshot="method")

    assert analysis.snapshot == "method"
    assert analysis.identities[0].identity.canonical == f"gpt:{GENUINE_GPT}"
    assert hive.open("MountedDevices").name == "MountedDevices"


def test_analysis_does_not_modify_hive_bytes() -> None:
    raw = build_hive(
        [
            (r"\DosDevices\C:", gpt_data(GENUINE_GPT), 3),
            (r"\DosDevices\D:", text_data(r"\DosDevices\C:"), 3),
            (r"\DosDevices\E:", b"\xde\xad\xbe\xef", 3),
        ]
    )
    buffer = io.BytesIO(raw)
    hive = regf.RegistryHive(buffer)

    analysis = mounted.analyze_mounted_devices(hive, snapshot="immutable")
    mounted.correlate_mounted_devices(analysis)

    buffer.seek(0)
    assert buffer.read() == raw


def test_key_node_source_matches_hive_source() -> None:
    raw = build_hive([(r"\DosDevices\C:", gpt_data(GENUINE_GPT), 3)])
    hive = regf.RegistryHive(io.BytesIO(raw))

    from_hive = mounted.analyze_mounted_devices(hive, snapshot="key")
    from_key = mounted.analyze_mounted_devices(hive.open("MountedDevices"), snapshot="key")

    assert [value.to_dict() for value in from_hive.values] == [value.to_dict() for value in from_key.values]
