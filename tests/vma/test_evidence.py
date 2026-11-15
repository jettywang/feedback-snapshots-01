from __future__ import annotations

import base64
import io
import json
import logging
import struct

import pytest

from dissect.archive.vma.c_vma import VMA_CLUSTER_SIZE
from dissect.archive.vma.evidence import (
    collect_device_declarations,
    export_evidence,
    log_escape,
    parse_blob_buffer,
    safe_name,
)
from dissect.archive.vma.vma import VMA
from tests._tools.vma._synth import SynthVMA, cluster_payload

CONFIG_A = (
    "name: sample-vm\n"
    "scsi0: local-lvm:vm-100-disk-0,size=1G\n"
    "#qmdump#map:scsi0:drive-scsi0:local-lvm:raw:\n"
)
CONFIG_B = "name: second-vm\nvirtio0: local:vm-200-disk-0,size=1G\n"
# A name carrying an embedded newline to exercise log injection defenses.
EVIL_NAME = "drive-\nnewline"


def _build_sample() -> bytes:
    """Two devices, two usable configs and one bad blob reference."""
    builder = SynthVMA()

    builder.add_config("qemu-server.conf", CONFIG_A)
    builder.add_config("other.conf", CONFIG_B)
    # A third config slot reuses an existing name but points its data outside
    # the blob buffer: it creates both a name conflict and an overrunning pointer.
    blob_size_so_far = builder._cursor
    builder.add_config("other.conf", blob_size_so_far + 4096)

    builder.add_device(1, "drive-scsi0", VMA_CLUSTER_SIZE * 4)
    builder.add_device(2, EVIL_NAME, VMA_CLUSTER_SIZE * 2)

    builder.add_extent(
        {
            1: [(0, 0xFFFF, cluster_payload(b"A")), (1, 0, None)],
            2: [(0, 0xFFFF, cluster_payload(b"B"))],
            # An extent block that names a device absent from the header.
            9: [(0, 0, None)],
        },
    )
    return builder.build()


@pytest.fixture()
def report() -> dict:
    vma = VMA(io.BytesIO(_build_sample()))
    return export_evidence(vma)


def test_report_is_json_serializable(report: dict) -> None:
    encoded = json.dumps(report)
    assert json.loads(encoded)["schema"] == "dissect.archive.vma.evidence/v1"

    # Every leaf must be a JSON-native type (no bytes or VMA objects leak out).
    def walk(value: object) -> None:
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        else:
            assert value is None or isinstance(value, str | int | float | bool)

    walk(report)


def test_config_blobs_keep_raw_bytes_and_locations(report: dict) -> None:
    configs = {config["name"]: config for config in report["configs"]}
    config_a = configs["qemu-server.conf"]

    assert config_a["name_location"] == {"kind": "blob", "blob_offset": 1}
    assert config_a["data_location"]["kind"] == "blob"
    assert base64.b64decode(config_a["blob_base64"]) == CONFIG_A.encode()
    assert config_a["text"] == CONFIG_A
    # The stored hash must match the independently hashed raw blob.
    import hashlib

    assert config_a["data_location"]["sha256"] == hashlib.sha256(CONFIG_A.encode()).hexdigest()


def test_bad_blob_pointer_is_an_explicit_issue(report: dict) -> None:
    codes = [issue["code"] for issue in report["issues"]]
    assert "blob_pointer_overflow" in codes

    conflict_slot = next(config for config in report["configs"] if config["config_slot"] == 2)
    assert conflict_slot["name"] == "other.conf"
    assert conflict_slot["data_location"] is None
    assert conflict_slot["blob_base64"] is None
    assert conflict_slot["text"] is None

    issue = next(
        issue
        for issue in report["issues"]
        if issue["code"] == "blob_pointer_overflow" and issue["location"]["kind"] == "config"
    )
    assert issue["location"]["config_slot"] == 2


def test_blob_buffer_overflow_is_detected_while_framing() -> None:
    good = b"x" * 4
    # Frame claims 50 bytes but only 4 follow.
    malformed = struct.pack("<H", 50) + good
    blob = b"\x00" + struct.pack("<H", len(good)) + good + malformed
    records, issues = parse_blob_buffer(blob)

    assert 1 in records
    assert any(issue["code"] == "blob_pointer_overflow" for issue in issues)


def test_config_name_conflict_is_reported(report: dict) -> None:
    conflict = next(issue for issue in report["issues"] if issue["code"] == "config_name_conflict")
    assert conflict["name"] == "other.conf"
    assert conflict["first_config_slot"] == 1
    assert conflict["location"]["config_slot"] == 2
    # Both records survive instead of one silently overwriting the other.
    assert [config["config_slot"] for config in report["configs"] if config["name"] == "other.conf"] == [1, 2]


def test_control_characters_in_names_are_flagged_and_escaped(report: dict) -> None:
    issue = next(issue for issue in report["issues"] if issue["code"] == "name_control_chars")
    assert issue.get("device_id", True)
    device = next(device for device in report["devices"] if device["device_id"] == 2)
    assert device["name"] == EVIL_NAME
    assert "\n" not in device["name_safe"]
    assert device["name_safe"] == safe_name(EVIL_NAME)
    assert "\\x0a" in device["name_safe"]
    assert log_escape("line1\nline2\r") == "line1\\nline2\\r"


def test_log_output_cannot_be_injected(report: dict, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="dissect.archive.vma.evidence"):
        VMA(io.BytesIO(_build_sample()))
        export_evidence(VMA(io.BytesIO(_build_sample())))

    raw = caplog.text
    # The hostile newline must never appear as a real line break in a log line.
    assert "drive-\nnewline" not in raw
    for line in raw.splitlines():
        if "newline" in line:
            assert "\\x0a" in line
    # Every recorded issue message is single-line safe.
    for issue in report["issues"]:
        assert "\n" not in issue["message"]
        assert "\r" not in issue["message"]


def test_duplicate_device_id_is_explicit() -> None:
    blob = b"\x00" + struct.pack("<H", 3) + b"dev"
    blobs, issues = parse_blob_buffer(blob)
    records = collect_device_declarations(
        [(1, 1, 1024), (1, 1, 2048)],
        blobs,
        len(blob),
        issues,
    )

    assert len(records) == 2
    assert all(record["device_id"] == 1 for record in records)
    assert any(issue["code"] == "duplicate_device_id" for issue in issues)


def test_undeclared_device_id_in_extent_is_reported(report: dict) -> None:
    issue = next(issue for issue in report["issues"] if issue["code"] == "undeclared_device_id")
    assert issue["device_id"] == 9
    assert issue["location"]["kind"] == "extent"


def test_correlation_traces_back_to_declaration_and_readable_range(report: dict) -> None:
    match = next(
        correlation
        for correlation in report["correlations"]
        if correlation["matched"] and correlation["config_key"] == "scsi0"
    )

    # The correlation points back at the actual config blob and device declaration.
    config = next(config for config in report["configs"] if config["config_slot"] == match["config_slot"])
    device = next(device for device in report["devices"] if device["device_id"] == match["device_id"])

    assert match["config_data_location"] == config["data_location"]
    assert match["device_declaration_location"] == device["declaration_location"]
    assert match["device_name_location"] == device["name_location"]
    assert match["map_line"] in config["text"]

    # The matched device has independently verified readable data.
    state = device["read_state"]
    assert state["status"] == "partial"
    assert state["allocated_clusters"] == 1
    assert state["allocated_cluster_ranges"] == [[0, 0]]
    assert state["probe"]["ok"] is True
    assert state["probe"]["verified_clusters"] == 1


def test_missing_correlation_device_is_reported() -> None:
    builder = SynthVMA()
    builder.add_config(
        "qemu-server.conf",
        "scsi0: local-lvm:vm-1-disk-0\n#qmdump#map:scsi0:drive-ghost:local-lvm:raw:\n",
    )
    builder.add_device(1, "drive-real", VMA_CLUSTER_SIZE)
    builder.add_extent({1: [(0, 0, None)]})

    report = export_evidence(VMA(io.BytesIO(builder.build())))
    issue = next(issue for issue in report["issues"] if issue["code"] == "correlation_device_missing")
    assert issue["name"] == "drive-ghost"
    assert not any(correlation["matched"] for correlation in report["correlations"])


def test_disk_paths_are_clues_only_and_never_opened(monkeypatch: pytest.MonkeyPatch, report: dict) -> None:
    import builtins

    real_open = builtins.open

    def guarded_open(*args: object, **kwargs: object) -> object:
        path = args[0] if args else kwargs.get("file")
        if isinstance(path, str) and ("vm-100-disk-0" in path or "vm-200-disk-0" in path):
            raise AssertionError(f"evidence export must not open host disk path: {path}")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)

    fresh = export_evidence(VMA(io.BytesIO(_build_sample())))
    hints = [correlation for correlation in fresh["correlations"] if "disk_volume_hint" in correlation]
    assert hints
    assert all(hint["opened"] is False for hint in hints)
    assert any("vm-100-disk-0" in hint["disk_volume_hint"] for hint in hints)


def test_presence_of_config_does_not_imply_complete_data() -> None:
    builder = SynthVMA()
    builder.add_config("qemu-server.conf", CONFIG_A)
    # Device declares four clusters but only one sparse cluster is present.
    builder.add_device(1, "drive-scsi0", VMA_CLUSTER_SIZE * 4)
    builder.add_extent({1: [(0, 0, None)]})

    report = export_evidence(VMA(io.BytesIO(builder.build())))
    state = report["devices"][0]["read_state"]
    assert state["status"] == "sparse"
    assert state["allocated_clusters"] == 0
    assert state["sparse_clusters"] == 1
    assert state["probe"] is None


def test_no_data_device_is_distinct_from_present_data() -> None:
    builder = SynthVMA()
    builder.add_config("qemu-server.conf", CONFIG_A)
    builder.add_device(1, "drive-scsi0", VMA_CLUSTER_SIZE)
    builder.add_device(2, "drive-empty", VMA_CLUSTER_SIZE)
    builder.add_extent({1: [(0, 0xFFFF, cluster_payload(b"Z"))]})

    report = export_evidence(VMA(io.BytesIO(builder.build())))
    states = {device["device_id"]: device["read_state"]["status"] for device in report["devices"]}
    assert states == {1: "complete", 2: "no_data"}


def test_probe_can_be_disabled() -> None:
    builder = SynthVMA()
    builder.add_device(1, "drive-scsi0", VMA_CLUSTER_SIZE)
    builder.add_extent({1: [(0, 0xFFFF, cluster_payload(b"Z"))]})

    report = export_evidence(VMA(io.BytesIO(builder.build())), probe_limit=0)
    assert report["devices"][0]["read_state"]["probe"] is None


def test_vma_still_parses_with_bad_pointers() -> None:
    vma = VMA(io.BytesIO(_build_sample()))
    # The hardened parser keeps the two valid configs and both devices.
    assert set(vma.configs()) == {"qemu-server.conf", "other.conf"}
    assert {device.id for device in vma.devices()} == {1, 2}
    assert vma.blob_buffer()
