import hashlib
import json
import os
import subprocess
import sys

import pytest

from py7zr.inventory import EVIDENCE_CONTENT, EVIDENCE_HEADER, collect_inventory

testdata_path = os.path.join(os.path.dirname(__file__), "data")

COPY_CONTENTS = {
    "test1.txt": b"This file is located in the root.",
    "test/test2.txt": b"This file is located in a folder.",
}


@pytest.mark.files
def test_inventory_header_only_copy():
    report = collect_inventory(os.path.join(testdata_path, "copy.7z"))
    assert report["format"] == "py7zr-inventory/1"
    assert report["archive"]["error"] is None
    assert report["archive"]["encrypted"] is False
    assert len(report["members"]) == 3
    for member in report["members"]:
        assert member["evidence"] == EVIDENCE_HEADER
        assert member["content"] is None
        assert member["error"] is None
    by_name = {m["filename"]: m for m in report["members"]}
    assert by_name["test"]["header"]["is_directory"] is True
    assert by_name["test1.txt"]["header"]["uncompressed"] == 33
    assert by_name["test1.txt"]["header"]["crc32"] == "08626a3e"


@pytest.mark.files
def test_inventory_verify_copy():
    report = collect_inventory(os.path.join(testdata_path, "copy.7z"), verify=True)
    by_name = {m["filename"]: m for m in report["members"]}
    for name, data in COPY_CONTENTS.items():
        member = by_name[name]
        assert member["evidence"] == EVIDENCE_CONTENT
        assert member["error"] is None
        assert member["content"]["sha256"] == hashlib.sha256(data).hexdigest()
        assert member["content"]["size"] == len(data)
        assert member["content"]["crc32_verified"] is True
    # directories carry no content, so they stay at header evidence
    assert by_name["test"]["evidence"] == EVIDENCE_HEADER
    assert by_name["test"]["content"] is None


@pytest.mark.files
def test_inventory_verify_crc_corrupted():
    report = collect_inventory(os.path.join(testdata_path, "crc_corrupted.7z"), verify=True)
    assert report["archive"]["error"] is None
    files = [m for m in report["members"] if not m["header"]["is_directory"]]
    assert len(files) == 3
    for member in files:
        # the solid block fails its CRC, so no member reaches content evidence
        assert member["evidence"] == EVIDENCE_HEADER
        assert member["content"] is None
        assert member["error"]["kind"] == "crc_mismatch"


@pytest.mark.files
def test_inventory_encrypted_without_password():
    report = collect_inventory(os.path.join(testdata_path, "encrypted_1.7z"), verify=True)
    assert report["archive"]["encrypted"] is True
    assert report["archive"]["error"] is None
    files = [m for m in report["members"] if m["header"]["is_file"]]
    assert len(files) == 2
    for member in files:
        # the header is readable, but content stays unverified without the key
        assert member["evidence"] == EVIDENCE_HEADER
        assert member["content"] is None
        assert member["error"]["kind"] == "password_required"


@pytest.mark.files
def test_inventory_repeatable():
    arcfile = os.path.join(testdata_path, "copy.7z")
    first = json.dumps(collect_inventory(arcfile, verify=True), sort_keys=True)
    second = json.dumps(collect_inventory(arcfile, verify=True), sort_keys=True)
    assert first == second


@pytest.mark.files
def test_inventory_no_disk_writes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report = collect_inventory(os.path.join(testdata_path, "copy.7z"), verify=True)
    assert report["archive"]["error"] is None
    assert list(tmp_path.iterdir()) == []


@pytest.mark.cli
def test_inventory_cli(tmp_path):
    arcfile = os.path.join(testdata_path, "copy.7z")
    result = subprocess.run(
        [sys.executable, "-m", "py7zr.inventory", "--verify", arcfile],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["format"] == "py7zr-inventory/1"
    by_name = {m["filename"]: m for m in report["members"]}
    assert by_name["test1.txt"]["evidence"] == EVIDENCE_CONTENT
    assert list(tmp_path.iterdir()) == []
