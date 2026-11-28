from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest
from auditwheel import provenance
from auditwheel.provenance import (
    ProvenanceRecorder,
    _snapshot_wheel,
    explain_member,
    sha256_file,
    verify_provenance,
)


def _write_wheel(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def test_snapshot_wheel_records_elf_members(tmp_path: Path) -> None:
    elf = tmp_path / "libffi.so.5"
    shutil.copy2(Path(__file__).parents[1] / "integration" / "libffi.so.5", elf)
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp27-none-linux_x86_64.whl",
        {
            "demo/__init__.py": b"",
            "demo/libffi.so.5": elf.read_bytes(),
        },
    )
    members = _snapshot_wheel(wheel)
    by_name = {member.name: member for member in members}
    assert by_name["demo/__init__.py"].kind == "file"
    assert by_name["demo/libffi.so.5"].kind == "elf"
    assert by_name["demo/libffi.so.5"].needed == ("libc.so.6",)


def test_json_path_is_used_verbatim(tmp_path: Path) -> None:
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp27-none-linux_x86_64.whl",
        {"demo/__init__.py": b""},
    )
    recorder = ProvenanceRecorder(
        wheel_path=wheel,
        abis=["manylinux_2_17_x86_64"],
        lib_sdir=".libs",
        strip=False,
        update_tags=True,
        workspace_root=None,
    )
    recorder.bind(tmp_path)
    output = _write_wheel(
        tmp_path / "demo-0.0.1-cp27-none-manylinux_2_17_x86_64.whl",
        {"demo/__init__.py": b""},
    )
    target = tmp_path / "evidence.json"
    written = recorder.write(output, target)
    assert written == target
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["schema"] == "auditwheel-provenance"
    assert document["version"] == 1
    assert document["input_wheel"]["path"] == "demo-0.0.1-cp27-none-linux_x86_64.whl"
    assert sha256_file(wheel) == document["input_wheel"]["sha256"]
    assert sha256_file(output) == document["output_wheel"]["sha256"]
    assert verify_provenance(target) == []


def test_directory_target_uses_wheel_name(tmp_path: Path) -> None:
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp27-none-linux_x86_64.whl",
        {"demo/__init__.py": b""},
    )
    recorder = ProvenanceRecorder(
        wheel_path=wheel,
        abis=["manylinux_2_17_x86_64"],
        lib_sdir=".libs",
        strip=False,
        update_tags=True,
        workspace_root=tmp_path,
    )
    recorder.bind(tmp_path)
    output = wheel
    document = recorder.write(output, tmp_path / "evidence")
    assert document.name == f"{output.name}.provenance.json"
    assert document.parent == tmp_path / "evidence"


def test_external_sources_use_basename_only(tmp_path: Path) -> None:
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp27-none-linux_x86_64.whl",
        {"demo/__init__.py": b""},
    )
    source = tmp_path / "outside" / "libffi.so.5"
    source.parent.mkdir()
    source.write_bytes(b"library")
    recorder = ProvenanceRecorder(
        wheel_path=wheel,
        abis=["manylinux_2_17_x86_64"],
        lib_sdir=".libs",
        strip=False,
        update_tags=True,
        workspace_root=tmp_path / "workspace",
    )
    recorder.bind(tmp_path)
    recorder.reference(
        tmp_path / "demo" / "extension.so",
        "libffi.so.5",
        source,
        status="resolved",
        policy="manylinux_2_17_x86_64",
    )
    output = _write_wheel(
        tmp_path / "out.whl",
        {"demo/__init__.py": b""},
    )
    document_path = recorder.write(output, tmp_path / "evidence")
    document = json.loads(document_path.read_text(encoding="utf-8"))
    payload = document["references"][0]["source"]
    assert payload["scope"] == "external"
    assert payload["path"] == "libffi.so.5"
    assert payload["sha256"] == sha256_file(source)


def test_member_name_after_shim(tmp_path: Path) -> None:
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp27-none-linux_x86_64.whl",
        {"demo/__init__.py": b""},
    )
    recorder = ProvenanceRecorder(
        wheel_path=wheel,
        abis=["manylinux_2_17_x86_64"],
        lib_sdir=".libs",
        strip=False,
        update_tags=True,
        workspace_root=tmp_path,
    )
    recorder.bind(tmp_path)
    old = tmp_path / "demo-0.0.1.data" / "scripts" / "tool"
    old.parent.mkdir(parents=True)
    old.write_bytes(b"")
    recorder.record_step("strip_symbols", old)
    new = tmp_path / "demo.scripts" / "tool"
    new.parent.mkdir()
    new.write_bytes(b"")
    recorder.record_relocation(old, new)
    output = _write_wheel(
        tmp_path / "out.whl",
        {"demo/__init__.py": b""},
    )
    document_path = recorder.write(output, tmp_path / "evidence")
    document = json.loads(document_path.read_text(encoding="utf-8"))
    strip = next(
        step for step in document["rewrite_steps"] if step["operation"] == "strip_symbols"
    )
    assert strip["member"] == "demo.scripts/tool"


def test_explain_unknown_member(tmp_path: Path) -> None:
    document = {"index": {"repaired_members": {}}, "references": [], "rewrite_steps": []}
    assert explain_member(document, "missing.so") == {
        "member": "missing.so",
        "found": False,
    }


def test_explain_member_merges_referrer_steps() -> None:
    document = {
        "references": [
            {
                "id": "ref-0001",
                "referrer": {"member": "pkg/ext.so", "sha256": "abc"},
                "rewrite_steps": [2],
            }
        ],
        "rewrite_steps": [
            {"step": 1, "operation": "copy_library"},
            {"step": 2, "operation": "replace_needed"},
            {"step": 3, "operation": "set_soname"},
        ],
        "index": {
            "repaired_members": {
                "pkg.libs/libx.so": {
                    "kind": "graft",
                    "graft": "graft-0001",
                    "references": ["ref-0001"],
                    "rewrite_steps": [1, 3],
                }
            }
        },
    }
    explanation = explain_member(document, "pkg.libs/libx.so")
    assert explanation["found"] is True
    assert explanation["input_members"] == [{"member": "pkg/ext.so", "sha256": "abc"}]
    assert [step["step"] for step in explanation["rewrite_steps"]] == [1, 2, 3]


def test_verify_flags_missing_document(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(FileNotFoundError):
        verify_provenance(missing)


def test_recorder_rejects_unknown_schema(tmp_path: Path) -> None:
    document = tmp_path / "document.json"
    document.write_text(json.dumps({"schema": "other", "version": 1}))
    assert verify_provenance(document) == [f"unsupported provenance document: {document}"]


def test_recorded_at_is_iso(tmp_path: Path) -> None:
    wheel = _write_wheel(
        tmp_path / "demo-0.0.1-cp27-none-linux_x86_64.whl",
        {"demo/__init__.py": b""},
    )
    recorder = ProvenanceRecorder(
        wheel_path=wheel,
        abis=["manylinux_2_17_x86_64"],
        lib_sdir=".libs",
        strip=False,
        update_tags=True,
        workspace_root=tmp_path,
    )
    recorder.bind(tmp_path)
    document_path = recorder.write(wheel, tmp_path / "evidence")
    document = json.loads(document_path.read_text(encoding="utf-8"))
    assert document["generated_at"].endswith("+00:00")
    assert provenance.DIGEST_ALGORITHM == "sha256"
