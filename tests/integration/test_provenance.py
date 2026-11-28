from __future__ import annotations

import dataclasses
import json
import shutil
import sys
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from auditwheel.architecture import Architecture
from auditwheel.libc import Libc
from auditwheel.patcher import ElfPatcher
from auditwheel.provenance import explain_member, verify_provenance
from auditwheel.repair import repair_wheel
from auditwheel.wheel_abi import analyze_wheel_abi

if TYPE_CHECKING:
    from collections.abc import Iterator

HERE = Path(__file__).parent.resolve()
DEMO_BUILDER = HERE / "provenance_demo"
sys.path.insert(0, str(DEMO_BUILDER))

import build_demo  # noqa: E402

POLICY = "manylinux_2_17_x86_64"
ABIS = [POLICY, "manylinux2014_x86_64", "linux_x86_64"]


class _InMemoryElfPatcher(ElfPatcher):
    """Apply no patches but keep real rpath lookup out of the test."""

    def get_rpath_direct(self, file_name: Path) -> str:
        return ""

    def apply_updates(self) -> None:
        self._updates.clear()


@pytest.fixture
def workspace(tmp_path: Path) -> Iterator[Path]:
    root = tmp_path / "workspace"
    (root / "input").mkdir(parents=True)
    (root / "libs").mkdir()
    (root / "output").mkdir()
    (root / "evidence").mkdir()
    yield root


def _repair(workspace: Path, provenance: Path) -> tuple[Path, dict[str, object]]:
    wheel = build_demo.build_demo_wheel(workspace / "input")
    library_dir = workspace / "libs"
    build_demo.stage_library(library_dir)
    wheel_abi = analyze_wheel_abi(
        Libc.GLIBC,
        Architecture.x86_64,
        wheel.resolve(),
        frozenset(),
        disable_isa_ext_check=True,
        allow_graft=True,
        requested_policy_base_name=POLICY,
        args_ldpaths=str(library_dir.resolve()),
    )
    output = repair_wheel(
        wheel_abi,
        wheel.resolve(),
        abis=ABIS,
        lib_sdir=".libs",
        out_dir=(workspace / "output").resolve(),
        update_tags=True,
        patcher=_InMemoryElfPatcher(POLICY),
        strip=False,
        zip_compression_level=6,
        provenance_path=provenance,
    )
    assert output is not None
    document_path = provenance / f"{output.name}.provenance.json"
    document = json.loads(document_path.read_text(encoding="utf-8"))
    return document_path, document


def test_shared_graft_keeps_per_referrer_evidence(workspace: Path) -> None:
    document_path, document = _repair(workspace, workspace / "evidence")

    referrers = {
        reference["referrer"]["member"]
        for reference in document["references"]
        if reference["soname"] == "libffi.so.5"
    }
    assert referrers == {
        "provenance_demo/_cffi_backend.so",
        "provenance_demo/tests/member_a.so",
        "provenance_demo/tests/member_b.so",
    }

    grafts = document["grafts"]
    assert len(grafts) == 1
    graft = grafts[0]
    assert graft["original_soname"] == "libffi.so.5"
    assert graft["new_soname"].startswith("libffi-")
    assert graft["source"]["sha256"] == graft["repaired_member"]["sha256"]

    libffi_refs = [ref for ref in document["references"] if ref["soname"] == "libffi.so.5"]
    assert {ref["graft"] for ref in libffi_refs} == {graft["id"]}
    # Each entry point keeps its own referrer digest and its own copy step.
    assert len({ref["referrer"]["sha256"] for ref in libffi_refs}) == 3
    assert all(ref["source"]["sha256"] == graft["source"]["sha256"] for ref in libffi_refs)
    for reference in libffi_refs:
        operations = {
            step["operation"]
            for step in document["rewrite_steps"]
            if step["step"] in reference["rewrite_steps"]
        }
        assert "replace_needed" in operations
        assert operations & {"copy_library", "reuse_graft"}
        # No evidence from another entry point leaks into this reference.
        for step in document["rewrite_steps"]:
            if step["step"] not in reference["rewrite_steps"]:
                continue
            if step["operation"] == "replace_needed":
                assert [reference["soname"], graft["new_soname"]] in step["pairs"]

    # The graft naming step records the rename from the source soname.
    soname_steps = [
        step for step in document["rewrite_steps"] if step["operation"] == "set_soname"
    ]
    assert soname_steps and soname_steps[0]["member"] == graft["repaired_member"]["member"]

    # A repaired member can be looked up directly.
    index = document["index"]["repaired_members"][graft["repaired_member"]["member"]]
    assert index["graft"] == graft["id"]
    assert set(index["references"]) == {ref["id"] for ref in libffi_refs}
    assert index["rewrite_steps"]

    # Look up a repaired referrer directly, then walk to its input and steps.
    repaired_referrer = "provenance_demo/_cffi_backend.so"
    referrer_ids = document["index"]["repaired_members"][repaired_referrer]["references"]
    assert referrer_ids
    for reference_id in referrer_ids:
        reference = next(item for item in document["references"] if item["id"] == reference_id)
        assert reference["referrer"]["member"] == repaired_referrer
        assert reference["rewrite_steps"]
    direct = document["index"]["repaired_references"][
        f"{repaired_referrer}|libffi.so.5"
    ]
    assert direct["reference"] in referrer_ids
    assert direct["graft"] == graft["id"]
    assert direct["repaired_member"] == graft["repaired_member"]["member"]
    direct_ref = next(
        item for item in document["references"] if item["id"] == direct["reference"]
    )
    assert direct_ref["soname"] == "libffi.so.5"
    assert direct_ref["source"]["sha256"] == graft["source"]["sha256"]

    # Source and output digests are independently stored and match the files.
    assert document["input_wheel"]["sha256"] != document["output_wheel"]["sha256"]
    assert verify_provenance(document_path) == []
    absolute = [
        value
        for value in _walk_strings(document)
        if value.startswith(("/tmp", "/private", "/Users", "/home", "/opt"))
    ]
    assert absolute == []

    # The document, input wheel, output wheel and staged source library move
    # together without rewriting any path.
    relocated = workspace.parent / "relocated"
    shutil.copytree(workspace, relocated)
    relocated_doc = relocated / document_path.relative_to(workspace)
    assert verify_provenance(relocated_doc) == []


def test_repaired_member_resolves_to_input_and_rewrites(workspace: Path) -> None:
    document_path, document = _repair(workspace, workspace / "evidence")
    output_wheel = workspace / "output" / document["output_wheel"]["name"]

    with zipfile.ZipFile(output_wheel) as archive:
        names = set(archive.namelist())
    grafted = [
        name
        for name in names
        if name.startswith("provenance_demo.libs/") and name.endswith(".so.5")
    ]
    assert len(grafted) == 1
    graft_member = grafted[0]
    index = document["index"]["repaired_members"][graft_member]

    references = {
        reference["id"]: reference
        for reference in document["references"]
    }
    input_members = {
        member["name"]: member for member in document["input_wheel"]["members"]
    }
    tracked = [references[reference_id] for reference_id in index["references"]]
    assert len(tracked) == 3
    assert index["kind"] == "graft"
    for reference in tracked:
        assert reference["referrer"]["member"] in input_members
        member = input_members[reference["referrer"]["member"]]
        assert reference["referrer"]["sha256"] == member["sha256"]
        assert reference["graft"] == index["graft"]
    assert {
        reference["referrer"]["member"] for reference in tracked
    } == {
        "provenance_demo/_cffi_backend.so",
        "provenance_demo/tests/member_a.so",
        "provenance_demo/tests/member_b.so",
    }
    explanation = explain_member(document, graft_member)
    assert explanation["found"] is True
    assert explanation["kind"] == "graft"
    assert {
        item["member"] for item in explanation["input_members"]
    } == {
        "provenance_demo/_cffi_backend.so",
        "provenance_demo/tests/member_a.so",
        "provenance_demo/tests/member_b.so",
    }
    assert any(
        step["operation"] == "replace_needed" for step in explanation["rewrite_steps"]
    )
    assert any(
        step["operation"] == "set_soname" for step in explanation["rewrite_steps"]
    )


def test_cli_repair_writes_evidence(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditwheel.main import main

    wheel = build_demo.build_demo_wheel(workspace / "input")
    library_dir = workspace / "libs"
    build_demo.stage_library(library_dir)
    evidence = workspace / "cli-evidence"

    argv = [
        "auditwheel",
        "repair",
        "-w",
        str(workspace / "output"),
        "--plat",
        POLICY,
        "--only-plat",
        "--disable-isa-ext-check",
        "--patcher",
        "none",
        "--ldpaths",
        str(library_dir),
        "--provenance",
        str(evidence),
        str(wheel),
    ]
    monkeypatch.delenv("AUDITWHEEL_LD_LIBRARY_PATH", raising=False)
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(Architecture, "detect", lambda **_: Architecture.x86_64)
    monkeypatch.setattr(Libc, "detect", lambda: Libc.GLIBC)

    def fake_analyze(*_args, **_kwargs):
        real = analyze_wheel_abi(
            Libc.GLIBC,
            Architecture.x86_64,
            wheel.resolve(),
            frozenset(),
            disable_isa_ext_check=True,
            allow_graft=True,
            requested_policy_base_name=POLICY,
            args_ldpaths=str(library_dir.resolve()),
        )
        return dataclasses.replace(
            real,
            ucs_policy=real.policies.highest,
            pyfpe_policy=real.policies.highest,
            blacklist_policy=real.policies.highest,
            machine_policy=real.policies.highest,
            sym_policy=real.policies.highest,
            overall_policy=real.policies.highest,
        )

    monkeypatch.setattr("auditwheel.wheel_abi.analyze_wheel_abi", fake_analyze)
    monkeypatch.setattr(
        "auditwheel.patcher.ElfPatcher.get_patcher",
        lambda *_args, **_kwargs: _InMemoryElfPatcher(POLICY),
    )
    assert main() == 0

    documents = list(evidence.glob("*.provenance.json"))
    assert len(documents) == 1
    document = json.loads(documents[0].read_text(encoding="utf-8"))
    grafts = document["grafts"]
    assert len(grafts) == 1
    libffi_refs = [
        reference for reference in document["references"] if reference["soname"] == "libffi.so.5"
    ]
    assert {reference["graft"] for reference in libffi_refs} == {grafts[0]["id"]}
    assert len(libffi_refs) == 3
    assert not verify_provenance(documents[0])


def test_verification_detects_tampering(workspace: Path) -> None:
    document_path, document = _repair(workspace, workspace / "evidence")
    assert verify_provenance(document_path) == []

    output_wheel = workspace / "output" / document["output_wheel"]["name"]
    output_wheel.write_bytes(output_wheel.read_bytes() + b"x")
    problems = verify_provenance(document_path)
    assert any("output_wheel digest mismatch" in problem for problem in problems)

    source = workspace / "libs" / "libffi.so.5"
    source.write_bytes(source.read_bytes() + b"x")
    problems = verify_provenance(
        document_path,
        output_wheel=output_wheel.parent / "missing.whl",
    )
    assert any("output_wheel file not found" in problem for problem in problems)
    assert any("graft source digest mismatch" in problem for problem in problems)


def _walk_strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)


def test_cli_provenance_verifies(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from auditwheel.main import main

    document_path, _ = _repair(workspace, workspace / "evidence")

    monkeypatch.setattr(sys, "argv", ["auditwheel", "provenance", str(document_path)])
    assert main() == 0
    assert "OK" in capsys.readouterr().out

    monkeypatch.setattr(
        sys,
        "argv",
        ["auditwheel", "provenance", "--json", str(document_path)],
    )
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["grafts"] == 1

    document = json.loads(document_path.read_text(encoding="utf-8"))
    graft_member = document["grafts"][0]["repaired_member"]["member"]
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "auditwheel",
            "provenance",
            "--json",
            "--member",
            graft_member,
            str(document_path),
        ],
    )
    assert main() == 0
    explanation = json.loads(capsys.readouterr().out)
    assert explanation["found"] is True
    assert explanation["kind"] == "graft"
    assert len(explanation["input_members"]) == 3
