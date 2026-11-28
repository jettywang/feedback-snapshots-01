from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditwheel.architecture import Architecture
from auditwheel.libc import Libc, LibcVersion
from auditwheel.main import main


@pytest.fixture
def linux_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(Architecture, "detect", lambda: Architecture.x86_64)
    monkeypatch.setattr(Libc, "detect", lambda: Libc.GLIBC)
    monkeypatch.setattr(Libc, "get_current_version", lambda _self: LibcVersion(2, 28))


def _attestation(tmp_path: Path) -> Path:
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps({"version": 1, "patches": []}))
    return path


def test_repair_rejects_malformed_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    linux_host: None,
) -> None:
    del linux_host
    wheel = tmp_path / "demo-0.1-cp312-cp312-linux_x86_64.whl"
    wheel.write_bytes(b"")
    attestation = tmp_path / "bad.json"
    attestation.write_text("{not json")
    monkeypatch.setattr(
        "sys.argv",
        ["auditwheel", "repair", "--patch-attestation", str(attestation), str(wheel)],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2
    assert "invalid JSON" in capsys.readouterr().err


def test_repair_requires_a_readable_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    linux_host: None,
) -> None:
    del linux_host
    wheel = tmp_path / "demo-0.1-cp312-cp312-linux_x86_64.whl"
    wheel.write_bytes(b"")
    monkeypatch.setattr(
        "sys.argv",
        [
            "auditwheel",
            "repair",
            "--patch-attestation",
            str(tmp_path / "missing.json"),
            str(wheel),
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2
    assert "cannot read" in capsys.readouterr().err


def test_show_writes_patch_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    linux_host: None,
) -> None:
    del linux_host
    from auditwheel.wheel_abi import WheelAbIInfo

    class _Policies:
        def __init__(self) -> None:
            self.linux = object()
            self.lowest = type("Low", (), {"name": "manylinux_2_17_x86_64"})()
            self.highest = type("High", (), {"name": "manylinux_2_28_x86_64"})()

        def __iter__(self):
            return iter(())

    policies = _Policies()
    overall = type("Overall", (), {"name": "manylinux_2_17_x86_64"})()
    winfo = WheelAbIInfo(
        policies=policies,  # type: ignore[arg-type]
        full_external_refs={},
        overall_policy=overall,  # type: ignore[arg-type]
        external_refs={
            "manylinux_2_28_x86_64": type("Ref", (), {"libs": {}, "blacklist": {}})()
        },
        ref_policy=overall,  # type: ignore[arg-type]
        versioned_symbols={},
        sym_policy=overall,  # type: ignore[arg-type]
        ucs_policy=None,  # type: ignore[arg-type]
        pyfpe_policy=None,  # type: ignore[arg-type]
        blacklist_policy=None,  # type: ignore[arg-type]
        machine_policy=None,  # type: ignore[arg-type]
        graft_policy=None,  # type: ignore[arg-type]
        wheel_path=tmp_path / "demo-0.1-cp312-cp312-linux_x86_64.whl",
    )

    monkeypatch.setattr("auditwheel.wheel_abi.analyze_wheel_abi", lambda *_a, **_k: winfo)
    wheel = tmp_path / "demo-0.1-cp312-cp312-linux_x86_64.whl"
    wheel.write_bytes(b"")
    report = tmp_path / "report.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "auditwheel",
            "show",
            "--json",
            "--patch-attestation",
            str(_attestation(tmp_path)),
            "--patch-report",
            str(report),
            str(wheel),
        ],
    )

    assert main() == 0
    payload = json.loads(report.read_text())
    assert payload["version"] == 1
    assert payload["policy"] == "manylinux_2_17_x86_64"
    assert payload["libraries"] == []
    assert payload["passed"] is True


def test_repair_stops_before_patcher_when_selection_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    linux_host: None,
) -> None:
    del linux_host
    import hashlib

    from auditwheel.patch_audit import PatchAttestation, evaluate_graft_plan
    from auditwheel.policy import ExternalReference
    from auditwheel.wheel_abi import WheelAbIInfo

    wheel = tmp_path / "demo-0.1-cp312-cp312-linux_x86_64.whl"
    wheel.write_bytes(b"")
    reviewed = tmp_path / "reviewed.so.1"
    reviewed.write_bytes(b"patched")
    selected = tmp_path / "selected.so.1"
    selected.write_bytes(b"plain")
    attestation_path = tmp_path / "attestation.json"
    attestation_path.write_text(
        json.dumps(
            {
                "version": 1,
                "patches": [
                    {
                        "soname": "libfoo.so.1",
                        "candidates": [
                            {
                                "id": "patched",
                                "path": str(reviewed),
                                "sha256": hashlib.sha256(b"patched").hexdigest(),
                            }
                        ],
                    }
                ],
            }
        )
    )

    policy_name = "manylinux_2_5_x86_64"
    policy = type(
        "P",
        (),
        {
            "name": policy_name,
            "priority": 100,
            "aliases": (),
            "__lt__": lambda self, other: self.priority < other.priority,
            "__gt__": lambda self, other: self.priority > other.priority,
            "__le__": lambda self, other: self.priority <= other.priority,
            "__ge__": lambda self, other: self.priority >= other.priority,
            "__eq__": lambda self, other: self.priority == other.priority,
            "__hash__": lambda self: hash(self.priority),
        },
    )()
    policies = type(
        "Policies",
        (),
        {
            "linux": policy,
            "lowest": policy,
            "architecture": type("A", (), {"value": "x86_64"})(),
            "get_policy_by_name": lambda _self, _name: policy,
            "__iter__": lambda _self: iter(()),
        },
    )()
    ref = ExternalReference({"libfoo.so.1": selected}, {}, policy)  # type: ignore[arg-type]
    winfo = WheelAbIInfo(
        policies=policies,  # type: ignore[arg-type]
        full_external_refs={tmp_path / "ext.so": {policy_name: ref}},
        overall_policy=policy,  # type: ignore[arg-type]
        external_refs={policy_name: ref},
        ref_policy=policy,  # type: ignore[arg-type]
        versioned_symbols={},
        sym_policy=policy,  # type: ignore[arg-type]
        ucs_policy=policy,  # type: ignore[arg-type]
        pyfpe_policy=policy,  # type: ignore[arg-type]
        blacklist_policy=policy,  # type: ignore[arg-type]
        machine_policy=policy,  # type: ignore[arg-type]
        graft_policy=policy,  # type: ignore[arg-type]
        wheel_path=wheel,
    )

    report = evaluate_graft_plan(
        winfo,
        policy_name,
        PatchAttestation.load(attestation_path),
    )
    assert not report.passed
    monkeypatch.setattr("auditwheel.wheel_abi.analyze_wheel_abi", lambda *_a, **_k: winfo)

    def _patcher_must_not_run(*_args, **_kwargs):
        pytest.fail("patcher must not be created for a rejected selection")

    monkeypatch.setattr("auditwheel.patcher.ElfPatcher.get_patcher", _patcher_must_not_run)
    monkeypatch.setattr(
        "sys.argv",
        [
            "auditwheel",
            "repair",
            "--patch-attestation",
            str(attestation_path),
            "--patch-report",
            str(tmp_path / "report.json"),
            str(wheel),
        ],
    )

    assert main() == 1
    written = json.loads((tmp_path / "report.json").read_text())
    assert written["passed"] is False
    assert written["libraries"][0]["status"] == "unapproved"
