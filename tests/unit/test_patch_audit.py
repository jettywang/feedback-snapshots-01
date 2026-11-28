from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest

from auditwheel.patch_audit import (
    CoverageReport,
    DeliveredLibrary,
    LibraryVerdict,
    PatchAttestation,
    PatchAttestationError,
    PatchCoverageError,
    evaluate_graft_plan,
    verify_delivered_libraries,
)
from auditwheel.policy import ExternalReference
from auditwheel.repair import repair_wheel
from auditwheel.wheel_abi import WheelAbIInfo, WheelBundledLibrary

POLICY_NAME = "manylinux_2_5_x86_64"


class _Policy:
    def __init__(self, name: str = POLICY_NAME) -> None:
        self.name = name


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_attestation(tmp_path: Path, payload: dict[str, Any]) -> Path:
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _library(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _attestation(
    tmp_path: Path,
    soname: str,
    candidates: list[dict[str, Any]],
) -> PatchAttestation:
    path = _write_attestation(
        tmp_path,
        {"version": 1, "patches": [{"soname": soname, "candidates": candidates}]},
    )
    return PatchAttestation.load(path)


def _abi(
    *,
    external: dict[str, Path | None],
    wheel_path: Path,
    bundled: dict[str, list[WheelBundledLibrary]] | None = None,
    function_name: str = "pkg/ext.so",
) -> WheelAbIInfo:
    policy = _Policy()
    external_ref = ExternalReference(dict(external), {}, policy)  # type: ignore[arg-type]
    fn = wheel_path / function_name
    return WheelAbIInfo(
        policies=None,  # type: ignore[arg-type]
        full_external_refs={fn: {POLICY_NAME: external_ref}},
        overall_policy=None,  # type: ignore[arg-type]
        external_refs={POLICY_NAME: external_ref},
        ref_policy=None,  # type: ignore[arg-type]
        versioned_symbols={},
        sym_policy=None,  # type: ignore[arg-type]
        ucs_policy=None,  # type: ignore[arg-type]
        pyfpe_policy=None,  # type: ignore[arg-type]
        blacklist_policy=None,  # type: ignore[arg-type]
        machine_policy=None,  # type: ignore[arg-type]
        graft_policy=None,  # type: ignore[arg-type]
        wheel_path=wheel_path,
        bundled_libs={} if bundled is None else bundled,
    )


def _evaluate(
    abi: WheelAbIInfo,
    attestation: PatchAttestation | None,
    *,
    require: bool = False,
) -> CoverageReport:
    return evaluate_graft_plan(abi, POLICY_NAME, attestation, require)


class TestAttestationLoading:
    def test_loads_candidates(self, tmp_path: Path) -> None:
        library = _library(tmp_path, "libfoo.so.1", b"foo")
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [{"id": "foo", "path": str(library), "sha256": _sha(b"foo")}],
        )
        (candidate,) = attestation.for_soname("libfoo.so.1")
        assert candidate.candidate_id == "foo"
        assert candidate.sha256 == _sha(b"foo")

    def test_rejects_unknown_version(self, tmp_path: Path) -> None:
        path = _write_attestation(tmp_path, {"version": 99, "patches": []})
        with pytest.raises(PatchAttestationError, match="unsupported attestation version"):
            PatchAttestation.load(path)

    def test_rejects_duplicate_soname(self, tmp_path: Path) -> None:
        path = _write_attestation(
            tmp_path,
            {
                "version": 1,
                "patches": [
                    {"soname": "libfoo.so.1", "candidates": [{"path": "/a"}]},
                    {"soname": "libfoo.so.1", "candidates": [{"path": "/b"}]},
                ],
            },
        )
        with pytest.raises(PatchAttestationError, match="duplicate SONAME"):
            PatchAttestation.load(path)

    def test_rejects_candidate_without_identity(self, tmp_path: Path) -> None:
        path = _write_attestation(
            tmp_path,
            {
                "version": 1,
                "patches": [{"soname": "libfoo.so.1", "candidates": [{}]}],
            },
        )
        with pytest.raises(PatchAttestationError, match="must provide 'path' and/or 'sha256'"):
            PatchAttestation.load(path)

    def test_rejects_malformed_sha256(self, tmp_path: Path) -> None:
        path = _write_attestation(
            tmp_path,
            {
                "version": 1,
                "patches": [{"soname": "libfoo.so.1", "candidates": [{"sha256": "ABCD"}]}],
            },
        )
        with pytest.raises(PatchAttestationError, match="lowercase hex SHA-256"):
            PatchAttestation.load(path)


class TestSelectionVerdicts:
    def test_approved_when_selected_content_matches(self, tmp_path: Path) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        selected = _library(tmp_path, "libfoo.so.1", b"patched")
        reviewed = _library(tmp_path, "reviewed.so.1", b"patched")
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [{"id": "patched", "path": str(reviewed), "sha256": _sha(b"patched")}],
        )

        report = _evaluate(_abi(external={"libfoo.so.1": selected}, wheel_path=wheel), attestation)

        (verdict,) = report.libraries
        assert verdict.status == "approved"
        assert verdict.accepted
        assert report.passed
        assert verdict.scope == "external"
        assert verdict.candidate_id == "patched"

    def test_unapproved_when_other_distribution_is_selected(self, tmp_path: Path) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        approved = _library(tmp_path, "libfoo-patched.so.1", b"patched")
        other_distro = _library(tmp_path, "libfoo-plain.so.1", b"plain")
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [{"id": "patched", "path": str(approved), "sha256": _sha(b"patched")}],
        )

        report = _evaluate(
            _abi(external={"libfoo.so.1": other_distro}, wheel_path=wheel),
            attestation,
        )

        (verdict,) = report.libraries
        assert verdict.status == "unapproved"
        assert not report.passed
        assert verdict.selected_sha256 == _sha(b"plain")

    def test_stale_when_content_changed_at_reviewed_path(self, tmp_path: Path) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        selected = _library(tmp_path, "libfoo.so.1", b"changed")
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [{"id": "patched", "path": str(selected), "sha256": _sha(b"patched")}],
        )

        (verdict,) = _evaluate(
            _abi(external={"libfoo.so.1": selected}, wheel_path=wheel),
            attestation,
        ).libraries

        assert verdict.status == "stale"
        assert "content changed" in verdict.reason

    def test_rejected_when_candidate_not_reviewed(self, tmp_path: Path) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        selected = _library(tmp_path, "libfoo.so.1", b"foo")
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [
                {
                    "id": "pending",
                    "path": str(selected),
                    "sha256": _sha(b"foo"),
                    "reviewed": False,
                }
            ],
        )

        (verdict,) = _evaluate(
            _abi(external={"libfoo.so.1": selected}, wheel_path=wheel),
            attestation,
        ).libraries

        assert verdict.status == "rejected"
        assert not report_passes(verdict)

    def test_unresolved_when_library_cannot_be_located(self, tmp_path: Path) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [{"id": "patched", "sha256": _sha(b"foo")}],
        )

        (verdict,) = _evaluate(
            _abi(external={"libfoo.so.1": None}, wheel_path=wheel),
            attestation,
        ).libraries

        assert verdict.status == "unresolved"

    def test_conflict_when_two_functions_resolve_different_files(self, tmp_path: Path) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        first = _library(tmp_path, "a.so.1", b"a")
        second = _library(tmp_path, "b.so.1", b"b")
        policy = _Policy()
        abi = WheelAbIInfo(
            policies=None,  # type: ignore[arg-type]
            full_external_refs={
                wheel / "pkg/a.so": {
                    POLICY_NAME: ExternalReference({"libfoo.so.1": first}, {}, policy)  # type: ignore[arg-type]
                },
                wheel / "pkg/b.so": {
                    POLICY_NAME: ExternalReference({"libfoo.so.1": second}, {}, policy)  # type: ignore[arg-type]
                },
            },
            overall_policy=None,  # type: ignore[arg-type]
            external_refs={},
            ref_policy=None,  # type: ignore[arg-type]
            versioned_symbols={},
            sym_policy=None,  # type: ignore[arg-type]
            ucs_policy=None,  # type: ignore[arg-type]
            pyfpe_policy=None,  # type: ignore[arg-type]
            blacklist_policy=None,  # type: ignore[arg-type]
            machine_policy=None,  # type: ignore[arg-type]
            graft_policy=None,  # type: ignore[arg-type]
            wheel_path=wheel,
        )

        (verdict,) = _evaluate(abi, None).libraries

        assert verdict.status == "conflict"
        assert "multiple files" in verdict.reason


def report_passes(verdict: LibraryVerdict) -> bool:
    report = CoverageReport("w", POLICY_NAME, None, False, [verdict])
    return report.passed


class TestBackports:
    def _report(
        self,
        tmp_path: Path,
        candidate: dict[str, Any],
        *,
        selected_data: bytes = b"patched",
    ) -> LibraryVerdict:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        selected = _library(tmp_path, "libfoo.so.1", selected_data)
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [{"id": "candidate", "path": str(selected), "sha256": _sha(selected_data), **candidate}],
        )
        (verdict,) = _evaluate(
            _abi(external={"libfoo.so.1": selected}, wheel_path=wheel),
            attestation,
        ).libraries
        return verdict

    def test_backport_with_unchanged_version_is_approved(self, tmp_path: Path) -> None:
        verdict = self._report(
            tmp_path,
            {
                "backport": True,
                "patch": "CVE-2026-0001",
                "ext_version": "3.4.2",
                "upstream_version": "3.4.2",
            },
        )
        assert verdict.status == "approved-backport"
        assert verdict.accepted
        assert verdict.backport
        assert verdict.patch == "CVE-2026-0001"

    def test_patch_without_backport_marker_is_stale(self, tmp_path: Path) -> None:
        verdict = self._report(
            tmp_path,
            {"patch": "CVE-2026-0001", "ext_version": "3.4.2", "upstream_version": "3.4.2"},
        )
        assert verdict.status == "stale"
        assert "without changing the version" in verdict.reason

    def test_backport_requires_patch_identity(self, tmp_path: Path) -> None:
        verdict = self._report(
            tmp_path,
            {"backport": True, "ext_version": "3.4.2", "upstream_version": "3.4.2"},
        )
        assert verdict.status == "stale"
        assert "missing patch" in verdict.reason

    def test_backport_with_version_bump_is_stale(self, tmp_path: Path) -> None:
        verdict = self._report(
            tmp_path,
            {
                "backport": True,
                "patch": "CVE-2026-0001",
                "ext_version": "3.4.3",
                "upstream_version": "3.4.2",
            },
        )
        assert verdict.status == "stale"
        assert "must keep the upstream version" in verdict.reason


class TestCoverageRequirements:
    def test_unattested_external_library_only_fails_when_required(self, tmp_path: Path) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        selected = _library(tmp_path, "libfoo.so.1", b"foo")

        optional = _evaluate(
            _abi(external={"libfoo.so.1": selected}, wheel_path=wheel),
            None,
        )
        (verdict,) = optional.libraries
        assert verdict.status == "uncovered"
        assert verdict.scope == "external"
        assert optional.passed
        assert not optional.coverage_complete

        required = _evaluate(
            _abi(external={"libfoo.so.1": selected}, wheel_path=wheel),
            None,
            require=True,
        )
        assert not required.passed
        assert required.failed_libraries[0].soname == "libfoo.so.1"

    def test_bundled_library_is_reported_separately(self, tmp_path: Path) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        (wheel / "pkg").mkdir()
        bundled_file = wheel / "pkg" / "libbar.so.2"
        bundled_file.write_bytes(b"bar")
        abi = _abi(
            external={},
            wheel_path=wheel,
            bundled={
                "libbar.so.2": [WheelBundledLibrary("libbar.so.2", "pkg/libbar.so.2", _sha(b"bar"))]
            },
        )

        report = _evaluate(abi, None)

        (verdict,) = report.libraries
        assert verdict.scope == "bundled"
        assert verdict.member == "pkg/libbar.so.2"
        assert verdict.selected_sha256 == _sha(b"bar")
        # Bundled libraries are reported, but they are not grafted by auditwheel.
        assert report.passed


class TestBundledScopeIntegration:
    def test_library_shipped_in_wheel_is_reported_as_bundled(self, tmp_path: Path) -> None:
        import shutil
        import zipfile

        from auditwheel.tools import zip2dir
        from auditwheel.wheel_abi import analyze_wheel_abi

        source = Path(__file__).parent.parent / "bundled-wheels"
        wheel = source / "cffi-1.5.0-cp27-none-linux_x86_64.whl"
        staged = (tmp_path / "stage").resolve()
        zip2dir(wheel, staged)
        bundled_bytes = (Path(__file__).parent.parent / "integration" / "libffi.so.5").read_bytes()
        (staged / "libffi.so.5").write_bytes(bundled_bytes)
        from auditwheel.wheeltools import rewrite_record

        rewrite_record(staged)
        repacked = (tmp_path / wheel.name).resolve()
        with zipfile.ZipFile(repacked, "w") as zf:
            for file in sorted(staged.rglob("*")):
                if file.is_file():
                    zf.write(file, file.relative_to(staged).as_posix())

        winfo = analyze_wheel_abi(
            None,
            None,
            repacked,
            frozenset(),
            disable_isa_ext_check=False,
            allow_graft=True,
            args_ldpaths="",
        )
        assert "libffi.so.5" in winfo.bundled_libs
        (entry,) = winfo.bundled_libs["libffi.so.5"]
        assert entry.member == "libffi.so.5"
        assert entry.sha256 == _sha(bundled_bytes)
        assert winfo.external_refs[POLICY_NAME].libs["libffi.so.5"] is None

        report = evaluate_graft_plan(winfo, POLICY_NAME, None)
        by_scope = {(v.soname, v.scope): v for v in report.libraries}
        assert by_scope[("libffi.so.5", "bundled")].selected_sha256 == _sha(bundled_bytes)
        # No attestation was supplied, so the external entry is uncovered.
        assert by_scope[("libffi.so.5", "external")].status == "uncovered"
        assert by_scope[("libffi.so.5", "bundled")].scope == "bundled"
        assert by_scope[("libffi.so.5", "external")].shadowed is True
        del shutil


class TestDeliveryVerification:
    def _report(self, data: bytes) -> CoverageReport:
        return CoverageReport(
            "demo.whl",
            POLICY_NAME,
            "attestation.json",
            False,
            [
                LibraryVerdict(
                    "libfoo.so.1",
                    "external",
                    "/reviewed/libfoo.so.1",
                    _sha(data),
                    "approved",
                    "ok",
                    candidate_id="patched",
                )
            ],
        )

    def _wheel(self, path: Path, data: bytes) -> Path:
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("pkg/.libs/libfoo-abc.so.1", data)
            zf.writestr("pkg-0.1.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        return path

    def test_packed_file_matches_approved_source(self, tmp_path: Path) -> None:
        data = b"approved"
        wheel = self._wheel(tmp_path / "demo.whl", data)
        delivered = [
            DeliveredLibrary(
                "libfoo.so.1",
                "external",
                "pkg/.libs/libfoo-abc.so.1",
                _sha(data),
                _sha(data),
                False,
            )
        ]

        report = self._report(data)
        assert verify_delivered_libraries(report, wheel, delivered)
        assert report.repaired["passed"]
        assert report.repaired["libraries"][0]["delivered"]

    def test_detects_tampering_inside_repaired_wheel(self, tmp_path: Path) -> None:
        data = b"approved"
        wheel = self._wheel(tmp_path / "demo.whl", b"tampered")
        delivered = [
            DeliveredLibrary(
                "libfoo.so.1",
                "external",
                "pkg/.libs/libfoo-abc.so.1",
                _sha(data),
                _sha(data),
                False,
            )
        ]

        report = self._report(data)
        assert not verify_delivered_libraries(report, wheel, delivered)
        assert not report.repaired["passed"]

    def test_detects_packaging_swappage(self, tmp_path: Path) -> None:
        data = b"approved"
        wheel = self._wheel(tmp_path / "demo.whl", b"swapped-during-packaging")
        delivered = [
            DeliveredLibrary(
                "libfoo.so.1",
                "external",
                "pkg/.libs/libfoo-abc.so.1",
                _sha(data),
                _sha(data),
                False,
                copied_sha256=_sha(data),
            )
        ]

        report = self._report(data)
        assert not verify_delivered_libraries(report, wheel, delivered)
        assert "verified grafted copy" in report.repaired["libraries"][0]["reason"]

    def test_detects_graft_corruption_before_packaging(self, tmp_path: Path) -> None:
        data = b"approved"
        corrupted = b"corrupted-graft"
        wheel = self._wheel(tmp_path / "demo.whl", corrupted)
        delivered = [
            DeliveredLibrary(
                "libfoo.so.1",
                "external",
                "pkg/.libs/libfoo-abc.so.1",
                _sha(data),
                _sha(corrupted),
                True,
                copied_sha256=_sha(corrupted),
            )
        ]

        report = self._report(data)
        assert not verify_delivered_libraries(report, wheel, delivered)
        assert "differs from the approved source" in report.repaired["libraries"][0]["reason"]

    def test_detects_missing_approved_member(self, tmp_path: Path) -> None:
        data = b"approved"
        wheel = tmp_path / "demo.whl"
        with zipfile.ZipFile(wheel, "w") as zf:
            zf.writestr("pkg-0.1.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        delivered = [
            DeliveredLibrary(
                "libfoo.so.1",
                "external",
                "pkg/.libs/libfoo-abc.so.1",
                _sha(data),
                _sha(data),
                False,
            )
        ]

        report = self._report(data)
        assert not verify_delivered_libraries(report, wheel, delivered)
        assert "missing" in report.repaired["libraries"][0]["reason"]

    def test_detects_grafted_library_without_approved_verdict(self, tmp_path: Path) -> None:
        data = b"approved"
        wheel = self._wheel(tmp_path / "demo.whl", data)
        delivered = [
            DeliveredLibrary("libevil.so.9", "external", "pkg/.libs/libevil.so.9", None, _sha(data), False)
        ]

        report = self._report(data)
        assert not verify_delivered_libraries(report, wheel, delivered)


class _FakeCtx:
    def __init__(self, path: Path, out_wheel: Path | None) -> None:
        self.path = path
        self.name = path
        self.out_wheel = out_wheel
        self.zip_compression_level = 0

    def __enter__(self) -> _FakeCtx:
        self._cwd = Path.cwd()
        os.chdir(self.path)
        return self

    def __exit__(self, *_exc: object) -> None:
        try:
            assert self.out_wheel is not None
            with zipfile.ZipFile(self.out_wheel, "w") as zf:
                for file in sorted(self.path.rglob("*")):
                    if file.is_file():
                        zf.write(file, file.relative_to(self.path).as_posix())
        finally:
            os.chdir(self._cwd)


class _StubPatcher:
    def __init__(self) -> None:
        self.updates: list[tuple[str, object]] = []

    def set_soname(self, path: Path, soname: str) -> None:
        self.updates.append(("soname", (path, soname)))

    def get_rpath(self, path: Path) -> str:
        return ""

    def set_rpath(self, path: Path, rpath: str) -> None:
        self.updates.append(("rpath", (path, rpath)))

    def clear_rpath(self, path: Path) -> None:
        self.updates.append(("clear_rpath", path))

    def replace_needed(self, path: Path, *pairs: tuple[str, str]) -> None:
        self.updates.append(("replace_needed", pairs))

    def remove_needed(self, path: Path, *sonames: str) -> None:
        self.updates.append(("remove_needed", sonames))

    def apply_updates(self) -> None:
        pass


class TestRepairPreflight:
    def test_blocks_before_copying_when_selection_is_not_approved(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        approved = _library(tmp_path, "libfoo-patched.so.1", b"patched")
        selected = _library(tmp_path, "libfoo-plain.so.1", b"plain")
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [{"id": "patched", "path": str(approved), "sha256": _sha(b"patched")}],
        )
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        report_path = tmp_path / "report.json"

        def _should_not_run(*_args: object, **_kwargs: object) -> None:
            pytest.fail("repair must not copy or patch a rejected selection")

        monkeypatch.setattr("auditwheel.repair.InWheelCtx", _should_not_run)
        monkeypatch.setattr("auditwheel.repair.copylib", _should_not_run)

        abi = _abi(external={"libfoo.so.1": selected}, wheel_path=wheel)
        with pytest.raises(PatchCoverageError, match="libfoo.so.1"):
            repair_wheel(
                abi,
                tmp_path / "demo-0.1-cp312-cp312-linux_x86_64.whl",
                abis=[POLICY_NAME],
                lib_sdir=".libs",
                out_dir=out_dir,
                update_tags=False,
                patcher=_StubPatcher(),  # type: ignore[arg-type]
                strip=False,
                zip_compression_level=0,
                patch_attestation=attestation,
                patch_report_path=report_path,
            )

        report = json.loads(report_path.read_text())
        assert report["passed"] is False
        (entry,) = report["libraries"]
        assert entry["status"] == "unapproved"
        assert not list(out_dir.iterdir())

    def test_repairs_and_confirms_the_packed_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        (wheel / "pkg").mkdir()
        (wheel / "pkg" / "ext.so").write_bytes(b"extension")
        dist_info = wheel / "demo-0.1.dist-info"
        dist_info.mkdir()
        (dist_info / "WHEEL").write_text("Wheel-Version: 1.0\n")
        selected = _library(tmp_path, "libfoo.so.1", b"patched")
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [{"id": "patched", "path": str(selected), "sha256": _sha(b"patched")}],
        )
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        report_path = tmp_path / "report.json"

        def _fake_ctx(in_wheel: Path, out_wheel: Path | None = None) -> _FakeCtx:
            del in_wheel, out_wheel
            return _FakeCtx(wheel, None)

        def _fake_copylib(src: Path, dest_dir: Path, patcher: object) -> tuple[str, Path]:
            del patcher
            (wheel / dest_dir).mkdir(exist_ok=True)
            dest = wheel / dest_dir / "libfoo-abc.so.1"
            dest.write_bytes(src.read_bytes())
            return dest.name, dest

        monkeypatch.setattr("auditwheel.repair.InWheelCtx", _fake_ctx)
        monkeypatch.setattr("auditwheel.repair.copylib", _fake_copylib)
        monkeypatch.setattr("auditwheel.repair.elf_read_dt_needed", lambda _path: [])
        monkeypatch.setattr("auditwheel.repair.create_sbom_for_wheel", lambda **_kw: None)

        abi = _abi(external={"libfoo.so.1": selected}, wheel_path=wheel)
        output = repair_wheel(
            abi,
            tmp_path / "demo-0.1-cp312-cp312-linux_x86_64.whl",
            abis=[POLICY_NAME],
            lib_sdir=".libs",
            out_dir=out_dir,
            update_tags=False,
            patcher=_StubPatcher(),  # type: ignore[arg-type]
            strip=False,
            zip_compression_level=0,
            patch_attestation=attestation,
            patch_report_path=report_path,
        )

        assert output is not None
        with zipfile.ZipFile(output) as zf:
            assert "demo.libs/libfoo-abc.so.1" in zf.namelist()

        report = json.loads(report_path.read_text())
        assert report["passed"] is True
        assert report["coverage_complete"] is True
        (repaired,) = report["repaired"]["libraries"]
        assert repaired["delivered"] is True
        assert repaired["sha256"] == _sha(b"patched")


    def test_removes_output_when_packed_file_fails_verification(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        wheel = tmp_path / "wheel"
        wheel.mkdir()
        (wheel / "pkg").mkdir()
        (wheel / "pkg" / "ext.so").write_bytes(b"extension")
        dist_info = wheel / "demo-0.1.dist-info"
        dist_info.mkdir()
        (dist_info / "WHEEL").write_text("Wheel-Version: 1.0\n")
        selected = _library(tmp_path, "libfoo.so.1", b"patched")
        attestation = _attestation(
            tmp_path,
            "libfoo.so.1",
            [{"id": "patched", "path": str(selected), "sha256": _sha(b"patched")}],
        )
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        report_path = tmp_path / "report.json"

        def _fake_ctx(in_wheel: Path, out_wheel: Path | None = None) -> _FakeCtx:
            del in_wheel, out_wheel
            return _FakeCtx(wheel, None)

        def _fake_copylib(src: Path, dest_dir: Path, patcher: object) -> tuple[str, Path]:
            # Simulate a corrupted graft: the packed copy no longer matches.
            del patcher
            (wheel / dest_dir).mkdir(exist_ok=True)
            dest = wheel / dest_dir / "libfoo-abc.so.1"
            dest.write_bytes(src.read_bytes() + b"tamper")
            return dest.name, dest

        monkeypatch.setattr("auditwheel.repair.InWheelCtx", _fake_ctx)
        monkeypatch.setattr("auditwheel.repair.copylib", _fake_copylib)
        monkeypatch.setattr("auditwheel.repair.elf_read_dt_needed", lambda _path: [])
        monkeypatch.setattr("auditwheel.repair.create_sbom_for_wheel", lambda **_kw: None)

        abi = _abi(external={"libfoo.so.1": selected}, wheel_path=wheel)
        with pytest.raises(PatchCoverageError, match="does not contain the approved"):
            repair_wheel(
                abi,
                tmp_path / "demo-0.1-cp312-cp312-linux_x86_64.whl",
                abis=[POLICY_NAME],
                lib_sdir=".libs",
                out_dir=out_dir,
                update_tags=False,
                patcher=_StubPatcher(),  # type: ignore[arg-type]
                strip=False,
                zip_compression_level=0,
                patch_attestation=attestation,
                patch_report_path=report_path,
            )

        assert not list(out_dir.iterdir())
        assert json.loads(report_path.read_text())["repaired"]["passed"] is False
