from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from auditwheel.architecture import Architecture
from auditwheel.candidates import (
    CandidateError,
    CandidateManifest,
    compare_candidates,
    load_manifest,
    required_sonames,
)
from auditwheel.libc import Libc
from auditwheel.policy import WheelPolicies
from auditwheel.wheel_abi import analyze_wheel_abi

from .candidate_fixtures import Needs, Provides, build_export_elf, build_import_elf

POLICIES = WheelPolicies(libc=Libc.GLIBC, arch=Architecture.x86_64)
MANYLINUX_2_17 = POLICIES.get_policy_by_name("manylinux_2_17_x86_64")
MANYLINUX_2_28 = POLICIES.get_policy_by_name("manylinux_2_28_x86_64")
MANYLINUX_2_31 = POLICIES.get_policy_by_name("manylinux_2_31_x86_64")


def _wheel(tmp_path: Path, *, glibc: str = "GLIBC_2.29") -> Path:
    """Build a wheel whose extension imports pow@glibc and memcpy@glibc."""
    module = build_import_elf(
        [
            Needs("libm.so.6", glibc, ["pow"]),
            Needs("libc.so.6", "GLIBC_2.17", ["memcpy"]),
        ]
    )
    wheel = tmp_path / "demo-1.0-cp312-cp312-linux_x86_64.whl"
    record = "demo/demo.so,,\ndemo-1.0.dist-info/METADATA,,\n"
    with zipfile.ZipFile(wheel, "w") as z:
        z.writestr(
            "demo-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
        )
        z.writestr(
            "demo-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: false\n"
            "Tag: cp312-cp312-linux_x86_64\n",
        )
        z.writestr("demo-1.0.dist-info/RECORD", record)
        z.writestr("demo/demo.so", module)
    return wheel


def _write_candidate(
    tmp_path: Path,
    name: str,
    *,
    glibc: str = "GLIBC_2.29",
    provide_pow: bool = True,
    runtime_glibc: str = "GLIBC_2.17",
) -> Path:
    provides = [Provides(glibc, ["pow"] if provide_pow else ["other"])]
    path = tmp_path / name
    path.write_bytes(
        build_export_elf(
            provides,
            needs=[Needs("libc.so.6", runtime_glibc, ["memcpy"])],
        )
    )
    return path


def _manifest(tmp_path: Path, candidates: list[dict]) -> CandidateManifest:
    manifest = tmp_path / "candidates.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "kind": "auditwheel-candidate-manifest",
                "candidates": candidates,
            }
        )
    )
    return load_manifest(manifest)


def _analysis(wheel: Path):
    return analyze_wheel_abi(
        Libc.GLIBC,
        Architecture.x86_64,
        wheel,
        frozenset(),
        disable_isa_ext_check=True,
        allow_graft=False,
    )


def test_symbol_boundary_candidate_retains_target_policy(tmp_path):
    wheel = _wheel(tmp_path)
    candidate = _write_candidate(tmp_path, "libm-boundary.so", glibc="GLIBC_2.29")
    manifest = _manifest(
        tmp_path,
        [
            {
                "soname": "libm.so.6",
                "path": candidate.name,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_17_x86_64",
                        "reference": "SEC-1234/evidence.json",
                    }
                ],
            }
        ],
    )
    winfo = _analysis(wheel)

    report = compare_candidates(
        policies=winfo.policies,
        manifest=manifest,
        imported_symbols=winfo.imported_symbols,
        baseline_policy=winfo.overall_policy,
        required_sonames=required_sonames(manifest, {"libm.so.6"}),
    )

    by_policy = {verdict.policy: verdict for verdict in report.policies}
    assert by_policy[MANYLINUX_2_17.name].retained
    assert by_policy[MANYLINUX_2_28.name].retained
    # The wheel needs GLIBC_2.29, so tags older than manylinux_2_17 are still
    # correctly refused even though the candidate has patch evidence.
    assert not by_policy["manylinux_2_12_x86_64"].retained
    # The candidate's own requirements cap it at manylinux_2_17, so the wheel
    # cannot claim newer tags just because the original analysis reached 2.31.
    assert report.best_retained is not None
    assert report.best_retained.policy == MANYLINUX_2_17.name
    assert report.baseline_covered
    library = report.libraries[0]
    assert library.soname == "libm.so.6"
    assert library.comparisons[0].satisfies_symbols
    assert not library.comparisons[0].missing_symbols


def test_candidate_with_evidence_but_missing_symbol_is_rejected(tmp_path):
    wheel = _wheel(tmp_path)
    candidate = _write_candidate(tmp_path, "libm-patched.so", glibc="GLIBC_2.29", provide_pow=False)
    manifest = _manifest(
        tmp_path,
        [
            {
                "soname": "libm.so.6",
                "path": candidate.name,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_17_x86_64",
                        "reference": "SEC-5678/evidence.json",
                    }
                ],
            }
        ],
    )
    winfo = _analysis(wheel)

    report = compare_candidates(
        policies=winfo.policies,
        manifest=manifest,
        imported_symbols=winfo.imported_symbols,
        baseline_policy=winfo.overall_policy,
        required_sonames=required_sonames(manifest, {"libm.so.6"}),
    )

    assert not report.retained
    assert not report.baseline_covered
    verdict = report.baseline_regressions[0]
    assert verdict.reason == "no candidate provides the required symbols"
    assert [(req.soname, req.symbol, req.version) for req in verdict.missing_symbols] == [
        ("libm.so.6", "pow", "GLIBC_2.29")
    ]


def test_newer_platform_candidate_cannot_keep_older_policy(tmp_path):
    wheel = _wheel(tmp_path, glibc="GLIBC_2.17")
    candidate = _write_candidate(
        tmp_path, "libm-new.so", glibc="GLIBC_2.17", runtime_glibc="GLIBC_2.28"
    )
    manifest = _manifest(
        tmp_path,
        [
            {
                "soname": "libm.so.6",
                "path": candidate.name,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_28_x86_64",
                        "reference": "SEC-9000/evidence.json",
                    }
                ],
            }
        ],
    )
    winfo = _analysis(wheel)

    report = compare_candidates(
        policies=winfo.policies,
        manifest=manifest,
        imported_symbols=winfo.imported_symbols,
        baseline_policy=winfo.overall_policy,
        required_sonames=required_sonames(manifest, {"libm.so.6"}),
    )

    old = next(v for v in report.dropped if v.policy == MANYLINUX_2_17.name)
    assert old.reason == "candidate only runs on a newer platform"
    # The baseline for this wheel (GLIBC_2.17) is manylinux_2_17, and the only
    # candidate cannot run there, so the original support range is not kept.
    assert not report.baseline_covered
    new = next(v for v in report.retained if v.policy == MANYLINUX_2_28.name)
    assert new.candidates == ("libm-new.so",)


def test_older_policy_can_be_left_to_independent_candidate(tmp_path):
    wheel = _wheel(tmp_path, glibc="GLIBC_2.17")
    old_candidate = _write_candidate(
        tmp_path, "libm-old.so", glibc="GLIBC_2.17", runtime_glibc="GLIBC_2.17"
    )
    new_candidate = _write_candidate(
        tmp_path, "libm-new.so", glibc="GLIBC_2.17", runtime_glibc="GLIBC_2.28"
    )
    manifest = _manifest(
        tmp_path,
        [
            {
                "soname": "libm.so.6",
                "path": old_candidate.name,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_17_x86_64",
                        "reference": "SEC-old/evidence.json",
                    }
                ],
            },
            {
                "soname": "libm.so.6",
                "path": new_candidate.name,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_28_x86_64",
                        "reference": "SEC-new/evidence.json",
                    }
                ],
            },
        ],
    )
    winfo = _analysis(wheel)

    report = compare_candidates(
        policies=winfo.policies,
        manifest=manifest,
        imported_symbols=winfo.imported_symbols,
        baseline_policy=winfo.overall_policy,
        required_sonames=required_sonames(manifest, {"libm.so.6"}),
    )

    by_policy = {verdict.policy: verdict for verdict in report.policies}
    assert by_policy[MANYLINUX_2_17.name].retained
    assert by_policy[MANYLINUX_2_17.name].candidates == ("libm-old.so",)
    assert by_policy[MANYLINUX_2_28.name].retained
    # Evidence for 2_17 also covers newer targets, so both candidates qualify.
    assert by_policy[MANYLINUX_2_28.name].candidates == ("libm-old.so", "libm-new.so")
    assert report.baseline_covered
    assert not report.baseline_regressions


def test_version_conflict_names_real_symbol_and_version(tmp_path):
    wheel = _wheel(tmp_path, glibc="GLIBC_2.29")
    candidate = _write_candidate(tmp_path, "libm-228.so", glibc="GLIBC_2.28")
    manifest = _manifest(
        tmp_path,
        [
            {
                "soname": "libm.so.6",
                "path": candidate.name,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_17_x86_64",
                        "reference": "SEC-1234/evidence.json",
                    }
                ],
            }
        ],
    )
    winfo = _analysis(wheel)

    report = compare_candidates(
        policies=winfo.policies,
        manifest=manifest,
        imported_symbols=winfo.imported_symbols,
        baseline_policy=winfo.overall_policy,
        required_sonames=required_sonames(manifest, {"libm.so.6"}),
    )

    comparison = report.libraries[0].comparisons[0]
    conflicts = [(c.symbol, c.required_version) for c in comparison.version_conflicts]
    assert ("pow", "GLIBC_2.29") in conflicts
    verdict = next(v for v in report.dropped if v.policy == MANYLINUX_2_17.name)
    assert ("libm.so.6", "pow", "GLIBC_2.29") in {
        (req.soname, req.symbol, req.version) for req in verdict.missing_symbols
    }


def test_missing_evidence_rejects_candidate(tmp_path):
    wheel = _wheel(tmp_path, glibc="GLIBC_2.17")
    candidate = _write_candidate(tmp_path, "libm.so", glibc="GLIBC_2.17")
    manifest = _manifest(
        tmp_path,
        [
            {
                "soname": "libm.so.6",
                "path": candidate.name,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_28_x86_64",
                        "reference": "SEC-other/evidence.json",
                    }
                ],
            }
        ],
    )
    winfo = _analysis(wheel)

    report = compare_candidates(
        policies=winfo.policies,
        manifest=manifest,
        imported_symbols=winfo.imported_symbols,
        baseline_policy=winfo.overall_policy,
        required_sonames=required_sonames(manifest, {"libm.so.6"}),
    )

    verdict = next(v for v in report.dropped if v.policy == MANYLINUX_2_17.name)
    assert verdict.reason == "candidate has no patch evidence for this policy"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"version": 2, "candidates": []},
        {"version": 1, "candidates": "nope"},
        {"version": 1, "candidates": []},
        {
            "version": 1,
            "candidates": [{"soname": "libm.so.6", "path": "missing.so", "patch_evidence": []}],
        },
    ],
)
def test_invalid_manifest_is_rejected(tmp_path, payload):
    manifest = tmp_path / "bad.json"
    manifest.write_text(json.dumps(payload))
    with pytest.raises(CandidateError):
        load_manifest(manifest)


def test_residual_requirements_bound_reclaimable_tags(tmp_path):
    """Replacing one lib must not claim tags another, untouched lib forbids."""
    wheel = _wheel(tmp_path, glibc="GLIBC_2.29")
    candidate = _write_candidate(
        tmp_path, "libm-old-runtime.so", glibc="GLIBC_2.29", runtime_glibc="GLIBC_2.17"
    )
    manifest = _manifest(
        tmp_path,
        [
            {
                "soname": "libm.so.6",
                "path": candidate.name,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_17_x86_64",
                        "reference": "SEC-1234/evidence.json",
                    }
                ],
            }
        ],
    )
    winfo = _analysis(wheel)

    report = compare_candidates(
        policies=winfo.policies,
        manifest=manifest,
        imported_symbols=winfo.imported_symbols,
        baseline_policy=winfo.overall_policy,
        required_sonames=required_sonames(manifest, {"libm.so.6"}),
    )

    by_policy = {verdict.policy: verdict for verdict in report.policies}
    # libc.so.6 still needs GLIBC_2.17 in this fixture, so the floor is 2_17.
    assert by_policy[MANYLINUX_2_17.name].retained
    assert not by_policy["manylinux_2_12_x86_64"].retained
    assert by_policy["manylinux_2_12_x86_64"].blocked_by == ("manylinux_2_17_x86_64",)


def test_candidate_checksum_mismatch_is_rejected(tmp_path):
    wheel = _wheel(tmp_path, glibc="GLIBC_2.17")
    candidate = _write_candidate(tmp_path, "libm-bad-digest.so", glibc="GLIBC_2.17")
    manifest = _manifest(
        tmp_path,
        [
            {
                "soname": "libm.so.6",
                "path": candidate.name,
                "sha256": "sha256:" + "0" * 64,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_17_x86_64",
                        "reference": "SEC-1234/evidence.json",
                    }
                ],
            }
        ],
    )
    winfo = _analysis(wheel)

    report = compare_candidates(
        policies=winfo.policies,
        manifest=manifest,
        imported_symbols=winfo.imported_symbols,
        baseline_policy=winfo.overall_policy,
        required_sonames=required_sonames(manifest, {"libm.so.6"}),
    )

    assert not report.baseline_covered
    verdict = next(v for v in report.dropped if v.policy == MANYLINUX_2_17.name)
    assert verdict.reason == "candidate checksum does not match the manifest"


def test_candidates_for_unused_libraries_do_not_claim_tags(tmp_path):
    wheel = _wheel(tmp_path, glibc="GLIBC_2.17")
    candidate = _write_candidate(tmp_path, "libz-unused.so", glibc="GLIBC_2.17")
    manifest = _manifest(
        tmp_path,
        [
            {
                "soname": "libz.so.1",
                "path": candidate.name,
                "patch_evidence": [
                    {
                        "policy": "manylinux_2_17_x86_64",
                        "reference": "SEC-1234/evidence.json",
                    }
                ],
            }
        ],
    )
    winfo = _analysis(wheel)

    with pytest.raises(CandidateError, match="no library this wheel imports"):
        compare_candidates(
            policies=winfo.policies,
            manifest=manifest,
            imported_symbols=winfo.imported_symbols,
            baseline_policy=winfo.overall_policy,
            required_sonames=required_sonames(manifest, {"libm.so.6"}),
        )
