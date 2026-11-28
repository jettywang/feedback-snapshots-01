"""Tests for release-matrix verification."""

from __future__ import annotations

import base64
import json
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from pypi_attestations._impl import AttestationError, Distribution
from pypi_attestations._matrix import (
    MatrixResult,
    ReleaseMatrix,
    ReleaseMatrixVerifier,
    ReleaseTarget,
    _is_dist,
)
from sigstore.verify import policy

_HERE = Path(__file__).parent
_DEMO = _HERE / "assets" / "release-matrix-demo"
_MATRIX = _DEMO / "matrix.json"
_TRUSTED_ROOT = _DEMO / "trusted_root.json"
_IDENTITY = "https://example.com/demo/.github/workflows/release.yml@refs/tags/v1.2.3"

_PURE = "demo_project-1.2.3-py3-none-any.whl"
_LINUX = "demo_project-1.2.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
_SDIST = "demo_project-1.2.3.tar.gz"


def _noop_verifier(_attestation: object, _dist: object) -> None:
    return


def _write_artifact(directory: Path, name: str, payload: bytes = b"demo\n") -> Path:
    path = directory / name
    path.write_bytes(payload)
    return path


def _write_attestation(
    directory: Path,
    artifact: Path,
    subject_name: str | None = None,
    subject_digest: str | None = None,
) -> Path:
    digest = sha256(artifact.read_bytes()).hexdigest()
    statement = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": subject_name or artifact.name,
                    "digest": {"sha256": subject_digest or digest},
                }
            ],
            "predicateType": "https://docs.pypi.org/attestations/publish/v1",
            "predicate": None,
        },
        separators=(",", ":"),
    ).encode()
    attestation = {
        "version": 1,
        "verification_material": {
            "certificate": base64.b64encode(b"cert").decode(),
            "transparency_entries": [{"logIndex": "1"}],
        },
        "envelope": {
            "statement": base64.b64encode(statement).decode(),
            "signature": base64.b64encode(b"sig").decode(),
        },
    }
    path = Path(f"{artifact}.publish.attestation")
    path.write_text(json.dumps(attestation))
    return path


def _raw_attestation(statement: dict[str, object]) -> str:
    return json.dumps(
        {
            "version": 1,
            "verification_material": {
                "certificate": base64.b64encode(b"cert").decode(),
                "transparency_entries": [{"logIndex": "1"}],
            },
            "envelope": {
                "statement": base64.b64encode(json.dumps(statement).encode()).decode(),
                "signature": base64.b64encode(b"sig").decode(),
            },
        }
    )


def _matrix(*targets: ReleaseTarget) -> ReleaseMatrix:
    return ReleaseMatrix(name="demo-project", release="1.2.3", targets=list(targets))


class TestReleaseMatrixModel:
    def test_normalizes_name_and_release(self) -> None:
        matrix = ReleaseMatrix(
            name="Demo_Project",
            release="1.2.3",
            targets=[ReleaseTarget(platform=None)],
        )
        assert matrix.name == "demo-project"
        assert matrix.release == "1.2.3"

    def test_rejects_duplicate_platforms(self) -> None:
        with pytest.raises(ValidationError, match="duplicate platform target"):
            ReleaseMatrix(
                name="demo-project",
                release="1.2.3",
                targets=[ReleaseTarget(platform=None), ReleaseTarget(platform=None)],
            )

    def test_rejects_empty_platform(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            ReleaseTarget(platform="")

    def test_target_matches_wheel_and_sdist(self) -> None:
        wheel = Distribution(name=_PURE, digest="a")
        sdist = Distribution(name=_SDIST, digest="a")
        assert ReleaseTarget(platform="any").matches(wheel)
        assert not ReleaseTarget(platform="manylinux_2_17_x86_64").matches(wheel)
        assert ReleaseTarget(platform=None).matches(sdist)
        assert not ReleaseTarget(platform=None).matches(wheel)

    def test_target_matches_compressed_platform_tags(self) -> None:
        dist = Distribution(name=_LINUX, digest="a")
        assert ReleaseTarget(platform="manylinux2014_x86_64").matches(dist)
        assert ReleaseTarget(platform="manylinux_2_17_x86_64").matches(dist)


class TestReleaseMatrixVerifier:
    def test_demo_release_with_real_signatures(self) -> None:
        verifier = ReleaseMatrixVerifier.from_file(_MATRIX)
        result = verifier.verify(
            _DEMO,
            policy.Identity(identity=_IDENTITY),
            offline=True,
            trusted_root=_TRUSTED_ROOT,
        )

        assert result.name == "demo-project"
        assert result.release == "1.2.3"

        admitted = {r.platform: r.artifact for r in result.admitted}
        assert admitted == {
            "manylinux_2_17_x86_64": _LINUX,
            None: _SDIST,
        }

        uncovered = {r.platform: r for r in result.uncovered}
        assert set(uncovered) == {"any", "win_amd64"}
        assert "attestation subject" in (uncovered["any"].reason or "")
        assert uncovered["win_amd64"].approved_omission is True
        assert "Windows wheel" in (uncovered["win_amd64"].reason or "")

        assert result.unattested == [_PURE]
        assert result.unplanned == []
        assert result.failed is True

    def test_all_targets_covered_with_injected_verifier(self, tmp_path: Path) -> None:
        pure = _write_artifact(tmp_path, _PURE)
        linux = _write_artifact(tmp_path, _LINUX)
        sdist = _write_artifact(tmp_path, _SDIST)
        for artifact in (pure, linux, sdist):
            _write_attestation(tmp_path, artifact)

        matrix = ReleaseMatrix(
            name="demo-project",
            release="1.2.3",
            targets=[
                ReleaseTarget(platform="any"),
                ReleaseTarget(platform="manylinux_2_17_x86_64"),
                ReleaseTarget(platform=None),
            ],
        )
        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert result.failed is False
        assert len(result.admitted) == 3
        assert result.unattested == []
        assert result.uncovered == []

    def test_single_attestation_does_not_cover_other_artifacts(self, tmp_path: Path) -> None:
        pure = _write_artifact(tmp_path, _PURE)
        linux = _write_artifact(tmp_path, _LINUX)
        # Only the universal wheel has evidence; it names the Linux wheel.
        _write_attestation(tmp_path, pure, subject_name=_LINUX)
        _write_attestation(tmp_path, linux, subject_name=_PURE)

        matrix = ReleaseMatrix(
            name="demo-project",
            release="1.2.3",
            targets=[
                ReleaseTarget(platform="any"),
                ReleaseTarget(platform="manylinux_2_17_x86_64"),
            ],
        )
        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert result.failed is True
        assert len(result.admitted) == 0
        assert set(result.unattested) == {_PURE, _LINUX}

    def test_missing_artifact_is_reported(self, tmp_path: Path) -> None:
        pure = _write_artifact(tmp_path, _PURE)
        _write_attestation(tmp_path, pure)

        matrix = ReleaseMatrix(
            name="demo-project",
            release="1.2.3",
            targets=[
                ReleaseTarget(platform="any"),
                ReleaseTarget(platform="manylinux_2_17_x86_64"),
            ],
        )
        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        missing = [r for r in result.uncovered if r.platform == "manylinux_2_17_x86_64"]
        assert len(missing) == 1
        assert missing[0].artifact is None
        assert "missing" in (missing[0].reason or "")

    def test_duplicate_artifacts_are_ambiguous(self, tmp_path: Path) -> None:
        first = _write_artifact(tmp_path, _PURE)
        _write_attestation(tmp_path, first)
        # A second universal wheel for the same version makes the slot ambiguous.
        second_name = "demo_project-1.2.3-py2.py3-none-any.whl"
        second = _write_artifact(tmp_path, second_name)
        _write_attestation(tmp_path, second)

        matrix = ReleaseMatrix(
            name="demo-project",
            release="1.2.3",
            targets=[ReleaseTarget(platform="any")],
        )
        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert result.failed is True
        assert "ambiguous" in (result.uncovered[0].reason or "")

    def test_wrong_version_is_not_matched(self, tmp_path: Path) -> None:
        wrong = _write_artifact(tmp_path, "demo_project-1.2.4-py3-none-any.whl")
        _write_attestation(tmp_path, wrong)

        matrix = ReleaseMatrix(
            name="demo-project",
            release="1.2.3",
            targets=[ReleaseTarget(platform="any")],
        )
        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert result.failed is True
        assert result.uncovered[0].artifact is None
        assert result.unplanned == ["demo_project-1.2.4-py3-none-any.whl"]

    def test_cryptographic_failure_is_reported(self, tmp_path: Path) -> None:
        pure = _write_artifact(tmp_path, _PURE)
        _write_attestation(tmp_path, pure)

        def failing(_attestation: object, _dist: object) -> None:
            raise AttestationError("Verification failed: bad identity")

        matrix = ReleaseMatrix(
            name="demo-project",
            release="1.2.3",
            targets=[ReleaseTarget(platform="any")],
        )
        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=failing
        )

        assert result.failed is True
        assert result.unattested == [_PURE]
        assert "bad identity" in (result.uncovered[0].reason or "")

    def test_missing_attestation_is_reported(self, tmp_path: Path) -> None:
        _write_artifact(tmp_path, _PURE)

        matrix = ReleaseMatrix(
            name="demo-project",
            release="1.2.3",
            targets=[ReleaseTarget(platform="any")],
        )
        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert result.failed is True
        assert result.unattested == [_PURE]
        assert "no attestation" in (result.uncovered[0].reason or "")

    def test_invalid_matrix_file(self, tmp_path: Path) -> None:
        path = tmp_path / "matrix.json"
        path.write_text("not json")

        with pytest.raises(AttestationError, match="invalid release matrix"):
            ReleaseMatrixVerifier.from_file(path)

    def test_missing_matrix_file(self, tmp_path: Path) -> None:
        with pytest.raises(AttestationError, match="could not read release matrix"):
            ReleaseMatrixVerifier.from_file(tmp_path / "missing.json")

    def test_format_report_lists_admitted_and_uncovered(self) -> None:
        verifier = ReleaseMatrixVerifier.from_file(_MATRIX)
        result = verifier.verify(
            _DEMO,
            policy.Identity(identity=_IDENTITY),
            offline=True,
            trusted_root=_TRUSTED_ROOT,
        )
        report = result.format_report()

        assert "Admitted targets:" in report
        assert "OK   manylinux_2_17_x86_64" in report
        assert "Uncovered targets:" in report
        assert "MISS any:" in report
        assert "approved omission" in report
        assert "Artifacts without complete evidence:" in report


class TestEvidenceBinding:
    def test_multiple_subjects_rejected(self, tmp_path: Path) -> None:
        artifact = _write_artifact(tmp_path, _PURE)
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": _PURE, "digest": {"sha256": sha256(artifact.read_bytes()).hexdigest()}},
                {"name": _PURE, "digest": {"sha256": "0" * 64}},
            ],
            "predicateType": "https://docs.pypi.org/attestations/publish/v1",
            "predicate": None,
        }
        Path(f"{artifact}.publish.attestation").write_text(_raw_attestation(statement))

        result = ReleaseMatrixVerifier(_matrix(ReleaseTarget(platform="any"))).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert result.failed is True
        assert "exactly one subject" in (result.uncovered[0].reason or "")

    def test_missing_subject_name_rejected(self, tmp_path: Path) -> None:
        artifact = _write_artifact(tmp_path, _PURE)
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"digest": {"sha256": sha256(artifact.read_bytes()).hexdigest()}},
            ],
            "predicateType": "https://docs.pypi.org/attestations/publish/v1",
            "predicate": None,
        }
        Path(f"{artifact}.publish.attestation").write_text(_raw_attestation(statement))

        result = ReleaseMatrixVerifier(_matrix(ReleaseTarget(platform="any"))).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert "missing a name" in (result.uncovered[0].reason or "")

    def test_invalid_subject_name_rejected(self, tmp_path: Path) -> None:
        artifact = _write_artifact(tmp_path, _PURE)
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "not-a-distribution.exe",
                    "digest": {"sha256": sha256(artifact.read_bytes()).hexdigest()},
                },
            ],
            "predicateType": "https://docs.pypi.org/attestations/publish/v1",
            "predicate": None,
        }
        Path(f"{artifact}.publish.attestation").write_text(_raw_attestation(statement))

        result = ReleaseMatrixVerifier(_matrix(ReleaseTarget(platform="any"))).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert "invalid attestation subject" in (result.uncovered[0].reason or "")

    def test_digest_mismatch_rejected(self, tmp_path: Path) -> None:
        artifact = _write_artifact(tmp_path, _PURE)
        _write_attestation(tmp_path, artifact, subject_digest="0" * 64)

        result = ReleaseMatrixVerifier(_matrix(ReleaseTarget(platform="any"))).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert "digest does not match" in (result.uncovered[0].reason or "")

    def test_invalid_attestation_json_rejected(self, tmp_path: Path) -> None:
        artifact = _write_artifact(tmp_path, _PURE)
        Path(f"{artifact}.publish.attestation").write_text("not an attestation")

        result = ReleaseMatrixVerifier(_matrix(ReleaseTarget(platform="any"))).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert "invalid attestation" in (result.uncovered[0].reason or "")


class TestReportEdges:
    def test_all_approved_omissions_do_not_fail(self, tmp_path: Path) -> None:
        matrix = _matrix(ReleaseTarget(platform="win_amd64", reason="not produced"))
        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert result.failed is False
        assert result.admitted == []
        assert len(result.uncovered) == 1
        assert result.uncovered[0].approved_omission is True

    def test_approved_target_with_artifact_still_needs_evidence(self, tmp_path: Path) -> None:
        _write_artifact(tmp_path, _PURE)
        matrix = _matrix(ReleaseTarget(platform="any", reason="approved but present"))

        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert result.failed is True
        assert result.uncovered[0].approved_omission is False
        assert result.unattested == [_PURE]

    def test_unplanned_artifact_is_reported(self, tmp_path: Path) -> None:
        _write_artifact(tmp_path, _PURE)
        _write_attestation(tmp_path, tmp_path / _PURE)
        extra = _write_artifact(tmp_path, "demo_project-1.2.3-cp312-cp312-win_amd64.whl")

        matrix = _matrix(ReleaseTarget(platform="any"))
        result = ReleaseMatrixVerifier(matrix).verify(
            tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
        )

        assert result.failed is False
        assert result.unplanned == [extra.name]

    def test_report_renders_empty_sections(self) -> None:
        report = MatrixResult(
            name="demo-project", release="1.2.3", results=[], unattested=[], unplanned=[]
        ).format_report()

        assert "Admitted targets:\n  (none)" in report
        assert "Uncovered targets:\n  (none)" in report
        assert "Artifacts without complete evidence" not in report

    def test_invalid_dist_filename_is_ignored(self) -> None:
        assert _is_dist("demo_project-1.2.3-py3-none-any.whl") is True
        assert _is_dist("demo_project-1.2.3.tar.gz") is True
        assert _is_dist("notes.txt") is False
        assert _is_dist("invalid.whl") is False


def test_report_lists_unplanned_artifacts() -> None:
    report = MatrixResult(
        name="demo-project",
        release="1.2.3",
        results=[],
        unattested=[],
        unplanned=["demo_project-1.2.3-cp312-cp312-win_amd64.whl"],
    ).format_report()

    assert "Artifacts not in the matrix:" in report
    assert "  - demo_project-1.2.3-cp312-cp312-win_amd64.whl" in report


def test_matches_file_rejects_bad_and_foreign_names() -> None:
    verifier = ReleaseMatrixVerifier(_matrix(ReleaseTarget(platform="any")))

    assert verifier._matches_file(ReleaseTarget(platform="any"), "not-a-dist.txt") is False
    assert verifier._matches_file(ReleaseTarget(platform="any"), "other-1.2.3.tar.gz") is False
    assert verifier._matches_file(ReleaseTarget(platform="any"), _PURE) is True
    assert verifier._matches_file(ReleaseTarget(platform=None), _SDIST) is True


def test_unreadable_artifact_is_reported(tmp_path: Path) -> None:
    artifact = _write_artifact(tmp_path, _PURE)
    _write_attestation(tmp_path, artifact)

    def failing(_attestation: object, _dist: object) -> None:
        raise OSError("disk on fire")

    result = ReleaseMatrixVerifier(_matrix(ReleaseTarget(platform="any"))).verify(
        tmp_path, policy.UnsafeNoOp(), verifier=failing
    )

    assert result.failed is True
    assert "could not read artifact" in (result.uncovered[0].reason or "")


def test_attestation_with_unparseable_statement(tmp_path: Path) -> None:
    artifact = _write_artifact(tmp_path, _PURE)
    payload = {
        "version": 1,
        "verification_material": {
            "certificate": base64.b64encode(b"cert").decode(),
            "transparency_entries": [{"logIndex": "1"}],
        },
        "envelope": {
            # Valid base64, but not valid JSON.
            "statement": base64.b64encode(b"not json").decode(),
            "signature": base64.b64encode(b"sig").decode(),
        },
    }
    Path(f"{artifact}.publish.attestation").write_text(json.dumps(payload))

    result = ReleaseMatrixVerifier(_matrix(ReleaseTarget(platform="any"))).verify(
        tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
    )

    assert result.failed is True
    assert "invalid statement" in (result.uncovered[0].reason or "")


def test_shared_evidence_cannot_admit_two_targets(tmp_path: Path) -> None:
    """One attestation printed twice must not cover two different artifacts."""
    pure = _write_artifact(tmp_path, _PURE)
    linux = _write_artifact(tmp_path, _LINUX)

    evidence = _write_attestation(tmp_path, pure)
    Path(f"{linux}.publish.attestation").write_bytes(evidence.read_bytes())

    matrix = _matrix(
        ReleaseTarget(platform="any"),
        ReleaseTarget(platform="manylinux_2_17_x86_64"),
    )
    result = ReleaseMatrixVerifier(matrix).verify(
        tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
    )

    assert result.failed is True
    assert [r.platform for r in result.admitted] == ["any"]
    assert result.unattested == [_LINUX]


def test_same_bytes_different_names_not_admitted_twice(tmp_path: Path) -> None:
    """Identical bytes under two names must each carry their own evidence."""
    pure = _write_artifact(tmp_path, _PURE, b"identical bytes\n")
    copied_name = "demo_project-1.2.3-py2.py3-none-any.whl"
    copied = _write_artifact(tmp_path, copied_name, b"identical bytes\n")

    _write_attestation(tmp_path, pure)

    matrix = _matrix(ReleaseTarget(platform="any"))
    result = ReleaseMatrixVerifier(matrix).verify(
        tmp_path, policy.UnsafeNoOp(), verifier=_noop_verifier
    )

    assert result.failed is True
    assert "ambiguous" in (result.uncovered[0].reason or "")
    assert copied.name in (result.uncovered[0].reason or "")


def test_invalid_trusted_root_fails_fast(tmp_path: Path) -> None:
    bad_root = tmp_path / "trusted_root.json"
    bad_root.write_text("not json")

    with pytest.raises(AttestationError, match="invalid trusted root"):
        ReleaseMatrixVerifier.from_file(_MATRIX).verify(
            _DEMO,
            policy.Identity(identity=_IDENTITY),
            offline=True,
            trusted_root=bad_root,
        )
