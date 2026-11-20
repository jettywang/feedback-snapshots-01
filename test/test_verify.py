import base64
import hashlib

import pytest
from packaging.version import Version

from pip_audit._verify import (
    DeploymentLockError,
    InstalledArtifact,
    LockedArtifact,
    VerifyVerdict,
    collect_installed,
    fingerprint_distribution,
    format_verify_results,
    load_deployment_lock,
    lock_entries_from_installed,
    render_deployment_lock,
    verification_failed,
    verify_deployment,
)


def _record_digest(content):
    digest = hashlib.sha256(content.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _install_fake_dist(env, marker, name="internal-widget", version="1.0.0"):
    package = name.replace("-", "_")
    dist_info = env / f"{package}-{version}.dist-info"
    package_dir = env / package
    package_dir.mkdir(parents=True)
    dist_info.mkdir()

    init = package_dir / "__init__.py"
    init.write_text(f'BUILD_MARKER = "{marker}"\n')
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    )
    record = (
        f"{package}/__init__.py,sha256={_record_digest(init.read_text())},"
        f"{len(init.read_bytes())}\n"
        f"{dist_info.name}/METADATA,sha256={_record_digest((dist_info / 'METADATA').read_text())},"
        f"{(dist_info / 'METADATA').stat().st_size}\n"
        f"{dist_info.name}/RECORD,,\n"
    )
    (dist_info / "RECORD").write_text(record)
    return env


def test_fingerprint_distribution_same_build(tmp_path):
    env_a = _install_fake_dist(tmp_path / "env_a", "build-a")
    env_b = _install_fake_dist(tmp_path / "env_b", "build-a")

    (dist_a,) = collect_installed(paths=[env_a])
    (dist_b,) = collect_installed(paths=[env_b])

    assert dist_a.fingerprint == dist_b.fingerprint


def test_fingerprint_distribution_ignores_bytecode(tmp_path):
    env_a = _install_fake_dist(tmp_path / "env_a", "build-a")
    env_b = _install_fake_dist(tmp_path / "env_b", "build-a")

    # Bytecode is generated at install time and must not affect the fingerprint.
    pycache = env_b / "internal_widget" / "__pycache__"
    pycache.mkdir()
    (pycache / "__init__.cpython-312.pyc").write_bytes(b"bytecode")
    record = env_b / "internal_widget-1.0.0.dist-info" / "RECORD"
    record.write_text(
        record.read_text() + "internal_widget/__pycache__/__init__.cpython-312.pyc,sha256=abc,8\n"
    )

    (dist_a,) = collect_installed(paths=[env_a])
    (dist_b,) = collect_installed(paths=[env_b])

    assert dist_a.fingerprint == dist_b.fingerprint


def test_fingerprint_distribution_rebuilt_same_version(tmp_path):
    env_a = _install_fake_dist(tmp_path / "env_a", "build-a")
    env_b = _install_fake_dist(tmp_path / "env_b", "build-b")

    (dist_a,) = collect_installed(paths=[env_a])
    (dist_b,) = collect_installed(paths=[env_b])

    assert dist_a.name == dist_b.name
    assert dist_a.version == dist_b.version
    assert dist_a.fingerprint != dist_b.fingerprint


def test_fingerprint_distribution_without_record(tmp_path):
    from importlib.metadata import distributions

    env = _install_fake_dist(tmp_path / "env", "build-a")
    (env / "internal_widget-1.0.0.dist-info" / "RECORD").unlink()

    (dist,) = distributions(path=[str(env)])
    assert fingerprint_distribution(dist)


def test_collect_installed_skips_invalid_version(tmp_path):
    env = _install_fake_dist(tmp_path / "env", "build-a", version="not-a-version")
    assert list(collect_installed(paths=[env])) == []


def test_verify_deployment_same_build(tmp_path):
    env = _install_fake_dist(tmp_path / "env", "build-a")
    installed = list(collect_installed(paths=[env]))
    locked = lock_entries_from_installed(installed)

    (result,) = verify_deployment(locked, installed)
    assert result.verdict is VerifyVerdict.SameBuild
    assert result.locked_version == Version("1.0.0")
    assert result.installed_version == Version("1.0.0")
    assert not verification_failed([result])


def test_verify_deployment_build_mismatch(tmp_path):
    env_a = _install_fake_dist(tmp_path / "env_a", "build-a")
    env_b = _install_fake_dist(tmp_path / "env_b", "build-b")
    locked = lock_entries_from_installed(collect_installed(paths=[env_a]))
    installed_b = list(collect_installed(paths=[env_b]))

    (result,) = verify_deployment(locked, installed_b)
    assert result.verdict is VerifyVerdict.BuildMismatch
    assert result.locked_version == result.installed_version == Version("1.0.0")
    assert result.actual_fingerprint not in result.expected_hashes
    assert verification_failed([result])


def test_verify_deployment_pending_evidence(tmp_path):
    env = _install_fake_dist(tmp_path / "env", "build-a")
    installed = list(collect_installed(paths=[env]))
    locked = [LockedArtifact(name="internal-widget", version=Version("1.0.0"))]

    (result,) = verify_deployment(locked, installed)
    assert result.verdict is VerifyVerdict.PendingEvidence
    assert result.installed_version == Version("1.0.0")
    # Missing evidence does not fail the deployment gate.
    assert not verification_failed([result])


def test_verify_deployment_version_mismatch(tmp_path):
    env = _install_fake_dist(tmp_path / "env", "build-a", version="2.0.0")
    installed = list(collect_installed(paths=[env]))
    locked = [LockedArtifact(name="internal-widget", version=Version("1.0.0"), hashes=("abc",))]

    (result,) = verify_deployment(locked, installed)
    assert result.verdict is VerifyVerdict.VersionMismatch
    assert result.installed_version == Version("2.0.0")
    assert verification_failed([result])


def test_verify_deployment_not_installed(tmp_path):
    locked = [LockedArtifact(name="internal-widget", version=Version("1.0.0"), hashes=("abc",))]

    (result,) = verify_deployment(locked, [])
    assert result.verdict is VerifyVerdict.NotInstalled
    assert result.installed_version is None
    assert verification_failed([result])


def test_deployment_lock_round_trip(tmp_path):
    env = _install_fake_dist(tmp_path / "env", "build-a")
    entries = lock_entries_from_installed(collect_installed(paths=[env]))

    lockfile = tmp_path / "deployment.lock"
    lockfile.write_text(render_deployment_lock(entries))

    assert load_deployment_lock(lockfile) == entries


def test_load_deployment_lock_without_evidence(tmp_path):
    lockfile = tmp_path / "deployment.lock"
    lockfile.write_text("# a comment\n\ninternal-widget==1.0.0\n")

    (entry,) = load_deployment_lock(lockfile)
    assert entry.name == "internal-widget"
    assert entry.version == Version("1.0.0")
    assert entry.hashes == ()


def test_load_deployment_lock_ignores_non_sha256(tmp_path):
    lockfile = tmp_path / "deployment.lock"
    lockfile.write_text("internal-widget==1.0.0 --hash=sha512:abc --hash=sha256:def\n")

    (entry,) = load_deployment_lock(lockfile)
    assert entry.hashes == ("def",)


def test_load_deployment_lock_invalid(tmp_path):
    lockfile = tmp_path / "deployment.lock"
    lockfile.write_text("internal-widget\n")
    with pytest.raises(DeploymentLockError):
        load_deployment_lock(lockfile)

    lockfile.write_text("internal-widget==1.0.0 --surprise\n")
    with pytest.raises(DeploymentLockError):
        load_deployment_lock(lockfile)

    lockfile.write_text("internal-widget==not-a-version\n")
    with pytest.raises(DeploymentLockError):
        load_deployment_lock(lockfile)


def test_format_verify_results_shows_versions_and_evidence(tmp_path):
    results = [
        verify_deployment(
            [LockedArtifact(name="same", version=Version("1.0.0"), hashes=("aaa",))],
            [InstalledArtifact(name="same", version=Version("1.0.0"), fingerprint="aaa")],
        )[0],
        verify_deployment(
            [LockedArtifact(name="rebuilt", version=Version("1.0.0"), hashes=("aaa",))],
            [InstalledArtifact(name="rebuilt", version=Version("1.0.0"), fingerprint="bbb")],
        )[0],
        verify_deployment(
            [LockedArtifact(name="pending", version=Version("1.0.0"))],
            [InstalledArtifact(name="pending", version=Version("1.0.0"), fingerprint="ccc")],
        )[0],
        verify_deployment(
            [LockedArtifact(name="missing", version=Version("1.0.0"), hashes=("ddd",))],
            [],
        )[0],
    ]

    output = format_verify_results(results)
    # Versions are visible for every verdict, so remediation owners can see
    # what is deployed even when evidence is missing or mismatched.
    assert "same" in output and "same-build" in output
    assert "rebuilt" in output and "build-mismatch" in output
    assert "sha256:aaa" in output and "sha256:bbb" in output
    assert "pending" in output and "pending-evidence" in output
    assert "sha256:ccc" in output
    assert "missing" in output and "not-installed" in output
    # Every row reports both the locked and installed version columns.
    assert output.count("1.0.0") >= 4
