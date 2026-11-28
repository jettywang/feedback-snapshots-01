from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tox.tox_env.python.build_reuse import (
    BuildApprovalError,
    BuildReuseStore,
    decision,
    dependency_records,
    diff_record,
    evaluate_approvals,
    installed_versions,
    load_approvals,
    read_wheel_metadata,
    restrict_resolved,
    reuse_key,
    source_change_reasons,
    source_digest,
    target_change_reasons,
)

if TYPE_CHECKING:
    from pathlib import Path

    from tox.pytest import MonkeyPatch, ToxProject, ToxProjectCreator


def _record(name: str = "setuptools", specifier: str = "==81.0.0") -> dict[str, object]:
    return {"name": name, "specifier": specifier, "approved_by": "reviewer", "approved_at": "2026-11-20"}


def _approvals_file(path: Path, *records: dict[str, object]) -> Path:
    path.write_text(json.dumps({"approvals": list(records)}), encoding="utf-8")
    return path


def test_load_approvals_reads_and_normalizes(tmp_path: Path) -> None:
    path = _approvals_file(tmp_path / "a.json", _record(name="Setuptools", specifier=">=81"))
    records = load_approvals(path)
    assert len(records) == 1
    assert records[0]["name"] == "setuptools"
    assert records[0]["specifier"] == ">=81"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        pytest.param("{}", "must hold an 'approvals' list", id="missing-list"),
        pytest.param('{"approvals": [{}]}', "needs a project name", id="no-name"),
        pytest.param('{"approvals": [{"name": "x"}]}', "needs a PEP 440 specifier", id="no-specifier"),
        pytest.param(
            '{"approvals": [{"name": "x", "specifier": "==1"}]}', "needs an approved_by record", id="no-approver"
        ),
        pytest.param(
            '{"approvals": [{"name": "x", "specifier": "==1", "approved_by": "a"}]}',
            "needs an approved_at record",
            id="no-date",
        ),
        pytest.param(
            '{"approvals": [{"name": "x", "specifier": "one", "approved_by": "a", "approved_at": "d"}]}',
            "invalid specifier",
            id="bad-specifier",
        ),
        pytest.param(
            '{"approvals": [{"name": "x", "specifier": "1.0", "approved_by": "a", "approved_at": "d"}]}',
            "expected a comparison operator",
            id="operator",
        ),
        pytest.param(
            json.dumps({
                "approvals": [
                    {"name": "x", "specifier": "==1", "approved_by": "a", "approved_at": "d"},
                    {"name": "x", "specifier": "==2", "approved_by": "a", "approved_at": "d"},
                ]
            }),
            "duplicate approval",
            id="duplicate",
        ),
    ],
)
def test_load_approvals_rejects_malformed(tmp_path: Path, payload: str, expected: str) -> None:
    path = tmp_path / "a.json"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(BuildApprovalError, match=expected):
        load_approvals(path)


def test_load_approvals_missing_file(tmp_path: Path) -> None:
    with pytest.raises(BuildApprovalError, match="does not exist"):
        load_approvals(tmp_path / "missing.json")


def test_load_approvals_rejects_a_link(tmp_path: Path) -> None:
    target = _approvals_file(tmp_path / "real.json", _record())
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(BuildApprovalError, match="is a link"):
        load_approvals(link)


def test_evaluate_approvals_reports_unmet() -> None:
    approvals = [_record("setuptools", "==81.0.0"), _record("wheel", ">=0.40")]
    declared = ["setuptools", "wheel", "hatchling"]
    resolved = {"setuptools": "80.0.0", "wheel": "0.45.0"}
    ok, unmet, applied = evaluate_approvals(approvals, declared, resolved, configured=True)
    assert ok is False
    assert "setuptools==81.0.0 (resolved 80.0.0)" in unmet
    assert "hatchling (no approval record)" in unmet
    assert [item["name"] for item in applied] == ["wheel"]


def test_evaluate_approvals_skipped_without_file() -> None:
    ok, unmet, applied = evaluate_approvals([], ["setuptools"], {}, configured=False)
    assert (ok, unmet, applied) == (True, [], [])


def test_dependency_records_marks_approval() -> None:
    records = dependency_records(["Setuptools==81"], {"setuptools": "81.0.0"}, [_record("setuptools", "==81.0.0")])
    assert records == [
        {
            "name": "setuptools",
            "requested": "Setuptools==81",
            "resolved": "81.0.0",
            "approval": _record("setuptools", "==81.0.0"),
            "approved": True,
        }
    ]


def test_diff_record_lists_revision_change() -> None:
    record = {
        "declared": ["setuptools"],
        "approvals": [_record("setuptools", "==81.0.0")],
        "dependencies": [{"name": "setuptools", "resolved": "81.0.0"}],
    }
    reasons = diff_record(
        record,
        declared=["setuptools"],
        resolved={"setuptools": "82.0.0"},
        approvals=[_record("setuptools", "==82.0.0")],
        unmet=[],
    )
    assert "build dependency revision changed: setuptools 81.0.0 -> 82.0.0" in reasons
    assert "build dependency approvals changed" in reasons


def test_source_digest_ignores_links_target_content(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("one", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / "readme").write_text("hello", encoding="utf-8")
    (project / "linked").symlink_to(outside / "secret")
    first = source_digest(project)
    (outside / "secret").write_text("two", encoding="utf-8")
    assert source_digest(project) == first


def test_source_digest_changes_with_content(tmp_path: Path) -> None:
    (tmp_path / "a").write_text("one", encoding="utf-8")
    first = source_digest(tmp_path)
    (tmp_path / "a").write_text("two", encoding="utf-8")
    assert source_digest(tmp_path) != first


def test_source_digest_excludes_a_directory(tmp_path: Path) -> None:
    (tmp_path / "a").write_text("one", encoding="utf-8")
    ignored = tmp_path / "ignored"
    ignored.mkdir()
    (ignored / "b").write_text("two", encoding="utf-8")
    with_ignored = source_digest(tmp_path)
    (ignored / "b").write_text("three", encoding="utf-8")
    assert source_digest(tmp_path) != with_ignored
    assert source_digest(tmp_path, exclude=[ignored]) == source_digest(
        tmp_path, exclude=[ignored]
    )


def test_reuse_key_is_stable_and_sensitive() -> None:
    target = {"implementation": "cpython", "version": "3.12"}
    key = reuse_key("wheel", "build", "digest", target)
    assert key == reuse_key("wheel", "build", "digest", dict(target))
    assert key != reuse_key("wheel", "build", "other", target)
    assert key != reuse_key("wheel", "build", "digest", {"implementation": "cpython", "version": "3.13"})


def test_store_keeps_old_entries(tmp_path: Path) -> None:
    store = BuildReuseStore(tmp_path / "prov")
    store.add_entry("key", {"artifact": "one"})
    store.add_entry("key", {"artifact": "two"})
    store.save()
    reloaded = BuildReuseStore(tmp_path / "prov")
    assert [item["artifact"] for item in reloaded.entries["key"]] == ["one", "two"]
    assert reloaded.latest("key") == {"artifact": "two"}


def test_store_archive_keeps_the_file_name(tmp_path: Path) -> None:
    artifact = tmp_path / "demo-1.0-py3-none-any.whl"
    artifact.write_bytes(b"content")
    store = BuildReuseStore(tmp_path / "prov")
    archived = store.archive(artifact)
    digest = hashlib.sha256(b"content").hexdigest()
    assert archived == tmp_path / "prov" / "artifacts" / digest / "demo-1.0-py3-none-any.whl"
    assert archived.read_bytes() == b"content"


def _demo_project(tox_project: ToxProjectCreator, demo_pkg_inline: Path, extra: str = "") -> ToxProject:
    toml = (demo_pkg_inline / "pyproject.toml").read_text()
    build = (demo_pkg_inline / "build.py").read_text()
    config = (
        '[env_run_base]\npackage = "wheel"\ncommands = [["python", "-c", '
        '"from demo_pkg_inline import do; do()"]]\n[env.".pkg"]\nreuse_built_package = true\n'
        + extra
    )
    return tox_project({"tox.toml": config, "pyproject.toml": toml, "build.py": build})


def _ledger(project: ToxProject) -> dict[str, object]:
    path = project.path / ".tox" / "build-provenance" / "ledger.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _journal(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_reuse_same_source_same_target(
    tox_project: ToxProjectCreator, demo_pkg_inline: Path, tmp_path: Path
) -> None:
    project = _demo_project(tox_project, demo_pkg_inline)
    first = project.run("r", "-e", "py", "--result-json", str(tmp_path / "one.json"))
    first.assert_success()
    second = project.run("r", "-e", "py", "--result-json", str(tmp_path / "two.json"))
    second.assert_success()

    first_journal = _journal(tmp_path / "one.json")["testenvs"][".pkg"]
    second_journal = _journal(tmp_path / "two.json")["testenvs"][".pkg"]
    # the first build only records provenance; a same-source same-target run reuses it instead
    assert "build_reuse" not in first_journal
    assert [item["mode"] for item in second_journal["build_reuse"]] == ["reuse"]
    assert second_journal["build_provenance"]["artifact_sha256"]

    ledger = _ledger(project)
    assert len(ledger["entries"]) == 1
    # the first build is the baseline; only the later reuse is a decision
    assert [item["mode"] for item in ledger["decisions"]] == ["reuse"]


def test_rebuild_when_build_dependency_changes(
    tox_project: ToxProjectCreator, demo_pkg_inline: Path, tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    wheel_dir = tmp_path / "wheels"
    _local_wheel(wheel_dir, "build-helper", "1.0")
    monkeypatch.setenv("PIP_FIND_LINKS", str(wheel_dir))
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    project = tox_project({
        "tox.toml": (
            '[env_run_base]\npackage = "wheel"\ncommands = [["python", "-c", "print(1)"]]\n'
            '[env.".pkg"]\nreuse_built_package = true\n'
        ),
        "pyproject.toml": (demo_pkg_inline / "pyproject.toml").read_text(),
        "build.py": _package_backend_requires(demo_pkg_inline, "build-helper>=1.0"),
    })
    project.run("r", "-e", "py").assert_success()
    # the same source now resolves the single build requirement to a newly published patch revision; recreating the
    # packager environment must not lose the earlier record, and the higher revision must force a rebuild
    _local_wheel(wheel_dir, "build-helper", "2.0")
    result = project.run("r", "-e", "py", "-r", "--result-json", str(tmp_path / "two.json"))
    result.assert_success()
    journal = _journal(tmp_path / "two.json")["testenvs"][".pkg"]
    decision = journal["build_reuse"][0]
    assert decision["mode"] == "rebuild"
    assert "build dependency revision changed: build-helper 1.0 -> 2.0" in decision["reasons"]
    # the artifact that is now released records the new revision, the old one stays for comparison
    ledger = _ledger(project)
    assert len(ledger["entries"]) == 1
    revisions = ledger["entries"][next(iter(ledger["entries"]))]
    resolved = [
        next(dep["resolved"] for dep in item["dependencies"] if dep["name"] == "build-helper") for item in revisions
    ]
    assert resolved == ["1.0", "2.0"]
    artifacts = project.path / ".tox" / "build-provenance" / "artifacts"
    assert len([item for item in artifacts.iterdir() if item.is_dir()]) == 2


def test_target_change_reasons_names_the_old_and_new_target() -> None:
    target = {"implementation": "cpython", "version": "3.12.1"}
    records = [{"key": "old", "source": "digest", "package_type": "wheel", "backend": "build", "target": target}]
    reasons = target_change_reasons(
        records,
        source="digest",
        package_type="wheel",
        backend="build",
        target={"implementation": "cpython", "version": "3.13.0"},
    )
    assert reasons == ["target environment changed: cpython 3.12.1 -> cpython 3.13.0"]


def test_target_change_reasons_ignores_a_matching_target() -> None:
    target = {"implementation": "cpython", "version": "3.12.1"}
    records = [{"key": "same", "source": "digest", "package_type": "wheel", "backend": "build", "target": target}]
    assert (
        target_change_reasons(records, source="digest", package_type="wheel", backend="build", target=target) == []
    )


def _local_wheel(directory: Path, name: str, version: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    wheel = directory / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    with ZipFile(wheel, "w") as archive:
        archive.writestr(f"{name.replace('-', '_')}/__init__.py", "")
        archive.writestr(f"{dist_info}/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
        archive.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr(f"{dist_info}/RECORD", "")
    return wheel


def _package_backend_requires(directory: Path, requirement: str) -> str:
    build = (directory / "build.py").read_text()
    marker = "return []  # pragma: no cover # only executed in non-host pythons"
    return build.replace(marker, f"return [{requirement!r}]")


def test_build_fails_when_approval_not_met(
    tox_project: ToxProjectCreator, demo_pkg_inline: Path, tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    wheel_dir = tmp_path / "wheels"
    _local_wheel(wheel_dir, "build-helper", "2.0")
    monkeypatch.setenv("PIP_FIND_LINKS", str(wheel_dir))
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    approvals = _approvals_file(tmp_path / "approvals.json", _record("build-helper", "==1.0"))
    build = _package_backend_requires(demo_pkg_inline, "build-helper")
    project = tox_project({
        "tox.toml": (
            '[env_run_base]\npackage = "wheel"\ncommands = [["python", "-c", "print(1)"]]\n'
            f'[env.".pkg"]\nreuse_built_package = true\nbuild_approvals_file = "{approvals}"\n'
        ),
        "pyproject.toml": (demo_pkg_inline / "pyproject.toml").read_text(),
        "build.py": build,
    })
    result = project.run("r", "-e", "py")
    result.assert_failed()
    assert "do not meet their approval records" in result.out
    artifacts = project.path / ".tox" / "build-provenance" / "artifacts"
    assert not artifacts.exists() or not list(artifacts.iterdir())


def test_build_records_approval(
    tox_project: ToxProjectCreator, demo_pkg_inline: Path, tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    wheel_dir = tmp_path / "wheels"
    _local_wheel(wheel_dir, "build-helper", "1.0")
    monkeypatch.setenv("PIP_FIND_LINKS", str(wheel_dir))
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    approvals = _approvals_file(tmp_path / "approvals.json", _record("build-helper", "==1.0"))
    build = _package_backend_requires(demo_pkg_inline, "build-helper")
    project = tox_project({
        "tox.toml": (
            '[env_run_base]\npackage = "wheel"\ncommands = [["python", "-c", "print(1)"]]\n'
            f'[env.".pkg"]\nreuse_built_package = true\nbuild_approvals_file = "{approvals}"\n'
        ),
        "pyproject.toml": (demo_pkg_inline / "pyproject.toml").read_text(),
        "build.py": build,
    })
    project.run("r", "-e", "py", "--result-json", str(tmp_path / "one.json")).assert_success()
    document = _journal(tmp_path / "one.json")["testenvs"][".pkg"]["build_provenance"]
    dependency = next(item for item in document["dependencies"] if item["name"] == "build-helper")
    assert dependency["approved"] is True
    assert dependency["resolved"] == "1.0"
    assert dependency["approval"]["specifier"] == "==1.0"
    sidecar = next(
        (project.path / ".tox" / "build-provenance" / "artifacts").rglob("*.provenance.json")
    )
    assert json.loads(sidecar.read_text(encoding="utf-8"))["approvals"][0]["approved_by"] == "reviewer"


def test_installed_versions_reads_site_packages(tmp_path: Path) -> None:
    site = tmp_path / "site"
    dist_info = site / "demo-1.2.3.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text("Metadata-Version: 2.1\nName: Demo_Pkg\nVersion: 1.2.3\n", encoding="utf-8")
    assert installed_versions([site, tmp_path / "missing"]) == {"demo-pkg": "1.2.3"}


def test_restrict_resolved_keeps_declared_names() -> None:
    declared = ["build-helper>=1", "bare/path"]
    resolved = {"build-helper": "2.0", "other": "1.0"}
    assert restrict_resolved(declared, resolved) == {"build-helper": "2.0"}


def test_read_wheel_metadata(tmp_path: Path) -> None:
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("demo-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n")
    assert read_wheel_metadata(wheel) == ("demo", "1.0")


def test_read_wheel_metadata_without_metadata(tmp_path: Path) -> None:
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "")
    assert read_wheel_metadata(wheel) == (None, None)
    broken = tmp_path / "broken-1.0-py3-none-any.whl"
    broken.write_bytes(b"not a zip")
    assert read_wheel_metadata(broken) == (None, None)


def test_store_ignores_a_link_and_a_corrupt_file(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"entries": {"k": [{"artifact": "a"}]}}), encoding="utf-8")
    linked_root = tmp_path / "linked"
    linked_root.mkdir()
    (linked_root / "ledger.json").symlink_to(real)
    assert BuildReuseStore(linked_root).entries == {}

    corrupt_root = tmp_path / "corrupt"
    corrupt_root.mkdir()
    (corrupt_root / "ledger.json").write_text("not json", encoding="utf-8")
    assert BuildReuseStore(corrupt_root).entries == {}


def test_store_artifact_path_rejects_missing_and_changed(tmp_path: Path) -> None:
    artifact = tmp_path / "demo-1.0-py3-none-any.whl"
    artifact.write_bytes(b"content")
    store = BuildReuseStore(tmp_path / "prov")
    archived = store.archive(artifact)
    record = {"artifact": archived.name, "artifact_sha256": hashlib.sha256(b"content").hexdigest()}
    assert store.artifact_path(record) == archived
    archived.write_bytes(b"tampered")
    assert store.artifact_path(record) is None
    assert store.artifact_path({"artifact": "missing.whl"}) is None


def test_restrict_resolved_ignores_a_bare_path() -> None:
    assert restrict_resolved(["bare/path"], {"bare": "1"}) == {}


def test_evaluate_approvals_not_installed() -> None:
    ok, unmet, _ = evaluate_approvals(
        [_record("setuptools", "==81.0.0")], ["setuptools"], {}, configured=True
    )
    assert ok is False
    assert "setuptools==81.0.0 (not installed)" in unmet


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        pytest.param(["a"], ["a", "b"], "build requirements changed (added b)", id="added"),
        pytest.param(["a", "b"], ["a"], "build requirements changed (removed b)", id="removed"),
    ],
)
def test_diff_record_declared_changes(old: list[str], new: list[str], expected: str) -> None:
    record = {"declared": old, "approvals": [], "dependencies": []}
    reasons = diff_record(record, declared=new, resolved={}, approvals=[], unmet=[])
    assert expected in reasons


def test_diff_record_added_and_removed_resolved() -> None:
    record = {"declared": ["a"], "approvals": [], "dependencies": [{"name": "a", "resolved": "1"}]}
    reasons = diff_record(record, declared=["a"], resolved={}, approvals=[], unmet=[])
    assert "build dependency removed: a 1" in reasons

    empty = {"declared": [], "approvals": [], "dependencies": []}
    reasons = diff_record(empty, declared=[], resolved={"b": "2"}, approvals=[], unmet=[])
    assert "build dependency added: b 2" in reasons


def test_diff_record_unmet() -> None:
    record = {"declared": [], "approvals": [], "dependencies": []}
    reasons = diff_record(record, declared=[], resolved={}, approvals=[], unmet=["x (no approval record)"])
    assert reasons == ["build dependency approval not satisfied: x (no approval record)"]


def test_target_change_reasons_skips_other_source() -> None:
    records = [{"key": "k", "source": "other", "package_type": "wheel", "backend": "build", "target": {}}]
    assert target_change_reasons(records, source="digest", package_type="wheel", backend="build", target={}) == []


def test_decision_shape() -> None:
    item = decision(mode="reuse", key="k", reasons=[], artifact="a.whl", record={"x": 1})
    assert item["mode"] == "reuse"
    assert item["provenance"] == {"x": 1}
    assert item["created"]
    empty = decision(mode="rebuild", key="k", reasons=["why"], artifact=None, record=None)
    assert empty["provenance"] is None


def test_store_decisions_are_bounded(tmp_path: Path) -> None:
    store = BuildReuseStore(tmp_path / "prov")
    for index in range(205):
        store.add_decision({"index": index})
    assert len(store.decisions) == 200
    assert store.decisions[0] == {"index": 5}


def test_all_records_lists_every_revision(tmp_path: Path) -> None:
    store = BuildReuseStore(tmp_path / "prov")
    store.add_entry("a", {"v": 1})
    store.add_entry("a", {"v": 2})
    store.add_entry("b", {"v": 3})
    assert [item["v"] for item in store.all_records()] == [1, 2, 3]


def test_source_change_reasons() -> None:
    records = [{"package_type": "wheel", "backend": "build", "source": "abcdef1234567890"}]
    assert source_change_reasons(
        records, source="other", package_type="wheel", backend="build"
    ) == ["source changed since the last build (abcdef123456 -> current)"]
    assert source_change_reasons([], source="other", package_type="wheel", backend="build") == []
    assert (
        source_change_reasons(
            records, source="abcdef1234567890", package_type="wheel", backend="build"
        )
        == []
    )


def test_source_change_reasons_ignores_other_packager() -> None:
    records = [{"package_type": "wheel", "backend": "hatchling", "source": "abcdef"}]
    assert source_change_reasons(records, source="other", package_type="wheel", backend="build") == []
