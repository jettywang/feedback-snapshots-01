"""Acceptance tests for the optional editable source-root validation.

Scenario: a minimal project with two legitimate source roots and one new,
unapproved root.  Editable and regular wheels are built before and after a
workspace migration.  The checks cover the real ``.pth`` content, offline
import resolution, rejection diagnostics and regular-wheel member parity.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile

from pathlib import Path
from typing import Any

import pytest

from poetry.core.factory import Factory
from poetry.core.masonry.builders.wheel import WheelBuilder
from poetry.core.masonry.utils.editable_roots import EditableRootPolicy
from poetry.core.masonry.utils.editable_roots import UnapprovedEditableRootError
from poetry.core.masonry.utils.editable_roots import validate_editable_roots


PACKAGES_WITH_THREE_ROOTS = """\
packages = [
  { include = "alpha_pkg", from = "src" },
  { include = "beta_pkg", from = "modules" },
  { include = "gamma_pkg", from = "experimental" },
]
"""


def _write_project(root: Path, *, approved: bool = False, gamma: bool = True) -> Path:
    (root / "src" / "alpha_pkg").mkdir(parents=True, exist_ok=True)
    (root / "src" / "alpha_pkg" / "__init__.py").write_text(
        'NAME = "alpha"\n', encoding="utf-8"
    )
    (root / "modules" / "beta_pkg").mkdir(parents=True, exist_ok=True)
    (root / "modules" / "beta_pkg" / "__init__.py").write_text(
        'NAME = "beta"\n', encoding="utf-8"
    )

    packages = [
        '{ include = "alpha_pkg", from = "src" }',
        '{ include = "beta_pkg", from = "modules" }',
    ]
    if gamma:
        (root / "experimental" / "gamma_pkg").mkdir(parents=True, exist_ok=True)
        (root / "experimental" / "gamma_pkg" / "__init__.py").write_text(
            'NAME = "gamma"\n', encoding="utf-8"
        )
        packages.append('{ include = "gamma_pkg", from = "experimental" }')

    approved_block = ""
    if approved:
        # Deliberately redundant representations of the same two roots.
        approved_block = (
            "\napproved-source-roots = [\n"
            '  "src", "./src/", "src/../src",\n'
            '  "modules", "./modules/",\n'
            "]\n"
        )

    (root / "pyproject.toml").write_text(
        "[tool.poetry]\n"
        'name = "roots-demo"\n'
        'version = "0.1.0"\n'
        'description = "multi source roots"\n'
        'authors = ["Team <team@example.com>"]\n'
        "packages = [\n    " + ",\n    ".join(packages) + ",\n]\n" + approved_block,
        encoding="utf-8",
    )
    return root


def _build(
    root: Path,
    dist: Path,
    *,
    editable: bool,
    **kwargs: Any,
) -> Path:
    dist.mkdir(parents=True, exist_ok=True)
    poetry = Factory().create_poetry(root, with_groups=False)
    filename = WheelBuilder.make_in(poetry, dist, editable=editable, **kwargs)
    return dist / filename


def _pth_entries(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as zf:
        pth_name = next(n for n in zf.namelist() if n.endswith(".pth"))
        return [
            line for line in zf.read(pth_name).decode().splitlines() if line.strip()
        ]


def _namelist(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as zf:
        return sorted(zf.namelist())


def test_canonical_representations_deduplicate_to_one_root(tmp_path: Path) -> None:
    policy = EditableRootPolicy(
        ["src", "./src/", "src/../src", str(tmp_path / "src")],
        project_root=tmp_path,
    )
    assert len(policy.approved_roots) == 1
    assert policy.approved_roots[0] == (tmp_path / "src").resolve()


def test_symlink_alias_counts_as_one_root(tmp_path: Path) -> None:
    real_src = tmp_path / "src"
    real_src.mkdir()
    link_src = tmp_path / "src-link"
    try:
        link_src.symlink_to(real_src, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported for this user/platform")
    policy = EditableRootPolicy(["src", "src-link", "./src/"], project_root=tmp_path)
    assert len(policy.approved_roots) == 1
    assert policy.approved_roots[0] == real_src.resolve()
    assert policy.is_approved(link_src)


def test_approval_is_path_part_aware(tmp_path: Path) -> None:
    policy = EditableRootPolicy(["src"], project_root=tmp_path)
    assert policy.is_approved(tmp_path / "src" / "alpha_pkg")
    # Naive string-prefix matching would wrongly accept this sibling.
    assert not policy.is_approved(tmp_path / "src-evil" / "pkg")
    assert not policy.is_approved(tmp_path / "elsewhere")


def test_validate_returns_full_report_and_pinpoints_branch(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path, approved=True)
    poetry = Factory().create_poetry(tmp_path, with_groups=False)
    builder = WheelBuilder(poetry, editable=True)
    with pytest.raises(UnapprovedEditableRootError) as exc_info:
        builder.validate_editable_roots()
    report = exc_info.value.report
    assert not report.ok
    assert len(report.search_roots) == 3
    (violation,) = report.violations
    assert violation.package == "gamma_pkg"
    assert violation.source == "experimental"
    assert violation.path == (tmp_path / "experimental").resolve()
    # The two approved roots are retained for diagnostics.
    assert len(report.approved_roots) == 2


def test_full_migration_wheel_and_offline_import_scenario(
    tmp_path: Path,
) -> None:
    workspace_a = tmp_path / "workspace-v1"
    workspace_a.mkdir()
    _write_project(workspace_a, approved=False)

    # Feature off: editable .pth lists all three effective roots.
    editable_off = _build(workspace_a, tmp_path / "dist-a-off", editable=True)
    pth_a = _pth_entries(editable_off)
    assert len(pth_a) == 3
    resolved_a = workspace_a.resolve()
    assert all(Path(p) == Path(p).resolve() for p in pth_a)
    assert all(resolved_a.as_posix() in p for p in pth_a)

    # Regular wheel baseline members before enabling the feature.
    normal_before = _build(
        workspace_a, tmp_path / "dist-a-normal-before", editable=False
    )
    members_before = _namelist(normal_before)

    # Enable approved-root configuration.
    _write_project(workspace_a, approved=True)

    # Regular wheel member locations are unchanged by the feature.
    normal_after = _build(workspace_a, tmp_path / "dist-a-normal-after", editable=False)
    assert _namelist(normal_after) == members_before

    # Editable build is rejected before any wheel lands in the target dir.
    rejected_dist = tmp_path / "dist-a-rejected"
    with pytest.raises(UnapprovedEditableRootError) as exc_info:
        _build(workspace_a, rejected_dist, editable=True)
    message = str(exc_info.value)
    assert "experimental" in message
    assert "gamma_pkg" in message
    assert not list(rejected_dist.glob("*.whl"))

    # ---- Migrate the workspace to a new absolute location ----
    workspace_b = tmp_path / "workspace-v2-migrated"
    shutil.move(str(workspace_a), str(workspace_b))
    resolved_b = workspace_b.resolve()

    with pytest.raises(UnapprovedEditableRootError) as exc_info_b:
        _build(workspace_b, tmp_path / "dist-b-rejected", editable=True)
    message_b = str(exc_info_b.value)
    # Relative configuration re-resolves against the new workspace...
    assert resolved_b.as_posix() in message_b
    assert "experimental" in message_b
    # ...and stale approvals from the old location are not reused.
    assert resolved_a.as_posix() not in message_b
    assert all(
        str(resolved_b) in str(root) for root in exc_info_b.value.report.approved_roots
    )

    # The regular wheel is unaffected by both the gate and the migration:
    # its archive member locations stay identical to the pre-feature build.
    normal_after_migration = _build(
        workspace_b, tmp_path / "dist-b-normal", editable=False
    )
    assert _namelist(normal_after_migration) == members_before

    # Removing the unapproved root makes the editable build succeed.
    _write_project(workspace_b, approved=True, gamma=False)
    fixed_wheel = _build(workspace_b, tmp_path / "dist-b-fixed", editable=True)
    pth_b = _pth_entries(fixed_wheel)
    assert {Path(p) for p in pth_b} == {
        (resolved_b / "src").resolve(),
        (resolved_b / "modules").resolve(),
    }

    # Install the wheel into an isolated site-packages (unzip == wheel install)
    # and let the interpreter process the .pth at startup via addsitedir.
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    with zipfile.ZipFile(fixed_wheel) as zf:
        zf.extractall(site_packages)

    probe = (
        "import site\n"
        f"site.addsitedir({str(site_packages)!r})\n"
        "import alpha_pkg, beta_pkg\n"
        "print('ALPHA=' + alpha_pkg.__file__)\n"
        "print('BETA=' + beta_pkg.__file__)\n"
        "try:\n"
        "    import gamma_pkg\n"
        "    print('GAMMA_LEAK=' + gamma_pkg.__file__)\n"
        "except ModuleNotFoundError:\n"
        "    print('GAMMA_BLOCKED')\n"
    )

    proc = subprocess.run(
        [sys.executable, "-I", "-c", probe],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert f"ALPHA={resolved_b / 'src'}" in proc.stdout
    assert f"BETA={resolved_b / 'modules'}" in proc.stdout
    assert "GAMMA_BLOCKED" in proc.stdout
    assert "GAMMA_LEAK" not in proc.stdout


def test_explicit_roots_and_config_settings_channels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write_project(root, approved=False)
    monkeypatch.chdir(root)

    from poetry.core.masonry import api

    with pytest.raises(UnapprovedEditableRootError):
        api.build_editable(
            str(tmp_path / "d1"),
            config_settings={"approved-source-roots": ["src"]},
        )

    filename = api.build_editable(
        str(tmp_path / "d2"),
        config_settings={"approved-source-roots": ["src", "modules", "experimental"]},
    )
    assert (tmp_path / "d2" / filename).exists()

    # Standalone functional entry point behaves the same.
    from poetry.core.masonry.utils.editable_roots import evaluate_editable_roots

    report = evaluate_editable_roots(
        [root / "src", root / "modules"],
        ["src"],
        project_root=root,
    )
    assert not report.ok
    assert {v.path.name for v in report.violations} == {"modules"}

    # The raising variant exposes the same report on the exception.
    with pytest.raises(UnapprovedEditableRootError):
        validate_editable_roots(
            [root / "src", root / "modules"],
            ["src"],
            project_root=root,
        )


def test_disabled_by_default_and_env_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write_project(root, approved=False)

    # No configuration: build succeeds and no policy is attached.
    poetry = Factory().create_poetry(root, with_groups=False)
    builder = WheelBuilder(poetry, editable=True)
    assert builder.validate_editable_roots() is None
    wheel = builder.build(tmp_path / "dist")
    assert wheel.exists()

    # Environment variable opts in with an absolute root.
    monkeypatch.setenv("POETRY_APPROVED_SOURCE_ROOTS", os.pathsep.join(["src"]))
    poetry2 = Factory().create_poetry(root, with_groups=False)
    builder2 = WheelBuilder(poetry2, editable=True)
    with pytest.raises(UnapprovedEditableRootError):
        builder2.build(tmp_path / "dist2")
