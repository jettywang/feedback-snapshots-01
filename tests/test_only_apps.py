from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from harness import app_name, run_pipx_cli
from pipx.paths import CTX
from pipx.pipx_metadata_file import PipxMetadata

if TYPE_CHECKING:
    from collections.abc import Callable

_FAKE_TOOLKIT_APPS: Final[dict[str, str]] = {
    "toolbox": "tool",
    "toolbox-admin": "admin",
    "toolbox-doc": "doc",
}
_DEPENDENCY_APPS: Final[dict[str, str]] = {
    "toolbox": "tool",
    "depdoc": "doc",
}


def _write_wheel(
    directory: Path,
    name: str,
    version: str,
    apps: dict[str, str],
    *,
    requires: tuple[str, ...] = (),
    man_pages: tuple[str, ...] = (),
) -> Path:
    """Write a wheel that installs console scripts, an optional dependency and man pages."""
    module: Final[str] = name.replace("-", "_")
    functions: Final[str] = "\n\n".join(
        f'def {function}() -> None:\n    print("{function} {version}")\n' for function in set(apps.values())
    )
    dist_info: Final[str] = f"{module}-{version}.dist-info"
    members: Final[dict[str, str]] = {
        f"{module}.py": functions,
        f"{dist_info}/METADATA": "".join([
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
            *(f"Requires-Dist: {requirement}\n" for requirement in requires),
        ]),
        f"{dist_info}/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{dist_info}/entry_points.txt": "".join([
            "[console_scripts]\n",
            *(f"{app} = {module}:{function}\n" for app, function in apps.items()),
        ]),
        **{
            f"{module}-{version}.data/data/share/man/man1/{page}": f".TH {page.upper()} 1\n"
            for page in man_pages
        },
    }
    directory.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel := directory / f"{module}-{version}-py3-none-any.whl", "w") as archive:
        for member, content in members.items():
            archive.writestr(member, content)
        archive.writestr(
            f"{dist_info}/RECORD", "".join(f"{member},,\n" for member in [*members, f"{dist_info}/RECORD"])
        )
    return wheel


@pytest.fixture
def fake_toolkit(tmp_path: Path) -> Callable[[str, tuple[str, ...]], Path]:
    """Build the toolkit wheel, with the dependency it carries and a documentation man page."""
    wheels: Path = tmp_path / "wheels"
    _write_wheel(wheels, "depbox", "1.0", _DEPENDENCY_APPS)

    def create(version: str = "1.0", requires: tuple[str, ...] = ("depbox==1.0",)) -> Path:
        return _write_wheel(
            wheels, "toolbox", version, _FAKE_TOOLKIT_APPS, requires=requires, man_pages=("toolbox-doc.1",)
        )

    return create


def _install_args(wheel: Path, *extra: str) -> list[str]:
    return ["install", *extra, "--pip-args", f"--no-index --find-links={wheel.parent}", str(wheel)]


def _published_commands() -> list[str]:
    return sorted(path.name for path in CTX.bin_dir.iterdir() if path.name != "pipx")


@pytest.mark.usefixtures("pipx_temp_env")
def test_only_apps_publishes_the_selected_entry_point_only(fake_toolkit: Callable[[], Path]) -> None:
    wheel: Final[Path] = fake_toolkit()

    assert not run_pipx_cli(_install_args(wheel, "--only-apps", "toolbox"))

    venv_bin: Final[Path] = CTX.venvs / "toolbox" / "bin"
    # all the code and every entry point stay installed in the environment
    assert sorted(path.name for path in venv_bin.iterdir() if path.name.startswith(("toolbox", "depdoc"))) == [
        "depdoc",
        "toolbox",
        "toolbox-admin",
        "toolbox-doc",
    ]
    # only the approved entry point reaches ordinary users; the same-named dependency entry and the doc entry do not
    assert _published_commands() == [app_name("toolbox")]
    assert not (CTX.man_dir / "man1" / "toolbox-doc.1").exists()
    metadata: Final[PipxMetadata] = PipxMetadata(CTX.venvs / "toolbox")
    assert (metadata.main_package.exposure.only_apps, metadata.main_package.apps_to_expose) == (
        ["toolbox"],
        ["toolbox"],
    )


@pytest.mark.usefixtures("pipx_temp_env")
def test_only_apps_rejects_a_missing_selection_and_rolls_back(fake_toolkit: Callable[[], Path]) -> None:
    wheel: Final[Path] = fake_toolkit()

    result: Final[int] = run_pipx_cli(_install_args(wheel, "--only-apps", "toolbox-admin", "--only-apps", "missing"))

    assert result == 1
    assert _published_commands() == []
    assert not (CTX.venvs / "toolbox").exists()


@pytest.mark.usefixtures("pipx_temp_env")
def test_only_apps_reinstall_keeps_the_selection(fake_toolkit: Callable[[], Path]) -> None:
    wheel: Final[Path] = fake_toolkit()
    assert not run_pipx_cli(_install_args(wheel, "--only-apps", "toolbox"))

    assert not run_pipx_cli(["reinstall", "toolbox"])

    assert _published_commands() == [app_name("toolbox")]
    assert PipxMetadata(CTX.venvs / "toolbox").main_package.exposure.only_apps == ["toolbox"]


@pytest.mark.usefixtures("pipx_temp_env")
def test_only_apps_failed_upgrade_keeps_the_old_command(fake_toolkit: Callable[[], Path]) -> None:
    wheel: Final[Path] = fake_toolkit()
    assert not run_pipx_cli(_install_args(wheel, "--only-apps", "toolbox"))
    published: Final[Path] = CTX.bin_dir / app_name("toolbox")
    before: Final[str] = subprocess.run([published], check=True, capture_output=True, text=True).stdout

    broken: Final[Path] = fake_toolkit("2.0", ("missing-package-that-cannot-install==9.9",))
    result: Final[int] = run_pipx_cli(_install_args(broken, "--force", "--only-apps", "toolbox"))

    assert result == 1
    metadata: Final[PipxMetadata] = PipxMetadata(CTX.venvs / "toolbox")
    assert (
        published.is_file(),
        subprocess.run([published], check=True, capture_output=True, text=True).stdout,
        metadata.main_package.package_version,
        metadata.main_package.exposure.only_apps,
    ) == (True, before, "1.0", ["toolbox"])


@pytest.mark.usefixtures("pipx_temp_env")
def test_only_apps_removes_a_previously_published_management_command(fake_toolkit: Callable[[], Path]) -> None:
    wheel: Final[Path] = fake_toolkit()
    assert not run_pipx_cli(_install_args(wheel, "--app", "toolbox", "--app", "toolbox-admin"))
    # without a publication selection every installed entry point is exposed, so the doc entry is there too
    assert _published_commands() == [app_name("toolbox"), app_name("toolbox-admin"), app_name("toolbox-doc")]

    assert not run_pipx_cli(_install_args(wheel, "--force", "--only-apps", "toolbox"))

    # the upgrade keeps both entry points in the environment but removes the unapproved link from PATH
    venv_bin: Final[Path] = CTX.venvs / "toolbox" / "bin"
    assert (venv_bin / "toolbox-admin").is_file()
    assert _published_commands() == [app_name("toolbox")]


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param(["--only-apps", "toolbox", "--include-deps"], id="include-deps"),
        pytest.param(["--only-apps", "toolbox", "--include-resources-from", "depbox"], id="include-resources"),
    ],
)
@pytest.mark.usefixtures("pipx_temp_env")
def test_only_apps_rejects_dependency_resource_selection(fake_toolkit: Callable[[], Path], extra: list[str]) -> None:
    wheel: Final[Path] = fake_toolkit()

    assert run_pipx_cli(_install_args(wheel, *extra))

    assert _published_commands() == []
    assert not (CTX.venvs / "toolbox").exists()
