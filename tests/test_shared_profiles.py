"""Versioned shared libraries profiles, exercised with local stand-ins and a recording fake installer.

The profiles hold pip for pipx's environments, so these tests never download pip: a fake ``run_subprocess`` records the
commands pipx would run and lays down the files pip would have installed. Each profile is a small directory tree, and
the environments that borrow one are built the same way, so the tests exercise independent upgrades, failed upgrades,
reuse of an older environment, and reclamation once nothing references a profile.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from harness import run_pipx_cli
from pipx import paths, shared_libs, shared_profiles
from pipx.constants import PIPX_SHARED_PTH, WINDOWS
from pipx.options import BackendOptions
from pipx.pipx_metadata_file import PIPX_INFO_FILENAME, PipxMetadata
from pipx.shared_libs import _SharedLibs
from pipx.shared_profiles import Profile, profile_root, profiles_root
from pipx.util import get_venv_paths

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from subprocess import CompletedProcess

    from pytest_mock import MockerFixture

_PIP_METADATA: Final[re.Pattern[str]] = re.compile(r"^Version:\s*(\S+)", re.MULTILINE)


@dataclass
class Installer:
    """Stand-in for pip: records each command and writes the files a successful install would.

    :param successful: the versions the fake install accepts; a pin to any other version fails.
    """

    successful: set[str] = field(default_factory=set)
    calls: list[list[str]] = field(default_factory=list)

    def run(self, command: Sequence[str | Path], **kwargs: object) -> CompletedProcess[str]:
        del kwargs
        argv: Final[list[str]] = [str(part) for part in command]
        self.calls.append(argv)
        return _answer(argv, self.successful)

    def pip_installs(self) -> list[list[str]]:
        return [call for call in self.calls if _installs_pip(call)]

    def requirements(self) -> list[str]:
        return [call[-1] for call in self.pip_installs()]


def _installs_pip(argv: list[str]) -> bool:
    return "install" in argv and argv[-1].lower().startswith("pip")


def _answer(argv: list[str], successful: set[str]) -> CompletedProcess[str]:
    import subprocess

    if "venv" in argv and "--without-pip" in argv:
        _layout_venv(Path(argv[-1]))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    if len(argv) > 2 and argv[1] == "-c" and "sysconfig.get_path" in argv[2]:
        root: Final[Path] = Path(argv[0]).parent.parent
        site: Final[Path] = _site_packages_for(root)
        return subprocess.CompletedProcess(argv, 0, stdout=f"{site}\n{site}\n", stderr="")
    if "ensurepip" in argv:
        # the real ensurepip lays down the interpreter's bundled pip; a stand-in for the accepted floor is enough
        _lay_down_pip(Path(argv[0]).parent.parent, shared_profiles.PIP_FLOOR)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    if _installs_pip(argv) and "uninstall" not in argv:
        return _install_pip(argv, successful)
    if "uninstall" in argv:
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def _install_pip(argv: list[str], successful: set[str]) -> CompletedProcess[str]:
    import subprocess

    version: str | None = _pinned_pip_version(argv)
    if version is not None and version not in successful:
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr=f"no matching distribution for pip {version}")
    target: Final[Path] = Path(argv[0]).parent.parent
    written: Final[str] = version or _highest(successful) or "26.2.2"
    _lay_down_pip(target, written)
    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def _pinned_pip_version(argv: list[str]) -> str | None:
    for argument in argv:
        match: Final[re.Match[str] | None] = re.fullmatch(r"pip==([^\s]+)", argument)
        if match is not None:
            return match.group(1)
    return None


def _highest(versions: set[str]) -> str | None:
    return max(versions, key=_version_key) if versions else None


def _version_key(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text))


def _layout_venv(root: Path) -> None:
    """Create the files ``python -m venv`` would, so validity checks find a working interpreter."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyvenv.cfg").write_text("version = 3.12.11\n", encoding="utf-8")
    _, python_path, _ = get_venv_paths(root)
    python_path.parent.mkdir(parents=True, exist_ok=True)
    python_path.write_text("# stand-in\n", encoding="utf-8")
    _site_packages_for(root).mkdir(parents=True, exist_ok=True)


def _lay_down_pip(root: Path, version: str) -> None:
    site_packages: Final[Path] = _site_packages_for(root)
    package: Final[Path] = site_packages / "pip" / "_internal" / "cli"
    package.mkdir(parents=True, exist_ok=True)
    (package / "main.py").write_text("# stand-in\n", encoding="utf-8")
    dist_info: Final[Path] = site_packages / f"pip-{version}.dist-info"
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: pip\nVersion: {version}\n", encoding="utf-8"
    )
    bin_dir, _, _ = get_venv_paths(root)
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / ("pip.exe" if WINDOWS else "pip")).write_text("# stand-in\n", encoding="utf-8")


def _site_packages_for(root: Path) -> Path:
    if WINDOWS:
        return root / "Lib" / "site-packages"
    version: Final[str] = f"python{sys.version_info.major}.{sys.version_info.minor}"
    return root / "lib" / version / "site-packages"


@pytest.fixture
def installer(mocker: MockerFixture) -> Installer:
    record: Final[Installer] = Installer()
    mocker.patch("pipx.shared_libs.run_subprocess", autospec=True, side_effect=record.run)
    return record


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point a fresh pipx home at a temporary directory without the pypiserver the other tests share."""
    home: Final[Path] = tmp_path / "pipxhome"
    for name, value in {
        "OVERRIDE_PIPX_HOME": home,
        "OVERRIDE_PIPX_SHARED_LIBS": home / "shared",
        "OVERRIDE_PIPX_BIN_DIR": tmp_path / "bin",
        "OVERRIDE_PIPX_MAN_DIR": tmp_path / "man",
    }.items():
        monkeypatch.setattr(paths, name, value)
    monkeypatch.setattr(paths, "OVERRIDE_PIPX_GLOBAL_HOME", None)
    monkeypatch.setattr(paths, "OVERRIDE_PIPX_GLOBAL_SHARED_LIBS", None)
    paths.CTX.make_local()
    fresh: Final[_SharedLibs] = _SharedLibs()
    import pipx.backends.pip as pip_backend
    import pipx.venv as venv_module

    monkeypatch.setattr(shared_libs, "SHARED_LIBS", fresh)
    # every caller resolves through shared_libs_for, so route the default profile to the fresh instance while keeping
    # the instances that name another profile
    patched_for: Final[Callable[[str | None], _SharedLibs]] = (
        lambda name: fresh if name in {None, "default"} else fresh.for_profile(name)
    )
    import pipx.commands.shared as shared_command

    for module in (shared_libs, venv_module, pip_backend, shared_command):
        monkeypatch.setattr(module, "shared_libs_for", patched_for)
    monkeypatch.delenv("PIPX_DISABLE_SHARED_LIBS_AUTO_UPGRADE", raising=False)
    return home


def _write_stand_in_environment(home: Path, name: str, profile: str, *, package: str = "tool") -> Path:
    """Create a virtual environment tree that links to a profile the way pipx writes it."""
    venv_dir: Final[Path] = home / "venvs" / name
    site_packages: Final[Path] = _site_packages_for(venv_dir)
    site_packages.mkdir(parents=True, exist_ok=True)
    (venv_dir / "pyvenv.cfg").write_text("version = 3.12.11\n", encoding="utf-8")
    _, python_path, _ = get_venv_paths(venv_dir)
    python_path.parent.mkdir(parents=True, exist_ok=True)
    python_path.write_text("# stand-in\n", encoding="utf-8")
    root: Final[Path] = profile_root(profile) if profile != "default" else home / "shared"
    shared_site: Final[Path] = _site_packages_for(root)
    (site_packages / PIPX_SHARED_PTH).write_text(f"{shared_site}\n", encoding="utf-8")
    metadata: Final[PipxMetadata] = PipxMetadata(venv_dir, read=False)
    metadata.main_package = _package_info(package)
    metadata.backend = "pip"
    metadata.shared_profile = profile
    metadata.python_version = "Python 3.12.11"
    metadata.write()
    return venv_dir


def _package_info(name: str) -> object:
    from pipx.options import ExposureOptions
    from pipx.pipx_metadata_file import PackageInfo, PackageResources

    return PackageInfo(
        package=name,
        package_or_url=name,
        pip_args=[],
        exposure=ExposureOptions(),
        resources=PackageResources(
            apps=[name], app_paths=[Path("/tmp") / name], apps_of_dependencies=[], app_paths_of_dependencies={}
        ),
        package_version="1.0",
    )


def _pip_version_in(root: Path) -> str | None:
    for dist_info in root.glob("**/pip-*.dist-info/METADATA"):
        match: Final[re.Match[str] | None] = _PIP_METADATA.search(dist_info.read_text(encoding="utf-8"))
        if match is not None:
            return match.group(1)
    return None


def _reset_shared_state() -> None:
    for shared in [shared_libs.SHARED_LIBS, *shared_libs.SHARED_LIBS._by_profile.values()]:
        shared.has_been_updated_this_run = False


def _declare(name: str, requires: str) -> None:
    profile: Final[Profile] = shared_profiles.declare(name, requires=requires)
    assert profile.registered


def test_legacy_default_profile_reads_the_historical_requirement(isolated_env: Path) -> None:
    profile: Final[Profile] = shared_profiles.load("default")

    assert (profile.effective_requires, profile.minimum_pip) == ("pip>=26.2.2", profile.minimum_pip)
    assert str(profile.minimum_pip) == "26.2.2"


def test_declare_only_records_without_touching_other_profiles(isolated_env: Path, installer: Installer) -> None:
    _declare("service-a", "pip==26.1.3")

    assert (shared_profiles.load("service-a").requires, installer.calls) == ("pip==26.1.3", [])
    recorded: Final[dict[str, object]] = json.loads(
        (profile_root("service-a") / "shared_profile.json").read_text(encoding="utf-8")
    )
    assert (recorded["requires"], recorded["schema"]) == ("pip==26.1.3", 1)


def test_apply_installs_only_the_requested_profile(isolated_env: Path, installer: Installer) -> None:
    installer.successful = {"26.1.3", "26.3.0"}
    _declare("service-a", "pip==26.1.3")
    _declare("service-b", "pip==26.3.0")

    assert not run_pipx_cli(["profile", "upgrade", "service-a"])

    assert _pip_version_in(profile_root("service-a")) == "26.1.3"
    assert _pip_version_in(profile_root("service-b")) is None
    assert installer.requirements() == ["pip==26.1.3"]


def test_failed_upgrade_keeps_the_previous_pip_and_declaration(isolated_env: Path, installer: Installer) -> None:
    installer.successful = {"26.1.3"}
    _declare("service-a", "pip==26.1.3")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])
    before: Final[str] = (profile_root("service-a") / "shared_profile.json").read_text(encoding="utf-8")

    # a pin outside the declaration is refused before pip runs, leaving the profile whole
    assert run_pipx_cli(["profile", "upgrade", "service-a", "--pip-args", "pip==26.3.0"])
    assert _pip_version_in(profile_root("service-a")) == "26.1.3"
    assert (profile_root("service-a") / "shared_profile.json").read_text(encoding="utf-8") == before
    assert installer.requirements() == ["pip==26.1.3"]


def test_installer_failure_leaves_the_previous_pip(isolated_env: Path, installer: Installer) -> None:
    installer.successful = {"26.1.3"}
    _declare("service-a", "pip>=26.1,<26.2")
    assert not run_pipx_cli(["profile", "upgrade", "service-a", "--pip-args", "pip==26.1.3"])
    # a real pipx run is a fresh process; drop the per-process flag the instance carries between in-process runs
    _reset_shared_state()
    installer.successful = {"26.1.0"}  # the pin below is not in the accepted set, so pip fails

    assert run_pipx_cli(["profile", "upgrade", "service-a", "--pip-args", "pip==26.1.9"])

    # the pin was inside the declaration, so pip ran and failed; the earlier pip and revision stay put
    assert _pip_version_in(profile_root("service-a")) == "26.1.3"
    assert shared_profiles.load("service-a").revision == 1
    assert installer.requirements() == ["pip==26.1.3", "pip==26.1.9"]


def test_force_records_an_override_across_the_declaration(isolated_env: Path, installer: Installer) -> None:
    installer.successful = {"26.3.0"}
    _declare("service-a", "pip==26.1.3")

    assert not run_pipx_cli(["profile", "upgrade", "service-a", "--pip-args", "pip==26.3.0", "--force"])

    profile: Final[Profile] = shared_profiles.load("service-a")
    assert (_pip_version_in(profile_root("service-a")), profile.compatibility_override) == ("26.3.0", True)


def test_older_environment_keeps_working_on_its_own_profile(isolated_env: Path, installer: Installer) -> None:
    installer.successful = {"26.1.3"}
    _declare("service-a", "pip==26.1.3")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])
    venv_dir: Final[Path] = _write_stand_in_environment(isolated_env, "legacy-tool", "service-a")

    # a newer profile is added and upgraded; the old environment still points at its own profile's pip
    installer.successful = {"26.3.0"}
    _declare("service-b", "pip==26.3.0")
    assert not run_pipx_cli(["profile", "upgrade", "service-b"])

    pth: Final[Path] = next(venv_dir.glob(f"**/{PIPX_SHARED_PTH}"))
    linked: Final[Path] = Path(pth.read_text(encoding="utf-8").strip())
    assert (linked, _pip_version_in(linked)) == (_site_packages_for(profile_root("service-a")), "26.1.3")


def test_profile_list_reports_declaration_and_users(isolated_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _declare("service-a", "pip==26.1.3")
    _write_stand_in_environment(isolated_env, "tool-a", "service-a")

    assert not run_pipx_cli(["profile", "list", "--output", "json"])

    document: Final[dict[str, object]] = json.loads(capsys.readouterr().out)
    rows: Final[list[dict[str, object]]] = document["data"]["profiles"]  # type: ignore[index]
    by_name: Final[dict[str, dict[str, object]]] = {row["name"]: row for row in rows}
    assert (by_name["service-a"]["requires"], by_name["service-a"]["referenced_by"]) == (
        "pip==26.1.3",
        ["tool-a"],
    )


def test_reclaim_refuses_a_profile_still_in_use(isolated_env: Path) -> None:
    _declare("service-a", "pip==26.1.3")
    _write_stand_in_environment(isolated_env, "tool-a", "service-a")

    assert run_pipx_cli(["profile", "reclaim", "service-a"])
    assert profile_root("service-a").is_dir()


def test_reclaim_removes_a_profile_no_environment_uses(isolated_env: Path, installer: Installer) -> None:
    installer.successful = {"26.1.3"}
    _declare("service-a", "pip==26.1.3")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])

    assert not run_pipx_cli(["profile", "reclaim", "service-a"])

    assert not profile_root("service-a").is_dir()


def test_dry_run_reclaim_and_gc_change_nothing(isolated_env: Path, installer: Installer) -> None:
    installer.successful = {"26.1.3"}
    _declare("service-a", "pip==26.1.3")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])

    assert not run_pipx_cli(["profile", "reclaim", "service-a", "--dry-run"])
    assert not run_pipx_cli(["profile", "gc", "--dry-run"])

    assert _pip_version_in(profile_root("service-a")) == "26.1.3"


def test_gc_reclaims_only_unused_profiles(isolated_env: Path, installer: Installer) -> None:
    installer.successful = {"26.1.3"}
    _declare("service-a", "pip==26.1.3")
    _declare("service-b", "pip==26.1.3")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])
    assert not run_pipx_cli(["profile", "upgrade", "service-b"])
    _write_stand_in_environment(isolated_env, "tool-a", "service-a")

    assert not run_pipx_cli(["profile", "gc"])

    assert (profile_root("service-a").is_dir(), profile_root("service-b").is_dir()) == (True, False)


def test_reclaim_never_removes_the_default_profile(isolated_env: Path) -> None:
    assert run_pipx_cli(["profile", "reclaim", "default"])


def test_profile_names_cannot_escape_the_profiles_directory(isolated_env: Path) -> None:
    assert run_pipx_cli(["profile", "declare", "../escape", "--requires", "pip==26.1.3"])
    with pytest.raises(Exception, match="Invalid shared profile name"):
        shared_profiles.profile_root("../escape")


def test_declaration_must_name_pip(isolated_env: Path) -> None:
    with pytest.raises(Exception, match="must name pip"):
        shared_profiles.declare("service-a", requires="setuptools==1")


def test_default_install_links_the_default_profile(isolated_env: Path, installer: Installer) -> None:
    # the classic layout is unchanged: a pip-backed environment links to $PIPX_HOME/shared
    _write_stand_in_environment(isolated_env, "tool", "default")
    pth: Final[Path] = next((isolated_env / "venvs" / "tool").glob(f"**/{PIPX_SHARED_PTH}"))

    assert Path(pth.read_text(encoding="utf-8").strip()) == _site_packages_for(isolated_env / "shared")


def test_metadata_records_and_reads_the_profile(isolated_env: Path) -> None:
    venv_dir: Final[Path] = _write_stand_in_environment(isolated_env, "tool", "service-a")

    assert PipxMetadata(venv_dir).shared_profile == "service-a"
    payload: Final[dict[str, object]] = json.loads((venv_dir / PIPX_INFO_FILENAME).read_text(encoding="utf-8"))
    assert payload["pipx_metadata_version"] == "0.13"


def test_old_metadata_reads_as_the_default_profile(isolated_env: Path) -> None:
    venv_dir: Final[Path] = _write_stand_in_environment(isolated_env, "tool", "default")
    record: Final[Path] = venv_dir / PIPX_INFO_FILENAME
    payload: Final[Mapping[str, object]] = json.loads(record.read_text(encoding="utf-8"))
    payload_without_profile: Final[dict[str, object]] = dict(payload)
    payload_without_profile.pop("shared_profile")
    payload_without_profile["pipx_metadata_version"] = "0.12"
    record.write_text(json.dumps(payload_without_profile), encoding="utf-8")

    assert PipxMetadata(venv_dir).shared_profile == "default"


def test_gc_after_reinstalling_away_from_a_profile(isolated_env: Path, installer: Installer) -> None:
    installer.successful = {"26.1.3"}
    _declare("service-a", "pip==26.1.3")
    _declare("service-b", "pip==26.1.3")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])
    assert not run_pipx_cli(["profile", "upgrade", "service-b"])
    venv_dir: Final[Path] = _write_stand_in_environment(isolated_env, "tool-a", "service-a")

    # moving the environment onto another profile makes the first one unreferenced
    _write_stand_in_environment(isolated_env, "tool-a", "service-b")
    assert not run_pipx_cli(["profile", "gc"])

    assert (profile_root("service-a").is_dir(), profile_root("service-b").is_dir()) == (False, True)
    assert venv_dir.is_dir()


def test_upgrade_without_declaration_is_refused(isolated_env: Path) -> None:
    assert run_pipx_cli(["profile", "upgrade", "undeclared"])


def test_create_venv_records_the_profile_and_links_it(
    isolated_env: Path, installer: Installer, mocker: MockerFixture
) -> None:
    from pipx.backends.pip import PipBackend
    from pipx.venv import Venv

    # the pip backend runs python -m venv through its own binding of run_subprocess
    mocker.patch("pipx.backends.pip.run_subprocess", autospec=True, side_effect=installer.run)
    installer.successful = {"26.1.3"}
    _declare("service-a", "pip==26.1.3")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])

    venv: Final[Venv] = Venv(
        isolated_env / "venvs" / "tool-a",
        backend=BackendOptions(cli="pip"),
        profile="service-a",
    )
    venv.pipx_metadata.main_package = _package_info("tool-a")
    venv.create_venv([], [])

    assert venv.pipx_metadata.shared_profile == "service-a"
    pth: Final[Path] = next(venv.root.glob(f"**/{PIPX_SHARED_PTH}"))
    assert Path(pth.read_text(encoding="utf-8").strip()) == _site_packages_for(profile_root("service-a"))


def test_install_selects_a_declared_profile(isolated_env: Path, installer: Installer) -> None:
    from pipx.backends.pip import PipBackend

    installer.successful = {"26.1.3"}
    _declare("service-a", "pip==26.1.3")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])

    venv_root: Final[Path] = isolated_env / "venvs" / "tool-a"
    PipBackend().create_venv(
        venv_root,
        python=sys.executable,
        venv_args=[],
        pip_args=[],
        include_pip=False,
        verbose=False,
        profile="service-a",
    )

    pth: Final[Path] = next(venv_root.glob(f"**/{PIPX_SHARED_PTH}"))
    assert Path(pth.read_text(encoding="utf-8").strip()) == _site_packages_for(profile_root("service-a"))


@pytest.mark.parametrize(
    ("requires", "minimum"),
    [
        pytest.param("pip==26.1.3", "26.1.3", id="exact"),
        pytest.param("pip>=26.1,<26.2", "26.1", id="range-with-upper"),
        pytest.param("pip<26.2", "26.1", id="upper-only"),
        pytest.param("pip>=26.1.0,!=26.1.0", "26.1.1", id="exclusion-raises-floor"),
        pytest.param("pip~=26.1", "26.1", id="compatible-release"),
        pytest.param("pip>=26.2.2", "26.2.2", id="floor"),
    ],
)
def test_minimum_version_reads_the_lower_bound(isolated_env: Path, requires: str, minimum: str) -> None:
    assert str(shared_profiles.minimum_version_of(requires, default="26.2.2")) == minimum


def test_override_inside_the_declaration_is_allowed(isolated_env: Path) -> None:
    profile: Final[Profile] = shared_profiles.declare("service-a", requires="pip>=26.1,<26.2")

    assert shared_profiles.check_pip_override(profile, ["pip==26.1.3"], force=False) is False


def test_override_outside_the_declaration_needs_force(isolated_env: Path) -> None:
    profile: Final[Profile] = shared_profiles.declare("service-a", requires="pip>=26.1,<26.2")

    with pytest.raises(Exception, match="does not accept pip"):
        shared_profiles.check_pip_override(profile, ["pip==26.2.0"], force=False)
    assert shared_profiles.check_pip_override(profile, ["pip==26.2.0"], force=True) is True


def test_override_must_pin_an_exact_version(isolated_env: Path) -> None:
    profile: Final[Profile] = shared_profiles.declare("service-a", requires="pip>=26.1,<26.2")

    with pytest.raises(Exception, match="exact pip version"):
        shared_profiles.check_pip_override(profile, ["pip<26.2"], force=False)


def test_legacy_default_profile_has_no_declaration_file(isolated_env: Path) -> None:
    # the historical shared directory carries no manifest, so a default environment keeps behaving as before
    profile: Final[Profile] = shared_profiles.load("default")

    assert profile.registered is False
    assert not (isolated_env / "shared" / "shared_profile.json").exists()


def test_manifest_is_atomic_and_schema_stamped(isolated_env: Path) -> None:
    shared_profiles.declare("service-a", requires="pip==26.1.3", python_requires=">=3.11")

    payload: Final[dict[str, object]] = json.loads(
        (profile_root("service-a") / "shared_profile.json").read_text(encoding="utf-8")
    )
    assert (payload["schema"], payload["requires"], payload["python_requires"]) == (1, "pip==26.1.3", ">=3.11")
    assert not list(profile_root("service-a").glob(".shared_profile.json.*.tmp"))


def test_check_upgrade_refreshes_only_the_environments_profile(
    isolated_env: Path, installer: Installer, mocker: MockerFixture
) -> None:
    from pipx.venv import Venv

    installer.successful = {"26.1.3", "26.3.0"}
    _declare("service-a", "pip==26.1.3")
    _declare("service-b", "pip==26.3.0")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])
    assert not run_pipx_cli(["profile", "upgrade", "service-b"])
    _reset_shared_state()

    # service-b's environment notices its pip drifted from the declaration and refreshes only its own profile
    venv_dir: Final[Path] = _write_stand_in_environment(isolated_env, "tool-b", "service-b")
    drifted_info: Final[Path] = _site_packages_for(profile_root("service-b")) / "pip-26.3.0.dist-info"
    (drifted_info / "METADATA").write_text("Metadata-Version: 2.1\nName: pip\nVersion: 26.2.0\n", encoding="utf-8")

    Venv(venv_dir).check_upgrade_shared_libs(verbose=False, pip_args=[])

    assert _pip_version_in(profile_root("service-a")) == "26.1.3"
    assert installer.requirements().count("pip==26.1.3") == 1  # service-a was only built once


def test_profile_gc_json_reports_reclaimed_profiles(
    isolated_env: Path, installer: Installer, capsys: pytest.CaptureFixture[str]
) -> None:
    installer.successful = {"26.1.3"}
    _declare("service-a", "pip==26.1.3")
    assert not run_pipx_cli(["profile", "upgrade", "service-a"])
    capsys.readouterr()  # the upgrade echoed its success message

    assert not run_pipx_cli(["profile", "gc", "--output", "json"])

    document: Final[dict[str, object]] = json.loads(capsys.readouterr().out)
    assert document["command"] == ["profile", "gc"]
    assert [row["name"] for row in document["data"]["profiles"]] == ["service-a"]  # type: ignore[index]


def test_environment_reports_the_profiles_root(isolated_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert not run_pipx_cli(["environment", "--value", "PIPX_SHARED_PROFILES"])

    assert capsys.readouterr().out.strip() == str(profiles_root())
