from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

import platformdirs
import pytest

from harness import app_name, run_pipx_cli, write_wheel
from pipx import paths
from pipx.paths import CTX
from pipx.venv import Venv

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pytest_mock import MockerFixture

_APPROVED_SOURCES_FILENAME: Final[str] = "pipx_approved_sources.json"


@pytest.fixture(autouse=True)
def isolated_pipx_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # the fake backend installs nothing, so the pypiserver of pipx_temp_env is unneeded; the paths still
    # get their own isolation so these tests also run under --noconftest
    for name, location in (
        ("OVERRIDE_PIPX_HOME", "subdir/pipxhome"),
        ("OVERRIDE_PIPX_BIN_DIR", "otherdir/pipxbindir"),
        ("OVERRIDE_PIPX_MAN_DIR", "otherdir/pipxmandir"),
        ("OVERRIDE_PIPX_GLOBAL_HOME", "global/pipxhome"),
        ("OVERRIDE_PIPX_GLOBAL_BIN_DIR", "global_otherdir/pipxbindir"),
        ("OVERRIDE_PIPX_GLOBAL_MAN_DIR", "global_otherdir/pipxmandir"),
    ):
        monkeypatch.setattr(paths, name, tmp_path / location)
    monkeypatch.setattr(platformdirs, "user_log_path", lambda *_args, **_kwargs: tmp_path / "fallback_logs")
    monkeypatch.setenv("PIPX_DEFAULT_BACKEND", "pip")
    CTX.make_local()
    yield
    CTX.make_local()


class FakeBackend(NamedTuple):
    """Records of a fake install backend: each preparation and each app it is asked to execute.

    :ivar installs: the package spec of every prepared environment, in order.
    :ivar executions: the content token of the app file every run executed, in order.
    """

    installs: list[str]
    executions: list[str]


@pytest.fixture
def fake_backend(mocker: MockerFixture) -> FakeBackend:
    # stands in for the install backend: preparing an environment stamps the app with a token of the
    # installed content, so a run can only execute what the last preparation approved
    backend: Final = FakeBackend(installs=[], executions=[])

    def create_venv(self: Venv, venv_args: list[str], pip_args: list[str], **kwargs: object) -> None:
        self.bin_path.mkdir(parents=True, exist_ok=True)

    def install_package(
        self: Venv, package_name: str, package_or_url: str, pip_args: list[str], **kwargs: object
    ) -> None:
        backend.installs.append(package_or_url)
        source: Final[Path] = Path(package_or_url)
        token: Final[str] = (
            hashlib.sha256(source.read_bytes()).hexdigest()[:12] if source.is_file() else "from-the-index"
        )
        (self.bin_path / app_name("demo")).write_text(token, encoding="utf-8")

    def run_app(self: Venv, app: str, filename: str, app_args: list[str], **kwargs: object) -> None:
        backend.executions.append((self.bin_path / filename).read_text(encoding="utf-8"))

    mocker.patch("pipx.commands.run.package_name_from_spec", autospec=True, return_value="demo")
    mocker.patch.object(Venv, "check_upgrade_shared_libs", autospec=True)
    mocker.patch.object(Venv, "create_venv", autospec=True, side_effect=create_venv)
    mocker.patch.object(Venv, "install_package", autospec=True, side_effect=install_package)
    mocker.patch.object(Venv, "run_app", autospec=True, side_effect=run_app)
    return backend


@pytest.fixture
def demo_wheel(tmp_path: Path) -> Path:
    return write_wheel(tmp_path, "demo", "1.0", module_code="REVISION = 1\n")


def cached_venv_dir() -> Path:
    return next(path for path in CTX.venv_cache.iterdir() if path.is_dir())


def run_demo(wheel: Path, *extra_args: str) -> None:
    assert not run_pipx_cli(["run", *extra_args, "--spec", str(wheel), "demo"])


def test_approved_cache_reuses_unchanged_source(
    fake_backend: FakeBackend, demo_wheel: Path, caplog: pytest.LogCaptureFixture
) -> None:
    run_demo(demo_wheel, "--approved-cache")
    caplog.set_level(logging.INFO)

    run_demo(demo_wheel, "--approved-cache")

    assert "Reusing cached venv" in caplog.text
    assert "the approved sources are unchanged" in caplog.text
    # the valid cache still spares the preparation
    assert len(fake_backend.installs) == 1
    assert fake_backend.executions == [fake_backend.executions[0], fake_backend.executions[0]]


def test_approved_cache_prepares_rereleased_source_again(
    fake_backend: FakeBackend, demo_wheel: Path, caplog: pytest.LogCaptureFixture
) -> None:
    run_demo(demo_wheel, "--approved-cache")
    approved_token: Final[str] = fake_backend.executions[0]
    # same coordinates, different content: the local build is released again under the same name and version
    write_wheel(demo_wheel.parent, "demo", "1.0", module_code="REVISION = 2\n")
    caplog.set_level(logging.INFO)

    run_demo(demo_wheel, "--approved-cache")

    assert "Preparing cached venv" in caplog.text
    assert "the approved source changed" in caplog.text
    assert len(fake_backend.installs) == 2
    # the unapproved cache was not executed: the second run went through the newly prepared environment
    assert fake_backend.executions[0] == approved_token
    assert fake_backend.executions[1] != approved_token


def test_approved_cache_prepares_cache_without_record_again(
    fake_backend: FakeBackend, demo_wheel: Path, caplog: pytest.LogCaptureFixture
) -> None:
    run_demo(demo_wheel, "--approved-cache")
    # only part of the cache is left: the environment survives but its approval record is gone
    (cached_venv_dir() / _APPROVED_SOURCES_FILENAME).unlink()
    caplog.set_level(logging.INFO)

    run_demo(demo_wheel, "--approved-cache")

    assert "it has no record of approved sources" in caplog.text
    assert len(fake_backend.installs) == 2


def test_approved_cache_prepares_cache_without_app_again(
    fake_backend: FakeBackend, demo_wheel: Path, caplog: pytest.LogCaptureFixture
) -> None:
    run_demo(demo_wheel, "--approved-cache")
    # only part of the cache is left: the approval record matches but the app is gone
    (Venv(cached_venv_dir()).bin_path / app_name("demo")).unlink()
    caplog.set_level(logging.INFO)

    run_demo(demo_wheel, "--approved-cache")

    assert "it does not provide the app" in caplog.text
    assert len(fake_backend.installs) == 2


def test_run_without_approved_cache_reuses_rereleased_source(
    fake_backend: FakeBackend, demo_wheel: Path, caplog: pytest.LogCaptureFixture
) -> None:
    run_demo(demo_wheel)
    write_wheel(demo_wheel.parent, "demo", "1.0", module_code="REVISION = 2\n")
    caplog.set_level(logging.INFO)

    run_demo(demo_wheel)

    # the approved-artifact mode is opt-in: a plain run reuses the cache as before
    assert "Reusing cached venv" in caplog.text
    assert len(fake_backend.installs) == 1


def test_approved_cache_is_mutually_exclusive_with_other_cache_modes(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit, match="2"):
        run_pipx_cli(["run", "--no-cache", "--approved-cache", "demo"])
    assert "not allowed with argument" in capsys.readouterr().err

    with pytest.raises(SystemExit, match="2"):
        run_pipx_cli(["run", "--refresh", "--approved-cache", "demo"])
    assert "not allowed with argument" in capsys.readouterr().err
