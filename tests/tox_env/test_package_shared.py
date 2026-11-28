"""The contract for run environments that share a packaging environment."""

from __future__ import annotations

import threading
import time
from textwrap import dedent
from typing import TYPE_CHECKING

import pytest

from tox.tox_env.errors import Fail
from tox.tox_env.package import packages_valid
from tox.tox_env.python.package import WheelPackage

if TYPE_CHECKING:
    from pathlib import Path

    from pytest_mock import MockerFixture

    from tox.pytest import ToxProjectCreator
    from tox.tox_env.package import Package, PackageToxEnv


@pytest.fixture
def shared_env(tox_project: ToxProjectCreator) -> tuple[PackageToxEnv, object, object]:
    """Two run environments that share one `.pkg`, built from `tox config` so no build runs."""
    toml = dedent("""\
        env_list = ["a", "b"]
        [env_run_base]
        package = "wheel"
        commands = [["python", "-c", "print('ok')"]]
    """)
    outcome = tox_project({"tox.toml": toml, "pyproject.toml": ""}).run("c", "-e", "a,b")
    outcome.assert_success()
    state = outcome.state
    return state.envs[".pkg"], state.envs["a"], state.envs["b"]


def _wheel(directory: Path, name: str = "demo-1.0-py3-none-any.whl") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(b"PK\x03\x04wheel")
    return path


def test_shared_env_lives_until_the_last_lease_is_released(
    shared_env: tuple[PackageToxEnv, object, object], mocker: MockerFixture
) -> None:
    pkg, a, b = shared_env
    torn_down = mocker.patch.object(pkg, "_teardown", wraps=pkg._teardown)  # ruff:ignore[private-member-access]
    pkg._run_state["setup"] = True  # ruff:ignore[private-member-access]  # simulate a shared env that built before

    a.mark_active()
    b.mark_active()
    assert pkg.lease_holders == ("a", "b")

    a.teardown()
    assert pkg.lease_holders == ("b",)
    torn_down.assert_not_called()
    assert pkg._run_state["teardown"] is False  # ruff:ignore[private-member-access]  # still serving b

    b.teardown()
    assert pkg.lease_holders == ()
    torn_down.assert_called_once_with()
    assert pkg._run_state["teardown"] is True  # ruff:ignore[private-member-access]  # released with the last user


def test_cancel_records_a_receipt_and_discards_only_its_build(
    shared_env: tuple[PackageToxEnv, object, object], tmp_path: Path, mocker: MockerFixture
) -> None:
    pkg, a, b = shared_env
    a.mark_active()
    b.mark_active()
    started, release = threading.Event(), threading.Event()
    produced: list[Path] = []

    def build(for_env: object) -> list[Package]:
        path = _wheel(tmp_path / "dist", f"{for_env.name}-1.0.0-py3-none-any.whl")  # type: ignore[attr-defined]
        pkg.register_artifact(path)
        produced.append(path)
        if for_env is a.conf:  # type: ignore[attr-defined]
            started.set()
            assert release.wait(30)  # the test controls when the cancelled build comes back
        return [WheelPackage(path, [])]

    mocker.patch.object(pkg, "perform_packaging", side_effect=build)
    errors: list[BaseException] = []

    def build_a() -> None:
        try:
            pkg.build_packages(a.conf)  # type: ignore[attr-defined]
        except BaseException as exception:  # noqa: BLE001  # the test asserts what was raised
            errors.append(exception)

    worker = threading.Thread(target=build_a, daemon=True)
    worker.start()
    assert started.wait(30)

    (receipt,) = a.cancel_package_envs()  # type: ignore[attr-defined]
    assert receipt.run_env == "a"
    assert receipt.shared_env == ".pkg"
    assert receipt.build_generation == 1
    assert receipt.interrupted_build is True
    assert receipt.invalidated is True
    assert receipt.kept_for == ("b",)
    assert pkg.cancellation_receipts == (receipt,)

    release.set()
    worker.join(30)
    assert not worker.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], SystemExit) and errors[0].code == -2
    assert produced and not produced[0].exists()  # the invalidated generation never enters an install

    # b still holds the shared env and gets a fresh, usable artifact from its own generation
    (package,) = pkg.build_packages(b.conf)  # type: ignore[attr-defined]
    assert package.generation == 2
    assert packages_valid([package])
    assert package.path.exists()
    assert pkg.lease_holders == ("a", "b")


def test_cancel_after_a_completed_build_keeps_the_artifact(
    shared_env: tuple[PackageToxEnv, object, object], tmp_path: Path, mocker: MockerFixture
) -> None:
    pkg, a, b = shared_env
    a.mark_active()
    b.mark_active()
    path = _wheel(tmp_path / "dist")
    mocker.patch.object(pkg, "perform_packaging", return_value=[WheelPackage(path, [])])

    (package,) = pkg.build_packages(a.conf)  # type: ignore[attr-defined]
    assert package.path.exists()

    (receipt,) = a.cancel_package_envs()  # type: ignore[attr-defined]
    assert receipt.interrupted_build is False
    assert receipt.build_generation is None
    assert receipt.invalidated is False
    assert receipt.kept_for == ("b",)
    assert path.exists()  # the completed artifact is still available to the sibling


def test_preparation_failure_is_not_reused_and_the_next_build_retries(
    shared_env: tuple[PackageToxEnv, object, object], tmp_path: Path, mocker: MockerFixture
) -> None:
    pkg, a, b = shared_env
    a.mark_active()
    b.mark_active()
    attempts: list[int] = []

    def build(for_env: object) -> list[Package]:
        attempts.append(1)
        if len(attempts) == 1:
            msg = "stand-in preparation failed"
            raise Fail(msg)
        return [WheelPackage(_wheel(tmp_path / "dist", "retry-1.0-py3-none-any.whl"), [])]

    mocker.patch.object(pkg, "perform_packaging", side_effect=build)
    with pytest.raises(Fail, match="stand-in preparation failed"):
        pkg.build_packages(a.conf)  # type: ignore[attr-defined]
    assert pkg._generation_artifacts == {}  # ruff:ignore[private-member-access]  # nothing survives a failure

    (package,) = pkg.build_packages(a.conf)  # type: ignore[attr-defined]
    assert package.generation == 2
    assert package.path.exists()
    assert pkg.cancellation_receipts == ()  # a failure is not a cancellation receipt
    assert pkg.lease_holders == ("a", "b")


def test_missing_or_empty_artifact_never_enters_an_install(tmp_path: Path) -> None:
    empty = tmp_path / "empty.whl"
    empty.write_bytes(b"")
    assert packages_valid([WheelPackage(tmp_path / "missing.whl", [])]) is False
    assert packages_valid([WheelPackage(empty, [])]) is False
    assert packages_valid([WheelPackage(_wheel(tmp_path), [])]) is True


def test_cancelling_a_pending_run_does_not_close_the_shared_env(
    shared_env: tuple[PackageToxEnv, object, object], tmp_path: Path, mocker: MockerFixture
) -> None:
    pkg, a, b = shared_env
    a.mark_active()
    b.mark_active()
    path = _wheel(tmp_path / "dist")
    mocker.patch.object(pkg, "perform_packaging", return_value=[WheelPackage(path, [])])
    pkg.build_packages(b.conf)  # type: ignore[attr-defined]  # b already has its artifact

    # a never started a build; cancelling it must not interrupt the shared env nor release b's lease
    (receipt,) = a.cancel_package_envs()  # type: ignore[attr-defined]
    assert receipt.interrupted_build is False
    assert receipt.invalidated is False
    assert receipt.kept_for == ("b",)
    assert pkg._interruption.requested is False  # ruff:ignore[private-member-access]  # no global interruption
    assert pkg._run_state["teardown"] is False  # ruff:ignore[private-member-access]  # still serving b
    assert pkg.lease_holders == ("a", "b")


@pytest.fixture
def gated_inline_build(demo_pkg_inline: Path) -> str:
    """The local demo build backend, gated so a test can hold a wheel build open and then release it."""
    build = (demo_pkg_inline / "build.py").read_text()
    return build.replace(
        '    base_name = f"{name}-{version}-py{sys.version_info[0]}-none-any.whl"',
        "    import time\n"
        '    base_name = f"{name}-{version}-py{sys.version_info[0]}-none-any.whl"\n'
        "    marker = Path(os.environ['TOX_PROBE_MARKER'])\n"
        "    marker.write_text('started')\n"
        "    release = Path(os.environ['TOX_PROBE_RELEASE'])\n"
        "    deadline = time.monotonic() + 60\n"
        "    while not release.exists():\n"
        "        if time.monotonic() > deadline:\n"
        "            raise RuntimeError('timeout')\n"
        "        time.sleep(0.01)\n",
    )


def _enable_install(options: object) -> None:
    # a `tox config` run does not parse the run-only flags; the run path reads them, so provide the defaults
    defaults = {"package_only": False, "no_test": False, "skip_pkg_install": False, "skip_env_install": False}
    for key, value in defaults.items():
        if not hasattr(options, key):
            setattr(options, key, value)


def test_local_cancel_then_continue_with_a_real_build(
    tox_project: ToxProjectCreator, demo_pkg_inline: Path, gated_inline_build: str
) -> None:
    toml = dedent("""\
        env_list = ["a", "b"]
        [env_run_base]
        package = "wheel"
        commands = [["python", "-c", "print('ok')"]]
        [env.".pkg"]
        pass_env = ["TOX_PROBE_*"]
    """)
    project = tox_project({
        "tox.toml": toml,
        "pyproject.toml": (demo_pkg_inline / "pyproject.toml").read_text(),
        "build.py": gated_inline_build,
    })
    marker, release = project.path / "marker", project.path / "release"
    project.monkeypatch.setenv("TOX_PROBE_MARKER", str(marker))
    project.monkeypatch.setenv("TOX_PROBE_RELEASE", str(release))
    outcome = project.run("c", "-e", "a,b")
    outcome.assert_success()
    state = outcome.state
    _enable_install(state.conf.options)
    a, b, pkg = state.envs["a"], state.envs["b"], state.envs[".pkg"]
    a.mark_active()
    b.mark_active()
    errors: list[BaseException] = []

    def build_a() -> None:
        try:
            a.setup()
        except BaseException as exception:  # noqa: BLE001  # the test asserts what was raised
            errors.append(exception)
        finally:
            a.teardown()

    worker = threading.Thread(target=build_a, daemon=True)
    worker.start()
    deadline = time.monotonic() + 30
    while not marker.exists():
        assert time.monotonic() < deadline, "the stand-in build never started"
        time.sleep(0.01)

    assert pkg.lease_holders == ("a", "b")
    (receipt,) = a.cancel_package_envs()
    release.write_text("go")
    worker.join(60)
    assert not worker.is_alive()

    assert receipt.build_generation == 1
    assert receipt.interrupted_build is True
    assert receipt.invalidated is True
    assert receipt.kept_for == ("b",)
    assert len(errors) == 1 and isinstance(errors[0], SystemExit) and errors[0].code == -2
    assert pkg.lease_holders == ("b",)
    assert pkg._run_state["teardown"] is False  # ruff:ignore[private-member-access]  # held by b

    b.setup()
    (package,) = b._packages  # ruff:ignore[private-member-access]  # the artifact b installed
    assert package.generation == 2
    assert package.path.exists()

    b.teardown()
    assert pkg.lease_holders == ()
    assert pkg._run_state["teardown"] is True  # ruff:ignore[private-member-access]  # released with the last user


def test_cancelling_a_queued_build_never_starts_it(
    shared_env: tuple[PackageToxEnv, object, object], tmp_path: Path, mocker: MockerFixture
) -> None:
    pkg, a, b = shared_env
    a.mark_active()
    b.mark_active()
    started, release = threading.Event(), threading.Event()
    calls: list[str] = []

    def build(for_env: object) -> list[Package]:
        calls.append(for_env.name)  # type: ignore[attr-defined]
        if for_env is a.conf:  # type: ignore[attr-defined]
            started.set()
            assert release.wait(30)
        name = f"{for_env.name}-1.0-py3-none-any.whl"  # type: ignore[attr-defined]
        return [WheelPackage(_wheel(tmp_path / "dist", name), [])]

    mocker.patch.object(pkg, "perform_packaging", side_effect=build)
    worker = threading.Thread(target=lambda: pkg.build_packages(a.conf), daemon=True)  # type: ignore[attr-defined]
    worker.start()
    assert started.wait(30)

    # b is queued behind a on the package build lock, then cancelled before it can run
    queued_errors: list[BaseException] = []

    def build_b() -> None:
        try:
            pkg.build_packages(b.conf)  # type: ignore[attr-defined]
        except BaseException as exception:  # noqa: BLE001  # the test asserts what was raised
            queued_errors.append(exception)

    queued = threading.Thread(target=build_b, daemon=True)
    queued.start()
    time.sleep(0.2)  # let b reach the build lock and queue behind a
    (receipt,) = b.cancel_package_envs()  # type: ignore[attr-defined]
    assert receipt.interrupted_build is False
    assert receipt.invalidated is False
    assert receipt.kept_for == ("a",)

    release.set()
    worker.join(60)
    queued.join(60)
    assert not queued.is_alive()
    assert len(queued_errors) == 1 and isinstance(queued_errors[0], SystemExit)
    assert calls == ["a"]  # b never built for the cancelled environment
    assert pkg.lease_holders == ("a", "b")


def test_teardown_after_an_invalidated_generation_is_safe(
    shared_env: tuple[PackageToxEnv, object, object], mocker: MockerFixture
) -> None:
    pkg, a, b = shared_env
    a.mark_active()
    b.mark_active()
    pkg._run_state["setup"] = True  # ruff:ignore[private-member-access]  # act as if the shared env built before
    pkg._backend_stale = True  # ruff:ignore[private-member-access]  # a cancelled generation left no backend

    with pkg.display_context(suspend=False):
        pkg.teardown()  # leases are held, so this only defers the shared teardown
    assert pkg._run_state["teardown"] is False  # ruff:ignore[private-member-access]  # internal state

    a.teardown()
    assert pkg._run_state["teardown"] is False  # ruff:ignore[private-member-access]  # b still holds a lease
    b.teardown()  # releasing the last lease closes the shared env without reaching for a backend that does not exist
    assert pkg._run_state["teardown"] is True  # ruff:ignore[private-member-access]  # internal state

