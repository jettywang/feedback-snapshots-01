"""Offline regression for the side-effect-free promise of ``tox config`` release reviews.

A release review materializes ``tox config`` for several checkouts inside a single tox process. The review must not
perform actions: no provisioning of another tox (bootstrap decision), no execution of project plugin code (plugin
registration), no packaging backend process (packaging metadata), and no project commands. Options the review can
safely know are still printed; values that only running something could reveal stay unresolved (``# Exception:``
markers, or the provision request file written by ``--no-provision``).

Recording test doubles at the four boundaries pin this contract, and a control with approved execution proves the
doubles are live. The module is self-contained (no ``tests/conftest.py`` fixtures) and runs offline with the pinned
dependencies of ``.feedback/requirements.txt``::

    .venv/bin/python -m pytest -q -o addopts= --noconftest tests/session/cmd/test_show_config_review.py
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from types import ModuleType, SimpleNamespace
from typing import TYPE_CHECKING, Final

import pytest

import tox.plugin.inline
import tox.provision
import tox.run
from tox.execute.pep517_backend import LocalSubProcessPep517Executor
from tox.tox_env.api import ToxEnv

if TYPE_CHECKING:
    from collections.abc import Sequence

BOOTSTRAP: Final = "bootstrap"
PLUGIN_REGISTRATION: Final = "plugin-registration"
PACKAGING_BACKEND: Final = "packaging-backend"
PROJECT_COMMAND: Final = "project-command"


class ReviewBoundaryCrossed(RuntimeError):
    """A review run attempted an action that only approved execution may perform."""

    def __init__(self, boundary: str, detail: str) -> None:
        self.boundary = boundary
        super().__init__(f"review crossed the {boundary} boundary: {detail}")


@dataclass
class _Record:
    boundary: str
    detail: str


class BoundaryRecorder:
    """Recording test doubles installed at the four side-effect boundaries of a review.

    :param monkeypatch: the pytest monkeypatch fixture used to install the doubles
    :param mode: ``guard`` to refuse actions (plugin code is stubbed, not run, so the review can proceed safely),
        ``delegate`` to record and really perform the action (approved execution control), or ``fake`` to record and
        return a canned result (approved action that must stay offline)
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch, mode: str = "guard") -> None:
        if mode not in {"guard", "delegate", "fake"}:
            msg = f"unknown recorder mode {mode!r}"
            raise ValueError(msg)
        self._mode = mode
        self.records: list[_Record] = []
        self._real_run_provision = tox.provision.run_provision
        self._real_load_plugin = tox.plugin.inline._load_plugin  # ruff:ignore[private-member-access]  # test double
        self._real_local_execute = LocalSubProcessPep517Executor.local_execute
        self._real_execute = ToxEnv.execute
        monkeypatch.setattr(tox.provision, "run_provision", self._run_provision)
        monkeypatch.setattr(tox.plugin.inline, "_load_plugin", self._load_plugin)
        # unbound wrappers: the doubles are looked up on the class and receive the instance as first argument
        monkeypatch.setattr(
            LocalSubProcessPep517Executor,
            "local_execute",
            lambda executor, options: self._local_execute(executor, options),
        )
        monkeypatch.setattr(
            ToxEnv,
            "execute",
            lambda tox_env, cmd, *args, **kwargs: self._execute(tox_env, cmd, *args, **kwargs),
        )

    def _note(self, boundary: str, detail: str) -> None:
        self.records.append(_Record(boundary, detail))

    def _run_provision(self, name: str, state: object) -> int:
        self._note(BOOTSTRAP, f"provision tox into env {name!r}")
        if self._mode == "delegate":
            return self._real_run_provision(name, state)  # type: ignore[arg-type]
        if self._mode == "fake":
            return 0
        raise ReviewBoundaryCrossed(BOOTSTRAP, f"provision env {name!r}")

    def _load_plugin(self, path: Path) -> ModuleType:
        self._note(PLUGIN_REGISTRATION, f"execute {path}")
        if self._mode == "delegate":
            return self._real_load_plugin(path)
        # registration is recorded, but the project code is not executed
        return ModuleType(path.stem)

    def _local_execute(self, executor: object, options: object) -> object:
        cmd = getattr(executor, "cmd", ("<unknown>",))
        self._note(PACKAGING_BACKEND, f"start backend: {' '.join(str(part) for part in cmd)}")
        if self._mode == "delegate":
            return self._real_local_execute(executor, options)  # type: ignore[arg-type]
        raise ReviewBoundaryCrossed(PACKAGING_BACKEND, f"start backend {cmd!r}")

    def _execute(self, tox_env: ToxEnv, cmd: Sequence[Path | str], *args: object, **kwargs: object) -> object:
        self._note(PROJECT_COMMAND, f"{tox_env.conf.name}: {' '.join(str(part) for part in cmd)}")
        if self._mode == "delegate":
            return self._real_execute(tox_env, cmd, *args, **kwargs)  # type: ignore[arg-type]
        raise ReviewBoundaryCrossed(PROJECT_COMMAND, f"run {cmd!r} in {tox_env.conf.name}")

    def count(self, boundary: str) -> int:
        """Count the recorded crossings of one boundary."""
        return sum(record.boundary == boundary for record in self.records)

    def details(self, boundary: str) -> list[str]:
        """List the recorded details of one boundary."""
        return [record.detail for record in self.records if record.boundary == boundary]

    def reset(self) -> None:
        """Forget all records so far."""
        self.records.clear()

    def fire_plugin_registration(self) -> None:
        """Trigger the plugin-registration double once, proving it records and attributes."""
        self._load_plugin(Path("sentinel") / "toxfile.py")

    def fire_backend_probe(self) -> None:
        """Trigger the packaging-backend double once, proving it records and attributes."""
        self._local_execute(SimpleNamespace(cmd=("sentinel-backend",)), None)


@dataclass
class ReviewOutcome:
    """The result of one in-process tox run, as captured by the review."""

    project: Path
    code: int
    out: str
    err: str


def _tox(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    *args: str,
) -> ReviewOutcome:
    """Run tox in-process against ``project``, the same way the release review does."""
    capfd.readouterr()  # drain earlier output
    code = -3
    with monkeypatch.context() as ctx:
        ctx.chdir(project)
        ctx.setattr(sys, "argv", [sys.executable, "-m", "tox", *args])
        try:
            tox.run.run(list(args))
        except SystemExit as exc:
            code = int(exc.code or 0)
    out, err = capfd.readouterr()
    return ReviewOutcome(project, code, out, err)


@pytest.fixture(autouse=True)
def _offline_review_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith(("TOX", "VIRTUALENV")) or key in {"PYTHONPATH", "_TOX_SHOW_CONFIG_RAISE"}:
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")  # stable plain-text output
    monkeypatch.setenv("PYTHONHASHSEED", "0")  # stable set_env, tox reuses the seed instead of drawing one
    # guarantee the regression stays offline: any pip invocation fails fast instead of reaching the network
    monkeypatch.setenv("PIP_INDEX_URL", "http://127.0.0.1:9/")
    monkeypatch.setenv("PIP_RETRIES", "0")
    monkeypatch.setenv("PIP_TIMEOUT", "0.001")
    # build test environments from the wheels bundled with virtualenv, never from an index
    monkeypatch.setenv("VIRTUALENV_PIP", "embed")
    monkeypatch.setenv("VIRTUALENV_SETUPTOOLS", "embed")


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> BoundaryRecorder:
    """Guard-mode boundary recorder: review runs cross no boundary."""
    return BoundaryRecorder(monkeypatch)


def _write_project(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(dedent(content), encoding="utf-8")
    return root


_BOOTSTRAP_FILES: Final = {
    "tox.ini": """
        [tox]
        requires =
            tox>9999.0
        env_list = py

        [testenv]
        package = skip
        commands = python -c "print('bootstrap-command-ran')"
        """,
}

_METADATA_FILES: Final = {
    "tox.ini": """
        [tox]
        env_list = py

        [testenv]
        commands = python -c "print('metadata-command-ran')"
        """,
    "pyproject.toml": """
        [build-system]
        requires = ["setuptools>=61"]
        build-backend = "setuptools.build_meta"

        [project]
        name = "review-metadata-demo"
        dynamic = ["version", "dependencies"]

        [tool.setuptools.dynamic]
        version = {attr = "review_metadata_demo.__version__"}
        dependencies = {file = ["requirements.txt"]}
        """,
    "requirements.txt": "colorama\n",
    "review_metadata_demo/__init__.py": '__version__ = "1.2.3"\n',
    "toxfile.py": """
        from pathlib import Path

        # project code: only runs if the review executes the inline plugin
        Path(__file__).with_name("toxfile-executed.txt").write_text("executed", encoding="utf-8")
        """,
}

_PLAIN_FILES: Final = {
    "tox.ini": """
        [tox]
        env_list = py

        [testenv]
        package = skip
        commands = python -c "print('plain-command-ran')"
        """,
}


@pytest.fixture
def bootstrap_project(tmp_path: Path) -> Path:
    """A checkout whose bootstrap constraint the running tox cannot satisfy."""
    return _write_project(tmp_path / "boot", _BOOTSTRAP_FILES)


@pytest.fixture
def metadata_project(tmp_path: Path) -> Path:
    """A checkout whose version and dependencies only exist as packaging metadata."""
    return _write_project(tmp_path / "metadata", _METADATA_FILES)


@pytest.fixture
def plain_project(tmp_path: Path) -> Path:
    """A checkout that fully expands without any dynamic information."""
    return _write_project(tmp_path / "plain", _PLAIN_FILES)


def test_review_bootstrap_constraint_is_reported_not_provisioned(
    bootstrap_project: Path,
    recorder: BoundaryRecorder,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    request_file = tmp_path / "provision-request.json"
    outcome = _tox(bootstrap_project, monkeypatch, capfd, "--no-provision", str(request_file), "c")
    assert outcome.code == -2
    assert "provisioning explicitly disabled" in outcome.out
    # the constraint the review cannot satisfy is written down as unresolved, not installed
    request = json.loads(request_file.read_text(encoding="utf-8"))
    assert "tox>9999.0" in request["requires"]
    assert not (bootstrap_project / ".tox").exists()
    assert recorder.records == []


def test_review_metadata_project_expands_static_config_only(
    metadata_project: Path,
    recorder: BoundaryRecorder,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    outcome = _tox(metadata_project, monkeypatch, capfd, "c")
    assert outcome.code == 0
    # ordinary options the review can safely know are still shown
    assert "[testenv:py]" in outcome.out
    assert "env_name = py" in outcome.out
    assert "package_env = .pkg" in outcome.out
    assert "commands" in outcome.out
    # values only the packaging backend could learn stay unresolved: absent, and the backend never ran
    assert "1.2.3" not in outcome.out
    assert "colorama" not in outcome.out
    assert not (metadata_project / ".tox" / ".pkg" / ".meta").exists()
    assert not (metadata_project / "build").exists()
    assert not list(metadata_project.glob("*.egg-info"))
    # the inline plugin registration is recorded, but the project code was not executed
    assert not (metadata_project / "toxfile-executed.txt").exists()
    assert recorder.details(PLUGIN_REGISTRATION) == [f"execute {metadata_project / 'toxfile.py'}"]
    assert recorder.count(BOOTSTRAP) == 0
    assert recorder.count(PACKAGING_BACKEND) == 0
    assert recorder.count(PROJECT_COMMAND) == 0


def test_review_marks_values_it_cannot_know_without_running(
    tmp_path: Path,
    recorder: BoundaryRecorder,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(
        tmp_path / "missing-interpreter",
        {
            "tox.ini": """
                [tox]
                env_list = py

                [testenv]
                package = skip
                base_python = py39-review-missing
                commands = python -c "print('unreachable')"
                """,
        },
    )
    outcome = _tox(project, monkeypatch, capfd, "c")
    assert outcome.code == -1
    # ordinary options are still shown, the unresolvable one is explicitly marked instead of discovered
    assert "env_name = py" in outcome.out
    assert "commands" in outcome.out
    assert "# Exception:" in outcome.out
    assert recorder.records == []


def test_sequential_reviews_in_one_process_do_not_leak_state(
    tmp_path: Path,
    recorder: BoundaryRecorder,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    plain = _write_project(tmp_path / "plain", _PLAIN_FILES)
    dynamic = _write_project(tmp_path / "dynamic", _METADATA_FILES)

    # the doubles each fire once in advance: a later "no records" is meaningful, and even though the two reviews
    # below produce unchanged config text, a crossing is attributed to the correct boundary
    recorder.fire_plugin_registration()
    with pytest.raises(ReviewBoundaryCrossed) as exc_info:
        recorder.fire_backend_probe()
    assert exc_info.value.boundary == PACKAGING_BACKEND
    assert [record.boundary for record in recorder.records] == [PLUGIN_REGISTRATION, PACKAGING_BACKEND]
    recorder.reset()

    first = _tox(plain, monkeypatch, capfd, "c")
    assert first.code == 0
    assert recorder.records == []

    review = _tox(dynamic, monkeypatch, capfd, "c")
    assert review.code == 0
    assert recorder.count(PLUGIN_REGISTRATION) == 1  # its own inline plugin, recorded and stubbed
    assert recorder.count(BOOTSTRAP) == 0
    assert recorder.count(PACKAGING_BACKEND) == 0
    assert recorder.count(PROJECT_COMMAND) == 0
    recorder.reset()

    second = _tox(plain, monkeypatch, capfd, "c")
    assert second.code == 0
    # no state from the dynamic checkout leaks into the plain one: identical text, no further plugin execution
    assert second.out == first.out
    assert recorder.records == []


def test_control_approved_run_executes_project_commands(
    plain_project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    recorder = BoundaryRecorder(monkeypatch, mode="delegate")
    outcome = _tox(plain_project, monkeypatch, capfd, "r")
    assert outcome.code == 0
    assert "plain-command-ran" in outcome.out
    # the approved run really crossed the project-command boundary, proving the double is live
    assert recorder.count(PROJECT_COMMAND) >= 1
    assert any("print('plain-command-ran')" in detail for detail in recorder.details(PROJECT_COMMAND))
    assert recorder.count(BOOTSTRAP) == 0
    assert recorder.count(PACKAGING_BACKEND) == 0


def test_control_approved_provision_takes_the_bootstrap_action(
    bootstrap_project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    recorder = BoundaryRecorder(monkeypatch, mode="fake")
    outcome = _tox(bootstrap_project, monkeypatch, capfd, "c")
    # without --no-provision the unsatisfiable bootstrap constraint escalates to the provision action
    assert outcome.code == 0
    assert recorder.details(BOOTSTRAP) == ["provision tox into env '.tox'"]


def test_control_approved_review_executes_inline_plugin(
    metadata_project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    recorder = BoundaryRecorder(monkeypatch, mode="delegate")
    outcome = _tox(metadata_project, monkeypatch, capfd, "c")
    assert outcome.code == 0
    # approved registration really executes the project plugin code
    assert (metadata_project / "toxfile-executed.txt").exists()
    assert recorder.count(PLUGIN_REGISTRATION) == 1
