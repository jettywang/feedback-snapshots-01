from __future__ import annotations

import json
import socket
import sys
from typing import TYPE_CHECKING

import pytest

from tox import __version__
from tox.journal import write_journal
from tox.journal.main import Journal
from tox.util.shared_output import SharedOutput

if TYPE_CHECKING:
    from pathlib import Path

    from pytest_mock import MockerFixture


@pytest.fixture(scope="session")
def base_info() -> dict[str, str | dict[str, dict[str, int]]]:
    return {
        "reportversion": "1",
        "toxversion": __version__,
        "platform": sys.platform,
        "host": socket.getfqdn(),
    }


def test_journal_enabled_default(base_info: dict[str, str | dict[str, dict[str, int]]]) -> None:
    journal = Journal(enabled=True)
    assert bool(journal) is True
    assert journal.content == base_info


def test_journal_disabled_default() -> None:
    journal = Journal(enabled=False)
    assert bool(journal) is False
    assert journal.content == {}


def test_env_journal_enabled(base_info: dict[str, str | dict[str, dict[str, int]]]) -> None:
    journal = Journal(enabled=True)
    env = journal.get_env_journal("a")
    assert journal.get_env_journal("a") is env
    env["demo"] = 1

    assert bool(env) is True
    base_info["testenvs"] = {"a": {"demo": 1}}
    assert journal.content == base_info


def test_env_journal_disabled() -> None:
    journal = Journal(enabled=False)
    env = journal.get_env_journal("a")
    assert bool(env) is False

    env["demo"] = 2
    assert journal.content == {"testenvs": {"a": {"demo": 2}}}


@pytest.mark.parametrize(
    "output",
    [
        pytest.param("\u2713 passed", id="outside-locale-code-page"),
        pytest.param("calf\udce9", id="undecodable-byte"),
    ],
)
def test_write_journal_round_trips_output(tmp_path: Path, mocker: MockerFixture, output: str) -> None:
    mocker.patch("locale.getpreferredencoding", autospec=True, return_value="cp1252")
    journal = Journal(enabled=True)
    journal.get_env_journal("py")["output"] = output
    path = tmp_path / "out.json"

    write_journal(path, journal)

    assert json.loads(path.read_text(encoding="utf-8"))["testenvs"]["py"]["output"] == output


def test_journal_shared_content_masks_restricted_values(tmp_path: Path) -> None:
    policy = SharedOutput()
    policy.add("/tmp/build-dir")
    journal = Journal(enabled=True, shared_output=policy)
    env = journal.get_env_journal("py")
    env["output"] = "at /tmp/build-dir/wheel.whl"

    assert env.content["output"] == "at /tmp/build-dir/wheel.whl"
    assert env.shared_content["output"] == "at <restricted>/wheel.whl"
    assert journal.shared_content["testenvs"]["py"]["output"] == "at <restricted>/wheel.whl"


def test_write_journal_uses_shared_content(tmp_path: Path) -> None:
    policy = SharedOutput()
    policy.add("hunter2-restricted")
    journal = Journal(enabled=True, shared_output=policy)
    journal.get_env_journal("py")["output"] = "value hunter2-restricted"
    path = tmp_path / "out.json"

    write_journal(path, journal)

    content = path.read_text(encoding="utf-8")
    assert "hunter2-restricted" not in content
    assert "value <restricted>" in content
