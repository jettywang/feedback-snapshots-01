from __future__ import annotations

import logging
import subprocess
import sys
from typing import TYPE_CHECKING, Final

import pytest

from harness import SKIP_IF_WINDOWS
from pipx.package_specifier import recordable_pip_args, replayable_pip_args, trusted_recorded_pip_args
from pipx.subprocess_runner import run_subprocess, subprocess_post_check
from pipx.util import PipxError

if TYPE_CHECKING:
    from pathlib import Path

# A pipx install runs its installer through run_subprocess, the controlled interface for command lines that can carry
# credentials, and the run leaves three records, covered here offline with a fake installer:
#
# - the live interface: the output the installer shows while it runs (stream_output, as --verbose does);
# - the job log: the "running" line, the captured output and the return code in the pipx.subprocess_runner log;
# - the reinstall record: the pip arguments recordable_pip_args saves into the venv metadata for a later reinstall.
#
# The fake installer echoes the index URL it is given, the way pip quotes an operand it rejects, writes its own line
# to each stream and exits with the status the test passes. The index credentials are the forbidden field of every
# record but the reinstall record, which keeps them so a reinstall can still authenticate against the private index;
# the reinstall record in turn forbids the options that only apply to one install, such as --log or --requirement.

_INDEX_URL: Final[str] = "https://deploy:s3cr3ttok@index.example/simple"
_MASKED_INDEX_URL: Final[str] = "https://****:****@index.example/simple"
_TOKEN: Final[str] = "s3cr3ttok"

_FAKE_INSTALLER: Final[str] = (
    "import sys;"
    " print('installing tool from ' + sys.argv[1]);"
    " print('installer warning: slow index', file=sys.stderr);"
    " sys.exit(int(sys.argv[2]))"
)
_INSTALLER_STDOUT: Final[str] = f"installing tool from {_INDEX_URL}\n"
_MASKED_INSTALLER_STDOUT: Final[str] = f"installing tool from {_MASKED_INDEX_URL}\n"
_INSTALLER_STDERR: Final[str] = "installer warning: slow index\n"


def _fake_installer(*, exit_code: int = 0) -> list[str]:
    return [sys.executable, "-c", _FAKE_INSTALLER, _INDEX_URL, str(exit_code)]


def test_live_interface_relays_each_installer_stream_as_it_runs(capsys: pytest.CaptureFixture[str]) -> None:
    process: Final = run_subprocess(_fake_installer(), stream_output=True)

    live: Final = capsys.readouterr()
    assert process.returncode == 0
    # the live interface relays the installer's own words, on the stream the installer wrote them to
    assert (live.out, live.err) == (_INSTALLER_STDOUT, _INSTALLER_STDERR)


@pytest.mark.parametrize(
    "stream_output", [pytest.param(False, id="captured"), pytest.param(True, id="streamed")]
)
def test_output_captured_for_the_ticket_masks_credentials(stream_output: bool) -> None:
    process: Final = run_subprocess(_fake_installer(), stream_output=stream_output)

    # whether or not the output was already shown live, the copy the run keeps attaches to the ticket masked
    assert (process.stdout, process.stderr) == (_MASKED_INSTALLER_STDOUT, _INSTALLER_STDERR)
    assert _TOKEN not in process.stdout + process.stderr


def test_job_log_records_masked_command_output_and_return_code(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="pipx.subprocess_runner"):
        run_subprocess(_fake_installer())

    messages: Final[list[str]] = [record.getMessage() for record in caplog.records]
    assert messages == [
        f"running {sys.executable} -c {_FAKE_INSTALLER} {_MASKED_INDEX_URL} 0",
        f"stdout: {_MASKED_INSTALLER_STDOUT.rstrip()}",
        f"stderr: {_INSTALLER_STDERR.rstrip()}",
        "returncode: 0",
    ]
    assert all(_TOKEN not in message for message in messages)


def test_job_log_of_a_streamed_run_keeps_only_command_and_return_code(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    with caplog.at_level(logging.DEBUG, logger="pipx.subprocess_runner"):
        run_subprocess(_fake_installer(), stream_output=True)

    # the output the run already showed live is not captured again into the job log
    assert capsys.readouterr().out == _INSTALLER_STDOUT
    messages: Final[list[str]] = [record.getMessage() for record in caplog.records]
    assert messages == [
        f"running {sys.executable} -c {_FAKE_INSTALLER} {_MASKED_INDEX_URL} 0",
        "returncode: 0",
    ]
    assert all(_TOKEN not in message for message in messages)


def test_job_log_omits_output_the_caller_displays_itself(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="pipx.subprocess_runner"):
        process: Final = run_subprocess(_fake_installer(), log_stdout=False, log_stderr=False)

    # the caller relays the output to the user itself, so the log keeps only the command and the return code while
    # the captured copy stays available, masked, for that display
    assert [record.getMessage() for record in caplog.records if record.levelno == logging.DEBUG] == ["returncode: 0"]
    assert (process.stdout, process.stderr) == (_MASKED_INSTALLER_STDOUT, _INSTALLER_STDERR)


@pytest.mark.parametrize(
    ("stream_output", "shown"),
    [
        pytest.param(False, (_MASKED_INSTALLER_STDOUT, _INSTALLER_STDERR), id="captured"),
        pytest.param(True, ("", ""), id="streamed"),
    ],
)
def test_failed_install_attaches_masked_output_to_the_error(
    capsys: pytest.CaptureFixture[str], stream_output: bool, shown: tuple[str, str]
) -> None:
    process: Final = run_subprocess(_fake_installer(exit_code=3), stream_output=stream_output)
    capsys.readouterr()

    with pytest.raises(PipxError) as error:
        subprocess_post_check(process, streamed=stream_output)

    # a streamed run showed its output live, so only a captured one prints it again; either way the message names
    # the failed command with its credentials masked
    displayed: Final = capsys.readouterr()
    assert (displayed.out, displayed.err) == shown
    assert _MASKED_INDEX_URL in str(error.value)
    assert _TOKEN not in str(error.value) + displayed.out + displayed.err


def test_reinstall_record_drops_one_shot_fields_and_keeps_replayable_data() -> None:
    install_pip_args: Final[list[str]] = [
        "--index-url",
        _INDEX_URL,
        "--cert",
        "ca.pem",
        "--pre",
        "--log",
        "pip.log",  # one-shot: this install's log file
        "--report",
        "report.json",  # one-shot: this install's report
        "--cache-dir",
        "cache",  # one-shot: this install's cache
        "--requirement",
        "requirements.txt",  # one-shot: this install's requirement file
    ]

    recorded: Final = recordable_pip_args(install_pip_args)

    assert recorded == ["--index-url", _INDEX_URL, "--cert", "ca.pem", "--pre"]
    # the record keeps the credentials a reinstall authenticates with; the one-shot fields are the forbidden ones
    assert all(field not in recorded for field in ("--log", "--report", "--cache-dir", "--requirement"))
    assert all(value not in recorded for value in ("pip.log", "report.json", "cache", "requirements.txt"))


def test_approved_record_survives_the_replay_round_trip(tmp_path: Path) -> None:
    venv_dir: Final[Path] = tmp_path.resolve() / "venv"
    venv_dir.mkdir()
    approved: Final[list[str]] = ["--index-url", _INDEX_URL, "--cert", "ca.pem", "--pre"]

    recorded: Final = recordable_pip_args(approved)

    # nothing the user approved is dropped on the way back to the installer
    assert trusted_recorded_pip_args(recorded, venv_dir) == recorded
    # only the relative cert path changes, resolved against the venv the record's installer ran in
    assert replayable_pip_args(recorded, venv_dir) == [
        "--index-url",
        _INDEX_URL,
        "--cert",
        str(venv_dir / "ca.pem"),
        "--pre",
    ]


@SKIP_IF_WINDOWS
def test_replay_refuses_a_record_pointing_where_others_can_change(tmp_path: Path) -> None:
    shared: Final[Path] = tmp_path.resolve() / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    recorded: Final = recordable_pip_args(["--index-url", _INDEX_URL, "--find-links", str(shared / "wheels")])

    with pytest.raises(PipxError, match=r"another account can change") as error:
        trusted_recorded_pip_args(recorded, tmp_path.resolve())

    # the refusal names the changeable location rather than silently dropping the approved fields around it
    assert str(shared) in str(error.value)
    assert _TOKEN not in str(error.value)
