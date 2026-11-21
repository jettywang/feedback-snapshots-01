from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from harness import SKIP_IF_WINDOWS, app_name, run_pipx_cli
from pipx.paths import CTX
from pipx.pipx_metadata_file import PIPX_INFO_FILENAME, PipxMetadata

if TYPE_CHECKING:
    from collections.abc import Callable

    from pytest_mock import MockerFixture


@pytest.fixture
def make_backup(tmp_path: Path) -> Callable[..., Path]:
    """Write a pipx-shaped virtual environment backup with a verifiable launcher and entry point."""

    def create(  # noqa: PLR0913
        *,
        name: str = "demo",
        recorded_package: str | None = "demo",
        recorded_version: str = "1.0",
        metadata_version: str | None = "0.12",
        entry_points: dict[str, str] | None = None,
        launchers: dict[str, str] | None = None,
        man_pages: dict[str, str] | None = None,
        extra_bin: dict[str, str] | None = None,
        pyvenv_cfg: bool = True,
        interpreter: bool = True,
        dist_version: str = "1.0",
    ) -> Path:
        backup: Final[Path] = tmp_path / f"backup-{name}"
        bin_dir: Final[Path] = backup / "bin"
        sites: Final[Path] = backup / "lib" / "python3.12" / "site-packages"
        dist_info: Final[Path] = sites / f"{name}-{dist_version}.dist-info"
        bin_dir.mkdir(parents=True)
        dist_info.mkdir(parents=True)
        if pyvenv_cfg:
            (backup / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
        if interpreter:
            (bin_dir / "python").write_text("#!/bin/sh\n", encoding="utf-8")
            (bin_dir / "python").chmod(0o755)
        (dist_info / "METADATA").write_text(f"Name: {name}\nVersion: {dist_version}\n", encoding="utf-8")
        entries: Final[dict[str, str]] = {"demo": name} if entry_points is None else entry_points
        if entries:
            (dist_info / "entry_points.txt").write_text(
                "[console_scripts]\n" + "".join(f"{app} = {target}:main\n" for app, target in entries.items()),
                encoding="utf-8",
            )
        for app in launchers if launchers is not None else {"demo": "#!/bin/sh\n"}:
            (bin_dir / app).write_text(f"#!{bin_dir / 'python'}\nprint('demo')\n", encoding="utf-8")
            (bin_dir / app).chmod(0o755)
        for app, content in (extra_bin or {}).items():
            (bin_dir / app).write_text(content, encoding="utf-8")
            (bin_dir / app).chmod(0o755)
        for page, content in (man_pages or {}).items():
            (backup / "share" / "man" / Path(page).parent).mkdir(parents=True, exist_ok=True)
            (backup / "share" / "man" / page).write_text(content, encoding="utf-8")
        if recorded_package is None and metadata_version is None:
            return backup
        (backup / PIPX_INFO_FILENAME).write_text(
            json.dumps(
                {
                    "pipx_metadata_version": metadata_version or "0.12",
                    "main_package": {
                        "package": recorded_package,
                        "package_version": recorded_version,
                        "apps": ["demo"],
                        "exposure_enabled": True,
                    },
                    "python_version": "3.12.0",
                }
            ),
            encoding="utf-8",
        )
        return backup

    return create


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_leaves_every_exposure_directory_untouched(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    backup: Final[Path] = make_backup(man_pages={"man1/demo.1": "manual\n"})

    assert run_pipx_cli(["takeover", "stage", str(backup), "--source", "usb-2026-11"]) == 0

    assert (
        list(CTX.bin_dir.iterdir()),
        list(CTX.man_dir.iterdir()),
        sorted(path.name for path in CTX.quarantine.iterdir()),
        not (CTX.venvs / "demo").exists(),
    ) == ([], [], ["demo"], True)
    out: Final[str] = capsys.readouterr().out
    assert ("staged in quarantine" in out, "usb-2026-11" in out, "would expose demo" in out) == (True, True, True)


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_keeps_the_backup_unchanged(make_backup: Callable[..., Path]) -> None:
    backup: Final[Path] = make_backup()
    before: Final[dict[str, bytes]] = {
        path.relative_to(backup).as_posix(): path.read_bytes() for path in backup.rglob("*") if path.is_file()
    }

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0

    assert {
        path.relative_to(backup).as_posix(): path.read_bytes() for path in backup.rglob("*") if path.is_file()
    } == before


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_does_not_replay_adversarial_metadata(
    make_backup: Callable[..., Path], caplog: pytest.LogCaptureFixture
) -> None:
    backup: Final[Path] = make_backup()
    record: Final[dict[str, object]] = json.loads((backup / PIPX_INFO_FILENAME).read_text(encoding="utf-8"))
    record["main_package"].update({
        "pip_args": ["--index-url", "https://evil.example/simple"],
        "package_or_url": "https://evil.example/archive.zip",
        "suffix": "/escape",
    })
    record["venv_args"] = ["--clear", "/tmp/elsewhere"]
    (backup / PIPX_INFO_FILENAME).write_text(json.dumps(record), encoding="utf-8")

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    assert run_pipx_cli(["takeover", "approve", "demo"]) == 0

    adopted: Final[PipxMetadata] = PipxMetadata(CTX.venvs / "demo")
    assert (
        adopted.main_package.pip_args,
        adopted.main_package.package_or_url,
        adopted.main_package.exposure.suffix,
        adopted.venv_args,
        "ignoring recorded venv arguments" in caplog.text,
    ) == ([], "demo", "", [], False)


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_never_runs_the_backup_interpreter(make_backup: Callable[..., Path], mocker: MockerFixture) -> None:
    backup: Final[Path] = make_backup()
    # a backup that would run code when its interpreter starts must still be inspected statically
    (backup / "bin" / "python").write_text('#!/bin/sh\ntouch "$(dirname "$0")/../ran"\n', encoding="utf-8")
    (backup / "bin" / "python").chmod(0o755)
    run: Final = mocker.patch("subprocess.run", autospec=True, side_effect=AssertionError("ran a subprocess"))

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0

    assert (run.call_count, (CTX.quarantine / "demo" / "ran").exists()) == (0, False)


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_accepts_a_backup_with_legacy_metadata(make_backup: Callable[..., Path]) -> None:
    backup: Final[Path] = make_backup(metadata_version="0.3")

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0

    assert run_pipx_cli(["takeover", "check", "demo"]) == 0


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_infers_the_package_from_distribution_metadata_when_the_record_is_gone(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    backup: Final[Path] = make_backup(recorded_package=None, metadata_version=None)

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0

    assert (CTX.quarantine / "demo" / "pipx_takeover.json").is_file()
    assert "demo: staged in quarantine" in capsys.readouterr().out


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_refuses_an_environment_whose_package_cannot_be_established(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    backup: Final[Path] = make_backup(recorded_package=None, metadata_version=None, entry_points={})
    # a second distribution makes the package name ambiguous, not inferred
    (site := backup / "lib" / "python3.12" / "site-packages" / "other-2.0.dist-info").mkdir()
    (site / "METADATA").write_text("Name: other\nVersion: 2.0\n", encoding="utf-8")

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 1

    assert "records no package name" in capsys.readouterr().err


@pytest.mark.usefixtures("pipx_temp_env")
def test_check_reports_missing_content_without_exposing_it(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    # the package declares an app whose launcher the backup lost
    backup: Final[Path] = make_backup(entry_points={"demo": "demo", "gone": "demo"}, launchers={"demo": "#!/bin/sh\n"})
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    capsys.readouterr()

    assert run_pipx_cli(["takeover", "check", "demo"]) == 0

    captured: Final = capsys.readouterr()
    assert (
        "would expose demo" in captured.out,
        "would expose gone" in captured.out,
        "is declared but" in captured.out,
        "gone" in captured.out,
    ) == (True, False, True, True)


@pytest.mark.usefixtures("pipx_temp_env")
def test_check_reports_a_boolean_unowned_file(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    backup: Final[Path] = make_backup(extra_bin={"mystery": "#!/bin/sh\necho not mine\n"})
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0

    assert run_pipx_cli(["takeover", "check", "demo"]) == 0

    assert "no package claims mystery" in capsys.readouterr().out


@pytest.mark.usefixtures("pipx_temp_env")
def test_approve_exposes_only_verified_resources(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    backup: Final[Path] = make_backup(
        entry_points={"demo": "demo", "gone": "demo"},
        launchers={"demo": "#!/bin/sh\n"},
        man_pages={"man1/demo.1": "manual\n"},
        extra_bin={"mystery": "#!/bin/sh\n"},
    )
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    capsys.readouterr()

    assert run_pipx_cli(["takeover", "approve", "demo"]) == 0

    metadata: Final[PipxMetadata] = PipxMetadata(CTX.venvs / "demo")
    assert (
        (CTX.bin_dir / app_name("demo")).exists(),
        (CTX.bin_dir / app_name("mystery")).exists(),
        (CTX.man_dir / "man1" / "demo.1").is_file(),
        metadata.main_package.package,
        metadata.main_package.package_version,
        metadata.main_package.resources.apps,
        not CTX.quarantine.joinpath("demo").exists(),
    ) == (True, False, True, "demo", "1.0", ["demo"], True)


@pytest.mark.usefixtures("pipx_temp_env")
def test_approve_rewrites_the_shebang_to_the_adopted_environment(make_backup: Callable[..., Path]) -> None:
    backup: Final[Path] = make_backup()
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0

    assert run_pipx_cli(["takeover", "approve", "demo"]) == 0

    adopted: Final[Path] = CTX.venvs / "demo" / "bin" / app_name("demo")
    assert adopted.read_text(encoding="utf-8").splitlines()[0].split(" -E")[0] == (
        f"#!{CTX.venvs / 'demo' / 'bin' / 'python'}"
    )


@SKIP_IF_WINDOWS
@pytest.mark.usefixtures("pipx_temp_env")
def test_approve_does_not_modify_a_hard_linked_launcher(make_backup: Callable[..., Path], tmp_path: Path) -> None:
    shared: Final[Path] = tmp_path / "python-shared"
    shared.write_text("#!/usr/local/bin/python-donor\nprint('shared')\n", encoding="utf-8")
    shared.chmod(0o755)
    backup: Final[Path] = make_backup()
    (backup / "bin" / "demo").unlink()
    os.link(shared, backup / "bin" / "demo")
    (backup / "bin" / "demo").chmod(0o755)
    before: Final[bytes] = shared.read_bytes()

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    assert run_pipx_cli(["takeover", "approve", "demo"]) == 0

    assert (shared.read_bytes(), shared.stat().st_nlink) == (before, 2)


@pytest.mark.usefixtures("pipx_temp_env")
def test_approve_refuses_a_launcher_that_escapes_the_backup(make_backup: Callable[..., Path], tmp_path: Path) -> None:
    outside: Final[Path] = tmp_path / "outside-python"
    outside.write_text("#!/bin/sh\n", encoding="utf-8")
    outside.chmod(0o755)
    backup: Final[Path] = make_backup()
    (backup / "bin" / "demo").write_text(f"#!{outside}\n", encoding="utf-8")
    (backup / "bin" / "demo").chmod(0o755)

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0

    assert run_pipx_cli(["takeover", "approve", "demo"]) == 1
    assert not (CTX.bin_dir / app_name("demo")).exists()


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_refuses_a_special_file(make_backup: Callable[..., Path]) -> None:
    backup: Final[Path] = make_backup()
    os.mkfifo(backup / "bin" / "fifo")

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 1
    assert not (CTX.quarantine / "demo").exists()


@pytest.mark.usefixtures("pipx_temp_env")
def test_a_record_whose_name_was_edited_is_refused(make_backup: Callable[..., Path]) -> None:
    backup: Final[Path] = make_backup()
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    record_path: Final[Path] = CTX.quarantine / "demo" / "pipx_takeover.json"
    record: Final[dict[str, object]] = json.loads(record_path.read_text(encoding="utf-8"))
    record["environment"] = "../escape"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    assert run_pipx_cli(["takeover", "approve", "demo"]) == 1
    assert not (CTX.venvs / "escape").exists()
    assert (CTX.quarantine / "demo" / "pipx_takeover.json").is_file()


@SKIP_IF_WINDOWS
@pytest.mark.usefixtures("pipx_temp_env")
def test_check_refuses_a_symlinked_stage(make_backup: Callable[..., Path], tmp_path: Path) -> None:
    backup: Final[Path] = make_backup()
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    elsewhere: Final[Path] = tmp_path / "elsewhere"
    (CTX.quarantine / "demo").rename(elsewhere)
    (CTX.quarantine / "demo").symlink_to(elsewhere)

    assert run_pipx_cli(["takeover", "check", "demo"]) == 1
    assert run_pipx_cli(["takeover", "approve", "demo"]) == 1


@pytest.mark.usefixtures("pipx_temp_env")
def test_approve_reports_a_collision_as_partial(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    blocker: Final[Path] = CTX.bin_dir / app_name("demo")
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker.write_text("not managed by pipx\n", encoding="utf-8")
    backup: Final[Path] = make_backup()
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    capsys.readouterr()

    assert run_pipx_cli(["takeover", "approve", "demo"]) == 1

    captured: Final = capsys.readouterr()
    assert (blocker.read_text(encoding="utf-8"), (CTX.venvs / "demo").is_dir()) == ("not managed by pipx\n", True)
    assert ("another file already owns that name" in captured.err, "exposed demo" in captured.out) == (True, False)


@pytest.mark.usefixtures("pipx_temp_env")
def test_approve_refuses_a_stage_changed_after_review(make_backup: Callable[..., Path]) -> None:
    backup: Final[Path] = make_backup()
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    staged_launcher: Final[Path] = CTX.quarantine / "demo" / "bin" / "demo"
    staged_launcher.write_text("#!/bin/sh\necho replaced\n", encoding="utf-8")

    assert run_pipx_cli(["takeover", "check", "demo"]) == 1
    assert run_pipx_cli(["takeover", "approve", "demo"]) == 1
    assert not (CTX.bin_dir / app_name("demo")).exists()


@pytest.mark.usefixtures("pipx_temp_env")
def test_approve_refuses_a_missing_interpreter(make_backup: Callable[..., Path]) -> None:
    backup: Final[Path] = make_backup(interpreter=False)

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 1
    assert run_pipx_cli(["takeover", "approve", "demo"]) == 1


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_refuses_a_name_that_would_escape_the_store(make_backup: Callable[..., Path]) -> None:
    backup: Final[Path] = make_backup()

    assert run_pipx_cli(["takeover", "stage", str(backup), "--name", "../escape"]) == 1

    assert not (CTX.quarantine.parent / "escape").exists()


@pytest.mark.usefixtures("pipx_temp_env")
def test_stage_refuses_an_existing_managed_environment(make_backup: Callable[..., Path]) -> None:
    (CTX.venvs / "pycowsay").mkdir(parents=True)
    backup: Final[Path] = make_backup(name="pycowsay", recorded_package="pycowsay")

    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 1


@pytest.mark.usefixtures("pipx_temp_env")
def test_remove_discards_a_stage_without_exposing_it(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    backup: Final[Path] = make_backup()
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    capsys.readouterr()

    assert run_pipx_cli(["takeover", "remove", "demo"]) == 0

    assert (not (CTX.quarantine / "demo").exists(), list(CTX.bin_dir.iterdir()), capsys.readouterr().out.strip()) == (
        True,
        [],
        "demo: removed from quarantine",
    )


@pytest.mark.usefixtures("pipx_temp_env")
def test_list_json_reports_provenance_and_problems(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    backup: Final[Path] = make_backup()
    assert run_pipx_cli(["takeover", "stage", str(backup), "--source", "usb-2026-11"]) == 0
    capsys.readouterr()

    assert run_pipx_cli(["takeover", "list", "--output", "json"]) == 0

    envelope: Final = json.loads(capsys.readouterr().out)
    environment: Final = envelope["data"]["environments"][0]
    assert (
        envelope["command"],
        environment["name"],
        environment["package"],
        environment["source"],
        environment["apps"],
        environment["problems"],
    ) == (["takeover", "list"], "demo", "demo", "usb-2026-11", ["demo"], [])


@pytest.mark.usefixtures("pipx_temp_env")
def test_list_is_empty_before_and_after_approval(
    make_backup: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_pipx_cli(["takeover", "list"]) == 0
    assert capsys.readouterr().out == "pipx has no environments in quarantine.\n"
    backup: Final[Path] = make_backup()
    assert run_pipx_cli(["takeover", "stage", str(backup)]) == 0
    assert run_pipx_cli(["takeover", "approve", "demo"]) == 0
    capsys.readouterr()

    assert run_pipx_cli(["takeover", "list"]) == 0
    assert capsys.readouterr().out == "pipx has no environments in quarantine.\n"


@pytest.mark.usefixtures("pipx_temp_env")
def test_quarantine_is_reported_as_a_derived_path(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_pipx_cli(["environment", "--value", "PIPX_QUARANTINE_DIR"]) == 0

    assert capsys.readouterr().out.strip() == str(CTX.quarantine)
