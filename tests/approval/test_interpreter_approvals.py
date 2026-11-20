from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from pipx import interpreter_approval, standalone_python
from pipx.constants import FetchPythonOptions
from pipx.interpreter import find_python_interpreter
from pipx.paths import CTX
from pipx.util import PipxError

if TYPE_CHECKING:
    from collections.abc import Callable

    from pytest_mock import MockerFixture, MockType

_VERSION: Final[str] = "3.99.0"
_REQUESTED: Final[str] = "3.99"


def _digest(archive_bytes: bytes) -> str:
    return f"sha256:{hashlib.sha256(archive_bytes).hexdigest()}"


def _python_archive_bytes() -> bytes:
    archive: Final[io.BytesIO] = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as python_tar:
        for name in ("python/bin/python3", "python/python.exe"):
            python_tar.addfile(tarfile.TarInfo(name), io.BytesIO())
    return archive.getvalue()


def test_approved_build_downloads_and_records_receipt(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    isolated_pipx_home: Path,
) -> None:
    archive_bytes: Final[bytes] = _python_archive_bytes()
    cache_dir, _link, digest, urlopen = fake_index(archive_bytes)
    approved_at: Final[float] = 1_700_000_000.0
    (isolated_pipx_home / "approvals.json").write_text(
        json.dumps({
            "created": approved_at,
            "releases": [{"version": _VERSION, "digest": digest}],
        }),
        encoding="utf-8",
    )

    python_path: Final[str] = standalone_python.download_python_build_standalone(_REQUESTED)

    assert (Path(python_path).is_file(), urlopen.call_count) == (True, 1)
    receipt = json.loads((cache_dir / _REQUESTED / "approval.json").read_text(encoding="utf-8"))
    assert (receipt["version"], receipt["digest"], receipt["approved"]) == (_VERSION, digest, approved_at)
    assert receipt["installed"] >= approved_at


def test_unapproved_build_is_refused_before_download(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    approval_manifest: Callable[[list[tuple[str, str]]], Path],
) -> None:
    archive_bytes: Final[bytes] = _python_archive_bytes()
    cache_dir, _link, _digest_value, urlopen = fake_index(archive_bytes)
    approval_manifest([(_VERSION, f"sha256:{'0' * 64}")])

    with pytest.raises(PipxError, match="not in the interpreter approval manifest"):
        standalone_python.download_python_build_standalone(_REQUESTED)

    assert (urlopen.call_count, (cache_dir / _REQUESTED).exists()) == (0, False)


def test_without_manifest_download_is_unchanged(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
) -> None:
    archive_bytes: Final[bytes] = _python_archive_bytes()
    cache_dir, _link, _digest_value, _urlopen = fake_index(archive_bytes)

    python_path: Final[str] = standalone_python.download_python_build_standalone(_REQUESTED)

    assert (Path(python_path).is_file(), (cache_dir / _REQUESTED / "approval.json").exists()) == (True, False)


def test_missing_manifest_blocks_download_when_enforced(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    archive_bytes: Final[bytes] = _python_archive_bytes()
    _cache_dir, _link, _digest_value, urlopen = fake_index(archive_bytes)
    missing: Final[Path] = tmp_path / "admin" / "approvals.json"
    monkeypatch.setenv(interpreter_approval.APPROVAL_MANIFEST_ENV, str(missing))

    with pytest.raises(PipxError, match="no interpreter approval manifest is in force"):
        standalone_python.download_python_build_standalone(_REQUESTED)

    assert urlopen.call_count == 0


def test_malformed_manifest_is_refused(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    isolated_pipx_home: Path,
) -> None:
    fake_index(_python_archive_bytes())
    (isolated_pipx_home / "approvals.json").write_text('{"releases": "nope"}', encoding="utf-8")

    with pytest.raises(PipxError, match="malformed"):
        standalone_python.download_python_build_standalone(_REQUESTED)


def test_cached_build_reuses_receipt_offline(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    approval_manifest: Callable[[list[tuple[str, str]]], Path],
    caplog: pytest.LogCaptureFixture,
) -> None:
    archive_bytes: Final[bytes] = _python_archive_bytes()
    cache_dir, _link, digest, urlopen = fake_index(archive_bytes)
    approval_manifest([(_VERSION, digest)])
    standalone_python.download_python_build_standalone(_REQUESTED)
    assert urlopen.call_count == 1

    # expire the index so a fresh lookup would hit the network, then take the network away; the cached build and its
    # receipt must still verify with no download at all
    index_file: Final[Path] = cache_dir / "index.json"
    stale = json.loads(index_file.read_text(encoding="utf-8"))
    stale["fetched"] = (dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=31)).timestamp()
    index_file.write_text(json.dumps(stale), encoding="utf-8")
    urlopen.side_effect = AssertionError("an offline cache hit must not open the network")

    python_path: Final[str] = standalone_python.download_python_build_standalone(_REQUESTED)

    assert Path(python_path).is_file()
    assert f"Using cached python {_VERSION}" in caplog.text


def test_cached_build_without_receipt_and_rotated_manifest_is_refused(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    approval_manifest: Callable[[list[tuple[str, str]]], Path],
) -> None:
    archive_bytes: Final[bytes] = _python_archive_bytes()
    cache_dir, _link, digest, _urlopen = fake_index(archive_bytes)
    approval_manifest([(_VERSION, digest)])
    standalone_python.download_python_build_standalone(_REQUESTED)
    # the admin rotates the manifest to a different build, and the receipt is gone
    (cache_dir / _REQUESTED / "approval.json").unlink()
    approval_manifest([(_VERSION, f"sha256:{'0' * 64}")])

    with pytest.raises(PipxError) as error:
        standalone_python.download_python_build_standalone(_REQUESTED)

    assert "not covered by the interpreter approval manifest" in error.value.raw_message


def test_index_advertising_wrong_digest_is_refused_before_install(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    approval_manifest: Callable[[list[tuple[str, str]]], Path],
) -> None:
    archive_bytes: Final[bytes] = _python_archive_bytes()
    cache_dir, _link, _index_digest, _urlopen = fake_index(archive_bytes)
    # the manifest approves this exact build, but the index advertises another digest, as a tampered index would
    approval_manifest([(_VERSION, _digest(archive_bytes))])
    index_file: Final[Path] = cache_dir / "index.json"
    tampered = json.loads(index_file.read_text(encoding="utf-8"))
    tampered["releases"][0][1] = f"sha256:{'f' * 64}"
    index_file.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(PipxError, match="not in the interpreter approval manifest"):
        standalone_python.download_python_build_standalone(_REQUESTED)

    assert not (cache_dir / _REQUESTED).exists()


def test_downloaded_bytes_differing_from_approval_are_refused(
    isolated_pipx_home: Path,
    approval_manifest: Callable[[list[tuple[str, str]]], Path],
    mocker: MockerFixture,
) -> None:
    good: Final[bytes] = _python_archive_bytes()
    mocker.patch.object(standalone_python.platform, "system", return_value="Darwin", autospec=True)
    mocker.patch.object(standalone_python.platform, "machine", return_value="arm64", autospec=True)
    link: Final[str] = "https://example.invalid/cpython-3.99.0-aarch64-apple-darwin-install_only.tar.gz"
    # the index and manifest agree on the digest of the good build, but the server hands back different bytes
    (isolated_pipx_home / "index.json").write_text(
        json.dumps({
            "fetched": dt.datetime.now(tz=dt.UTC).timestamp(),
            "releases": [[link, _digest(good)]],
        })
    )
    approval_manifest([(_VERSION, _digest(good))])
    mocker.patch.object(standalone_python, "urlopen", return_value=io.BytesIO(b"tampered payload"), autospec=True)

    with pytest.raises(PipxError, match="Checksum mismatch"):
        standalone_python.download_python_build_standalone(_REQUESTED)

    assert not (isolated_pipx_home / _REQUESTED).exists()


def test_manifest_path_environment_override(
    isolated_pipx_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    custom: Final[Path] = tmp_path / "admin-approvals.json"
    monkeypatch.setenv(interpreter_approval.APPROVAL_MANIFEST_ENV, str(custom))

    assert interpreter_approval.approval_manifest_path() == custom
    custom.write_text(
        json.dumps({"created": 1.0, "releases": [{"version": _VERSION, "digest": _digest(b"x")}]}),
        encoding="utf-8",
    )
    approvals = interpreter_approval.load_approvals()

    assert approvals is not None
    assert approvals[(_VERSION, _digest(b"x"))].version == _VERSION


def test_local_interpreter_still_selected_with_manifest(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    approval_manifest: Callable[[list[tuple[str, str]]], Path],
    monkeypatch: pytest.MonkeyPatch,
    mocker: MockerFixture,
) -> None:
    archive_bytes: Final[bytes] = _python_archive_bytes()
    _cache_dir, _link, digest, _urlopen = fake_index(archive_bytes)
    # the manifest only approves the unrelated 3.99 build, which fetching would otherwise try to download
    approval_manifest([(_VERSION, digest)])
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/python3.13" if name == "python3.13" else None)
    download: Final[MockType] = mocker.patch.object(
        standalone_python, "download_python_build_standalone", autospec=True
    )

    python_path: Final[str] = find_python_interpreter("3.13", FetchPythonOptions.MISSING)

    assert (python_path, download.call_count) == ("/usr/bin/python3.13", 0)


def test_receipt_round_trip(isolated_pipx_home: Path) -> None:
    install_dir: Final[Path] = isolated_pipx_home / "3.99"
    install_dir.mkdir()
    approval = interpreter_approval.Approval(version=_VERSION, digest=_digest(b"build"), approved_at=1.0)

    interpreter_approval.write_approval_receipt(install_dir, approval)
    receipt = interpreter_approval.read_approval_receipt(install_dir)

    assert receipt is not None
    assert (receipt["version"], receipt["digest"]) == (_VERSION, _digest(b"build"))


def test_corrupt_receipt_falls_back_to_manifest_check(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    approval_manifest: Callable[[list[tuple[str, str]]], Path],
) -> None:
    archive_bytes: Final[bytes] = _python_archive_bytes()
    cache_dir, _link, digest, _urlopen = fake_index(archive_bytes)
    approval_manifest([(_VERSION, digest)])
    standalone_python.download_python_build_standalone(_REQUESTED)
    (cache_dir / _REQUESTED / "approval.json").write_text("not json", encoding="utf-8")

    # no receipt can be matched, and the unpacked tree hash differs from the archive digest, so it is refused rather
    # than silently treated as approved
    with pytest.raises(PipxError) as error:
        standalone_python.download_python_build_standalone(_REQUESTED)

    assert "not covered by the interpreter approval manifest" in error.value.raw_message


def test_interpreter_list_names_the_approval_used(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
    approval_manifest: Callable[[list[tuple[str, str]]], Path],
) -> None:
    from pipx.commands.interpreter import list_interpreters
    from pipx.venv import VenvContainer

    archive_bytes: Final[bytes] = _python_archive_bytes()
    cache_dir, _link, digest, _urlopen = fake_index(archive_bytes)
    approval_manifest([(_VERSION, digest)])
    standalone_python.download_python_build_standalone(_REQUESTED)

    result = list_interpreters(VenvContainer(CTX.venvs))
    text = result.messages[0].text

    assert f"Approved: {_VERSION} ({digest})" in text
    assert f"Python {_REQUESTED}" in text


def test_interpreter_list_without_receipt_stays_silent(
    fake_index: Callable[..., tuple[Path, str, str, MockType]],
) -> None:
    from pipx.commands.interpreter import list_interpreters
    from pipx.venv import VenvContainer

    archive_bytes: Final[bytes] = _python_archive_bytes()
    fake_index(archive_bytes)
    standalone_python.download_python_build_standalone(_REQUESTED)

    result = list_interpreters(VenvContainer(CTX.venvs))
    text = result.messages[0].text

    assert "Approved:" not in text
