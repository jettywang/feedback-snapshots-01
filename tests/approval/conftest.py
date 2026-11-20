from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from pipx import paths, standalone_python
from pipx.paths import CTX

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from pytest_mock import MockerFixture, MockType

_DARWIN_LINK: Final[str] = "https://example.invalid/cpython-3.99.0-aarch64-apple-darwin-install_only.tar.gz"


@pytest.fixture(autouse=True)
def _approval_logs_propagate() -> Iterator[None]:
    # pipx's logging setup can stop the standalone module logger from propagating; caplog only catches propagated
    # records, so pin propagation on for these unit tests
    logger = logging.getLogger("pipx.standalone_python")
    previous = logger.propagate
    logger.propagate = True
    yield
    logger.propagate = previous


@pytest.fixture
def isolated_pipx_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(paths, "OVERRIDE_PIPX_HOME", tmp_path / "pipxhome")
    monkeypatch.delenv("PIPX_INTERPRETER_APPROVALS", raising=False)
    CTX.make_local()
    CTX.standalone_python_cachedir.mkdir(parents=True, exist_ok=True)
    return CTX.standalone_python_cachedir


@pytest.fixture(scope="session", autouse=True)
def pipx_local_pypiserver() -> str:
    # these tests never install a package, so they need neither the local pypiserver nor its network cache update
    return ""


@pytest.fixture
def fake_index(
    isolated_pipx_home: Path,
    mocker: MockerFixture,
) -> Callable[[bytes], tuple[Path, str, str, MockType]]:
    mocker.patch.object(standalone_python.platform, "system", return_value="Darwin", autospec=True)
    mocker.patch.object(standalone_python.platform, "machine", return_value="arm64", autospec=True)

    def publish(archive_bytes: bytes) -> tuple[Path, str, str, MockType]:
        cache_dir: Final[Path] = isolated_pipx_home
        digest: Final[str] = f"sha256:{hashlib.sha256(archive_bytes).hexdigest()}"
        (cache_dir / "index.json").write_text(
            json.dumps({
                "fetched": dt.datetime.now(tz=dt.UTC).timestamp(),
                "releases": [[_DARWIN_LINK, digest]],
            })
        )
        urlopen: Final[MockType] = mocker.patch.object(
            standalone_python, "urlopen", return_value=io.BytesIO(archive_bytes), autospec=True
        )
        return cache_dir, _DARWIN_LINK, digest, urlopen

    return publish


@pytest.fixture
def approval_manifest(isolated_pipx_home: Path) -> Callable[[list[tuple[str, str]]], Path]:
    def write(entries: list[tuple[str, str]]) -> Path:
        manifest: Final[Path] = isolated_pipx_home / "approvals.json"
        manifest.write_text(
            json.dumps({
                "created": dt.datetime.now(tz=dt.UTC).timestamp(),
                "releases": [{"version": version, "digest": digest} for version, digest in entries],
            }),
            encoding="utf-8",
        )
        return manifest

    return write
