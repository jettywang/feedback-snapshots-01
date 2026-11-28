from __future__ import annotations

import json
import logging
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import auditwheel.lddtree
import auditwheel.wheel_abi
from auditwheel.architecture import Architecture
from auditwheel.error import MissingLibraryError, SearchPathError
from auditwheel.lddtree import build_search_paths, ldd
from auditwheel.libc import Libc
from auditwheel.main import main
from auditwheel.patcher import ElfPatcher
from auditwheel.repair import repair_wheel
from auditwheel.tools import zip2dir

if TYPE_CHECKING:
    from collections.abc import Iterator

HERE = Path(__file__).parent.resolve()
BUNDLED_WHEELS = HERE / ".." / "bundled-wheels"
# A real x86_64 shared object used as a stand-in for system libraries.
LIBFFI = HERE / ".." / "integration" / "libffi.so.5"


def _make_sysroot(
    root: Path,
    *,
    conf: str = "/lib\n/opt/approved\n",
    libraries: dict[str, str] | None = None,
    approved: str = "/opt/approved",
) -> Path:
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "ld.so.conf").write_text(conf)
    (root / "lib").mkdir()
    (root / "usr" / "lib").mkdir(parents=True)
    approved_dir = root / approved.lstrip("/")
    approved_dir.mkdir(parents=True, exist_ok=True)
    for soname, directory in (libraries or {}).items():
        target = root / directory.lstrip("/") / soname
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(LIBFFI, target)
    return root


def _extract_wheel(name: str, target: Path) -> Path:
    zip2dir(BUNDLED_WHEELS / name, target)
    return next(target.rglob("*.so"))


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    auditwheel.wheel_abi.get_wheel_elfdata.cache_clear()
    auditwheel.lddtree.load_ld_paths.cache_clear()
    yield
    auditwheel.wheel_abi.get_wheel_elfdata.cache_clear()
    auditwheel.lddtree.load_ld_paths.cache_clear()


def test_strict_search_ignores_host_environment(tmp_path: Path, monkeypatch) -> None:
    host = tmp_path / "host"
    host.mkdir()
    shutil.copy(LIBFFI, host / "libffi.so.5")
    monkeypatch.setenv("AUDITWHEEL_LD_LIBRARY_PATH", str(host))
    monkeypatch.setenv("LD_LIBRARY_PATH", str(host))

    sysroot = _make_sysroot(tmp_path / "sysroot")
    so = _extract_wheel("testzlib-0.0.1-cp310-cp310-linux_x86_64.whl", tmp_path / "wheel")

    search = build_search_paths(
        None,
        sysroot=str(sysroot),
        internal_root=str(tmp_path / "wheel"),
    )
    assert search is not None
    assert all(str(host) not in path for path in search.all_display_paths())

    with pytest.raises(SearchPathError, match="outside the sysroot"):
        build_search_paths(
            str(host),
            sysroot=str(sysroot),
            internal_root=str(tmp_path / "wheel"),
        )
    assert so.is_file()


def test_strict_search_reports_missing_sonames_and_required_by(tmp_path: Path) -> None:
    sysroot = _make_sysroot(tmp_path / "sysroot")
    so = _extract_wheel("testzlib-0.0.1-cp310-cp310-linux_x86_64.whl", tmp_path / "wheel")

    search = build_search_paths(None, sysroot=str(sysroot))
    with pytest.raises(MissingLibraryError) as exc_info:
        ldd(so, ldpaths=search)

    error = exc_info.value
    assert {"libz.so.1", "libc.so.6", "libpthread.so.0"} <= set(error.missing)
    assert str(so) in error.missing["libz.so.1"]
    assert str(sysroot / "lib") in error.search_paths
    assert str(sysroot / "opt" / "approved") in error.search_paths


def test_strict_search_resolves_nested_dependency_from_approved_source(
    tmp_path: Path,
) -> None:
    sysroot = _make_sysroot(
        tmp_path / "sysroot",
        libraries={
            "libffi.so.5": "/opt/approved",
            "libc.so.6": "/lib",
            "libpthread.so.0": "/lib",
            "ld-linux-x86-64.so.2": "/lib",
        },
    )
    so = _extract_wheel("cffi-1.5.0-cp27-none-linux_x86_64.whl", tmp_path / "wheel")

    result = ldd(so, ldpaths=build_search_paths(None, sysroot=str(sysroot)))

    libffi = result.libraries["libffi.so.5"]
    assert libffi.realpath == sysroot / "opt" / "approved" / "libffi.so.5"
    assert libffi.search_dir == str(sysroot / "opt" / "approved")
    assert libffi.search_source == "sysroot ld.so.conf:" + libffi.search_dir

    libc = result.libraries["libc.so.6"]
    assert libc.realpath == sysroot / "lib" / "libc.so.6"
    assert libc.search_dir == str(sysroot / "lib")


def test_strict_search_loads_approved_ldpaths_config(tmp_path: Path) -> None:
    sysroot = _make_sysroot(tmp_path / "sysroot", conf="")
    extra = sysroot / "srv" / "toolchain" / "lib"
    extra.mkdir(parents=True)
    shutil.copy(LIBFFI, extra / "libffi.so.5")
    for soname in ("libc.so.6", "libpthread.so.0", "ld-linux-x86-64.so.2"):
        shutil.copy(LIBFFI, sysroot / "lib" / soname)
    so = _extract_wheel("cffi-1.5.0-cp27-none-linux_x86_64.whl", tmp_path / "wheel")

    with pytest.raises(MissingLibraryError):
        ldd(so, ldpaths=build_search_paths(None, sysroot=str(sysroot)))

    search = build_search_paths(str(extra), sysroot=str(sysroot))
    result = ldd(so, ldpaths=search)
    assert result.libraries["libffi.so.5"].realpath == extra / "libffi.so.5"
    assert result.libraries["libffi.so.5"].search_source == f"--ldpaths:{extra}"


def test_strict_search_requires_sysroot_config(tmp_path: Path) -> None:
    sysroot = tmp_path / "empty"
    sysroot.mkdir()
    so = _extract_wheel("testzlib-0.0.1-cp310-cp310-linux_x86_64.whl", tmp_path / "wheel")

    with pytest.raises(SearchPathError, match="ld.so.conf"):
        ldd(so, ldpaths=build_search_paths(None, sysroot=str(sysroot)))


def test_analyze_fails_when_approved_source_is_incomplete(tmp_path: Path) -> None:
    sysroot = _make_sysroot(
        tmp_path / "sysroot",
        libraries={"libz.so.1": "/opt/approved"},
    )
    wheel = BUNDLED_WHEELS / "testzlib-0.0.1-cp310-cp310-linux_x86_64.whl"

    with pytest.raises(MissingLibraryError) as exc_info:
        auditwheel.wheel_abi.analyze_wheel_abi(
            Libc.GLIBC,
            Architecture.x86_64,
            wheel,
            frozenset(),
            disable_isa_ext_check=False,
            allow_graft=True,
            sysroot=str(sysroot),
        )

    assert {"libc.so.6", "libpthread.so.0"} <= set(exc_info.value.missing)


def test_analyze_records_sources_used_for_repair(tmp_path: Path) -> None:
    sysroot = _make_sysroot(
        tmp_path / "sysroot",
        libraries={
            "libz.so.1": "/opt/approved",
            "libc.so.6": "/lib",
            "libpthread.so.0": "/lib",
        },
    )
    wheel = BUNDLED_WHEELS / "testzlib-0.0.1-cp310-cp310-linux_x86_64.whl"

    winfo = auditwheel.wheel_abi.analyze_wheel_abi(
        Libc.GLIBC,
        Architecture.x86_64,
        wheel,
        frozenset(),
        disable_isa_ext_check=False,
        allow_graft=True,
        sysroot=str(sysroot),
    )

    assert winfo.library_provenance["libz.so.1"]["directory"] == str(
        sysroot / "opt" / "approved",
    )
    assert winfo.library_provenance["libc.so.6"]["directory"] == str(sysroot / "lib")
    assert str(sysroot / "opt" / "approved") in winfo.search_paths


class _OfflinePatcher(ElfPatcher):
    def __init__(self) -> None:
        super().__init__("")

    def get_rpath_direct(self, file_name: Path) -> str:
        return ""

    def apply_updates(self) -> None:
        self._updates.clear()


def test_repair_takes_library_from_approved_source(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sysroot = _make_sysroot(
        tmp_path / "sysroot",
        libraries={
            "libffi.so.5": "/opt/approved",
            "libc.so.6": "/lib",
            "libpthread.so.0": "/lib",
            "ld-linux-x86-64.so.2": "/lib",
        },
    )
    wheel = BUNDLED_WHEELS / "cffi-1.5.0-cp27-none-linux_x86_64.whl"

    winfo = auditwheel.wheel_abi.analyze_wheel_abi(
        Libc.GLIBC,
        Architecture.x86_64,
        wheel,
        frozenset(),
        disable_isa_ext_check=False,
        allow_graft=True,
        sysroot=str(sysroot),
    )
    out_dir = tmp_path / "wheelhouse"
    out_dir.mkdir()

    with caplog.at_level(logging.INFO, logger="auditwheel.repair"):
        repaired = repair_wheel(
            winfo,
            wheel,
            abis=["manylinux_2_5_x86_64"],
            lib_sdir=".libs",
            out_dir=out_dir,
            update_tags=False,
            patcher=_OfflinePatcher(),
            strip=False,
            zip_compression_level=6,
        )

    assert repaired is not None
    approved = str(sysroot / "opt" / "approved" / "libffi.so.5")
    assert f"Grafting libffi.so.5 from {approved} (approved via sysroot ld.so.conf:" in caplog.text


def test_show_json_reports_sources_and_fails_on_missing_approved_source(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sysroot = _make_sysroot(
        tmp_path / "sysroot",
        libraries={
            "libz.so.1": "/opt/approved",
            "libc.so.6": "/lib",
            "libpthread.so.0": "/lib",
        },
    )
    wheel = BUNDLED_WHEELS / "testzlib-0.0.1-cp310-cp310-linux_x86_64.whl"

    monkeypatch.setattr(
        sys,
        "argv",
        ["auditwheel", "show", "--json", "--sysroot", str(sysroot), str(wheel)],
    )
    assert main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["library_sources"]["libz.so.1"]["directory"] == str(
        sysroot / "opt" / "approved",
    )
    assert str(sysroot / "lib") in output["search_paths"]

    (sysroot / "opt" / "approved" / "libz.so.1").unlink()
    auditwheel.wheel_abi.get_wheel_elfdata.cache_clear()
    monkeypatch.setattr(
        sys,
        "argv",
        ["auditwheel", "show", "--json", "--sysroot", str(sysroot), str(wheel)],
    )
    assert main() == 1
    output = json.loads(capsys.readouterr().out)
    assert "libz.so.1" in output["missing_libs"]
    assert str(wheel.name) not in output["missing_libs"]["libz.so.1"]


def test_strict_search_remaps_absolute_rpath_below_sysroot(tmp_path: Path) -> None:
    # cffi's extension carries RPATH /opt/2.7.11/lib, which only exists in the
    # approved tree on this build host (never at the host root).
    sysroot = _make_sysroot(
        tmp_path / "sysroot",
        libraries={
            "libffi.so.5": "/opt/2.7.11/lib",
            "libc.so.6": "/lib",
            "libpthread.so.0": "/lib",
            "ld-linux-x86-64.so.2": "/lib",
        },
    )
    so = _extract_wheel("cffi-1.5.0-cp27-none-linux_x86_64.whl", tmp_path / "wheel")

    result = ldd(so, ldpaths=build_search_paths(None, sysroot=str(sysroot)))

    # The extension's absolute RPATH /opt/2.7.11/lib is remapped below the
    # sysroot instead of being consulted on the host.
    libffi = result.libraries["libffi.so.5"]
    assert libffi.realpath == sysroot / "opt/2.7.11/lib/libffi.so.5"
    assert libffi.search_dir == str(sysroot / "opt/2.7.11/lib")
    approved = build_search_paths(None, sysroot=str(sysroot))
    assert approved.approved_dir("rpath", "/opt/2.7.11/lib") == str(sysroot / "opt/2.7.11/lib")


def test_strict_search_keeps_wheel_internal_references(tmp_path: Path) -> None:
    sysroot = _make_sysroot(tmp_path / "sysroot")
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    internal = wheel_dir / "pkg" / ".libs"
    internal.mkdir(parents=True)

    search = build_search_paths(
        None,
        sysroot=str(sysroot),
        internal_root=str(wheel_dir),
    )
    assert search is not None
    assert search.approved_dir("rpath", str(internal)) == str(internal)
    assert search.approved_dir("runpath", "$ORIGIN/../.libs") is None
    outside = tmp_path / "other"
    outside.mkdir()
    assert search.approved_dir("rpath", str(outside)) is None
