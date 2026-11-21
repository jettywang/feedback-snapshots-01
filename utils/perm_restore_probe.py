#!/usr/bin/env python
"""Reproduce py7zr's permission-restore behaviour in a throwaway directory.

The probe builds small 7z archives whose member attributes are written
explicitly, extracts them into fresh directories, and records every
``os.chmod`` request py7zr makes.  It answers four questions for a managed
recovery service:

* which members are restored at all (regular files, directories, links,
  sockets, FIFOs/devices, junction-like members);
* what py7zr asks the kernel to apply (including setuid/setgid and sticky);
* what the kernel actually accepts on this host;
* what a ``WriterFactory`` changes about the answer.

Run from the repository root::

    .venv/bin/python utils/perm_restore_probe.py

The script exits non-zero if an expectation that is portable across POSIX
hosts fails.  Platform-specific observations are printed, not asserted.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import pathlib
import shutil
import stat
import sys
import tempfile

import py7zr
from py7zr.io import BytesIOFactory
from py7zr.member import FILE_ATTRIBUTE_UNIX_EXTENSION

UX = FILE_ATTRIBUTE_UNIX_EXTENSION
IS_POSIX = os.name == "posix"
IS_WINDOWS = sys.platform == "win32"

WIN_ARCHIVE = getattr(stat, "FILE_ATTRIBUTE_ARCHIVE", 0x20)
WIN_DIRECTORY = getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
WIN_READONLY = getattr(stat, "FILE_ATTRIBUTE_READONLY", 0x01)
WIN_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    RESULTS.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}: {detail}")


def attrs(win: int, unix_mode: int | None = None) -> int:
    """Build a 7z attribute word, optionally with the Unix extension."""
    value = win
    if unix_mode is not None:
        value |= UX | (unix_mode << 16)
    return value


def mode_of(path: pathlib.Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@contextlib.contextmanager
def umask(mask: int):
    previous = os.umask(mask)
    try:
        yield
    finally:
        os.umask(previous)


@contextlib.contextmanager
def record_chmod():
    """Record every os.chmod request, including pathlib.Path.chmod calls."""
    calls: list[tuple[str, int, bool]] = []
    real = os.chmod

    def spy(path, mode, *args, **kwargs):
        calls.append((os.path.abspath(os.fspath(path)), int(mode), bool(kwargs.get("follow_symlinks", True))))
        return real(path, mode, *args, **kwargs)

    os.chmod = spy
    try:
        yield calls
    finally:
        os.chmod = real


def build_archive(target: pathlib.Path, entries: list[tuple[str, int, bytes]]) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with py7zr.SevenZipFile(target, "w") as archive:
        for name, attributes, payload in entries:
            archive.writestr(payload, name)
            archive.files.files_list[-1]["attributes"] = attributes


def extract(archive_path: pathlib.Path, dest: pathlib.Path, factory=None, targets=None):
    with py7zr.SevenZipFile(archive_path, "r") as archive:
        if factory is not None:
            archive.extractall(dest, factory=factory)
        elif targets is not None:
            archive.extract(dest, targets=targets, recursive=True)
        else:
            archive.extractall(dest)


def probe_regular_and_directory(root: pathlib.Path) -> None:
    source = root / "src"
    (source / "d").mkdir(parents=True)
    (source / "d" / "f").write_text("data")
    (source / "plain").write_text("data")
    os.chmod(source / "d", 0o750)
    os.chmod(source / "d" / "f", 0o640)
    os.chmod(source / "plain", 0o600)

    archive = root / "tree.7z"
    with py7zr.SevenZipFile(archive, "w") as writer:
        writer.writeall(source, "tree")

    dest = root / "out"
    with umask(0o077):
        extract(archive, dest)

    check("regular file mode restored", mode_of(dest / "tree" / "d" / "f") == 0o640, oct(mode_of(dest / "tree" / "d" / "f")))
    check("directory mode restored", mode_of(dest / "tree" / "d") == 0o750, oct(mode_of(dest / "tree" / "d")))
    check("file mode restored", mode_of(dest / "tree" / "plain") == 0o600, oct(mode_of(dest / "tree" / "plain")))
    check("base directory follows umask", mode_of(dest) == 0o700, oct(mode_of(dest)))


def probe_windows_only_attributes(root: pathlib.Path) -> None:
    archive = root / "windows.7z"
    build_archive(
        archive,
        [
            ("rw.txt", attrs(WIN_ARCHIVE), b"rw"),
            ("ro.txt", attrs(WIN_ARCHIVE | WIN_READONLY), b"ro"),
            ("dir", attrs(WIN_DIRECTORY | WIN_READONLY), b""),
        ],
    )
    for mask, expected_rw, expected_ro, expected_dir in ((0o022, 0o644, 0o444, 0o755), (0o077, 0o600, 0o400, 0o700)):
        dest = root / f"win-{mask:o}"
        with umask(mask):
            extract(archive, dest)
        if IS_POSIX:
            check(
                f"readonly fallback umask {mask:o}",
                (mode_of(dest / "rw.txt"), mode_of(dest / "ro.txt"), mode_of(dest / "dir"))
                == (expected_rw, expected_ro, expected_dir),
                f"rw={oct(mode_of(dest / 'rw.txt'))} ro={oct(mode_of(dest / 'ro.txt'))} dir={oct(mode_of(dest / 'dir'))}",
            )
        else:
            print(f"[INFO] Windows host: observed rw={oct(mode_of(dest / 'rw.txt'))} ro={oct(mode_of(dest / 'ro.txt'))}")


def probe_posix_overrides_readonly(root: pathlib.Path) -> None:
    if not IS_POSIX:
        print("[SKIP] POSIX mode override is not applicable on this host")
        return
    archive = root / "override.7z"
    build_archive(archive, [("f", attrs(WIN_ARCHIVE | WIN_READONLY, stat.S_IFREG | 0o644), b"x")])
    dest = root / "override"
    extract(archive, dest)
    check("posix_mode bypasses readonly fallback", mode_of(dest / "f") == 0o644, oct(mode_of(dest / "f")))


def probe_special_bits(root: pathlib.Path) -> None:
    if not IS_POSIX:
        print("[SKIP] Unix permission bits are not applicable on this host")
        return
    archive = root / "special.7z"
    build_archive(
        archive,
        [
            ("suid", attrs(WIN_ARCHIVE, stat.S_IFREG | 0o4755), b"x"),
            ("sgid-dir", attrs(WIN_DIRECTORY, stat.S_IFDIR | 0o2775), b""),
            ("sticky-dir", attrs(WIN_DIRECTORY, stat.S_IFDIR | 0o1777), b""),
        ],
    )
    dest = root / "special"
    with record_chmod() as calls:
        extract(archive, dest)
    requested = {pathlib.Path(path).name: mode for path, mode, _ in calls}
    check("setuid is requested verbatim", requested.get("suid") == 0o4755, f"requested {oct(requested.get('suid', 0))}")
    sgid = requested.get("sgid-dir", 0)
    sticky = requested.get("sticky-dir", 0)
    check("setgid directory is requested verbatim", sgid == 0o2775, f"requested {oct(sgid)}")
    check("sticky directory is requested verbatim", sticky == 0o1777, f"requested {oct(sticky)}")
    print(
        "[INFO] kernel accepted: "
        f"suid={oct(mode_of(dest / 'suid'))} sgid-dir={oct(mode_of(dest / 'sgid-dir'))} "
        f"sticky-dir={oct(mode_of(dest / 'sticky-dir'))}"
    )


def probe_directory_order(root: pathlib.Path) -> None:
    if not IS_POSIX:
        print("[SKIP] restrictive directory ordering test is POSIX-specific")
        return
    restricted_first = root / "restricted-first.7z"
    build_archive(
        restricted_first,
        [
            ("d", attrs(WIN_DIRECTORY, stat.S_IFDIR | 0o000), b""),
            ("d/f", attrs(WIN_ARCHIVE, stat.S_IFREG | 0o644), b"x"),
        ],
    )
    dest = root / "restricted-first"
    failed = False
    try:
        extract(restricted_first, dest)
    except PermissionError:
        failed = True
    check("0000 directory before child fails post-processing", failed, f"leftover mode {oct(mode_of(dest / 'd'))}")
    os.chmod(dest / "d", 0o700)

    child_first = root / "child-first.7z"
    build_archive(
        child_first,
        [
            ("d/f", attrs(WIN_ARCHIVE, stat.S_IFREG | 0o644), b"x"),
            ("d", attrs(WIN_DIRECTORY, stat.S_IFDIR | 0o000), b""),
        ],
    )
    dest2 = root / "child-first"
    failed2 = False
    try:
        extract(child_first, dest2)
    except PermissionError:
        failed2 = True
    child_mode = mode_of(dest2 / "d")
    check("same modes in child-first order succeed", not failed2 and child_mode == 0o000, oct(child_mode))
    os.chmod(dest2 / "d", 0o700)


def probe_preexisting_directory(root: pathlib.Path) -> None:
    archive = root / "predir.7z"
    build_archive(
        archive,
        [
            ("d", attrs(WIN_DIRECTORY, stat.S_IFDIR | 0o755), b""),
            ("d/f", attrs(WIN_ARCHIVE, stat.S_IFREG | 0o644), b"x"),
        ],
    )
    dest = root / "predir"
    (dest / "d").mkdir(parents=True)
    os.chmod(dest / "d", 0o700)
    with record_chmod() as calls:
        extract(archive, dest)
    touched = [path for path, _, _ in calls if pathlib.Path(path).name == "d"]
    kept = mode_of(dest / "d")
    check("pre-existing directory mode is not applied", kept == 0o700 and not touched, oct(kept))


def probe_implicit_parents(root: pathlib.Path) -> None:
    archive = root / "implicit.7z"
    build_archive(archive, [("a/b/c.txt", attrs(WIN_ARCHIVE), b"x")])
    dest = root / "implicit"
    with umask(0o077):
        extract(archive, dest)
        # Measure before the umask context unwinds: os.umask below only affects creation.
        observed = tuple(mode_of(dest / p) for p in ("a", "a/b", "a/b/c.txt"))
    check("implicit parents follow umask", observed == (0o700, 0o700, 0o600), ", ".join(oct(m) for m in observed))


def probe_symlink(root: pathlib.Path) -> None:
    source = root / "link-src"
    source.mkdir(parents=True)
    (source / "target").write_text("x")
    (source / "link").symlink_to("target")
    archive = root / "link.7z"
    with py7zr.SevenZipFile(archive, "w") as writer:
        writer.writeall(source, "tree")

    dest = root / "link-out"
    with record_chmod() as calls:
        try:
            extract(archive, dest)
        except OSError as error:
            print(f"[SKIP] symlink creation not permitted on this host: {error}")
            return
    link = dest / "tree" / "link"
    touched = [path for path, _, _ in calls if pathlib.Path(path).name == "link"]
    target = os.readlink(link) if link.is_symlink() else "not a link"
    check("symlink is created with its target", link.is_symlink() and target == "target", target)
    check("symlink never receives chmod", not touched, f"chmod calls={len(touched)}")
    print(f"[INFO] symlink mode after extraction: {oct(mode_of(link))} (platform/umask default)")

    synthetic = root / "link-mode.7z"
    build_archive(synthetic, [("ln", attrs(WIN_ARCHIVE, stat.S_IFLNK | 0o711), b"target")])
    dest2 = root / "link-mode"
    with umask(0o022), record_chmod() as calls2:
        try:
            extract(synthetic, dest2)
        except OSError as error:
            print(f"[SKIP] synthetic symlink creation not permitted: {error}")
            return
    observed = mode_of(dest2 / "ln")
    check(
        "archive symlink mode is ignored",
        observed != 0o711 and not calls2,
        f"requested={oct(0o711)} observed={oct(observed)}",
    )


def probe_factory(root: pathlib.Path) -> None:
    source = root / "factory-src"
    (source / "d").mkdir(parents=True)
    (source / "d" / "f").write_text("data")
    (source / "link").symlink_to("d/f")
    archive = root / "factory.7z"
    with py7zr.SevenZipFile(archive, "w") as writer:
        writer.writeall(source, "tree")

    dest = root / "factory-out"
    factory = BytesIOFactory(1 << 20)
    with record_chmod() as calls:
        extract(archive, dest, factory=factory)
    check("factory performs no chmod", not calls, f"chmod calls={len(calls)}")
    entries = sorted(dest.rglob("*")) if dest.exists() else []
    check("factory writes no files", not entries, f"entries={[str(p.relative_to(dest)) for p in entries]}")
    names = sorted(pathlib.Path(name).name for name in factory.products)
    check("factory sees files and links, not directories", names == ["f", "link"], str(names))
    payload = factory.products[next(name for name in factory.products if name.endswith("/link"))]
    payload.seek(0)
    link_bytes = payload.read()
    check("factory receives link target as bytes", link_bytes == b"d/f", repr(link_bytes))


def probe_junction(root: pathlib.Path) -> None:
    archive = root / "junction.7z"
    build_archive(archive, [("j", attrs(WIN_DIRECTORY | WIN_REPARSE), b"C:/target")])
    dest = root / "junction"
    with py7zr.SevenZipFile(archive, "r") as reader:
        member = reader.files[0]
        is_dir, is_junction = member.is_directory, member.is_junction
        reader.extractall(dest)
    path = dest / "j"
    check(
        "junction is classified as directory",
        is_dir and is_junction and path.is_dir() and not path.is_symlink(),
        f"is_directory={is_dir} is_junction={is_junction} extracted_dir={path.is_dir()}",
    )
    print("[INFO] junction payload is not written on this platform; an empty directory is created")


def probe_type_confusion(root: pathlib.Path) -> None:
    if not IS_POSIX:
        print("[SKIP] Unix file-type bits are not applicable on this host")
        return
    cases = [
        ("fifo", stat.S_IFIFO | 0o644),
        ("chr", stat.S_IFCHR | 0o600),
    ]
    for name, unix_mode in cases:
        archive = root / f"{name}.7z"
        build_archive(archive, [(name, attrs(WIN_ARCHIVE, unix_mode), b"x")])
        dest = root / f"{name}-out"
        extract(archive, dest)
        path = dest / name
        check(
            f"{name} degrades to regular file",
            path.is_file() and not path.is_symlink() and mode_of(path) == stat.S_IMODE(unix_mode),
            f"is_file={path.is_file()} mode={oct(mode_of(path))}",
        )

    socket_archive = root / "socket.7z"
    build_archive(socket_archive, [("sock", attrs(WIN_ARCHIVE, stat.S_IFSOCK | 0o600), b"")])
    socket_dest = root / "socket-out"
    extract(socket_archive, socket_dest)
    check("socket is skipped", not (socket_dest / "sock").exists(), "no output entry")

    unix_dir_archive = root / "unix-dir.7z"
    build_archive(unix_dir_archive, [("ud", attrs(WIN_ARCHIVE, stat.S_IFDIR | 0o755), b"")])
    unix_dir_dest = root / "unix-dir-out"
    extract(unix_dir_archive, unix_dir_dest)
    path = unix_dir_dest / "ud"
    check(
        "unix S_IFDIR without Windows bit becomes a file",
        path.is_file() and mode_of(path) == 0o755,
        f"is_file={path.is_file()} mode={oct(mode_of(path))}",
    )


def probe_aliasing(root: pathlib.Path) -> None:
    if not IS_POSIX:
        print("[SKIP] symlink aliasing test is POSIX-specific")
        return
    dest = root / "alias"
    dest.mkdir(parents=True)
    victim = dest / "victim"
    victim.write_text("ORIGINAL")
    os.chmod(victim, 0o644)
    (dest / "f").symlink_to("victim")

    archive = root / "alias.7z"
    build_archive(archive, [("f", attrs(WIN_ARCHIVE, stat.S_IFREG | 0o600), b"NEW")])
    extract(archive, dest)
    check(
        "in-root pre-existing symlink is followed",
        (dest / "f").is_symlink() and victim.read_text() == "NEW" and mode_of(victim) == 0o600,
        f"content={victim.read_text()} mode={oct(mode_of(victim))}",
    )

    outside = root / "outside"
    outside.mkdir()
    (outside / "victim").write_text("SAFE")
    dest2 = root / "alias-outside"
    dest2.mkdir(parents=True)
    (dest2 / "f").symlink_to(outside / "victim")
    escaped = False
    try:
        extract(archive, dest2)
    except py7zr.Bad7zFile:
        escaped = True
    check("out-of-root pre-existing symlink is rejected", escaped, "Bad7zFile raised" if escaped else "no error")


def probe_target_prefix(root: pathlib.Path) -> None:
    archive = root / "targets.7z"
    build_archive(
        archive,
        [
            ("etc/passwd", attrs(WIN_ARCHIVE, stat.S_IFREG | 0o644), b"a"),
            ("etcpasswd", attrs(WIN_ARCHIVE, stat.S_IFREG | 0o644), b"b"),
            ("etc2/x", attrs(WIN_ARCHIVE, stat.S_IFREG | 0o644), b"c"),
        ],
    )
    dest = root / "targets-out"
    extract(archive, dest, targets=["etc"])
    extracted = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    check(
        "recursive target matching is a string prefix",
        extracted == ["etc/passwd", "etc2/x", "etcpasswd"],
        str(extracted),
    )


def run(root: pathlib.Path) -> int:
    print(f"platform={sys.platform} os.name={os.name} python={sys.version.split()[0]}")
    print(f"probe root={root}\n")
    probe_regular_and_directory(root / "p01")
    probe_windows_only_attributes(root / "p02")
    probe_posix_overrides_readonly(root / "p03")
    probe_special_bits(root / "p04")
    probe_directory_order(root / "p05")
    probe_preexisting_directory(root / "p06")
    probe_implicit_parents(root / "p07")
    probe_symlink(root / "p08")
    probe_factory(root / "p09")
    probe_junction(root / "p10")
    probe_type_confusion(root / "p11")
    probe_aliasing(root / "p12")
    probe_target_prefix(root / "p13")

    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        print("failed: " + ", ".join(failed))
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory for inspection")
    parser.add_argument("--root", type=pathlib.Path, help="use this directory instead of creating a temporary one")
    options = parser.parse_args()

    if options.root is not None:
        root = options.root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        temporary = False
    else:
        root = pathlib.Path(tempfile.mkdtemp(prefix="py7zr-perm-probe-"))
        temporary = True

    try:
        return run(root)
    finally:
        if temporary and not options.keep:
            shutil.rmtree(root, ignore_errors=True)
        elif temporary:
            print(f"kept probe root: {root}")


if __name__ == "__main__":
    sys.exit(main())
