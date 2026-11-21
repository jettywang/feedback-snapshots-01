#!/usr/bin/env python
"""Materialise an archive with a predictable permission policy.

py7zr restores modes verbatim from the archive.  For a managed recovery
service that is not a safe default: an archive can carry setuid bits,
world-writable directories or a directory mode that makes later members
unreadable.  This example shows the three-phase pattern that keeps the
result a pure function of the policy, not of archive ordering:

1. create the complete directory skeleton with a restrictive mode before
   extraction, so py7zr never applies an archive directory mode;
2. extract with a known umask into that skeleton;
3. walk the result once and apply the site policy bottom-up, never
   following links.

Run from the repository root::

    .venv/bin/python utils/restore_policy_example.py --keep

The final block prints the exact modes and exits non-zero if they differ
from the policy.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import stat
import sys
import tempfile

import py7zr
from py7zr.member import FILE_ATTRIBUTE_UNIX_EXTENSION

UX = FILE_ATTRIBUTE_UNIX_EXTENSION
WIN_ARCHIVE = getattr(stat, "FILE_ATTRIBUTE_ARCHIVE", 0x20)
WIN_DIRECTORY = getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)

# Site policy: every value below is what the service promises to produce.
DIR_MODE = 0o750
DATA_MODE = 0o640
EXEC_MODE = 0o750
EXECUTABLE_PREFIXES = ("bin/", "sbin/", "usr/bin/", "usr/sbin/")
FORBIDDEN_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | stat.S_IWOTH | stat.S_IROTH | stat.S_IXOTH
ALLOWED_UNIX_TYPES = {stat.S_IFREG}


def build_sample_archive(target: pathlib.Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    entries = [
        ("data/secret", stat.S_IFREG | 0o600, b"secret"),
        ("data/world", stat.S_IFREG | 0o666, b"world"),
        ("bin/tool", stat.S_IFREG | 0o4755, b"#!/bin/sh\n"),
        ("locked", stat.S_IFREG | 0o000, b"locked"),
        ("reports", stat.S_IFDIR | 0o777, b""),
        ("reports/q1.txt", stat.S_IFREG | 0o644, b"q1"),
        ("empty", stat.S_IFDIR | 0o000, b""),
        ("empty/later.txt", stat.S_IFREG | 0o644, b"later"),
    ]
    with py7zr.SevenZipFile(target, "w") as archive:
        for name, mode, payload in entries:
            archive.writestr(payload, name)
            info = archive.files.files_list[-1]
            win = WIN_DIRECTORY if stat.S_ISDIR(mode) else WIN_ARCHIVE
            info["attributes"] = win | UX | (mode << 16)
        # A symlink member is stored as its target path and has no restorable mode.
        archive.writestr(b"data/secret", "data/link")
        info = archive.files.files_list[-1]
        info["attributes"] = WIN_ARCHIVE | UX | ((stat.S_IFLNK | 0o777) << 16)


def archive_directories(archive_path: pathlib.Path) -> list[str]:
    """Return every directory the archive implies, explicit or implicit."""
    dirs: set[pathlib.PurePosixPath] = set()
    with py7zr.SevenZipFile(archive_path, "r") as archive:
        for member in archive.files:
            path = pathlib.PurePosixPath(member.filename)
            if member.st_fmt == stat.S_IFDIR:
                dirs.add(path)
            for parent in path.parents:
                if str(parent) != ".":
                    dirs.add(parent)
    return sorted(str(path) for path in dirs)


def build_skeleton(dest: pathlib.Path, directories: list[str]) -> None:
    dest.mkdir(parents=True, mode=0o700)
    for name in directories:
        path = dest / name
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)


def classify(dest: pathlib.Path) -> tuple[list[pathlib.Path], list[pathlib.Path], list[tuple[pathlib.Path, str]]]:
    files: list[pathlib.Path] = []
    directories: list[pathlib.Path] = []
    links: list[tuple[pathlib.Path, str]] = []
    for path in dest.rglob("*"):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            links.append((path, os.readlink(path)))
        elif stat.S_ISDIR(info.st_mode):
            directories.append(path)
        else:
            files.append(path)
    return files, directories, links


def policy_mode(path: pathlib.Path, relative: str, is_directory: bool) -> int:
    if is_directory:
        return DIR_MODE
    if relative.startswith(EXECUTABLE_PREFIXES):
        return EXEC_MODE
    return DATA_MODE


def apply_policy(dest: pathlib.Path, links: list[tuple[pathlib.Path, str]]) -> None:
    files, directories, _ = classify(dest)
    # Links are removed, never chmod'ed or followed.
    for path, _target in links:
        path.unlink()
    # Deepest first: a parent is only locked down after its children are final.
    for path in sorted(files, key=lambda p: len(p.parts), reverse=True):
        relative = path.relative_to(dest).as_posix()
        mode = policy_mode(path, relative, is_directory=False)
        os.chmod(path, mode, follow_symlinks=False)
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        relative = path.relative_to(dest).as_posix()
        os.chmod(path, policy_mode(path, relative, is_directory=True), follow_symlinks=False)


def verify(dest: pathlib.Path) -> list[str]:
    problems: list[str] = []
    for path in sorted(dest.rglob("*")):
        info = path.lstat()
        relative = path.relative_to(dest).as_posix()
        if stat.S_ISLNK(info.st_mode):
            problems.append(f"{relative}: link survived policy")
            continue
        mode = stat.S_IMODE(info.st_mode)
        expected = policy_mode(path, relative, stat.S_ISDIR(info.st_mode))
        if mode != expected:
            problems.append(f"{relative}: {oct(mode)} != {oct(expected)}")
        if mode & FORBIDDEN_BITS:
            problems.append(f"{relative}: forbidden bits in {oct(mode)}")
    return problems


def run(root: pathlib.Path) -> int:
    archive_path = root / "incoming.7z"
    build_sample_archive(archive_path)
    directories = archive_directories(archive_path)
    print("archive-implied directories:", directories)

    dest = root / "restore"
    previous = os.umask(0o077)
    try:
        build_skeleton(dest, directories)
        with py7zr.SevenZipFile(archive_path, "r") as archive:
            archive.extractall(dest)
    finally:
        os.umask(previous)

    files, dirs, links = classify(dest)
    print(f"extracted: {len(files)} files, {len(dirs)} dirs, {len(links)} links")
    apply_policy(dest, links)

    print("\nfinal tree:")
    for path in sorted(dest.rglob("*")):
        info = path.lstat()
        kind = "link" if stat.S_ISLNK(info.st_mode) else ("dir" if stat.S_ISDIR(info.st_mode) else "file")
        print(f"  {path.relative_to(dest).as_posix():<22} {kind:<4} {oct(stat.S_IMODE(info.st_mode))}")

    problems = verify(dest)
    if problems:
        print("\npolicy violations:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("\npolicy satisfied: directories 0750, executables 0750, data 0640, no links, no special bits")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory")
    parser.add_argument("--root", type=pathlib.Path, help="use this directory instead of a temporary one")
    options = parser.parse_args()
    if options.root is not None:
        root = options.root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        temporary = False
    else:
        root = pathlib.Path(tempfile.mkdtemp(prefix="py7zr-restore-policy-"))
        temporary = True
    try:
        return run(root)
    finally:
        if temporary and not options.keep:
            shutil.rmtree(root, ignore_errors=True)
        elif temporary:
            print(f"kept example root: {root}")


if __name__ == "__main__":
    sys.exit(main())
