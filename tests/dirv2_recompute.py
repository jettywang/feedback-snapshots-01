#!/usr/bin/env python3
# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Independent recomputation reference for the ``dirv2:`` directory digest.

This script is deliberately self-contained: it only uses the Python standard
library and never imports ``in_toto``. Its sole purpose is to let a verifier
recompute a ``dirv2`` digest from an on-disk directory using an independent
implementation of the format specification, and compare it against the digest
recorded in in-toto link metadata.

Canonical message format (byte-oriented, no locale dependency)::

    dirv2 0x1e
    <name-utf8> 0x1f <type> 0x1f <digest> 0x1e
    <name-utf8> 0x1f <type> 0x1f <digest> 0x1e
    ...

* Records are sorted byte-wise by the UTF-8 encoded relative entry name.
* ``type`` is ``f`` (regular file), ``d`` (directory) or ``s`` (symlink).
* ``digest`` is the file content sha256 (``f``), empty (``d``) or the sha256
  of the symlink target as UTF-8 (``s``).
* The directory digest is the sha256 of the whole message.

An empty directory hashes the preamble ``b"dirv2\\x1e"`` by itself.

Usage::

    python dirv2_recompute.py PATH [PATH ...]
    python dirv2_recompute.py --exclude PATTERN [--exclude PATTERN ...] PATH
    python dirv2_recompute.py --follow-symlink-dirs PATH
    python dirv2_recompute.py --self-test

The script prints one ``<path>  sha256:<digest>`` line per directory.
``--exclude`` patterns are matched relative to each directory and use a
stdlib-only approximation of gitignore matching; for exact gitignore semantics
rely on the in-toto resolver itself.
"""

import argparse
import fnmatch
import hashlib
import os
import sys
import tempfile

VERSION = b"dirv2"
RECORD_SEPARATOR = b"\x1e"
FIELD_SEPARATOR = b"\x1f"
TYPE_FILE = b"f"
TYPE_DIR = b"d"
TYPE_SYMLINK = b"s"


def _is_excluded(rel_path, patterns):
    """Match a directory-relative path against gitignore-style patterns.

    This is a small, standard-library-only approximation (``fnmatch``) used
    only by the standalone reference. The authoritative gitignore matching in
    in-toto itself is provided by ``pathspec``.
    """
    normalized = rel_path.replace(os.sep, "/")
    return any(
        fnmatch.fnmatch(normalized, pattern)
        or fnmatch.fnmatch(os.path.basename(normalized), pattern)
        for pattern in patterns
    )


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest().encode("ascii")


def _sha256_symlink(path):
    target = os.readlink(path)
    return hashlib.sha256(target.encode("utf-8")).hexdigest().encode("ascii")


def _iter_entries(root, follow_symlink_dirs=False, exclude_patterns=None):
    """Yield (relative_name, type_byte, digest_byte) tuples for root."""
    exclude_patterns = exclude_patterns or []
    for base, dirs, names in os.walk(root, followlinks=follow_symlink_dirs):
        kept_dirs = []
        for dirname in dirs:
            dirpath = os.path.normpath(os.path.join(base, dirname))
            rel_dir = os.path.relpath(dirpath, root)
            if _is_excluded(rel_dir, exclude_patterns):
                continue
            if os.path.islink(dirpath):
                if follow_symlink_dirs:
                    kept_dirs.append(dirname)
                else:
                    yield rel_dir, TYPE_SYMLINK, _sha256_symlink(dirpath)
            else:
                yield rel_dir, TYPE_DIR, b""
                kept_dirs.append(dirname)
        dirs[:] = kept_dirs

        for filename in names:
            filepath = os.path.normpath(os.path.join(base, filename))
            rel_name = os.path.relpath(filepath, root)
            if _is_excluded(rel_name, exclude_patterns):
                continue

            if os.path.islink(filepath):
                if not os.path.exists(filepath):
                    # Broken symlinks are skipped.
                    continue
                if os.path.isdir(filepath):
                    continue
                yield rel_name, TYPE_SYMLINK, _sha256_symlink(filepath)
            elif os.path.isfile(filepath):
                yield rel_name, TYPE_FILE, _sha256_file(filepath)


def dirv2_digest(root, follow_symlink_dirs=False, exclude_patterns=None):
    """Return the dirv2 sha256 hexdigest for ``root``."""
    if not os.path.isdir(root):
        raise ValueError(f"path '{root}' is not a directory")

    records = []
    for rel_name, entry_type, digest in _iter_entries(
        root, follow_symlink_dirs, exclude_patterns
    ):
        name_bytes = rel_name.replace("\\", "/").encode("utf-8")
        records.append(
            FIELD_SEPARATOR.join([name_bytes, entry_type, digest])
            + RECORD_SEPARATOR
        )

    records.sort()
    message = VERSION + RECORD_SEPARATOR + b"".join(records)
    return hashlib.sha256(message).hexdigest()


def _self_test():
    """Exercise newline names, empty dirs, symlinks and structure ordering."""
    with tempfile.TemporaryDirectory() as tmp:
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        assert dirv2_digest(empty) == hashlib.sha256(
            b"dirv2\x1e"
        ).hexdigest()

        tree = os.path.join(tmp, "tree")
        os.makedirs(os.path.join(tree, "sub"))
        with open(
            os.path.join(tree, "li\nne-ä.txt"), "w", encoding="utf-8"
        ) as handle:
            handle.write("x")
        with open(os.path.join(tree, "sub", "b.txt"), "w") as handle:
            handle.write("y")
        os.symlink("sub/b.txt", os.path.join(tree, "link.txt"))
        os.makedirs(os.path.join(tree, "emptydir"))

        first = dirv2_digest(tree)
        # Deterministic across repeated runs.
        assert first == dirv2_digest(tree)
        # Adding an empty directory changes the structural digest.
        os.makedirs(os.path.join(tree, "another"))
        assert first != dirv2_digest(tree)

    print("dirv2 self-test OK")


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        _self_test()
        return 0

    parser = argparse.ArgumentParser(
        description="Recompute dirv2 directory digests (stdlib only)."
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="gitignore-style pattern applied relative to each directory",
    )
    parser.add_argument(
        "--follow-symlink-dirs",
        action="store_true",
        help="enumerate the targets of symlinked directories",
    )
    parser.add_argument("paths", nargs="*", help="directories to hash")
    args = parser.parse_args(argv[1:])

    if not args.paths:
        parser.print_help()
        return 2

    for root in args.paths:
        digest = dirv2_digest(
            root,
            follow_symlink_dirs=args.follow_symlink_dirs,
            exclude_patterns=args.exclude,
        )
        print(f"{root}  sha256:{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
