"""Resolver interface and implementations for files, OSTree, and directory
artifacts."""

import hashlib
import locale
import logging
import os
import stat
from abc import ABC, abstractmethod
from functools import cmp_to_key
from itertools import combinations
from os.path import exists, isdir, isfile, join, normpath
from typing import NamedTuple, Optional, Tuple

from pathspec import GitIgnoreSpec

from in_toto.exceptions import PrefixError, StrictRecordingError

logger = logging.getLogger(__name__)

_HASH_ALGORITHM = "sha256"

RESOLVER_FOR_URI_SCHEME = {}


class ReadEvent(NamedTuple):
    """Information passed to a strict recording read hook.

    A read hook is a callable that is invoked at deterministic points while an
    artifact is read in strict mode. It is intended for tests that need to
    simulate concurrent replacement or modification between those points. It
    must not modify the file descriptor passed in ``fd``.

    Attributes:
      operation: One of ``"open"`` (file opened, before reading), ``"read"``
          (after a chunk was read), ``"before-verify"`` (all bytes read, before
          the final path and descriptor checks), ``"list"`` (directory entries
          snapshotted, before recording them), or ``"list-verify"`` (before a
          directory snapshot is re-checked).
      path: The path being recorded, as seen from the resolver invocation
          directory.
      fd: Open file descriptor for file operations, otherwise ``None``.
      bytes_read: Number of content bytes read so far for file operations.
      entries: Sorted entry names for directory operations, otherwise ``()``.
    """

    operation: str
    path: str
    fd: Optional[int] = None
    bytes_read: Optional[int] = None
    entries: Tuple[str, ...] = ()


def _call_read_hook(read_hook, operation, path, **kwargs):
    """Invoke optional read hook with a ``ReadEvent``."""
    if read_hook is not None:
        read_hook(ReadEvent(operation, path, **kwargs))


def _stat_identity(stat_result):
    """Return the filesystem identity tuple for a stat result."""
    return (stat_result.st_dev, stat_result.st_ino)


def _stat_signature(stat_result):
    """Return identity, type, size and timestamps used to detect changes.

    ``st_atime`` is intentionally not included, because reading a file updates
    it. The remaining values detect in-place writes and truncation that happen
    between two observations, provided the filesystem reports them.
    """
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat.S_IFMT(stat_result.st_mode),
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
    )


def _strict_error(path, reason, detail):
    """Build a ``StrictRecordingError`` with machine-readable metadata."""
    return StrictRecordingError(
        f"strict recording failed for '{path}' ({reason}): {detail}",
        path=path,
        reason=reason,
    )


def _verify_path_identity(path_for_messages, path, expected):
    """Fail if ``path`` no longer names the same file as ``expected``."""
    try:
        current = os.stat(path)
    except OSError as exc:
        raise _strict_error(
            path_for_messages,
            "path-vanished",
            f"path could not be stat'ed after opening it: {exc}",
        ) from exc

    if _stat_identity(current) != _stat_identity(expected):
        raise _strict_error(
            path_for_messages,
            "path-replaced",
            "path refers to a different file than the one that was opened",
        )


def _verify_fd_unchanged(path, fd, expected):
    """Fail if an open file descriptor no longer matches ``expected``."""
    try:
        current = os.fstat(fd)
    except OSError as exc:
        raise _strict_error(
            path,
            "descriptor-invalid",
            f"open file descriptor could not be stat'ed: {exc}",
        ) from exc

    if _stat_signature(current) != _stat_signature(expected):
        raise _strict_error(
            path,
            "file-changed",
            "file size, timestamps, or identity changed while it was open",
        )


def _read_file_strict(
    path, algo, normalize_line_endings, read_hook, path_for_messages=None
):
    """Hash ``path`` and fail on any observed change to path or content.

    The returned digest is computed exclusively from bytes read from the file
    descriptor that was opened for ``path``. The path is checked before and
    after reading, so a path that starts naming another file (even one with
    identical contents) is detected. The descriptor is checked in between read
    chunks, so truncation and in-place writes are detected when the filesystem
    reports them. An unobserved change after the final checks cannot be
    detected by reading a file.
    """
    if path_for_messages is None:
        path_for_messages = path

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)

    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _strict_error(
            path_for_messages, "open-failed", f"file could not be opened: {exc}"
        ) from exc

    try:
        try:
            stat_open = os.fstat(fd)
        except OSError as exc:
            raise _strict_error(
                path_for_messages,
                "descriptor-invalid",
                f"opened file descriptor could not be stat'ed: {exc}",
            ) from exc

        if not stat.S_ISREG(stat_open.st_mode):
            raise _strict_error(
                path_for_messages,
                "not-a-regular-file",
                "strict recording only supports regular files",
            )

        _verify_path_identity(path_for_messages, path, stat_open)
        _call_read_hook(
            read_hook, "open", path_for_messages, fd=fd, bytes_read=0
        )
        _verify_path_identity(path_for_messages, path, stat_open)
        _verify_fd_unchanged(path_for_messages, fd, stat_open)

        digest = hashlib.new(algo)
        bytes_read = 0

        while True:
            data = os.read(fd, 4096)
            if not data:
                break

            bytes_read += len(data)

            if normalize_line_endings:
                while data[-1:] == b"\r":
                    char = os.read(fd, 1)
                    if not char:
                        break

                    bytes_read += len(char)
                    data += char

                data = (
                    data
                    # First Windows
                    .replace(b"\r\n", b"\n")
                    # Then Mac
                    .replace(b"\r", b"\n")
                )

            digest.update(data)
            _call_read_hook(
                read_hook,
                "read",
                path_for_messages,
                fd=fd,
                bytes_read=bytes_read,
            )
            _verify_path_identity(path_for_messages, path, stat_open)
            _verify_fd_unchanged(path_for_messages, fd, stat_open)

        if bytes_read != stat_open.st_size:
            raise _strict_error(
                path_for_messages,
                "size-mismatch",
                f"read {bytes_read} bytes but the file was "
                f"{stat_open.st_size} bytes when opened",
            )

        _call_read_hook(
            read_hook,
            "before-verify",
            path_for_messages,
            fd=fd,
            bytes_read=bytes_read,
        )
        _verify_path_identity(path_for_messages, path, stat_open)
        _verify_fd_unchanged(path_for_messages, fd, stat_open)

        return digest.hexdigest()

    finally:
        os.close(fd)


class Resolver(ABC):
    """Resolver interface and factory."""

    @classmethod
    def for_uri(cls, uri):
        """Return registered resolver instance for passed URI."""
        scheme, match, _ = uri.partition(":")

        if not match or scheme not in RESOLVER_FOR_URI_SCHEME:
            scheme = FileResolver.SCHEME

        return RESOLVER_FOR_URI_SCHEME[scheme]

    @abstractmethod
    def hash_artifacts(self, uris):
        """Return hash dictionary for passed list of artifact URIs."""
        raise NotImplementedError


class FileResolver(Resolver):
    """File resolver implementation.

    Provides a ``hash_artifacts`` method to generate hashes for passed file
    paths. The resolver is configurable via its constructor.

    """

    SCHEME = "file"

    def __init__(
        self,
        exclude_patterns=None,
        base_path=None,
        follow_symlink_dirs=False,
        normalize_line_endings=False,
        lstrip_paths=None,
        strict=False,
        read_hook=None,
    ):
        if exclude_patterns is None:
            exclude_patterns = []

        if not lstrip_paths:
            lstrip_paths = []

        if base_path is not None and not isinstance(base_path, str):
            raise ValueError("'base_path' must be string")

        for name, val in [
            ("exclude_patterns", exclude_patterns),
            ("lstrip_paths", lstrip_paths),
        ]:
            if not isinstance(val, list) or not all(
                isinstance(i, str) for i in val
            ):
                raise ValueError(f"'{name}' must be list of strings")

        for a_, b_ in combinations(lstrip_paths, 2):
            if a_.startswith(b_) or b_.startswith(a_):
                raise PrefixError(
                    f"'{a_}' and '{b_}' triggered a left substring error"
                )

        # Compile gitignore-style patterns
        self._exclude_filter = GitIgnoreSpec.from_lines(
            "gitwildmatch", exclude_patterns
        )
        self._base_path = base_path
        self._follow_symlink_dirs = follow_symlink_dirs
        self._normalize_line_endings = normalize_line_endings
        self._lstrip_paths = lstrip_paths
        self._strict = strict
        self._read_hook = read_hook
        self._message_prefix = ""

    def _exclude(self, path):
        """Helper to check, if path matches pre-compiled exclude patterns."""
        return self._exclude_filter.match_file(path)

    def _message_path(self, path):
        """Return path as seen from the resolver invocation directory."""
        path = path.removeprefix("./")

        if self._message_prefix:
            if path == ".":
                return normpath(self._message_prefix)
            return normpath(join(self._message_prefix, path))

        return normpath(path)

    def _hash(self, path):
        """Helper to generate hash dictionary for path."""
        if self._strict:
            hexdigest = _read_file_strict(
                path,
                _HASH_ALGORITHM,
                self._normalize_line_endings,
                self._read_hook,
                path_for_messages=self._message_path(path),
            )
        else:
            hexdigest = _hash_file(
                path,
                _HASH_ALGORITHM,
                self._normalize_line_endings,
            )
        return {_HASH_ALGORITHM: hexdigest}

    def _mangle(self, path, existing_paths, scheme_prefix):
        """Helper for path mangling."""

        # Normalize slashes for cross-platform metadata consistency
        path = path.replace("\\", "/")

        # Left-strip names using configured path prefixes
        for lstrip_path in self._lstrip_paths:
            if path.startswith(lstrip_path):
                path = path[len(lstrip_path) :]
                break

        # Fail if left-stripping above results in duplicates
        if self._lstrip_paths and path in existing_paths:
            raise PrefixError(
                "Prefix selection has resulted in non unique dictionary key "
                f"'{path}'"
            )

        # Prepend passed scheme prefix
        return scheme_prefix + path

    def _strip_scheme_prefix(self, path):
        """Helper to strip file resolver scheme prefix from path."""

        prefix = self.SCHEME + ":"
        if path.startswith(prefix):
            path = path[len(prefix) :]
        else:
            prefix = ""

        return path, prefix

    def _walk_dir(self, path, hashes, prefix):
        """Record files below ``path``, snapshotting dirs in strict mode."""
        if not self._strict:
            for base, dirs, names in os.walk(
                path, followlinks=self._follow_symlink_dirs
            ):
                # Filter directories to avoid unnecessary recursion below
                # NOTE: Normalize to filter on directory paths without
                # their dot-slash prefix, if path was dot.
                dirs[:] = [
                    dirname
                    for dirname in dirs
                    if not self._exclude(normpath(join(base, dirname)))
                ]

                for filename in names:
                    # NOTE: Normalize to filter on and return file paths
                    # without their dot-slash prefix, if path was dot.
                    filepath = normpath(join(base, filename))

                    if self._exclude(filepath):
                        continue

                    if not isfile(filepath):
                        logger.info(
                            "File '%s' appears to be a broken symlink. "
                            "Skipping...",
                            filepath,
                        )
                        continue

                    name = self._mangle(filepath, hashes, prefix)
                    hashes[name] = self._hash(filepath)

            return

        self._walk_dir_strict(path, hashes, prefix)

    def _list_dir_strict(self, dirpath):
        """Return identity and recordable entries for a directory.

        The returned entries map entry names to identity, type, size and
        mtime tuples. Size and mtime detect in-place changes that happen after
        an entry was read. Excluded entries are omitted because they are not
        part of the recorded tree.
        """
        try:
            dir_stat = os.stat(dirpath)
        except OSError as exc:
            raise _strict_error(
                self._message_path(dirpath),
                "directory-vanished",
                f"directory could not be stat'ed: {exc}",
            ) from exc

        if not stat.S_ISDIR(dir_stat.st_mode):
            raise _strict_error(
                self._message_path(dirpath),
                "not-a-directory",
                "path is no longer a directory",
            )

        entries = {}
        try:
            with os.scandir(dirpath) as iterator:
                for entry in iterator:
                    entry_path = normpath(join(dirpath, entry.name))
                    if self._exclude(entry_path):
                        continue

                    entry_stat = entry.stat(follow_symlinks=False)
                    entries[entry.name] = (
                        entry_stat.st_dev,
                        entry_stat.st_ino,
                        stat.S_IFMT(entry_stat.st_mode),
                        entry_stat.st_size,
                        entry_stat.st_mtime_ns,
                    )
        except OSError as exc:
            raise _strict_error(
                self._message_path(dirpath),
                "directory-unreadable",
                f"directory entries could not be listed: {exc}",
            ) from exc

        _call_read_hook(
            self._read_hook,
            "list",
            self._message_path(dirpath),
            entries=tuple(sorted(entries)),
        )
        return dir_stat, entries

    def _verify_dir_strict(self, dirpath, dir_stat, entries):
        """Fail if directory identity or recordable entries changed."""
        _call_read_hook(
            self._read_hook,
            "list-verify",
            self._message_path(dirpath),
            entries=tuple(sorted(entries)),
        )
        current_stat, current_entries = self._list_dir_strict_entries(dirpath)

        if _stat_identity(current_stat) != _stat_identity(dir_stat):
            raise _strict_error(
                self._message_path(dirpath),
                "directory-replaced",
                "directory refers to a different filesystem object",
            )
        if current_entries != entries:
            added = sorted(set(current_entries) - set(entries))
            removed = sorted(set(entries) - set(current_entries))
            raised = sorted(
                name
                for name in set(entries) & set(current_entries)
                if entries[name] != current_entries[name]
            )
            detail = (
                f"entry additions={added}, removals={removed}, "
                f"identity/type changes={raised}"
            )
            raise _strict_error(
                self._message_path(dirpath),
                "directory-entries-changed",
                detail,
            )

    def _list_dir_strict_entries(self, dirpath):
        """List entries without invoking the read hook."""
        entries = {}
        try:
            with os.scandir(dirpath) as iterator:
                for entry in iterator:
                    entry_path = normpath(join(dirpath, entry.name))
                    if self._exclude(entry_path):
                        continue

                    entry_stat = entry.stat(follow_symlinks=False)
                    entries[entry.name] = (
                        entry_stat.st_dev,
                        entry_stat.st_ino,
                        stat.S_IFMT(entry_stat.st_mode),
                        entry_stat.st_size,
                        entry_stat.st_mtime_ns,
                    )

            return os.stat(dirpath), entries

        except OSError as exc:
            raise _strict_error(
                self._message_path(dirpath),
                "directory-vanished",
                f"directory changed or could not be read during "
                f"verification: {exc}",
            ) from exc

    def _walk_dir_strict(self, path, hashes, prefix):
        """Recursively record directory tree with directory snapshots."""
        dir_stat, entries = self._list_dir_strict(path)

        try:
            for entry_name in sorted(entries):
                filepath = normpath(join(path, entry_name))

                try:
                    entry_is_dir = isdir(filepath)
                    entry_is_symlink = os.path.islink(filepath)

                except OSError as exc:
                    raise _strict_error(
                        self._message_path(filepath),
                        "entry-unreadable",
                        f"directory entry could not be inspected: {exc}",
                    ) from exc

                if entry_is_dir:
                    if not self._follow_symlink_dirs and entry_is_symlink:
                        continue

                    self._walk_dir_strict(filepath, hashes, prefix)
                    continue

                if not isfile(filepath):
                    # A broken symlink was stable at snapshot time and is
                    # stable when inspected here. It is skipped, as in
                    # non-strict mode.
                    logger.info(
                        "File '%s' appears to be a broken symlink. Skipping...",
                        filepath,
                    )
                    continue

                name = self._mangle(filepath, hashes, prefix)
                hashes[name] = self._hash(filepath)

        except StrictRecordingError:
            raise
        except OSError as exc:
            raise _strict_error(
                self._message_path(path),
                "directory-changed",
                f"directory changed while its entries were recorded: {exc}",
            ) from exc

        self._verify_dir_strict(path, dir_stat, entries)

    def hash_artifacts(self, uris):  # noqa: C901
        hashes = {}

        if self._base_path:
            original_cwd = os.getcwd()
            os.chdir(self._base_path)

        try:
            for path in uris:
                # Remove scheme prefix, but preserve to re-add later (see
                # _mangle)
                path, prefix = self._strip_scheme_prefix(path)  # noqa: PLW2901

                # Normalize URI before filtering and returning them
                # FIXME: Is this expected behavior? Does this make exclude
                # patterns with slashes platform-dependent? Check how
                # 'gitwildmatch' treats dots and slashes!
                path = normpath(path)  # noqa: PLW2901

                if self._exclude(path):
                    continue

                if not exists(path):
                    if self._strict:
                        # Non-strict mode silently skips missing paths. In
                        # strict mode an explicitly requested artifact that
                        # cannot be observed must not be omitted.
                        raise _strict_error(
                            path,
                            "path-missing",
                            "explicitly passed artifact does not exist",
                        )

                    logger.info("path: %s does not exist, skipping..", path)
                    continue

                if isfile(path):
                    name = self._mangle(path, hashes, prefix)
                    hashes[name] = self._hash(path)

                elif isdir(path):
                    self._walk_dir(path, hashes, prefix)

                elif self._strict:
                    raise _strict_error(
                        path,
                        "not-a-regular-file",
                        "explicitly passed artifact is neither a regular "
                        "file nor a directory",
                    )

        finally:
            # Change back to original current working dir
            if self._base_path:
                os.chdir(original_cwd)

        return hashes


class OSTreeResolver(Resolver):
    """Resolver for OSTree repositories."""

    SCHEME = "ostree"

    # defining this separately as it should be pinned to OSTree's default
    # rather than in-toto's
    _HASH_ALGORITHM = "sha256"

    def __init__(self, base_path=None):
        self._base_path = base_path

    def _strip_scheme_prefix(self, path):
        """Helper to strip OSTree resolver scheme prefix from path."""

        return path[len(self.SCHEME + ":") :]

    def _add_scheme_prefix(self, path):
        """Helper to add scheme back after recording the hash."""

        return f"{self.SCHEME}:{path}"

    def _hash(self, path):
        """Helper to hash OSTree commits."""

        ref_path = os.path.join("refs", "heads", path)

        with open(ref_path) as ref:  # noqa: PLW1514, RUF100
            ref_contents = ref.read()
        ref_contents = ref_contents.strip("\n")

        object_path = os.path.join(
            "objects", ref_contents[:2], f"{ref_contents[2:]}.commit"
        )

        hexdigest = _hash_file(object_path, self._HASH_ALGORITHM, False)

        return {self._HASH_ALGORITHM: hexdigest}

    def hash_artifacts(self, uris):
        hashes = {}

        if self._base_path:
            original_cwd = os.getcwd()
            os.chdir(self._base_path)

        for path in uris:
            # Remove scheme prefix, but preserver to re-add later
            path = self._strip_scheme_prefix(path)  # noqa: PLW2901
            hashes[self._add_scheme_prefix(path)] = self._hash(path)

        # Change back to original current working dir
        if self._base_path:
            os.chdir(original_cwd)

        return hashes


class DirectoryResolver(Resolver):
    """Directory resolver implementation.

    Implementation of the following shell command for some directory URI:

    find . -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum | sha256sum |
        cut -f1 -d' '

    `exclude_patterns` are not applied on the directory paths passed to
    `hash_artifacts`, but on the files inside the directory. Similarly,
    `follow_symlink_dirs` and `normalize_line_endings` are used on
    subdirectories and files inside the directories passed to `hash_artifacts`.

    """

    SCHEME = "dir"

    def __init__(
        self,
        exclude_patterns=None,
        follow_symlink_dirs=False,
        normalize_line_endings=False,
        lstrip_paths=None,
        strict=False,
        read_hook=None,
    ):
        if not exclude_patterns:
            exclude_patterns = []

        if not lstrip_paths:
            lstrip_paths = []

        self._exclude_patterns = exclude_patterns
        self._follow_symlink_dirs = follow_symlink_dirs
        self._normalize_line_endings = normalize_line_endings
        self._lstrip_paths = lstrip_paths
        self._strict = strict
        self._read_hook = read_hook

    def _strip_scheme_prefix(self, path):
        """Helper to strip file resolver scheme prefix from path."""

        return path[len(self.SCHEME + ":") :]

    def _mangle(self, path, existing_paths):
        """Helper for path mangling."""

        # Normalize slashes for cross-platform metadata consistency
        path = path.replace("\\", "/")

        # Left-strip names using configured path prefixes
        for lstrip_path in self._lstrip_paths:
            if path.startswith(lstrip_path):
                path = path[len(lstrip_path) :]
                break

        # Prepend passed scheme prefix
        # We do this first because the entries in existing_paths have the scheme
        # affixed already.
        path = self.SCHEME + ":" + path

        # Fail if left-stripping above results in duplicates
        if self._lstrip_paths and path in existing_paths:
            raise PrefixError(
                "Prefix selection has resulted in non unique dictionary key "
                f"'{path}'"
            )

        return path

    def _hash(self, file_hashes):
        """Helper to correctly sort and hash every element."""

        text_repr = ""
        keys = list(file_hashes.keys())
        if keys:
            locale.setlocale(locale.LC_ALL, "C")
            keys.sort(key=cmp_to_key(locale.strcoll))

            text_repr = "\n".join(
                [f"{file_hashes[k][_HASH_ALGORITHM]}  {k}" for k in keys]
            )
            text_repr += "\n"  # trailing new line

        digest_obj = hashlib.new(_HASH_ALGORITHM)
        digest_obj.update(text_repr.encode("utf-8"))

        return {_HASH_ALGORITHM: digest_obj.hexdigest()}

    def hash_artifacts(self, uris):
        hashes = {}

        for path in uris:
            path = self._strip_scheme_prefix(path)  # noqa: PLW2901

            try:
                root_stat = os.stat(path)
            except OSError as exc:
                raise ValueError(f"path '{path}' is not a directory") from exc

            if not stat.S_ISDIR(root_stat.st_mode):
                raise ValueError(f"path '{path}' is not a directory")

            file_resolver = FileResolver(
                base_path=path,
                exclude_patterns=self._exclude_patterns,
                follow_symlink_dirs=self._follow_symlink_dirs,
                normalize_line_endings=self._normalize_line_endings,
                strict=self._strict,
                read_hook=self._read_hook,
            )
            # Records are relative to the directory itself. Use the passed
            # path as prefix in strict messages, so they are meaningful
            # outside the temporary working directory.
            file_resolver._message_prefix = path  # noqa: SLF001

            file_hashes = file_resolver.hash_artifacts(["."])
            if not file_hashes:
                logger.info(
                    "path: %s has no files, recording empty dir...", path
                )

            if self._strict:
                try:
                    current_stat = os.stat(path)
                except OSError as exc:
                    raise _strict_error(
                        path,
                        "directory-vanished",
                        f"directory could not be stat'ed after recording: "
                        f"{exc}",
                    ) from exc

                if _stat_identity(current_stat) != _stat_identity(root_stat):
                    raise _strict_error(
                        path,
                        "directory-replaced",
                        "directory path refers to a different filesystem "
                        "object after its contents were recorded",
                    )

            name = self._mangle(path, hashes)
            hashes[name] = self._hash(file_hashes)

        return hashes


def _hash_file(path, algo, normalize_line_endings):
    """Returns hashed file."""

    digest = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            # Chunk size is taken from the previously used and now deprecated
            # `securesystemslib.hash.digest_fileobject`.
            data = f.read(4096)
            if not data:
                break

            if normalize_line_endings:
                while data[-1:] == b"\r":
                    c = f.read(1)
                    if not c:
                        break

                    data += c

                data = (
                    data
                    # First Windows
                    .replace(b"\r\n", b"\n")
                    # Then Mac
                    .replace(b"\r", b"\n")
                )

            digest.update(data)

    return digest.hexdigest()
