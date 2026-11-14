"""Resolver interface and implementations for files, OSTree, and directory
artifacts."""

import hashlib
import locale
import logging
import os
from abc import ABC, abstractmethod
from functools import cmp_to_key
from itertools import combinations
from os.path import exists, isdir, isfile, join, normpath

from pathspec import GitIgnoreSpec

from in_toto.exceptions import PrefixError

logger = logging.getLogger(__name__)

_HASH_ALGORITHM = "sha256"

RESOLVER_FOR_URI_SCHEME = {}

# Marker bytes and type identifiers used by the versioned directory digest
# (``DirV2Resolver``). They are fixed byte values so the format never depends
# on the process locale, platform line endings or a text codec's newline
# handling.
_DIRV2_VERSION = b"dirv2"
_DIRV2_RECORD_SEPARATOR = b"\x1e"
_DIRV2_FIELD_SEPARATOR = b"\x1f"
_DIRV2_TYPE_FILE = b"f"
_DIRV2_TYPE_DIR = b"d"
_DIRV2_TYPE_SYMLINK = b"s"


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

    def _exclude(self, path):
        """Helper to check, if path matches pre-compiled exclude patterns."""
        return self._exclude_filter.match_file(path)

    def _hash(self, path):
        """Helper to generate hash dictionary for path."""
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

    def hash_artifacts(self, uris):  # noqa: C901
        hashes = {}

        if self._base_path:
            original_cwd = os.getcwd()
            os.chdir(self._base_path)

        for path in uris:
            # Remove scheme prefix, but preserver to re-add later (see _mangle)
            path, prefix = self._strip_scheme_prefix(path)  # noqa: PLW2901

            # Normalize URI before filtering and returning them
            # FIXME: Is this expected behavior? Does this make exclude patterns
            # with slashes platform-dependent? Check how 'gitwildmatch' treats
            # dots and slashes!
            path = normpath(path)  # noqa: PLW2901

            if self._exclude(path):
                continue

            if not exists(path):
                logger.info("path: %s does not exist, skipping..", path)
                continue

            if isfile(path):
                name = self._mangle(path, hashes, prefix)
                hashes[name] = self._hash(path)

            if isdir(path):
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
    ):
        if not exclude_patterns:
            exclude_patterns = []

        if not lstrip_paths:
            lstrip_paths = []

        self._exclude_patterns = exclude_patterns
        self._follow_symlink_dirs = follow_symlink_dirs
        self._normalize_line_endings = normalize_line_endings
        self._lstrip_paths = lstrip_paths

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

            if not os.path.isdir(path):
                raise ValueError(f"path '{path}' is not a directory")

            file_resolver = FileResolver(
                base_path=path,
                exclude_patterns=self._exclude_patterns,
                follow_symlink_dirs=self._follow_symlink_dirs,
                normalize_line_endings=self._normalize_line_endings,
            )

            file_hashes = file_resolver.hash_artifacts(["."])
            if not file_hashes:
                logger.info(
                    "path: %s has no files, recording empty dir...", path
                )

            name = self._mangle(path, hashes)
            hashes[name] = self._hash(file_hashes)

        return hashes


class DirV2Resolver(Resolver):
    """Versioned directory resolver (``dirv2:`` scheme).

    This is an independent, explicitly versioned replacement for the legacy
    :class:`DirectoryResolver` (``dir:`` scheme). The legacy scheme and its
    digest values are intentionally left unchanged. A digest computed with one
    scheme MUST NOT be treated as equivalent to a digest with the same artifact
    name from the other scheme, which is guaranteed by both the distinct URI
    scheme and a distinct, unambiguous serialization.

    Canonical serialization (all bytes, no locale or text-line dependencies):

    1. The message starts with the fixed version marker ``dirv2`` followed by
       the record separator byte ``0x1e``.
    2. Every traversed entry (files, directories and symlinks) yields one
       record. Records are sorted by the entry name's UTF-8 bytes, i.e. a plain
       byte-wise ordering independent of :func:`locale.strcoll` or ``LC_ALL``.
    3. Each record joins three fields with the field separator byte ``0x1f``::

           <entry-name-utf8> 0x1f <type> 0x1f <digest>

       followed by the record separator byte ``0x1e``.

       * ``entry-name``: the path relative to the hashed directory, using
         forward slashes (backslashes are normalized on Windows). Names are
         encoded as UTF-8 and may contain arbitrary bytes, including newlines
         and non-ASCII characters; the control-byte separators make embedded
         newlines unambiguous.
       * ``type``: one of ``f`` (regular file), ``d`` (directory) or
         ``s`` (symbolic link). Explicit types let distinct structures (e.g. an
         empty subdirectory or a file/directory type swap) produce different
         digests even when the file contents are identical.
       * ``digest``:
           - regular file: the sha256 of the file content, honoring
             ``normalize_line_endings``;
           - directory: the empty string (its presence and type are the
             relevant information);
           - symbolic link: the sha256 of the link target string encoded as
             UTF-8.
    4. The sha256 of the complete message is the directory digest.

    An empty directory therefore hashes the fixed preamble
    ``b"dirv2\\x1e"`` rather than the empty string, so it can never be confused
    with the legacy empty-directory digest.

    Semantics shared with the legacy resolver:

    * ``exclude_patterns`` are gitignore-style and applied to the entries
      *inside* each directory, not to the directory URI itself. Excluding a
      directory excludes the directory entry and everything beneath it.
    * ``follow_symlink_dirs`` only controls whether symlinked directories are
      traversed. Symlinked files are always hashed. A symlinked directory is
      recorded as a single ``s`` record when it is not followed, and its target
      tree is enumerated when it is followed.
    * broken symlinks are skipped (they cannot be read), matching the file
      resolver behavior.
    * ``lstrip_paths`` only affect the artifact name stored in the result
      dictionary, never the digest.
    """

    SCHEME = "dirv2"

    def __init__(
        self,
        exclude_patterns=None,
        follow_symlink_dirs=False,
        normalize_line_endings=False,
        lstrip_paths=None,
    ):
        if not exclude_patterns:
            exclude_patterns = []

        if not lstrip_paths:
            lstrip_paths = []

        self._exclude_patterns = exclude_patterns
        self._follow_symlink_dirs = follow_symlink_dirs
        self._normalize_line_endings = normalize_line_endings
        self._lstrip_paths = lstrip_paths
        self._exclude_filter = GitIgnoreSpec.from_lines(
            "gitwildmatch", exclude_patterns
        )

    def _strip_scheme_prefix(self, path):
        """Helper to strip the dirv2 resolver scheme prefix from a path."""

        return path[len(self.SCHEME + ":") :]

    def _exclude(self, path):
        """Helper to check if a path matches pre-compiled exclude patterns."""
        return self._exclude_filter.match_file(path)

    def _mangle(self, path, existing_paths):
        """Helper for path mangling."""

        # Normalize slashes for cross-platform metadata consistency
        path = path.replace("\\", "/")

        # Left-strip names using configured path prefixes
        for lstrip_path in self._lstrip_paths:
            if path.startswith(lstrip_path):
                path = path[len(lstrip_path) :]
                break

        # Prepend the scheme prefix first because entries in existing_paths
        # already carry the scheme prefix.
        path = self.SCHEME + ":" + path

        # Fail if left-stripping above results in duplicates
        if self._lstrip_paths and path in existing_paths:
            raise PrefixError(
                "Prefix selection has resulted in non unique dictionary key "
                f"'{path}'"
            )

        return path

    def _iter_entries(self, root):
        """Yield ``(relative_name, entry_type, digest)`` tuples for ``root``.

        ``relative_name`` uses the directory's own separator and is converted
        to forward slashes by the caller when serializing.
        """
        for base, dirs, names in os.walk(
            root, followlinks=self._follow_symlink_dirs
        ):
            # Filter directories in-place to prune excluded subtrees and to
            # decide how symlinked directories should be represented.
            kept_dirs = []
            for dirname in dirs:
                dirpath = normpath(join(base, dirname))
                rel_dir = os.path.relpath(dirpath, root)
                # Exclude patterns are matched against the path relative to
                # the hashed directory, as in the legacy directory resolver.
                if self._exclude(rel_dir):
                    continue

                if os.path.islink(dirpath):
                    if self._follow_symlink_dirs:
                        # os.walk traverses the target; enumerate its contents
                        # under the link's name instead of recording the link.
                        kept_dirs.append(dirname)
                    else:
                        # Record the link itself and do not descend into it.
                        yield (
                            rel_dir,
                            _DIRV2_TYPE_SYMLINK,
                            self._hash_symlink(dirpath),
                        )
                else:
                    yield rel_dir, _DIRV2_TYPE_DIR, b""
                    kept_dirs.append(dirname)
            dirs[:] = kept_dirs

            for filename in names:
                filepath = normpath(join(base, filename))
                rel_name = os.path.relpath(filepath, root)
                if self._exclude(rel_name):
                    continue

                if os.path.islink(filepath):
                    if not exists(filepath):
                        # Broken symlinks cannot be read and are skipped,
                        # matching the file resolver behavior.
                        logger.info(
                            "File '%s' appears to be a broken symlink. "
                            "Skipping...",
                            filepath,
                        )
                        continue
                    # Symlinked files (and links to non-directories) are always
                    # recorded regardless of follow_symlink_dirs. A link that
                    # points to a directory is handled above.
                    if os.path.isdir(filepath):
                        continue
                    yield (
                        rel_name,
                        _DIRV2_TYPE_SYMLINK,
                        self._hash_symlink(filepath),
                    )
                elif isfile(filepath):
                    hexdigest = _hash_file(
                        filepath,
                        _HASH_ALGORITHM,
                        self._normalize_line_endings,
                    )
                    yield (
                        rel_name,
                        _DIRV2_TYPE_FILE,
                        hexdigest.encode("ascii"),
                    )
                else:
                    # Special file that cannot be read as a regular file.
                    logger.info(
                        "File '%s' is not a regular file. Skipping...",
                        filepath,
                    )

    @staticmethod
    def _hash_symlink(path):
        """Return the sha256 hex digest of a symlink's target string."""
        target = os.readlink(path)
        digest = hashlib.new(_HASH_ALGORITHM)
        digest.update(target.encode("utf-8"))
        return digest.hexdigest().encode("ascii")

    def _hash(self, entries):
        """Serialize entries canonically and return their sha256 digest dict."""
        records = []
        for rel_name, entry_type, digest in entries:
            name_bytes = rel_name.replace("\\", "/").encode("utf-8")
            records.append(
                _DIRV2_FIELD_SEPARATOR.join(
                    [name_bytes, entry_type, digest]
                )
                + _DIRV2_RECORD_SEPARATOR
            )

        # Pure byte-wise ordering: stable across locales and platforms and
        # unambiguous for names containing newlines or non-ASCII bytes.
        records.sort()

        message = _DIRV2_VERSION + _DIRV2_RECORD_SEPARATOR
        message += b"".join(records)

        digest_obj = hashlib.new(_HASH_ALGORITHM)
        digest_obj.update(message)

        return {_HASH_ALGORITHM: digest_obj.hexdigest()}

    def hash_artifacts(self, uris):
        hashes = {}

        for path in uris:
            path = self._strip_scheme_prefix(path)  # noqa: PLW2901

            if not os.path.isdir(path):
                raise ValueError(f"path '{path}' is not a directory")

            entries = list(self._iter_entries(path))
            if not entries:
                logger.info(
                    "path: %s has no entries, recording empty dir...", path
                )

            name = self._mangle(path, hashes)
            hashes[name] = self._hash(entries)

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
