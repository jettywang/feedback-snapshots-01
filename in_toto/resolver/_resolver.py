"""Resolver interface and implementations for files, OSTree, and directory
artifacts."""

import hashlib
import logging
import os
from abc import ABC, abstractmethod
from itertools import combinations
from os.path import exists, isdir, isfile, join, normpath

from pathspec import GitIgnoreSpec

from in_toto.exceptions import PrefixError

logger = logging.getLogger(__name__)

_HASH_ALGORITHM = "sha256"

RESOLVER_FOR_URI_SCHEME = {}


class Resolver(ABC):
    """Resolver interface and factory."""

    @classmethod
    def for_uri(cls, uri, resolver_for_uri_scheme=None):
        """Return registered resolver instance for passed URI.

        Resolvers are looked up in ``resolver_for_uri_scheme`` if passed,
        otherwise in the process-wide ``RESOLVER_FOR_URI_SCHEME`` registry.
        Passing a per-call registry lets callers resolve artifacts without
        mutating or depending on process-global state.
        """
        if resolver_for_uri_scheme is None:
            resolver_for_uri_scheme = RESOLVER_FOR_URI_SCHEME

        scheme, match, _ = uri.partition(":")

        if not match or scheme not in resolver_for_uri_scheme:
            scheme = FileResolver.SCHEME

        return resolver_for_uri_scheme[scheme]

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

    def _disk_path(self, path):
        """Return the on-disk location of an artifact path.

        Joins ``base_path`` (if configured) instead of changing the process
        working directory, so concurrent recordings stay isolated.
        """
        if self._base_path:
            return join(self._base_path, path)
        return path

    def _rel_name(self, disk_path):
        """Return the artifact name for a walked file.

        With ``base_path`` set, names are relative to ``base_path`` (the
        walked directory prefix is dropped). Without it, names are returned
        as the normalized on-disk path, i.e. relative to the current working
        directory and including the originally passed directory. This keeps
        the returned artifact names identical to the pre-isolation behavior.
        """
        if self._base_path:
            return normpath(os.path.relpath(disk_path, self._base_path))
        return normpath(disk_path)

    def hash_artifacts(self, uris):  # noqa: C901
        hashes = {}

        # Fail early on a bogus base path, mirroring the OSError raised by the
        # previous implementation when it tried to change into the directory.
        if self._base_path and not isdir(self._base_path):
            raise OSError(f"'{self._base_path}' is not a directory")

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

            disk_path = self._disk_path(path)
            if not exists(disk_path):
                logger.info("path: %s does not exist, skipping..", path)
                continue

            if isfile(disk_path):
                name = self._mangle(path, hashes, prefix)
                hashes[name] = self._hash(disk_path)

            if isdir(disk_path):
                for base, dirs, names in os.walk(
                    disk_path, followlinks=self._follow_symlink_dirs
                ):
                    # Filter directories to avoid unnecessary recursion below
                    # NOTE: Normalize to filter on directory paths without
                    # their dot-slash prefix, if path was dot.
                    dirs[:] = [
                        dirname
                        for dirname in dirs
                        if not self._exclude(
                            self._rel_name(join(base, dirname))
                        )
                    ]

                    for filename in names:
                        # NOTE: Normalize to filter on and return file paths
                        # without their dot-slash prefix, if path was dot.
                        rel_name = self._rel_name(join(base, filename))

                        if self._exclude(rel_name):
                            continue

                        filepath = join(base, filename)
                        if not isfile(filepath):
                            logger.info(
                                "File '%s' appears to be a broken symlink. "
                                "Skipping...",
                                rel_name,
                            )
                            continue

                        name = self._mangle(rel_name, hashes, prefix)
                        hashes[name] = self._hash(filepath)

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

        if self._base_path:
            repo_path = self._base_path
        else:
            repo_path = ""

        ref_path = os.path.join(repo_path, "refs", "heads", path)

        with open(ref_path) as ref:  # noqa: PLW1514, RUF100
            ref_contents = ref.read()
        ref_contents = ref_contents.strip("\n")

        object_path = os.path.join(
            repo_path,
            "objects",
            ref_contents[:2],
            f"{ref_contents[2:]}.commit",
        )

        hexdigest = _hash_file(object_path, self._HASH_ALGORITHM, False)

        return {self._HASH_ALGORITHM: hexdigest}

    def hash_artifacts(self, uris):
        hashes = {}

        for path in uris:
            # Remove scheme prefix, but preserver to re-add later
            path = self._strip_scheme_prefix(path)  # noqa: PLW2901
            hashes[self._add_scheme_prefix(path)] = self._hash(path)

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
            # Sorting by the raw UTF-8 bytes reproduces `LC_ALL=C sort`
            # (byte-wise ordering) without mutating the process-wide locale.
            keys.sort(key=lambda key: key.encode("utf-8", "surrogateescape"))

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
