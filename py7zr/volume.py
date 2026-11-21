#!/usr/bin/python -u
#
# p7zr library
#
# Copyright (c) 2019-2026 Hiroshi Miura <miurahr@linux.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
"""Controlled loading of multi-volume 7z archives.

A caller that received only part of an offline backup cannot tell from the
bytes alone whether the set is complete: 7-Zip volumes carry no cross-volume
manifest.  This module lets the caller supply the volume catalog it holds
(a name, size, and SHA-256 digest for every volume), verifies the directory
against that catalog, and then exposes the verified files as one seekable
read-only stream -- without concatenating them into a temporary archive.

Verification and extraction use the same open file descriptors, so a volume
replaced between the check and the read cannot slip past the digest check.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import pathlib
import re
import stat
from dataclasses import dataclass, field
from typing import IO, Iterable

from py7zr.exceptions import (
    VolumeSetAlteredError,
    VolumeSetIncompleteError,
    VolumeSetUnexpectedError,
)

__all__ = [
    "VolumeEntry",
    "VolumeSet",
    "VolumeSetVerification",
    "load_volumes",
]

_HASH_BLOCK_SIZE = 1024 * 1024
_VOLUME_PATTERN = re.compile(r"^(?P<base>.+)\.(?P<number>[0-9]+)$")


@dataclass(frozen=True)
class VolumeEntry:
    """One expected volume in a catalog.

    :param name: File name of the volume, for example ``backup.7z.0001``.
        A bare name is resolved relative to the catalog's directory.
    :param size: Exact size of the volume in bytes.
    :param sha256: Lower-case hexadecimal SHA-256 digest of the volume.
    """

    name: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name or pathlib.PurePath(self.name).name != self.name:
            raise ValueError(f"volume name must be a bare file name: {self.name!r}")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError(f"volume size must be a non-negative integer: {self.size!r}")
        if not isinstance(self.sha256, str):
            raise ValueError(f"volume sha256 must be a string: {self.sha256!r}")
        digest = self.sha256.lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"volume sha256 must be 64 hexadecimal characters: {self.sha256!r}")
        object.__setattr__(self, "sha256", digest)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable representation."""
        return {"name": self.name, "size": self.size, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> VolumeEntry:
        """Build an entry from a mapping with ``name``, ``size`` and ``sha256``."""
        try:
            name = data["name"]
            size = data["size"]
            sha256 = data["sha256"]
        except KeyError as exc:
            raise ValueError(f"volume entry is missing {exc.args[0]!r}") from None
        if not isinstance(name, str) or not isinstance(sha256, str) or not isinstance(size, int):
            raise ValueError("volume entry requires str name, int size, and str sha256")
        return cls(name=name, size=size, sha256=sha256)


@dataclass
class VolumeSetVerification:
    """Outcome of verifying a directory against a volume catalog.

    :ivar expected: The catalog, in stream order.
    :ivar present: Names of catalog volumes found in the directory.
    :ivar missing: Names of catalog volumes absent from the directory.
    :ivar altered: Names whose size or digest differs from the catalog.
    :ivar unexpected: Volume-shaped files in the directory not listed in the
        catalog. ``check_extra=False`` leaves this empty.
    :ivar digests: SHA-256 digests computed while verifying, keyed by name.
    """

    expected: tuple[VolumeEntry, ...]
    present: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    altered: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    digests: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """``True`` when every catalog volume is present and unchanged."""
        return not (self.missing or self.altered or self.unexpected)

    @property
    def total_size(self) -> int:
        """Sum of the catalog sizes, i.e. the logical archive size."""
        return sum(entry.size for entry in self.expected)

    def reason(self) -> str | None:
        """Return a stable machine-readable reason, or ``None`` when ``ok``.

        The values are ``"missing"``, ``"altered"``, ``"unexpected"``, or a
        combination such as ``"missing,altered"`` in that fixed order.
        """
        reasons = []
        if self.missing:
            reasons.append("missing")
        if self.altered:
            reasons.append("altered")
        if self.unexpected:
            reasons.append("unexpected")
        return ",".join(reasons) if reasons else None

    def describe(self) -> str:
        """Return a human-readable explanation of the outcome."""
        if self.ok:
            return f"verified {len(self.expected)} volume(s), {self.total_size} bytes"
        parts = []
        if self.missing:
            parts.append("missing volume(s): " + ", ".join(self.missing))
        if self.altered:
            parts.append("altered volume(s): " + ", ".join(self.altered))
        if self.unexpected:
            parts.append("unexpected volume(s): " + ", ".join(self.unexpected))
        return "; ".join(parts)

    def raise_for_error(self) -> None:
        """Raise the matching :class:`VolumeSetError` when verification failed."""
        reason = self.reason()
        if reason is None:
            return
        message = f"multi-volume set failed verification: {self.describe()}"
        if self.altered:
            raise VolumeSetAlteredError(message, verification=self)
        if self.missing:
            raise VolumeSetIncompleteError(message, verification=self)
        raise VolumeSetUnexpectedError(message, verification=self)


class VolumeSet(io.RawIOBase):
    """A seekable read-only stream over a verified set of volume files.

    Instances are normally created with :func:`load_volumes`, which verifies
    the catalog and keeps the verified descriptors open.  The stream owns
    those descriptors and closes them on :meth:`close`.

    The object can be passed directly to :class:`py7zr.SevenZipFile`; the
    archive metadata methods use :attr:`path`, :attr:`stat_result` and
    :attr:`volume_names`.
    """

    def __init__(
        self,
        files: list[IO[bytes]],
        entries: list[VolumeEntry],
        verification: VolumeSetVerification,
        *,
        path: pathlib.Path,
        identities: list[tuple[int, int, int, int]] | None = None,
    ) -> None:
        super().__init__()
        self._files = files
        self._entries = entries
        self._verification = verification
        self._identities = identities
        self._position = 0
        self._size = sum(entry.size for entry in entries)
        self._positions = [0]
        for entry in entries:
            self._positions.append(self._positions[-1] + entry.size)
        self.path = path
        self.name = str(path)
        self.entries = tuple(entries)
        self.verification = verification

    @property
    def volume_names(self) -> list[str]:
        """Names of the verified volumes, in stream order."""
        return [entry.name for entry in self._entries]

    @property
    def stat_result(self) -> os.stat_result:
        """Combined stat of the verified volumes for ``archiveinfo()``."""
        first = os.fstat(self._files[0].fileno())
        return os.stat_result(
            (
                first.st_mode,
                first.st_ino,
                first.st_dev,
                first.st_nlink,
                first.st_uid,
                first.st_gid,
                self._size,
                first.st_atime,
                first.st_mtime,
                first.st_ctime,
            )
        )

    def check_unchanged(self) -> None:
        """Confirm the open descriptors still refer to the verified bytes.

        Detection uses the inode and the modification time captured during
        verification.  A volume replaced *by path* does not affect the open
        descriptors, so extraction keeps reading the verified inode; an
        in-place truncation or rewrite is detected here before parsing.

        Raises :class:`VolumeSetAlteredError` if a pinned file changed after
        verification.
        """
        if self._identities is None:
            return
        altered = []
        for entry, handle, identity in zip(self._entries, self._files, self._identities):
            st = os.fstat(handle.fileno())
            current = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
            if current != identity or st.st_size != entry.size:
                altered.append(entry.name)
        if altered:
            verification = VolumeSetVerification(
                expected=tuple(self._entries), present=[e.name for e in self._entries], altered=altered
            )
            raise VolumeSetAlteredError(
                "volume(s) changed after verification: " + ", ".join(altered), verification=verification
            )

    def readable(self) -> bool:
        return not self.closed

    def seekable(self) -> bool:
        return not self.closed

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed volume set")
        if whence == io.SEEK_SET:
            target = offset
        elif whence == io.SEEK_CUR:
            target = self._position + offset
        elif whence == io.SEEK_END:
            target = self._size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if target < 0:
            raise ValueError(f"negative seek position: {target}")
        self._position = target
        if self._files:
            index = self._index_for(target)
            handle = self._files[index]
            handle.seek(target - self._positions[index])
        return self._position

    def _index_for(self, position: int) -> int:
        # Last volume absorbs positions at or beyond the declared size so a
        # short read is reported as EOF rather than an IndexError.
        for index in range(len(self._files) - 1):
            if self._positions[index] <= position < self._positions[index + 1]:
                return index
        return len(self._files) - 1

    def read(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed volume set")
        if size is None or size < 0:
            return self.readall()
        chunks = []
        remaining = size
        while remaining > 0 and self._position < self._size:
            index = self._index_for(self._position)
            available = self._positions[index + 1] - self._position
            handle = self._files[index]
            expected_offset = self._position - self._positions[index]
            if handle.tell() != expected_offset:
                handle.seek(expected_offset)
            chunk = handle.read(min(remaining, available))
            if not chunk:
                break
            chunks.append(chunk)
            self._position += len(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def readall(self) -> bytes:
        chunks = []
        while True:
            chunk = self.read(_HASH_BLOCK_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def close(self) -> None:
        if self.closed:
            return
        try:
            for handle in self._files:
                with contextlib.suppress(OSError):
                    handle.close()
        finally:
            self._files = []
            super().close()


def _volume_sort_key(path: pathlib.Path):
    match = _VOLUME_PATTERN.match(path.name)
    if match is None:
        return (1, path.name)
    return (0, match.group("base"), int(match.group("number")))


def _scan_unexpected(directory: pathlib.Path, basename: str | None, listed: set[str]) -> list[str]:
    unexpected = []
    for child in directory.iterdir():
        if child.name in listed:
            continue
        match = _VOLUME_PATTERN.match(child.name)
        if match is None:
            continue
        if basename is not None and match.group("base") != basename:
            continue
        unexpected.append(child.name)
    return sorted(unexpected, key=lambda name: _volume_sort_key(pathlib.Path(name)))


def _digest_file(handle: IO[bytes]) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = handle.read(_HASH_BLOCK_SIZE)
        if not chunk:
            break
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def _catalog_basename(entries: list[VolumeEntry]) -> str:
    """Validate that the catalog is one contiguous, ordered volume run.

    Returns the shared archive base name, for example ``backup.7z``.
    """
    bases = set()
    numbers = []
    for entry in entries:
        match = _VOLUME_PATTERN.match(entry.name)
        if match is None:
            raise ValueError(f"catalog entry is not a numbered volume: {entry.name!r}")
        bases.add(match.group("base"))
        numbers.append(int(match.group("number")))
    if len(bases) != 1:
        raise ValueError("catalog mixes more than one archive base name: " + ", ".join(sorted(bases)))
    first = numbers[0]
    if numbers != list(range(first, first + len(numbers))):
        raise ValueError("catalog volume numbers must be contiguous and ascending from the first entry")
    return bases.pop()


@contextlib.contextmanager
def load_volumes(
    directory: pathlib.Path | str,
    catalog: Iterable[VolumeEntry | dict[str, object]],
    *,
    basename: str | None = None,
    check_extra: bool = True,
):
    """Verify a volume catalog against *directory* and open the volumes.

    The catalog is authoritative: every listed volume must be present with
    exactly the recorded size and SHA-256.  Entries must share one archive
    base name and use ascending, contiguous volume numbers, for example
    ``backup.7z.0001`` through ``backup.7z.0004``; this catches gaps in the
    catalog itself.  With ``check_extra`` (the default) the directory may
    not contain other volume-shaped files for that base name, so a
    partially delivered set is refused even when the missing volume happens
    to be beyond the last one the catalog lists.

    On success the returned :class:`VolumeSet` is a seekable read-only
    stream over the volumes in catalog order.  The volumes are read in
    place; they are never concatenated or copied.  On failure
    :class:`VolumeSetError` is raised and the directory is left untouched.
    Use the context manager form to close the descriptors::

        with load_volumes(directory, catalog) as volumes:
            with py7zr.SevenZipFile(volumes, "r") as archive:
                archive.extractall(target)

    :param directory: Directory holding the volume files.
    :param catalog: Expected volumes as :class:`VolumeEntry` objects or
        mappings with ``name``, ``size`` and ``sha256`` keys.
    :param basename: When given, limit the unexpected-file scan to volumes
        with this archive base name. Defaults to the catalog's base name.
    :param check_extra: Reject volume-shaped files absent from the catalog.
    """
    directory = pathlib.Path(directory)
    if not directory.is_dir():
        raise NotADirectoryError(f"not a directory: {directory}")
    entries = [item if isinstance(item, VolumeEntry) else VolumeEntry.from_dict(item) for item in catalog]
    if not entries:
        raise ValueError("volume catalog must not be empty")
    names = [entry.name for entry in entries]
    if len(set(names)) != len(names):
        raise ValueError("volume catalog contains duplicate names")
    derived_basename = _catalog_basename(entries)
    if basename is None:
        basename = derived_basename
    elif basename != derived_basename:
        raise ValueError(f"basename {basename!r} does not match the catalog's base name {derived_basename!r}")

    verification = VolumeSetVerification(expected=tuple(entries))
    handles: list[IO[bytes]] = []
    identities: list[tuple[int, int, int, int]] = []
    stream: VolumeSet | None = None
    try:
        for entry in entries:
            source = directory.joinpath(entry.name)
            try:
                lst = os.lstat(source)
            except FileNotFoundError:
                verification.missing.append(entry.name)
                continue
            if not stat.S_ISREG(lst.st_mode) or stat.S_ISLNK(lst.st_mode):
                verification.missing.append(entry.name)
                continue
            handle: IO[bytes] = open(source, "rb")
            st = os.fstat(handle.fileno())
            if st.st_size != entry.size:
                verification.altered.append(entry.name)
                handle.close()
                continue
            size, digest = _digest_file(handle)
            verification.digests[entry.name] = digest
            if size != entry.size or digest != entry.sha256:
                verification.altered.append(entry.name)
                handle.close()
                continue
            handle.seek(0)
            handles.append(handle)
            identities.append((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns))
            verification.present.append(entry.name)
        if check_extra:
            verification.unexpected = _scan_unexpected(directory, basename, set(names))
        verification.raise_for_error()
        stream = VolumeSet(
            handles,
            entries,
            verification,
            path=directory.joinpath(entries[0].name),
            identities=identities,
        )
        handles = []
        yield stream
    finally:
        for handle in handles:
            handle.close()
        if stream is not None:
            stream.close()
