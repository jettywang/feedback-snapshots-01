# Copyright (C) 2026  Paramiko Developers
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Consistency diagnostics for the SFTP ``check-file`` extension.

A forensic collector may be handed several ``check-file`` digests for the
same path and need to know whether they all describe one stable file.  The
digests returned by the server are not, by themselves, evidence that the
underlying bytes stayed unchanged between requests -- a file can be
replaced, truncated or rewritten while a handle stays open, and nothing in
the SFTPv3 ``check-file`` reply records what each digest actually covered.

The checks in this module therefore keep the *existing, single* open handle
(the path is never re-opened, so a same-named replacement file can never be
silently stitched into the result), snapshot the handle's metadata before
and after the work, independently re-read every byte through the same
handle and hash them locally with :mod:`hashlib`, and report the exact
``[start, end)`` range each returned digest covers.  Every hash name is
validated against a fixed client-side allow-list before it is sent, so a
peer cannot make the client instantiate arbitrary named hashes, and the
total amount of data read is bounded by ``max_bytes``.

The remote digests are only ever compared against the locally computed
digests; they are never treated as proof of where the bytes came from.
"""

import hashlib
from dataclasses import dataclass, field

from paramiko.sftp import (
    CMD_ATTRS,
    CMD_DATA,
    CMD_EXTENDED,
    CMD_FSTAT,
    CMD_READ,
    CMD_STATUS,
    SFTPError,
    int64,
)

#: Hash algorithms this client is willing to request.  Only names that
#: exist in :mod:`hashlib` and are considered acceptable for forensic use
#: are listed here; anything else is rejected before it touches the wire.
ALLOWED_HASH_ALGORITHMS = ("sha256", "sha1", "md5")

#: ``check-file`` requires block sizes of at least 256 bytes.
MIN_BLOCK_SIZE = 256

#: Default ceiling on how many bytes are read back per snapshot check.
DEFAULT_MAX_BYTES = 16 * 1024 * 1024

#: Individual SFTP ``CMD_READ`` requests stay at this size, matching
#: `.SFTPFile.MAX_REQUEST_SIZE`.
_READ_CHUNK_SIZE = 32768

#: Outcome values for `.SnapshotConsistencyReport.state`.
STATE_STABLE = "stable"
STATE_UNSTABLE = "unstable"
STATE_UNVERIFIABLE = "unverifiable"


@dataclass
class DigestCoverage:
    """
    What one digest returned by the server actually covers.

    ``server_digest`` and ``local_digest`` are raw bytes (hexadecimal forms
    are available through `hexdigest`).  ``local_digest`` is computed
    independently with :mod:`hashlib` over the bytes read back through the
    same handle; ``server_digest`` is whatever the peer sent and is never
    trusted on its own.
    """

    index: int
    start: int
    end: int
    requested_length: int
    actual_length: int
    server_digest: bytes
    local_digest: bytes
    digest_matches: bool
    short_read: bool

    @property
    def range(self):
        """The half-open byte range ``[start, end)`` this digest covers."""
        return (self.start, self.end)

    def hexdigest(self):
        """
        Return ``(server_hex, local_hex)`` for this digest.

        If the server did not return a digest for this block (for example
        because the extension was unsupported or the file was truncated),
        ``server_hex`` is ``None``.
        """
        server_hex = (
            self.server_digest.hex() if self.server_digest else None
        )
        return server_hex, self.local_digest.hex()

    def as_dict(self):
        """Render this coverage record as a plain, JSON-friendly dict."""
        server_hex, local_hex = self.hexdigest()
        return {
            "index": self.index,
            "start": self.start,
            "end": self.end,
            "range": [self.start, self.end],
            "requested_length": self.requested_length,
            "actual_length": self.actual_length,
            "short_read": self.short_read,
            "server_digest": server_hex,
            "local_digest": local_hex,
            "digest_matches": self.digest_matches,
        }


@dataclass
class SnapshotConsistencyReport:
    """
    Result of a `check_snapshot` run.

    ``state`` is one of :data:`STATE_STABLE`, :data:`STATE_UNSTABLE` and
    :data:`STATE_UNVERIFIABLE`.  A report is only *stable* when the handle
    metadata seen before and after the check is identical, every expected
    block was read in full (no short reads / early EOF), and every
    server-provided digest matches an independently computed local digest.
    Anything suspicious degrades the report to *unstable*; if the protocol
    capability needed to judge stability (``fstat`` or the ``check-file``
    extension) is missing, the report is *unverifiable* instead, because the
    client honestly cannot prove that one snapshot was observed.
    """

    algorithm: str
    offset: int
    requested_length: int
    requested_block_size: int
    effective_block_size: int
    max_bytes: int
    state: str
    eof_reached: bool
    ended_early: bool
    bytes_read: int = 0
    server_supported: bool = False
    server_algorithm: object = None
    identity_before: object = None
    identity_after: object = None
    instability_reasons: list = field(default_factory=list)
    coverage: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def __post_init__(self):
        # A remote digest can never authenticate file provenance; this flag
        # is always False and exists so callers cannot mistake it for one.
        self.provenance_trusted = False
        self.notes.append(
            "remote check-file digests are compared against locally "
            "computed hashes only; they do not prove the file's provenance"
        )

    @property
    def stable(self):
        """``True`` only when ``state == 'stable'``."""
        return self.state == STATE_STABLE

    @property
    def ranges(self):
        """The actual ``[start, end)`` range covered by every digest."""
        return [item.range for item in self.coverage]

    def as_dict(self):
        """Render the full report as a plain, JSON-friendly dict."""
        return {
            "algorithm": self.algorithm,
            "state": self.state,
            "stable": self.stable,
            "provenance_trusted": self.provenance_trusted,
            "offset": self.offset,
            "requested_length": self.requested_length,
            "requested_block_size": self.requested_block_size,
            "effective_block_size": self.effective_block_size,
            "max_bytes": self.max_bytes,
            "bytes_read": self.bytes_read,
            "eof_reached": self.eof_reached,
            "ended_early": self.ended_early,
            "server_supported": self.server_supported,
            "server_algorithm": self.server_algorithm,
            "identity_before": list(self.identity_before)
            if self.identity_before is not None
            else None,
            "identity_after": list(self.identity_after)
            if self.identity_after is not None
            else None,
            "instability_reasons": list(self.instability_reasons),
            "notes": list(self.notes),
            "coverage": [item.as_dict() for item in self.coverage],
        }


def _identity(attrs):
    """
    Reduce an `.SFTPAttributes` object to the fields that identify a stable
    file.  ``st_atime`` is deliberately excluded: merely reading a handle may
    update access time on some servers without the file content changing.
    Returns ``None`` when no usable attributes are available.
    """
    if attrs is None or getattr(attrs, "st_size", None) is None:
        return None
    return (
        attrs.st_size,
        attrs.st_mtime,
        attrs.st_mode,
        attrs.st_uid,
        attrs.st_gid,
    )


def _fstat(sftp_file):
    """``fstat`` on the existing handle, returning ``None`` on failure."""
    try:
        t, msg = sftp_file.sftp._request(CMD_FSTAT, sftp_file.handle)
    except (IOError, EOFError, SFTPError):
        return None
    if t != CMD_ATTRS:
        return None
    try:
        from paramiko.sftp_attr import SFTPAttributes

        return SFTPAttributes._from_msg(msg)
    except SFTPError:
        return None


def _raw_read(sftp_file, offset, length):
    """
    Issue one ``CMD_READ`` on the existing handle without touching the
    `.BufferedFile` cursor state.  Returns the bytes read (possibly empty at
    EOF), or raises on a protocol/transport error.
    """
    t, msg = sftp_file.sftp._request(
        CMD_READ, sftp_file.handle, int64(offset), int(length)
    )
    if t == CMD_STATUS:
        # An SFTP status reply here is an EOF or an error; surface it to
        # the caller via the normal status translation.
        sftp_file.sftp._convert_status(msg)
    if t != CMD_DATA:
        raise SFTPError("Expected data")
    return msg.get_string()


def _check_file_request(sftp_file, algorithm, offset, length, block_size):
    """
    Send one ``check-file`` extended request on the existing handle.

    Returns ``(supported, server_algorithm, digest_blob)``.  ``supported``
    is ``False`` (rather than an exception) when the peer does not implement
    the extension, so the caller can still report a local-only result.
    """
    try:
        t, msg = sftp_file.sftp._request(
            CMD_EXTENDED,
            "check-file",
            sftp_file.handle,
            algorithm,
            int64(offset),
            int64(length),
            block_size,
        )
    except IOError:
        return False, None, b""
    if t == CMD_STATUS:
        return False, None, b""
    ext_name = msg.get_text()
    if ext_name != "check-file":
        raise SFTPError("Unexpected extended reply {!r}".format(ext_name))
    server_algorithm = msg.get_text()
    digest_blob = msg.get_remainder()
    return True, server_algorithm, digest_blob


def check_snapshot(
    sftp_file,
    hash_algorithm,
    offset=0,
    length=0,
    block_size=0,
    max_bytes=DEFAULT_MAX_BYTES,
):
    """
    Run a bounded, consistency-diagnostic ``check-file`` verification.

    The handle is opened once by the caller and never re-opened here, so a
    same-named replacement on the server cannot be used to complete a
    partial result.  The sequence is:

    1. validate every parameter locally (allow-listed hash name, non-negative
       offsets, protocol-legal block size, read budget);
    2. ``fstat`` the handle to record the pre-check file identity;
    3. send exactly one allow-listed ``check-file`` request;
    4. independently re-read the same bytes through the same handle, hashing
       each block with :mod:`hashlib` and recording short reads / EOF;
    5. ``fstat`` again and compare identities;
    6. split the server's digest blob across the blocks actually covered and
       compare each one with the local digest.

    :param `.SFTPFile` sftp_file: an already-open remote file handle.
    :param str hash_algorithm: name from `ALLOWED_HASH_ALGORITHMS`; any
        other value raises ``ValueError`` and is never sent to the server.
    :param int offset: byte offset to start at.
    :param int length: bytes to cover; ``0`` means to the end of file,
        bounded by ``max_bytes``.
    :param int block_size: bytes per digest (minimum 256); ``0`` means one
        digest over the whole requested segment.
    :param int max_bytes: hard ceiling on bytes read back; the check stops
        at this bound even if the file is longer.
    :return: a `.SnapshotConsistencyReport` describing every digest and the
        stability verdict.
    :raises ValueError: for any locally invalid parameter.
    """
    if not isinstance(hash_algorithm, str):
        raise ValueError("hash_algorithm must be a string")
    if hash_algorithm not in ALLOWED_HASH_ALGORITHMS:
        raise ValueError(
            "hash_algorithm {!r} is not in the client allow-list {}".format(
                hash_algorithm, ALLOWED_HASH_ALGORITHMS
            )
        )
    if not hashlib.new(hash_algorithm):
        # Defense in depth: the allow-list should make this unreachable.
        raise ValueError(
            "hash_algorithm {!r} unavailable in hashlib".format(
                hash_algorithm
            )
        )
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if length < 0:
        raise ValueError("length must be non-negative")
    if block_size < 0:
        raise ValueError("block_size must be non-negative")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if 0 < block_size < MIN_BLOCK_SIZE:
        raise ValueError(
            "block_size must be 0 or at least {}".format(MIN_BLOCK_SIZE)
        )

    reasons = []
    notes = []

    before = _fstat(sftp_file)
    identity_before = _identity(before)
    if identity_before is None:
        notes.append(
            "fstat before the check was unavailable; snapshot identity "
            "cannot be established"
        )

    if length == 0:
        if identity_before is not None:
            requested_length = max(0, before.st_size - offset)
        else:
            # No metadata and an open-ended request: the read budget is the
            # only bound we can honestly apply.
            requested_length = max_bytes
            notes.append(
                "length=0 without fstat support; reading at most max_bytes"
            )
    else:
        requested_length = length
    if requested_length > max_bytes:
        raise ValueError(
            "requested range of {} bytes exceeds max_bytes={}".format(
                requested_length, max_bytes
            )
        )

    report = SnapshotConsistencyReport(
        algorithm=hash_algorithm,
        offset=offset,
        requested_length=requested_length,
        requested_block_size=block_size,
        effective_block_size=block_size or requested_length,
        max_bytes=max_bytes,
        state=STATE_STABLE,
        eof_reached=False,
        ended_early=False,
        identity_before=identity_before,
        notes=notes,
    )

    if requested_length == 0:
        # An empty range (empty file, or offset at/after EOF) has no bytes
        # to hash and no check-file block to request.  Probe EOF once so the
        # verdict still reflects a real, stable, empty snapshot.
        try:
            probe = _raw_read(sftp_file, offset, 1)
        except (EOFError, IOError, SFTPError):
            probe = b""
        report.eof_reached = len(probe) == 0
        after = _fstat(sftp_file)
        report.identity_after = _identity(after)
        if (
            identity_before is not None
            and report.identity_after is not None
            and identity_before != report.identity_after
        ):
            report.instability_reasons.append(
                "handle metadata changed during the check: {} -> {}".format(
                    identity_before, report.identity_after
                )
            )
        if identity_before is None or report.identity_after is None:
            report.notes.append(
                "unable to prove snapshot consistency: handle identity was "
                "not observable for the whole check"
            )
            report.state = STATE_UNVERIFIABLE
        elif report.instability_reasons:
            report.state = STATE_UNSTABLE
        return report

    # One allow-listed check-file request, on the existing handle.
    supported, server_algorithm, digest_blob = _check_file_request(
        sftp_file, hash_algorithm, offset, length, block_size
    )
    report.server_supported = supported
    report.server_algorithm = server_algorithm
    if not supported:
        report.state = STATE_UNVERIFIABLE
        report.notes.append(
            "server does not support the check-file extension; only local "
            "hashes are available"
        )
    elif server_algorithm != hash_algorithm:
        report.state = STATE_UNSTABLE
        reasons.append(
            "server echoed algorithm {!r} instead of {!r}".format(
                server_algorithm, hash_algorithm
            )
        )

    digest_size = hashlib.new(hash_algorithm).digest_size

    # Independently read every byte through the same handle and hash it.
    # The work is organized as the same block layout that was requested, so
    # every local digest lines up with a slot in the server's digest blob.
    position = offset
    remaining = requested_length
    block_index = 0

    while remaining > 0:
        block_requested = (
            min(report.effective_block_size, remaining)
            if report.effective_block_size
            else remaining
        )
        block_start = position
        block_remaining = block_requested
        hasher = hashlib.new(hash_algorithm)
        read_failed = False

        while block_remaining > 0:
            chunk_size = min(_READ_CHUNK_SIZE, block_remaining)
            try:
                data = _raw_read(sftp_file, position, chunk_size)
            except EOFError:
                # The server signaled SFTP_EOF: a clean end of file, which
                # the short-read accounting below will record.
                report.eof_reached = True
                break
            except (IOError, SFTPError) as e:
                report.ended_early = True
                reasons.append(
                    "read at offset {} failed: {}".format(position, e)
                )
                read_failed = True
                break

            got = len(data)
            if got == 0:
                # Clean EOF before the requested range was covered.
                report.eof_reached = True
                break
            hasher.update(data)
            position += got
            block_remaining -= got
            remaining -= got
            report.bytes_read += got

        actual_length = block_requested - block_remaining
        short_read = actual_length < block_requested
        if short_read and not read_failed:
            # The short read came from an EOF rather than a transport error.
            report.ended_early = True
            reasons.append(
                "early EOF at offset {}; block {} covers {} of {} "
                "requested bytes".format(
                    position, block_index, actual_length, block_requested
                )
            )

        local_digest = hasher.digest()
        server_digest = b""
        digest_matches = False
        if supported:
            slot = block_index * digest_size
            server_digest = digest_blob[slot : slot + digest_size]
            digest_matches = (
                len(server_digest) == digest_size
                and server_digest == local_digest
            )
        report.coverage.append(
            DigestCoverage(
                index=block_index,
                start=block_start,
                end=block_start + actual_length,
                requested_length=block_requested,
                actual_length=actual_length,
                server_digest=server_digest,
                local_digest=local_digest,
                digest_matches=digest_matches,
                short_read=short_read,
            )
        )
        block_index += 1

        if short_read or read_failed:
            # No point issuing further reads past an EOF/error.
            break

    # If the requested range was covered in full without an explicit EOF
    # reply, probe one byte further: a length=0 ("to end of file") request
    # has only really reached EOF when the next read comes back empty.
    if not report.eof_reached and not report.ended_early:
        try:
            probe = _raw_read(sftp_file, position, 1)
        except EOFError:
            probe = b""
        except (IOError, SFTPError):
            probe = b""
        report.eof_reached = len(probe) == 0

    # Post-check identity on the same handle -- no re-open anywhere.
    after = _fstat(sftp_file)
    identity_after = _identity(after)
    report.identity_after = identity_after
    if identity_after is None:
        report.notes.append(
            "fstat after the check was unavailable; snapshot identity "
            "cannot be confirmed"
        )
    if identity_before is not None and identity_after is not None:
        if identity_before != identity_after:
            reasons.append(
                "handle metadata changed during the check: {} -> {}".format(
                    identity_before, identity_after
                )
            )
    elif identity_before is None or identity_after is None:
        # Missing fstat evidence means stability simply cannot be proven.
        report.notes.append(
            "unable to prove snapshot consistency: handle identity was not "
            "observable for the whole check"
        )

    if supported:
        expected_digests = len(report.coverage)
        if len(digest_blob) != expected_digests * digest_size:
            reasons.append(
                "server returned {} digest bytes for {} blocks of {}".format(
                    len(digest_blob), expected_digests, hash_algorithm
                )
            )
        for item in report.coverage:
            if not item.digest_matches:
                reasons.append(
                    "digest mismatch on block {} (range [{}-{}))".format(
                        item.index, item.start, item.end
                    )
                )

    report.instability_reasons = reasons

    if reasons:
        report.state = STATE_UNSTABLE
    elif report.state != STATE_UNVERIFIABLE and (
        identity_before is None or identity_after is None
    ):
        report.state = STATE_UNVERIFIABLE
    elif report.state != STATE_UNVERIFIABLE:
        report.state = STATE_STABLE
    return report
