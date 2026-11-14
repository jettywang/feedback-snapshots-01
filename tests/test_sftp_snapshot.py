# Copyright (C) 2026 Paramiko Developers
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Consistency-diagnostic tests for the SFTP ``check-file`` extension.

Every digest asserted here is computed independently with :mod:`hashlib`
from bytes the test itself wrote.  Digests returned by the SFTP server are
only ever compared against those local digests -- they are never used as
evidence that the remote file is what it claims to be.
"""

import hashlib
import os
import shutil
import threading
import uuid

import pytest

from paramiko import (
    SFTP,
    RSAKey,
    SFTPAttributes,
    SFTPHandle,
    SFTPServer,
    Transport,
)
from paramiko.common import o666
from paramiko.sftp_snapshot import (
    ALLOWED_HASH_ALGORITHMS,
    DEFAULT_MAX_BYTES,
    DigestCoverage,
    SnapshotConsistencyReport,
    STATE_STABLE,
    STATE_UNSTABLE,
    STATE_UNVERIFIABLE,
)

from ._loop import LoopSocket
from ._stub_sftp import StubServer, StubSFTPServer
from ._util import _support


def _local_digest(algorithm, data):
    return hashlib.new(algorithm, data).digest()


@pytest.fixture
def scratch_file():
    """
    Create a unique scratch directory under the test CWD (which is the stub
    server's ROOT).  Yields ``(sftp_path, real_path)`` and removes the
    directory afterwards.
    """
    directory = "snapshot-test-{}".format(uuid.uuid4().hex)
    os.mkdir(directory)
    name = "target.bin"
    sftp_path = "/".join(("", directory, name))
    real_path = os.path.join(os.getcwd(), directory, name)
    try:
        yield sftp_path, real_path
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _start_sftp(interface_class, server_class=SFTPServer):
    """
    Bring up an in-process client/server SFTP pair over loop sockets.

    Returns ``(client, transport_client, transport_server)``; the caller is
    responsible for closing the client and transports.
    """
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(host_key)
    event = threading.Event()
    ts.set_subsystem_handler("sftp", server_class, interface_class)
    ts.start_server(event, StubServer())
    tc.connect(username="slowdive", password="pygmalion")
    assert event.wait(2.0)
    client = SFTP.from_transport(tc)
    return client, tc, ts


class MutatingHandle(SFTPHandle):
    """
    An SFTP handle that mutates the underlying file at a chosen read offset.

    The mutation runs while this handle is open, i.e. mid-operation, so the
    test exercises a file changing underneath an in-flight check rather than
    a freshly re-opened path.
    """

    def __init__(self, flags, real_path, trigger_offset, mutation):
        super().__init__(flags)
        self._real_path = real_path
        self._trigger_offset = trigger_offset
        self._mutation = mutation
        self._fired = False
        fd = os.open(real_path, flags | getattr(os, "O_BINARY", 0), o666)
        self.readfile = os.fdopen(fd, "rb")
        self.writefile = self.readfile

    def read(self, offset, length):
        if not self._fired and offset >= self._trigger_offset:
            self._fired = True
            self._mutation(self._real_path)
        return super().read(offset, length)

    def stat(self):
        try:
            return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)


class MutatingSFTPServer(StubSFTPServer):
    trigger_offset = 0
    mutation = staticmethod(lambda path: None)

    def open(self, path, flags, attr):
        real_path = self._realpath(path)
        return MutatingHandle(
            flags, real_path, self.trigger_offset, self.mutation
        )


class FakeDigestServer(SFTPServer):
    """Serves a check-file reply containing attacker-chosen digests."""

    forged_blob = b""
    forged_algorithm = "sha256"

    def _check_file(self, request_number, msg):
        # Consume the request fields so the message is fully parsed, then
        # reply with digests that do not correspond to any real file bytes.
        msg.get_binary()
        msg.get_list()
        msg.get_int64()
        msg.get_int64()
        msg.get_int()
        from paramiko.message import Message
        from paramiko.sftp import CMD_EXTENDED_REPLY

        reply = Message()
        reply.add_int(request_number)
        reply.add_string("check-file")
        reply.add_string(self.forged_algorithm)
        reply.add_bytes(self.forged_blob)
        self._send_packet(CMD_EXTENDED_REPLY, reply)


class UnsupportedCheckFileServer(SFTPServer):
    def _check_file(self, request_number, msg):
        from paramiko.sftp import SFTP_OP_UNSUPPORTED as _code

        self._send_status(request_number, _code)


def _truncate_to(size):
    def _do(path):
        with open(path, "r+b") as fh:
            fh.truncate(size)

    return _do


def _overwrite_same_length(data):
    def _do(path):
        with open(path, "r+b") as fh:
            fh.seek(0)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

    return _do


# --- stable, well-behaved behaviour against the ordinary stub server ------


def test_snapshot_full_file_is_stable(sftp):
    data = b"stable forensic content " * 64
    path = sftp.FOLDER + "/stable.bin"
    with sftp.open(path, "w") as fh:
        fh.write(data)

    with sftp.open(path, "r") as fh:
        report = fh.check_snapshot("sha256")

    assert isinstance(report, SnapshotConsistencyReport)
    assert report.state == STATE_STABLE
    assert report.server_supported is True
    assert report.eof_reached is True
    assert report.ended_early is False
    assert report.bytes_read == len(data)
    assert report.provenance_trusted is False
    assert any(
        "do not prove the file's provenance" in note
        for note in report.notes
    )
    assert report.ranges == [(0, len(data))]
    assert len(report.coverage) == 1
    item = report.coverage[0]
    assert isinstance(item, DigestCoverage)
    assert item.short_read is False
    assert item.digest_matches is True
    server_hex, local_hex = item.hexdigest()
    assert local_hex == hashlib.sha256(data).hexdigest()
    assert server_hex == local_hex
    assert report.identity_before == report.identity_after

    sftp.unlink(path)


def test_snapshot_block_ranges_match_independent_hashes(sftp):
    data = bytes((i * 7 + 3) % 256 for i in range(2000))
    path = sftp.FOLDER + "/blocks.bin"
    with sftp.open(path, "w") as fh:
        fh.write(data)

    block_size = 512
    with sftp.open(path, "r") as fh:
        report = fh.check_snapshot("sha256", block_size=block_size)

    assert report.state == STATE_STABLE
    assert report.effective_block_size == block_size
    expected_ranges = [(0, 512), (512, 1024), (1024, 1536), (1536, 2000)]
    assert report.ranges == expected_ranges
    assert [item.requested_length for item in report.coverage] == [
        512,
        512,
        512,
        464,
    ]
    for item in report.coverage:
        start, end = item.range
        assert item.actual_length == end - start
        assert item.local_digest == _local_digest(
            report.algorithm, data[start:end]
        )
        assert item.server_digest == item.local_digest
        assert item.digest_matches is True
        assert item.short_read is False

    sftp.unlink(path)


def test_snapshot_explicit_offset_and_length(sftp):
    data = b"".join(bytes([i % 256]) for i in range(3000))
    path = sftp.FOLDER + "/slice.bin"
    with sftp.open(path, "w") as fh:
        fh.write(data)

    offset, length = 500, 1200
    with sftp.open(path, "r") as fh:
        report = fh.check_snapshot("sha1", offset=offset, length=length)

    assert report.state == STATE_STABLE
    assert report.bytes_read == length
    assert report.ranges == [(offset, offset + length)]
    assert report.requested_length == length
    assert report.eof_reached is False
    item = report.coverage[0]
    assert item.local_digest == hashlib.sha1(
        data[offset : offset + length]
    ).digest()
    assert item.server_digest == item.local_digest

    sftp.unlink(path)


def test_snapshot_md5_allowed_and_verified(sftp):
    data = b"md5 me please " * 32
    path = sftp.FOLDER + "/md5.bin"
    with sftp.open(path, "w") as fh:
        fh.write(data)

    with sftp.open(path, "r") as fh:
        report = fh.check_snapshot("md5")

    assert report.state == STATE_STABLE
    assert report.algorithm == "md5"
    assert report.coverage[0].local_digest == hashlib.md5(data).digest()

    sftp.unlink(path)


def test_snapshot_empty_file_is_stable_with_no_blocks(sftp):
    path = sftp.FOLDER + "/empty.bin"
    with sftp.open(path, "w"):
        pass

    with sftp.open(path, "r") as fh:
        report = fh.check_snapshot("sha256")

    assert report.state == STATE_STABLE
    assert report.coverage == []
    assert report.bytes_read == 0
    assert report.eof_reached is True
    assert report.identity_before == report.identity_after

    sftp.unlink(path)


def test_snapshot_small_file_below_block_minimum(sftp):
    data = b"tiny"
    path = sftp.FOLDER + "/tiny.bin"
    with sftp.open(path, "w") as fh:
        fh.write(data)

    with sftp.open(path, "r") as fh:
        # block_size=0 means one block over the whole segment, even though
        # the file is shorter than the 256-byte minimum block size.
        report = fh.check_snapshot("sha256")

    assert report.state == STATE_STABLE
    assert report.ranges == [(0, len(data))]
    assert report.coverage[0].local_digest == hashlib.sha256(data).digest()

    sftp.unlink(path)


def test_snapshot_offset_past_eof_is_unstable(sftp):
    path = sftp.FOLDER + "/past.bin"
    with sftp.open(path, "w") as fh:
        fh.write(b"abcdef")

    with sftp.open(path, "r") as fh:
        report = fh.check_snapshot("sha256", offset=10, length=4)

    assert report.state == STATE_UNSTABLE
    assert report.ended_early is True
    assert report.eof_reached is True
    assert report.ranges == [(10, 10)]
    assert report.coverage[0].short_read is True

    sftp.unlink(path)


def test_snapshot_as_dict_is_serializable(sftp):
    data = b"x" * 600
    path = sftp.FOLDER + "/dict.bin"
    with sftp.open(path, "w") as fh:
        fh.write(data)

    with sftp.open(path, "r") as fh:
        report = fh.check_snapshot("sha256", block_size=256)
    rendered = report.as_dict()

    assert rendered["state"] == "stable"
    assert rendered["provenance_trusted"] is False
    assert len(rendered["coverage"]) == 3
    first = rendered["coverage"][0]
    assert first["range"] == [0, 256]
    assert isinstance(first["local_digest"], str)
    assert first["digest_matches"] is True

    sftp.unlink(path)


# --- instability: the file changes or shrinks on the open handle ----------


def test_snapshot_truncation_mid_handle_is_unstable(scratch_file):
    sftp_path, real_path = scratch_file
    original = b"A" * 4096
    with open(real_path, "wb") as fh:
        fh.write(original)

    MutatingSFTPServer.trigger_offset = 1024
    MutatingSFTPServer.mutation = staticmethod(_truncate_to(1500))
    client, tc, ts = _start_sftp(MutatingSFTPServer)
    try:
        with client.open(sftp_path, "r") as fh:
            report = fh.check_snapshot("sha256", block_size=512)
    finally:
        client.close()
        tc.close()
        ts.close()

    assert report.state == STATE_UNSTABLE
    assert report.ended_early is True
    assert report.identity_before != report.identity_after
    assert report.identity_after[0] == 1500
    assert any("EOF" in reason or "metadata changed" in reason
               for reason in report.instability_reasons)
    # Every emitted digest is still independently verified over its real,
    # truncated range -- nothing was stitched together from another file.
    with open(real_path, "rb") as fh:
        on_disk = fh.read()
    for item in report.coverage:
        start, end = item.range
        if item.server_digest:
            assert item.digest_matches == (
                item.server_digest
                == hashlib.sha256(on_disk[start:end]).digest()
            )


def test_snapshot_same_length_rewrite_mid_handle_is_unstable(scratch_file):
    sftp_path, real_path = scratch_file
    original = b"B" * 4096
    with open(real_path, "wb") as fh:
        fh.write(original)

    MutatingSFTPServer.trigger_offset = 1024
    replacement = b"C" * 4096
    MutatingSFTPServer.mutation = staticmethod(
        _overwrite_same_length(replacement)
    )
    client, tc, ts = _start_sftp(MutatingSFTPServer)
    try:
        with client.open(sftp_path, "r") as fh:
            report = fh.check_snapshot("sha256", block_size=512)
    finally:
        client.close()
        tc.close()
        ts.close()

    assert report.state == STATE_UNSTABLE
    # Local digests describe the mixed bytes actually read; at least one
    # server block (hashed before the rewrite) then disagrees.
    mismatched = [item for item in report.coverage if not item.digest_matches]
    assert mismatched or report.identity_before != report.identity_after
    assert report.instability_reasons


def test_snapshot_short_read_explicit_length(scratch_file):
    sftp_path, real_path = scratch_file
    with open(real_path, "wb") as fh:
        fh.write(b"Z" * 300)

    MutatingSFTPServer.trigger_offset = 0
    MutatingSFTPServer.mutation = staticmethod(_truncate_to(100))
    client, tc, ts = _start_sftp(MutatingSFTPServer)
    try:
        with client.open(sftp_path, "r") as fh:
            report = fh.check_snapshot("sha256", offset=0, length=300)
    finally:
        client.close()
        tc.close()
        ts.close()

    assert report.state == STATE_UNSTABLE
    assert report.ended_early is True
    assert report.eof_reached is True
    assert report.coverage[-1].short_read is True
    assert report.bytes_read < 300


# --- remote digests are never trusted as provenance evidence ---------------


def test_forged_server_digest_is_caught(scratch_file):
    sftp_path, real_path = scratch_file
    data = b"forgery target" * 64
    with open(real_path, "wb") as fh:
        fh.write(data)

    FakeDigestServer.forged_blob = b"\x00" * hashlib.sha256().digest_size
    FakeDigestServer.forged_algorithm = "sha256"

    client, tc, ts = _start_sftp(
        StubSFTPServer, server_class=FakeDigestServer
    )
    try:
        with client.open(sftp_path, "r") as fh:
            report = fh.check_snapshot("sha256")
    finally:
        client.close()
        tc.close()
        ts.close()

    assert report.state == STATE_UNSTABLE
    assert report.server_supported is True
    assert report.coverage[0].server_digest == FakeDigestServer.forged_blob
    assert report.coverage[0].digest_matches is False
    assert report.coverage[0].local_digest == hashlib.sha256(data).digest()
    assert report.provenance_trusted is False
    assert any("digest mismatch" in r for r in report.instability_reasons)


def test_unsupported_check_file_is_unverifiable_not_stable(scratch_file):
    sftp_path, real_path = scratch_file
    payload = b"no extension here" * 10
    with open(real_path, "wb") as fh:
        fh.write(payload)

    client, tc, ts = _start_sftp(
        StubSFTPServer, server_class=UnsupportedCheckFileServer
    )
    try:
        with client.open(sftp_path, "r") as fh:
            report = fh.check_snapshot("sha256")
    finally:
        client.close()
        tc.close()
        ts.close()

    assert report.state == STATE_UNVERIFIABLE
    assert report.server_supported is False
    assert report.coverage[0].local_digest == hashlib.sha256(payload).digest()
    assert report.coverage[0].server_digest == b""
    assert any("check-file" in note for note in report.notes)


# --- local validation, read budget and no re-open --------------------------


@pytest.mark.parametrize("bad_name", ["sha3-256", "SHA256", "rmd160", ""])
def test_arbitrary_hash_names_are_rejected_locally(sftp, bad_name):
    path = sftp.FOLDER + "/hash.bin"
    with sftp.open(path, "w") as fh:
        fh.write(b"abc")
    with sftp.open(path, "r") as fh:
        with pytest.raises(ValueError):
            fh.check_snapshot(bad_name)
    sftp.unlink(path)


def test_allowed_algorithms_are_fixed_allowlist():
    assert ALLOWED_HASH_ALGORITHMS == ("sha256", "sha1", "md5")
    for name in ALLOWED_HASH_ALGORITHMS:
        hashlib.new(name)


def test_read_budget_is_enforced(sftp):
    path = sftp.FOLDER + "/budget.bin"
    with sftp.open(path, "w") as fh:
        fh.write(b"q" * 4096)

    with sftp.open(path, "r") as fh:
        with pytest.raises(ValueError):
            fh.check_snapshot("sha256", length=4096, max_bytes=1024)
        # A within-budget request works and never exceeds its ceiling.
        report = fh.check_snapshot(
            "sha256", length=1024, max_bytes=1024, block_size=256
        )
    assert report.state == STATE_STABLE
    assert report.bytes_read == 1024
    assert report.max_bytes == 1024
    sftp.unlink(path)


def test_default_budget_constant_is_bounded():
    assert DEFAULT_MAX_BYTES == 16 * 1024 * 1024


def test_invalid_arguments_raise_locally(sftp):
    path = sftp.FOLDER + "/args.bin"
    with sftp.open(path, "w") as fh:
        fh.write(b"abcd" * 128)
    with sftp.open(path, "r") as fh:
        with pytest.raises(ValueError):
            fh.check_snapshot("sha256", offset=-1)
        with pytest.raises(ValueError):
            fh.check_snapshot("sha256", length=-1)
        with pytest.raises(ValueError):
            fh.check_snapshot("sha256", block_size=255)
        with pytest.raises(ValueError):
            fh.check_snapshot("sha256", max_bytes=0)
    sftp.unlink(path)


def test_check_never_reopens_the_path(sftp, monkeypatch):
    path = sftp.FOLDER + "/reopen.bin"
    with sftp.open(path, "w") as fh:
        fh.write(b"never reopen me" * 32)

    with sftp.open(path, "r") as fh:
        original_request = fh.sftp._request

        def guarded_request(t, *args):
            # CMD_OPEN would mean a second handle (re-open) was created.
            from paramiko.sftp import CMD_OPEN

            assert t != CMD_OPEN, "check_snapshot must not re-open the file"
            return original_request(t, *args)

        monkeypatch.setattr(fh.sftp, "_request", guarded_request)
        report = fh.check_snapshot("sha256", block_size=256)

    assert report.state == STATE_STABLE
    sftp.unlink(path)
