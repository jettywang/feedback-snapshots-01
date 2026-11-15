"""
Tests for policy-enforced SFTP file creation.

Every test goes through a real SSH transport and real SFTP protocol
requests.  The helper starts a server and a client on a socketpair so the
tests also work in network-restricted sandboxes.
"""

import os
import socket
import stat
import tempfile
import threading
from unittest import mock

import pytest

from paramiko import (
    AUTH_SUCCESSFUL,
    OPEN_SUCCEEDED,
    RSAKey,
    SFTPAttributes,
    SFTPServer,
    ServerInterface,
    Transport,
)
from paramiko.common import o600, o644, o700, o777

o640 = 0o640
from paramiko.sftp import (
    CMD_CLOSE,
    CMD_HANDLE,
    CMD_OPEN,
    CMD_SETSTAT,
    CMD_WRITE,
    SFTP_FLAG_CREATE,
    SFTP_FLAG_EXCL,
    SFTP_FLAG_WRITE,
    int64,
)
from paramiko.sftp_client import SFTPClient
from paramiko.sftp_policy import (
    RestrictedSFTPServerInterface,
    SFTPPermissionPolicy,
)

from ._util import _support


class _Server(ServerInterface):
    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


class _Session:
    """
    One live SSH server + SFTP client, with a policy and observation hook.

    ``created`` records ``(path, mode)`` from the server side at the moment
    the kernel has created the file and before control returns to the SFTP
    request, which is the first point the path can be observed.
    """

    def __init__(
        self,
        root,
        policy,
        interface_cls=RestrictedSFTPServerInterface,
        extra_interface_kwargs=None,
    ):
        self.root = root
        self.policy = policy
        self.created = []
        self._created_lock = threading.Lock()
        self._client_sock, server_sock = socket.socketpair()
        self.server_transport = Transport(server_sock)
        self.server_transport.add_server_key(
            RSAKey.from_private_key_file(_support("rsa.key"))
        )
        event = threading.Event()
        kwargs = {"policy": policy, "created_hook": self._record_created}
        kwargs.update(extra_interface_kwargs or {})
        self.server_transport.set_subsystem_handler(
            "sftp", SFTPServer, interface_cls, root, **kwargs
        )
        self.server_transport.start_server(event, _Server())
        event.wait(1.0)
        self.client_transport = Transport(self._client_sock)
        self.client_transport.connect(username="policy-user", password="x")
        self.sftp = SFTPClient.from_transport(self.client_transport)

    def _record_created(self, path, mode):
        # The hook runs after the kernel has created the path but before the
        # SFTP handle is returned, so this is the first observable state.
        visible = stat.S_IMODE(os.lstat(path).st_mode)
        with self._created_lock:
            self.created.append((path, mode, visible))

    def modes(self):
        with self._created_lock:
            return [mode for _path, mode, _visible in self.created]

    def close(self):
        try:
            self.sftp.close()
        finally:
            self.client_transport.close()
            self.server_transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


def _modes_for(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _raw_open(sftp, path, flags, attr):
    t, msg = sftp._request(CMD_OPEN, path, flags, attr)
    if t != CMD_HANDLE:
        raise AssertionError("expected a handle, got {}".format(t))
    return msg.get_binary()


def _protocol_write(sftp, handle, offset, data):
    sftp._request(CMD_WRITE, handle, int64(offset), data)


def _protocol_close(sftp, handle):
    sftp._request(CMD_CLOSE, handle)


def _requested_attr(mode=None, uid=None, gid=None, extra=None):
    attr = SFTPAttributes()
    if mode is not None:
        attr.st_mode = mode
    if uid is not None:
        attr.st_uid, attr.st_gid = uid, gid
    if extra:
        attr.attr.update(extra)
    return attr


pytestmark = pytest.mark.skipif(
    not hasattr(socket, "socketpair"), reason="requires socketpair"
)


@pytest.fixture(autouse=True)
def known_umask():
    """
    Give the tests a known umask so expected modes are deterministic.

    Creation honours the process umask (it can only make the result
    narrower); the implementation must never change it.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


class TestCreationObservation:
    def test_first_visible_mode_is_already_restricted(self):
        """
        A create request asking for 0777 must be observable as 0600 at the
        first moment the path exists; there must be no later chmod step.
        """
        with tempfile.TemporaryDirectory() as root:
            root = os.path.realpath(root)
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o600
            )
            with _Session(root, policy) as sess:
                path = os.path.join(root, "first")
                handle = _raw_open(
                    sess.sftp,
                    "/first",
                    SFTP_FLAG_WRITE | SFTP_FLAG_CREATE | SFTP_FLAG_EXCL,
                    _requested_attr(mode=o777),
                )
                _protocol_close(sess.sftp, handle)
                assert sess.created == [(path, o600, o600)]
                assert _modes_for(path) == o600
                assert os.path.getsize(path) == 0

    def test_create_never_calls_chmod(self):
        """
        The creation path must not rely on chmod.  Patch both chmod entry
        points to fail loudly and create a 0777-requesting file; the request
        succeeds because the final mode was supplied to open() itself.
        """
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o600
            )
            with _Session(root, policy) as sess:
                with mock.patch(
                    "os.chmod", side_effect=AssertionError("chmod called")
                ) as chmod, mock.patch(
                    "os.fchmod", side_effect=AssertionError("fchmod called")
                ) as fchmod:
                    handle = _raw_open(
                        sess.sftp,
                        "/no-chmod",
                        SFTP_FLAG_WRITE
                        | SFTP_FLAG_CREATE
                        | SFTP_FLAG_EXCL,
                        _requested_attr(mode=o777),
                    )
                    _protocol_write(sess.sftp, handle, 0, b"x")
                    _protocol_close(sess.sftp, handle)
                assert chmod.call_count == 0
                assert fchmod.call_count == 0
                path = os.path.join(root, "no-chmod")
                assert _modes_for(path) == o600
                assert sess.modes() == [o600]

    def test_umask_is_never_touched(self):
        """
        The handler must not read or write the process umask.  A mock that
        fails on any call proves neither creation nor a later setstat relies
        on changing global state.
        """
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600,
                allowed_file_mode=o640,
                allow_chmod=True,
                allow_setstat_size=True,
            )
            with _Session(root, policy) as sess:
                with mock.patch(
                    "os.umask",
                    side_effect=AssertionError("umask touched"),
                ) as umask:
                    with sess.sftp.open("/umask", "w") as f:
                        f.write(b"x")
                    sess.sftp.chmod("/umask", o640)
                    sess.sftp.truncate("/umask", 0)
                assert umask.call_count == 0
                assert _modes_for(os.path.join(root, "umask")) == o640

    def test_open_receives_final_policy_mode(self):
        """
        The mode handed to the creation syscall is already the policy result;
        no wider mode is ever passed and tightened afterwards.
        """
        real_open = os.open
        calls = []

        def recording_open(path, flags, mode=0o777, *args, **kwargs):
            if flags & os.O_CREAT:
                calls.append((path, mode))
            return real_open(path, flags, mode, *args, **kwargs)

        with tempfile.TemporaryDirectory() as root:
            root = os.path.realpath(root)
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o640
            )
            with _Session(root, policy) as sess:
                with mock.patch("os.open", side_effect=recording_open):
                    handle = _raw_open(
                        sess.sftp,
                        "/final",
                        SFTP_FLAG_WRITE
                        | SFTP_FLAG_CREATE
                        | SFTP_FLAG_EXCL,
                        _requested_attr(mode=o777),
                    )
                    _protocol_close(sess.sftp, handle)
                assert calls == [(os.path.join(root, "final"), o640)]

    def test_default_mode_used_when_client_omits_mode(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o640
            )
            with _Session(root, policy) as sess:
                handle = _raw_open(
                    sess.sftp,
                    "/defaulted",
                    SFTP_FLAG_WRITE
                    | SFTP_FLAG_CREATE
                    | SFTP_FLAG_EXCL,
                    SFTPAttributes(),
                )
                _protocol_close(sess.sftp, handle)
                path = os.path.join(root, "defaulted")
                assert _modes_for(path) == o600
                assert sess.modes() == [o600]

    def test_failed_open_leaves_no_file_at_all(self):
        """
        If handle construction fails after creation, the new path is removed.
        While it existed, it was already restricted, so no wide empty file can
        survive even on the failure path.
        """

        class BrokenHandleInterface(RestrictedSFTPServerInterface):
            def _make_handle(self, fd, path, flags, policy, created):
                os.close(fd)
                raise RuntimeError("simulated handle failure")

        with tempfile.TemporaryDirectory() as root:
            root = os.path.realpath(root)
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o600
            )
            with _Session(root, policy, BrokenHandleInterface) as sess:
                path = os.path.join(root, "broken")
                with pytest.raises(IOError):
                    sess.sftp.open("/broken", "w")
                assert not os.path.exists(path)
                assert sess.created == [(path, o600, o600)]


class TestCreationSemantics:
    def test_create_mode_merges_policy_and_request(self):
        """
        The client's mode is a request only.  It is intersected with the
        server cap in the actual creation call; special bits disappear.
        """
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o640
            )
            with _Session(root, policy) as sess:
                path = os.path.join(root, "merged")
                requested = stat.S_IFREG | 0o777 | stat.S_ISUID
                handle = _raw_open(
                    sess.sftp,
                    "/merged",
                    SFTP_FLAG_WRITE | SFTP_FLAG_CREATE | SFTP_FLAG_EXCL,
                    _requested_attr(mode=requested),
                )
                _protocol_write(sess.sftp, handle, 0, b"hello")
                _protocol_close(sess.sftp, handle)
                assert _modes_for(path) == o640
                assert stat.S_IMODE(os.stat(path).st_mode) == o640
                assert sess.modes() == [o640]
                with sess.sftp.open("/merged", "r") as f:
                    assert f.read() == b"hello"

    def test_client_uid_gid_and_extended_attrs_do_not_apply(self):
        """
        Open-time uid/gid and extended attributes cannot expand the server
        policy, nor change ownership.
        """
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o600
            )
            with _Session(root, policy) as sess:
                path = os.path.join(root, "owned")
                uid = os.getuid() if hasattr(os, "getuid") else None
                gid = os.getgid() if hasattr(os, "getgid") else None
                handle = _raw_open(
                    sess.sftp,
                    "/owned",
                    SFTP_FLAG_WRITE | SFTP_FLAG_CREATE | SFTP_FLAG_EXCL,
                    _requested_attr(
                        mode=o777,
                        uid=(uid + 1) if uid is not None else 0,
                        gid=(gid + 1) if gid is not None else 0,
                        extra={"user.paramiko": b"expanded"},
                    ),
                )
                _protocol_write(sess.sftp, handle, 0, b"data")
                _protocol_close(sess.sftp, handle)
                st = os.stat(path)
                assert stat.S_IMODE(st.st_mode) == o600
                if uid is not None:
                    # The server process owns the file; the uid/gid values in
                    # the client request are ignored (the effective gid may
                    # legitimately equal 0 in a test sandbox).
                    assert st.st_uid == uid
                    # gid reflects the process/directory group, not the
                    # client's request; compare against a known non-matching
                    # sentinel rather than assuming the effective gid.
                    assert st.st_gid != (gid + 1)
                if hasattr(os, "listxattr"):
                    assert os.listxattr(path) == []

    def test_exclusive_create_never_touches_existing_file(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600,
                allowed_file_mode=o600,
                allow_truncate=True,
            )
            with _Session(root, policy) as sess:
                path = os.path.join(root, "exclusive")
                with sess.sftp.open("/exclusive", "wx") as f:
                    f.write(b"original")
                assert _modes_for(path) == o600
                with pytest.raises(IOError):
                    sess.sftp.open("/exclusive", "wx")
                assert sess.sftp.stat("/exclusive").st_size == 8
                assert _modes_for(path) == o600
                with sess.sftp.open("/exclusive", "r") as f:
                    assert f.read() == b"original"

    def test_truncate_denied_without_policy_permission(self):
        """
        O_TRUNC on an existing file is refused before the open, so neither
        contents nor mode change.
        """
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o600
            )
            with _Session(root, policy) as sess:
                path = os.path.join(root, "keep")
                with sess.sftp.open("/keep", "w") as f:
                    f.write(b"keep me")
                with pytest.raises(IOError):
                    sess.sftp.open("/keep", "w")
                assert sess.sftp.stat("/keep").st_size == 7
                assert _modes_for(path) == o600
                with sess.sftp.open("/keep", "r") as f:
                    assert f.read() == b"keep me"
                assert len(sess.created) == 1

    def test_truncate_allowed_does_not_reset_mode(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600,
                allowed_file_mode=o640,
                allow_truncate=True,
            )
            with _Session(root, policy) as sess:
                path = os.path.join(root, "truncate")
                handle = _raw_open(
                    sess.sftp,
                    "/truncate",
                    SFTP_FLAG_WRITE | SFTP_FLAG_CREATE | SFTP_FLAG_EXCL,
                    _requested_attr(mode=0o777),
                )
                _protocol_write(sess.sftp, handle, 0, b"12345678")
                _protocol_close(sess.sftp, handle)
                assert _modes_for(path) == o640
                with sess.sftp.open("/truncate", "w") as f:
                    f.write(b"xy")
                # Reopening an existing file must not re-run creation rules.
                assert _modes_for(path) == o640
                assert sess.sftp.stat("/truncate").st_size == 2

    def test_existing_file_open_keeps_its_mode(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o600
            )
            with _Session(root, policy) as sess:
                path = os.path.join(root, "existing")
                with sess.sftp.open("/existing", "w") as f:
                    f.write(b"abc")
                os.chmod(path, o640)
                handle = _raw_open(
                    sess.sftp,
                    "/existing",
                    SFTP_FLAG_WRITE,
                    _requested_attr(mode=o777),
                )
                _protocol_write(sess.sftp, handle, 0, b"Z")
                _protocol_close(sess.sftp, handle)
                assert _modes_for(path) == o640
                with sess.sftp.open("/existing", "r") as f:
                    assert f.read() == b"Zbc"

    def test_directory_mode_is_capped(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_directory_mode=o700,
                allowed_directory_mode=o700,
            )
            with _Session(root, policy) as sess:
                sess.sftp.mkdir("/dir", o777)
                path = os.path.join(root, "dir")
                assert _modes_for(path) == o700
                sess.sftp.rmdir("/dir")


class TestLaterSetstat:
    def test_setstat_extended_attributes_denied(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o600
            )
            with _Session(root, policy) as sess:
                with sess.sftp.open("/xattrs", "w") as f:
                    f.write(b"x")
                attr = SFTPAttributes()
                attr.attr = {"user.paramiko": b"injected"}
                with pytest.raises(IOError):
                    sess.sftp._request(CMD_SETSTAT, "/xattrs", attr)
                if hasattr(os, "listxattr"):
                    path = os.path.join(root, "xattrs")
                    assert os.listxattr(path) == []
                assert _modes_for(os.path.join(root, "xattrs")) == o600

    def test_chmod_and_truncate_denied_by_default(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600, allowed_file_mode=o600
            )
            with _Session(root, policy) as sess:
                path = os.path.join(root, "later")
                with sess.sftp.open("/later", "w") as f:
                    f.write(b"abcdef")
                with pytest.raises(IOError):
                    sess.sftp.chmod("/later", o600)
                with pytest.raises(IOError):
                    sess.sftp.chown("/later", 0, 0)
                with pytest.raises(IOError):
                    sess.sftp.truncate("/later", 3)
                assert _modes_for(path) == o600
                assert sess.sftp.stat("/later").st_size == 6
                # Timestamps do not widen access, so they remain available.
                sess.sftp.utime("/later", (100, 200))
                assert int(sess.sftp.stat("/later").st_mtime) == 200

    def test_chmod_within_cap_only(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600,
                allowed_file_mode=o640,
                allow_chmod=True,
            )
            with _Session(root, policy) as sess:
                path = os.path.join(root, "chmod")
                with sess.sftp.open("/chmod", "w") as f:
                    f.write(b"x")
                assert _modes_for(path) == o600
                sess.sftp.chmod("/chmod", o640)
                assert _modes_for(path) == o640
                sess.sftp.chmod("/chmod", o600)
                assert _modes_for(path) == o600
                with pytest.raises(IOError):
                    sess.sftp.chmod("/chmod", 0o644)
                assert _modes_for(path) == o600

                with sess.sftp.open("/chmod", "r+") as f:
                    f.chmod(o640)
                    assert f.stat().st_mode & o777 == o640
                    with pytest.raises(IOError):
                        f.chmod(o644)
                    with pytest.raises(IOError):
                        f.chown(0, 0)

    def test_setstat_size_only_when_policy_allows(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy(
                default_file_mode=o600,
                allowed_file_mode=o600,
                allow_setstat_size=True,
            )
            with _Session(root, policy) as sess:
                with sess.sftp.open("/size", "w") as f:
                    f.write(b"123456")
                sess.sftp.truncate("/size", 3)
                assert sess.sftp.stat("/size").st_size == 3
                with sess.sftp.open("/size", "r+") as f:
                    f.truncate(1)
                    assert f.stat().st_size == 1


class TestRootedInterface:
    def test_path_traversal_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as root:
            policy = SFTPPermissionPolicy()
            with _Session(root, policy) as sess:
                with pytest.raises(IOError):
                    sess.sftp.open("/../../etc/passwd", "r")
                with pytest.raises(IOError):
                    sess.sftp.open("/missing/../../etc/passwd", "w")

    def test_symlink_escape_is_refused_for_open_and_stat(self):
        with tempfile.TemporaryDirectory() as root, (
            tempfile.TemporaryDirectory()
        ) as outside:
            secret = os.path.join(outside, "secret")
            with open(secret, "w") as f:
                f.write("secret")
            os.symlink(secret, os.path.join(root, "escape"))
            policy = SFTPPermissionPolicy()
            with _Session(root, policy) as sess:
                with pytest.raises(IOError):
                    sess.sftp.open("/escape", "r")
                # stat follows the link, so it must also stay rooted.
                with pytest.raises(IOError):
                    sess.sftp.stat("/escape")
                # lstat does not follow it, so it can be listed safely.
                assert sess.sftp.lstat("/escape").st_mode


class TestConcurrentSessions:
    def test_sessions_with_different_policies_do_not_interfere(self):
        """
        Two simultaneous SFTP sessions, each with its own policy, create
        files at the same time.  Neither process umask nor the other session
        may change the result.
        """
        # The suite-level fixture already pins the umask; changing it here
        # would itself prove nothing about the implementation.
        original_umask = os.umask(0o022)
        try:
            with tempfile.TemporaryDirectory() as root_a, (
                tempfile.TemporaryDirectory()
            ) as root_b:
                policy_a = SFTPPermissionPolicy(
                    default_file_mode=o600, allowed_file_mode=o600
                )
                policy_b = SFTPPermissionPolicy(
                    default_file_mode=o640, allowed_file_mode=o640
                )
                barrier = threading.Barrier(2)
                errors = []
                results = {}

                def worker(name, root, policy, expected_mode):
                    try:
                        with _Session(root, policy) as sess:
                            barrier.wait()
                            for index in range(8):
                                filename = "/{}-{}".format(name, index)
                                handle = _raw_open(
                                    sess.sftp,
                                    filename,
                                    SFTP_FLAG_WRITE
                                    | SFTP_FLAG_CREATE
                                    | SFTP_FLAG_EXCL,
                                    _requested_attr(mode=o777),
                                )
                                _protocol_write(
                                    sess.sftp,
                                    handle,
                                    0,
                                    name.encode("ascii"),
                                )
                                _protocol_close(sess.sftp, handle)
                            results[name] = (
                                sess.modes(),
                                [
                                    _modes_for(
                                        os.path.join(
                                            root, "{}-{}".format(name, i)
                                        )
                                    )
                                    for i in range(8)
                                ],
                            )
                    except Exception as e:  # pragma: nocover
                        errors.append(e)

                threads = [
                    threading.Thread(
                        target=worker,
                        args=("alpha", root_a, policy_a, o600),
                    ),
                    threading.Thread(
                        target=worker,
                        args=("beta", root_b, policy_b, o640),
                    ),
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(10)
                    assert not thread.is_alive()

                assert not errors
                for name, expected in (("alpha", o600), ("beta", o640)):
                    observed, on_disk = results[name]
                    assert observed == [expected] * 8
                    assert on_disk == [expected] * 8
                    root = root_a if name == "alpha" else root_b
                    first = os.path.join(root, "{}-0".format(name))
                    with open(first, "rb") as f:
                        assert f.read() == name.encode("ascii")

                # The umask observed here is the one the fixture established;
                # neither worker nor interface may have changed it.
                assert os.umask(0o022) == 0o022
        finally:
            os.umask(original_umask)
