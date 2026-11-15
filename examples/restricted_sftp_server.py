"""
Example: a multi-user SFTP server whose file creation is policy-restricted.

Run the built-in self-test (real SSH transport, real SFTP requests, a
temporary directory; no network binding needed):

    python examples/restricted_sftp_server.py

Serve the same policy to real clients on a TCP port:

    python examples/restricted_sftp_server.py --listen 127.0.0.1:2222

Each authenticated username gets its own root directory and its own
`SFTPPermissionPolicy` instance.  A fresh interface (and therefore a fresh
policy) is created for every SFTP session, and no code here touches the
process umask.
"""

import argparse
import os
import socket
import stat
import sys
import tempfile
import threading

import paramiko
from paramiko.sftp_policy import (
    RestrictedSFTPServerInterface,
    SFTPPermissionPolicy,
)


# DEMO ONLY: accept any password; replace with real authentication.
class DemoServer(paramiko.ServerInterface):
    def __init__(self):
        self.username = None

    def check_auth_password(self, username, password):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED


def policy_for(username):
    """Return the permission policy for one user."""
    return SFTPPermissionPolicy(
        default_file_mode=0o600,
        allowed_file_mode=0o600,
        default_directory_mode=0o700,
        allowed_directory_mode=0o700,
        allow_truncate=True,
        allow_chmod=True,
    )


class PolicyServer:
    """
    Paramiko SFTP server which builds one interface per SFTP session.

    `Transport.set_subsystem_handler` stores its extra constructor arguments
    once.  We pass a *factory* instead of a shared interface object, so
    Paramiko calls it once per ``sftp`` subsystem request:

        factory(server) -> RestrictedSFTPServerInterface

    The factory reads the authenticated username from that session's
    `ServerInterface` and returns an interface with a new policy.
    """

    def __init__(self, roots, host_key=None, created_callback=None):
        self.roots = roots
        self.host_key = host_key or paramiko.RSAKey.generate(2048)
        self.created_callback = created_callback

    def _root_for(self, server):
        username = server.username or "anonymous"
        try:
            return self.roots[username]
        except KeyError:
            raise paramiko.SSHException("unknown user")

    def session_interface(self, server):
        """
        Build the interface for one SFTP session.

        Paramiko calls this through ``SFTPServer``'s ``sftp_si`` argument.
        It receives the session's own `ServerInterface`, so the username
        (and therefore the root and policy) belongs to this session only.
        """
        username = getattr(server, "username", None) or "anonymous"
        root = self._root_for(server)
        policy = policy_for(username)

        def observe(path, mode):
            if self.created_callback is not None:
                self.created_callback(username, path, mode)

        return RestrictedSFTPServerInterface(
            server, root, policy=policy, created_hook=observe
        )

    def wrap(self, sock, server=None):
        transport = paramiko.Transport(sock)
        transport.add_server_key(self.host_key)
        transport.set_subsystem_handler(
            "sftp", paramiko.SFTPServer, self.session_interface
        )
        # Start asynchronously so a caller (or accept loop) can service the
        # other end of the connection immediately.  Negotiation failures show
        # up in Paramiko's transport logs and via is_active().
        event = threading.Event()
        transport.start_server(event, server or DemoServer())
        return transport

    def serve_forever(self, host, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(16)
        try:
            while True:
                sock, _addr = listener.accept()
                transport = self.wrap(sock)
                threading.Thread(
                    target=transport.join, daemon=True
                ).start()
        finally:
            listener.close()


def run_real_session(root, policy, username):
    """
    Run one real SSH/SFTP session over a socketpair and return a report.

    This uses the actual protocol path: the client asks for mode 0777 and the
    server's policy decides what is created.  The server-side hook records
    the mode at the moment the file first exists.
    """
    observed = []
    client_sock, server_sock = socket.socketpair()
    transport = paramiko.Transport(server_sock)
    transport.add_server_key(paramiko.RSAKey.generate(2048))
    transport.set_subsystem_handler(
        "sftp",
        paramiko.SFTPServer,
        _ObservedInterface,
        root,
        policy,
        observed,
    )
    event = threading.Event()
    transport.start_server(event, DemoServer())
    event.wait(5)

    client_transport = paramiko.Transport(client_sock)
    client_transport.connect(username=username, password="demo")
    sftp = paramiko.SFTPClient.from_transport(client_transport)
    report = []
    try:
        with sftp.open("/created.txt", "w") as f:
            f.write(b"created through SFTP\n")
        path = os.path.join(root, "created.txt")
        # `observed` is filled by the server-side hook before the open reply
        # is sent, and the hook also records the path's first visible mode.
        report.append(("at first visibility", oct(observed[0])))
        report.append(
            ("mode on disk", oct(stat.S_IMODE(os.stat(path).st_mode)))
        )
        with sftp.open("/created.txt", "r") as f:
            report.append(("content", f.read().decode().strip()))
        try:
            sftp.chmod("/created.txt", 0o644)
        except IOError:
            report.append(("widen to 0644", "denied"))
        else:
            report.append(("widen to 0644", "ALLOWED (bug)"))
        sftp.chmod("/created.txt", 0o600)
        report.append(("set 0600 within cap", "allowed"))
        report.append(
            (
                "mode after setstat",
                oct(stat.S_IMODE(os.stat(path).st_mode)),
            )
        )
    finally:
        sftp.close()
        client_transport.close()
        transport.close()
    return report


class _ObservedInterface(RestrictedSFTPServerInterface):
    def __init__(self, server, root, policy, observed):
        super().__init__(server, root, policy=policy)
        self._observed = observed

    def _file_created(self, path, mode):
        self._observed.append(stat.S_IMODE(os.lstat(path).st_mode))


def self_test():
    with tempfile.TemporaryDirectory() as root_a, (
        tempfile.TemporaryDirectory()
    ) as root_b:
        print("Session A (policy: files 0600, cap 0600) in", root_a)
        report = run_real_session(root_a, policy_for("alice"), "alice")
        for key, value in report:
            print("  {:24} {}".format(key, value))

        # A second simultaneous-style session with a different policy does
        # not inherit anything from the first one.
        other = SFTPPermissionPolicy(
            default_file_mode=0o640,
            allowed_file_mode=0o640,
            allow_chmod=True,
        )
        print("Session B (policy: files 0640, cap 0640) in", root_b)
        for key, value in run_real_session(root_b, other, "bob"):
            print("  {:24} {}".format(key, value))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="policy-restricted SFTP server example"
    )
    parser.add_argument(
        "--listen",
        metavar="HOST:PORT",
        help="serve real SSH clients instead of running the self-test",
    )
    parser.add_argument(
        "--root", default=os.getcwd(), help="directory served to all users"
    )
    args = parser.parse_args(argv)
    if not args.listen:
        return self_test()

    host, _, port = args.listen.rpartition(":")
    root = os.path.realpath(args.root)
    os.makedirs(root, exist_ok=True)
    server = PolicyServer(_AnyUserRoot(root))
    print("serving {} on {}:{}".format(root, host, port))
    server.serve_forever(host, int(port))


class _AnyUserRoot(dict):
    """Serve the same root to every username (demo convenience)."""

    def __init__(self, root):
        super().__init__()
        self._root = root

    def __getitem__(self, username):
        return self._root


if __name__ == "__main__":
    sys.exit(main())
