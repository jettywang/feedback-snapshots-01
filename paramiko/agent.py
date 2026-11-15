# Copyright (C) 2003-2007  John Rochester <john@jrochester.org>
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
SSH Agent interface
"""

import os
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
from logging import DEBUG
from select import select

from paramiko.common import byte_chr, io_sleep
from paramiko.message import Message
from paramiko.pkey import PKey, UnknownKeyType
from paramiko.ssh_exception import AuthenticationException, SSHException
from paramiko.util import asbytes, get_logger

cSSH2_AGENTC_REQUEST_IDENTITIES = byte_chr(11)
SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENT_IDENTITIES_ANSWER = 12
cSSH2_AGENTC_SIGN_REQUEST = byte_chr(13)
SSH2_AGENTC_SIGN_REQUEST = 13
SSH2_AGENT_SIGN_RESPONSE = 14

# Generic agent replies, plus the request types which can change the state of a
# real agent. Only identity enumeration and signing may ever be forwarded by a
# restricted forwarder; everything else is denied by default.
SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
cSSH2_AGENTC_ADD_IDENTITY = byte_chr(17)
cSSH2_AGENTC_REMOVE_IDENTITY = byte_chr(18)
cSSH2_AGENTC_REMOVE_ALL_IDENTITIES = byte_chr(19)
cSSH2_AGENTC_LOCK = byte_chr(22)
cSSH2_AGENTC_UNLOCK = byte_chr(23)
cSSH2_AGENTC_ADD_ID_CONSTRAINED = byte_chr(25)
cSSH2_AGENTC_EXTENSION = byte_chr(27)

SSH_AGENT_RSA_SHA2_256 = 2
SSH_AGENT_RSA_SHA2_512 = 4
# NOTE: RFC mildly confusing; while these flags are OR'd together, OpenSSH at
# least really treats them like "AND"s, in the sense that if it finds the
# SHA256 flag set it won't continue looking at the SHA512 one; it
# short-circuits right away.
# Thus, we never want to eg submit 6 to say "either's good".
ALGORITHM_FLAG_MAP = {
    "rsa-sha2-256": SSH_AGENT_RSA_SHA2_256,
    "rsa-sha2-512": SSH_AGENT_RSA_SHA2_512,
}
for key, value in list(ALGORITHM_FLAG_MAP.items()):
    ALGORITHM_FLAG_MAP[f"{key}-cert-v01@openssh.com"] = value


# TODO (backwards incompat): rename all these - including making some of their
# methods public?
class AgentSSH:
    def __init__(self):
        self._conn = None
        self._keys = ()

    def get_keys(self):
        """
        Return the list of keys available through the SSH agent, if any.  If
        no SSH agent was running (or it couldn't be contacted), an empty list
        will be returned.

        This method performs no IO, just returns the list of keys retrieved
        when the connection was made.

        :return:
            a tuple of `.AgentKey` objects representing keys available on the
            SSH agent
        """
        return self._keys

    def _connect(self, conn):
        self._conn = conn
        ptype, result = self._send_message(cSSH2_AGENTC_REQUEST_IDENTITIES)
        if ptype != SSH2_AGENT_IDENTITIES_ANSWER:
            raise SSHException("could not get keys from ssh-agent")
        keys = []
        for i in range(result.get_int()):
            keys.append(
                AgentKey(
                    agent=self,
                    blob=result.get_binary(),
                    comment=result.get_text(),
                )
            )
        self._keys = tuple(keys)

    def _close(self):
        if self._conn is not None:
            self._conn.close()
        self._conn = None
        self._keys = ()

    def _send_message(self, msg):
        msg = asbytes(msg)
        self._conn.send(struct.pack(">I", len(msg)) + msg)
        data = self._read_all(4)
        msg = Message(self._read_all(struct.unpack(">I", data)[0]))
        return ord(msg.get_byte()), msg

    def _read_all(self, wanted):
        result = self._conn.recv(wanted)
        while len(result) < wanted:
            if len(result) == 0:
                raise SSHException("lost ssh-agent")
            extra = self._conn.recv(wanted - len(result))
            if len(extra) == 0:
                raise SSHException("lost ssh-agent")
            result += extra
        return result


class AgentProxyThread(threading.Thread):
    """
    Class in charge of communication between two channels.
    """

    def __init__(self, agent):
        threading.Thread.__init__(self, target=self.run)
        self._agent = agent
        self._exit = False

    def run(self):
        try:
            (r, addr) = self.get_connection()
            # Found that r should be either
            # a socket from the socket library or None
            self.__inr = r
            # The address should be an IP address as a string? or None
            self.__addr = addr
            self._agent.connect()
            if not isinstance(self._agent, int) and (
                self._agent._conn is None
                or not hasattr(self._agent._conn, "fileno")
            ):
                raise AuthenticationException("Unable to connect to SSH agent")
            self._communicate()
        except:
            # XXX Not sure what to do here ... raise or pass ?
            raise

    def _communicate(self):
        import fcntl

        oldflags = fcntl.fcntl(self.__inr, fcntl.F_GETFL)
        fcntl.fcntl(self.__inr, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)
        while not self._exit:
            events = select([self._agent._conn, self.__inr], [], [], 0.5)
            for fd in events[0]:
                if self._agent._conn == fd:
                    data = self._agent._conn.recv(512)
                    if len(data) != 0:
                        self.__inr.send(data)
                    else:
                        self._close()
                        break
                elif self.__inr == fd:
                    data = self.__inr.recv(512)
                    if len(data) != 0:
                        self._agent._conn.send(data)
                    else:
                        self._close()
                        break
            time.sleep(io_sleep)

    def _close(self):
        self._exit = True
        self.__inr.close()
        self._agent._conn.close()


class AgentLocalProxy(AgentProxyThread):
    """
    Class to be used when wanting to ask a local SSH Agent being
    asked from a remote fake agent (so use a unix socket for ex.)
    """

    def __init__(self, agent):
        AgentProxyThread.__init__(self, agent)

    def get_connection(self):
        """
        Return a pair of socket object and string address.

        May block!
        """
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.bind(self._agent._get_filename())
            conn.listen(1)
            (r, addr) = conn.accept()
            return r, addr
        except:
            raise


class AgentRemoteProxy(AgentProxyThread):
    """
    Class to be used when wanting to ask a remote SSH Agent
    """

    def __init__(self, agent, chan):
        AgentProxyThread.__init__(self, agent)
        self.__chan = chan

    def get_connection(self):
        return self.__chan, None


def get_agent_connection():
    """
    Returns some SSH agent object, or None if none were found/supported.

    .. versionadded:: 2.10
    """
    if ("SSH_AUTH_SOCK" in os.environ) and (sys.platform != "win32"):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.connect(os.environ["SSH_AUTH_SOCK"])
            return conn
        except:
            # probably a dangling env var: the ssh agent is gone
            return
    elif sys.platform == "win32":
        from . import win_openssh, win_pageant

        conn = None
        if win_pageant.can_talk_to_agent():
            conn = win_pageant.PageantConnection()
        elif win_openssh.can_talk_to_agent():
            conn = win_openssh.OpenSSHAgentConnection()
        return conn
    else:
        # no agent support
        return


class AgentClientProxy:
    """
    Class proxying request as a client:

    #. client ask for a request_forward_agent()
    #. server creates a proxy and a fake SSH Agent
    #. server ask for establishing a connection when needed,
       calling the forward_agent_handler at client side.
    #. the forward_agent_handler launch a thread for connecting
       the remote fake agent and the local agent
    #. Communication occurs ...
    """

    def __init__(self, chanRemote):
        self._conn = None
        self.__chanR = chanRemote
        self.thread = AgentRemoteProxy(self, chanRemote)
        self.thread.start()

    def __del__(self):
        self.close()

    def connect(self):
        """
        Method automatically called by ``AgentProxyThread.run``.
        """
        conn = get_agent_connection()
        if not conn:
            return
        self._conn = conn

    def close(self):
        """
        Close the current connection and terminate the agent
        Should be called manually
        """
        if hasattr(self, "thread"):
            self.thread._exit = True
            self.thread.join(1000)
        if self._conn is not None:
            self._conn.close()


class AgentServerProxy(AgentSSH):
    """
    Allows an SSH server to access a forwarded agent.

    This also creates a unix domain socket on the system to allow external
    programs to also access the agent. For this reason, you probably only want
    to create one of these.

    :meth:`connect` must be called before it is usable. This will also load the
    list of keys the agent contains. You must also call :meth:`close` in
    order to clean up the unix socket and the thread that maintains it.
    (:class:`contextlib.closing` might be helpful to you.)

    :param .Transport t: Transport used for SSH Agent communication forwarding

    :raises: `.SSHException` -- mostly if we lost the agent
    """

    def __init__(self, t):
        AgentSSH.__init__(self)
        self.__t = t
        self._dir = tempfile.mkdtemp("sshproxy")
        os.chmod(self._dir, stat.S_IRWXU)
        self._file = self._dir + "/sshproxy.ssh"
        self.thread = AgentLocalProxy(self)
        self.thread.start()

    def __del__(self):
        self.close()

    def connect(self):
        conn_sock = self.__t.open_forward_agent_channel()
        if conn_sock is None:
            raise SSHException("lost ssh-agent")
        conn_sock.set_name("auth-agent")
        self._connect(conn_sock)

    def close(self):
        """
        Terminate the agent, clean the files, close connections
        Should be called manually
        """
        os.remove(self._file)
        os.rmdir(self._dir)
        self.thread._exit = True
        self.thread.join(1000)
        self._close()

    def get_env(self):
        """
        Helper for the environment under unix

        :return:
            a dict containing the ``SSH_AUTH_SOCK`` environment variables
        """
        return {"SSH_AUTH_SOCK": self._get_filename()}

    def _get_filename(self):
        return self._file


class AgentRequestHandler:
    """
    Primary/default implementation of SSH agent forwarding functionality.

    Simply instantiate this class, handing it a live command-executing session
    object, and it will handle forwarding any local SSH agent processes it
    finds.

    For example::

        # Connect
        client = SSHClient()
        client.connect(host, port, username)
        # Obtain session
        session = client.get_transport().open_session()
        # Forward local agent
        AgentRequestHandler(session)
        # Commands executed after this point will see the forwarded agent on
        # the remote end.
        session.exec_command("git clone https://my.git.repository/")

    To restrict such a session to specific keys and RSA signature algorithms,
    supply a policy; see `.RestrictedAgentRequestHandler` for a shorter
    spelling::

        policy = AgentForwardingPolicy(
            keys=[key], algorithms=["rsa-sha2-256"]
        )
        AgentRequestHandler(session, policy=policy)

    :param chanClient: the live command-executing session to forward over.
    :param policy:
        optional `.RestrictedAgentPolicy` / `.AgentForwardingPolicy`; when
        given, every forwarded connection is mediated by a fresh
        `.AgentForwardingSession` enforcing that policy instead of being
        passed to the local agent unfiltered.

    .. versionchanged:: 5.2
        Added the optional ``policy`` keyword argument.
    """

    def __init__(self, chanClient, policy=None):
        self._conn = None
        self._policy = policy
        self.__chanC = chanClient
        chanClient.request_forward_agent(self._forward_agent_handler)
        self.__clientProxys = []

    def _forward_agent_handler(self, chanRemote):
        if self._policy is None:
            proxy = AgentClientProxy(chanRemote)
        else:
            proxy = RestrictedAgentClientProxy(chanRemote, self._policy)
        self.__clientProxys.append(proxy)

    def __del__(self):
        self.close()

    def close(self):
        for p in self.__clientProxys:
            p.close()


class Agent(AgentSSH):
    """
    Client interface for using private keys from an SSH agent running on the
    local machine.  If an SSH agent is running, this class can be used to
    connect to it and retrieve `.PKey` objects which can be used when
    attempting to authenticate to remote SSH servers.

    Upon initialization, a session with the local machine's SSH agent is
    opened, if one is running. If no agent is running, initialization will
    succeed, but `get_keys` will return an empty tuple.

    :raises: `.SSHException` --
        if an SSH agent is found, but speaks an incompatible protocol

    .. versionchanged:: 2.10
        Added support for native openssh agent on windows (extending previous
        putty pageant support)
    """

    def __init__(self):
        AgentSSH.__init__(self)

        conn = get_agent_connection()
        if not conn:
            return
        self._connect(conn)

    def close(self):
        """
        Close the SSH agent connection.
        """
        self._close()


class AgentKey(PKey):
    """
    Private key held in a local SSH agent.  This type of key can be used for
    authenticating to a remote server (signing).  Most other key operations
    work as expected.

    .. versionchanged:: 3.2
        Added the ``comment`` kwarg and attribute.

    .. versionchanged:: 3.2
        Added the ``.inner_key`` attribute holding a reference to the 'real'
        key instance this key is a proxy for, if one was obtainable, else None.
    """

    def __init__(self, agent: Agent, blob: bytes, comment: str = ""):
        self.public_blob = None  # Match sibling key classes
        self.agent = agent
        self.blob = blob
        self.comment = comment
        msg = Message(blob)
        self.name = msg.get_text()
        self._logger = get_logger(__file__)
        self.inner_key = None
        try:
            self.inner_key = PKey.from_type_string(
                key_type=self.name, key_bytes=blob
            )
        except UnknownKeyType:
            # Log, but don't explode, since inner_key is a best-effort thing.
            err = "Unable to derive inner_key for agent key of type {!r}"
            self.log(DEBUG, err.format(self.name))

    def log(self, *args, **kwargs):
        return self._logger.log(*args, **kwargs)

    def asbytes(self):
        # Prefer inner_key.asbytes, since that will differ for eg RSA-CERT
        return self.inner_key.asbytes() if self.inner_key else self.blob

    def get_name(self):
        return self.name

    def get_bits(self):
        # Have to work around PKey's default get_bits being crap
        if self.inner_key is not None:
            return self.inner_key.get_bits()
        return super().get_bits()

    def __getattr__(self, name):
        """
        Proxy any un-implemented methods/properties to the inner_key.
        """
        if self.inner_key is None:  # nothing to proxy to
            raise AttributeError(name)
        return getattr(self.inner_key, name)

    @property
    def _fields(self):
        fallback = [self.get_name(), self.blob]
        return self.inner_key._fields if self.inner_key else fallback

    def sign_ssh_data(self, data, algorithm=None):
        msg = Message()
        msg.add_byte(cSSH2_AGENTC_SIGN_REQUEST)
        # NOTE: this used to be just self.blob, which is not entirely right for
        # RSA-CERT 'keys' - those end up always degrading to ssh-rsa type
        # signatures, for reasons probably internal to OpenSSH's agent code,
        # even if everything else wants SHA2 (including our flag map).
        msg.add_string(self.asbytes())
        msg.add_string(data)
        msg.add_int(ALGORITHM_FLAG_MAP.get(algorithm, 0))
        ptype, result = self.agent._send_message(msg)
        if ptype != SSH2_AGENT_SIGN_RESPONSE:
            raise SSHException("key cannot be used for signing")
        return result.get_binary()


# Maximum agent message size accepted by the restricted forwarder. Real
# identity answers and signatures are far smaller; this mostly keeps a hostile
# peer from making us buffer an unbounded frame.
MAX_AGENT_MESSAGE_SIZE = 16 * 1024 * 1024


def _failure_payload():
    """Return a bare ``SSH_AGENT_FAILURE`` agent response payload."""
    return byte_chr(SSH_AGENT_FAILURE)


def _empty_identities_payload():
    """Return an identity answer containing no keys."""
    msg = Message()
    msg.add_byte(byte_chr(SSH2_AGENT_IDENTITIES_ANSWER))
    msg.add_int(0)
    return asbytes(msg)


def _write_frame(conn, payload):
    """Write one length-prefixed agent message to a socket-like object."""
    payload = asbytes(payload)
    data = struct.pack(">I", len(payload)) + payload
    send = getattr(conn, "send", None)
    if send is not None:
        while data:
            sent = send(data)
            if not sent:
                raise SSHException("lost ssh-agent")
            data = data[sent:]
        return
    conn.sendall(data)


class _FramedReader:
    """
    Read length-prefixed agent messages from a socket-like object.

    ``recv`` is explicitly allowed to return partial data and multiple messages
    may arrive in a single call; leftover bytes are retained for the next
    read.
    """

    def __init__(
        self, conn, max_size=MAX_AGENT_MESSAGE_SIZE, should_stop=None
    ):
        self._conn = conn
        self._buffer = b""
        self._max_size = max_size
        self._should_stop = should_stop

    def _recv_chunk(self):
        while True:
            try:
                return self._conn.recv(65536)
            except socket.timeout:
                # Channel/socket objects may be in timeout mode; that is not
                # EOF, so keep waiting, but stop if the session was revoked.
                if self._should_stop is not None and self._should_stop():
                    return b""
                time.sleep(io_sleep)
                continue

    def read(self):
        """
        Return the next payload, or ``None`` on a clean EOF before a message.
        """
        while len(self._buffer) < 4:
            chunk = self._recv_chunk()
            if not chunk:
                if self._buffer:
                    raise SSHException(
                        "truncated ssh-agent message header"
                    )
                return None
            self._buffer += chunk
        length = struct.unpack(">I", self._buffer[:4])[0]
        if length > self._max_size:
            raise SSHException("ssh-agent message too large")
        total = 4 + length
        while len(self._buffer) < total:
            chunk = self._recv_chunk()
            if not chunk:
                raise SSHException("truncated ssh-agent message body")
            self._buffer += chunk
        payload = self._buffer[4:total]
        self._buffer = self._buffer[total:]
        return payload


class _PayloadReader:
    """
    Strict reader for an in-memory agent message.

    `.Message` pads short reads with zero bytes, which is fine for normal
    protocol use but unsuitable for a security boundary: a truncated request
    must be rejected, not silently completed. This helper raises
    `.SSHException` instead.
    """

    def __init__(self, data):
        self._data = asbytes(data)
        self._pos = 0

    def _take(self, size):
        end = self._pos + size
        if end > len(self._data):
            raise SSHException("truncated ssh-agent message")
        result = self._data[self._pos : end]
        self._pos = end
        return result

    def byte(self):
        return ord(self._take(1))

    def string(self):
        (length,) = struct.unpack(">I", self._take(4))
        return self._take(length)

    def int(self):
        (value,) = struct.unpack(">I", self._take(4))
        return value

    def done(self):
        return self._pos == len(self._data)


def _parse_sign_request(payload):
    """
    Strictly parse a sign request.

    Returns ``(key_blob, data, flags)`` or ``None`` when the request is
    malformed or has trailing bytes. The complete, exact public key blob is
    retained for policy comparison.
    """
    try:
        reader = _PayloadReader(payload)
        if reader.byte() != SSH2_AGENTC_SIGN_REQUEST:
            return None
        blob = reader.string()
        data = reader.string()
        flags = reader.int()
        if not reader.done():
            return None
        return blob, data, flags
    except SSHException:
        return None


def _parse_identity_request(payload):
    """Return True only for a well-formed, exactly-sized identity request."""
    try:
        reader = _PayloadReader(payload)
        if reader.byte() != SSH2_AGENTC_REQUEST_IDENTITIES:
            return False
        return reader.done()
    except SSHException:
        return False


def _parse_identities_answer(payload):
    """
    Parse a well-formed identity answer.

    Returns a list of ``(blob, comment)`` pairs, or ``None`` if the payload is
    not an identity answer (eg an agent failure). Malformed identity answers
    raise `.SSHException`.
    """
    reader = _PayloadReader(payload)
    if reader.byte() != SSH2_AGENT_IDENTITIES_ANSWER:
        return None
    count = reader.int()
    # Each entry consumes at least eight bytes (two empty strings). Reject
    # absurd counts before looping.
    remaining = len(payload) - reader._pos
    if count > remaining // 8:
        raise SSHException("malformed identities answer")
    entries = []
    for _ in range(count):
        blob = reader.string()
        comment = reader.string()
        entries.append((blob, comment))
    if not reader.done():
        raise SSHException("trailing data in identities answer")
    return entries


def _flags_for_algorithms(algorithms):
    """Map algorithm names to agent sign-request flag values."""
    if algorithms is None:
        return set()
    if isinstance(algorithms, str):
        algorithms = (algorithms,)
    flags = set()
    for algorithm in algorithms:
        if algorithm in ("ssh-rsa", None):
            flags.add(0)
            continue
        try:
            flags.add(ALGORITHM_FLAG_MAP[algorithm])
        except KeyError:
            raise SSHException(
                "Unknown or un-policyable signature algorithm: {!r}".format(
                    algorithm
                )
            )
    return flags


def _split_raw_blob(blob):
    """
    Split a raw public key blob into identity and sign-request material.

    A raw certificate blob cannot be compared directly against the underlying
    key blob a sign request carries, so attempt to derive the latter via
    `.AgentKey`'s best-effort inner key. Failure simply means both sides are
    the original blob.
    """
    try:
        name = Message(blob).get_text()
    except Exception:
        return blob, blob
    if not name.endswith("-cert-v01@openssh.com"):
        return blob, blob
    try:
        sign_blob = asbytes(AgentKey(agent=None, blob=blob).asbytes())
    except Exception:
        return blob, blob
    return blob, sign_blob


def _key_blobs(key):
    """
    Return ``(identity_blob, sign_blob)`` for a key or raw blob.

    For certificate-bearing keys these differ: an agent exposes the complete
    certificate blob during identity enumeration, but sign requests carry the
    underlying complete public key blob. Both are kept intact and compared
    byte-for-byte; no truncation or prefix matching is performed. Plain keys
    (and raw blobs) naturally yield the same value twice.
    """
    if isinstance(key, PKey):
        sign_blob = asbytes(key.asbytes())
        public_blob = getattr(key, "public_blob", None)
        if public_blob is not None:
            identity_blob = asbytes(public_blob.key_blob)
        else:
            blob = getattr(key, "blob", None)
            identity_blob = asbytes(blob) if blob else sign_blob
        return identity_blob, sign_blob
    return _split_raw_blob(asbytes(key))


def _blob_is_rsa(blob):
    """Best-effort detection of RSA key/certificate blobs."""
    try:
        name = Message(blob).get_text()
    except Exception:
        return False
    return name in (
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "rsa-sha2-256-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com",
        "ssh-rsa-cert-v01@openssh.com",
    )


class RestrictedKeyRule:
    """
    One allow-list entry for a restricted agent forwarder.

    The rule binds a single public key -- identified by its *complete* SSH
    public key blob, compared byte for byte -- to the exact set of sign-request
    ``flags`` values permitted for it.

    :param blob:
        the complete public key blob, or a `.PKey` whose ``asbytes`` yields it.
    :param str comment:
        optional comment to expose in filtered identity answers.
    :param allowed_flags:
        iterable of permitted integer flag words. Defaults to ``{0}``, i.e. an
        un-flagged (legacy ``ssh-rsa`` or non-RSA) signature.
    """

    def __init__(self, blob, comment="", allowed_flags=(0,)):
        if isinstance(blob, PKey):
            if not comment:
                comment = getattr(blob, "comment", "") or ""
            identity_blob, sign_blob = _key_blobs(blob)
        else:
            identity_blob, sign_blob = _split_raw_blob(asbytes(blob))
        if isinstance(allowed_flags, int):
            allowed_flags = (allowed_flags,)
        self.blob = identity_blob
        # Complete public key material sent in sign requests. For plain keys
        # this equals ``blob``; for certificates it is the underlying key.
        self.sign_blob = sign_blob
        self.comment = comment or ""
        self.allowed_flags = frozenset(int(flag) for flag in allowed_flags)

    def __repr__(self):
        return (
            "{}(blob={!r}, sign_blob={!r}, comment={!r}, "
            "allowed_flags={!r})"
        ).format(
            self.__class__.__name__,
            self.blob,
            self.sign_blob,
            self.comment,
            sorted(self.allowed_flags),
        )

    @classmethod
    def from_algorithms(cls, key, algorithms=(), comment=""):
        """
        Build a rule from a key/blob and named signature algorithms.

        Algorithm names are mapped through `.ALGORITHM_FLAG_MAP` (``ssh-rsa``
        maps to flag ``0``). An empty algorithm list yields the zero-flag rule.
        Unknown names raise `.SSHException` rather than being ignored.
        """
        flags = _flags_for_algorithms(algorithms)
        if not flags:
            flags = {0}
        return cls(key, comment=comment, allowed_flags=flags)

    @classmethod
    def from_flags(cls, key, flags, comment=""):
        """Build a rule from explicit agent flag values."""
        return cls(key, comment=comment, allowed_flags=flags)


class RestrictedAgentPolicy:
    """
    Locally-owned allow-list policy for restricted SSH agent forwarding.

    The policy answers two questions and denies everything else:

    * which identities an enumeration request may reveal, and
    * whether a sign request may proceed, based on both the *complete* public
      key blob and the exact ``flags`` word.

    Guest/host name strings sent by a remote peer are never consulted. A
    ``target`` may be supplied by the local application as a trusted binding,
    but it does not widen the key/algorithm allow-list; authorization is
    snapshotted when a forwarding session is created. With no trusted target
    binding, the guarantee is explicitly limited to the allowed keys and
    signature algorithms, not to the identity of the remote destination.

    :param rules:
        iterable of `.RestrictedKeyRule` objects.
    :param target:
        optional locally-trusted target identifier, recorded for callers. This
        is never read from the remote side.
    """

    def __init__(self, rules=(), target=None, **kwargs):
        # Identity-enumeration lookups are keyed by the full identity blob;
        # sign requests are looked up separately because certificate keys use
        # the underlying key blob there.
        self._rules = {}
        self._sign_rules = {}
        self.target = target
        # Convenience construction; all values are local/trusted.
        keys = kwargs.pop("keys", None)
        algorithms = kwargs.pop("algorithms", None)
        rsa_flags = kwargs.pop("rsa_flags", None)
        if kwargs:
            raise TypeError(
                "unexpected keyword arguments: {}".format(
                    ", ".join(sorted(kwargs))
                )
            )
        if isinstance(rules, RestrictedKeyRule):
            rules = (rules,)
        for rule in rules:
            self.add_rule(rule)
        if keys is not None:
            if isinstance(keys, (PKey, bytes)):
                keys = (keys,)
            if isinstance(keys, dict):
                for key, key_algorithms in keys.items():
                    self.allow(key, algorithms=key_algorithms)
            else:
                for key in keys:
                    if rsa_flags is not None:
                        self.add_rule(
                            RestrictedKeyRule.from_flags(key, rsa_flags)
                        )
                    else:
                        self.allow(key, algorithms=algorithms)

    def add_rule(self, rule):
        """Register a `.RestrictedKeyRule` and return it."""
        self._rules[rule.blob] = rule
        self._sign_rules[rule.sign_blob] = rule
        return rule

    def allow(self, key, algorithms=(), comment=""):
        """Allow ``key`` for the given named signature algorithms."""
        return self.add_rule(
            RestrictedKeyRule.from_algorithms(
                key, algorithms=algorithms, comment=comment
            )
        )

    @property
    def rules(self):
        """Tuple of configured `.RestrictedKeyRule` objects."""
        return tuple(self._rules.values())

    @property
    def key_blobs(self):
        """Frozenset of complete identity blobs allowed by this policy."""
        return frozenset(self._rules)

    @property
    def sign_blobs(self):
        """Frozenset of complete sign-request blobs allowed by this policy."""
        return frozenset(self._sign_rules)

    def identities(self):
        """
        Return the ``(blob, comment)`` pairs this policy permits exposing.
        """
        return [(rule.blob, rule.comment) for rule in self._rules.values()]

    def allows_key(self, blob):
        """Whether the complete public key ``blob`` is allowed."""
        return asbytes(blob) in self._rules

    def check_sign_request(self, blob, flags):
        """
        Return True only for an allowed exact sign blob and flags word.

        The blob is the complete public key material carried by the request,
        compared byte for byte; prefixes and truncated forms never match.
        """
        rule = self._sign_rules.get(asbytes(blob))
        return rule is not None and flags in rule.allowed_flags

    # Alias for callers that prefer the shorter name.
    allows_sign_request = check_sign_request

    def decide(self, message):
        """
        Inspect one complete agent request.

        :return:
            ``(verdict, payload)`` where verdict is ``"forward"``,
            ``"filter_identities"`` or ``"deny"``. The payload is the original
            request bytes for allowed requests, else ``None``.
        """
        payload = (
            message.asbytes()
            if hasattr(message, "asbytes")
            else asbytes(message)
        )
        try:
            reader = _PayloadReader(payload)
            ptype = reader.byte()
        except SSHException:
            return "deny", None
        if ptype == SSH2_AGENTC_REQUEST_IDENTITIES:
            return (
                ("filter_identities", payload)
                if _parse_identity_request(payload)
                else ("deny", None)
            )
        if ptype == SSH2_AGENTC_SIGN_REQUEST:
            request = _parse_sign_request(payload)
            if request is None:
                return "deny", None
            blob, _data, flags = request
            if self.check_sign_request(blob, flags):
                return "forward", payload
            return "deny", None
        # Unknown requests and all state-changing requests are denied.
        return "deny", None


class AgentForwardingPolicy(RestrictedAgentPolicy):
    """
    Simple key/algorithm allow-list policy for restricted agent forwarding.

    :param keys:
        iterable of `.PKey` objects and/or complete public key blobs (bytes)
        the remote session may see and sign with. A single key/blob is also
        accepted. Alternatively a ``{key: algorithms}`` mapping may be given
        to assign each key its own algorithm list.
    :param rsa_flags:
        iterable of allowed sign-request flag values
        (``SSH_AGENT_RSA_SHA2_256`` / ``SSH_AGENT_RSA_SHA2_512``), or their
        algorithm names (``"rsa-sha2-256"`` / ``"rsa-sha2-512"``). Flags are
        matched exactly; combined or unknown values are denied. Defaults to
        SHA2-256 for RSA keys. Non-RSA keys are always allowed with flag
        ``0`` only; RSA flag bits never widen a non-RSA key.
    :param algorithms:
        convenience alias for algorithm names; overrides the default when
        ``rsa_flags`` is not given.
    :param target:
        optional locally-trusted target binding (never remote input).

    .. versionadded:: 5.2
    """

    def __init__(
        self,
        keys=(),
        rsa_flags=None,
        algorithms=None,
        target=None,
        **kwargs,
    ):
        if "allowed_algorithms" in kwargs and algorithms is None:
            algorithms = kwargs.pop("allowed_algorithms")
        if "allowed_keys" in kwargs and not keys:
            keys = kwargs.pop("allowed_keys")
        if kwargs:
            raise TypeError(
                "unexpected keyword arguments: {}".format(
                    ", ".join(sorted(kwargs))
                )
            )
        if algorithms is not None and rsa_flags is None:
            flags = _flags_for_algorithms(algorithms)
            if not flags:
                flags = {0}
            rsa_flags = flags
        elif rsa_flags is None:
            rsa_flags = {SSH_AGENT_RSA_SHA2_256}
        elif isinstance(rsa_flags, int):
            rsa_flags = (rsa_flags,)
        elif isinstance(rsa_flags, str):
            flags = _flags_for_algorithms((rsa_flags,))
            rsa_flags = flags or {0}
        else:
            converted = set()
            for flag in rsa_flags:
                if isinstance(flag, str):
                    converted.update(_flags_for_algorithms((flag,)))
                else:
                    converted.add(int(flag))
            rsa_flags = converted
        self._rsa_flags = frozenset(rsa_flags)
        if isinstance(keys, (PKey, bytes)):
            keys = (keys,)
        if isinstance(keys, dict):
            # ``{key: algorithms}`` is the most explicit form; each key gets
            # its own algorithm list instead of the shared ``rsa_flags``.
            rules = [
                RestrictedKeyRule.from_algorithms(
                    key, algorithms=key_algorithms
                )
                for key, key_algorithms in keys.items()
            ]
        else:
            rules = []
            for key in keys:
                identity_blob, sign_blob = _key_blobs(key)
                if _blob_is_rsa(sign_blob):
                    allowed = set(self._rsa_flags)
                else:
                    # Non-RSA agent keys (ed25519, ecdsa, ...) sign with flag
                    # 0; RSA flag bits never widen them.
                    allowed = {0}
                rule = RestrictedKeyRule(
                    identity_blob,
                    comment=getattr(key, "comment", "") or "",
                    allowed_flags=allowed,
                )
                rule.sign_blob = sign_blob
                rules.append(rule)
        RestrictedAgentPolicy.__init__(self, rules, target=target)

    @property
    def rsa_flags(self):
        """Frozenset of configured RSA sign-request flag values."""
        return self._rsa_flags

    def allows_sign_flags(self, flags):
        """Whether ``flags`` is one of the configured allowed flag values."""
        return flags in self._rsa_flags


class AgentForwardingSession:
    """
    Snapshot of a `.RestrictedAgentPolicy`, bound to one forwarding session.

    A new session is created for each accepted forwarded connection, copying
    the policy rules at that moment. Later mutation of the original policy
    cannot widen an already-authorized session, and :meth:`close` permanently
    revokes it. This is the "authorization belongs to the current forwarding
    session" requirement; no target name supplied by the remote peer is ever
    consulted.
    """

    def __init__(self, policy):
        if not isinstance(policy, RestrictedAgentPolicy):
            if not hasattr(policy, "rules"):
                raise TypeError("a restricted agent policy is required")
        self._closed = False
        self.target = getattr(policy, "target", None)
        self._rules = {}
        self._sign_rules = {}
        for rule in policy.rules:
            entry = (frozenset(rule.allowed_flags), rule.comment)
            self._rules[rule.blob] = entry
            self._sign_rules[rule.sign_blob] = entry

    @property
    def authorized(self):
        """False once this forwarding session has been closed."""
        return not self._closed

    @property
    def closed(self):
        return self._closed

    @property
    def target(self):
        """Locally-supplied target binding, or None when not available."""
        return self._target

    @target.setter
    def target(self, value):
        self._target = value

    def close(self):
        """Revoke this session's authorization for good."""
        self._closed = True

    def identities(self):
        """Return allowed ``(blob, comment)`` pairs."""
        if self._closed:
            return []
        return [
            (blob, comment) for blob, (_, comment) in self._rules.items()
        ]

    def identities_map(self):
        """Return allowed keys as a ``{blob: comment}`` dict."""
        if self._closed:
            return {}
        return {
            blob: comment for blob, (_, comment) in self._rules.items()
        }

    def allows_key(self, blob):
        if self._closed:
            return False
        return asbytes(blob) in self._rules

    def allows_sign(self, blob, flags):
        """Whether this live session permits this exact key and flags word."""
        if self._closed:
            return False
        rule = self._sign_rules.get(asbytes(blob))
        return rule is not None and flags in rule[0]

    # Compatibility aliases.
    check_sign_request = allows_sign

    def filter_identities(self, entries):
        """
        Filter parsed ``(blob, comment)`` pairs, preserving agent ordering.

        Policy comments take precedence when non-empty; otherwise the agent's
        own comment is preserved.
        """
        allowed = self.identities_map()
        kept = []
        for blob, comment in entries:
            if blob in allowed:
                kept.append((blob, allowed[blob] or comment))
        return kept


class RestrictedAgentForwarder:
    """
    Policy-enforcing bridge between a remote agent requester and a local agent.

    Each instance owns exactly one authorized forwarding session. Requests are
    read and parsed completely, then checked against the session policy
    *before* anything is written to the local agent. Denied requests are
    answered locally with ``SSH_AGENT_FAILURE`` and therefore never reach the
    local agent at all. Identity answers are rewritten to contain only allowed
    keys; sign requests are forwarded only when both the complete public key
    blob and the exact flags word match an allowed rule.

    Closing the forwarder -- or the remote side closing the connection --
    revokes the session; subsequent requests are denied.

    ``remote`` and ``local`` are socket-like objects with
    ``recv``/``sendall``/``close`` (paramiko `.Channel` qualifies). ``local``
    may also be a callable returning such an object; by default the local agent
    is connected lazily through `.get_agent_connection`, so a session which
    only sends denied requests never contacts it.
    """

    def __init__(
        self,
        remote,
        local=None,
        policy=None,
        local_factory=None,
        session=None,
        agent_connect=None,
    ):
        if session is None:
            if policy is None:
                raise TypeError("a restricted agent policy is required")
            session = AgentForwardingSession(policy)
        self._session = session
        if agent_connect is not None and local_factory is None:
            local_factory = agent_connect
        if local is not None and callable(local) and not hasattr(
            local, "recv"
        ) and not hasattr(local, "_send_message"):
            # ``local`` was given as a connector callable.
            local_factory = local
            local = None
        self._remote = remote
        self._local = local
        self._local_factory = local_factory
        self._remote_reader = _FramedReader(
            remote, should_stop=lambda: not self.authorized
        )
        self._local_reader = (
            _FramedReader(local, should_stop=lambda: not self.authorized)
            if local is not None
            else None
        )
        self._authorized = True
        self._thread = None
        # Diagnostics, useful for tests and logging.
        self.denied = 0
        self.forwarded = 0

    @property
    def session(self):
        """The `.AgentForwardingSession` for this forwarder."""
        return self._session

    @property
    def authorized(self):
        """Whether this session may still forward requests."""
        return self._authorized and self._session.authorized

    def _get_local(self):
        if self._local is not None:
            return self._local
        factory = self._local_factory or get_agent_connection
        conn = factory()
        if not conn:
            return None
        self._local = conn
        self._local_reader = _FramedReader(
            conn, should_stop=lambda: not self.authorized
        )
        return conn

    def _exchange(self, payload):
        """Send one request payload to the local agent and return its reply."""
        conn = self._get_local()
        if conn is None:
            return None
        # Support a fake/in-process agent exposing AgentSSH._send_message,
        # which is handy for callers and tests.
        if hasattr(conn, "_send_message") and not hasattr(conn, "recv"):
            ptype, result = conn._send_message(asbytes(payload))
            return byte_chr(ptype) + asbytes(result.get_remainder())
        if self._local_reader is None:
            self._local_reader = _FramedReader(
                conn, should_stop=lambda: not self.authorized
            )
        _write_frame(conn, payload)
        return self._local_reader.read()

    def _deny(self):
        self.denied += 1
        return _failure_payload()

    def _handle_identities(self, payload):
        # Nothing is allowed, so do not even contact the local agent.
        if not self._session.identities_map():
            return _empty_identities_payload()
        try:
            reply = self._exchange(payload)
        except Exception:
            return _failure_payload()
        if reply is None:
            return _failure_payload()
        try:
            entries = _parse_identities_answer(reply)
        except SSHException:
            return _failure_payload()
        if entries is None:
            # Pass genuine non-answer responses (eg SSH_AGENT_FAILURE)
            # through untouched.
            return reply
        kept = self._session.filter_identities(entries)
        out = Message()
        out.add_byte(byte_chr(SSH2_AGENT_IDENTITIES_ANSWER))
        out.add_int(len(kept))
        for blob, comment in kept:
            out.add_string(blob)
            out.add_string(comment)
        return asbytes(out)

    def handle_request(self, payload):
        """
        Apply policy to one complete request payload and return a response
        payload. No bytes are sent to the remote by this method.

        Denied/malformed requests return ``SSH_AGENT_FAILURE`` without any
        local agent interaction.
        """
        if not self.authorized:
            return _failure_payload()
        payload = asbytes(payload)
        try:
            # Cheap peek; full strict parsing happens below.
            ptype = _PayloadReader(payload).byte()
        except SSHException:
            return self._deny()
        if ptype == SSH2_AGENTC_REQUEST_IDENTITIES:
            if not _parse_identity_request(payload):
                return self._deny()
            return self._handle_identities(payload)
        if ptype == SSH2_AGENTC_SIGN_REQUEST:
            request = _parse_sign_request(payload)
            if request is None:
                return self._deny()
            blob, _data, flags = request
            if not self._session.allows_sign(blob, flags):
                return self._deny()
            try:
                reply = self._exchange(payload)
            except Exception:
                return _failure_payload()
            if reply is None:
                return _failure_payload()
            self.forwarded += 1
            return reply
        # Unknown, state-changing, lock/unlock, add/remove identity,
        # extensions: deny by default.
        return self._deny()

    def run(self):
        """Pump requests until the remote closes or authorization ends."""
        try:
            while self.authorized:
                try:
                    payload = self._remote_reader.read()
                except (OSError, EOFError, SSHException):
                    break
                if payload is None:
                    break
                response = self.handle_request(payload)
                try:
                    _write_frame(self._remote, response)
                except (OSError, EOFError, SSHException):
                    break
        finally:
            self.close()

    def start(self):
        """Start :meth:`run` in a daemon thread and return the thread."""
        if self._thread is None:
            self._thread = threading.Thread(target=self.run, daemon=True)
            self._thread.start()
        return self._thread

    def join(self, timeout=None):
        if self._thread is not None:
            self._thread.join(timeout)

    def close(self):
        """End this forwarding session and revoke its authorization."""
        self._authorized = False
        self._session.close()
        for conn in (self._remote, self._local):
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass


class RestrictedAgentClientProxy:
    """
    Policy-enforcing alternative to `AgentClientProxy`.

    Wraps a `.RestrictedAgentForwarder` in a thread, mirroring the existing
    forwarded-agent proxy API. The policy is bound to this forwarding session
    when the object is constructed; :meth:`close` revokes it.
    """

    def __init__(
        self, chanRemote, policy=None, agent_connect=None, session=None
    ):
        self._chanRemote = chanRemote
        self._policy = policy
        self._conn = None
        self.forwarder = RestrictedAgentForwarder(
            remote=chanRemote,
            local=None,
            policy=policy,
            session=session,
            local_factory=agent_connect or get_agent_connection,
        )
        self._session = self.forwarder.session
        self.thread = threading.Thread(
            target=self.forwarder.run, daemon=True
        )
        self.thread.start()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    @property
    def session(self):
        return self._session

    @property
    def denied(self):
        return self.forwarder.denied

    @property
    def forwarded(self):
        return self.forwarder.forwarded

    def connect(self):
        """Connect to the local agent (performed lazily as needed)."""
        self._conn = self.forwarder._get_local()
        return self._conn

    def _process_request(self, payload):
        """Synchronously apply policy to one request payload."""
        return self.forwarder.handle_request(payload)

    def close(self):
        """Revoke this session's authorization and stop the proxy thread."""
        self.forwarder.close()
        if self.thread is not threading.current_thread():
            self.thread.join(1.0)


class RestrictedAgentRequestHandler:
    """
    Restricted alternative to `.AgentRequestHandler`.

    Hand it a live command-executing session and a locally-built
    `.RestrictedAgentPolicy`; each forwarded agent connection is then mediated
    by a fresh `.AgentForwardingSession` snapshot of that policy::

        policy = RestrictedAgentPolicy()
        policy.allow(key, algorithms=["rsa-sha2-256"])
        RestrictedAgentRequestHandler(session, policy)
    """

    def __init__(self, chanClient, policy=None, agent_connect=None):
        if policy is None:
            raise TypeError("a restricted agent policy is required")
        self._chanClient = chanClient
        self._policy = policy
        self._agent_connect = agent_connect
        self._proxies = []
        chanClient.request_forward_agent(self._forward_agent_handler)

    def _forward_agent_handler(self, chanRemote):
        self._proxies.append(
            RestrictedAgentClientProxy(
                chanRemote,
                self._policy,
                agent_connect=self._agent_connect,
            )
        )

    def close(self):
        for proxy in self._proxies:
            proxy.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
