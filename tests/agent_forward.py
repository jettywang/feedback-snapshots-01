"""Tests for policy-enforced SSH agent forwarding.

The fake local agent below records every request payload it actually receives.
Denied requests must therefore never appear in its log, which is the central
isolation property of the restricted forwarder.
"""

import socket
import struct
import threading

from pytest import raises

from paramiko import Ed25519Key, Message, RSAKey
from paramiko.agent import (
    SSH2_AGENTC_REQUEST_IDENTITIES,
    SSH2_AGENTC_SIGN_REQUEST,
    SSH2_AGENT_IDENTITIES_ANSWER,
    SSH2_AGENT_SIGN_RESPONSE,
    SSH_AGENT_FAILURE,
    SSH_AGENT_RSA_SHA2_256,
    SSH_AGENT_RSA_SHA2_512,
    AgentForwardingPolicy,
    AgentForwardingSession,
    RestrictedAgentForwarder,
    RestrictedAgentPolicy,
    RestrictedKeyRule,
    cSSH2_AGENTC_ADD_IDENTITY,
    cSSH2_AGENTC_REQUEST_IDENTITIES,
    cSSH2_AGENTC_SIGN_REQUEST,
    cSSH2_AGENTC_EXTENSION,
    cSSH2_AGENTC_LOCK,
    cSSH2_AGENTC_REMOVE_ALL_IDENTITIES,
    cSSH2_AGENTC_UNLOCK,
)
from paramiko.ssh_exception import SSHException

from ._util import _support

FRAME = struct.Struct(">I")


def _frame(payload):
    return FRAME.pack(len(payload)) + payload


def _read_frame(sock):
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    (length,) = FRAME.unpack(header)
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise SSHException("truncated")
        body += chunk
    return body


def _sign_request(blob, data, flags):
    msg = Message()
    msg.add_byte(cSSH2_AGENTC_SIGN_REQUEST)
    msg.add_string(blob)
    msg.add_string(data)
    msg.add_int(flags)
    return bytes(msg)


def _identity_request():
    return bytes(cSSH2_AGENTC_REQUEST_IDENTITIES)


class _FakeAgent(threading.Thread):
    """Minimal agent holding real keys; records all *received* payloads."""

    daemon = True

    def __init__(self, keys):
        super().__init__()
        self.keys = list(keys)
        self.received = []
        self._stop_event = threading.Event()
        self._server, self._client = socket.socketpair()
        self._server.settimeout(0.2)

    def run(self):
        while not self._stop_event.is_set():
            try:
                header = self._recv_exact(4)
                if header is None:
                    break
                (length,) = FRAME.unpack(header)
                payload = self._recv_exact(length)
                if payload is None:
                    break
                self.received.append(payload)
                self._answer(payload)
            except (OSError, socket.timeout):
                continue
        try:
            self._server.close()
        except OSError:
            pass

    def _recv_exact(self, size):
        data = b""
        while len(data) < size:
            chunk = self._server.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _answer(self, payload):
        msg = Message(payload)
        ptype = ord(msg.get_byte())
        if ptype == SSH2_AGENTC_REQUEST_IDENTITIES:
            out = Message()
            out.add_byte(bytes([SSH2_AGENT_IDENTITIES_ANSWER]))
            out.add_int(len(self.keys))
            for key in self.keys:
                out.add_string(key.asbytes())
                out.add_string("fake")
            self._send(bytes(out))
        elif ptype == SSH2_AGENTC_SIGN_REQUEST:
            blob = msg.get_string()
            data = msg.get_string()
            flags = msg.get_int()
            key = next(
                (k for k in self.keys if k.asbytes() == blob), None
            )
            if key is None:
                self._send(bytes([SSH_AGENT_FAILURE]))
                return
            algorithm = None
            if isinstance(key, RSAKey):
                if flags & SSH_AGENT_RSA_SHA2_512:
                    algorithm = "rsa-sha2-512"
                elif flags & SSH_AGENT_RSA_SHA2_256:
                    algorithm = "rsa-sha2-256"
            sig = key.sign_ssh_data(data, algorithm=algorithm)
            out = Message()
            out.add_byte(bytes([SSH2_AGENT_SIGN_RESPONSE]))
            out.add_string(bytes(sig))
            self._send(bytes(out))

    def _send(self, payload):
        self._server.sendall(_frame(payload))

    def stop(self):
        self._stop_event.set()
        try:
            self._client.close()
        except OSError:
            pass
        self.join(2)


class _Harness:
    def __init__(self, policy, keys):
        self.remote, peer = socket.socketpair()
        self.remote.settimeout(2)
        self.agent = _FakeAgent(keys)
        self.agent.start()
        self.forwarder = RestrictedAgentForwarder(
            remote=peer,
            local=self.agent._client,
            policy=policy,
        )
        self.forwarder.start()

    def request(self, payload):
        self.remote.sendall(_frame(payload))
        return _read_frame(self.remote)

    def shutdown(self):
        try:
            self.remote.close()
        except OSError:
            pass
        self.forwarder.close()
        self.agent.stop()

    def seen_types(self):
        return [ord(Message(p).get_byte()) for p in self.agent.received]


class RestrictedKeyRule_:
    def builds_from_key_and_algorithms(self):
        rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        rule = RestrictedKeyRule.from_algorithms(
            rsa, algorithms=["rsa-sha2-256"]
        )
        assert rule.blob == rsa.asbytes()
        assert rule.allowed_flags == frozenset({SSH_AGENT_RSA_SHA2_256})

    def defaults_to_zero_flag(self):
        ed = Ed25519Key.from_private_key_file(_support("ed25519.key"))
        assert RestrictedKeyRule(ed).allowed_flags == frozenset({0})

    def unknown_algorithm_rejected(self):
        rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        with raises(SSHException):
            RestrictedKeyRule.from_algorithms(rsa, ["bogus"])


class RestrictedAgentPolicy_:
    def setup_method(self):
        self.rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        self.ed = Ed25519Key.from_private_key_file(_support("ed25519.key"))
        self.policy = RestrictedAgentPolicy(target="trusted@build")
        self.policy.allow(self.rsa, algorithms=["rsa-sha2-256"])
        self.policy.allow(self.ed)

    def identities_only_expose_allowed_keys(self):
        blobs = [blob for blob, _ in self.policy.identities()]
        assert blobs == [self.rsa.asbytes(), self.ed.asbytes()]

    def sign_checks_full_blob_and_exact_flags(self):
        assert self.policy.check_sign_request(
            self.rsa.asbytes(), SSH_AGENT_RSA_SHA2_256
        )
        assert not self.policy.check_sign_request(
            self.rsa.asbytes(), SSH_AGENT_RSA_SHA2_512
        )
        assert not self.policy.check_sign_request(self.rsa.asbytes(), 0)
        assert not self.policy.check_sign_request(b"truncated", 0)
        assert self.policy.check_sign_request(self.ed.asbytes(), 0)
        assert not self.policy.check_sign_request(
            self.ed.asbytes(), SSH_AGENT_RSA_SHA2_256
        )

    def unknown_and_mutating_requests_denied(self):
        for payload in (
            b"\x00x",
            bytes(cSSH2_AGENTC_ADD_IDENTITY) + b"key",
            bytes(cSSH2_AGENTC_REMOVE_ALL_IDENTITIES),
            bytes(cSSH2_AGENTC_LOCK) + b"password",
            bytes(cSSH2_AGENTC_UNLOCK) + b"password",
            bytes(cSSH2_AGENTC_EXTENSION) + b"vendor@example",
        ):
            verdict, _ = self.policy.decide(Message(payload))
            assert verdict == "deny"

    def target_never_widens_scope(self):
        assert self.policy.target == "trusted@build"
        assert not self.policy.check_sign_request(b"other", 0)

    def session_snapshot_and_revocation(self):
        session = AgentForwardingSession(self.policy)
        assert session.allows_sign(
            self.rsa.asbytes(), SSH_AGENT_RSA_SHA2_256
        )
        session.close()
        assert not session.allows_sign(
            self.rsa.asbytes(), SSH_AGENT_RSA_SHA2_256
        )
        assert session.identities() == []


class CertificateKey_:
    def rule_uses_certificate_for_identity_and_key_for_signing(self):
        rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        rsa.load_certificate(_support("rsa.key-cert.pub"))
        policy = RestrictedAgentPolicy()
        policy.allow(rsa, algorithms=["rsa-sha2-256"])
        identity_blob, _ = policy.identities()[0]
        assert identity_blob == rsa.public_blob.key_blob
        assert policy.check_sign_request(rsa.asbytes(), SSH_AGENT_RSA_SHA2_256)
        # A certificate blob is materially different from the underlying key
        # and must not be accepted as a sign-request key blob.
        assert not policy.check_sign_request(
            rsa.public_blob.key_blob, SSH_AGENT_RSA_SHA2_256
        )

    def raw_certificate_blob_resolves_underlying_sign_material(self):
        rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        rsa.load_certificate(_support("rsa.key-cert.pub"))
        cert_blob = rsa.public_blob.key_blob
        policy = RestrictedAgentPolicy()
        policy.allow(cert_blob, algorithms=["rsa-sha2-256"])
        assert policy.identities()[0][0] == cert_blob
        assert policy.check_sign_request(rsa.asbytes(), SSH_AGENT_RSA_SHA2_256)
        assert not policy.check_sign_request(
            cert_blob, SSH_AGENT_RSA_SHA2_256
        )


class AgentForwardingPolicy_:
    def setup_method(self):
        self.rsa = RSAKey.from_private_key_file(_support("rsa.key"))

    def default_is_sha256_for_rsa(self):
        policy = AgentForwardingPolicy(keys=[self.rsa])
        assert policy.rsa_flags == frozenset({SSH_AGENT_RSA_SHA2_256})
        assert policy.check_sign_request(
            self.rsa.asbytes(), SSH_AGENT_RSA_SHA2_256
        )
        assert not policy.check_sign_request(
            self.rsa.asbytes(), SSH_AGENT_RSA_SHA2_512
        )

    def named_algorithms_and_flags(self):
        policy = AgentForwardingPolicy(
            keys=[self.rsa], rsa_flags=[SSH_AGENT_RSA_SHA2_512]
        )
        assert policy.check_sign_request(
            self.rsa.asbytes(), SSH_AGENT_RSA_SHA2_512
        )
        assert not policy.check_sign_request(
            self.rsa.asbytes(), SSH_AGENT_RSA_SHA2_256
        )
        policy2 = AgentForwardingPolicy(
            keys=[self.rsa], algorithms=["rsa-sha2-256"]
        )
        assert policy2.check_sign_request(
            self.rsa.asbytes(), SSH_AGENT_RSA_SHA2_256
        )

    def non_rsa_key_uses_zero_flag_only(self):
        ed = Ed25519Key.from_private_key_file(_support("ed25519.key"))
        policy = AgentForwardingPolicy(keys=[ed])
        assert policy.check_sign_request(ed.asbytes(), 0)
        assert not policy.check_sign_request(
            ed.asbytes(), SSH_AGENT_RSA_SHA2_256
        )


class RestrictedForwarder_:
    def setup_method(self):
        self.rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        self.ed = Ed25519Key.from_private_key_file(_support("ed25519.key"))
        self.policy = AgentForwardingPolicy(
            keys=[self.rsa], algorithms=["rsa-sha2-256"]
        )
        # The local agent holds an extra, non-allowed key.
        self.harness = _Harness(self.policy, [self.rsa, self.ed])

    def teardown_method(self):
        self.harness.shutdown()

    def identities_are_filtered(self):
        answer = Message(self.harness.request(_identity_request()))
        assert ord(answer.get_byte()) == SSH2_AGENT_IDENTITIES_ANSWER
        count = answer.get_int()
        blobs = [answer.get_binary() for _ in range(count)]
        assert blobs == [self.rsa.asbytes()]

    def allowed_signature_reaches_agent_and_verifies(self):
        data = b"challenge"
        answer = Message(
            self.harness.request(
                _sign_request(
                    self.rsa.asbytes(), data, SSH_AGENT_RSA_SHA2_256
                )
            )
        )
        assert ord(answer.get_byte()) == SSH2_AGENT_SIGN_RESPONSE
        sig = answer.get_binary()
        assert self.rsa.verify_ssh_sig(data, Message(sig))
        assert (
            self.harness.seen_types().count(SSH2_AGENTC_SIGN_REQUEST) >= 1
        )

    def denied_requests_never_reach_agent(self):
        before = len(self.harness.agent.received)
        cases = [
            _sign_request(
                self.rsa.asbytes(), b"x", SSH_AGENT_RSA_SHA2_512
            ),
            _sign_request(self.rsa.asbytes(), b"x", 0),
            _sign_request(self.ed.asbytes(), b"x", 0),
            _sign_request(b"not-a-key", b"x", 0),
            bytes(cSSH2_AGENTC_REMOVE_ALL_IDENTITIES),
            bytes(cSSH2_AGENTC_ADD_IDENTITY) + b"newkey",
            bytes(cSSH2_AGENTC_LOCK) + b"pw",
        ]
        for payload in cases:
            assert self.harness.request(payload) == bytes(
                [SSH_AGENT_FAILURE]
            )
        assert len(self.harness.agent.received) == before
        assert self.harness.forwarder.denied == len(cases)

    def fragmented_and_coalesced_frames(self):
        data1 = b"fragmented"
        payload = _frame(
            _sign_request(
                self.rsa.asbytes(), data1, SSH_AGENT_RSA_SHA2_256
            )
        )
        for byte in payload:
            self.harness.remote.sendall(bytes([byte]))
        answer = Message(_read_frame(self.harness.remote))
        assert ord(answer.get_byte()) == SSH2_AGENT_SIGN_RESPONSE
        assert self.rsa.verify_ssh_sig(data1, Message(answer.get_binary()))

        coalesced = _frame(_identity_request()) + _frame(
            _sign_request(
                self.rsa.asbytes(), b"second", SSH_AGENT_RSA_SHA2_256
            )
        )
        self.harness.remote.sendall(coalesced)
        ident = Message(_read_frame(self.harness.remote))
        assert ord(ident.get_byte()) == SSH2_AGENT_IDENTITIES_ANSWER
        second = Message(_read_frame(self.harness.remote))
        assert ord(second.get_byte()) == SSH2_AGENT_SIGN_RESPONSE
        assert self.rsa.verify_ssh_sig(
            b"second", Message(second.get_binary())
        )

    def malformed_or_trailing_data_denied(self):
        before = len(self.harness.agent.received)
        good = _sign_request(
            self.rsa.asbytes(), b"x", SSH_AGENT_RSA_SHA2_256
        )
        for payload in (good[:-1], good + b"trailing", bytes([13])):
            assert self.harness.request(payload) == bytes(
                [SSH_AGENT_FAILURE]
            )
        assert len(self.harness.agent.received) == before

    def closing_connection_revokes_authorization(self):
        assert self.harness.forwarder.authorized
        self.harness.remote.close()
        self.harness.forwarder.join(2)
        assert not self.harness.forwarder.authorized
        assert not self.harness.forwarder.session.authorized
        # Even a policy-conforming request is now refused locally.
        assert self.harness.forwarder.handle_request(
            _sign_request(
                self.rsa.asbytes(), b"after", SSH_AGENT_RSA_SHA2_256
            )
        ) == bytes([SSH_AGENT_FAILURE])

    def policy_mutation_does_not_widen_live_session(self):
        # Grant SHA2-512 after the session was created; its snapshot must not
        # pick it up.
        self.policy.allow(self.rsa, algorithms=["rsa-sha2-512"])
        assert self.harness.request(
            _sign_request(
                self.rsa.asbytes(), b"x", SSH_AGENT_RSA_SHA2_512
            )
        ) == bytes([SSH_AGENT_FAILURE])


class ChannelIntegration_:
    def test_forwarder_works_over_channel_like_object(self):
        # A paramiko Channel is not a raw socket; exercise the duck-typed
        # recv/sendall/close path using a minimal stand-in with the same
        # semantics (notably: timeout mode instead of immediate EOF).
        class Chan:
            def __init__(self, peer):
                self.peer = peer
                self.timeout = 0.01
                self.closed = False

            def recv(self, n):
                import socket as socketmod
                if self.closed:
                    return b""
                data = self.peer.recv(n)
                if not data:
                    raise socketmod.timeout()
                return data

            def sendall(self, data):
                self.peer.sendall(data)

            def close(self):
                self.closed = True

        rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        policy = AgentForwardingPolicy(keys=[rsa])
        remote_sock, peer_sock = socket.socketpair()
        remote_sock.settimeout(2)
        peer_sock.settimeout(2)
        agent = _FakeAgent([rsa])
        agent.start()
        chan_remote = Chan(peer_sock)
        chan_chan = Chan(remote_sock)
        forwarder = RestrictedAgentForwarder(
            remote=chan_chan, local=agent._client, policy=policy
        )
        forwarder.start()
        chan_remote.sendall(
            _frame(
                _sign_request(
                    rsa.asbytes(), b"via-channel", SSH_AGENT_RSA_SHA2_256
                )
            )
        )
        payload = _read_frame(chan_remote.peer)
        answer = Message(payload)
        assert ord(answer.get_byte()) == SSH2_AGENT_SIGN_RESPONSE
        assert rsa.verify_ssh_sig(
            b"via-channel", Message(answer.get_binary())
        )
        forwarder.close()
        agent.stop()


class RemoteTargetCannotWidenPolicy_:
    def test_remote_target_fields_are_ignored(self):
        rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        policy = AgentForwardingPolicy(keys=[rsa])
        # A remote peer has no way to set ``target`` through the wire, and
        # even the locally trusted target cannot widen key/algorithm scope.
        assert policy.target is None
        assert not policy.check_sign_request(b"attacker-key", 0)
        policy.target = "attacker-supplied@elsewhere"
        assert not policy.check_sign_request(b"attacker-key", 0)

    def test_no_target_is_documented_as_key_and_algorithm_scope(self):
        rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        policy = AgentForwardingPolicy(keys=[rsa])
        session = AgentForwardingSession(policy)
        assert session.target is None
        # Scope remains exactly the explicitly allowed key/flags pair.
        assert session.allows_sign(rsa.asbytes(), SSH_AGENT_RSA_SHA2_256)
        assert not session.allows_sign(rsa.asbytes(), SSH_AGENT_RSA_SHA2_512)


class DeniedTrafficDoesNotContactAgent_:
    def test_denied_only_session_never_calls_factory(self):
        rsa = RSAKey.from_private_key_file(_support("rsa.key"))
        policy = AgentForwardingPolicy(keys=[rsa])
        remote, peer = socket.socketpair()
        remote.settimeout(2)
        called = []

        def factory():
            called.append(True)
            raise AssertionError("must not contact local agent")

        forwarder = RestrictedAgentForwarder(
            remote=peer, policy=policy, local_factory=factory
        )
        forwarder.start()
        for payload in (
            bytes(cSSH2_AGENTC_REMOVE_ALL_IDENTITIES),
            bytes(cSSH2_AGENTC_EXTENSION) + b"x",
            _sign_request(b"other", b"data", 0),
        ):
            remote.sendall(_frame(payload))
            assert _read_frame(remote) == bytes([SSH_AGENT_FAILURE])
        assert called == []
        remote.close()
        forwarder.join(2)
        assert not forwarder.authorized
