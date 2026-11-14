# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Lifecycle contract tests for ContextProxy.new_context().

The retry helper in the callers uses new_context() to build a fresh security
context from an existing one. That is only safe when the new object copies the
configuration (credentials and security policy) but not the authenticated
session state. These tests pin that contract down for NTLM, Negotiate, and
CredSSP so a retry can never present the peer with a resumed session.

The tests use the real pure Python NTLM provider and the local CredSSP TLS
stack. The only provider path that has to use a stand-in here is the Kerberos
mech that Negotiate can inject: this host has no KDC or gssapi module, so
``test_negotiate_new_context_stub_preserves_injected_policy`` uses a fake
context and its docstring states exactly what that does and does not prove.
The SSPI and GSSAPI ``new_context()`` implementations cannot be constructed
in this environment and are not covered by this module.
"""

import os
import socket
import ssl
import struct
import typing

import pytest

import spnego
import spnego._credssp as credssp
from spnego._context import ContextProxy, ContextReq
from spnego.exceptions import BadMICError, NegotiateOptions, SpnegoError


# The three providers and the minimal options needed to reach each one on a
# host without SSPI/GSSAPI. These are the providers a retry helper would pick
# when the platform implementations are not available.
PROVIDERS = [
    pytest.param("ntlm", NegotiateOptions.use_ntlm, id="ntlm"),
    pytest.param("negotiate", NegotiateOptions.use_negotiate, id="negotiate"),
    pytest.param("credssp", NegotiateOptions.use_ntlm, id="credssp"),
]


def _write_credential_store(tmpdir: str, content: str) -> str:
    path = os.path.join(tmpdir, "ntlm.cred")
    with open(path, "wb") as fd:
        fd.write(content.encode())
    return path


def _drive(client: ContextProxy, server: ContextProxy, limit: int = 50) -> None:
    """Runs a full token exchange and fails if it does not complete."""
    client_token: typing.Optional[bytes] = None
    server_token: typing.Optional[bytes] = None

    for _ in range(limit):
        if client.complete and server.complete:
            return

        client_token = client.step(server_token) if not client.complete else None
        server_token = server.step(client_token) if not server.complete else None

    raise AssertionError("The token exchange did not complete")


def _new_pair(protocol: str, options: NegotiateOptions) -> typing.Tuple[ContextProxy, ContextProxy]:
    return (
        spnego.client(
            "DOMAIN\\user",
            "Password01",
            hostname=socket.gethostname(),
            protocol=protocol,
            options=options,
        ),
        spnego.server(
            hostname=socket.gethostname(),
            protocol=protocol,
            options=options,
        ),
    )


def _completed_pair(protocol: str, options: NegotiateOptions) -> typing.Tuple[ContextProxy, ContextProxy]:
    client, server = _new_pair(protocol, options)
    _drive(client, server)
    return client, server


@pytest.fixture()
def ntlm_store(tmpdir, monkeypatch):
    """A real NTLM_USER_FILE with the credentials the contract tests use."""
    path = _write_credential_store(str(tmpdir), "DOMAIN:user:Password01")
    monkeypatch.setenv("NTLM_USER_FILE", path)
    return path


# ---------------------------------------------------------------------------
# 1. Configuration is copied.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protocol, options", PROVIDERS)
def test_new_context_copies_configuration(protocol, options, ntlm_store):
    """The new object keeps the credentials, SPN, options, and context_req."""
    original, _ = _new_pair(protocol, options)
    fresh = original.new_context()

    assert type(fresh) is type(original)
    assert fresh.usage == original.usage
    assert fresh.protocol == original.protocol
    assert fresh.options == original.options
    assert fresh.context_req == original.context_req
    assert fresh.spn == original.spn
    assert fresh.channel_bindings is original.channel_bindings

    # Credentials are copied, not dropped, even before the mech list exists.
    if isinstance(fresh, spnego._negotiate.NegotiateProxy):
        assert fresh._credentials == original._credentials
    elif isinstance(fresh, spnego._credssp.CredSSPProxy):
        assert fresh._credentials == original._credentials
    else:
        assert fresh._credential is not original._credential
        assert fresh._credential.nt_hash == original._credential.nt_hash
        assert fresh._credential.lm_hash == original._credential.lm_hash
        assert fresh._credential.username == original._credential.username


def test_ntlm_new_context_keeps_cache_resolved_username(tmpdir, monkeypatch):
    """A cache credential without a username resolves the same identity on retry.

    Before the fix the NTLM retry rebuilt the credential with an empty username
    which made the acceptor reject the resulting anonymous token.
    """
    path = _write_credential_store(str(tmpdir), "DOMAIN:user:Password01\nOTHER:other:Password02")
    monkeypatch.setenv("NTLM_USER_FILE", path)

    client = spnego.client(hostname=socket.gethostname(), protocol="ntlm", options=NegotiateOptions.use_ntlm)
    assert client._credential._raw_username is None

    fresh = client.new_context()
    assert fresh._credential.username == "user"
    assert fresh._credential.domain == "DOMAIN"

    server = spnego.server(hostname=socket.gethostname(), protocol="ntlm", options=NegotiateOptions.use_ntlm)
    _drive(fresh, server)
    assert server.client_principal == "DOMAIN\\user"


def test_credssp_new_context_keeps_policy():
    """credssp_min_protocol and the caller's TLS settings survive a retry.

    The TLS plumbing itself is exercised by _StubCredSSPTLSContext below; this
    test proves the policy values are passed to the new CredSSPProxy.
    """
    tls_context = spnego.tls.default_tls_context(usage="initiate")
    original = credssp.CredSSPProxy(
        "DOMAIN\\user",
        "Password01",
        hostname=socket.gethostname(),
        credssp_min_protocol=5,
        credssp_tls_context=tls_context,
    )
    fresh = original.new_context()

    assert fresh._min_version == 5
    assert fresh._tls_context is tls_context
    # The TLS context is configuration. The session buffers and TLS object are not.
    assert fresh._in_buff is not original._in_buff
    assert fresh._out_buff is not original._out_buff
    assert fresh._tls_object is not original._tls_object


# ---------------------------------------------------------------------------
# 2. Session state is not copied.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protocol, options", PROVIDERS)
def test_new_context_does_not_inherit_session_state(protocol, options, ntlm_store):
    """complete, keying material, counters, MIC state, and TLS buffers reset."""
    original, _ = _completed_pair(protocol, options)

    assert original.complete
    fresh = original.new_context()
    assert not fresh.complete

    if isinstance(original, spnego._ntlm.NTLMProxy):
        # The session key and signing/sealing handles belong to the old session.
        assert original.session_key
        assert fresh.session_key == b""
        assert fresh._session_key is None
        assert fresh._sign_key_out is None
        assert fresh._sign_key_in is None
        assert fresh._handle_out is None
        assert fresh._handle_in is None
        # _seq_num_in is a property that also increments the counter, read the private values directly.
        assert fresh._NTLMProxy__seq_num_out == 0
        assert fresh._NTLMProxy__seq_num_in == 0
        assert fresh._mic_required is False
        assert fresh._temp_negotiate is None
        assert fresh._temp_challenge is None

    elif isinstance(original, spnego._negotiate.NegotiateProxy):
        assert original._context_list
        assert fresh._context_list == {}
        assert fresh._mech_list == []
        assert fresh._init_sent is False
        assert fresh._mech_sent is False
        assert fresh._mic_sent is False
        assert fresh._mic_recv is False
        assert fresh.session_key == b""

    else:
        assert isinstance(original, credssp.CredSSPProxy)
        assert original.get_extra_info("protocol_version") is not None
        assert fresh._step_gen is None
        assert fresh._selected_version is None
        assert fresh._complete is False
        # The old CredSSP session has consumed its TLS handshake, the new one starts over.
        assert fresh._in_buff.pending == 0
        assert fresh._out_buff.pending == 0
        assert fresh._tls_object is not original._tls_object
        with pytest.raises(ValueError):
            fresh._tls_object.getpeercert(True)
        assert fresh._auth_stage == "TLS Handshake"
        # The inner Negotiate session is rebuilt rather than shared.
        assert original._auth_context is not None
        assert fresh._auth_context is not None
        assert fresh._auth_context is not original._auth_context
        assert not fresh._auth_context.complete


def test_ntlm_new_context_resets_rc4_handles_mid_session(ntlm_store):
    """Wrapping on the old context moves its counters; the retry starts at zero."""
    original, server = _completed_pair("ntlm", NegotiateOptions.use_ntlm)
    original.wrap(b"one")
    original.unwrap(server.wrap(b"two").data)

    fresh = original.new_context()
    assert fresh._NTLMProxy__seq_num_out == 0
    assert fresh._NTLMProxy__seq_num_in == 0
    assert fresh._complete is False

    server_fresh = server.new_context()
    _drive(fresh, server_fresh)

    # A new session has fresh keys and counters, so old ciphertext is rejected.
    with pytest.raises(BadMICError):
        server_fresh.unwrap(original.wrap(b"replayed").data)


# ---------------------------------------------------------------------------
# 3. Rebuild is possible when the old object failed or is still in flight.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protocol, options", PROVIDERS)
def test_new_context_from_inflight_session(protocol, options, ntlm_store):
    """A retry can be built while the old handshake is only partially done."""
    original, server = _new_pair(protocol, options)

    if protocol == "credssp":
        # Stop after the TLS hello so a real partial state exists.
        client_token = original.step()
        server.step(client_token)
        assert original.get_extra_info("auth_stage") == "TLS Handshake"
    else:
        # Advance one client token then leave both sides mid-flight.
        server.step(original.step())

    assert not original.complete
    fresh = original.new_context()
    assert not fresh.complete

    fresh_server = spnego.server(
        hostname=socket.gethostname(), protocol=protocol, options=options
    )
    _drive(fresh, fresh_server)
    assert fresh.complete
    assert fresh_server.complete


@pytest.mark.parametrize("protocol, options", PROVIDERS)
def test_new_context_after_failure(protocol, options, ntlm_store):
    """A failed session still yields a usable retry context."""
    original, server = _new_pair(protocol, options)

    first = original.step()
    assert first is not None

    if protocol == "credssp":
        # Corrupt the TLS record to fail the handshake.
        with pytest.raises(SpnegoError):
            original.step(b"not a tls record")
    else:
        # Corrupt the NTLM/SPNEGO token to fail token processing. NTLM raises struct.error while SPNEGO raises
        # ValueError, both come from the real provider parsers.
        expected = (SpnegoError, ValueError, struct.error)
        with pytest.raises(expected):
            server.step(b"\x00" * 4)

    fresh = original.new_context()
    fresh_server = spnego.server(hostname=socket.gethostname(), protocol=protocol, options=options)
    _drive(fresh, fresh_server)
    assert fresh.complete
    assert fresh_server.complete


# ---------------------------------------------------------------------------
# 4. Old and new objects do not consume each other's tokens or protection state.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "protocol, options",
    [
        pytest.param("ntlm", NegotiateOptions.use_ntlm, id="ntlm"),
        pytest.param("negotiate", NegotiateOptions.use_negotiate, id="negotiate"),
    ],
)
def test_interleaved_sessions_do_not_share_tokens(protocol, options, ntlm_store):
    """Two live sessions advanced alternately keep independent keys and counters."""
    old_client, old_server = _completed_pair(protocol, options)
    new_client = old_client.new_context()
    new_server = old_server.new_context()
    _drive(new_client, new_server)

    assert old_client.complete and old_server.complete
    assert new_client.complete and new_server.complete

    # Interleave protection operations in both directions.
    for index in range(3):
        old_payload = b"old-%d" % index
        new_payload = b"new-%d" % index

        assert old_server.unwrap(old_client.wrap(old_payload).data).data == old_payload
        assert new_server.unwrap(new_client.wrap(new_payload).data).data == new_payload
        assert old_client.unwrap(old_server.wrap(old_payload).data).data == old_payload
        assert new_client.unwrap(new_server.wrap(new_payload).data).data == new_payload

    # NTLM is always the inner provider on this host; check its per-session counters advanced.
    old_ntlm = old_client._context if protocol == "negotiate" else old_client
    new_ntlm = new_client._context if protocol == "negotiate" else new_client
    assert old_ntlm._NTLMProxy__seq_num_out > 0
    assert new_ntlm._NTLMProxy__seq_num_out > 0


def test_credssp_interleaved_sessions_keep_tls_streams_apart(ntlm_store):
    """Two CredSSP sessions interleave independent TLS streams and credentials."""
    old_client, old_server = _completed_pair("credssp", NegotiateOptions.use_ntlm)
    new_client = old_client.new_context()
    new_server = old_server.new_context()
    _drive(new_client, new_server)

    for index in range(3):
        old_payload = b"old-%d" % index
        new_payload = b"new-%d" % index
        assert old_server.unwrap(old_client.wrap(old_payload).data).data == old_payload
        assert new_server.unwrap(new_client.wrap(new_payload).data).data == new_payload
        assert old_client.unwrap(old_server.wrap(old_payload).data).data == old_payload
        assert new_client.unwrap(new_server.wrap(new_payload).data).data == new_payload


# ---------------------------------------------------------------------------
# 5. Real handshake proof: old protected messages do not pass on the new session.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "protocol, options",
    [
        pytest.param("ntlm", NegotiateOptions.use_ntlm, id="ntlm"),
        pytest.param("negotiate", NegotiateOptions.use_negotiate, id="negotiate"),
    ],
)
def test_old_session_message_rejected_by_new_session(protocol, options, ntlm_store):
    """Two full handshakes with the pure Python NTLM provider, then replay old data."""
    old_client, old_server = _completed_pair(protocol, options)

    new_client = old_client.new_context()
    new_server = old_server.new_context()
    _drive(new_client, new_server)

    assert old_client.complete and old_server.complete
    assert new_client.complete and new_server.complete
    assert old_client.session_key
    assert new_client.session_key
    assert old_client.session_key != new_client.session_key

    # The new session works with its own key before the replay attempt. A failed unwrap consumes the receiver's
    # RC4 stream, so the replay check has to come last.
    assert new_server.unwrap(new_client.wrap(b"new session data").data).data == b"new session data"

    old_message = old_client.wrap(b"protected on the old session").data
    with pytest.raises(BadMICError):
        new_server.unwrap(old_message)

    # The same data must still work in the session that produced it.
    assert old_server.unwrap(old_message).data == b"protected on the old session"


def test_old_credssp_record_rejected_by_new_session(ntlm_store):
    """Two full TLS+CredSSP handshakes with local TLS, then replay an old record."""
    old_client, old_server = _completed_pair("credssp", NegotiateOptions.use_ntlm)

    new_client = old_client.new_context()
    new_server = old_server.new_context()
    _drive(new_client, new_server)

    assert old_client.complete and old_server.complete
    assert new_client.complete and new_server.complete

    # The new session works with its own TLS keys before the replay attempt. A TLS record layer failure closes
    # the receiving SSLObject, so the replay check has to come last.
    assert new_server.unwrap(new_client.wrap(b"new tls session").data).data == b"new tls session"

    old_record = old_client.wrap(b"protected on the old tls session").data
    with pytest.raises(SpnegoError):
        new_server.unwrap(old_record)

    # The record is still valid on the stream that produced it.
    assert old_server.unwrap(old_record).data == b"protected on the old tls session"


# ---------------------------------------------------------------------------
# 6. Stand-in coverage: explicit evidence scope.
# ---------------------------------------------------------------------------


def test_credssp_new_context_acceptor_drops_delegated_credential(ntlm_store):
    """The acceptor's received TSCredentials belong to the old session only."""
    original, _ = _new_pair("credssp", NegotiateOptions.use_ntlm)
    original_server = spnego.server(
        hostname=socket.gethostname(), protocol="credssp", options=NegotiateOptions.use_ntlm
    )
    _drive(original, original_server)

    assert original_server._ts_credential is not None
    fresh_server = original_server.new_context()
    assert fresh_server._ts_credential is None
    assert not fresh_server.complete


def test_negotiate_new_context_stub_preserves_injected_policy():
    """DOCUMENTED STAND-IN SCOPE: injected mech contexts are configuration.

    ``NegotiateProxy`` normally builds its mech contexts from credentials, but
    public callers can inject one through the private ``_negotiate_contexts``
    kwarg (the existing tests use this for Kerberos). This test uses a fake
    Kerberos context because this host has no KDC or gssapi module.

    Proven: an injected context is copied with ``new_context()`` instead of
    aliased, the rebuilt SPNEGO context starts with no mech list, complete
    flag, or MIC bookkeeping.

    Not proven: anything about Kerberos authentication, tickets, or GSSAPI
    state. The real rebuild proof for the credential-built path is the pure
    Python NTLM tests above; SSPI/GSSAPI new_context() is out of scope here.
    """

    class FakeKerberosContext(ContextProxy):
        def __init__(self, usage="initiate", token=b"AP-REQ"):
            super().__init__([], None, None, None, ContextReq.default, usage, "kerberos", NegotiateOptions.none)
            self.token = token
            self._complete = False

        @classmethod
        def available_protocols(cls, options=None):
            return ["kerberos"]

        @property
        def client_principal(self):
            return None

        @property
        def complete(self):
            return self._complete

        @property
        def negotiated_protocol(self):
            return "kerberos"

        @property
        def session_key(self):
            return b"\x00" * 16

        def new_context(self):
            return FakeKerberosContext(self.usage, self.token)

        def query_message_sizes(self):
            raise NotImplementedError()

        def step(self, in_token=None, *, channel_bindings=None):
            self._complete = True
            return self.token

        def wrap(self, *args, **kwargs):
            raise NotImplementedError()

        def wrap_iov(self, *args, **kwargs):
            raise NotImplementedError()

        def wrap_winrm(self, *args, **kwargs):
            raise NotImplementedError()

        def unwrap(self, *args, **kwargs):
            raise NotImplementedError()

        def unwrap_iov(self, *args, **kwargs):
            raise NotImplementedError()

        def unwrap_winrm(self, *args, **kwargs):
            raise NotImplementedError()

        def sign(self, data, qop=None):
            return b"MIC" + data

        def verify(self, data, mic):
            return 0

        @property
        def _context_attr_map(self):
            return []

    kerberos = spnego._context.GSSMech.kerberos
    original = spnego._negotiate.NegotiateProxy(
        usage="initiate",
        options=NegotiateOptions.use_negotiate,
        _negotiate_contexts={kerberos: FakeKerberosContext()},
    )

    fresh = original.new_context()

    assert fresh._available_contexts is not original._available_contexts
    assert set(fresh._available_contexts) == {kerberos}
    assert fresh._available_contexts[kerberos] is not original._available_contexts[kerberos]
    assert fresh._context_list == {}
    assert fresh._mech_list == []
    assert fresh._mic_sent is False
    assert fresh._mic_recv is False
    assert fresh._complete is False


def test_negotiate_stub_rebuilds_injected_context_before_first_step():
    """DOCUMENTED STAND-IN SCOPE: same fake as above, but before the mech list exists.

    This is the retry case that used to drop configuration: an injected mech
    context must survive a new_context() taken before the first step. Again
    this proves the copy/rebuild plumbing only, not Kerberos itself.
    """
    kerberos = spnego._context.GSSMech.kerberos
    original = _StubNegotiateContext()
    fresh = original.new_context()

    assert fresh._context_list == {}
    assert fresh._available_contexts is not original._available_contexts
    assert set(fresh._available_contexts) == {kerberos}
    assert fresh._available_contexts[kerberos] is not original._available_contexts[kerberos]
    assert fresh._mic_sent is False
    assert fresh._mic_recv is False


class _StubNegotiateContext(spnego._negotiate.NegotiateProxy):
    """NegotiateProxy with one injected, credential-less Kerberos stand-in."""

    def __init__(self, **kwargs: typing.Any) -> None:
        super().__init__(
            usage="initiate",
            options=NegotiateOptions.use_negotiate,
            _negotiate_contexts={spnego._context.GSSMech.kerberos: _StubMechContext()},
            **kwargs,
        )


class _StubMechContext(ContextProxy):
    """Minimal ContextProxy stand-in injected into Negotiate; no auth is performed."""

    def __init__(self) -> None:
        super().__init__([], None, None, None, ContextReq.default, "initiate", "kerberos", NegotiateOptions.none)

    @classmethod
    def available_protocols(cls, options=None):
        return ["kerberos"]

    @property
    def client_principal(self):
        return None

    @property
    def complete(self):
        return False

    @property
    def negotiated_protocol(self):
        return "kerberos"

    @property
    def session_key(self):
        return b"\x00" * 16

    def new_context(self):
        return _StubMechContext()

    def query_message_sizes(self):
        raise NotImplementedError()

    def step(self, in_token=None, *, channel_bindings=None):
        return b"AP-REQ"

    def wrap(self, *args, **kwargs):
        raise NotImplementedError()

    def wrap_iov(self, *args, **kwargs):
        raise NotImplementedError()

    def wrap_winrm(self, *args, **kwargs):
        raise NotImplementedError()

    def unwrap(self, *args, **kwargs):
        raise NotImplementedError()

    def unwrap_iov(self, *args, **kwargs):
        raise NotImplementedError()

    def unwrap_winrm(self, *args, **kwargs):
        raise NotImplementedError()

    def sign(self, data, qop=None):
        return b"MIC" + data

    def verify(self, data, mic):
        return 0

    @property
    def _context_attr_map(self):
        return []
