# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

import pytest

import spnego
import spnego._gss
from spnego._context import GSSMech
from spnego._negotiate import NegotiateProxy
from spnego._spnego import NegState, NegTokenInit, NegTokenResp
from spnego.exceptions import (
    BadMechanismError,
    InvalidCredentialError,
    InvalidTokenError,
    NoCredentialError,
)


def test_token_rejected(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)

    c.step()
    token_resp = NegTokenResp(neg_state=NegState.reject).pack()

    with pytest.raises(InvalidTokenError, match="Received SPNEGO rejection with no token error message"):
        c.step(token_resp)


def test_token_invalid_input(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)

    c.step()
    with pytest.raises(InvalidTokenError, match="Failed to unpack input token"):
        c.step(b"\x00")


def test_token_no_common_mechs(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)

    with pytest.raises(BadMechanismError, match="Unable to negotiate common mechanism"):
        c.step(NegTokenInit(mech_types=["1.2.3.4"]).pack())


def test_token_acceptor_first(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    assert getattr(c, "_mech_list", None) == []
    assert getattr(s, "_mech_list", None) == []

    token1 = s.step()
    assert isinstance(token1, bytes)
    assert not c.complete
    assert not s.complete
    assert getattr(c, "_mech_list", None) == []
    assert GSSMech.ntlm.value in getattr(s, "_mech_list", [])

    negotiate = c.step(token1)
    assert isinstance(negotiate, bytes)
    assert not c.complete
    assert not s.complete
    assert getattr(c, "_mech_list", None) == [GSSMech.ntlm.value]
    assert GSSMech.ntlm.value in getattr(s, "_mech_list", [])

    challenge = s.step(negotiate)
    assert isinstance(challenge, bytes)
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert isinstance(authenticate, bytes)
    assert not c.complete
    assert not s.complete

    mech_list_mic = s.step(authenticate)
    assert isinstance(mech_list_mic, bytes)
    assert not c.complete
    assert s.complete

    final_token = c.step(mech_list_mic)
    assert final_token is None
    assert c.complete
    assert s.complete


@pytest.mark.skipif("ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Requires SSPI library")
def test_iov_available_sspi():
    assert NegotiateProxy.iov_available()


@pytest.mark.skipif(not spnego._gss.HAS_GSSAPI, reason="Requires the gssapi library to be installed for testing")
def test_iov_available_gssapi():
    assert NegotiateProxy.iov_available() == spnego._gss.GSSAPIProxy.iov_available()


class FakeKerberosContext(spnego._context.ContextProxy):
    """A stand in for a Kerberos context that completes in one round trip without needing a KDC.

    The protocol can be changed to have the context stand in for another mechanism, like NTLM, when a test needs
    multiple fake mechanisms in the one exchange.
    """

    def __init__(self, usage: str = "initiate", protocol: str = "kerberos") -> None:
        super().__init__(
            [spnego.CredentialCache()],
            None,
            None,
            None,
            spnego.ContextReq.default,
            usage,
            protocol,
            spnego.NegotiateOptions.none,
        )
        self._complete = False
        self.tokens: typing.List[typing.Optional[bytes]] = []

    @classmethod
    def available_protocols(cls, options=None):
        return ["kerberos", "ntlm"]

    @property
    def client_principal(self):
        return None

    @property
    def complete(self):
        return self._complete

    @property
    def negotiated_protocol(self):
        return self.protocol

    @property
    def session_key(self):
        return b"\x00" * 16

    def new_context(self):
        return FakeKerberosContext(self.usage)

    def query_message_sizes(self):
        raise NotImplementedError()

    def step(self, in_token=None, *, channel_bindings=None):
        self.tokens.append(in_token)
        if self.usage == "accept":
            self._complete = True
            return b"AP-REP"

        elif in_token:
            self._complete = True
            return None

        else:
            return b"AP-REQ"

    def wrap(self, data, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_iov(self, iov, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_winrm(self, data):
        raise NotImplementedError()

    def unwrap(self, data):
        raise NotImplementedError()

    def unwrap_iov(self, iov):
        raise NotImplementedError()

    def unwrap_winrm(self, header, data):
        raise NotImplementedError()

    def sign(self, data, qop=None):
        return b"MIC" + data

    def verify(self, data, mic):
        assert mic == b"MIC" + data
        return 0

    @property
    def _context_attr_map(self):
        return []


@pytest.fixture()
def kerberos_preferred(monkeypatch):
    """Make the Negotiate proxy prefer Kerberos regardless of what the host supports."""
    monkeypatch.setattr(
        NegotiateProxy,
        "available_protocols",
        classmethod(lambda cls, options=None: ["kerberos", "ntlm", "negotiate"]),
    )


@pytest.mark.parametrize(
    "mech_types, expected_mech",
    [
        # Windows lists the MS Kerberos OID first and rejects a reply that does not echo it.
        (
            [GSSMech._ms_kerberos.value, GSSMech.kerberos.value, GSSMech.negoex.value, GSSMech.ntlm.value],
            GSSMech._ms_kerberos.value,
        ),
        ([GSSMech.kerberos.value, GSSMech._ms_kerberos.value, GSSMech.ntlm.value], GSSMech.kerberos.value),
        ([GSSMech.kerberos.value, GSSMech.ntlm.value], GSSMech.kerberos.value),
        ([GSSMech._ms_kerberos.value, GSSMech.ntlm.value], GSSMech._ms_kerberos.value),
    ],
)
def test_acceptor_echoes_offered_kerberos_oid(mech_types, expected_mech, kerberos_preferred):
    s = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("accept")},
    )

    init = NegTokenInit(mech_types=mech_types, mech_token=b"AP-REQ").pack()
    out_token = s.step(init)
    assert out_token
    resp = spnego._spnego.unpack_token(out_token)

    assert isinstance(resp, NegTokenResp)
    assert resp.supported_mech == expected_mech
    assert resp.neg_state == NegState.accept_complete
    assert resp.response_token == b"AP-REP"
    assert resp.mech_list_mic is None
    assert s.complete
    assert s.negotiated_protocol == "kerberos"


def test_acceptor_verifies_mic_after_ms_kerberos(kerberos_preferred):
    s = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("accept")},
    )

    mech_types = [GSSMech._ms_kerberos.value, GSSMech.kerberos.value, GSSMech.ntlm.value]
    s.step(NegTokenInit(mech_types=mech_types, mech_token=b"AP-REQ").pack())
    assert s.complete

    # Windows still sends its mechListMIC after accept-completed, it must verify against the list it sent.
    mic = b"MIC" + spnego._spnego.pack_mech_type_list(mech_types)
    assert s.step(NegTokenResp(mech_list_mic=mic).pack()) is None
    assert s.complete


def test_acceptor_creates_mech_contexts_with_credentials(monkeypatch, kerberos_preferred):
    real_server = spnego.server
    calls = []

    def fake_server(**kwargs):
        calls.append(kwargs)
        if kwargs["protocol"] == "kerberos":
            return FakeKerberosContext("accept")

        return real_server(**kwargs)

    monkeypatch.setattr(spnego, "server", fake_server)

    cred = spnego.Password(username="svc-winrm@PSWSMAN.TEST", password="pass")
    s = NegotiateProxy(
        cred,
        hostname="winrm.pswsman.test",
        service="HTTP",
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
    )

    # Only the MS Kerberos OID is offered, the acceptor must still treat that as Kerberos.
    init = NegTokenInit(mech_types=[GSSMech._ms_kerberos.value, GSSMech.ntlm.value], mech_token=b"AP-REQ").pack()
    out_token = s.step(init)
    assert out_token
    resp = spnego._spnego.unpack_token(out_token)
    assert isinstance(resp, NegTokenResp)

    kerberos_calls = [c for c in calls if c["protocol"] == "kerberos"]
    assert len(kerberos_calls) == 1
    assert kerberos_calls[0]["credentials"] == [cred]
    assert kerberos_calls[0]["hostname"] == "winrm.pswsman.test"
    assert kerberos_calls[0]["service"] == "HTTP"

    assert resp.supported_mech == GSSMech._ms_kerberos.value
    assert resp.neg_state == NegState.accept_complete
    assert s.complete


@pytest.mark.parametrize("supported_mech", [GSSMech._ms_kerberos.value, GSSMech._kerberos_draft.value])
def test_initiator_accepts_kerberos_alias_supported_mech(supported_mech):
    c = NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("initiate")},
    )

    out_token = c.step()
    assert out_token
    init = spnego._spnego.unpack_token(out_token)
    assert isinstance(init, NegTokenInit)
    assert init.mech_types == [GSSMech.kerberos.value]
    assert init.mech_token == b"AP-REQ"

    resp = NegTokenResp(
        neg_state=NegState.accept_complete,
        supported_mech=supported_mech,
        response_token=b"AP-REP",
    ).pack()
    assert c.step(resp) is None
    assert c.complete
    assert c.negotiated_protocol == "kerberos"


def test_mech_policy_requires_mechs():
    with pytest.raises(ValueError, match="at least one allowed mechanism"):
        spnego.MechPolicy([])


def test_mech_policy_unknown_mech():
    with pytest.raises(ValueError, match="is not a valid GSSMech OID"):
        spnego.MechPolicy(["1.2.3.4"])


def test_mech_policy_normalizes_kerberos_aliases():
    policy = spnego.MechPolicy([GSSMech._ms_kerberos.value, "ntlm"])

    assert policy.allowed_mechs == {GSSMech.kerberos, GSSMech.ntlm}
    assert policy.allows("kerberos")
    assert policy.allows(GSSMech._kerberos_draft)
    assert policy.allows(GSSMech.kerberos.value)
    assert not policy.allows("negoex")
    assert not policy.allows("1.2.3.4")


def test_context_carries_explicit_mech_policy():
    policy = spnego.MechPolicy(["kerberos"])
    c = NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=policy,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("initiate")},
    )

    assert c.mech_policy is policy

    c.step()
    assert c.new_context().mech_policy is policy


def test_context_default_mech_policy():
    c = NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("initiate")},
    )

    assert c.mech_policy == spnego.MechPolicy.default()
    assert c.mech_policy.allows("kerberos")
    assert c.mech_policy.allows("ntlm")


def test_policy_filters_optimistic_token(kerberos_preferred, ntlm_cred):
    ntlm_context = spnego.client(ntlm_cred[0], ntlm_cred[1], protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
    c = NegotiateProxy(
        ntlm_cred[0],
        ntlm_cred[1],
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=spnego.MechPolicy(["ntlm"]),
        _negotiate_contexts={
            GSSMech.kerberos: FakeKerberosContext("initiate"),
            GSSMech.ntlm: ntlm_context,
        },
    )

    out_token = c.step()
    assert out_token
    init = spnego._spnego.unpack_token(out_token)

    # The Kerberos context was provided first but is not allowed, the optimistic token must be the NTLM one.
    assert isinstance(init, NegTokenInit)
    assert init.mech_types == [GSSMech.ntlm.value]
    assert init.mech_token is not None
    assert init.mech_token.startswith(b"NTLMSSP\x00")


def test_policy_excludes_all_local_mechs(monkeypatch):
    monkeypatch.setattr(
        NegotiateProxy,
        "available_protocols",
        classmethod(lambda cls, options=None: ["ntlm", "negotiate"]),
    )
    c = NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=spnego.MechPolicy(["kerberos"]),
    )

    with pytest.raises(BadMechanismError, match="No locally available mechanism is allowed by the context"):
        c.step()


def test_acceptor_rejects_peer_without_allowed_mech(monkeypatch, kerberos_preferred):
    real_server = spnego.server

    def fake_server(**kwargs):
        if kwargs["protocol"] == "kerberos":
            return FakeKerberosContext("accept")

        return real_server(**kwargs)

    monkeypatch.setattr(spnego, "server", fake_server)

    s = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=spnego.MechPolicy(["kerberos"]),
    )

    # The peer only offers NTLM which the policy does not admit.
    init = NegTokenInit(mech_types=[GSSMech.ntlm.value], mech_token=b"NTLMSSP\x00" + b"\x00" * 32).pack()
    with pytest.raises(BadMechanismError, match="Unable to negotiate common mechanism"):
        s.step(init)


def test_initiator_rejects_unallowed_supported_mech():
    c = NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=spnego.MechPolicy(["kerberos"]),
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("initiate")},
    )

    c.step()
    resp = NegTokenResp(
        neg_state=NegState.accept_incomplete,
        supported_mech=GSSMech.ntlm.value,
        response_token=b"NTLMSSP\x00" + b"\x00" * 32,
    ).pack()
    with pytest.raises(BadMechanismError, match="not allowed by the context mechanism policy"):
        c.step(resp)


def test_initiator_rejects_mech_switching():
    c = NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=spnego.MechPolicy(["kerberos", "ntlm"]),
        _negotiate_contexts={
            GSSMech.kerberos: FakeKerberosContext("initiate"),
            GSSMech.ntlm: FakeKerberosContext("initiate", protocol="ntlm"),
        },
    )

    c.step()

    # The acceptor selecting another allowed mech than the optimistic one is still negotiation.
    resp1 = NegTokenResp(
        neg_state=NegState.accept_incomplete,
        supported_mech=GSSMech.ntlm.value,
        response_token=b"CHALLENGE",
    ).pack()
    assert c.step(resp1) is not None

    # Switching the mechanism again after one was chosen is a downgrade attempt and must be rejected.
    resp2 = NegTokenResp(
        neg_state=NegState.accept_incomplete,
        supported_mech=GSSMech.kerberos.value,
        response_token=b"AP-REQ",
    ).pack()
    with pytest.raises(InvalidTokenError, match="switch the negotiated mechanism"):
        c.step(resp2)


def test_raw_ntlm_token_rejected_by_policy():
    s = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=spnego.MechPolicy(["kerberos"]),
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("accept")},
    )

    with pytest.raises(BadMechanismError, match="Raw ntlm tokens are not allowed by the context mechanism policy"):
        s.step(b"NTLMSSP\x00" + b"\x00" * 32)


def test_unavailable_mech_falls_back_within_policy(monkeypatch, kerberos_preferred, ntlm_cred):
    real_client = spnego.client

    def fake_client(*args, **kwargs):
        if kwargs.get("protocol") == "kerberos":
            raise NoCredentialError(context_msg="no credential cache for kerberos")

        return real_client(*args, **kwargs)

    monkeypatch.setattr(spnego, "client", fake_client)

    c = NegotiateProxy(
        ntlm_cred[0],
        ntlm_cred[1],
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=spnego.MechPolicy(["kerberos", "ntlm"]),
    )

    out_token = c.step()
    assert out_token
    init = spnego._spnego.unpack_token(out_token)

    # Kerberos is not usable locally so the next allowed mechanism is used.
    assert isinstance(init, NegTokenInit)
    assert init.mech_types == [GSSMech.ntlm.value]


def test_credential_error_does_not_fall_back(monkeypatch, kerberos_preferred, ntlm_cred):
    real_client = spnego.client

    def fake_client(*args, **kwargs):
        if kwargs.get("protocol") == "kerberos":
            raise InvalidCredentialError(context_msg="kerberos credential was rejected")

        return real_client(*args, **kwargs)

    monkeypatch.setattr(spnego, "client", fake_client)

    c = NegotiateProxy(
        ntlm_cred[0],
        ntlm_cred[1],
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=spnego.MechPolicy(["kerberos", "ntlm"]),
    )

    # A credential failure is not a reason to silently try the weaker mechanism.
    with pytest.raises(InvalidCredentialError, match="kerberos credential was rejected"):
        c.step()


def test_token_validation_error_does_not_fall_back(monkeypatch, kerberos_preferred, ntlm_cred):
    class BadTokenContext(FakeKerberosContext):
        def step(self, in_token=None, *, channel_bindings=None):
            raise InvalidTokenError(context_msg="kerberos token validation failed")

    real_client = spnego.client

    def fake_client(*args, **kwargs):
        if kwargs.get("protocol") == "kerberos":
            return BadTokenContext("initiate")

        return real_client(*args, **kwargs)

    monkeypatch.setattr(spnego, "client", fake_client)

    c = NegotiateProxy(
        ntlm_cred[0],
        ntlm_cred[1],
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=spnego.MechPolicy(["kerberos", "ntlm"]),
    )

    # A token validation failure is not a reason to silently try the weaker mechanism.
    with pytest.raises(InvalidTokenError, match="kerberos token validation failed"):
        c.step()


def test_ntlm_only_policy_full_exchange(ntlm_cred):
    """A Kerberos free host can complete SPNEGO when the policy admits NTLM, using the pure Python NTLM provider."""
    policy = spnego.MechPolicy(["ntlm"])
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        options=spnego.NegotiateOptions.use_negotiate,
        mech_policy=policy,
    )
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate, mech_policy=policy)

    assert isinstance(c, NegotiateProxy)
    assert isinstance(s, NegotiateProxy)
    assert c.mech_policy is policy
    assert s.mech_policy is policy

    negotiate = c.step()
    assert isinstance(negotiate, bytes)
    init = spnego._spnego.unpack_token(negotiate)
    assert isinstance(init, NegTokenInit)
    assert init.mech_types == [GSSMech.ntlm.value]
    assert not c.complete
    assert not s.complete

    challenge = s.step(negotiate)
    assert isinstance(challenge, bytes)
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert isinstance(authenticate, bytes)
    assert not c.complete
    assert not s.complete

    mech_list_mic = s.step(authenticate)
    assert isinstance(mech_list_mic, bytes)
    assert not c.complete
    assert s.complete

    final_token = c.step(mech_list_mic)
    assert final_token is None
    assert c.complete
    assert s.complete

    assert c.negotiated_protocol == "ntlm"
    assert s.negotiated_protocol == "ntlm"

    # The exchange was done with the pure Python NTLM provider, no native Kerberos or SSPI was involved.
    assert isinstance(c._context_list[GSSMech.ntlm][0], spnego._ntlm.NTLMProxy)
    assert isinstance(s._context_list[GSSMech.ntlm][0], spnego._ntlm.NTLMProxy)
