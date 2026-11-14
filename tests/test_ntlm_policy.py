import re
import socket

import pytest

import spnego
import spnego._ntlm as ntlm
from spnego._ntlm_policy import NTLMPolicy
from spnego._ntlm_raw.messages import (
    Authenticate,
    Negotiate,
    NegotiateFlags,
)
from spnego.exceptions import (
    InvalidTokenError,
    OperationNotAvailableError,
    SpnegoError,
)


def _ntlm_client(username, password, **kwargs):
    return spnego.client(
        username,
        password,
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
        **kwargs,
    )


def _ntlm_server(**kwargs):
    return spnego.server(
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
        **kwargs,
    )


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        (
            {"generate_ntlmv1": False, "generate_ntlmv2": False},
            "must allow the initiator to generate NTLMv1 and/or NTLMv2",
        ),
        (
            {"generate_lm": True, "generate_ntlmv1": False},
            "cannot generate LM responses without allowing NTLMv1",
        ),
        (
            {"accept_lm": False, "accept_ntlmv1": False, "accept_ntlmv2": False},
            "must allow the acceptor to accept LM, NTLMv1, and/or NTLMv2",
        ),
        (
            {"accept_lm": True, "accept_ntlmv1": False},
            "cannot accept LM responses without allowing NTLMv1",
        ),
    ],
)
def test_invalid_policy(kwargs, expected):
    with pytest.raises(ValueError, match=re.escape(expected)):
        NTLMPolicy(**kwargs)


def test_policy_not_policy_instance(ntlm_cred):
    expected = "ntlm_policy must be an spnego.NTLMPolicy instance, got str"
    with pytest.raises(SpnegoError, match=re.escape(expected)):
        _ntlm_client(ntlm_cred[0], ntlm_cred[1], ntlm_policy="strict")


@pytest.mark.parametrize(
    "level, expected",
    [
        (0, (True, True, False, True, True, True, False, True)),
        (1, (True, True, False, True, True, True, True, True)),
        (2, (False, True, False, True, True, True, True, False)),
        (3, (False, False, True, True, True, True, True, False)),
        (4, (False, False, True, False, True, True, True, False)),
        (5, (False, False, True, False, False, True, True, False)),
    ],
)
def test_policy_from_compat_level(level, expected):
    policy = NTLMPolicy.from_compat_level(level)

    actual = (
        policy.generate_lm,
        policy.generate_ntlmv1,
        policy.generate_ntlmv2,
        policy.accept_lm,
        policy.accept_ntlmv1,
        policy.accept_ntlmv2,
        policy.extended_session_security,
        policy.lm_key,
    )
    assert actual == expected


@pytest.mark.parametrize("level", [-1, 6])
def test_policy_from_invalid_compat_level(level):
    with pytest.raises(ValueError, match="Invalid LM compatibility level"):
        NTLMPolicy.from_compat_level(level)


def test_policy_strict_is_level_5():
    assert NTLMPolicy.strict() == NTLMPolicy.from_compat_level(5)


def test_policy_from_env_default(monkeypatch):
    monkeypatch.delenv("LM_COMPAT_LEVEL", raising=False)
    assert NTLMPolicy.from_env() == NTLMPolicy.from_compat_level(3)


def test_policy_from_env_value(monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", "0")
    assert NTLMPolicy.from_env() == NTLMPolicy.from_compat_level(0)


@pytest.mark.parametrize("value", ["-1", "6", "invalid"])
def test_policy_from_env_invalid(value, monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", value)
    with pytest.raises(SpnegoError, match="Invalid LM_COMPAT_LEVEL"):
        NTLMPolicy.from_env()


@pytest.mark.parametrize("level", range(6))
def test_policy_matches_legacy_env_config(level, ntlm_cred, monkeypatch):
    """Migration check: an explicit policy behaves like the old env var config."""
    monkeypatch.setenv("LM_COMPAT_LEVEL", str(level))
    env_client = _ntlm_client(ntlm_cred[0], ntlm_cred[1])
    env_server = _ntlm_server()

    monkeypatch.delenv("LM_COMPAT_LEVEL")
    policy = NTLMPolicy.from_compat_level(level)
    policy_client = _ntlm_client(ntlm_cred[0], ntlm_cred[1], ntlm_policy=policy)
    policy_server = _ntlm_server(ntlm_policy=policy)

    for env_context, policy_context in [(env_client, policy_client), (env_server, policy_server)]:
        assert (env_context._lm, env_context._nt_v1, env_context._nt_v2) == (
            policy_context._lm,
            policy_context._nt_v1,
            policy_context._nt_v2,
        )
        assert env_context._context_req == policy_context._context_req


def test_explicit_policy_overrides_env(ntlm_cred, monkeypatch):
    # The env var would allow LM/NTLMv1 but the explicit policy wins.
    monkeypatch.setenv("LM_COMPAT_LEVEL", "0")

    c = _ntlm_client(ntlm_cred[0], ntlm_cred[1], ntlm_policy=NTLMPolicy.strict())
    s = _ntlm_server(ntlm_policy=NTLMPolicy.strict())

    negotiate = c.step()
    auth = c.step(s.step(negotiate))
    s.step(auth)

    assert c.complete
    assert s.complete

    negotiate_msg = Negotiate.unpack(negotiate)
    assert negotiate_msg.flags & NegotiateFlags.extended_session_security
    assert not negotiate_msg.flags & NegotiateFlags.lm_key

    auth_msg = Authenticate.unpack(auth)
    assert len(auth_msg.nt_challenge_response) > 24  # NTLMv2 response


def test_env_change_after_creation_does_not_affect_context(ntlm_cred, monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", "5")
    c = _ntlm_client(ntlm_cred[0], ntlm_cred[1])
    s = _ntlm_server()

    # Weakening the env var after the contexts exist must not change the
    # ongoing handshake.
    monkeypatch.setenv("LM_COMPAT_LEVEL", "0")

    negotiate = c.step()
    auth = c.step(s.step(negotiate))
    s.step(auth)

    assert c.complete
    assert s.complete

    negotiate_msg = Negotiate.unpack(negotiate)
    assert negotiate_msg.flags & NegotiateFlags.extended_session_security
    assert not negotiate_msg.flags & NegotiateFlags.lm_key

    auth_msg = Authenticate.unpack(auth)
    assert len(auth_msg.nt_challenge_response) > 24  # still NTLMv2


def test_interleaved_strict_and_compatible_contexts(ntlm_cred):
    """Strict and compatible instances run interleaved in the one process.

    Each pair keeps its own acceptance range, the compatible pair completes
    with a real NTLMv1 exchange while the strict pair only accepts NTLMv2.
    """
    strict_policy = NTLMPolicy.strict()
    compat_policy = NTLMPolicy.from_compat_level(0)

    strict_c = _ntlm_client(ntlm_cred[0], ntlm_cred[1], ntlm_policy=strict_policy)
    strict_s = _ntlm_server(ntlm_policy=strict_policy)
    compat_c = _ntlm_client(ntlm_cred[0], ntlm_cred[1], ntlm_policy=compat_policy)
    compat_s = _ntlm_server(ntlm_policy=compat_policy)

    # Interleave the two handshakes step by step.
    compat_negotiate = compat_c.step()
    strict_negotiate = strict_c.step()

    compat_challenge = compat_s.step(compat_negotiate)
    strict_challenge = strict_s.step(strict_negotiate)

    compat_auth = compat_c.step(compat_challenge)
    strict_auth = strict_c.step(strict_challenge)

    # The compatible initiator generated a real NTLMv1 response while the
    # strict initiator generated NTLMv2.
    compat_auth_msg = Authenticate.unpack(compat_auth)
    assert len(compat_auth_msg.nt_challenge_response) == 24  # NTLMv1
    strict_auth_msg = Authenticate.unpack(strict_auth)
    assert len(strict_auth_msg.nt_challenge_response) > 24  # NTLMv2

    compat_s.step(compat_auth)
    strict_s.step(strict_auth)

    assert compat_c.complete and compat_s.complete
    assert strict_c.complete and strict_s.complete

    # The strict acceptor still rejects a legacy NTLMv1 response even though
    # the compatible acceptor just completed one successfully.
    legacy_c = _ntlm_client(ntlm_cred[0], ntlm_cred[1], ntlm_policy=compat_policy)
    strict_s2 = _ntlm_server(ntlm_policy=strict_policy)
    legacy_auth = legacy_c.step(strict_s2.step(legacy_c.step()))
    assert len(Authenticate.unpack(legacy_auth).nt_challenge_response) == 24

    with pytest.raises(InvalidTokenError, match="Acceptor settings are set to reject NTv1 responses"):
        strict_s2.step(legacy_auth)

    # ... and the strict instances were not loosened by the legacy success.
    assert strict_s._ntlm_policy == strict_policy
    assert strict_s._nt_v1 is False
    assert strict_s._lm is False


def test_acceptor_rejects_lm_response(ntlm_cred):
    # The acceptor allows NTLMv1 but not LM (level 4 equivalent).
    compat_policy = NTLMPolicy.from_compat_level(0)

    c = _ntlm_client(ntlm_cred[0], ntlm_cred[1], ntlm_policy=compat_policy)
    s = _ntlm_server(ntlm_policy=NTLMPolicy.from_compat_level(4))

    auth = memoryview(bytearray(c.step(s.step(c.step())) or b""))
    auth[20:28] = b"\x00" * 8  # strip the NT response, leaving only LM

    with pytest.raises(InvalidTokenError, match="Acceptor settings are set to reject LM responses"):
        s.step(auth.tobytes())


def test_compatible_acceptor_still_allows_ntlmv2(ntlm_cred):
    # A compatible acceptor (level 0) accepts the strict initiator's NTLMv2
    # response, i.e. the accept ranges are independent per instance.
    c = _ntlm_client(ntlm_cred[0], ntlm_cred[1], ntlm_policy=NTLMPolicy.strict())
    s = _ntlm_server(ntlm_policy=NTLMPolicy.from_compat_level(0))

    auth = c.step(s.step(c.step()))
    s.step(auth)

    assert c.complete
    assert s.complete


def test_acceptor_rejects_ntlmv2_when_policy_disallows(ntlm_cred):
    policy = NTLMPolicy(
        generate_ntlmv1=True,
        generate_ntlmv2=False,
        accept_ntlmv1=True,
        accept_ntlmv2=False,
    )

    c = _ntlm_client(ntlm_cred[0], ntlm_cred[1], ntlm_policy=NTLMPolicy.strict())
    s = _ntlm_server(ntlm_policy=policy)

    auth = c.step(s.step(c.step()))
    assert len(Authenticate.unpack(auth).nt_challenge_response) > 24

    with pytest.raises(InvalidTokenError, match="Acceptor settings are set to reject NTv2 responses"):
        s.step(auth)


def test_negotiate_context_enforces_policy(ntlm_cred):
    # The SPNEGO wrapper forwards the policy to the Python NTLM provider.
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_negotiate,
        protocol="negotiate",
        ntlm_policy=NTLMPolicy.strict(),
    )
    s = spnego.server(
        options=spnego.NegotiateOptions.use_negotiate,
        protocol="negotiate",
        ntlm_policy=NTLMPolicy.strict(),
    )

    in_token = None
    while not (c.complete and s.complete):
        out_token = c.step(in_token)
        in_token = s.step(out_token)

    assert c.complete
    assert s.complete


def test_negotiate_strict_acceptor_rejects_legacy(ntlm_cred):
    # A compatible SPNEGO initiator cannot complete NTLMv1 auth against a
    # strict SPNEGO acceptor.
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_negotiate,
        protocol="negotiate",
        ntlm_policy=NTLMPolicy.from_compat_level(0),
    )
    s = spnego.server(
        options=spnego.NegotiateOptions.use_negotiate,
        protocol="negotiate",
        ntlm_policy=NTLMPolicy.strict(),
    )

    with pytest.raises(InvalidTokenError, match="Acceptor settings are set to reject NTv1 responses"):
        in_token = None
        while not s.complete:
            out_token = c.step(in_token)
            in_token = s.step(out_token)


def test_sspi_provider_cannot_enforce_policy(ntlm_cred):
    expected = "The SSPI provider cannot enforce an explicit NTLM policy"
    with pytest.raises(OperationNotAvailableError, match=re.escape(expected)):
        spnego.client(
            ntlm_cred[0],
            ntlm_cred[1],
            options=spnego.NegotiateOptions.use_sspi,
            protocol="ntlm",
            ntlm_policy=NTLMPolicy.strict(),
        )


def test_gssapi_provider_cannot_enforce_policy(ntlm_cred):
    expected = "The GSSAPI provider cannot enforce an explicit NTLM policy"
    with pytest.raises(OperationNotAvailableError, match=re.escape(expected)):
        spnego.client(
            ntlm_cred[0],
            ntlm_cred[1],
            options=spnego.NegotiateOptions.use_gssapi,
            protocol="ntlm",
            ntlm_policy=NTLMPolicy.strict(),
        )
