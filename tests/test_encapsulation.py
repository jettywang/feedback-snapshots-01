# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import socket
import typing

import pytest

import spnego
from spnego._context import GSSMech
from spnego._negotiate import NegotiateProxy
from spnego._ntlm import NTLMProxy
from spnego._spnego import (
    EncapsulationPolicy,
    InitialContextToken,
    NegState,
    NegTokenInit,
    NegTokenResp,
    classify_negotiate_token,
    unpack_token,
)
from spnego.channel_bindings import GssChannelBindings
from spnego.exceptions import InvalidTokenError


class RecordingNTLMProxy(NTLMProxy):
    """An NTLM context that records every raw mechanism token the SPNEGO layer hands to it."""

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        self.received_tokens: typing.List[typing.Optional[bytes]] = []

    def step(
        self,
        in_token: typing.Optional[bytes] = None,
        *,
        channel_bindings: typing.Optional[GssChannelBindings] = None,
    ) -> typing.Optional[bytes]:
        self.received_tokens.append(in_token)
        return super().step(in_token=in_token, channel_bindings=channel_bindings)


def _raw_ntlm_client(ntlm_cred: typing.Tuple[str, str]) -> spnego.ContextProxy:
    return spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )


def _spnego_client(ntlm_cred: typing.Tuple[str, str]) -> spnego.ContextProxy:
    return spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_negotiate,
    )


def _recording_server(policy: EncapsulationPolicy) -> typing.Tuple[NegotiateProxy, RecordingNTLMProxy]:
    inner = RecordingNTLMProxy(
        usage="accept",
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )
    server = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        encapsulation=policy,
        _negotiate_contexts={GSSMech.ntlm: inner},
    )
    return server, inner


def test_encapsulation_policy_native():
    assert EncapsulationPolicy.native(EncapsulationPolicy.spnego) == EncapsulationPolicy.spnego
    assert EncapsulationPolicy.native("raw") == EncapsulationPolicy.raw
    assert EncapsulationPolicy.native("SPNEGO") == EncapsulationPolicy.spnego

    with pytest.raises(ValueError, match="Invalid encapsulation policy"):
        EncapsulationPolicy.native("does-not-exist")


def test_classify_rejects_empty_token():
    with pytest.raises(InvalidTokenError, match="Received an empty authentication token"):
        classify_negotiate_token(b"")


def test_classify_rejects_unknown_oid():
    token = InitialContextToken("1.2.3.4.5", b"\x00\x00\x00\x00").pack()

    with pytest.raises(InvalidTokenError, match="unknown mechanism OID '1.2.3.4.5'"):
        classify_negotiate_token(token)


def test_classify_rejects_nested_wrapper():
    inner = NegTokenInit(mech_types=[GSSMech.ntlm.value]).pack()
    nested = InitialContextToken(GSSMech.spnego, inner).pack()

    with pytest.raises(InvalidTokenError, match="nested InitialContextToken"):
        classify_negotiate_token(nested)


def test_classify_rejects_unstructured_bytes():
    with pytest.raises(InvalidTokenError, match="does not match a SPNEGO, NTLM, or Kerberos message structure"):
        classify_negotiate_token(b"\x00\x01\x02\x03")


def test_classify_bad_application_tag():
    from spnego._asn1 import TagClass, pack_asn1

    token = pack_asn1(TagClass.application, True, 1, b"\x00\x00\x00\x00")
    with pytest.raises(InvalidTokenError, match="Expecting a tag number of 0 not 1"):
        classify_negotiate_token(token)


def test_classify_bad_negotiation_choice():
    from spnego._asn1 import TagClass, pack_asn1

    token = pack_asn1(TagClass.context_specific, True, 2, b"\x00\x00\x00\x00")
    with pytest.raises(InvalidTokenError, match="Unknown NegotiationToken CHOICE 2"):
        classify_negotiate_token(token)


def test_classify_identifies_spnego_and_raw_ntlm(ntlm_cred):
    spnego_init = _spnego_client(ntlm_cred).step()
    classified = classify_negotiate_token(spnego_init)
    assert classified.kind == "spnego"
    assert isinstance(classified.token, NegTokenInit)
    assert classified.mech is None

    raw_negotiate = _raw_ntlm_client(ntlm_cred).step()
    classified = classify_negotiate_token(raw_negotiate)
    assert classified.kind == "ntlm"
    assert classified.mech == GSSMech.ntlm
    assert classified.token.startswith(b"NTLMSSP\x00")


def test_spnego_policy_rejects_raw_first_token(ntlm_cred):
    server, inner = _recording_server(EncapsulationPolicy.spnego)
    raw_negotiate = _raw_ntlm_client(ntlm_cred).step()

    with pytest.raises(InvalidTokenError, match="Encapsulation policy 'spnego' does not permit a 'raw' first token"):
        server.step(raw_negotiate)

    # The rejection happens in the outer layer, the underlying NTLM mechanism never saw the token.
    assert inner.received_tokens == []
    assert server._failed


def test_raw_policy_rejects_spnego_first_token(ntlm_cred):
    server, inner = _recording_server(EncapsulationPolicy.raw)
    spnego_init = _spnego_client(ntlm_cred).step()

    with pytest.raises(InvalidTokenError, match="Encapsulation policy 'raw' does not permit a 'spnego' first token"):
        server.step(spnego_init)

    assert inner.received_tokens == []
    assert server._failed


def test_raw_ntlm_after_spnego_start_cannot_skip_outer_state(ntlm_cred):
    server, inner = _recording_server(EncapsulationPolicy.any)
    client = _spnego_client(ntlm_cred)

    challenge = server.step(client.step())
    assert isinstance(unpack_token(challenge), NegTokenResp)
    assert server._encapsulation == "spnego"

    # Build a genuine bare NTLM authenticate for the challenge the SPNEGO layer wrapped.
    raw_client = _raw_ntlm_client(ntlm_cred)
    raw_client.step()
    wrapped_challenge = unpack_token(challenge).response_token
    bare_authenticate = raw_client.step(wrapped_challenge)

    with pytest.raises(InvalidTokenError, match="Encapsulation cannot change mid-exchange"):
        server.step(bare_authenticate)

    # The underlying NTLM mechanism only processed the negotiate from the SPNEGO mechToken, the stripped bare token was
    # never handed down.
    assert len(inner.received_tokens) == 1
    assert inner.received_tokens[0].startswith(b"NTLMSSP\x00\x01")
    assert server._failed

    # Remaining bytes after the rejection cannot start another authentication on the same context.
    with pytest.raises(InvalidTokenError, match="exchange has already failed"):
        server.step(bare_authenticate)


def test_duplicate_initial_context_token_restarts_nothing(ntlm_cred):
    server, inner = _recording_server(EncapsulationPolicy.any)
    client = _spnego_client(ntlm_cred)

    init = client.step()
    server.step(init)

    with pytest.raises(InvalidTokenError, match="duplicate NegTokenInit"):
        server.step(init)

    assert server._failed


def test_empty_token_is_state_dependent(ntlm_cred):
    # An empty token before the exchange starts is legal: the acceptor emits a NegTokenInit2 hint.
    hint_server = spnego.server(options=spnego.NegotiateOptions.use_negotiate)
    hint = hint_server.step()
    assert isinstance(unpack_token(hint), NegTokenInit)

    # An empty token once the exchange is underway is invalid rather than a fresh empty authentication.
    server, _ = _recording_server(EncapsulationPolicy.any)
    client = _spnego_client(ntlm_cred)
    server.step(client.step())

    with pytest.raises(InvalidTokenError, match="empty token after the SPNEGO exchange had started"):
        server.step(b"")


def test_neg_token_resp_before_init_is_rejected(ntlm_cred):
    server, _ = _recording_server(EncapsulationPolicy.any)
    response = NegTokenResp(neg_state=NegState.accept_incomplete).pack()

    with pytest.raises(InvalidTokenError, match="NegTokenResp before the SPNEGO exchange had started"):
        server.step(response)


def test_spnego_rejection_kills_the_context(ntlm_cred):
    client = _spnego_client(ntlm_cred)
    client.step()

    rejection = NegTokenResp(neg_state=NegState.reject).pack()
    with pytest.raises(InvalidTokenError, match="Received SPNEGO rejection with no token error message"):
        client.step(rejection)

    assert client._failed
    with pytest.raises(InvalidTokenError, match="exchange has already failed"):
        client.step(rejection)


def test_legacy_raw_handshake_completes_under_raw_policy(ntlm_cred):
    server, inner = _recording_server(EncapsulationPolicy.raw)
    client = _raw_ntlm_client(ntlm_cred)

    negotiate = client.step()
    challenge = server.step(negotiate)
    assert challenge.startswith(b"NTLMSSP\x00\x02")
    assert server._encapsulation == "raw"

    authenticate = client.step(challenge)
    final = server.step(authenticate)

    assert final is None
    assert client.complete
    assert server.complete
    assert server.negotiated_protocol == "ntlm"

    # The underlying NTLM mechanism saw the full legacy handshake, no SPNEGO wrapper was ever involved.
    assert [token[:8] for token in inner.received_tokens] == [b"NTLMSSP\x00", b"NTLMSSP\x00"]
    assert all(not isinstance(token, type(None)) for token in inner.received_tokens)


def test_legacy_raw_handshake_completes_under_any_policy(ntlm_cred):
    server, inner = _recording_server(EncapsulationPolicy.any)
    client = _raw_ntlm_client(ntlm_cred)

    challenge = server.step(client.step())
    final = server.step(client.step(challenge))

    assert final is None
    assert client.complete and server.complete
    assert server._encapsulation == "raw"
    assert len(inner.received_tokens) == 2


def test_spnego_handshake_records_wrapped_ntlm_tokens(ntlm_cred):
    server, inner = _recording_server(EncapsulationPolicy.spnego)
    client = _spnego_client(ntlm_cred)

    challenge = server.step(client.step())
    assert isinstance(unpack_token(challenge), NegTokenResp)

    authenticate = client.step(challenge)
    mech_list_mic = server.step(authenticate)
    client.step(mech_list_mic)

    assert client.complete and server.complete
    assert server._encapsulation == "spnego"

    # The mechanism only ever receives the inner NTLM tokens, never the outer SPNEGO wrapper.
    assert len(inner.received_tokens) == 2
    assert inner.received_tokens[0].startswith(b"NTLMSSP\x00\x01")
    assert inner.received_tokens[1].startswith(b"NTLMSSP\x00\x03")


def test_policy_is_pinned_and_propagated_to_new_context(ntlm_cred):
    server, _ = _recording_server(EncapsulationPolicy.spnego)
    new_context = server.new_context()

    assert isinstance(new_context, NegotiateProxy)
    assert new_context._encapsulation_policy == EncapsulationPolicy.spnego
    assert new_context._encapsulation is None
    assert new_context._failed is False


def test_raw_policy_acceptor_cannot_emit_spnego_hint(ntlm_cred):
    server = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        encapsulation=EncapsulationPolicy.raw,
    )

    with pytest.raises(InvalidTokenError, match="Encapsulation policy 'raw' does not permit a 'spnego' first token"):
        server.step()

    assert server._failed


def test_hint_pins_spnego_and_rejects_later_raw_token(ntlm_cred):
    server, inner = _recording_server(EncapsulationPolicy.spnego)
    hint = server.step()
    assert isinstance(unpack_token(hint), NegTokenInit)
    assert server._encapsulation == "spnego"

    raw_negotiate = _raw_ntlm_client(ntlm_cred).step()
    with pytest.raises(InvalidTokenError, match="Encapsulation cannot change mid-exchange"):
        server.step(raw_negotiate)

    assert inner.received_tokens == []


def test_classify_ntlm_oid_initial_context_token(ntlm_cred):
    raw_negotiate = _raw_ntlm_client(ntlm_cred).step()
    wrapped = InitialContextToken(GSSMech.ntlm, raw_negotiate).pack()

    classified = classify_negotiate_token(wrapped)
    assert classified.kind == "ntlm"
    assert classified.mech == GSSMech.ntlm
    assert classified.token == raw_negotiate


def test_classify_kerberos_initial_context_token():
    raw = b"\x30\x03\x01\x02\x03"
    wrapped = InitialContextToken(GSSMech.kerberos, raw).pack()

    classified = classify_negotiate_token(wrapped)
    assert classified.kind == "kerberos"
    assert classified.mech == GSSMech.kerberos
    assert classified.token == wrapped


def test_initiator_rejects_duplicate_init(ntlm_cred):
    server, _ = _recording_server(EncapsulationPolicy.any)
    client = _spnego_client(ntlm_cred)

    hint = server.step()
    client.step(hint)
    assert client._init_sent

    with pytest.raises(InvalidTokenError, match="duplicate NegTokenInit"):
        client.step(hint)

    assert client._failed


def test_classify_rejects_malformed_inner_spnego_token():
    from spnego._asn1 import TagClass, pack_asn1

    # InitialContextToken(SPNEGO) whose inner value claims to be a NegotiationToken CHOICE but cannot be parsed.
    malformed_choice = pack_asn1(TagClass.context_specific, True, 0, b"\x04\x00")
    token = InitialContextToken(GSSMech.spnego, malformed_choice).pack()

    with pytest.raises(InvalidTokenError, match="Failed to unpack inner SPNEGO token"):
        classify_negotiate_token(token)
