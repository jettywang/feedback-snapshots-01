# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@example.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import socket
import struct
import typing

import pytest

import spnego
from spnego._ntlm_raw.messages import Authenticate, AvId, NTClientChallengeV2
from spnego._spn_policy import (
    SPNTargetNameStatus,
    SPNTargetPolicy,
    SPNTargetPolicyMode,
    canonicalize_spn,
)
from spnego.exceptions import InvalidTokenError, OperationNotAvailableError, SPNTargetPolicyError

VALID_SPN = "http/srv.example.com"
OTHER_SPN = "cifs/srv.example.com"
ALIAS_SPN = "http/alias.example.com"


def make_policy(mode: SPNTargetPolicyMode, *, aliases: typing.Optional[typing.List[str]] = None) -> SPNTargetPolicy:
    return SPNTargetPolicy(
        allowed_names=[VALID_SPN],
        trusted_aliases=aliases or [ALIAS_SPN],
        mode=mode,
    )


# ---------------------------------------------------------------------------
# Pure policy / canonicalization behaviour
# ---------------------------------------------------------------------------


def test_canonicalize_spn():
    assert canonicalize_spn("HTTP/Srv.Example.COM.") == "http/srv.example.com"
    assert canonicalize_spn("http/srv.example.com") == "http/srv.example.com"
    assert canonicalize_spn("  http/srv.example.com  ") == "http/srv.example.com"
    assert canonicalize_spn("http/srv.example.com.") == "http/srv.example.com"
    # Non SPN shaped values are lower cased but preserved so they can be reported as malformed.
    assert canonicalize_spn("NotAnSPN") == "notanspn"
    # A separator with an empty service or host falls back to the lower cased raw value.
    assert canonicalize_spn("/host-only") == "/host-only"
    assert canonicalize_spn(None) is None
    assert canonicalize_spn("   ") is None


def test_policy_accepts_string_and_dedupes():
    policy = SPNTargetPolicy(allowed_names=VALID_SPN, trusted_aliases=ALIAS_SPN)
    assert policy.allowed_names == ("http/srv.example.com",)
    assert policy.trusted_aliases == ("http/alias.example.com",)

    dup = SPNTargetPolicy(allowed_names=[VALID_SPN, "HTTP/SRV.EXAMPLE.COM"])
    assert dup.allowed_names == ("http/srv.example.com",)


def test_policy_requires_allowed_name():
    with pytest.raises(ValueError, match="at least one allowed name"):
        SPNTargetPolicy(allowed_names=[])

    with pytest.raises(ValueError, match="must not be empty"):
        SPNTargetPolicy(allowed_names="   ")


def test_policy_rejects_alias_overlap_and_bad_mode():
    with pytest.raises(ValueError, match="must not duplicate allowed names"):
        SPNTargetPolicy(allowed_names=[VALID_SPN], trusted_aliases=["HTTP/SRV.example.com"])

    with pytest.raises(ValueError, match="must be a SPNTargetPolicyMode"):
        SPNTargetPolicy(allowed_names=[VALID_SPN], mode="strict")  # type: ignore[arg-type]


def test_policy_validate_statuses():
    policy = make_policy(SPNTargetPolicyMode.strict)

    cases = [
        (VALID_SPN, SPNTargetNameStatus.allowed_name, True),
        ("HTTP/SRV.EXAMPLE.COM", SPNTargetNameStatus.representation, True),
        ("http/srv.example.com.", SPNTargetNameStatus.representation, True),
        (ALIAS_SPN, SPNTargetNameStatus.trusted_alias, True),
        ("HTTP/ALIAS.Example.COM", SPNTargetNameStatus.representation, True),
        (OTHER_SPN, SPNTargetNameStatus.mismatch, False),
        ("http/evil.example.com", SPNTargetNameStatus.mismatch, False),
        ("weird-name", SPNTargetNameStatus.mismatch_malformed, False),
        (None, SPNTargetNameStatus.missing, False),
        ("", SPNTargetNameStatus.missing, False),
    ]

    for presented, expected_status, expected_allowed in cases:
        result = policy.validate(presented)
        assert result.status == expected_status, presented
        assert result.allowed is expected_allowed, presented
        if expected_allowed:
            assert result.matched is not None
        else:
            assert result.matched is None


def test_policy_repr_equality_and_hash():
    policy = SPNTargetPolicy(allowed_names=VALID_SPN, trusted_aliases=ALIAS_SPN)
    assert "SPNTargetPolicy(" in repr(policy)
    assert VALID_SPN in repr(policy)

    same = SPNTargetPolicy(allowed_names=[VALID_SPN], trusted_aliases=[ALIAS_SPN])
    different = SPNTargetPolicy(allowed_names=[VALID_SPN], mode=SPNTargetPolicyMode.strict)
    assert policy == same
    assert policy != different
    assert hash(policy) == hash(same)
    assert (policy == "not-a-policy") is False


def test_policy_rejects_non_string_entries():
    with pytest.raises(ValueError, match="names must be strings"):
        SPNTargetPolicy(allowed_names=[VALID_SPN, 123])  # type: ignore[list-item]

    with pytest.raises(ValueError, match="names must be strings"):
        SPNTargetPolicy(allowed_names=[VALID_SPN], trusted_aliases=[456])  # type: ignore[list-item]


def test_canonicalize_non_spn_value_preserved():
    # A value without a service separator is lower cased but retained so it is reported as malformed, not silently
    # treated as a match. Both branches of the malformed canonicalization are exercised.
    assert canonicalize_spn("UPPERHOST") == "upperhost"
    assert SPNTargetPolicy(allowed_names=[VALID_SPN]).validate("UPPERHOST").status == (
        SPNTargetNameStatus.mismatch_malformed
    )


def test_policy_does_not_grow_from_client_input():
    policy = make_policy(SPNTargetPolicyMode.strict)
    before = (policy.allowed_names, policy.trusted_aliases)

    for presented in ["http/attacker.example.com", "http/new-alias.example.com"]:
        result = policy.validate(presented)
        assert result.allowed is False

    after = (policy.allowed_names, policy.trusted_aliases)
    assert before == after


# ---------------------------------------------------------------------------
# End to end pure Python NTLM authentication
# ---------------------------------------------------------------------------


def run_ntlm_exchange(
    ntlm_cred,
    policy: typing.Optional[SPNTargetPolicy],
    *,
    service: str = "http",
    hostname: str = "srv.example.com",
):
    client = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=hostname,
        service=service,
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )
    server = spnego.server(
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
        spn_target_policy=policy,
    )

    negotiate = client.step()
    challenge = server.step(negotiate)
    authenticate = client.step(challenge)
    return client, server, authenticate


def drive_handshake(client, server):
    """Drive a full context handshake, including the SPNEGO mechListMIC round trips."""
    token = client.step()
    while not (client.complete and server.complete):
        token = server.step(token)
        if server.complete and client.complete:
            break
        token = client.step(token)
    return client, server


def test_ntlm_auth_without_policy_keeps_legacy_path(ntlm_cred):
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, None)

    assert server.spn_target_policy is None
    assert server.spn_target_result is None
    assert server.step(authenticate) is None
    assert server.complete
    assert server.client_principal is not None
    # The client still embeds its configured SPN even when no policy enforces it.
    auth = Authenticate.unpack(authenticate)
    client_challenge = NTClientChallengeV2.unpack(auth.nt_challenge_response[16:])
    assert client_challenge.av_pairs[AvId.target_name] == VALID_SPN


def test_ntlm_strict_policy_allows_matching_target(ntlm_cred):
    policy = make_policy(SPNTargetPolicyMode.strict)
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, policy)

    assert server.step(authenticate) is None
    assert server.complete
    result = server.spn_target_result
    assert result is not None
    assert result.status == SPNTargetNameStatus.allowed_name
    assert result.allowed is True
    assert result.matched == VALID_SPN


def test_ntlm_strict_policy_allows_representation_difference(ntlm_cred):
    # The client presents an upper case, trailing dot spelling while local config uses the canonical form.
    policy = SPNTargetPolicy(
        allowed_names=["http/srv.example.com"],
        trusted_aliases=[],
        mode=SPNTargetPolicyMode.strict,
    )
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, policy, hostname="SRV.EXAMPLE.COM.")

    assert server.step(authenticate) is None
    assert server.complete
    result = server.spn_target_result
    assert result.status == SPNTargetNameStatus.representation
    assert result.presented == "http/SRV.EXAMPLE.COM."
    assert result.matched == VALID_SPN


def test_ntlm_strict_policy_allows_trusted_alias(ntlm_cred):
    policy = SPNTargetPolicy(allowed_names=[VALID_SPN], trusted_aliases=[ALIAS_SPN], mode=SPNTargetPolicyMode.strict)
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, policy, hostname="alias.example.com")

    assert server.step(authenticate) is None
    assert server.complete
    result = server.spn_target_result
    assert result.status == SPNTargetNameStatus.trusted_alias
    assert result.matched == ALIAS_SPN


def test_ntlm_strict_policy_rejects_wrong_service_at_authenticate_stage(ntlm_cred):
    # Same host, different service class: the password proof is valid but the token targeted another service.
    policy = SPNTargetPolicy(allowed_names=[OTHER_SPN], trusted_aliases=[], mode=SPNTargetPolicyMode.strict)
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, policy)

    # The negotiate and challenge legs completed, rejection happens when the authenticate token is processed.
    assert not server.complete
    with pytest.raises(SPNTargetPolicyError, match="rejected the authentication"):
        server.step(authenticate)

    assert not server.complete
    result = server.spn_target_result
    assert result.status == SPNTargetNameStatus.mismatch
    assert result.presented == VALID_SPN


def test_ntlm_policy_evaluated_before_password_proof(ntlm_cred):
    # Corrupt the NT proof string. A strict policy must still fail on the SPN rather than the broken password proof,
    # proving the admission decision runs before the credential proof is verified.
    policy = SPNTargetPolicy(allowed_names=[OTHER_SPN], trusted_aliases=[], mode=SPNTargetPolicyMode.strict)
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, policy)

    buf = bytearray(authenticate)
    nt_len, nt_max, nt_off = struct.unpack("<HHI", bytes(buf[20:28]))
    for idx in range(nt_off, nt_off + 16):
        buf[idx] ^= 0xFF

    with pytest.raises(SPNTargetPolicyError):
        server.step(bytes(buf))
    assert not server.complete

    # In permissive mode the same corrupted token passes the policy (with a warning) and reaches the proof check.
    permissive = SPNTargetPolicy(allowed_names=[OTHER_SPN], trusted_aliases=[], mode=SPNTargetPolicyMode.permissive)
    perm_client, perm_server, perm_token = run_ntlm_exchange(ntlm_cred, permissive)
    perm_buf = bytearray(perm_token)
    nt_len, nt_max, nt_off = struct.unpack("<HHI", bytes(perm_buf[20:28]))
    for idx in range(nt_off, nt_off + 16):
        perm_buf[idx] ^= 0xFF

    with pytest.warns(UserWarning):
        with pytest.raises(InvalidTokenError, match="Invalid NTLM response"):
            perm_server.step(bytes(perm_buf))


def test_ntlm_strict_policy_rejects_wrong_host(ntlm_cred):
    policy = SPNTargetPolicy(allowed_names=[VALID_SPN], trusted_aliases=[], mode=SPNTargetPolicyMode.strict)
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, policy, hostname="other.example.com")

    with pytest.raises(SPNTargetPolicyError):
        server.step(authenticate)
    assert server.spn_target_result.status == SPNTargetNameStatus.mismatch


def test_ntlm_permissive_policy_warns_but_completes(ntlm_cred):
    policy = SPNTargetPolicy(allowed_names=[OTHER_SPN], trusted_aliases=[], mode=SPNTargetPolicyMode.permissive)
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, policy)

    with pytest.warns(UserWarning, match="did not admit"):
        assert server.step(authenticate) is None

    assert server.complete
    assert server.spn_target_result.status == SPNTargetNameStatus.mismatch


def test_ntlm_strict_policy_rejects_missing_target_name(ntlm_cred):
    policy = SPNTargetPolicy(allowed_names=[VALID_SPN], trusted_aliases=[], mode=SPNTargetPolicyMode.strict)
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, policy)

    # Strip the MSV_AV_TARGET_NAME AV pair from the client challenge and rebuild the authenticate token.
    auth = Authenticate.unpack(authenticate)
    challenge_v2 = NTClientChallengeV2.unpack(auth.nt_challenge_response[16:])
    av_pairs = challenge_v2.av_pairs
    del av_pairs[AvId.target_name]
    rebuilt = NTClientChallengeV2(
        time_stamp=challenge_v2.time_stamp,
        client_challenge=challenge_v2.challenge_from_client,
        av_pairs=av_pairs,
    )
    tampered_response = auth.nt_challenge_response[:16] + rebuilt.pack()

    # Rebuild an authenticate message carrying the modified NT challenge response.
    rebuilt_auth = Authenticate(
        auth.flags,
        auth.lm_challenge_response or b"",
        tampered_response,
        domain_name=auth.domain_name,
        username=auth.user_name,
        workstation=auth.workstation,
        encrypted_session_key=auth.encrypted_random_session_key,
    )

    with pytest.raises(SPNTargetPolicyError, match="MSV_AV_TARGET_NAME AV pair was missing"):
        server.step(rebuilt_auth.pack())
    assert server.spn_target_result.status == SPNTargetNameStatus.missing


def test_ntlm_permissive_policy_warns_on_missing_target_name(ntlm_cred):
    policy = SPNTargetPolicy(allowed_names=[VALID_SPN], trusted_aliases=[], mode=SPNTargetPolicyMode.permissive)
    client, server, authenticate = run_ntlm_exchange(ntlm_cred, policy)

    auth = Authenticate.unpack(authenticate)
    challenge_v2 = NTClientChallengeV2.unpack(auth.nt_challenge_response[16:])
    av_pairs = challenge_v2.av_pairs
    del av_pairs[AvId.target_name]
    rebuilt = NTClientChallengeV2(
        time_stamp=challenge_v2.time_stamp,
        client_challenge=challenge_v2.challenge_from_client,
        av_pairs=av_pairs,
    )
    tampered_response = auth.nt_challenge_response[:16] + rebuilt.pack()
    rebuilt_auth = Authenticate(
        auth.flags,
        auth.lm_challenge_response or b"",
        tampered_response,
        domain_name=auth.domain_name,
        username=auth.user_name,
        workstation=auth.workstation,
        encrypted_session_key=auth.encrypted_random_session_key,
    )

    with pytest.warns(UserWarning, match="MSV_AV_TARGET_NAME AV pair was missing"):
        # The password proof will no longer match because the AV pair set changed, but the policy warning must be
        # emitted before that proof is evaluated.
        with pytest.raises(spnego.exceptions.InvalidTokenError):
            server.step(rebuilt_auth.pack())

    assert server.spn_target_result.status == SPNTargetNameStatus.missing


def test_ntlm_client_target_name_traces_to_hostname_service(ntlm_cred, caplog):
    with caplog.at_level(logging.DEBUG, logger="spnego._ntlm"):
        client, server, authenticate = run_ntlm_exchange(
            ntlm_cred,
            make_policy(SPNTargetPolicyMode.strict),
            service="http",
            hostname="srv.example.com",
        )
        server.step(authenticate)

    trace = [r.message for r in caplog.records if "MSV_AV_TARGET_NAME" in r.message]
    assert trace, "expected a client log tracing the target name to the hostname/service config"
    assert "service='http'" in trace[0]
    assert "hostname='srv.example.com'" in trace[0]

    auth = Authenticate.unpack(authenticate)
    client_challenge = NTClientChallengeV2.unpack(auth.nt_challenge_response[16:])
    assert client_challenge.av_pairs[AvId.target_name] == client.spn == VALID_SPN


def test_ntlm_policy_type_validation(ntlm_cred):
    with pytest.raises(TypeError, match="spn_target_policy must be a SPNTargetPolicy"):
        spnego.server(
            protocol="ntlm",
            options=spnego.NegotiateOptions.use_ntlm,
            spn_target_policy={"allowed_names": [VALID_SPN]},
        )


def test_ntlm_new_context_preserves_policy(ntlm_cred):
    policy = make_policy(SPNTargetPolicyMode.strict)
    server = spnego.server(
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
        spn_target_policy=policy,
    )
    assert server.new_context().spn_target_policy == policy


# ---------------------------------------------------------------------------
# The same credential used against two different service names
# ---------------------------------------------------------------------------


def test_shared_credential_two_services_strict_isolation(ntlm_cred):
    """One credential store backs two services; strict policy must stop cross service replay."""
    service_a = SPNTargetPolicy(allowed_names=["http/srv.example.com"], mode=SPNTargetPolicyMode.strict)
    service_b = SPNTargetPolicy(allowed_names=["cifs/srv.example.com"], mode=SPNTargetPolicyMode.strict)

    # A token minted for the http service presented to the cifs service must be rejected, and vice versa.
    http_client, cifs_server, http_token = run_ntlm_exchange(ntlm_cred, service_b, service="http")
    with pytest.raises(SPNTargetPolicyError):
        cifs_server.step(http_token)

    cifs_client, http_server, cifs_token = run_ntlm_exchange(ntlm_cred, service_a, service="cifs")
    with pytest.raises(SPNTargetPolicyError):
        http_server.step(cifs_token)

    # The same credential still authenticates legitimately when the target matches.
    ok_client, ok_server, ok_token = run_ntlm_exchange(ntlm_cred, service_a, service="http")
    assert ok_server.step(ok_token) is None
    assert ok_server.complete


def test_shared_credential_two_services_permissive_compat(ntlm_cred):
    """Default/permissive policy retains the legacy cross service behaviour but records a warning."""
    permissive = SPNTargetPolicy(allowed_names=["cifs/srv.example.com"], mode=SPNTargetPolicyMode.permissive)
    client, server, token = run_ntlm_exchange(ntlm_cred, permissive, service="http")

    with pytest.warns(UserWarning):
        assert server.step(token) is None
    assert server.complete


# ---------------------------------------------------------------------------
# Providers that cannot enforce the policy must reject it explicitly
# ---------------------------------------------------------------------------


def test_ntlmv1_strict_policy_fails_closed(ntlm_cred, monkeypatch):
    # LM_COMPAT_LEVEL 0 makes the client send an NTLMv1/LM response which cannot carry a target name.
    monkeypatch.setenv("LM_COMPAT_LEVEL", "0")
    client = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )
    policy = SPNTargetPolicy(
        allowed_names=["host/%s" % socket.gethostname()],
        trusted_aliases=[],
        mode=SPNTargetPolicyMode.strict,
    )
    server = spnego.server(
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
        spn_target_policy=policy,
    )

    authenticate = client.step(server.step(client.step()))
    with pytest.raises(SPNTargetPolicyError, match="does not carry an MSV_AV_TARGET_NAME"):
        server.step(authenticate)
    assert server.spn_target_result.status == SPNTargetNameStatus.missing


def test_ntlmv1_permissive_policy_completes(ntlm_cred, monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", "0")
    client = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )
    policy = SPNTargetPolicy(
        allowed_names=["host/%s" % socket.gethostname()],
        trusted_aliases=[],
        mode=SPNTargetPolicyMode.permissive,
    )
    server = spnego.server(
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
        spn_target_policy=policy,
    )

    authenticate = client.step(server.step(client.step()))
    with pytest.warns(UserWarning, match="does not carry an MSV_AV_TARGET_NAME"):
        assert server.step(authenticate) is None
    assert server.complete
    assert server.spn_target_result.status == SPNTargetNameStatus.missing


def test_gssapi_provider_rejects_spn_policy(ntlm_cred):
    if "kerberos" not in spnego._gss.GSSAPIProxy.available_protocols():
        pytest.skip("Test requires the GSSAPI provider")

    with pytest.raises(OperationNotAvailableError, match="GSSAPI provider does not support"):
        spnego.client(
            ntlm_cred[0],
            ntlm_cred[1],
            hostname="srv.example.com",
            protocol="kerberos",
            spn_target_policy=make_policy(SPNTargetPolicyMode.strict),
        )


def test_credssp_provider_rejects_spn_policy(ntlm_cred):
    with pytest.raises(OperationNotAvailableError, match="CredSSP provider does not support"):
        spnego.client(
            ntlm_cred[0],
            ntlm_cred[1],
            hostname="srv.example.com",
            protocol="credssp",
            spn_target_policy=make_policy(SPNTargetPolicyMode.strict),
        )


def test_negotiate_pure_python_forwards_policy_to_ntlm(ntlm_cred):
    policy = make_policy(SPNTargetPolicyMode.strict)
    client = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname="srv.example.com",
        service="http",
        protocol="negotiate",
        options=spnego.NegotiateOptions.use_negotiate,
        spn_target_policy=policy,
    )
    server = spnego.server(
        protocol="negotiate",
        options=spnego.NegotiateOptions.use_negotiate,
        spn_target_policy=policy,
    )

    drive_handshake(client, server)
    assert server.complete
    assert server.negotiated_protocol == "ntlm"
    inner = server._context
    assert getattr(inner, "spn_target_policy", None) == policy


def test_negotiate_strict_policy_rejects_cross_service(ntlm_cred):
    policy = SPNTargetPolicy(allowed_names=[OTHER_SPN], mode=SPNTargetPolicyMode.strict)
    client = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname="srv.example.com",
        service="http",
        protocol="negotiate",
        options=spnego.NegotiateOptions.use_negotiate,
    )
    server = spnego.server(
        protocol="negotiate",
        options=spnego.NegotiateOptions.use_negotiate,
        spn_target_policy=policy,
    )

    with pytest.raises(SPNTargetPolicyError):
        drive_handshake(client, server)
    assert not server.complete
