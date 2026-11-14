# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import hashlib
import pathlib
import re
import socket
import typing

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import spnego
import spnego._credssp as credssp
from spnego._credssp_structures import NegoData, TSCredentials, TSPasswordCreds, TSRequest
from spnego.exceptions import (
    BadBindingsError,
    DelegationDeniedError,
    FeatureMissingError,
    InvalidTokenError,
    NegotiateOptions,
    NoContextError,
    OperationNotAvailableError,
    SpnegoError,
)
from spnego.tls import default_tls_context


@pytest.mark.parametrize(
    "expected, usage, nonce",
    [
        (b"\x00\x01", "initiate", None),
        (
            b"\x45\x90\xc2\x6c\x83\x7d\xac\xdf\x3d\xa8\xfa\xe5\x78\x26\x4d\x9e"
            b"\x45\x48\x6a\xfc\x39\x51\xf2\x1e\xf3\x57\x06\x4c\xd5\x5f\xbb\xb5",
            "initiate",
            b"\x00\x00",
        ),
        (b"\x01\x01", "accept", None),
        (
            b"\xcd\xf4\xff\xee\x6c\xb6\x39\x5e\x5b\x69\x2c\x2d\xa3\x97\x38\x6f"
            b"\x6a\x1e\xab\x2d\x3a\x62\x71\x81\x6a\x04\xc7\xa2\x91\x4d\x33\x3f",
            "accept",
            b"\x00\x00",
        ),
    ],
)
def test_pub_key_auth(expected, usage, nonce):
    actual = credssp._get_pub_key_auth(b"\x00\x01", usage, nonce=nonce)

    assert actual == expected


@pytest.mark.parametrize(
    "protocol, cipher, expected",
    [
        ["TLSv1.3", "TLS_AES_128_GCM_SHA256", 17],
        ["TLSv1.3", "TLS_AES_256_GCM_SHA384", 17],
        ["TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", 16],
        ["TLSv1.2", "RC4-MD5", 16],
        ["TLSv1.2", "ECDH-ECDSA-3DES-SHA256", 34],
        ["TLSv1.2", "ECDH-RSA-AES-SHA384", 50],
        ["TLSv1.2", "ECDH-RSA-AES", 2],
    ],
)
def test_get_credssp_trailer_length(protocol, cipher, expected):
    actual = credssp._tls_trailer_length(30, protocol, cipher)
    assert actual == expected


def test_credssp_no_iov():
    assert not credssp.CredSSPProxy("username", "password").iov_available()


def test_credssp_iov_not_available():
    expected = (
        "The system is missing the GSSAPI IOV extension headers or CredSSP is being requested, "
        "cannot utilize wrap_iov and unwrap_iov"
    )
    with pytest.raises(FeatureMissingError, match=re.escape(expected)):
        credssp.CredSSPProxy("username", "password", options=spnego.NegotiateOptions.wrapping_iov)


def test_credssp_no_session_key():
    with pytest.raises(FeatureMissingError, match="The protocol selected does not support getting the session key"):
        credssp.CredSSPProxy("user", "password", options=NegotiateOptions.session_key)


def test_credssp_fail_getting_session_key():
    context = credssp.CredSSPProxy("username", "password")

    with pytest.raises(OperationNotAvailableError, match="CredSSP does not have a session key to share"):
        _ = context.session_key


def test_credssp_wrap_iov_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer IOV wrapping"):
        credssp.CredSSPProxy("username", "password").wrap_iov([])


def test_credssp_unwrap_iov_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer IOV wrapping"):
        credssp.CredSSPProxy("username", "password").unwrap_iov([])


def test_credssp_sign_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer signing"):
        credssp.CredSSPProxy("username", "password").sign(b"")


def test_credssp_verify_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer verification"):
        credssp.CredSSPProxy("username", "password").verify(b"", b"")


def test_credssp_wrap_no_context():
    with pytest.raises(SpnegoError, match="Invalid TLS state when wrapping data"):
        credssp.CredSSPProxy("username", "password").wrap(b"data")


def test_credssp_query_message_sizes_fail():
    with pytest.raises(NoContextError, match="Cannot get message sizes until context has been established"):
        credssp.CredSSPProxy("username", "password").query_message_sizes()


def test_credssp_invalid_handshake(ntlm_cred):
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], protocol="credssp")
    s = credssp.CredSSPProxy(None, None, protocol="credssp", usage="accept")

    server_hello = s.step(c.step())
    assert server_hello is not None

    with pytest.raises(InvalidTokenError, match="TLS handshake for CredSSP"):
        c.step(b"\x00" + server_hello)


def test_credssp_server_without_pub_key():
    context = default_tls_context(usage="accept")
    with pytest.raises(OperationNotAvailableError, match="Provided tls context does not have a public key set"):
        credssp.CredSSPProxy("username", "password", usage="accept", credssp_tls_context=context)


@pytest.mark.parametrize("version", [2, 5])
def test_credssp_invalid_client_authentication_v2(version, ntlm_cred, monkeypatch):
    monkeypatch.setattr(credssp, "_CREDSSP_VERSION", version)

    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    # Set up the state so the server can send the error code
    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    bad_request = TSRequest(credssp._CREDSSP_VERSION, nego_tokens=NegoData(b"\x00"))
    actual = s.step(c.wrap(bad_request.pack()).data)

    # On CredSSP v2 or 5 there is no error message from the server, just no token
    assert actual is None


@pytest.mark.parametrize("version", [3, 4, 6])
def test_credssp_invalid_client_authentication(version, ntlm_cred, monkeypatch):
    monkeypatch.setattr(credssp, "_CREDSSP_VERSION", version)

    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    # Set up the state so the server can send the error code
    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    assert server_tls_token is not None
    c.unwrap(server_tls_token)
    bad_request = TSRequest(credssp._CREDSSP_VERSION, nego_tokens=NegoData(b"\x00"))
    error_msg = s.step(c.wrap(bad_request.pack()).data)

    expected = re.escape("Received NTStatus in TSRequest from acceptor, Context: Authentication")
    with pytest.raises(InvalidTokenError, match=expected):
        c.step(error_msg)


def test_credssp_no_pub_key_after_auth(ntlm_cred):
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)

    # Send back a TSRequest without the public key.
    assert ntlm3_pub_key is not None
    s.unwrap(ntlm3_pub_key)
    ts_request = TSRequest(credssp._CREDSSP_VERSION)

    with pytest.raises(InvalidTokenError, match="Acceptor did not response with pubKeyAuth info"):
        c.step(s.wrap(ts_request.pack()).data)


def test_credssp_pub_key_mismatch_initiator(ntlm_cred):
    options = NegotiateOptions.use_ntlm
    c = credssp.CredSSPProxy(
        ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp", options=options
    )
    s = credssp.CredSSPProxy(
        None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept", options=options
    )

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)

    s_auth_context = s._auth_context
    assert s_auth_context is not None

    # Send back a TSRequest with a bad pub_key_auth value.
    assert ntlm3_pub_key is not None
    request = TSRequest.unpack(s.unwrap(ntlm3_pub_key).data)
    assert request.nego_tokens is not None
    s_auth_context.step(request.nego_tokens[0].nego_token)
    ts_request = TSRequest(credssp._CREDSSP_VERSION, pub_key_auth=s_auth_context.wrap(b"bad").data)

    with pytest.raises(BadBindingsError, match="Public key verification failed, potential man in the middle attack"):
        c.step(s.wrap(ts_request.pack()).data)


def test_credssp_pub_key_mismatch_acceptor(ntlm_cred):
    options = NegotiateOptions.use_ntlm
    c = credssp.CredSSPProxy(
        ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp", options=options
    )
    s = credssp.CredSSPProxy(
        None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept", options=options
    )

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    # Craft the TSRequest with the NTLMv3 token and invalid pub_key_auth
    assert server_tls_token is not None
    ntlm2_request = TSRequest.unpack(c.unwrap(server_tls_token).data)
    assert ntlm2_request.nego_tokens is not None
    ntlm3 = c._auth_context.step(ntlm2_request.nego_tokens[0].nego_token)
    assert ntlm3 is not None

    request = TSRequest(
        credssp._CREDSSP_VERSION, nego_tokens=NegoData(ntlm3), pub_key_auth=c._auth_context.wrap(b"bad").data
    )

    with pytest.raises(BadBindingsError, match="Public key verification failed, potential man in the middle attack"):
        s.step(c.wrap(request.pack()).data)


def test_credssp_no_credential(ntlm_cred):
    options = NegotiateOptions.use_ntlm
    c = credssp.CredSSPProxy(
        ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp", options=options
    )
    s = credssp.CredSSPProxy(
        None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept", options=options
    )

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)
    assert ntlm3_pub_key is not None

    pub_key_resp = s.step(ntlm3_pub_key)
    assert pub_key_resp is not None
    server_pub_key = TSRequest.unpack(c.unwrap(pub_key_resp).data)

    # Unpack the TSRequest properly and craft a TSRequest without a credential
    assert server_pub_key.pub_key_auth is not None
    c._auth_context.unwrap(server_pub_key.pub_key_auth)

    request = TSRequest(credssp._CREDSSP_VERSION)

    with pytest.raises(InvalidTokenError, match="No credential received on CredSSP TSRequest from initiator"):
        s.step(c.wrap(request.pack()).data)


# Delegation authorization


@dataclasses.dataclass
class _PeerRun:
    """The result of driving a CredSSP handshake."""

    client: credssp.CredSSPProxy
    server: credssp.CredSSPProxy
    credential: typing.Optional[bytes]


def _drive_credssp(
    client: credssp.CredSSPProxy,
    server: credssp.CredSSPProxy,
    *,
    stop_before_credentials: bool = False,
    fail_on_denial: bool = True,
) -> _PeerRun:
    """Drives a CredSSP exchange up to and including the credential exchange.

    Returns the raw ``authInfo`` token the client sent, if any, so a caller
    can assert on whether a credential package existed at all. When
    ``stop_before_credentials`` is set the exchange stops right before the
    client evaluates delegation and sends the credential package.
    """
    server_tls_token = None
    while client.get_extra_info("auth_stage") == "TLS Handshake":
        client_tls_token = client.step(server_tls_token)
        assert not client.complete
        assert not server.complete

        server_tls_token = server.step(client_tls_token)
        assert not client.complete
        assert not server.complete

    pub_key_token = client.step(server_tls_token)
    assert not client.complete
    server_pub_key = server.step(pub_key_token)

    if stop_before_credentials:
        return _PeerRun(client=client, server=server, credential=None)

    try:
        credential_token = client.step(server_pub_key)
    except DelegationDeniedError:
        if fail_on_denial:
            raise
        return _PeerRun(client=client, server=server, credential=None)

    assert credential_token is not None
    final_token = server.step(credential_token)
    assert final_token is None

    return _PeerRun(client=client, server=server, credential=credential_token)


def _client(
    ntlm_cred: typing.Tuple[str, str],
    authorizer: typing.Optional[credssp.DelegationAuthorizationCallback],
) -> credssp.CredSSPProxy:
    kwargs: typing.Dict[str, typing.Any] = {}
    if authorizer is not None:
        kwargs["credssp_delegation_authorizer"] = authorizer

    return credssp.CredSSPProxy(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        protocol="credssp",
        options=NegotiateOptions.use_ntlm,
        **kwargs,
    )


def _server(
    tls_context: typing.Optional[typing.Any] = None,
) -> credssp.CredSSPProxy:
    kwargs: typing.Dict[str, typing.Any] = {}
    if tls_context is not None:
        kwargs["credssp_tls_context"] = tls_context

    return credssp.CredSSPProxy(
        None,
        None,
        hostname=socket.gethostname(),
        protocol="credssp",
        usage="accept",
        options=NegotiateOptions.use_ntlm,
        **kwargs,
    )


def _server_tls_context(tmp_path: pathlib.Path) -> typing.Tuple[typing.Any, str]:
    """Creates an acceptor TLS context with its own cert and its SHA-256 fingerprint."""
    tls_context = default_tls_context(usage="accept")
    cert_pem, key_pem, public_key = spnego.tls.generate_tls_certificate()

    fingerprint = x509.load_pem_x509_certificate(cert_pem, default_backend()).fingerprint(hashes.SHA256()).hex()

    cert_path = tmp_path / "ca.pem"
    tmp_path.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert_pem + key_pem)

    tls_context.context.load_cert_chain(str(cert_path))
    tls_context.public_key = public_key

    return tls_context, fingerprint


def test_credssp_delegation_requires_authorizer(ntlm_cred):
    c = _client(ntlm_cred, None)
    s = _server()

    with pytest.raises(DelegationDeniedError, match="No CredSSP delegation authorizer was configured"):
        _drive_credssp(c, s)

    assert not c.complete
    assert not s.complete
    assert c._ts_credential is None
    assert s.get_extra_info("client_credential") is None


def test_credssp_delegation_denied_does_not_pack_credentials(ntlm_cred, monkeypatch):
    calls: typing.List[bytes] = []
    original_pack = TSCredentials.pack
    monkeypatch.setattr(TSCredentials, "pack", lambda self: calls.append(b"packed") or original_pack(self))

    seen: typing.List[credssp.CredSSPDelegationInfo] = []
    c = _client(ntlm_cred, lambda info: seen.append(info) or False)
    s = _server()

    with pytest.raises(DelegationDeniedError, match="denied delegating credentials"):
        _drive_credssp(c, s)

    assert calls == []
    assert c._ts_credential is None
    assert not c.complete
    assert not s.complete
    assert s.get_extra_info("client_credential") is None

    # The callback got the verified peer details, and no secret.
    assert len(seen) == 1
    info = seen[0]
    assert info.hostname == socket.gethostname()
    assert info.credential_type == "password"
    assert info.protocol_version == credssp._CREDSSP_VERSION
    assert info.peer_certificate is not None
    assert info.tls_certificate_sha256 == hashlib.sha256(info.peer_certificate).hexdigest()
    assert info.tls_protocol.startswith("TLS")
    assert info.peer_certificate_subject
    assert ntlm_cred[1] not in repr(info)


@pytest.mark.parametrize("decision", [False, None, 0, ""])
def test_credssp_delegation_falsy_decision_is_a_denial(ntlm_cred, monkeypatch, decision):
    calls: typing.List[bytes] = []
    original_pack = TSCredentials.pack
    monkeypatch.setattr(TSCredentials, "pack", lambda self: calls.append(b"packed") or original_pack(self))

    c = _client(ntlm_cred, lambda info: decision)
    s = _server()

    with pytest.raises(DelegationDeniedError):
        _drive_credssp(c, s)

    assert calls == []
    assert c._ts_credential is None
    assert not c.complete
    assert not s.complete


def test_credssp_delegation_exception_does_not_pack_credentials(ntlm_cred, monkeypatch):
    calls: typing.List[bytes] = []
    original_pack = TSCredentials.pack
    monkeypatch.setattr(TSCredentials, "pack", lambda self: calls.append(b"packed") or original_pack(self))

    class AuthorizationFailure(Exception):
        pass

    def authorizer(info: credssp.CredSSPDelegationInfo) -> bool:
        raise AuthorizationFailure("The application could not evaluate this peer")

    c = _client(ntlm_cred, authorizer)
    s = _server()

    with pytest.raises(AuthorizationFailure):
        _drive_credssp(c, s)

    assert calls == []
    assert c._ts_credential is None
    assert not c.complete
    assert not s.complete
    assert s.get_extra_info("client_credential") is None


def test_credssp_delegation_denied_when_peer_identity_missing(ntlm_cred, monkeypatch):
    """Without a verified peer identity there is nothing to authorize against."""
    calls: typing.List[bytes] = []
    original_pack = TSCredentials.pack
    monkeypatch.setattr(TSCredentials, "pack", lambda self: calls.append(b"packed") or original_pack(self))

    c = _client(ntlm_cred, lambda info: True)
    s = _server()
    run = _drive_credssp(c, s, stop_before_credentials=True)

    # Peer was authenticated, but the verified certificate is unavailable.
    monkeypatch.setattr(run.client, "_peer_certificate", None, raising=False)

    with pytest.raises(DelegationDeniedError, match="without the peer TLS certificate"):
        run.client._authorize_delegation()

    assert calls == []
    assert run.client._ts_credential is None
    assert not run.client.complete
    assert not run.server.complete


def test_credssp_delegation_only_authorized_peer_gets_credentials(ntlm_cred, monkeypatch, tmp_path):
    """Two peers complete authentication, only the approved one is delegated to."""
    calls: typing.List[bytes] = []
    original_pack = TSCredentials.pack

    def track_pack(self: TSCredentials) -> bytes:
        calls.append(self.credentials.password.encode())  # type: ignore[union-attr]
        return original_pack(self)

    monkeypatch.setattr(TSCredentials, "pack", track_pack)

    approved: typing.List[credssp.CredSSPDelegationInfo] = []
    refused: typing.List[credssp.CredSSPDelegationInfo] = []

    # The application selects the peer by the TLS fingerprint it learned out of
    # band. Both servers authenticate the same client user.
    approved_tls, approved_fingerprint = _server_tls_context(tmp_path / "approved")
    refused_tls, refused_fingerprint = _server_tls_context(tmp_path / "refused")
    assert approved_fingerprint != refused_fingerprint

    def authorizer(info: credssp.CredSSPDelegationInfo) -> bool:
        if info.tls_certificate_sha256 == approved_fingerprint:
            approved.append(info)
            return True

        refused.append(info)
        return False

    allowed_client = _client(ntlm_cred, authorizer)
    allowed_server = _server(approved_tls)
    allowed = _drive_credssp(allowed_client, allowed_server)

    assert allowed.client.complete
    assert allowed.server.complete
    credential = typing.cast(TSPasswordCreds, allowed.server.get_extra_info("client_credential"))
    assert isinstance(credential, TSPasswordCreds)
    assert credential.domain_name == ntlm_cred[0].split("\\")[0]
    assert credential.username == ntlm_cred[0].split("\\")[1]
    assert credential.password == ntlm_cred[1]

    refused_client = _client(ntlm_cred, authorizer)
    refused_server = _server(refused_tls)
    with pytest.raises(DelegationDeniedError):
        _drive_credssp(refused_client, refused_server)

    assert not refused_client.complete
    assert not refused_server.complete
    assert refused_server.get_extra_info("client_credential") is None

    assert len(approved) == 1
    assert len(refused) == 1
    assert approved[0].tls_certificate_sha256 == approved_fingerprint
    assert refused[0].tls_certificate_sha256 == refused_fingerprint

    # Proof at the packing boundary: exactly one usable credential package
    # existed, and it is the one the authorized peer received.
    assert calls == [ntlm_cred[1].encode()]
    assert allowed.credential is not None


def test_credssp_new_context_does_not_inherit_delegation_permit(ntlm_cred):
    decisions: typing.List[bool] = [True]
    seen: typing.List[credssp.CredSSPDelegationInfo] = []

    def authorizer(info: credssp.CredSSPDelegationInfo) -> bool:
        seen.append(info)
        return decisions[-1]

    c = _client(ntlm_cred, authorizer)
    s = _server()
    run = _drive_credssp(c, s)
    assert run.client.complete
    assert run.client._delegation_authorized is True
    assert len(seen) == 1

    # The permit belongs to the completed handshake only.
    new_client = run.client.new_context()
    assert new_client._delegation_authorized is None
    assert new_client._ts_credential is None

    # The new handshake asks the application again. Denying it now must stop
    # the new context even though the previous handshake was authorized.
    decisions[:] = [False]
    new_server = _server()
    with pytest.raises(DelegationDeniedError):
        _drive_credssp(new_client, new_server)

    assert len(seen) == 2
    assert seen[0].tls_certificate_sha256 == seen[1].tls_certificate_sha256
    assert new_client._delegation_authorized is False
    assert new_client._ts_credential is None
    assert not new_client.complete
    assert not new_server.complete


def test_credssp_delegation_denial_is_sticky(ntlm_cred):
    """Stepping a denied context again must not report a usable completion."""
    c = _client(ntlm_cred, lambda info: False)
    s = _server()

    server_tls_token = None
    while c.get_extra_info("auth_stage") == "TLS Handshake":
        client_tls_token = c.step(server_tls_token)
        server_tls_token = s.step(client_tls_token)

    assert c.get_extra_info("delegation_authorized") is None

    pub_key_token = c.step(server_tls_token)
    server_pub_key = s.step(pub_key_token)

    with pytest.raises(DelegationDeniedError):
        c.step(server_pub_key)

    assert c.get_extra_info("delegation_authorized") is False
    assert not c.complete
    assert c._ts_credential is None

    # Repeating the step must fail the same way rather than signalling a
    # normal end of the exchange.
    with pytest.raises(DelegationDeniedError):
        c.step(b"")

    assert not c.complete
    assert c._ts_credential is None
    assert not s.complete
    assert s.get_extra_info("client_credential") is None


def test_credssp_delegation_authorized_extra_info(ntlm_cred):
    c = _client(ntlm_cred, lambda info: True)
    s = _server()

    assert c.get_extra_info("delegation_authorized") is None
    run = _drive_credssp(c, s)

    assert run.client.get_extra_info("delegation_authorized") is True
    assert run.server.get_extra_info("delegation_authorized") is None
